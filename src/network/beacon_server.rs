use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use anyhow::{anyhow, Result};
use futures::StreamExt;
use quinn::{Endpoint, IdleTimeout, TransportConfig, VarInt};

use std::sync::Mutex as stdMutex;
use std::time::{Duration, Instant};
use std::{collections::HashMap, error::Error, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;

use tracing::{debug, error, info, info_span, trace};
use tracing_futures::Instrument as _;

use crate::cryptography::ALPN_QUIC_HTTP;

pub const BEACON_MTU: usize = 1330;
pub static KEEP_ALIVE_INTERVAL: u64 = 8;
pub static MAX_IDLE_TIMEOUT: u32 = 10_000;
pub const MAX_PUBLISH_RATE_SEC: u64 = 2;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum OutboundMessage {
    BeaconParam {
        your_ip: Box<SocketAddr>,
        token: [u8; 4],
    },
    Candidate {
        peer_info: Box<PeerInfo>,
        connection_token: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum InbounddMessage {
    Hello {},
    Announce {
        peer_info: Box<PeerInfo>,
        connection_tokens: Vec<Vec<u8>>,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct PeerInfo {
    pub ip: SocketAddr,
    pub certificate: Vec<u8>,
    pub pub_key: [u8; 32],
    pub signature: Vec<u8>,
}
type ConnMap = Arc<stdMutex<HashMap<Vec<u8>, Vec<Arc<Peer>>>>>;

pub fn start_beacon_server(
    bind_addr: SocketAddr,
    pub_key: rustls::Certificate,
    secret_key: rustls::PrivateKey,
) -> Result<Endpoint, Box<dyn Error>> {
    let cert_chain = vec![pub_key.clone()];

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, secret_key)?;

    //reduce the amount of rountrip for TLS negociation
    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    //Introduces an additional round-trip to the handshake to make denial of service attacks more difficult
    server_config.use_retry(true);

    let mut transport: TransportConfig = Default::default();
    transport
        .max_concurrent_uni_streams(0_u8.into()) //accept only bi directional stream
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from(MAX_IDLE_TIMEOUT))));

    server_config.transport = Arc::new(transport);

    let (endpoint, mut incoming) = Endpoint::server(server_config, bind_addr)?;

    let connection_map: ConnMap = Arc::new(stdMutex::new(HashMap::new()));

    let mut csprng = OsRng {};
    let mut random: [u8; 4] = [0_u8; 4];
    csprng.fill_bytes(&mut random);
    let token: Arc<stdMutex<[u8; 4]>> = Arc::new(stdMutex::new(random));

    tokio::spawn(async move {
        while let Some(conn) = incoming.next().await {
            info!("connection incoming");
            let fut = handle_connection(conn, connection_map.clone(), token.clone());
            tokio::spawn(async move {
                if let Err(e) = fut.await {
                    error!("connection failed: {reason}", reason = e.to_string())
                }
            });
        }
    });

    Ok(endpoint)
}

struct Peer {
    send_stream: Arc<Mutex<quinn::SendStream>>,
    peer_info: Box<PeerInfo>,
    connection_tokens: Vec<Vec<u8>>,
}

async fn handle_connection(
    conn: quinn::Connecting,
    connection_map: ConnMap,
    token: Arc<stdMutex<[u8; 4]>>,
) -> Result<()> {
    let quinn::NewConnection {
        connection,
        mut bi_streams,
        ..
    } = conn.await?;
    let span = info_span!(
        "connection",
        remote = %connection.remote_address(),
        protocol = %connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );
    async {
        info!("established");
        let socket_adress = connection.remote_address();
        while let Some(stream) = bi_streams.next().await {
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            let conn_map = connection_map.clone();
            let token = token.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_request(stream, socket_adress, conn_map, token).await {
                    error!("failed: {reason}", reason = e.to_string());
                }
            });
        }
        Ok(())
    }
    .instrument(span)
    .await?;
    Ok(())
}

async fn handle_request(
    (send, mut recv): (quinn::SendStream, quinn::RecvStream),
    adress: SocketAddr,
    connection_map: ConnMap,
    token: Arc<stdMutex<[u8; 4]>>,
) -> Result<()> {
    const MAX_LENGTH: usize = BEACON_MTU - 2;

    let mut message_length_buff = [0_u8; 2];
    let mut message_buff = [0_u8; MAX_LENGTH];
    let mut outbuffer: Vec<u8> = Vec::with_capacity(128);
    let send: Arc<Mutex<quinn::SendStream>> = Arc::new(Mutex::new(send));
    let mut _peer_cleaner: PeerCleaner;
    let mut instant: Option<Instant> = None;

    loop {
        recv.read_exact(&mut message_length_buff)
            .await
            .map_err(|e| anyhow!("failed reading request: {}", e))?;

        let res: u16 = bincode::deserialize(&message_length_buff)
            .map_err(|e| anyhow!("failed deserialise request: {}", e))?;

        let res = usize::from(res);
        if res > MAX_LENGTH {
            return Err(anyhow!("message lenght too large: {}", res));
        }

        recv.read_exact(&mut message_buff[0..res])
            .await
            .map_err(|e| anyhow!("failed reading request: {}", e))?;

        let message: InbounddMessage = bincode::deserialize(&message_buff[0..res])
            .map_err(|e| anyhow!("failed deserialise request: {}", e))?;

        outbuffer.clear();
        match message {
            InbounddMessage::Hello {} => {
                handle_hello_message(&adress, &token, &mut outbuffer, &send).await?;
            }
            InbounddMessage::Announce {
                peer_info,
                connection_tokens,
            } => {
                if instant.is_none() {
                    //do not check first message
                    instant = Some(Instant::now());
                } else if instant.unwrap().elapsed()
                    <= Duration::from_secs(MAX_PUBLISH_RATE_SEC - 1)
                {
                    error!("Client re-published too soon");
                    break;
                } else {
                    instant = Some(Instant::now());
                }

                let peer = Arc::new(Peer {
                    send_stream: send.clone(),
                    peer_info,
                    connection_tokens,
                });
                _peer_cleaner = PeerCleaner {
                    peer: peer.clone(),
                    connection_map: connection_map.clone(),
                };
                handle_announce_message(peer, &connection_map, &mut outbuffer, &send).await?;
            }
        }
    }
    Ok(())
}

async fn handle_hello_message(
    adress: &SocketAddr,
    token: &Arc<stdMutex<[u8; 4]>>,
    outbuffer: &mut Vec<u8>,
    send: &Arc<Mutex<quinn::SendStream>>,
) -> Result<()> {
    let tok;
    {
        tok = token.lock().unwrap().clone();
    }

    let out = OutboundMessage::BeaconParam {
        your_ip: Box::new(adress.clone()),
        token: tok,
    };

    write_all(send, outbuffer, out).await?;
    Ok(())
}

async fn handle_announce_message(
    peer: Arc<Peer>,
    connection_map: &ConnMap,
    outbuffer: &mut Vec<u8>,
    send: &Arc<Mutex<quinn::SendStream>>,
) -> Result<()> {
    debug!("Received Announce from  {}", peer.peer_info.ip);
    let tokens: &Vec<Vec<u8>> = peer.connection_tokens.as_ref();
    for token in tokens {
        insert_peer(&connection_map, token.clone(), &peer);
        let vp = find_matched_peer(&connection_map, &token, &peer);
        if vp.is_some() {
            for valid_peer in vp.unwrap() {
                let local_answer = OutboundMessage::Candidate {
                    peer_info: valid_peer.peer_info.clone(),
                    connection_token: token.clone(),
                };
                write_all(send, outbuffer, local_answer).await?;

                outbuffer.clear();
                let remote_answer = OutboundMessage::Candidate {
                    peer_info: peer.peer_info.clone(),
                    connection_token: token.clone(),
                };

                if let Err(e) = write_all(&valid_peer.send_stream, outbuffer, remote_answer).await {
                    //log the error but do not fail the
                    trace!(
                        "failed to send candidate : {reason}",
                        reason = e.to_string()
                    );
                }
            }
        }
    }

    Ok(())
}

async fn write_all(
    send: &Arc<Mutex<quinn::SendStream>>,
    mut outbuffer: &mut Vec<u8>,
    data: OutboundMessage,
) -> Result<()> {
    outbuffer.clear();
    bincode::serialize_into(&mut outbuffer, &data)
        .map_err(|e| anyhow!("failed to seliralise Hello answer: {}", e))?;

    let len: u16 = u16::try_from(outbuffer.len())?;
    let len_buff = bincode::serialize(&len)?;

    let mut mut_send = send.lock().await;
    mut_send
        .write_all(&len_buff[..])
        .await
        .map_err(|e| anyhow!("failed to send Hello answer: {}", e))?;

    mut_send
        .write_all(&outbuffer[..])
        .await
        .map_err(|e| anyhow!("failed to send Hello answer: {}", e))?;
    Ok(())
}

struct PeerCleaner {
    peer: Arc<Peer>,
    connection_map: ConnMap,
}
impl Drop for PeerCleaner {
    fn drop(&mut self) {
        let tokens: &Vec<Vec<u8>> = self.peer.connection_tokens.as_ref();

        for token in tokens {
            remove_peer(&self.connection_map, token, &self.peer);
        }
    }
}

fn remove_peer(db: &ConnMap, key: &Vec<u8>, value: &Arc<Peer>) {
    let mut map = db.lock().unwrap();
    let v = map.get_mut(key);
    match v {
        Some(stac) => {
            stac.retain(|x| x.peer_info != value.peer_info);
            if stac.is_empty() {
                map.remove(key);
            }
        }
        None => (),
    };
}

fn insert_peer(db: &ConnMap, key: Vec<u8>, value: &Arc<Peer>) {
    let mut map = db.lock().unwrap();

    let v = map.get_mut(&key);
    match v {
        Some(stac) => stac.push(value.clone()),
        None => {
            map.insert(key, vec![value.clone()]);
        }
    };
}

fn find_matched_peer(db: &ConnMap, key: &Vec<u8>, value: &Arc<Peer>) -> Option<Vec<Arc<Peer>>> {
    let map = db.lock().unwrap();

    let v = map.get(key);
    match v {
        Some(stac) => {
            let res = stac
                .iter()
                .filter(|peer| (peer.peer_info != value.peer_info))
                .filter(|peer| {
                    (peer.peer_info.ip.is_ipv4() && value.peer_info.ip.is_ipv4())
                        || (peer.peer_info.ip.is_ipv6() && value.peer_info.ip.is_ipv6())
                })
                .cloned()
                .collect::<Vec<Arc<Peer>>>();

            if res.len() > 0 {
                return Some(res);
            }
            None
        }

        None => None,
    }
}
