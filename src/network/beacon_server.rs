use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use anyhow::{anyhow, Result};

use quinn::{Endpoint, IdleTimeout, TransportConfig, VarInt, ConnectionError};

use std::sync::Mutex as stdMutex;
use std::time::{Duration, Instant};
use std::{collections::HashMap, error::Error, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;

use crate::cryptography::ALPN_QUIC_HTTP;
use tracing::{debug, error, info, trace};


pub const BEACON_MTU: usize = 1200;
pub const KEEP_ALIVE_INTERVAL: u64 = 8;
pub const MAX_IDLE_TIMEOUT: u32 = 10_000;
pub const MAX_PUBLISH_RATE_SEC: u64 = 2;

type ConnMap = Arc<stdMutex<HashMap<Token, Vec<Arc<Peer>>>>>;
pub const TOKEN_SIZE: usize = 8;
pub type Token = [u8; TOKEN_SIZE];

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum OutboundMessage {
    BeaconParam {
        your_ip: Box<SocketAddr>,
        hash_token: Token,
    },
    Candidate {
        peer_info: Box<PeerInfo>,
        connection_token: Token,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum InbounddMessage {
    Hello {},
    Announce {
        peer_info: Box<PeerInfo>,
        connection_tokens: Vec<Token>,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct PeerInfo {
    pub ip: SocketAddr,
    pub certificate: Vec<u8>,
    pub signature: Vec<u8>,
}

struct Peer {
    send_stream: Arc<Mutex<quinn::SendStream>>,
    peer_info: Box<PeerInfo>,
    connection_tokens: Vec<Token>,
}

pub fn start_beacon_server(
    bind_addr: SocketAddr,
    pub_key: rustls::Certificate,
    secret_key: rustls::PrivateKey,
) -> Result<(), Box<dyn Error>> {
    let cert_chain = vec![pub_key];

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

    let endpoint = Endpoint::server(server_config, bind_addr)?;
    println!("{}", endpoint.local_addr().unwrap());
    let connection_map: ConnMap = Arc::new(stdMutex::new(HashMap::new()));

    let mut csprng = OsRng {};
    let mut random: Token = [0_u8; TOKEN_SIZE];
    csprng.fill_bytes(&mut random);
    let token: Arc<stdMutex<Token>> = Arc::new(stdMutex::new(random));

    tokio::spawn(async move {
        while let Some(conn) = endpoint.accept().await {
            info!("connection incoming");
            let fut = handle_connection(conn, connection_map.clone(), token.clone());
            tokio::spawn(async move {
                if let Err(e) = fut.await {
                    error!("connection failed: {reason}", reason = e.to_string())
                }
            });
        }
    });

    Ok(())
}

async fn handle_connection(
    connection: quinn::Connecting,
    connection_map: ConnMap,
    token: Arc<stdMutex<Token>>,
) -> Result<(), ConnectionError> {


        info!("established");
        let socket_adress = connection.remote_address();
  
        let conn = match connection.await {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                info!("connection closed");
                return Ok(());
            }
            Err(e) => {
                return Err(e);
            }
            Ok(s) => s,
        };



        
            let stream = match conn.accept_bi().await {
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
        
        Ok(())

}

async fn handle_request(
    (send, mut recv): (quinn::SendStream, quinn::RecvStream),
    adress: SocketAddr,
    connection_map: ConnMap,
    token: Arc<stdMutex<Token>>,
) -> Result<()> {
    const MAX_LENGTH: usize = BEACON_MTU - 2;

    let send: Arc<Mutex<quinn::SendStream>> = Arc::new(Mutex::new(send));
    let mut _peer_cleaner: PeerCleaner;
    let mut instant: Option<Instant> = None;

    loop {
        let mut message_length_buff = [0_u8; 2];

        recv.read_exact(&mut message_length_buff)
            .await
            .map_err(|e| anyhow!("failed reading request: {}", e))?;

        let len: u16 = bincode::deserialize(&message_length_buff)
            .map_err(|e| anyhow!("failed deserialise request: {}", e))?;

        let len = usize::from(len);
        if len > MAX_LENGTH {
            return Err(anyhow!("message lenght too large: {}", len));
        }
        let mut message_buff = vec![0; len]; //do not allocat array outside the look to quikly free memory
        recv.read_exact(&mut message_buff[0..len])
            .await
            .map_err(|e| anyhow!("failed reading request: {}", e))?;

        let message: InbounddMessage = bincode::deserialize(&message_buff[0..len])
            .map_err(|e| anyhow!("failed deserialise request: {}", e))?;

        match message {
            InbounddMessage::Hello {} => {
                handle_hello_message(&adress, &token, &send).await?;
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
                handle_announce_message(peer, &connection_map, &send).await?;
            }
        }
    }
    Ok(())
}

async fn handle_hello_message(
    adress: &SocketAddr,
    token: &Arc<stdMutex<Token>>,
    send: &Arc<Mutex<quinn::SendStream>>,
) -> Result<()> {
    let mut outbuffer: Vec<u8> = Vec::with_capacity(128);
    let tok;
    {
        tok = *token.lock().unwrap();
    }

    let out = OutboundMessage::BeaconParam {
        your_ip: Box::new(*adress),
        hash_token: tok,
    };

    write_all(send, &mut outbuffer, out).await?;
    Ok(())
}

async fn handle_announce_message(
    peer: Arc<Peer>,
    connection_map: &ConnMap,
    send: &Arc<Mutex<quinn::SendStream>>,
) -> Result<()> {
    debug!("Received Announce from  {}", peer.peer_info.ip);
    let mut outbuffer: Vec<u8> = Vec::with_capacity(256); //avoid realocating buffer reallocate buffer every time
    let tokens: &Vec<Token> = peer.connection_tokens.as_ref();
    for token in tokens {
        insert_peer(connection_map, *token, &peer);
        let vp = find_matched_peer(connection_map, token, &peer);
        if vp.is_some() {
            for valid_peer in vp.unwrap() {
                let local_answer = OutboundMessage::Candidate {
                    peer_info: valid_peer.peer_info.clone(),
                    connection_token: *token,
                };
                write_all(send, &mut outbuffer, local_answer).await?;

                let remote_answer = OutboundMessage::Candidate {
                    peer_info: peer.peer_info.clone(),
                    connection_token: *token,
                };

                if let Err(e) =
                    write_all(&valid_peer.send_stream, &mut outbuffer, remote_answer).await
                {
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
        let tokens: &Vec<Token> = self.peer.connection_tokens.as_ref();

        for token in tokens {
            remove_peer(&self.connection_map, token, &self.peer);
        }
    }
}

fn remove_peer(db: &ConnMap, key: &Token, value: &Arc<Peer>) {
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

fn insert_peer(db: &ConnMap, key: Token, value: &Arc<Peer>) {
    let mut map = db.lock().unwrap();

    let v = map.get_mut(&key);
    match v {
        Some(stac) => stac.push(value.clone()),
        None => {
            map.insert(key, vec![value.clone()]);
        }
    };
}

fn find_matched_peer(db: &ConnMap, key: &Token, value: &Arc<Peer>) -> Option<Vec<Arc<Peer>>> {
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

            if !res.is_empty() {
                return Some(res);
            }
            None
        }

        None => None,
    }
}
