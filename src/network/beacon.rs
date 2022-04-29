use serde::{Deserialize, Serialize};

use anyhow::{anyhow, Result};
use futures::StreamExt;
use quinn::{Endpoint, IdleTimeout, ServerConfig, TransportConfig, VarInt};

use std::sync::Mutex as stdMutex;
use std::{collections::HashMap, error::Error, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;

use tracing::{error, info, info_span, trace};
use tracing_futures::Instrument as _;

pub const BEACON_MTU: usize = 1330;
pub static KEEP_ALIVE_INTERVAL: u64 = 8;
pub static MAX_IDLE_TIMEOUT: u32 = 10_000;
const PUBLISH_EVERY_S_HINT: u16 = 60;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum OutboundMessage {
    BeaconParam {
        your_ip: Box<SocketAddr>,
        token: [u8; 4],
        publish_every: u16,
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
    ip: SocketAddr,
    certificate: Vec<u8>,
    pub_key: [u8; 32],
    signature: Vec<u8>,
}
type ConnMap = Arc<stdMutex<HashMap<Vec<u8>, Vec<Arc<Peer>>>>>;

pub fn start_beacon_server(
    bind_addr: SocketAddr,
    pub_key: rustls::Certificate,
    secret_key: rustls::PrivateKey,
) -> Result<Endpoint, Box<dyn Error>> {
    let cert_chain = vec![pub_key.clone()];

    let mut server_config = ServerConfig::with_single_cert(cert_chain, secret_key)?;

    let mut transport: TransportConfig = Default::default();
    transport
        .max_concurrent_uni_streams(0_u8.into())
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from(MAX_IDLE_TIMEOUT))));

    server_config.transport = Arc::new(transport);

    let (endpoint, mut incoming) = Endpoint::server(server_config, bind_addr)?;

    let connection_map: ConnMap = Arc::new(stdMutex::new(HashMap::new()));
    let token: Arc<stdMutex<[u8; 4]>> = Arc::new(stdMutex::new([0_u8; 4]));

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
                if let Err(e) = handle_request(stream, socket_adress.clone(), conn_map, token).await
                {
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

        let message: InbounddMessage = bincode::deserialize(&message_buff)
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
                let peer = Arc::new(Peer {
                    send_stream: send.clone(),
                    peer_info,
                    connection_tokens,
                });
                handle_announce_message(&peer, &connection_map, &mut outbuffer, &send).await?;
                _peer_cleaner = PeerCleaner {
                    peer,
                    connection_map: connection_map.clone(),
                };
            }
        }
    }
}

async fn handle_hello_message(
    adress: &SocketAddr,
    token: &Arc<stdMutex<[u8; 4]>>,
    mut outbuffer: &mut Vec<u8>,
    send: &Arc<Mutex<quinn::SendStream>>,
) -> Result<()> {
    let tok;
    {
        tok = token.lock().unwrap().clone();
    }

    let out = OutboundMessage::BeaconParam {
        your_ip: Box::new(adress.clone()),
        token: tok,
        publish_every: PUBLISH_EVERY_S_HINT,
    };

    outbuffer.clear();
    bincode::serialize_into(&mut outbuffer, &out)
        .map_err(|e| anyhow!("failed to seliralise Hello answer: {}", e))?;

    send.lock()
        .await
        .write_all(&outbuffer[..])
        .await
        .map_err(|e| anyhow!("failed to send Hello answer: {}", e))?;

    Ok(())
}

async fn handle_announce_message(
    peer: &Arc<Peer>,
    connection_map: &ConnMap,
    mut outbuffer: &mut Vec<u8>,
    send: &Arc<Mutex<quinn::SendStream>>,
) -> Result<()> {
    let tokens: &Vec<Vec<u8>> = peer.connection_tokens.as_ref();
    for token in tokens {
        insert_peer(&connection_map, token.clone(), &peer);
        let vp = find_matched_peer(&connection_map, &token, &peer);
        if vp.is_some() {
            for valid_peer in vp.unwrap() {
                outbuffer.clear();
                let local_answer = OutboundMessage::Candidate {
                    peer_info: valid_peer.peer_info.clone(),
                    connection_token: token.clone(),
                };
                bincode::serialize_into(&mut outbuffer, &local_answer)
                    .map_err(|e| anyhow!("failed to serialize answer: {}", e))?;
                {
                    send.lock()
                        .await
                        .write_all(&outbuffer[..])
                        .await
                        .map_err(|e| anyhow!("failed to send answer: {}", e))?;
                }

                outbuffer.clear();
                let remote_answer = OutboundMessage::Candidate {
                    peer_info: peer.peer_info.clone(),
                    connection_token: token.clone(),
                };
                bincode::serialize_into(&mut outbuffer, &remote_answer)
                    .map_err(|e| anyhow!("failed to send response: {}", e))?;

                if let Err(e) = valid_peer
                    .send_stream
                    .lock()
                    .await
                    .write_all(&outbuffer[..])
                    .await
                    .map_err(|e| anyhow!("failed to send response: {}", e))
                {
                    //log the error but do not fail the connection
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
        println!("Removing tokens for {}", self.peer.peer_info.ip);
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
                .filter(|peer| (peer.peer_info.ip.is_ipv4() && value.peer_info.ip.is_ipv4()))
                .filter(|peer| (peer.peer_info.ip.is_ipv6() && value.peer_info.ip.is_ipv6()))
                .cloned()
                .collect::<Vec<Arc<Peer>>>();
            Some(res)
        }

        None => None,
    }
}

#[cfg(test)]
mod test {

    use super::*;
    // #[test]
    // fn test_size() {
    //     println!("Size is {}", std::mem::size_of::<Message>());
    // }
}
