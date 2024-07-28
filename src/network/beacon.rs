use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use quinn::{crypto::rustls::QuicServerConfig, Connection, Endpoint, Incoming, SendStream, VarInt};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

use crate::{log_service::LogService, security::MeetingToken};

use super::{
    peer_manager::MAX_MESSAGE_SIZE, shared_buffers::SharedBuffers, Announce, AnnounceHeader,
    ALPN_QUIC_HTTP,
};

#[derive(Serialize, Deserialize)]
pub enum BeaconMessage {
    InitiateConnection(AnnounceHeader, SocketAddr, MeetingToken),
}

pub struct Beacon {}
impl Beacon {
    pub fn start(
        ipv4_port: u16,
        ipv6_port: u16,
        der: Vec<u8>,
        pks_der: Vec<u8>,
        log_service: LogService,
        num_buffers: usize,
    ) -> Result<Self, super::Error> {
        let input_buffers = Arc::new(tokio::sync::Mutex::new(SharedBuffers::new(num_buffers)));

        let ipv4_addr: SocketAddr = format!("0.0.0.0:{}", ipv4_port).parse()?;
        let ipv4_endpoint = Self::enpoint(ipv4_addr, der.clone(), pks_der.clone())?;
        Self::start_endpoint(
            ipv4_endpoint,
            log_service.clone(),
            input_buffers.clone(),
            MAX_MESSAGE_SIZE,
        );
        let ipv6_addr: SocketAddr = format!("[::]:{}", ipv6_port).parse()?;
        let ipv6_endpoint = Self::enpoint(ipv6_addr, der, pks_der)?;
        Self::start_endpoint(
            ipv6_endpoint,
            log_service.clone(),
            input_buffers,
            MAX_MESSAGE_SIZE,
        );
        Ok(Self {})
    }

    fn enpoint(addr: SocketAddr, der: Vec<u8>, pks_der: Vec<u8>) -> Result<Endpoint, super::Error> {
        let cert_der = CertificateDer::from(der);
        let priv_key = PrivatePkcs8KeyDer::from(pks_der);
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], priv_key.into())?;

        server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.max_concurrent_uni_streams(0_u8.into());

        Ok(Endpoint::server(server_config, addr)?)
    }

    fn start_endpoint(
        endpoint: Endpoint,
        logs: LogService,
        input_buffers: Arc<Mutex<SharedBuffers>>,
        max_buffer_size: usize,
    ) {
        tokio::spawn(async move {
            let meeting_point: Arc<Mutex<MeetingPoint>> = Arc::new(Mutex::new(MeetingPoint {
                meeting: HashMap::new(),
                buffer: Vec::new(),
            }));

            while let Some(incoming) = endpoint.accept().await {
                let input_buffers = input_buffers.clone();
                let logs = logs.clone();
                let meeting_point = meeting_point.clone();
                tokio::spawn(async move {
                    let new_conn = Self::start_accepted(
                        incoming,
                        input_buffers,
                        max_buffer_size,
                        meeting_point,
                    )
                    .await;
                    if let Err(e) = new_conn {
                        logs.error("ipv4 - start_accepted".to_string(), crate::Error::from(e));
                    }
                });
            }
        });
    }

    async fn start_accepted(
        incoming: Incoming,
        input_buffers: Arc<Mutex<SharedBuffers>>,
        max_buffer_size: usize,
        meeting_point: Arc<Mutex<MeetingPoint>>,
    ) -> Result<(), super::Error> {
        let new_conn = incoming.await?;
        let (send, mut recv) = new_conn.accept_bi().await?;

        recv.read_u8().await?;

        let ibuff = input_buffers.clone();
        tokio::spawn(async move {
            let id = new_conn.stable_id();
            let conn_info: Arc<Mutex<ConnectionInfo>> = Arc::new(Mutex::new(ConnectionInfo {
                conn: new_conn,
                sender: send,
                header: None,
            }));
            let mut header_initialised = false;
            let mut last_tokens: HashSet<MeetingToken> = HashSet::new();
            loop {
                let len = recv.read_u32().await;
                if len.is_err() {
                    break;
                }
                let len: usize = len.unwrap().try_into().unwrap();
                if len > max_buffer_size {
                    break;
                }

                let mut buf_lock = ibuff.lock().await;
                let arc_buf = buf_lock.get();
                drop(buf_lock);
                let mut buffer = arc_buf.lock().await;

                if buffer.len() < len {
                    buffer.resize(len, 0);
                }

                let answer_bytes = recv.read_exact(&mut buffer[0..len]).await;
                if answer_bytes.is_err() {
                    break;
                }
                let announce: Result<Announce, Box<bincode::ErrorKind>> =
                    bincode::deserialize(&buffer[0..len]);
                drop(buffer);

                if announce.is_err() {
                    break;
                }

                let announce = announce.unwrap();
                if !header_initialised {
                    let header = announce.header;

                    let mut info_lock = conn_info.lock().await;
                    info_lock.header = Some(header);
                    drop(info_lock);

                    header_initialised = true;
                }

                let new_tokens: HashSet<MeetingToken> =
                    HashSet::from_iter(announce.tokens.into_iter());

                let to_remove: HashSet<&MeetingToken> =
                    last_tokens.difference(&new_tokens).collect();

                let to_add: HashSet<&MeetingToken> = new_tokens.difference(&last_tokens).collect();

                let mut meeting = meeting_point.lock().await;

                meeting.remove_tokens(id, &to_remove).await;
                meeting.add_tokens(id, &to_add, &conn_info).await;

                last_tokens = new_tokens;
            }
            let mut to_remove: HashSet<&MeetingToken> = HashSet::with_capacity(last_tokens.len());
            for s in &last_tokens {
                to_remove.insert(s);
            }
            let mut meeting = meeting_point.lock().await;
            meeting.remove_tokens(id, &to_remove).await;
        });

        Ok(())
    }
}

struct MeetingPoint {
    meeting: HashMap<MeetingToken, Vec<Arc<Mutex<ConnectionInfo>>>>,
    buffer: Vec<u8>,
}
impl MeetingPoint {
    pub async fn add_tokens(
        &mut self,
        id: usize,
        tokens: &HashSet<&MeetingToken>,
        conn: &Arc<Mutex<ConnectionInfo>>,
    ) {
        for token in tokens {
            let entry = self.meeting.entry(**token).or_default();
            let mut insert = true;
            for other_conn in entry.iter() {
                let mut other_peer = other_conn.lock().await;
                if other_peer.conn.stable_id() == id {
                    insert = false;
                } else {
                    let mut this_peer = conn.lock().await;
                    let this_msg = BeaconMessage::InitiateConnection(
                        other_peer.header.clone().unwrap(),
                        other_peer.conn.remote_address(),
                        **token,
                    );
                    self.buffer.clear();
                    bincode::serialize_into::<&mut Vec<u8>, _>(&mut self.buffer, &this_msg)
                        .unwrap();

                    if this_peer
                        .sender
                        .write_u32(self.buffer.len() as u32)
                        .await
                        .is_err()
                    {
                        this_peer.conn.close(VarInt::from_u32(1), "".as_bytes());
                        break;
                    }
                    if this_peer.sender.write_all(&self.buffer).await.is_err() {
                        this_peer.conn.close(VarInt::from_u32(1), "".as_bytes());
                        break;
                    }

                    let other_msg = BeaconMessage::InitiateConnection(
                        this_peer.header.clone().unwrap(),
                        this_peer.conn.remote_address(),
                        **token,
                    );
                    self.buffer.clear();
                    bincode::serialize_into::<&mut Vec<u8>, _>(&mut self.buffer, &other_msg)
                        .unwrap();

                    if other_peer
                        .sender
                        .write_u32(self.buffer.len() as u32)
                        .await
                        .is_err()
                    {
                        other_peer.conn.close(VarInt::from_u32(1), "".as_bytes());
                    }

                    if other_peer.sender.write_all(&self.buffer).await.is_err() {
                        other_peer.conn.close(VarInt::from_u32(1), "".as_bytes());
                    }

                    // println!(
                    //     "Beacon connect {} <-> {}",
                    //     this_peer.conn.remote_address(),
                    //     other_peer.conn.remote_address()
                    // );
                }
            }
            if insert {
                entry.push(conn.clone())
            }
        }
    }

    pub async fn remove_tokens(&mut self, id: usize, tokens: &HashSet<&MeetingToken>) {
        for token in tokens {
            if let Some(entry) = self.meeting.get_mut(*token) {
                let mut index = -1;
                for i in 0..entry.len() {
                    let peer = entry[i].lock().await;
                    if peer.conn.stable_id() == id {
                        index = i as i32;
                        break;
                    }
                }
                if index >= 0 {
                    entry.remove(index as usize);
                }
            }
        }
    }
}

struct ConnectionInfo {
    conn: Connection,
    sender: SendStream,
    header: Option<AnnounceHeader>,
}
