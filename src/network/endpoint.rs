#[cfg(feature = "log")]
use log::{error, info};

use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    ClientConfig, Connection, Endpoint, IdleTimeout, Incoming, RecvStream, SendStream,
    TransportConfig, VarInt,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    ops::Deref,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

use crate::{
    peer_connection_service::{PeerConnectionMessage, PeerConnectionService},
    security::{self, hash, new_uid, random_domain_name, MeetingToken, Uid},
    synchronisation::{Answer, QueryProtocol, RemoteEvent},
};

use super::{
    beacon::BeaconMessage, shared_buffers::SharedBuffers, Announce, ConnectionInfo, Error,
    ALPN_QUIC_HTTP,
};

static MAX_CONNECTION_RETRY: usize = 4;

static CHANNEL_SIZE: usize = 1;

static KEEP_ALIVE_INTERVAL: u64 = 8;
static MAX_IDLE_TIMEOUT: u32 = 10_000;

static ANSWER_STREAM: u8 = 1;
static QUERY_STREAM: u8 = 2;
static EVENT_STREAM: u8 = 3;

pub enum EndpointMessage {
    InitiateConnection(SocketAddr, [u8; 32], Uid, MeetingToken, Vec<u8>),
    InitiateBeaconConnection(SocketAddr, [u8; 32]),
}

pub struct DiscretEndpoint {
    pub id: Uid,
    pub sender: mpsc::Sender<EndpointMessage>,
    pub ipv4_port: u16,
    pub ipv4_cert_hash: [u8; 32],
}
impl DiscretEndpoint {
    pub async fn start(
        peer_service: PeerConnectionService,
        max_buffer_size: usize,
        local_verifying_key: &[u8],
    ) -> Result<Self, Error> {
        let cert_verifier = ServerCertVerifier::new();
        let endpoint_id = new_uid();

        let (sender, mut connection_receiver) = mpsc::channel::<EndpointMessage>(20);

        let cert: rcgen::CertifiedKey = security::generate_x509_certificate(&random_domain_name());
        let ipv4_cert_hash = hash(cert.cert.der().deref());
        let addr = "0.0.0.0:0".parse()?;
        let ipv4_endpoint = build_endpoint(addr, cert, cert_verifier.clone())?;
        let ipv4_port = ipv4_endpoint.local_addr()?.port();

        let ipv4 = ipv4_endpoint.clone();
        let peer_s = peer_service.clone();
        let data_buffer = Arc::new(SharedBuffers::new());
        let shared_buffers = data_buffer.clone();

        let local_verifying_key = local_verifying_key.to_owned();
        tokio::spawn(async move {
            while let Some(msg) = connection_receiver.recv().await {
                match msg {
                    EndpointMessage::InitiateConnection(
                        address,
                        cert_hash,
                        remote_id,
                        meeting_token,
                        peer_verifying_key,
                    ) => {
                        Self::initiate_connection(
                            cert_verifier.clone(),
                            endpoint_id,
                            remote_id,
                            address,
                            cert_hash,
                            meeting_token,
                            peer_verifying_key,
                            local_verifying_key.clone(),
                            &peer_s,
                            &ipv4,
                            &shared_buffers,
                            max_buffer_size,
                        );
                    }
                    EndpointMessage::InitiateBeaconConnection(address, cert_hash) => {
                        Self::initiate_beacon_connection(
                            address,
                            cert_hash,
                            cert_verifier.clone(),
                            &peer_s,
                            &ipv4,
                        )
                        .await;
                    }
                }
            }
        });

        //ipv4 server

        let peer_s = peer_service.clone();

        let b_buffer = data_buffer.clone();

        tokio::spawn(async move {
            while let Some(incoming) = ipv4_endpoint.accept().await {
                let peer_s = peer_s.clone();
                let shared_buffers = b_buffer.clone();
                tokio::spawn(async move {
                    let new_conn =
                        Self::start_accepted(&peer_s, incoming, shared_buffers, max_buffer_size)
                            .await;
                    if let Err(_e) = new_conn {
                        #[cfg(feature = "log")]
                        error!("ipv4 - start_accepted, error: {}", _e);
                    }
                });
            }
        });

        Ok(Self {
            id: endpoint_id,
            sender,
            ipv4_port,
            ipv4_cert_hash,
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn initiate_connection(
        cert_verifier: Arc<ServerCertVerifier>,
        endpoint_id: Uid,
        remote_id: Uid,
        address: SocketAddr,
        cert_hash: [u8; 32],
        meeting_token: MeetingToken,
        peer_verifying_key: Vec<u8>,
        local_verifying_key: Vec<u8>,
        peer_service: &PeerConnectionService,
        ipv4_endpoint: &Endpoint,
        shared_buffers: &Arc<SharedBuffers>,
        max_buffer_size: usize,
    ) {
        let endpoint = ipv4_endpoint.clone();
        let peer_service = peer_service.clone();

        let shared_buffers: Arc<SharedBuffers> = shared_buffers.clone();
        let peer_verifying_key = peer_verifying_key.clone();
        let name = cert_verifier.add_valid_certificate(cert_hash);

        #[cfg(feature = "log")]
        info!(
            "Connecting: {} -> {}",
            &endpoint.local_addr().unwrap(),
            address
        );

        tokio::spawn(async move {
            for i in 0..MAX_CONNECTION_RETRY {
                let conn_result: Result<quinn::Connecting, quinn::ConnectError> =
                    endpoint.connect(address, &name);

                match conn_result {
                    Ok(connecting) => {
                        match connecting.await {
                            Ok(conn) => {
                                let connnection_id = new_uid();
                                let info = ConnectionInfo {
                                    endpoint_id,
                                    remote_id,
                                    conn_id: connnection_id,
                                    meeting_token,
                                    peer_verifying_key,
                                };

                                if let Err(_e) = Self::start_connection(
                                    conn,
                                    &peer_service,
                                    &local_verifying_key,
                                    info,
                                    shared_buffers,
                                    max_buffer_size,
                                )
                                .await
                                {
                                    #[cfg(feature = "log")]
                                    error!(
                                        "InitiateConnection.start_connection error: {}",
                                        crate::Error::from(_e),
                                    );

                                    let _ = &peer_service
                                        .sender
                                        .send(PeerConnectionMessage::PeerConnectionFailed(
                                            endpoint_id,
                                            remote_id,
                                        ))
                                        .await;
                                    return;
                                }
                                break;
                            }
                            Err(_e) => {
                                if i == MAX_CONNECTION_RETRY - 1 {
                                    #[cfg(feature = "log")]
                                    error!(
                                        "InitiateConnection error: {}",
                                        Error::ConnectionFailed(
                                            address.to_string(),
                                            MAX_CONNECTION_RETRY,
                                            _e.to_string(),
                                        ),
                                    );
                                    let _ = &peer_service
                                        .sender
                                        .send(PeerConnectionMessage::PeerConnectionFailed(
                                            endpoint_id,
                                            remote_id,
                                        ))
                                        .await;
                                }
                            }
                        };
                    }
                    Err(_e) => {
                        if i == MAX_CONNECTION_RETRY - 1 {
                            #[cfg(feature = "log")]
                            error!(
                                "InitiateConnection error: {}",
                                crate::Error::from(Error::from(_e)),
                            );

                            let _ = &peer_service
                                .sender
                                .send(PeerConnectionMessage::PeerConnectionFailed(
                                    endpoint_id,
                                    remote_id,
                                ))
                                .await;
                        }
                    }
                };

                let wait = 1 + i;
                tokio::time::sleep(Duration::from_secs(wait.try_into().unwrap())).await;
            }
        });
    }
    async fn start_connection(
        conn: Connection,
        peer_service: &PeerConnectionService,
        local_verifying_key: &[u8],
        info: ConnectionInfo,
        shared_buffers: Arc<SharedBuffers>,
        max_buffer_size: usize,
    ) -> Result<(), Error> {
        let (mut answer_send, answer_receiv) = conn.open_bi().await?;
        answer_send.write_u8(ANSWER_STREAM).await?;

        let (mut query_send, query_receiv) = conn.open_bi().await?;
        query_send.write_u8(QUERY_STREAM).await?;

        let (mut event_send, event_receiv) = conn.open_bi().await?;
        event_send.write_u8(EVENT_STREAM).await?;

        let mut remote_con_msg = info.clone();
        remote_con_msg.peer_verifying_key = local_verifying_key.to_owned();

        let conn_info = bincode::serialize(&remote_con_msg)?;
        event_send
            .write_u32(conn_info.len().try_into().unwrap())
            .await?;
        event_send.write_all(&conn_info).await?;

        Self::start_channels(
            conn,
            peer_service,
            info,
            answer_send,
            answer_receiv,
            query_send,
            query_receiv,
            event_send,
            event_receiv,
            shared_buffers,
            max_buffer_size,
        )
        .await;

        Ok(())
    }

    async fn start_accepted(
        peer_service: &PeerConnectionService,
        incoming: Incoming,
        shared_buffers: Arc<SharedBuffers>,
        max_buffer_size: usize,
    ) -> Result<(), Error> {
        let new_conn = incoming.await?;
        let mut answer_send: Option<SendStream> = None;
        let mut answer_receiv: Option<RecvStream> = None;
        let mut query_send: Option<SendStream> = None;
        let mut query_receiv: Option<RecvStream> = None;
        let mut event_send: Option<SendStream> = None;
        let mut event_receiv: Option<RecvStream> = None;

        for _ in 0..3 {
            let (send, mut recv) = new_conn.accept_bi().await?;
            let flag = recv.read_u8().await?;

            if flag.eq(&ANSWER_STREAM) {
                answer_send = Some(send);
                answer_receiv = Some(recv);
            } else if flag.eq(&QUERY_STREAM) {
                query_send = Some(send);
                query_receiv = Some(recv);
            } else if flag.eq(&EVENT_STREAM) {
                event_send = Some(send);
                event_receiv = Some(recv);
            } else {
                return Err(Error::InvalidStream(flag));
            }
        }

        if answer_send.is_none() || query_send.is_none() || event_send.is_none() {
            return Err(Error::MissingStream());
        }

        let answer_send = answer_send.unwrap();
        let answer_receiv = answer_receiv.unwrap();
        let query_send = query_send.unwrap();
        let query_receiv = query_receiv.unwrap();
        let event_send = event_send.unwrap();
        let mut event_receiv = event_receiv.unwrap();

        let len = event_receiv.read_u32().await?;
        let len: usize = len.try_into().unwrap();
        let mut buf = vec![0; len];

        event_receiv.read_exact(&mut buf[0..len]).await?;
        let remote_info: ConnectionInfo = bincode::deserialize(&buf)?;

        Self::start_channels(
            new_conn,
            peer_service,
            remote_info,
            answer_send,
            answer_receiv,
            query_send,
            query_receiv,
            event_send,
            event_receiv,
            shared_buffers,
            max_buffer_size,
        )
        .await;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_channels(
        conn: Connection,
        peer_service: &PeerConnectionService,
        info: ConnectionInfo,
        mut answer_send: SendStream,
        mut answer_receiv: RecvStream,
        mut query_send: SendStream,
        mut query_receiv: RecvStream,
        mut event_send: SendStream,
        mut event_receiv: RecvStream,
        shared_buffers: Arc<SharedBuffers>,

        max_buffer_size: usize,
    ) {
        //process Answsers
        let (in_answer_sd, in_answer_rcv) = mpsc::channel::<Answer>(CHANNEL_SIZE);
        let shared_b = shared_buffers.clone();
        tokio::spawn(async move {
            loop {
                let len = answer_receiv.read_u32().await;
                if len.is_err() {
                    break;
                }
                let len: usize = len.unwrap().try_into().unwrap();
                if len > max_buffer_size {
                    break;
                }

                let mut buffer = shared_b.take();

                if buffer.len() < len {
                    buffer.resize(len, 0);
                }

                let answer_bytes = answer_receiv.read_exact(&mut buffer[0..len]).await;
                if answer_bytes.is_err() {
                    shared_b.release(buffer);
                    break;
                }

                let answer: Result<Answer, Box<bincode::ErrorKind>> =
                    bincode::deserialize(&buffer[0..len]);

                if answer.is_err() {
                    shared_b.release(buffer);
                    break;
                }
                shared_b.release(buffer);

                let answer = answer.unwrap();
                let _ = in_answer_sd.send(answer).await;
            }
        });

        let (out_answer_sd, mut out_answer_rcv) = mpsc::channel::<Answer>(CHANNEL_SIZE);
        let shared_b = shared_buffers.clone();
        tokio::spawn(async move {
            while let Some(answer) = out_answer_rcv.recv().await {
                let mut buffer = shared_b.take();
                buffer.clear();

                let serialised =
                    bincode::serialize_into::<&mut Vec<u8>, Answer>(&mut buffer, &answer);
                if serialised.is_err() {
                    shared_b.release(buffer);
                    break;
                }

                let sent = answer_send.write_u32(buffer.len() as u32).await;
                if sent.is_err() {
                    shared_b.release(buffer);
                    break;
                }
                let sent = answer_send.write_all(&buffer).await;
                if sent.is_err() {
                    shared_b.release(buffer);
                    break;
                }
                shared_b.release(buffer);
            }
        });

        //process Queries
        let (in_query_sd, in_query_rcv) = mpsc::channel::<QueryProtocol>(CHANNEL_SIZE);
        let shared_b = shared_buffers.clone();
        tokio::spawn(async move {
            loop {
                let len = query_receiv.read_u32().await;
                if len.is_err() {
                    break;
                }
                let len: usize = len.unwrap().try_into().unwrap();
                if len > max_buffer_size {
                    break;
                }

                let mut buffer = shared_b.take();

                if buffer.len() < len {
                    buffer.resize(len, 0);
                }

                let answer_bytes = query_receiv.read_exact(&mut buffer[0..len]).await;
                if answer_bytes.is_err() {
                    shared_b.release(buffer);
                    break;
                }

                let query: Result<QueryProtocol, Box<bincode::ErrorKind>> =
                    bincode::deserialize(&buffer[0..len]);

                if query.is_err() {
                    shared_b.release(buffer);
                    break;
                }
                shared_b.release(buffer);

                let query = query.unwrap();
                let _ = in_query_sd.send(query).await;
            }
        });

        let (out_query_sd, mut out_query_rcv) = mpsc::channel::<QueryProtocol>(CHANNEL_SIZE);
        let shared_b = shared_buffers.clone();
        tokio::spawn(async move {
            while let Some(query) = out_query_rcv.recv().await {
                let mut buffer = shared_b.take();
                buffer.clear();

                let serialised =
                    bincode::serialize_into::<&mut Vec<u8>, QueryProtocol>(&mut buffer, &query);
                if serialised.is_err() {
                    shared_b.release(buffer);
                    break;
                }

                let sent = query_send.write_u32(buffer.len() as u32).await;
                if sent.is_err() {
                    shared_b.release(buffer);
                    break;
                }
                let sent = query_send.write_all(&buffer).await;

                if sent.is_err() {
                    shared_b.release(buffer);
                    break;
                }
                shared_b.release(buffer);
            }
        });

        //process remote Events
        let (in_event_sd, in_event_rcv) = mpsc::channel::<RemoteEvent>(CHANNEL_SIZE);
        let shared_b = shared_buffers.clone();
        tokio::spawn(async move {
            loop {
                let len = event_receiv.read_u32().await;
                if len.is_err() {
                    break;
                }
                let len: usize = len.unwrap().try_into().unwrap();
                if len > max_buffer_size {
                    break;
                }

                let mut buffer = shared_b.take();

                if buffer.len() < len {
                    buffer.resize(len, 0);
                }

                let answer_bytes = event_receiv.read_exact(&mut buffer[0..len]).await;
                if answer_bytes.is_err() {
                    shared_b.release(buffer);
                    break;
                }

                let event: Result<RemoteEvent, Box<bincode::ErrorKind>> =
                    bincode::deserialize(&buffer[0..len]);

                if event.is_err() {
                    shared_b.release(buffer);
                    break;
                }
                shared_b.release(buffer);
                let event = event.unwrap();
                let _ = in_event_sd.send(event).await;
            }
        });

        let (out_event_sd, mut out_event_rcv) = mpsc::channel::<RemoteEvent>(CHANNEL_SIZE);
        let shared_b = shared_buffers.clone();
        tokio::spawn(async move {
            while let Some(event) = out_event_rcv.recv().await {
                let mut buffer = shared_b.take();
                buffer.clear();

                let serialised =
                    bincode::serialize_into::<&mut Vec<u8>, RemoteEvent>(&mut buffer, &event);
                if serialised.is_err() {
                    shared_b.release(buffer);
                    break;
                }

                let sent = event_send.write_u32(buffer.len().try_into().unwrap()).await;
                if sent.is_err() {
                    shared_b.release(buffer);
                    break;
                }
                let sent = event_send.write_all(&buffer).await;

                if sent.is_err() {
                    shared_b.release(buffer);
                    break;
                }
                shared_b.release(buffer);
            }
        });

        let _ = peer_service
            .sender
            .send(PeerConnectionMessage::NewConnection(
                Some(conn),
                info,
                out_answer_sd,
                in_answer_rcv,
                out_query_sd,
                in_query_rcv,
                out_event_sd,
                in_event_rcv,
            ))
            .await;
    }

    pub async fn initiate_beacon_connection(
        address: SocketAddr,
        cert_hash: [u8; 32],
        cert_verifier: Arc<ServerCertVerifier>,
        peer_service: &PeerConnectionService,
        ipv4_endpoint: &Endpoint,
    ) {
        let peer_service = peer_service.clone();
        let name = cert_verifier.add_valid_certificate(cert_hash);

        #[cfg(feature = "log")]
        info!(
            "Connecting to beacon: {} -> {}",
            ipv4_endpoint.local_addr().unwrap(),
            address
        );

        let endpoint = ipv4_endpoint.clone();
        tokio::spawn(async move {
            let conn_result: Result<quinn::Connecting, quinn::ConnectError> =
                endpoint.connect(address, &name);
            match conn_result {
                Ok(connecting) => match connecting.await {
                    Ok(conn) => {
                        if let Err(e) = Self::start_beacon_client(conn, &peer_service).await {
                            let _ = &peer_service
                                .sender
                                .send(PeerConnectionMessage::BeaconConnectionFailed(
                                    address,
                                    e.to_string(),
                                ))
                                .await;
                        }
                    }
                    Err(e) => {
                        let _ = &peer_service
                            .sender
                            .send(PeerConnectionMessage::BeaconConnectionFailed(
                                address,
                                e.to_string(),
                            ))
                            .await;
                    }
                },
                Err(e) => {
                    let _ = &peer_service
                        .sender
                        .send(PeerConnectionMessage::BeaconConnectionFailed(
                            address,
                            e.to_string(),
                        ))
                        .await;
                }
            }
        });
    }

    pub async fn start_beacon_client(
        conn: Connection,
        peer_service: &PeerConnectionService,
    ) -> Result<(), Error> {
        let (mut beacon_send_stream, mut beacon_recv_stream) = conn.open_bi().await?;
        beacon_send_stream.write_u8(ANSWER_STREAM).await?;

        let (beacon_send, mut beacon_recv) = mpsc::channel::<Announce>(1);

        let _ = &peer_service
            .sender
            .send(PeerConnectionMessage::BeaconConnected(
                conn.remote_address(),
                beacon_send,
            ))
            .await;
        let peer_s = peer_service.clone();
        let con = conn.clone();
        tokio::spawn(async move {
            while let Some(announce) = beacon_recv.recv().await {
                let bin = bincode::serialize(&announce);
                if bin.is_err() {
                    break;
                }
                let bin = bin.unwrap();
                let sent = beacon_send_stream.write_u32(bin.len() as u32).await;
                if sent.is_err() {
                    break;
                }
                let sent = beacon_send_stream.write_all(&bin).await;
                if sent.is_err() {
                    break;
                }
            }
            con.close(VarInt::from(1_u8), "".as_bytes());
            let _ = &peer_s
                .sender
                .send(PeerConnectionMessage::BeaconDisconnected(
                    con.remote_address(),
                ))
                .await;
        });

        let peer_s = peer_service.clone();
        let con = conn.clone();
        tokio::spawn(async move {
            let mut buffer: Vec<u8> = vec![0; 512];
            loop {
                let len = beacon_recv_stream.read_u32().await;
                if len.is_err() {
                    break;
                }
                let len: usize = len.unwrap().try_into().unwrap();
                if len > buffer.len() {
                    println!("beacon response too large");
                    break;
                }
                let answer_bytes = beacon_recv_stream.read_exact(&mut buffer[0..len]).await;
                if answer_bytes.is_err() {
                    break;
                }

                let msg: Result<BeaconMessage, Box<bincode::ErrorKind>> =
                    bincode::deserialize(&buffer[0..len]);
                if msg.is_err() {
                    break;
                }

                let msg = msg.unwrap();
                match msg {
                    BeaconMessage::InitiateConnection(header, adress, token) => {
                        let _ = &peer_s
                            .sender
                            .send(PeerConnectionMessage::BeaconInitiateConnection(
                                adress, header, token,
                            ))
                            .await;
                    }
                }
            }

            con.close(VarInt::from(1_u8), "".as_bytes());
            let _ = &peer_s
                .sender
                .send(PeerConnectionMessage::BeaconDisconnected(
                    con.remote_address(),
                ))
                .await;
        });

        Ok(())
    }
}

pub fn build_endpoint(
    bind_addr: SocketAddr,
    certificate: rcgen::CertifiedKey,
    cert_verifier: Arc<ServerCertVerifier>,
) -> Result<Endpoint, Error> {
    let cert_der = CertificateDer::from(certificate.cert);
    let priv_key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], priv_key.into())?;

    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    let mut endpoint = Endpoint::server(server_config, bind_addr)?;
    endpoint.set_default_client_config(client_tls_config(cert_verifier)?);
    Ok(endpoint)
}

fn client_tls_config(cert_verifier: Arc<ServerCertVerifier>) -> Result<ClientConfig, Error> {
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(cert_verifier)
        .with_no_client_auth();

    tls_config.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let quick_client_config = Arc::new(QuicClientConfig::try_from(tls_config)?);

    let mut config = ClientConfig::new(quick_client_config);

    let mut transport: TransportConfig = Default::default();
    transport
        .keep_alive_interval(Some(Duration::new(KEEP_ALIVE_INTERVAL, 0)))
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from(MAX_IDLE_TIMEOUT))));

    config.transport_config(Arc::new(transport));
    Ok(config)
}

lazy_static::lazy_static! {
    pub static ref VALID_CERTIFICATES: Arc<std::sync::Mutex<HashSet<[u8; 32]>>> =
    Arc::new(std::sync::Mutex::new(HashSet::new()));
}

#[derive(Debug)]
pub struct ServerCertVerifier {
    provider: rustls::crypto::CryptoProvider,
    valid_certificates: std::sync::Mutex<HashMap<String, [u8; 32]>>,
}

impl ServerCertVerifier {
    pub fn new() -> Arc<ServerCertVerifier> {
        Arc::new(ServerCertVerifier {
            provider: rustls::crypto::ring::default_provider(),
            valid_certificates: std::sync::Mutex::new(HashMap::new()),
        })
    }

    pub fn add_valid_certificate(&self, certificate: [u8; 32]) -> String {
        let mut v = self.valid_certificates.lock().unwrap();
        let mut name = random_domain_name();
        while v.contains_key(&name) {
            name = random_domain_name();
        }

        v.insert(name.clone(), certificate);
        name
    }

    pub fn get(&self, name: &str) -> Option<[u8; 32]> {
        let v = self.valid_certificates.lock().unwrap();
        let g = v.get(name);
        g.copied()
    }
    // pub fn remove_valid_certificate(&self, name: &str) {
    //     let mut v = self.valid_certificates.lock().unwrap();
    //     v.remove(name);
    // }
}

impl rustls::client::danger::ServerCertVerifier for ServerCertVerifier {
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let server_name = server_name.to_str().to_string();
        let cert = self.get(&server_name);
        match cert {
            Some(cert) => {
                let hash = &hash(end_entity.deref());
                if cert.eq(hash) {
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ))
                }
            }
            None => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{date_utils::now, security};

    #[tokio::test(flavor = "multi_thread")]
    async fn test_connection_ipv4() {
        let addr = "0.0.0.0:0".parse().unwrap();

        let cert: rcgen::CertifiedKey = security::generate_x509_certificate("server_one.me");
        let der = cert.cert.der().deref();
        let hasshe = hash(der);
        let cert_verifier = ServerCertVerifier::new();
        let con_name_one = cert_verifier.add_valid_certificate(hasshe);

        let endpoint_one = build_endpoint(addr, cert, cert_verifier.clone()).unwrap();
        let localaddress_one = endpoint_one.local_addr().unwrap();
        let endpoint = endpoint_one.clone();
        tokio::spawn(async move {
            loop {
                let incoming_conn = endpoint.accept().await.unwrap();
                let new_conn = incoming_conn.await.unwrap();
                let (_, mut receiv) = new_conn.accept_bi().await.unwrap();
                let number = receiv.read_i32().await.unwrap();
                println!(
                    "[server one] connection accepted: addr={} received {}",
                    new_conn.remote_address(),
                    number
                );
            }
        });

        let cert = security::generate_x509_certificate("server_two.me");
        let der = cert.cert.der().deref();
        let hasshe = hash(der);
        let con_name_two = cert_verifier.add_valid_certificate(hasshe);

        let endpoint_two = build_endpoint(addr, cert, cert_verifier).unwrap();
        let localaddress_two = endpoint_two.local_addr().unwrap();
        let endpoint = endpoint_two.clone();
        tokio::spawn(async move {
            loop {
                let incoming_conn = endpoint.accept().await.unwrap();
                let new_conn = incoming_conn.await.unwrap();
                let (_, mut receiv) = new_conn.accept_bi().await.unwrap();
                let number = receiv.read_i32().await.unwrap();
                println!(
                    "[server two] connection accepted: addr={} received: {}",
                    new_conn.remote_address(),
                    number
                );
            }
        });

        let addr_one = format!("127.0.0.1:{}", localaddress_one.port())
            .parse()
            .unwrap();

        let connection_two = endpoint_two
            .connect(addr_one, &con_name_one)
            .unwrap()
            .await
            .unwrap();

        let (mut send, _) = connection_two.open_bi().await.unwrap();
        send.write_i32(222222).await.unwrap();

        let addr_two = format!("127.0.0.1:{}", localaddress_two.port())
            .parse()
            .unwrap();

        let connection_one = endpoint_one
            .connect(addr_two, &con_name_two)
            .unwrap()
            .await
            .unwrap();

        let (mut send, _) = connection_one.open_bi().await.unwrap();
        send.write_i32(111111).await.unwrap();

        let connection_one = endpoint_one
            .connect(addr_two, &con_name_two)
            .unwrap()
            .await
            .unwrap();
        let (mut send, _) = connection_one.open_bi().await.unwrap();
        send.write_i32(33333).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        println!("{}: end", now());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_connection_ipv6() {
        let addr = "[::]:0".parse().unwrap();

        let cert = security::generate_x509_certificate("hello.world");
        let der = cert.cert.der().deref();
        let hash = hash(der);
        let cert_verifier = ServerCertVerifier::new();
        let conn_name = cert_verifier.add_valid_certificate(hash);

        let endpoint = build_endpoint(addr, cert, cert_verifier.clone()).unwrap();
        let localadree = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            let incoming_conn = endpoint.accept().await.unwrap();
            let new_conn = incoming_conn.await.unwrap();
            println!(
                "[server] connection accepted: addr= {}",
                new_conn.remote_address()
            );
        });

        let cert = security::generate_x509_certificate("hello.world.de");
        let endpoint = build_endpoint(addr, cert, cert_verifier).unwrap();
        let addr = format!("[::1]:{}", localadree.port()).parse().unwrap();

        let connection = endpoint.connect(addr, &conn_name).unwrap().await.unwrap();

        println!("[client] connected: addr={}", connection.remote_address());
        // Dropping handles allows the corresponding objects to automatically shut down
        drop(connection);
        // Make sure the server has a chance to clean up
        endpoint.wait_idle().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_invalid_server_name() {
        let addr = "[::]:0".parse().unwrap();
        let cert = security::generate_x509_certificate("hello.world");
        let der = cert.cert.der().deref();
        let hash = hash(der);
        let cert_verifier = ServerCertVerifier::new();
        cert_verifier.add_valid_certificate(hash);

        let endpoint = build_endpoint(addr, cert, cert_verifier.clone()).unwrap();

        let localadree = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            let incoming_conn = endpoint.accept().await.unwrap();
            incoming_conn
                .await
                .expect_err("connection should have failed due to invalid certificate");
        });

        let cert = security::generate_x509_certificate("invalid.me");
        let endpoint = build_endpoint(addr, cert, cert_verifier).unwrap();
        let addr = format!("[::1]:{}", localadree.port()).parse().unwrap();

        endpoint
            .connect(addr, "invalid.me")
            .unwrap()
            .await
            .expect_err("connection should have failed due to invalid certificate");

        endpoint.wait_idle().await;
    }
}
