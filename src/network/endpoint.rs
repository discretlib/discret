use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    ClientConfig, Connection, Endpoint, IdleTimeout, Incoming, RecvStream, SendStream,
    TransportConfig, VarInt,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::{
    collections::HashSet,
    net::SocketAddr,
    ops::Deref,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

use crate::{
    log_service::LogService,
    peer_connection_service::{ConnectionInfo, PeerConnectionMessage, PeerConnectionService},
    security::{self, hash, new_uid, Uid},
    synchronisation::{Answer, QueryProtocol, RemoteEvent},
};

use super::Error;
static MAX_CONNECTION_RETRY: usize = 3;

static CHANNEL_SIZE: usize = 4;

static KEEP_ALIVE_INTERVAL: u64 = 8;
static MAX_IDLE_TIMEOUT: u32 = 10_000;

static ANSWER_STREAM: u8 = 1;
static QUERY_STREAM: u8 = 2;
static EVENT_STREAM: u8 = 3;

pub enum EndpointMessage {
    InitiateConnection(SocketAddr, [u8; 32], bool),
}

pub struct DiscretEndpoint {
    sender: mpsc::Sender<EndpointMessage>,
    ipv4_port: u16,
    ipv6_port: Option<u16>,
}
impl DiscretEndpoint {
    pub async fn start(
        peer_service: PeerConnectionService,
        log: LogService,
        verifying_key: Vec<u8>,
    ) -> Result<Self, Error> {
        let endpoint_id = new_uid();
        let (hardware_key, hardware_name) = security::hardware_fingerprint();
        let (sender, mut connection_receiver) = mpsc::channel::<EndpointMessage>(20);
        let cert: rcgen::CertifiedKey = security::generate_x509_certificate();

        let addr = "0.0.0.0:0".parse()?;
        let ipv4_endpoint = build_endpoint(addr, cert)?;
        let ipv4_port = ipv4_endpoint.local_addr()?.port();

        let cert: rcgen::CertifiedKey = security::generate_x509_certificate();
        let addr = "[::]:0".parse()?;

        let ipv6_endpoint = build_endpoint(addr, cert);
        let (ipv6_endpoint, ipv6_port) = match ipv6_endpoint {
            Ok(end) => {
                let ipv6_port = end.local_addr()?.port();
                (Some(end), Some(ipv6_port))
            }
            Err(_) => (None, None),
        };

        let ipv4 = ipv4_endpoint.clone();
        let ipv6 = ipv6_endpoint.clone();
        let logs = log.clone();
        let peer_s = peer_service.clone();
        tokio::spawn(async move {
            while let Some(msg) = connection_receiver.recv().await {
                match msg {
                    EndpointMessage::InitiateConnection(address, cert_hash, send_hardware) => {
                        Self::initiate_connection(
                            endpoint_id,
                            address,
                            cert_hash,
                            &peer_s,
                            &logs,
                            &ipv4,
                            &ipv6,
                            &verifying_key,
                            send_hardware,
                            &hardware_key,
                            &hardware_name,
                        );
                    }
                }
            }
        });

        let logs = log.clone();
        let peer_s = peer_service.clone();

        //ipv4 server
        tokio::spawn(async move {
            while let Some(incoming) = ipv4_endpoint.accept().await {
                let new_conn = Self::start_accepted(&peer_s, incoming).await;
                if let Err(e) = new_conn {
                    logs.error(
                        "Incoming connection".to_string(),
                        crate::Error::from(Error::from(e)),
                    );
                }
            }
        });

        //ipv6 server
        let logs = log.clone();
        if let Some(endpoint) = ipv6_endpoint {
            tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let new_conn = Self::start_accepted(&peer_service, incoming).await;
                    if let Err(e) = new_conn {
                        logs.error(
                            "Incoming connection".to_string(),
                            crate::Error::from(Error::from(e)),
                        );
                    }
                }
            });
        }

        Ok(Self {
            sender,
            ipv4_port,
            ipv6_port,
        })
    }

    async fn start_accepted(
        peer_service: &PeerConnectionService,
        incoming: Incoming,
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
        let mut buf: Vec<u8> = Vec::with_capacity(len.try_into().unwrap());
        event_receiv.read_exact(&mut buf).await?;
        let info: ConnectionInfo = bincode::deserialize(&buf)?;

        Self::start_channels(
            peer_service,
            info,
            answer_send,
            answer_receiv,
            query_send,
            query_receiv,
            event_send,
            event_receiv,
        )
        .await;

        Ok(())
    }

    fn initiate_connection(
        endpoint_id: Uid,
        address: SocketAddr,
        cert_hash: [u8; 32],
        peer_service: &PeerConnectionService,
        log: &LogService,
        ipv4_endpoint: &Endpoint,
        ipv6_endpoint: &Option<Endpoint>,
        verifying_key: &Vec<u8>,
        send_hardware: bool,
        hardware_key: &[u8; 32],
        hardware_name: &str,
    ) {
        add_valid_certificate(cert_hash);
        let log = log.clone();
        let endpoint = if address.is_ipv4() {
            ipv4_endpoint.clone()
        } else {
            match ipv6_endpoint {
                Some(endpoint) => endpoint.clone(),
                None => {
                    log.error(
                        "IPV6 not supported".to_string(),
                        crate::Error::from(Error::IPV6NotSuported()),
                    );
                    return;
                }
            }
        };
        let peer_service = peer_service.clone();
        let verifying_key = verifying_key.clone();
        let hardware_key = hardware_key.clone();
        let hardware_name = hardware_name.to_string();
        tokio::spawn(async move {
            for i in 0..MAX_CONNECTION_RETRY {
                let conn_result: Result<quinn::Connecting, quinn::ConnectError> =
                    endpoint.connect(address, "");

                match conn_result {
                    Ok(connecting) => {
                        match connecting.await {
                            Ok(conn) => {
                                let connnection_id = new_uid();

                                let (hardware_key, hardware_name) = if send_hardware {
                                    (Some(hardware_key), Some(hardware_name.clone()))
                                } else {
                                    (None, None)
                                };

                                let info = ConnectionInfo {
                                    endpoint_id,
                                    connnection_id,
                                    verifying_key: verifying_key.clone(),
                                    hardware_key: hardware_key,
                                    hardware_name: hardware_name,
                                };

                                if let Err(e) =
                                    Self::start_connection(conn, &peer_service, info).await
                                {
                                    log.error(
                                        "InitiateConnection.start_connection".to_string(),
                                        crate::Error::from(e),
                                    );
                                    return;
                                };
                            }
                            Err(e) => {
                                if i == MAX_CONNECTION_RETRY - 1 {
                                    log.error(
                                        "InitiateConnection".to_string(),
                                        crate::Error::from(Error::ConnectionFailed(
                                            address.to_string(),
                                            MAX_CONNECTION_RETRY,
                                            e.to_string(),
                                        )),
                                    );
                                }
                            }
                        };
                    }
                    Err(e) => {
                        log.error(
                            "InitiateConnection".to_string(),
                            crate::Error::from(Error::from(e)),
                        );
                        break;
                    }
                };
            }
        });
    }
    async fn start_connection(
        conn: Connection,
        peer_service: &PeerConnectionService,
        info: ConnectionInfo,
    ) -> Result<(), Error> {
        let (mut answer_send, answer_receiv) = conn.open_bi().await?;
        answer_send.write_u8(ANSWER_STREAM).await?;

        let (mut query_send, query_receiv) = conn.open_bi().await?;
        query_send.write_u8(QUERY_STREAM).await?;

        let (mut event_send, event_receiv) = conn.open_bi().await?;
        event_send.write_u8(EVENT_STREAM).await?;
        let conn_info = bincode::serialize(&info)?;
        event_send
            .write_u32(conn_info.len().try_into().unwrap())
            .await?;
        event_send.write_all(&conn_info).await?;

        Self::start_channels(
            peer_service,
            info,
            answer_send,
            answer_receiv,
            query_send,
            query_receiv,
            event_send,
            event_receiv,
        )
        .await;

        Ok(())
    }

    async fn start_channels(
        peer_service: &PeerConnectionService,
        info: ConnectionInfo,
        mut answer_send: SendStream,
        mut answer_receiv: RecvStream,
        mut query_send: SendStream,
        mut query_receiv: RecvStream,
        mut event_send: SendStream,
        mut event_receiv: RecvStream,
    ) {
        //process Answsers
        let (in_answer_sd, in_answer_rcv) = mpsc::channel::<Answer>(CHANNEL_SIZE);
        tokio::spawn(async move {
            let mut buffer: Vec<u8> = Vec::new();
            loop {
                buffer.clear();
                let len = answer_receiv.read_u32().await;
                if len.is_err() {
                    break;
                }
                let len: usize = len.unwrap().try_into().unwrap();
                if buffer.capacity() < len {
                    buffer.reserve_exact(len - buffer.capacity());
                } else {
                    buffer.shrink_to(len);
                }

                let answer_bytes = answer_receiv.read_exact(&mut buffer).await;
                if answer_bytes.is_err() {
                    break;
                }

                let answer: Result<Answer, Box<bincode::ErrorKind>> = bincode::deserialize(&buffer);
                if answer.is_err() {
                    break;
                }
                let answer = answer.unwrap();
                let _ = in_answer_sd.send(answer).await;
            }
        });

        let (out_answer_sd, mut out_answer_rcv) = mpsc::channel::<Answer>(CHANNEL_SIZE);
        tokio::spawn(async move {
            let mut buffer: Vec<u8> = Vec::new();
            while let Some(answer) = out_answer_rcv.recv().await {
                buffer.clear();
                let serialised =
                    bincode::serialize_into::<&mut Vec<u8>, Answer>(&mut buffer, &answer);
                if serialised.is_err() {
                    break;
                }

                let sent = answer_send
                    .write_u32(buffer.len().try_into().unwrap())
                    .await;
                if sent.is_err() {
                    break;
                }
                let sent = answer_send.write_all(&buffer).await;
                if sent.is_err() {
                    break;
                }
            }
        });

        //process Queries
        let (in_query_sd, in_query_rcv) = mpsc::channel::<QueryProtocol>(CHANNEL_SIZE);
        tokio::spawn(async move {
            let mut buffer: Vec<u8> = Vec::new();
            loop {
                buffer.clear();
                let len = query_receiv.read_u32().await;
                if len.is_err() {
                    break;
                }
                let len: usize = len.unwrap().try_into().unwrap();

                if buffer.capacity() < len {
                    buffer.reserve_exact(len - buffer.capacity());
                } else {
                    buffer.shrink_to(len);
                }

                let answer_bytes = query_receiv.read(&mut buffer).await;
                if answer_bytes.is_err() {
                    break;
                }

                let query: Result<QueryProtocol, Box<bincode::ErrorKind>> =
                    bincode::deserialize(&buffer);
                if query.is_err() {
                    break;
                }
                let query = query.unwrap();
                let _ = in_query_sd.send(query).await;
            }
        });

        let (out_query_sd, mut out_query_rcv) = mpsc::channel::<QueryProtocol>(CHANNEL_SIZE);
        tokio::spawn(async move {
            let mut buffer: Vec<u8> = Vec::new();
            while let Some(query) = out_query_rcv.recv().await {
                buffer.clear();
                let serialised =
                    bincode::serialize_into::<&mut Vec<u8>, QueryProtocol>(&mut buffer, &query);
                if serialised.is_err() {
                    break;
                }

                let sent = query_send.write_u32(buffer.len().try_into().unwrap()).await;
                if sent.is_err() {
                    break;
                }
                let sent = query_send.write_all(&buffer).await;
                if sent.is_err() {
                    break;
                }
            }
        });

        //process remote Events
        let (in_event_sd, in_event_rcv) = mpsc::channel::<RemoteEvent>(CHANNEL_SIZE);
        tokio::spawn(async move {
            let mut buffer: Vec<u8> = Vec::new();
            loop {
                buffer.clear();
                let len = event_receiv.read_u32().await;
                if len.is_err() {
                    break;
                }
                let len: usize = len.unwrap().try_into().unwrap();

                if buffer.capacity() < len {
                    buffer.reserve_exact(len - buffer.capacity());
                } else {
                    buffer.shrink_to(len);
                }

                let answer_bytes = event_receiv.read(&mut buffer).await;
                if answer_bytes.is_err() {
                    break;
                }

                let event: Result<RemoteEvent, Box<bincode::ErrorKind>> =
                    bincode::deserialize(&buffer);
                if event.is_err() {
                    break;
                }
                let event = event.unwrap();
                let _ = in_event_sd.send(event).await;
            }
        });

        let (out_event_sd, mut out_event_rcv) = mpsc::channel::<RemoteEvent>(CHANNEL_SIZE);
        tokio::spawn(async move {
            let mut buffer: Vec<u8> = Vec::new();
            while let Some(event) = out_event_rcv.recv().await {
                buffer.clear();
                let serialised =
                    bincode::serialize_into::<&mut Vec<u8>, RemoteEvent>(&mut buffer, &event);
                if serialised.is_err() {
                    break;
                }

                let sent = event_send.write_u32(buffer.len().try_into().unwrap()).await;
                if sent.is_err() {
                    break;
                }
                let sent = event_send.write_all(&buffer).await;
                if sent.is_err() {
                    break;
                }
            }
        });

        let _ = peer_service
            .sender
            .send(PeerConnectionMessage::NewPeer(
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
}

pub fn build_endpoint(
    bind_addr: SocketAddr,
    certificate: rcgen::CertifiedKey,
) -> Result<Endpoint, Error> {
    let cert_der = CertificateDer::from(certificate.cert);
    let priv_key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], priv_key.into())?;

    server_crypto.alpn_protocols = security::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    let mut endpoint = Endpoint::server(server_config, bind_addr)?;
    endpoint.set_default_client_config(client_tls_config()?);
    Ok(endpoint)
}
/// Constructs a QUIC endpoint configured for use a client only.
///
/// ## Args
///
/// - server_certs: list of trusted certificates.
pub fn client_ipv4() -> Result<Endpoint, Error> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_tls_config()?);
    Ok(endpoint)
}

pub fn client_ipv6() -> Result<Endpoint, Error> {
    let mut endpoint = Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_tls_config()?);
    Ok(endpoint)
}

fn client_tls_config() -> Result<ClientConfig, Error> {
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(ServerCertVerifier::new())
        .with_no_client_auth();

    tls_config.alpn_protocols = security::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

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
    pub static ref VALID_CERTIFICATES: Arc<Mutex<HashSet<[u8; 32]>>> =
    Arc::new(Mutex::new(HashSet::new()));
}

pub fn add_valid_certificate(certificate: [u8; 32]) {
    let mut v = VALID_CERTIFICATES.lock().unwrap();
    v.insert(certificate);
}

pub fn remove_valid_certificate(sert_hash: &[u8; 32]) {
    let mut v = VALID_CERTIFICATES.lock().unwrap();
    v.remove(sert_hash);
}
#[derive(Debug)]
pub struct ServerCertVerifier {
    provider: rustls::crypto::CryptoProvider,
}

impl ServerCertVerifier {
    pub fn new() -> Arc<ServerCertVerifier> {
        Arc::new(ServerCertVerifier {
            provider: rustls::crypto::ring::default_provider(),
        })
    }
    pub fn contains(&self, cert: &[u8]) -> bool {
        let v = VALID_CERTIFICATES.lock().unwrap();
        v.contains(cert)
    }
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
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let hash = &hash(end_entity.deref());
        if self.contains(hash) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::security;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_connection_ipv4() {
        let addr = "0.0.0.0:0".parse().unwrap();
        let cert: rcgen::CertifiedKey = security::generate_x509_certificate();
        let der = cert.cert.der().deref();
        let hash = hash(der);
        add_valid_certificate(hash);

        let endpoint = build_endpoint(addr, cert).unwrap();
        let localadree = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            let incoming_conn = endpoint.accept().await.unwrap();
            let new_conn = incoming_conn.await.unwrap();
            println!(
                "[server] connection accepted: addr={}",
                new_conn.remote_address()
            );
        });
        let cert = security::generate_x509_certificate();
        let endpoint = build_endpoint(addr, cert).unwrap();
        let addr = format!("127.0.0.1:{}", localadree.port()).parse().unwrap();

        let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        //connection.open_bi();
        println!("[client] connected: addr={}", connection.remote_address());
        // Dropping handles allows the corresponding objects to automatically shut down
        drop(connection);
        // Make sure the server has a chance to clean up
        endpoint.wait_idle().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_connection_ipv6() {
        let addr = "[::]:0".parse().unwrap();
        let cert = security::generate_x509_certificate();
        let der = cert.cert.der().deref();
        let hash = hash(der);
        add_valid_certificate(hash);

        let endpoint = build_endpoint(addr, cert).unwrap();
        let localadree = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            let incoming_conn = endpoint.accept().await.unwrap();
            let new_conn = incoming_conn.await.unwrap();
            println!(
                "[server] connection accepted: addr={}",
                new_conn.remote_address()
            );
        });

        let endpoint = client_ipv6().unwrap();
        let addr = format!("[::1]:{}", localadree.port()).parse().unwrap();

        let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        // let (send, receiv) = connection.open_bi().await.unwrap();
        // send.write_all(buf).await;

        //let s = connection.accept_bi().await.unwrap();

        println!("[client] connected: addr={}", connection.remote_address());
        // Dropping handles allows the corresponding objects to automatically shut down
        drop(connection);
        // Make sure the server has a chance to clean up
        endpoint.wait_idle().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_invalid_certificate() {
        let addr = "[::]:0".parse().unwrap();
        let cert = security::generate_x509_certificate();
        //let pub_key = cert.key_pair.public_key_der();
        // the server's certificate is not added to the valid list
        // add_valid_certificate(pub_key.clone());
        //add_valid_public_key(pub_key);

        let endpoint = build_endpoint(addr, cert).unwrap();

        let localadree = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            let incoming_conn = endpoint.accept().await.unwrap();
            incoming_conn
                .await
                .expect_err("connection should have failed due to invalid certificate");
        });

        let endpoint = client_ipv6().unwrap();
        let addr = format!("[::1]:{}", localadree.port()).parse().unwrap();

        endpoint
            .connect(addr, "localhost")
            .unwrap()
            .await
            .expect_err("connection should have failed due to invalid certificate");

        endpoint.wait_idle().await;
    }
}
