use quinn::{ClientConfig, Endpoint, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use std::{
    collections::HashSet,
    error::Error,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

lazy_static::lazy_static! {
    // I don't know how to do better than a static map to handle cetificate checking
    pub static ref VALID_CERTIFICATES: Arc<Mutex<HashSet<rustls::Certificate>>> =
    Arc::new(Mutex::new(HashSet::new()));
}

pub fn add_valid_certificate(certificate: rustls::Certificate) {
    let mut v = VALID_CERTIFICATES.lock().unwrap();
    v.insert(certificate);
}

pub fn remove_valid_certificate(certificate: &rustls::Certificate) {
    let mut v = VALID_CERTIFICATES.lock().unwrap();
    v.remove(certificate);
}

static KEEP_ALIVE_INTERVAL: u64 = 8;
static MAX_IDLE_TIMEOUT: u32 = 10_000;

pub async fn endpoint(
    bind_addr: SocketAddr,
    pub_key: rustls::Certificate,
    secret_key: rustls::PrivateKey,
) -> Result<Endpoint, Box<dyn Error>> {
    let cert_chain = vec![pub_key];

    let mut server_config = ServerConfig::with_single_cert(cert_chain, secret_key)?;

    let mut transport: TransportConfig = Default::default();
    transport
        .max_concurrent_uni_streams(0_u8.into())
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from(MAX_IDLE_TIMEOUT))));

    server_config.transport = Arc::new(transport);

    let mut endpoint = Endpoint::server(server_config, bind_addr)?;
    endpoint.set_default_client_config(client_tls_config());

    Ok(endpoint)
}

/// Constructs a QUIC endpoint configured for use a client only.
///
/// ## Args
///
/// - server_certs: list of trusted certificates.
#[allow(unused)]
pub fn client_ipv4() -> Result<Endpoint, Box<dyn Error>> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_tls_config());
    Ok(endpoint)
}

pub fn client_ipv6() -> Result<Endpoint, Box<dyn Error>> {
    let mut endpoint = Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_tls_config());
    Ok(endpoint)
}

fn client_tls_config() -> ClientConfig {
    let tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(ServerCertVerifier::new())
        .with_no_client_auth();

    let mut config = ClientConfig::new(Arc::new(tls_config));
    let mut transport: TransportConfig = Default::default();
    transport
        .keep_alive_interval(Some(Duration::new(KEEP_ALIVE_INTERVAL, 0)))
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from(MAX_IDLE_TIMEOUT))));

    config.transport_config(Arc::new(transport));
    config
}

pub struct ServerCertVerifier {}

impl ServerCertVerifier {
    pub fn new() -> Arc<ServerCertVerifier> {
        Arc::new(ServerCertVerifier {})
    }
    pub fn contains(&self, certificate: &rustls::Certificate) -> bool {
        let v = VALID_CERTIFICATES.lock().unwrap();
        v.contains(certificate)
    }
}

impl rustls::client::ServerCertVerifier for ServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        if self.contains(end_entity) {
            Ok(rustls::client::ServerCertVerified::assertion())
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
    use crate::cryptography;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_connection_ipv4() -> Result<(), Box<dyn Error>> {
        let addr = "0.0.0.0:0".parse().unwrap();
        let (pub_key, secret_key) = cryptography::generate_self_signed_certificate();
        add_valid_certificate(pub_key.clone());

        let endpoint = endpoint(addr, pub_key, secret_key).await.unwrap();
        let localadree = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            let incoming_conn = endpoint.accept().await.unwrap();
            let new_conn = incoming_conn.await.unwrap();
            println!(
                "[server] connection accepted: addr={}",
                new_conn.remote_address()
            );
        });

        let endpoint = client_ipv4().unwrap();
        let addr = format!("127.0.0.1:{}", localadree.port()).parse().unwrap();

        let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        println!("[client] connected: addr={}", connection.remote_address());
        // Dropping handles allows the corresponding objects to automatically shut down
        drop(connection);
        // Make sure the server has a chance to clean up
        endpoint.wait_idle().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_connection_ipv6() -> Result<(), Box<dyn Error>> {
        let addr = "[::]:0".parse().unwrap();
        let (pub_key, secret_key) = cryptography::generate_self_signed_certificate();
        add_valid_certificate(pub_key.clone());

        let endpoint = endpoint(addr, pub_key, secret_key).await.unwrap();
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
        println!("[client] connected: addr={}", connection.remote_address());
        // Dropping handles allows the corresponding objects to automatically shut down
        drop(connection);
        // Make sure the server has a chance to clean up
        endpoint.wait_idle().await;

        Ok(())
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn test_invalid_certificate() -> Result<(), Box<dyn Error>> {
        let addr = "[::]:0".parse().unwrap();
        let (pub_key, secret_key) = cryptography::generate_self_signed_certificate();

        // the server's certificate is not added to the valid list
        // add_valid_certificate(pub_key.clone());

        let endpoint = endpoint(addr, pub_key, secret_key).await.unwrap();
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

        Ok(())
    }
}
