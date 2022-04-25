use quinn::{ClientConfig, Endpoint, Incoming, ServerConfig};
use std::{collections::HashSet, error::Error, net::SocketAddr, sync::Arc};

pub struct P2pEndpoint {
    endpoint: Endpoint,
    incoming: Incoming,
    pub_key: rustls::Certificate,
}
impl P2pEndpoint {
    pub fn new(
        bind_addr: SocketAddr,
        cert_verifier: Arc<ServerCertVerifier>,
    ) -> Result<P2pEndpoint, Box<dyn Error>> {
        let (pub_key, secret_key) = generate_self_signed_certificate();
        let cert_chain = vec![pub_key.clone()];

        let mut server_config = ServerConfig::with_single_cert(cert_chain, secret_key)?;
        Arc::get_mut(&mut server_config.transport)
            .unwrap()
            .max_concurrent_uni_streams(0_u8.into());

        let (mut endpoint, incoming) = Endpoint::server(server_config, bind_addr)?;
        endpoint.set_default_client_config(client_tls_config(cert_verifier));
        Ok(P2pEndpoint {
            endpoint,
            incoming,
            pub_key,
        })
    }
}

/// Constructs a QUIC endpoint configured for use a client only.
///
/// ## Args
///
/// - server_certs: list of trusted certificates.
#[allow(unused)]
pub fn client_endpoint(
    bind_addr: SocketAddr,
    cert_verifier: Arc<ServerCertVerifier>,
) -> Result<Endpoint, Box<dyn Error>> {
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_tls_config(cert_verifier));
    Ok(endpoint)
}

pub struct ServerCertVerifier {
    valid_certificates: HashSet<rustls::Certificate>,
}

impl ServerCertVerifier {
    pub fn new() -> Arc<ServerCertVerifier> {
        Arc::new(ServerCertVerifier {
            valid_certificates: HashSet::new(),
        })
    }

    pub fn add(&mut self, certificate: rustls::Certificate) {
        self.valid_certificates.insert(certificate);
    }

    pub fn remove(&mut self, certificate: &rustls::Certificate) {
        self.valid_certificates.remove(certificate);
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
        if self.valid_certificates.contains(end_entity) {
            Ok(rustls::client::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificateSignature)
        }
    }
}

fn client_tls_config(cert_verifier: Arc<ServerCertVerifier>) -> ClientConfig {
    let tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(cert_verifier)
        .with_no_client_auth();

    ClientConfig::new(Arc::new(tls_config))
}

fn generate_self_signed_certificate() -> (rustls::Certificate, rustls::PrivateKey) {
    let mut param = rcgen::CertificateParams::new(vec!["vault.self.signed".into()]);
    param.alg = &rcgen::PKCS_ED25519;

    let cert = rcgen::Certificate::from_params(param).unwrap();

    let key = cert.serialize_private_key_der();
    let secret_key = rustls::PrivateKey(key);

    let cert = cert.serialize_der().unwrap();
    let pub_key = rustls::Certificate(cert);

    (pub_key, secret_key)
}
