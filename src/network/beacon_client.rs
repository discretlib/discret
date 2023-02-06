use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::{ClientConfig, IdleTimeout, TransportConfig, VarInt};
use serde::Deserialize;
use serde::Serialize;
use tokio::sync::mpsc::{self, Sender};
use tokio::time::sleep;
use tracing::debug;

use crate::cryptography::ALPN_QUIC_HTTP;
use crate::message::Message;
use crate::network::beacon_server::OutboundMessage;
use crate::network::beacon_server::PeerInfo;

use super::beacon_server::InbounddMessage;
use super::beacon_server::Token;
use super::beacon_server::BEACON_MTU;
use super::beacon_server::KEEP_ALIVE_INTERVAL;
use super::beacon_server::MAX_IDLE_TIMEOUT;
use super::beacon_server::MAX_PUBLISH_RATE_SEC;
use super::error::Error;

pub const BEACON_DATA_SIZE: usize = BEACON_MTU - 2;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct PeerRequest {
    certificate: Vec<u8>,
    signature: Vec<u8>,
    connection_tokens: Vec<Token>,
}

struct AnnounceBuilder {
    adress: Option<SocketAddr>,
    peer_request: Option<PeerRequest>,
}
impl AnnounceBuilder {
    fn is_ready(&self) -> bool {
        self.adress.is_some() && self.peer_request.is_some()
    }

    fn build(&self) -> InbounddMessage {
        let pr = self.peer_request.clone().unwrap();
        let pi = PeerInfo {
            ip: self.adress.unwrap(),
            certificate: pr.certificate,
            signature: pr.signature,
        };
        InbounddMessage::Announce {
            peer_info: Box::new(pi),
            connection_tokens: pr.connection_tokens,
        }
    }
}

pub async fn star_beacon_client(
    beacon_adress: SocketAddr,
    mut send_to: Sender<Result<Message, Error>>,
) -> Result<Sender<PeerRequest>, Error> {
    let (sender, mut internal_reciever) = mpsc::channel(1);

    let bind_adress: SocketAddr = if beacon_adress.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    let mut endpoint = quinn::Endpoint::client(bind_adress)?;
    endpoint.set_default_client_config(client_tls_config());

    let new_conn = endpoint.connect(beacon_adress, "_")?.await?;


    let (mut send_stream, mut receiv_stream): (quinn::SendStream, quinn::RecvStream) =
    new_conn.open_bi().await?;

    tokio::spawn(async move {
        let mut write_buffer: Vec<u8> = Vec::with_capacity(BEACON_MTU);
        let mut read_header: [u8; 2] = [0_u8; 2];
        let mut read_buffer: [u8; BEACON_DATA_SIZE] = [0_u8; BEACON_DATA_SIZE];

        let mut annouce_builder = AnnounceBuilder {
            adress: None,
            peer_request: None,
        };
        //send first hello
        write_all(
            &mut send_stream,
            &mut write_buffer,
            InbounddMessage::Hello {},
            &mut send_to,
        )
        .await;
        loop {
            tokio::select! {
                peer_request = internal_reciever.recv() => {
                    if peer_request.is_none() {
                        return;
                    }
                    let previously_not_ready:bool  = !annouce_builder.is_ready();
                    annouce_builder.peer_request= peer_request;
                    if annouce_builder.is_ready() && previously_not_ready{
                        send_announce_if_ready(
                            &annouce_builder,
                            &mut send_stream,
                            &mut write_buffer,
                            &mut send_to,
                        ).await;
                    };
                },
                read_fut = receiv_stream.read_exact(&mut read_header) => {
                    handle_response(
                            read_fut,
                            &mut receiv_stream,
                            &read_header,
                            &mut read_buffer,
                            &mut send_to,
                            &mut annouce_builder,
                            &mut send_stream,
                            &mut write_buffer,
                        ).await;
                },
                _ = sleep(Duration::from_secs(MAX_PUBLISH_RATE_SEC)) => {
                    write_all(&mut send_stream, &mut write_buffer,InbounddMessage::Hello {  }, &mut send_to).await;
                },
            };
        }
    });

    Ok(sender)
}

async fn send_announce_if_ready(
    annouce_builder: &AnnounceBuilder,
    send_stream: &mut quinn::SendStream,
    write_buffer: &mut Vec<u8>,
    error_channel: &mut Sender<Result<Message, Error>>,
) {
    if annouce_builder.is_ready() {
        write_all(
            send_stream,
            write_buffer,
            annouce_builder.build(),
            error_channel,
        )
        .await;
    }
}

async fn write_all(
    send_stream: &mut quinn::SendStream,
    mut write_buffer: &mut Vec<u8>,
    data: InbounddMessage,
    error_channel: &mut Sender<Result<Message, Error>>,
) {
    let err: Result<(), Error> = async {
        write_buffer.clear();
        bincode::serialize_into(&mut write_buffer, &data)?;

        if write_buffer.len() > (BEACON_DATA_SIZE) {
            return Err(Error::MsgSerialisationToLong(
                write_buffer.len(),
                BEACON_DATA_SIZE,
            ));
        }
        let len: u16 =
            u16::try_from(write_buffer.len()).map_err(|e| Error::Unknown(e.to_string()))?;
        let len_buff = bincode::serialize(&len)?;

        send_stream.write_all(&len_buff).await?;
        send_stream.write_all(write_buffer).await?;

        Ok(())
    }
    .await;
    if let Err(e) = err {
        let _ = error_channel.send(Err(e)).await;
    }
}
#[allow(clippy::too_many_arguments)]
async fn handle_response(
    read_fut: Result<(), quinn::ReadExactError>,
    receiv: &mut quinn::RecvStream,
    read_header: &[u8; 2],
    read_buffer: &mut [u8; BEACON_DATA_SIZE],
    send_to: &mut Sender<Result<Message, Error>>,
    annouce_builder: &mut AnnounceBuilder,
    send_stream: &mut quinn::SendStream,
    write_buffer: &mut Vec<u8>,
) {
    let err: Result<(), Error> = async {
        read_fut.map_err(Error::from)?;
        let res: u16 = bincode::deserialize(read_header)?;

        let res = usize::from(res);
        if res > read_buffer.len() {
            return Err(Error::MsgDeserialisationToLong(res, read_buffer.len()));
        }

        receiv.read_exact(&mut read_buffer[0..res]).await?;

        let message: OutboundMessage = bincode::deserialize(&read_buffer[0..res])?;

        match message {
            OutboundMessage::BeaconParam {
                your_ip,
                hash_token: token,
            } => {
                annouce_builder.adress = Some(*your_ip);
                let _t = token;

                send_announce_if_ready(annouce_builder, send_stream, write_buffer, send_to).await;
            }
            OutboundMessage::Candidate {
                peer_info,
                connection_token,
            } => {
                debug!("Candidate received {}", &peer_info.ip);
                let _ = send_to
                    .send(Ok(Message::BeaconCandidate {
                        peer_info,
                        connection_token,
                    }))
                    .await;
            }
        };
        Ok(())
    }
    .await;
    if let Err(e) = err {
        let _ = send_to.send(Err(e)).await;
    }
}

fn client_tls_config() -> ClientConfig {
    let mut tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(ServerCertVerifier {}))
        .with_no_client_auth();
    tls_config.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    let mut config = ClientConfig::new(Arc::new(tls_config));
    let mut transport: TransportConfig = Default::default();
    transport
        .keep_alive_interval(Some(Duration::new(KEEP_ALIVE_INTERVAL, 0)))
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from(MAX_IDLE_TIMEOUT))));

        config.transport_config(Arc::new(transport));
    config
}

pub struct ServerCertVerifier {}
impl rustls::client::ServerCertVerifier for ServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[cfg(test)]
mod test {

    // use std::thread;

    //use tracing::Level;

    use super::*;
    use crate::{
        cryptography::generate_self_signed_certificate,
        network::beacon_server::{start_beacon_server, TOKEN_SIZE},
    };

    #[test]
    fn test_max_token() -> Result<(), Box<dyn std::error::Error>> {
        let (pub_key, _secret_key) = generate_self_signed_certificate();
        let serialised_cert = pub_key.as_ref().clone();
        let vect = Vec::from(serialised_cert);
        let s: SocketAddr = "[::]:0".parse().unwrap();

        let pi = PeerInfo {
            ip: s,
            certificate: vect,
            signature: vec![1_u8; 64],
        };
        let msg = InbounddMessage::Announce {
            peer_info: Box::new(pi.clone()),
            connection_tokens: vec![],
        };
        let val = bincode::serialize(&msg).unwrap();
        println!("header len: {}", val.len());
        let mut v: Vec<Token> = vec![];
        for i in 0..100 {
            v.push([i; TOKEN_SIZE]);
        }

        let msg = InbounddMessage::Announce {
            peer_info: Box::new(pi),
            connection_tokens: v,
        };
        let val = bincode::serialize(&msg).unwrap();
        println!("message len: {}", val.len());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn beacon_discovery_test() -> Result<(), Box<dyn std::error::Error>> {
        // tracing_subscriber::fmt()
        //     .with_max_level(tracing::Level::DEBUG)
        //     .init();

        let bind_addr: SocketAddr = "0.0.0.0:4242".parse().unwrap();
        let (pub_key, secret_key) = generate_self_signed_certificate();
        start_beacon_server(bind_addr, pub_key, secret_key)?;

        let beacon_adress: SocketAddr = "127.0.0.1:4242".parse().unwrap();

        let valid_token = [1_u8; TOKEN_SIZE];

        let (cli1_send, mut cli1_receiv) = mpsc::channel(5);
        let client1 = star_beacon_client(beacon_adress, cli1_send).await?;
        let req = PeerRequest {
            certificate: vec![1_u8, 1, 1],
            signature: vec![1_u8, 1, 1],
            connection_tokens: vec![valid_token.clone(), [2; TOKEN_SIZE]],
        };

        let (cli2_send, mut cli2_receiv) = mpsc::channel(5);
        let client2 = star_beacon_client(beacon_adress, cli2_send).await?;
        let req2 = PeerRequest {
            certificate: vec![2_u8, 2, 2],
            signature: vec![2_u8, 2, 2],
            connection_tokens: vec![valid_token.clone()],
        };
        let _s = client2.send(req2).await?;
        let _s = client1.send(req).await?;

        let candidate1 = cli1_receiv.recv().await.unwrap()?;

        match candidate1 {
            Message::BeaconCandidate {
                peer_info: _,
                connection_token: _,
            } => assert!(true),
            _ => assert!(false),
        }
        let candidate2 = cli2_receiv.recv().await.unwrap()?;
        match candidate2 {
            Message::BeaconCandidate {
                peer_info: _,
                connection_token: _,
            } => assert!(true),
            _ => assert!(false),
        }
        Ok(())
    }
}
