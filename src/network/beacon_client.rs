use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::{ClientConfig, IdleTimeout, TransportConfig, VarInt};
use serde::Deserialize;
use serde::Serialize;
use tokio::sync::mpsc::{self, Sender};
use tokio::time::sleep;

use crate::network::beacon_server::OutboundMessage;
use crate::network::beacon_server::PeerInfo;
use crate::{error::Error, message::Message};

use super::beacon_server::InbounddMessage;
use super::beacon_server::BEACON_MTU;
use super::beacon_server::KEEP_ALIVE_INTERVAL;
use super::beacon_server::MAX_IDLE_TIMEOUT;
use super::beacon_server::PUBLISH_EVERY_S_HINT;
use super::multicast::Announce;

pub const BEACON_DATA_SIZE: usize = BEACON_DATA_SIZE;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct PeerRequest {
    certificate: Vec<u8>,
    pub_key: [u8; 32],
    signature: Vec<u8>,
    connection_tokens: Vec<Vec<u8>>,
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
        let pr = &self.peer_request.clone().unwrap();
        let pi = PeerInfo {
            ip: &self.adress.unwrap().clone(),
            certificate: pr.certificate,
            pub_key: pr.pub_key,
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

    let bind_adress: SocketAddr;
    if beacon_adress.is_ipv4() {
        bind_adress = "0.0.0.0:0".parse().unwrap();
    } else {
        bind_adress = "[::]:0".parse().unwrap();
    }

    let mut endpoint = quinn::Endpoint::client(bind_adress)?;
    endpoint.set_default_client_config(client_tls_config());

    let new_conn = endpoint.connect(beacon_adress, "")?.await?;
    let quinn::NewConnection {
        connection: conn, ..
    } = new_conn;

    let (mut send_stream, mut receiv_stream): (quinn::SendStream, quinn::RecvStream) =
        conn.open_bi().await?;

    tokio::spawn(async move {
        let mut write_buffer: Vec<u8> = Vec::with_capacity(BEACON_MTU);
        let mut read_header: [u8; 2] = [0_u8; 2];
        let mut read_buffer: [u8; 1328] = [0_u8; BEACON_DATA_SIZE];

        let mut annouce_builder = AnnounceBuilder {
            adress: None,
            peer_request: None,
        };

        loop {
            tokio::select! {
                peer_request = internal_reciever.recv() => {
                    if peer_request.is_none() {
                        return;
                    }
                    annouce_builder.peer_request= peer_request;
                },
                read_fut = receiv_stream.read_exact(&mut read_header) => {
                    handle_response(
                            read_fut,
                            &mut receiv_stream,
                            &read_header,
                            &mut read_buffer,
                            &mut send_to,
                            &mut annouce_builder
                        ).await;
                },
                _ = sleep(PUBLISH_EVERY_S_HINT) => {

                    write_all(&mut send_stream, &mut write_buffer,InbounddMessage::Hello {  }, &mut send_to).await;

                },
            };

            if annouce_builder.is_ready() {
                write_all(
                    &mut send_stream,
                    &mut write_buffer,
                    annouce_builder.build(),
                    &mut send_to,
                )
                .await;
            }
        }
    });

    Ok(sender)
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
        send_stream.write_all(&write_buffer).await?;

        Ok(())
    }
    .await;
    if let Err(e) = err {
        let _ = error_channel.send(Err(e)).await;
    }
}

async fn handle_response(
    read_fut: Result<(), quinn::ReadExactError>,
    receiv: &mut quinn::RecvStream,
    read_header: &[u8; 2],
    read_buffer: &mut [u8; BEACON_DATA_SIZE],
    send_to: &mut Sender<Result<Message, Error>>,
    annouce_builder: &mut AnnounceBuilder,
) {
    let err: Result<(), Error> = async {
        read_fut.map_err(|e| Error::from(e))?;
        let res: u16 = bincode::deserialize(read_header)?;

        let res = usize::from(res);
        if res > read_buffer.len() {
            return Err(Error::MsgDeserialisationToLong(res, read_buffer.len()));
        }

        receiv.read_exact(&mut read_buffer[0..res]).await?;

        let message: OutboundMessage = bincode::deserialize(&read_buffer[0..res])?;

        match message {
            OutboundMessage::BeaconParam { your_ip, token } => {
                annouce_builder.adress = Some(*your_ip);
                let _t = token;
            }
            OutboundMessage::Candidate {
                peer_info,
                connection_token,
            } => {
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
    let tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(ServerCertVerifier {}))
        .with_no_client_auth();

    let mut config = ClientConfig::new(Arc::new(tls_config));
    let mut transport: TransportConfig = Default::default();
    transport
        .keep_alive_interval(Some(Duration::new(KEEP_ALIVE_INTERVAL, 0)))
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from(MAX_IDLE_TIMEOUT))));

    config.transport = Arc::new(transport);
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
