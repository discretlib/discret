use std::{collections::HashMap, net::SocketAddr};

use quinn::{Connection, VarInt};
use tokio::sync::mpsc;

use crate::{
    base64_decode, base64_encode,
    database::{graph_database::GraphDatabaseService, system_entities::AllowedPeer},
    network::endpoint::EndpointMessage,
    security::{MeetingSecret, MeetingToken},
    signature_verification_service::SignatureVerificationService,
    Uid,
};

use super::{endpoint::DiscretEndpoint, multicast::MulticastMessage, Announce, AnnounceHeader};

//indicate that an other connection has be kept
const ERROR_CONN_ELECTION: u16 = 1;

//A technical error has occured
const ERROR_TECHNICAL: u16 = 2;

pub struct PeerManager {
    pub endpoint: DiscretEndpoint,
    pub multicast_discovery: mpsc::Sender<MulticastMessage>,
    pub private_room_id: Uid,
    pub verifying_key: Vec<u8>,
    pub meeting_secret: MeetingSecret,
    pub allowed_peers: Vec<AllowedPeer>,

    pub allowed_token: HashMap<MeetingToken, Vec<Vec<u8>>>,

    connection_progress: HashMap<Uid, bool>,
    connected: HashMap<Uid, (Connection, Uid)>,

    db: GraphDatabaseService,
    verify_service: SignatureVerificationService,

    ipv4_header: AnnounceHeader,
    ipv6_header: Option<AnnounceHeader>,
}
impl PeerManager {
    pub async fn new(
        endpoint: DiscretEndpoint,
        multicast_discovery: mpsc::Sender<MulticastMessage>,
        db: GraphDatabaseService,
        verify_service: SignatureVerificationService,
        private_room_id: Uid,
        verifying_key: Vec<u8>,
        meeting_secret: MeetingSecret,
    ) -> Result<Self, crate::Error> {
        let allowed_peers = db.get_allowed_peers(private_room_id).await?;
        let mut allowed_token: HashMap<MeetingToken, Vec<Vec<u8>>> = HashMap::new();
        for peers in &allowed_peers {
            let token = MeetingSecret::decode_token(&peers.meeting_token)?;
            let entry = allowed_token.entry(token).or_default();
            let verifying_key = base64_decode(peers.peer.verifying_key.as_bytes())?;

            entry.push(verifying_key);
        }

        let mut ipv4_header = AnnounceHeader {
            endpoint_id: endpoint.id,
            port: endpoint.ipv4_port,
            certificate_hash: endpoint.ipv4_cert_hash,
            ..Default::default()
        };

        let (_verifying, signature) = db.sign(ipv4_header.hash_for_signature().to_vec()).await;
        ipv4_header.signature = signature;

        let ipv6_header = if let Some(port) = endpoint.ipv6_port {
            let mut ipv6_header = AnnounceHeader {
                endpoint_id: endpoint.id,
                port: port,
                certificate_hash: endpoint.ipv6_cert_hash,
                ..Default::default()
            };
            let (_verifying, signature) = db.sign(ipv6_header.hash_for_signature().to_vec()).await;
            ipv6_header.signature = signature;
            Some(ipv6_header)
        } else {
            None
        };

        Ok(Self {
            endpoint,
            multicast_discovery,
            private_room_id,
            verifying_key,
            meeting_secret,
            allowed_peers,
            allowed_token,
            connected: HashMap::new(),
            connection_progress: HashMap::new(),
            db,
            verify_service,
            ipv4_header,
            ipv6_header,
        })
    }

    pub async fn send_annouces(&self) -> Result<(), crate::Error> {
        let mut tokens: Vec<MeetingToken> = Vec::new();
        for tok in &self.allowed_peers {
            tokens.push(MeetingSecret::decode_token(&tok.meeting_token)?);
        }
        let ipv4_announce = Announce {
            header: self.ipv4_header.clone(),
            tokens,
        };

        self.multicast_discovery
            .send(MulticastMessage::Annouce(ipv4_announce))
            .await
            .map_err(|_| crate::Error::ChannelError("MulticastMessage send".to_string()))?;
        Ok(())
    }

    pub async fn process_multicast(&mut self, msg: MulticastMessage, address: SocketAddr) {
        match msg {
            MulticastMessage::Annouce(a) => {
                if a.header.endpoint_id == self.endpoint.id {
                    return;
                }
                for candidate in &a.tokens {
                    if let Some(verifying_keys) = self.allowed_token.get(candidate) {
                        let connection_progress = self
                            .connection_progress
                            .entry(a.header.endpoint_id)
                            .or_default();
                        if !*connection_progress {
                            for verifying_key in verifying_keys {
                                let mut include_hardware = false;
                                let hash_to_verify = a.header.hash_for_signature();
                                let signature = a.header.signature.clone();
                                let validated = self
                                    .verify_service
                                    .verify_hash(signature, hash_to_verify, verifying_key.clone())
                                    .await;
                                if validated {
                                    *connection_progress = true;
                                    if verifying_key.eq(&self.verifying_key) {
                                        include_hardware = true;
                                    }

                                    let target: SocketAddr =
                                        format!("{}:{}", &address.ip(), &a.header.port)
                                            .parse()
                                            .unwrap();
                                    println!("initiate from Annouce to target {} ", target);
                                    let _ = self
                                        .multicast_discovery
                                        .send(MulticastMessage::InitiateConnection(
                                            self.ipv4_header.clone(),
                                            *candidate,
                                        ))
                                        .await;

                                    let _ = self
                                        .endpoint
                                        .sender
                                        .send(EndpointMessage::InitiateConnection(
                                            target,
                                            a.header.certificate_hash,
                                            include_hardware,
                                        ))
                                        .await;
                                }
                            }
                        }
                    }
                }
            }
            MulticastMessage::InitiateConnection(header, token) => {
                if header.endpoint_id == self.endpoint.id {
                    return;
                }
                if let Some(verifying_keys) = self.allowed_token.get(&token) {
                    let connection_progress = self
                        .connection_progress
                        .entry(header.endpoint_id)
                        .or_default();
                    if !*connection_progress {
                        for verifying_key in verifying_keys {
                            let mut include_hardware = false;
                            let hash_to_verify = header.hash_for_signature();
                            let signature = header.signature.clone();
                            let validated = self
                                .verify_service
                                .verify_hash(signature, hash_to_verify, verifying_key.clone())
                                .await;
                            if validated {
                                *connection_progress = true;
                                if verifying_key.eq(&self.verifying_key) {
                                    include_hardware = true;
                                }
                                let target: SocketAddr =
                                    format!("{}:{}", &address.ip(), &header.port)
                                        .parse()
                                        .unwrap();

                                let _ = self
                                    .endpoint
                                    .sender
                                    .send(EndpointMessage::InitiateConnection(
                                        target,
                                        header.certificate_hash,
                                        include_hardware,
                                    ))
                                    .await;
                            }
                        }
                    }
                }
            }
        }
    }

    //peer to peer connectoin tends to create two connections
    //we arbitrarily remove the on the highest conn_id
    pub fn add_connection(&mut self, endpoint_id: Uid, conn: Connection, conn_id: Uid) {
        if let Some((old_conn, old_conn_id)) = self.connected.remove(&endpoint_id) {
            if old_conn_id > conn_id {
                println!("closing old{}", base64_encode(&old_conn_id));
                old_conn.close(VarInt::from(ERROR_CONN_ELECTION), "e".as_bytes());
                self.connected.insert(endpoint_id, (conn, conn_id));
            } else {
                println!("closing new{}", base64_encode(&conn_id));
                conn.close(VarInt::from(ERROR_CONN_ELECTION), "e".as_bytes());
                self.connected.insert(endpoint_id, (old_conn, old_conn_id));
            }
        } else {
            println!("adding new connection {}", base64_encode(&conn_id));
            self.connected.insert(endpoint_id, (conn, conn_id));
        }
    }

    pub fn disconnect(&mut self, endpoint_id: Uid, error_code: u16, message: &str) {
        if let Some((conn, _)) = self.connected.remove(&endpoint_id) {
            conn.close(VarInt::from(error_code), message.as_bytes());
        }
    }

    pub fn clean_progress(&mut self, endpoint_id: Uid) {
        self.connection_progress.remove(&endpoint_id);
    }
}
