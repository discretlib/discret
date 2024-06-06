use crate::Error;
use quinn::{Connection, VarInt};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};
use tokio::sync::mpsc;

use crate::{
    base64_decode,
    database::{
        graph_database::GraphDatabaseService,
        system_entities::{AllowedHardware, AllowedPeer},
    },
    log_service::LogService,
    network::endpoint::EndpointMessage,
    security::{random32, HardwareFingerprint, MeetingSecret, MeetingToken},
    signature_verification_service::SignatureVerificationService,
    Uid,
};

use super::{endpoint::DiscretEndpoint, multicast::MulticastMessage, Announce, AnnounceHeader};

//indicate that an other connection has be kept
const REASON_CONN_ELECTION: u16 = 1;

//the remote peer does not hav to knwow why the connection is closed
pub const REASON_UNKNOWN: u16 = 2;

pub struct PeerManager {
    endpoint: DiscretEndpoint,
    multicast_discovery: mpsc::Sender<MulticastMessage>,
    private_room_id: Uid,
    verifying_key: Vec<u8>,

    pub meeting_secret: MeetingSecret,

    pub allowed_peers: Vec<AllowedPeer>,
    pub allowed_token: HashMap<MeetingToken, Vec<Vec<u8>>>,

    connection_progress: HashMap<[u8; 32], bool>,
    connected: HashMap<[u8; 32], (Connection, Uid)>,
    local_connection: HashSet<[u8; 32]>,

    db: GraphDatabaseService,
    logs: LogService,
    verify_service: SignatureVerificationService,

    probe_value: [u8; 32],
    ipv4_header: Option<AnnounceHeader>,
    ipv6_header: Option<AnnounceHeader>,
}
impl PeerManager {
    pub async fn new(
        endpoint: DiscretEndpoint,
        multicast_discovery: mpsc::Sender<MulticastMessage>,
        db: GraphDatabaseService,
        logs: LogService,
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

        let probe_value = random32();
        let _ = multicast_discovery
            .send(MulticastMessage::ProbeLocalIp(probe_value))
            .await;

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
            local_connection: HashSet::new(),
            db,
            logs,
            verify_service,
            probe_value,
            ipv4_header: None,
            ipv6_header: None,
        })
    }

    pub async fn send_annouces(&self) -> Result<(), crate::Error> {
        if let Some(ipv4_header) = &self.ipv4_header {
            let mut tokens: Vec<MeetingToken> = Vec::new();
            for tok in &self.allowed_peers {
                tokens.push(MeetingSecret::decode_token(&tok.meeting_token)?);
            }
            let ipv4_announce = Announce {
                header: ipv4_header.clone(),
                tokens,
            };

            self.multicast_discovery
                .send(MulticastMessage::Annouce(ipv4_announce))
                .await
                .map_err(|_| crate::Error::ChannelError("MulticastMessage send".to_string()))?;
        }

        Ok(())
    }

    pub async fn validate_probe(
        &mut self,
        probe_value: [u8; 32],
        address: SocketAddr,
    ) -> Result<bool, Error> {
        if self.ipv4_header.is_some() {
            return Ok(false);
        }
        if probe_value.eq(&self.probe_value) {
            let ipv4_adress = SocketAddr::new(address.ip(), self.endpoint.ipv4_port);
            self.logs
                .info(format!("Detected Local Adress {}", &address.ip()));
            let mut ipv4_header = AnnounceHeader {
                socket_adress: ipv4_adress,
                endpoint_id: self.endpoint.id,
                certificate_hash: self.endpoint.ipv4_cert_hash,
                signature: Vec::new(),
            };

            let (_verifying, signature) = self
                .db
                .sign(ipv4_header.hash_for_signature().to_vec())
                .await;
            ipv4_header.signature = signature;
            self.ipv4_header = Some(ipv4_header);

            return Ok(true);
        }
        Ok(false)
    }

    pub async fn process_announce(&mut self, a: Announce, address: SocketAddr) {
        if self.ipv4_header.is_none() {
            return;
        }
        if !a.header.socket_adress.ip().eq(&address.ip()) {
            return;
        }
        if a.header.endpoint_id.eq(&self.endpoint.id) {
            return;
        }

        let circuit_id = Self::circuit_id(a.header.endpoint_id, self.endpoint.id);
        if self.connected.contains_key(&circuit_id) {
            return;
        }
        let connection_progress = self.connection_progress.entry(circuit_id).or_default();
        if *connection_progress {
            return;
        }

        let header = self.ipv4_header.as_ref().unwrap();

        for candidate in &a.tokens {
            if let Some(verifying_keys) = self.allowed_token.get(candidate) {
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
                            self.local_connection.insert(circuit_id);
                            let target: SocketAddr = a.header.socket_adress;

                            let _ = self
                                .multicast_discovery
                                .send(MulticastMessage::InitiateConnection(
                                    header.clone(),
                                    *candidate,
                                ))
                                .await;

                            let _ = self
                                .endpoint
                                .sender
                                .send(EndpointMessage::InitiateConnection(
                                    target,
                                    a.header.certificate_hash,
                                    a.header.endpoint_id,
                                    include_hardware,
                                ))
                                .await;
                        }
                    }
                }
            }
        }
    }

    pub async fn process_initiate_connection(
        &mut self,
        header: AnnounceHeader,
        token: MeetingToken,
        address: SocketAddr,
    ) {
        if self.ipv4_header.is_none() {
            return;
        }
        if !header.socket_adress.ip().eq(&address.ip()) {
            return;
        }
        if header.endpoint_id == self.endpoint.id {
            return;
        }
        let circuit_id = Self::circuit_id(header.endpoint_id, self.endpoint.id);
        let connection_progress = self.connection_progress.entry(circuit_id).or_default();
        if *connection_progress {
            return;
        }
        if self.connected.contains_key(&circuit_id) {
            return;
        }

        if let Some(verifying_keys) = self.allowed_token.get(&token) {
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
                        let target: SocketAddr = header.socket_adress;

                        let _ = self
                            .endpoint
                            .sender
                            .send(EndpointMessage::InitiateConnection(
                                target,
                                header.certificate_hash,
                                header.endpoint_id,
                                include_hardware,
                            ))
                            .await;
                    }
                }
            }
        }
    }

    //peer to peer connectoin tends to create two connections
    //we arbitrarily remove the on the highest conn_id (the newest conn, Uids starts with a timestamps)
    pub fn add_connection(&mut self, circuit_id: [u8; 32], conn: Connection, conn_id: Uid) {
        self.connection_progress.remove(&circuit_id);

        if let Some((old_conn, old_conn_id)) = self.connected.remove(&circuit_id) {
            if old_conn_id > conn_id {
                old_conn.close(VarInt::from(REASON_CONN_ELECTION), "".as_bytes());
                self.connected.insert(circuit_id, (conn, conn_id));
            } else {
                conn.close(VarInt::from(REASON_CONN_ELECTION), "".as_bytes());
                self.connected.insert(circuit_id, (old_conn, old_conn_id));
            }
        } else {
            self.connected.insert(circuit_id, (conn, conn_id));
        }
    }

    pub fn disconnect(
        &mut self,
        circuit_id: [u8; 32],
        conn_id: Uid,
        error_code: u16,
        message: &str,
    ) -> bool {
        let mut disconnected = false;
        let conn = self.connected.get(&circuit_id);
        if let Some((conn, uid)) = conn {
            if conn_id.eq(uid) {
                conn.close(VarInt::from(error_code), message.as_bytes());
                self.connected.remove(&circuit_id);
                self.local_connection.remove(&circuit_id);
                disconnected = true
            }
        }
        disconnected
    }

    pub fn clean_progress(&mut self, endpoint_id: Uid, remote_id: Uid) {
        let circuit_id = Self::circuit_id(endpoint_id, remote_id);
        self.connection_progress.remove(&circuit_id);
    }

    pub fn circuit_id(endpoint_id: Uid, remote_id: Uid) -> [u8; 32] {
        let mut v = vec![endpoint_id, remote_id];
        v.sort();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&v[0]);
        hasher.update(&v[1]);
        let hash = hasher.finalize();
        *hash.as_bytes()
    }

    pub async fn validate_hardware(
        &self,
        endpoint_id: Uid,
        hardware: HardwareFingerprint,
        auto_allow_local: bool,
    ) -> bool {
        let s = self
            .validate_hardware_int(endpoint_id, hardware, auto_allow_local)
            .await;

        match s {
            Ok(valid) => valid,
            Err(e) => {
                self.logs.error(
                    "PeerManager.validate_hardware".to_string(),
                    crate::Error::from(e),
                );
                false
            }
        }
    }

    pub async fn validate_hardware_int(
        &self,
        endpoint_id: Uid,
        hardware: HardwareFingerprint,
        auto_allow_local: bool,
    ) -> Result<bool, super::Error> {
        let allowed_status = "allowed";
        let pending_status = "pending";

        let valid = if endpoint_id == self.endpoint.id {
            true
        } else {
            match AllowedHardware::get(hardware.id, self.private_room_id, allowed_status, &self.db)
                .await?
            {
                Some(_) => true,
                None => {
                    if auto_allow_local {
                        AllowedHardware::put(
                            hardware.id,
                            self.private_room_id,
                            &hardware.name,
                            allowed_status,
                            &self.db,
                        )
                        .await?;
                        true
                    } else {
                        AllowedHardware::put(
                            hardware.id,
                            self.private_room_id,
                            &hardware.name,
                            pending_status,
                            &self.db,
                        )
                        .await?;
                        false
                    }
                }
            }
        };
        Ok(valid)
    }
}
