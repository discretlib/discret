use crate::{
    base64_encode,
    database::{
        node::Node,
        system_entities::{Invite, OwnedInvite, Peer, Status},
    },
    uid_encode, DefaultRoom, Error, Parameters, ParametersAdd,
};
use quinn::{Connection, VarInt};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};
use tokio::sync::mpsc;
use x25519_dalek::PublicKey;

use crate::{
    base64_decode,
    database::{
        graph_database::GraphDatabaseService,
        system_entities::{AllowedHardware, AllowedPeer},
    },
    log_service::LogService,
    network::endpoint::EndpointMessage,
    security::{HardwareFingerprint, MeetingSecret, MeetingToken},
    signature_verification_service::SignatureVerificationService,
    Uid,
};

use super::{endpoint::DiscretEndpoint, multicast::MulticastMessage, Announce, AnnounceHeader};

#[derive(Clone)]
pub enum TokenType {
    AllowedPeer(AllowedPeer),
    OwnedInvite(OwnedInvite),
    Invite(Invite),
}
//indicate that an other connection has be kept
const REASON_CONN_ELECTION: u16 = 1;

//the remote peer does not hav to knwow why the connection is closed
pub const REASON_UNKNOWN: u16 = 2;

pub const MAX_MESSAGE_SIZE: usize = 4096;
//with a 7 byte token, fits into a 4096 message
pub const MAX_ANNOUNCE_TOKENS: usize = 512;

const DERIVE_STRING: &str = "P";

pub struct BeaconInfo {
    pub cert_hash: [u8; 32],
    pub header: AnnounceHeader,
    pub retry: u8,
}

pub struct MulticastInfo {
    sender: mpsc::Sender<MulticastMessage>,
    // probe_value: [u8; 32],
    // nonce: [u8; 32],
    header: AnnounceHeader,
}

pub struct PeerManager {
    app_name: String,
    endpoint: DiscretEndpoint,

    private_room_id: Uid,
    //  verifying_key: Vec<u8>,
    meeting_secret: MeetingSecret,

    multicast: Option<MulticastInfo>,

    allowed_peers: Vec<AllowedPeer>,
    owned_invites: Vec<OwnedInvite>,
    invites: Vec<Invite>,

    allowed_token: HashMap<MeetingToken, Vec<TokenType>>,
    connection_progress: HashMap<[u8; 32], bool>,
    connected: HashMap<[u8; 32], (Connection, Uid, MeetingToken)>,
    connected_tokens: HashMap<MeetingToken, HashSet<[u8; 32]>>,
    local_circuit: HashSet<[u8; 32]>,
    beacons: HashMap<SocketAddr, BeaconInfo>,
    connected_beacons: HashMap<SocketAddr, mpsc::Sender<Announce>>,

    db: GraphDatabaseService,
    logs: LogService,
    verify_service: SignatureVerificationService,
}
impl PeerManager {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        app_name: String,
        endpoint: DiscretEndpoint,
        multicast_discovery: Option<mpsc::Sender<MulticastMessage>>,
        db: GraphDatabaseService,
        logs: LogService,
        verify_service: SignatureVerificationService,
        private_room_id: Uid,
        //  verifying_key: Vec<u8>,
        meeting_secret: MeetingSecret,
    ) -> Result<Self, crate::Error> {
        let allowed_peers = db.get_allowed_peers(private_room_id).await?;
        let mut allowed_token: HashMap<MeetingToken, Vec<TokenType>> = HashMap::new();

        for peer in &allowed_peers {
            let token = MeetingSecret::decode_token(&peer.meeting_token)?;
            let entry = allowed_token.entry(token).or_default();
            entry.push(TokenType::AllowedPeer(peer.clone()));
        }

        let owned_invites = OwnedInvite::list_valid(uid_encode(&private_room_id), &db).await?;
        for owned in &owned_invites {
            let token = MeetingSecret::derive_token(DERIVE_STRING, &owned.id);
            let entry = allowed_token.entry(token).or_default();
            entry.push(TokenType::OwnedInvite(owned.clone()));
        }
        let invites = Invite::list(uid_encode(&private_room_id), &db).await?;
        for invite in &invites {
            let uid = &invite.invite_id;
            let token = MeetingSecret::derive_token(DERIVE_STRING, uid);
            let entry = allowed_token.entry(token).or_default();
            entry.push(TokenType::Invite(invite.clone()));
        }

        let multicast = if let Some(multicast_discovery) = multicast_discovery {
            // let probe_value = random32();
            // let nonce = random32();
            let mut header = AnnounceHeader {
                endpoint_id: endpoint.id,
                certificate_hash: endpoint.ipv4_cert_hash,
                signature: Vec::new(),
            };
            let (_verifying, signature) = db.sign(header.hash().to_vec()).await;
            header.signature = signature;

            Some(MulticastInfo {
                sender: multicast_discovery,
                // probe_value,
                // nonce,
                header,
            })
        } else {
            None
        };

        Ok(Self {
            app_name,
            endpoint,
            private_room_id,
            //   verifying_key,
            meeting_secret,
            multicast,
            allowed_peers,
            owned_invites,
            invites,
            allowed_token,
            connected: HashMap::new(),
            connected_tokens: HashMap::new(),
            connection_progress: HashMap::new(),
            local_circuit: HashSet::new(),
            beacons: HashMap::new(),
            connected_beacons: HashMap::new(),
            db,
            logs,
            verify_service,
        })
    }

    pub async fn add_beacon(
        &mut self,
        hostname: &str,
        cert_hash: &str,
    ) -> Result<(), crate::Error> {
        for address in tokio::net::lookup_host(&hostname).await? {
            let local_cert_has = if address.is_ipv4() {
                self.endpoint.ipv4_cert_hash
            } else {
                self.endpoint.ipv6_cert_hash
            };

            let mut header = AnnounceHeader {
                endpoint_id: self.endpoint.id,
                certificate_hash: local_cert_has,
                signature: Vec::new(),
            };
            let (_verifying, signature) = self.db.sign(header.hash().to_vec()).await;
            header.signature = signature;

            let deserialized = base64_decode(cert_hash.as_bytes())?;

            let cert_hash: [u8; 32] = deserialized
                .try_into()
                .map_err(|_| crate::Error::InvalidCertificateHash(cert_hash.to_string()))?;

            self.beacons.insert(
                address,
                BeaconInfo {
                    cert_hash,
                    header,
                    retry: 0,
                },
            );

            let _ = self
                .endpoint
                .sender
                .send(EndpointMessage::InitiateBeaconConnection(
                    address, cert_hash,
                ))
                .await;
        }
        Ok(())
    }

    pub async fn send_annouces(&self) -> Result<(), crate::Error> {
        let total_peer = self.allowed_peers.len() + self.invites.len() + self.owned_invites.len();
        if total_peer >= MAX_ANNOUNCE_TOKENS {
            return Err(crate::Error::Unsupported(format!(
                "Soon to be fixed, but for now, the total of allowed peers, invites and owned invites is limited to {}",
                MAX_ANNOUNCE_TOKENS
            )));
        }
        let mut tokens: Vec<MeetingToken> = Vec::new();
        for tok in &self.allowed_peers {
            tokens.push(MeetingSecret::decode_token(&tok.meeting_token)?);
        }

        for inv in &self.invites {
            let meeting_token = MeetingSecret::derive_token(DERIVE_STRING, &inv.invite_id);
            tokens.push(meeting_token);
        }

        for owned in &self.owned_invites {
            let meeting_token = MeetingSecret::derive_token(DERIVE_STRING, &owned.id);

            tokens.push(meeting_token);
        }

        if let Some(multicast) = &self.multicast {
            let ipv4_announce = Announce {
                header: multicast.header.clone(),
                tokens: tokens.clone(),
            };
            multicast
                .sender
                .send(MulticastMessage::Annouce(
                    ipv4_announce,
                    self.endpoint.ipv4_port,
                ))
                .await
                .map_err(|_| crate::Error::ChannelError("MulticastMessage send".to_string()))?;
        }

        for (address, sender) in &self.connected_beacons {
            if let Some(info) = self.beacons.get(address) {
                let announce = Announce {
                    header: info.header.clone(),
                    tokens: tokens.clone(),
                };
                let _ = sender.send(announce).await;
            }
        }

        Ok(())
    }

    pub async fn multicast_announce(
        &mut self,
        a: Announce,
        address: SocketAddr,
        port: u16,
        local: bool,
    ) -> Result<(), crate::Error> {
        if self.multicast.is_none() {
            return Ok(());
        }
        let multicast = self.multicast.as_ref().unwrap();

        if a.header.endpoint_id.eq(&self.endpoint.id) {
            return Ok(());
        }

        let circuit_id = Self::circuit_id(a.header.endpoint_id, self.endpoint.id);
        if self.connected.contains_key(&circuit_id) {
            return Ok(());
        }
        let connection_progress = self.connection_progress.entry(circuit_id).or_default();
        if *connection_progress {
            return Ok(());
        }

        for candidate in &a.tokens {
            if let Some(verifying_keys) = self.allowed_token.get(candidate) {
                for token_type in verifying_keys {
                    let hash_to_verify = a.header.hash();
                    let signature = a.header.signature.clone();
                    let (validated, identifier) = match token_type {
                        TokenType::AllowedPeer(peer) => {
                            let verifying_key = base64_decode(peer.peer.verifying_key.as_bytes())?;
                            let validated = self
                                .verify_service
                                .verify_hash(signature, hash_to_verify, verifying_key.clone())
                                .await;

                            (validated, verifying_key)
                        }
                        TokenType::OwnedInvite(owned) => (true, owned.id.to_vec()),
                        TokenType::Invite(inv) => (true, inv.invite_id.to_vec()),
                    };

                    if validated {
                        *connection_progress = true;

                        let _ = multicast
                            .sender
                            .send(MulticastMessage::InitiateConnection(
                                multicast.header.clone(),
                                *candidate,
                                self.endpoint.ipv4_port,
                            ))
                            .await;

                        if local {
                            self.local_circuit.insert(circuit_id);
                        }
                        let address = SocketAddr::new(address.ip(), port);
                        let _ = self
                            .endpoint
                            .sender
                            .send(EndpointMessage::InitiateConnection(
                                address,
                                a.header.certificate_hash,
                                a.header.endpoint_id,
                                *candidate,
                                identifier,
                            ))
                            .await;
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn multicast_initiate_connection(
        &mut self,
        header: AnnounceHeader,
        token: MeetingToken,
        address: SocketAddr,
        port: u16,
        local: bool,
    ) -> Result<(), crate::Error> {
        if self.multicast.is_none() {
            return Ok(());
        }

        if header.endpoint_id == self.endpoint.id {
            return Ok(());
        }
        let circuit_id = Self::circuit_id(header.endpoint_id, self.endpoint.id);
        let connection_progress = self.connection_progress.entry(circuit_id).or_default();
        if *connection_progress {
            return Ok(());
        }
        if self.connected.contains_key(&circuit_id) {
            return Ok(());
        }

        if let Some(verifying_keys) = self.allowed_token.get(&token) {
            if !*connection_progress {
                for token_type in verifying_keys {
                    let hash_to_verify = header.hash();
                    let signature = header.signature.clone();
                    let (validated, identifier) = match token_type {
                        TokenType::AllowedPeer(peer) => {
                            let verifying_key = base64_decode(peer.peer.verifying_key.as_bytes())?;
                            let validated = self
                                .verify_service
                                .verify_hash(signature, hash_to_verify, verifying_key.clone())
                                .await;

                            (validated, verifying_key)
                        }
                        TokenType::OwnedInvite(owned) => (true, owned.id.to_vec()),
                        TokenType::Invite(inv) => (true, inv.invite_id.to_vec()),
                    };

                    if validated {
                        *connection_progress = true;

                        if local {
                            self.local_circuit.insert(circuit_id);
                        }
                        let address = SocketAddr::new(address.ip(), port);

                        let _ = self
                            .endpoint
                            .sender
                            .send(EndpointMessage::InitiateConnection(
                                address,
                                header.certificate_hash,
                                header.endpoint_id,
                                token,
                                identifier,
                            ))
                            .await;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn is_local_circuit(&self, circuit_id: &[u8; 32]) -> bool {
        self.local_circuit.contains(circuit_id)
    }
    //peer to peer connection tends to create two connections
    //we arbitrarily remove the on the highest conn_id (the newest conn, Uids starts with a timestamps)
    pub fn add_connection(
        &mut self,
        circuit_id: [u8; 32],
        conn: Connection,
        conn_id: Uid,
        token: MeetingToken,
    ) {
        self.connection_progress.remove(&circuit_id);

        if let Some((old_conn, old_conn_id, token)) = self.connected.remove(&circuit_id) {
            if old_conn_id > conn_id {
                old_conn.close(VarInt::from(REASON_CONN_ELECTION), "".as_bytes());
                self.connected.insert(circuit_id, (conn, conn_id, token));
                let token_entry = self.connected_tokens.entry(token).or_default();
                token_entry.insert(circuit_id);
            } else {
                conn.close(VarInt::from(REASON_CONN_ELECTION), "".as_bytes());
                self.connected
                    .insert(circuit_id, (old_conn, old_conn_id, token));
                let token_entry = self.connected_tokens.entry(token).or_default();
                token_entry.insert(circuit_id);
            }
        } else {
            self.connected.insert(circuit_id, (conn, conn_id, token));
            let token_entry = self.connected_tokens.entry(token).or_default();
            token_entry.insert(circuit_id);
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
        if let Some((conn, uid, token)) = conn {
            if conn_id.eq(uid) {
                conn.close(VarInt::from(error_code), message.as_bytes());
                let token = *token;
                let circuit = circuit_id;
                self.connected.remove(&circuit);
                disconnected = true;
                let mut remove_entry = false;

                if let Some(tokens) = self.connected_tokens.get_mut(&token) {
                    tokens.remove(&circuit);
                    if tokens.is_empty() {
                        remove_entry = true;
                    }
                }

                if remove_entry {
                    self.connected_tokens.remove(&token);
                }
            }
        }
        if !self.connected.contains_key(&circuit_id) {
            self.local_circuit.remove(&circuit_id);
        }
        disconnected
    }

    pub fn clean_progress(&mut self, endpoint_id: Uid, remote_id: Uid) {
        let circuit_id = Self::circuit_id(endpoint_id, remote_id);
        self.connection_progress.remove(&circuit_id);
    }

    pub fn circuit_id(endpoint_id: Uid, remote_id: Uid) -> [u8; 32] {
        let mut v = [endpoint_id, remote_id];
        v.sort();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&v[0]);
        hasher.update(&v[1]);
        let hash = hasher.finalize();
        *hash.as_bytes()
    }

    pub async fn init_hardware(&self, hardware: HardwareFingerprint) -> Result<(), crate::Error> {
        let allowed_status = "allowed";
        AllowedHardware::put(
            hardware.id,
            self.private_room_id,
            &hardware.name,
            allowed_status,
            &self.db,
        )
        .await?;
        Ok(())
    }

    pub async fn validate_hardware(
        &self,
        circuit_id: &[u8; 32],
        hardware: HardwareFingerprint,
        auto_allow_local: bool,
    ) -> Result<bool, crate::Error> {
        let allowed_status = "allowed";
        let pending_status = "pending";
        let is_local = self.is_local_circuit(circuit_id);
        let valid =
            match AllowedHardware::get(hardware.id, self.private_room_id, allowed_status, &self.db)
                .await?
            {
                Some(_) => true,
                None => {
                    if auto_allow_local && is_local {
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
            };

        Ok(valid)
    }

    pub fn get_token_type(
        &self,
        token: &MeetingToken,
        key: &Vec<u8>,
    ) -> Result<TokenType, crate::Error> {
        if let Some(tokens) = self.allowed_token.get(token) {
            for token_type in tokens {
                match token_type {
                    TokenType::AllowedPeer(peer) => {
                        let verifying_key = base64_decode(peer.peer.verifying_key.as_bytes())?;
                        if key.eq(&verifying_key) {
                            return Ok(token_type.clone());
                        }
                    }
                    TokenType::OwnedInvite(_) => {
                        return Ok(token_type.clone());
                    }
                    TokenType::Invite(_) => {
                        return Ok(token_type.clone());
                    }
                }
            }
        }
        Err(crate::Error::InvalidConnection(
            "connection token not found".to_string(),
        ))
    }

    pub async fn create_invite(
        &mut self,
        default_room: Option<DefaultRoom>,
    ) -> Result<Vec<u8>, crate::Error> {
        let (invite, owned) = Invite::create(
            uid_encode(&self.private_room_id),
            default_room,
            self.app_name.to_string(),
            &self.db,
        )
        .await?;

        let token = MeetingSecret::derive_token(DERIVE_STRING, &owned.id);
        let entry = self.allowed_token.entry(token).or_default();
        entry.push(TokenType::OwnedInvite(owned.clone()));
        self.owned_invites.push(owned);
        self.send_annouces().await?;

        Ok(bincode::serialize(&invite)?)
    }

    pub async fn accept_invite(&mut self, invite: &[u8]) -> Result<(), crate::Error> {
        let inv: Invite = bincode::deserialize(invite)?;
        if !inv.application.eq(&self.app_name) {
            return Err(Error::InvalidInvite(format!(
                "this invite is for app {} and not for {}",
                &inv.application, &self.app_name
            )));
        }
        inv.insert(uid_encode(&self.private_room_id), &self.db)
            .await?;
        let token = MeetingSecret::derive_token(DERIVE_STRING, &inv.invite_id);
        let entry = self.allowed_token.entry(token).or_default();
        entry.push(TokenType::Invite(inv.clone()));
        self.invites.push(inv);
        self.send_annouces().await?;
        Ok(())
    }

    pub async fn invite_accepted(
        &mut self,
        token_type: TokenType,
        peer: Node,
    ) -> Result<(), crate::Error> {
        self.db.add_peer_nodes(vec![peer.clone()]).await?;

        let verifying_key = base64_encode(&peer.verifying_key);
        let pub_key = Peer::pub_key(&peer)?;
        let peer_public: PublicKey = bincode::deserialize(&pub_key)?;
        let token = self.meeting_secret.token(&peer_public);

        let room_id = uid_encode(&self.private_room_id);
        let allowed = AllowedPeer::add(
            &room_id,
            &verifying_key,
            &base64_encode(&token),
            Status::Enabled,
            &self.db,
        )
        .await?;

        let entry = self.allowed_token.entry(token).or_default();
        entry.push(TokenType::AllowedPeer(allowed.clone()));
        self.allowed_peers.push(allowed);

        match token_type {
            TokenType::OwnedInvite(owned) => {
                OwnedInvite::delete(owned.id, &self.db).await?;

                if let Some(room) = owned.room {
                    if let Some(auth) = owned.authorisation {
                        let room = uid_encode(&room);
                        let auth = uid_encode(&auth);
                        let verif_key = base64_encode(&peer.verifying_key);

                        let mut param = Parameters::new();
                        param.add("id", room)?;
                        param.add("auth", auth)?;
                        param.add("verif_key", verif_key)?;
                        self.db
                            .mutate(
                                r#"mutate {
                                sys.Room{
                                    id:$id
                                    authorisations:[{
                                        id:$auth
                                        users: [{
                                            verif_key:$verif_key
                                            enabled:true
                                        }]
                                    }]
                                }
                            }"#,
                                Some(param),
                            )
                            .await?;
                    }
                }

                let o: Option<&mut Vec<TokenType>> = self.allowed_token.get_mut(&token);
                if let Some(tokens) = o {
                    let index = tokens.iter().position(|tt| {
                        if let TokenType::OwnedInvite(owned_tok) = tt {
                            owned.id.eq(&owned_tok.id)
                        } else {
                            false
                        }
                    });

                    if let Some(index) = index {
                        tokens.remove(index);
                    }
                }
                self.owned_invites = OwnedInvite::list_valid(room_id.clone(), &self.db).await?;
            }
            TokenType::Invite(invite) => {
                let o = self.allowed_token.get_mut(&token);
                if let Some(tokens) = o {
                    let index = tokens.iter().position(|tt| {
                        if let TokenType::Invite(i) = tt {
                            i.invite_id.eq(&invite.invite_id)
                        } else {
                            false
                        }
                    });
                    if let Some(index) = index {
                        tokens.remove(index);
                    }
                }
                Invite::delete(room_id.clone(), invite.invite_id, &self.db).await?;
                self.invites = Invite::list(room_id.clone(), &self.db).await?;
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    pub async fn add_new_peers(
        &mut self,
        peers: Vec<Node>,
        auto_allow_new_peers: bool,
    ) -> Result<bool, crate::Error> {
        let room_id = uid_encode(&self.private_room_id);
        let mut pending = false;
        let mut send_announce = false;
        for peer in peers {
            let verifying_key = base64_encode(&peer.verifying_key);

            let pub_key = Peer::pub_key(&peer)?;

            let peer_public: PublicKey = bincode::deserialize(&pub_key)?;

            let token = self.meeting_secret.token(&peer_public);

            if auto_allow_new_peers {
                let allowed = AllowedPeer::add(
                    &room_id,
                    &verifying_key,
                    &base64_encode(&token),
                    Status::Enabled,
                    &self.db,
                )
                .await?;

                let entry = self.allowed_token.entry(token).or_default();
                entry.push(TokenType::AllowedPeer(allowed.clone()));
                self.allowed_peers.push(allowed);
                send_announce = true;
            } else {
                AllowedPeer::add(
                    &room_id,
                    &verifying_key,
                    &base64_encode(&token),
                    Status::Pending,
                    &self.db,
                )
                .await?;
                pending = true;
            }
        }
        if send_announce {
            self.send_annouces().await?;
        }
        Ok(pending)
    }

    pub async fn beacon_connection_failed(&mut self, address: SocketAddr, error: String) {
        if let Some(beacon) = self.beacons.get_mut(&address) {
            beacon.retry += 1;
            if beacon.retry <= 3 {
                let _ = self
                    .endpoint
                    .sender
                    .send(EndpointMessage::InitiateBeaconConnection(
                        address,
                        beacon.cert_hash,
                    ))
                    .await;
            } else {
                self.logs.error(
                    "beacon_connection_failed".to_string(),
                    crate::Error::BeaconConnectionFailed(address.to_string(), error),
                );
            }
        }
    }
    pub async fn beacon_connected(
        &mut self,
        address: SocketAddr,
        sender: mpsc::Sender<Announce>,
    ) -> Result<(), crate::Error> {
        if let Some(info) = self.beacons.get(&address) {
            let mut tokens: Vec<MeetingToken> = Vec::new();
            for tok in &self.allowed_peers {
                tokens.push(MeetingSecret::decode_token(&tok.meeting_token)?);
            }

            for inv in &self.invites {
                let meeting_token = MeetingSecret::derive_token(DERIVE_STRING, &inv.invite_id);
                tokens.push(meeting_token);
            }

            for owned in &self.owned_invites {
                let meeting_token = MeetingSecret::derive_token(DERIVE_STRING, &owned.id);
                tokens.push(meeting_token);
            }

            let announce = Announce {
                header: info.header.clone(),
                tokens: tokens.clone(),
            };
            let _ = sender.send(announce).await;
            self.connected_beacons.insert(address, sender);
        }
        Ok(())
    }

    pub async fn beacon_disconnected(&mut self, address: SocketAddr) {
        if let Some(beacon) = self.beacons.get_mut(&address) {
            beacon.retry += 1;
            if beacon.retry <= 3 {
                let _ = self
                    .endpoint
                    .sender
                    .send(EndpointMessage::InitiateBeaconConnection(
                        address,
                        beacon.cert_hash,
                    ))
                    .await;
            } else {
                self.logs.info(format!("Beacon disconnected: {}", address));
            }
        }
        self.connected_beacons.remove(&address);
    }
    pub async fn beacon_initiate_connection(
        &mut self,
        address: SocketAddr,
        header: AnnounceHeader,
        token: MeetingToken,
    ) -> Result<(), crate::Error> {
        if self.beacons.is_empty() {
            return Ok(());
        }

        if header.endpoint_id == self.endpoint.id {
            return Ok(());
        }

        let circuit_id = Self::circuit_id(header.endpoint_id, self.endpoint.id);
        let connection_progress = self.connection_progress.entry(circuit_id).or_default();
        if *connection_progress {
            return Ok(());
        }
        if self.connected.contains_key(&circuit_id) {
            return Ok(());
        }
        if let Some(verifying_keys) = self.allowed_token.get(&token) {
            if !*connection_progress {
                for token_type in verifying_keys {
                    let hash_to_verify = header.hash();
                    let signature = header.signature.clone();
                    let (validated, identifier) = match token_type {
                        TokenType::AllowedPeer(peer) => {
                            let verifying_key = base64_decode(peer.peer.verifying_key.as_bytes())?;
                            let validated = self
                                .verify_service
                                .verify_hash(signature, hash_to_verify, verifying_key.clone())
                                .await;

                            (validated, verifying_key)
                        }
                        TokenType::OwnedInvite(owned) => (true, owned.id.to_vec()),
                        TokenType::Invite(inv) => (true, inv.invite_id.to_vec()),
                    };

                    if validated {
                        *connection_progress = true;

                        let _ = self
                            .endpoint
                            .sender
                            .send(EndpointMessage::InitiateConnection(
                                address,
                                header.certificate_hash,
                                header.endpoint_id,
                                token,
                                identifier,
                            ))
                            .await;
                    }
                }
            }
        }
        Ok(())
    }
}
