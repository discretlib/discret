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
    security::{random32, HardwareFingerprint, MeetingSecret, MeetingToken},
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

//with a 7 byte token, fits into a 4096 message
pub const MAX_ANNOUNCE_TOKENS: usize = 512;

const DERIVE_STRING: &str = "P";

pub struct PeerManager {
    app_name: String,
    endpoint: DiscretEndpoint,
    multicast_discovery: mpsc::Sender<MulticastMessage>,
    private_room_id: Uid,
    pub verifying_key: Vec<u8>,

    pub meeting_secret: MeetingSecret,

    pub allowed_peers: Vec<AllowedPeer>,

    owned_invites: Vec<OwnedInvite>,
    invites: Vec<Invite>,

    pub allowed_token: HashMap<MeetingToken, Vec<TokenType>>,

    connection_progress: HashMap<[u8; 32], bool>,
    connected: HashMap<[u8; 32], (Connection, Uid, MeetingToken)>,
    connected_tokens: HashMap<MeetingToken, HashSet<[u8; 32]>>,

    db: GraphDatabaseService,
    logs: LogService,
    verify_service: SignatureVerificationService,

    probe_value: [u8; 32],
    ipv4_header: Option<AnnounceHeader>,
    ipv6_header: Option<AnnounceHeader>,

    multicast_nonce: [u8; 32],
}
impl PeerManager {
    pub async fn new(
        app_name: String,
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

        let probe_value = random32();
        let _ = multicast_discovery
            .send(MulticastMessage::ProbeLocalIp(probe_value))
            .await;
        let multicast_nonce = random32();
        Ok(Self {
            app_name,
            endpoint,
            multicast_discovery,
            private_room_id,
            verifying_key,
            meeting_secret,
            allowed_peers,
            owned_invites,
            invites,
            allowed_token,
            connected: HashMap::new(),
            connected_tokens: HashMap::new(),
            connection_progress: HashMap::new(),
            db,
            logs,
            verify_service,
            probe_value,
            ipv4_header: None,
            ipv6_header: None,
            multicast_nonce,
        })
    }

    pub async fn send_annouces(&self) -> Result<(), crate::Error> {
        if let Some(ipv4_header) = &self.ipv4_header {
            let mut tokens: Vec<MeetingToken> = Vec::new();
            for tok in &self.allowed_peers {
                tokens.push(MeetingSecret::decode_token(&tok.meeting_token)?);
            }

            for inv in &self.invites {
                let meeting_token = MeetingSecret::derive_token(DERIVE_STRING, &inv.invite_id);
                println!(
                    "{}: Anouncing invite {}",
                    ipv4_header.socket_adress,
                    base64_encode(&meeting_token)
                );
                tokens.push(meeting_token);
            }

            for owned in &self.owned_invites {
                let meeting_token = MeetingSecret::derive_token(DERIVE_STRING, &owned.id);

                println!(
                    "{}: Anouncing owned invite {}",
                    ipv4_header.socket_adress,
                    base64_encode(&meeting_token)
                );
                tokens.push(meeting_token);
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
            self.logs.info(format!("Local Adress {}", &address.ip()));
            let mut ipv4_header = AnnounceHeader {
                socket_adress: ipv4_adress,
                endpoint_id: self.endpoint.id,
                certificate_hash: self.endpoint.ipv4_cert_hash,
                signature: Vec::new(),
            };

            let (_verifying, signature) = self.db.sign(ipv4_header.hash().to_vec()).await;
            ipv4_header.signature = signature;
            self.ipv4_header = Some(ipv4_header);

            return Ok(true);
        }
        Ok(false)
    }

    pub async fn process_announce(
        &mut self,
        a: Announce,
        address: SocketAddr,
    ) -> Result<(), crate::Error> {
        if self.ipv4_header.is_none() {
            return Ok(());
        }
        if !a.header.socket_adress.ip().eq(&address.ip()) {
            return Ok(());
        }
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

        let header = self.ipv4_header.as_ref().unwrap();

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

                        let target: SocketAddr = a.header.socket_adress;

                        let _ = self
                            .multicast_discovery
                            .send(MulticastMessage::InitiateConnection(
                                header.clone(),
                                *candidate,
                            ))
                            .await;

                        println!(
                            "{} -> {} for token {}",
                            self.ipv4_header.as_ref().unwrap().socket_adress,
                            target,
                            base64_encode(candidate)
                        );

                        let _ = self
                            .endpoint
                            .sender
                            .send(EndpointMessage::InitiateConnection(
                                target,
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

    pub async fn process_initiate_connection(
        &mut self,
        header: AnnounceHeader,
        token: MeetingToken,
        address: SocketAddr,
    ) -> Result<(), crate::Error> {
        if self.ipv4_header.is_none() {
            return Ok(());
        }
        if !header.socket_adress.ip().eq(&address.ip()) {
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
                        let target: SocketAddr = header.socket_adress;
                        println!(
                            "{} -> {} for token {}",
                            self.ipv4_header.as_ref().unwrap().socket_adress,
                            target,
                            base64_encode(&token)
                        );
                        let _ = self
                            .endpoint
                            .sender
                            .send(EndpointMessage::InitiateConnection(
                                target,
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

    //peer to peer connectoin tends to create two connections
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
                let token = token.clone();
                let circuit = circuit_id.clone();
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
    ) -> Result<bool, crate::Error> {
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
                    TokenType::OwnedInvite(owned) => {
                        if key.eq(&owned.id.to_vec()) {
                            return Ok(token_type.clone());
                        }
                    }
                    TokenType::Invite(invite) => {
                        if key.eq(&invite.invite_id.to_vec()) {
                            return Ok(token_type.clone());
                        }
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
        num_use: i64,
        default_room: Option<DefaultRoom>,
    ) -> Result<Vec<u8>, crate::Error> {
        let (invite, owned) = Invite::create(
            uid_encode(&self.private_room_id),
            num_use,
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

    pub async fn accept_invite(&mut self, invite: &Vec<u8>) -> Result<(), crate::Error> {
        let inv: Invite = bincode::deserialize(&invite)?;
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
                println!("TokenType::OwnedInvite");
                let deleted =
                    OwnedInvite::decrease_and_delete(room_id.clone(), owned.id, &self.db).await?;

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
                if deleted {
                    println!("TokenType::Invite");
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

    // pub async fn invite_accepted(&mut self, id: Uid, peer: Node) -> Result<(), crate::Error> {
    //     let verifying_key = base64_encode(&peer.verifying_key);

    //     let pub_key = Peer::pub_key(&peer)?;
    //     let peer_public: PublicKey = bincode::deserialize(&pub_key)?;
    //     let token = self.meeting_secret.token(&peer_public);

    //     self.db.add_peer_nodes(vec![peer.clone()]).await?;
    //     let room_id = uid_encode(&self.private_room_id);
    //     let allowed = AllowedPeer::add(
    //         &room_id,
    //         &verifying_key,
    //         &base64_encode(&token),
    //         Status::Enabled,
    //         &self.db,
    //     )
    //     .await?;

    //     let entry = self.allowed_token.entry(token).or_default();
    //     entry.push(TokenType::AllowedPeer(allowed.clone()));
    //     self.allowed_peers.push(allowed);
    //     /*
    //     if owned {
    //         if OwnedInvite::decrease_and_delete(room_id.clone(), id, &self.db).await? {
    //             let token = MeetingSecret::derive_token(DERIVE_STRING, &id);
    //             let o: Option<&mut Vec<TokenType>> = self.allowed_token.get_mut(&token);
    //             if let Some(tokens) = o {
    //                 let index = tokens.iter().position(|tt| {
    //                     if let TokenType::OwnedInvite(owned) = tt {
    //                         owned.id.eq(&id)
    //                     } else {
    //                         false
    //                     }
    //                 });

    //                 if let Some(index) = index {
    //                     let owned = &tokens[index];
    //                     if let TokenType::OwnedInvite(owned) = owned {
    //                         if let Some(room) = owned.room {
    //                             if let Some(auth) = owned.authorisation {
    //                                 println!("inserting new user");
    //                                 let room = uid_encode(&room);
    //                                 let auth = uid_encode(&auth);
    //                                 let verif_key = base64_encode(&peer.verifying_key);

    //                                 let mut param = Parameters::new();
    //                                 param.add("id", room)?;
    //                                 param.add("auth", auth)?;
    //                                 param.add("verif_key", verif_key)?;
    //                                 self.db
    //                                     .mutate(
    //                                         r#"mutate {
    //                                     sys.Room{
    //                                         id:$id
    //                                         authorisations:[{
    //                                             id:$auth
    //                                             users: [{
    //                                                 verif_key:$verif_key
    //                                                 enabled:true
    //                                             }]
    //                                         }]
    //                                     }
    //                                 }"#,
    //                                         Some(param),
    //                                     )
    //                                     .await?;
    //                             }
    //                         }
    //                     }
    //                     tokens.remove(index);
    //                 }
    //             }
    //             self.owned_invites = OwnedInvite::list_valid(room_id.clone(), &self.db).await?;
    //         }
    //     } else {
    //         let token = MeetingSecret::derive_token(DERIVE_STRING, &id);
    //         let o = self.allowed_token.get_mut(&token);
    //         if let Some(tokens) = o {
    //             let index = tokens.iter().position(|tt| {
    //                 if let TokenType::Invite(i) = tt {
    //                     i.invite_id.eq(&id)
    //                 } else {
    //                     false
    //                 }
    //             });
    //             if let Some(index) = index {
    //                 tokens.remove(index);
    //             }
    //         }
    //         Invite::delete(room_id.clone(), id, &self.db).await?;
    //         self.invites = Invite::list(room_id.clone(), &self.db).await?;
    //     }*/
    //     Ok(())
    // }
}
