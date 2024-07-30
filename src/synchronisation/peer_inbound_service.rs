use std::{
    collections::{HashMap, HashSet, VecDeque},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use futures::Future;
use serde::de::DeserializeOwned;
use tokio::{
    sync::{
        broadcast,
        mpsc::{self, Receiver, Sender},
        oneshot, Mutex,
    },
    time::timeout,
};

use crate::{
    base64_decode,
    database::{
        daily_log::{DailyLog, RoomDefinitionLog},
        edge::{Edge, EdgeDeletionEntry},
        graph_database::GraphDatabaseService,
        node::{Node, NodeDeletionEntry, NodeIdentifier},
        room_node::RoomNode,
        system_entities::Peer,
    },
    event_service::{EventService, EventServiceMessage},
    log_service::LogService,
    network::{peer_manager::TokenType, ConnectionInfo},
    peer_connection_service::{PeerConnectionMessage, PeerConnectionService},
    security::{self, base64_encode, random32, HardwareFingerprint, Uid},
    signature_verification_service::SignatureVerificationService,
    uid_encode,
};

use super::{
    peer_outbound_service::InboundQueryService, room_locking_service::RoomLockService, Answer,
    Error, IdentityAnswer, LocalEvent, Query, QueryProtocol, RemoteEvent, NETWORK_TIMEOUT_SEC,
};

static QUERY_SEND_BUFFER: usize = 10;

pub type AnswerFn =
    Box<dyn FnOnce(bool, bool, Vec<u8>) -> Pin<Box<AsnwerResultFut>> + Send + 'static>;
pub type AnswerMultipleFn =
    Box<dyn Fn(bool, bool, Vec<u8>) -> Pin<Box<AsnwerResultFut>> + Send + 'static>;

pub type AsnwerResultFut = dyn Future<Output = ()> + Send + 'static;

pub enum QueryFn {
    Once(Query, AnswerFn),
    Multiple(Query, AnswerMultipleFn),
}
#[derive(Clone)]
pub struct QueryService {
    sender: mpsc::Sender<QueryFn>,
}
impl QueryService {
    pub fn start(
        remote_sender: mpsc::Sender<QueryProtocol>,
        mut remote_receiver: mpsc::Receiver<Answer>,
        log_service: LogService,
    ) -> Self {
        let (sender, mut local_receiver) = mpsc::channel::<QueryFn>(QUERY_SEND_BUFFER);

        tokio::spawn(async move {
            let mut next_message_id: u64 = 0;
            let mut sent_query: HashMap<u64, AnswerFn> = HashMap::new();
            let mut sent_query_multiple: HashMap<u64, AnswerMultipleFn> = HashMap::new();
            loop {
                tokio::select! {
                    msg = local_receiver.recv() =>{
                        match msg {
                            Some(msg) => {
                                match msg{
                                    QueryFn::Once(query, fun) => {
                                        let id = next_message_id;
                                        let query_prot = QueryProtocol { id, query };
                                        if let Err(e)  = remote_sender.send(query_prot).await {
                                            log_service.error("QueryService".to_string(), crate::Error::SendError(e.to_string()));
                                            break;
                                        }
                                        sent_query.insert(id, fun);
                                        next_message_id += 1;
                                    },
                                    QueryFn::Multiple(query, fun) => {
                                        let id = next_message_id;
                                        let query_prot = QueryProtocol { id, query };
                                        if let Err(e)  = remote_sender.send(query_prot).await {
                                            log_service.error("QueryService".to_string(), crate::Error::SendError(e.to_string()));
                                            break;
                                        }
                                        sent_query_multiple.insert(id, fun);
                                        next_message_id += 1;
                                    },
                                }

                            },
                            None => {

                                break
                            },
                        }
                    }
                    msg = remote_receiver.recv() =>{

                        match msg {
                            Some(msg) => {
                                if let Some(func) = sent_query.remove(&msg.id) {
                                    func(msg.success,msg.complete, msg.serialized).await;
                                }else if let Some(func) = sent_query_multiple.get(&msg.id) {
                                    func(msg.success,msg.complete, msg.serialized).await;
                                    if msg.complete{
                                        sent_query_multiple.remove(&msg.id);
                                    }
                                }
                            }
                            None => {

                                break
                            },
                        }
                    }

                }
            }
        });

        Self { sender }
    }

    async fn send(&self, query: QueryFn) {
        let _ = self.sender.send(query).await;
    }
}

pub struct LocalPeerService {}
impl LocalPeerService {
    #[allow(clippy::too_many_arguments)]
    pub async fn initialise_connection(
        connection_info: &ConnectionInfo,
        local_key: &Vec<u8>,
        token_type: TokenType,
        conn_ready: &Arc<AtomicBool>,
        query_service: &QueryService,
        remote_verifying_key: &Arc<Mutex<Vec<u8>>>,
        peer_service: &PeerConnectionService,
        event_sender: &Sender<RemoteEvent>,
    ) -> Result<bool, crate::Error> {
        let challenge = random32().to_vec();

        let proof = Self::query(query_service, Query::ProveIdentity(challenge.clone())).await;
        if proof.is_err() {
            return Ok(false); //silently return to try to avoid poluting the logs with the error caused by the deletion of one of the two connection established during P2P initiaiton
        }
        let proof: IdentityAnswer = proof.unwrap();
        proof.verify(&challenge)?;
        Peer::validate(&proof.peer)?;
        let mut ready = true;
        match &token_type {
            TokenType::AllowedPeer(peer) => {
                let expected_key = base64_decode(peer.peer.verifying_key.as_bytes())?;

                if expected_key.eq(&proof.peer.verifying_key) {
                    let mut key = remote_verifying_key.lock().await;
                    *key = proof.peer.verifying_key.clone();
                    drop(key);
                } else {
                    return Err(crate::Error::InvalidConnection("Invalid Peer".to_string()));
                }
                if local_key.eq(&proof.peer.verifying_key) {
                    ready = false;
                    conn_ready.store(false, Ordering::Relaxed);
                    let res = Self::send_event(event_sender, RemoteEvent::ReadyFingerprint)
                        .await
                        .map_err(|_| crate::Error::TimeOut("ReadyFingerprint".to_string()));
                    if res.is_err() {
                        return Ok(false); //silently return to try to avoid poluting the logs with the error caused by the deletion of one of the two connection established during P2P initiaiton
                    }
                }
            }
            TokenType::OwnedInvite(_) => {
                let mut key = remote_verifying_key.lock().await;
                *key = proof.peer.verifying_key.clone();
                drop(key);
                peer_service
                    .invite_accepted(token_type.clone(), proof.peer.clone())
                    .await;
            }

            TokenType::Invite(invite) => {
                invite.hash();
                {
                    let pub_key = security::import_verifying_key(&proof.peer.verifying_key)?;
                    pub_key.verify(&invite.hash(), &invite.invite_sign)?;
                }
                let mut key = remote_verifying_key.lock().await;
                *key = proof.peer.verifying_key.clone();
                drop(key);
                peer_service
                    .invite_accepted(token_type.clone(), proof.peer.clone())
                    .await;
                //accept peer
                //remove invite
                //send connection
            }
        };

        if ready {
            let res = Self::send_event(event_sender, RemoteEvent::Ready)
                .await
                .map_err(|_| crate::Error::TimeOut("Ready".to_string()));
            if res.is_err() {
                return Ok(false); //silently return to try to avoid poluting the logs with the error caused by the deletion of one of the two connection established during P2P initiaiton
            }

            peer_service
                .connected(proof.peer.verifying_key, connection_info.conn_id)
                .await;
        }
        Ok(true)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        mut remote_event: Receiver<RemoteEvent>,
        mut local_event: broadcast::Receiver<LocalEvent>,
        circuit_id: [u8; 32],
        connection_info: ConnectionInfo,
        local_verifying_key: Vec<u8>,
        token_type: TokenType,
        remote_verifying_key: Arc<Mutex<Vec<u8>>>,
        conn_ready: Arc<AtomicBool>,
        db: GraphDatabaseService,
        lock_service: RoomLockService,
        query_service: QueryService,
        event_sender: Sender<RemoteEvent>,
        log_service: LogService,
        peer_service: PeerConnectionService,
        event_service: EventService,
        inbound_query_service: InboundQueryService,
        verify_service: SignatureVerificationService,
    ) {
        let (lock_reply, mut lock_receiver) = mpsc::unbounded_channel::<Uid>();

        tokio::spawn(async move {
            match Self::initialise_connection(
                &connection_info,
                &local_verifying_key,
                token_type,
                &conn_ready,
                &query_service,
                &remote_verifying_key,
                &peer_service,
                &event_sender,
            )
            .await
            {
                Ok(success) => {
                    if !success {
                        let key = remote_verifying_key.lock().await;
                        let verif_key = key.clone();
                        drop(key);
                        peer_service
                            .disconnect(verif_key, circuit_id, connection_info.conn_id)
                            .await;
                        return;
                    }
                }
                Err(e) => {
                    log_service.error("LocalPeerServiceInit".to_string(), e);
                    let key = remote_verifying_key.lock().await;
                    let verif_key = key.clone();
                    drop(key);
                    peer_service
                        .disconnect(verif_key, circuit_id, connection_info.conn_id)
                        .await;
                    return;
                }
            }

            let mut remote_rooms: HashSet<Uid> = HashSet::new();
            let acquired_lock = Arc::new(Mutex::new(HashSet::<Uid>::new()));
            loop {
                tokio::select! {
                    msg = remote_event.recv() =>{
                        match msg{
                            Some(msg) => {
                                let key = remote_verifying_key.lock().await;
                                let verif_key = key.clone();
                                drop(key);

                                if let Err(e) = Self::process_remote_event(
                                    msg,
                                    lock_reply.clone(),
                                    &lock_service,
                                    &query_service,
                                    &mut remote_rooms,
                                    circuit_id,
                                    &conn_ready,
                                    &event_sender,
                                    &peer_service,
                                    verif_key,
                                    connection_info.conn_id
                                 )
                                    .await{
                                        log_service.error("LocalPeerService remote event".to_string(),e);
                                        break;
                                }
                            }
                            None => break,
                        }
                    }

                    msg = local_event.recv() =>{
                        if let Ok(msg) = msg{
                            if let Err(e) = Self::process_local_event(msg, &remote_verifying_key, &event_sender, &remote_rooms, &inbound_query_service).await{
                                log_service.error("LocalPeerService Local event".to_string(),e);
                                break;
                            }
                        }
                    }

                    msg = lock_receiver.recv() =>{
                        match msg{
                            Some(room) => {
                                if let Err(e) =Self::process_acquired_lock(
                                    room,
                                    acquired_lock.clone(),
                                    db.clone(),
                                    query_service.clone(),
                                    event_service.clone(),
                                    log_service.clone(),
                                    lock_service.clone(),
                                    verify_service.clone(),
                                    peer_service.clone(),
                                )
                                    .await {
                                        log_service.error("LocalPeerService Lock".to_string(),e);
                                        break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
            let acquere = acquired_lock.lock().await;
            let mut rooms: Vec<Uid> = Vec::new();
            for room in acquere.iter() {
                rooms.push(*room);
            }
            Self::cleanup(&lock_service, rooms).await;
            let key = remote_verifying_key.lock().await;
            peer_service
                .disconnect(key.clone(), circuit_id, connection_info.conn_id)
                .await;
        });
    }
    #[allow(clippy::too_many_arguments)]
    async fn process_remote_event(
        event: RemoteEvent,
        lock_reply: mpsc::UnboundedSender<Uid>,
        lock_service: &RoomLockService,
        query_service: &QueryService,
        remote_rooms: &mut HashSet<Uid>,
        circuit_id: [u8; 32],
        conn_ready: &Arc<AtomicBool>,
        event_sender: &Sender<RemoteEvent>,
        peer_service: &PeerConnectionService,
        verifying_key: Vec<u8>,
        connection_id: Uid,
    ) -> Result<(), crate::Error> {
        match event {
            RemoteEvent::Ready => {
                let mut rooms_rcv: Receiver<Result<VecDeque<Uid>, Error>> =
                    Self::query_multiple(query_service, Query::RoomList).await;
                while let Some(rooms) = rooms_rcv.recv().await {
                    let rooms = rooms?;
                    for room in &rooms {
                        remote_rooms.insert(*room);
                    }
                    lock_service
                        .request_locks(circuit_id, rooms, lock_reply.clone())
                        .await;
                }
            }

            RemoteEvent::ReadyFingerprint => {
                let fingerprint: HardwareFingerprint =
                    Self::query(query_service, Query::HardwareFingerprint()).await?;

                let (reply, receive) = oneshot::channel::<Result<bool, crate::Error>>();
                let _ = peer_service
                    .sender
                    .send(PeerConnectionMessage::ValidateHardware(
                        circuit_id,
                        fingerprint,
                        reply,
                    ))
                    .await;

                let validated = receive.await??;

                if validated {
                    conn_ready.store(true, Ordering::Relaxed);

                    Self::send_event(event_sender, RemoteEvent::Ready)
                        .await
                        .map_err(|_| crate::Error::TimeOut("Ready".to_string()))?;

                    peer_service.connected(verifying_key, connection_id).await;
                } else {
                    peer_service
                        .disconnect(verifying_key, circuit_id, connection_id)
                        .await;
                }
            }

            RemoteEvent::RoomDefinitionChanged(room) => {
                remote_rooms.insert(room);
                let mut q = VecDeque::new();
                q.push_back(room);
                lock_service.request_locks(circuit_id, q, lock_reply).await;
            }

            RemoteEvent::RoomDataChanged(room) => {
                if remote_rooms.contains(&room) {
                    let mut q = VecDeque::new();
                    q.push_back(room);
                    lock_service.request_locks(circuit_id, q, lock_reply).await;
                }
            }
        }
        Ok(())
    }

    async fn process_local_event(
        msg: LocalEvent,
        remote_key: &Arc<Mutex<Vec<u8>>>,
        event_sender: &Sender<RemoteEvent>,
        remote_rooms: &HashSet<Uid>,
        inbound_query_service: &InboundQueryService,
    ) -> Result<(), crate::Error> {
        match msg {
            LocalEvent::RoomDefinitionChanged(room) => {
                let key = remote_key.lock().await;
                if room.has_user(&key) {
                    inbound_query_service.add_allowed_room(room.id);
                    Self::send_event(event_sender, RemoteEvent::RoomDefinitionChanged(room.id))
                        .await
                        .map_err(|_| crate::Error::TimeOut("RoomDefinitionChanged".to_string()))?;
                }
            }
            LocalEvent::RoomDataChanged(rooms) => {
                for room in rooms {
                    if remote_rooms.contains(&room) {
                        Self::send_event(event_sender, RemoteEvent::RoomDataChanged(room))
                            .await
                            .map_err(|_| {
                                crate::Error::TimeOut("RoomDefinitionChanged".to_string())
                            })?;
                    }
                }
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    async fn process_acquired_lock(
        room: Uid,
        acquired_lock: Arc<Mutex<HashSet<Uid>>>,
        db: GraphDatabaseService,
        query_service: QueryService,
        event_service: EventService,
        log_service: LogService,
        lock_service: RoomLockService,
        verify_service: SignatureVerificationService,
        peer_service: PeerConnectionService,
    ) -> Result<(), crate::Error> {
        tokio::spawn(async move {
            {
                acquired_lock.lock().await.insert(room);
            }
            match Self::synchronise_room(
                room,
                &db,
                &query_service,
                &verify_service,
                peer_service,
                &log_service,
            )
            .await
            {
                Ok(_) => {
                    event_service
                        .notify(EventServiceMessage::RoomSynchronized(room))
                        .await;
                }
                Err(e) => {
                    log_service.error("synchronise_room".to_string(), e);

                    //TODO should stop the peer???
                }
            };

            lock_service.unlock(room).await;
            acquired_lock.lock().await.remove(&room);
        });

        Ok(())
    }

    async fn synchronise_room(
        room_id: Uid,
        db: &GraphDatabaseService,
        query_service: &QueryService,
        verify_service: &SignatureVerificationService,
        peer_service: PeerConnectionService,
        log_service: &LogService,
    ) -> Result<(), crate::Error> {
        //
        // update room definition
        //
        let remote_room_def: Option<RoomDefinitionLog> =
            Self::query(query_service, Query::RoomDefinition(room_id)).await?;
        let local_room_def = db.get_room_definition(room_id).await?;

        if remote_room_def.is_none() {
            return Err(crate::Error::RoomUnknow(base64_encode(&room_id)));
        }
        let remote_room = remote_room_def.unwrap();
        Self::synchronise_room_definition(
            &remote_room,
            &local_room_def,
            db,
            query_service,
            verify_service,
        )
        .await?;

        //
        //retrieve the peers for the room and insert/update the changes
        //
        let mut local_peers_receiv = db.peers_for_room(room_id).await;
        let mut local_peers = HashMap::new();
        while let Some(node) = local_peers_receiv.recv().await {
            match node {
                Ok(nodes) => {
                    for node in nodes {
                        local_peers.insert(node.id, node);
                    }
                }
                Err(e) => return Err(crate::Error::from(e)),
            }
        }

        let mut peers_receiv: Receiver<Result<Vec<Node>, Error>> =
            Self::query_multiple(query_service, Query::PeersForRoom(room_id)).await;

        let mut peer_nodes: Vec<Node> = Vec::new();
        while let Some(node) = peers_receiv.recv().await {
            match node {
                Ok(nodes) => {
                    for node in nodes {
                        let local = local_peers.get(&node.id);
                        match local {
                            Some(local_node) => {
                                if local_node.mdate < node.mdate {
                                    Peer::validate(&node)?;
                                    peer_nodes.push(node);
                                }
                            }
                            None => {
                                Peer::validate(&node)?;
                                peer_nodes.push(node);
                            }
                        }
                    }
                }
                Err(e) => return Err(crate::Error::from(e)),
            }
        }

        let peer_nodes: Vec<Node> = verify_service.verify_nodes(peer_nodes).await?;
        db.add_peer_nodes(peer_nodes.clone()).await?;

        let _ = peer_service
            .sender
            .send(PeerConnectionMessage::NewPeer(peer_nodes))
            .await;

        if Self::synchronise_room_data(
            &remote_room,
            &local_room_def,
            db,
            query_service,
            verify_service,
            log_service,
        )
        .await?
        {
            db.compute_daily_log().await;
        }
        Ok(())
    }

    async fn synchronise_room_definition(
        remote_room: &RoomDefinitionLog,
        local_room_def: &Option<RoomDefinitionLog>,
        db: &GraphDatabaseService,
        query_service: &QueryService,
        verify_service: &SignatureVerificationService,
    ) -> Result<(), crate::Error> {
        let load_room = match local_room_def {
            Some(local_room) => local_room.room_def_date < remote_room.room_def_date,
            None => true,
        };

        if load_room {
            let node: Option<RoomNode> =
                Self::query(query_service, Query::RoomNode(remote_room.room_id)).await?;
            match node {
                Some(node) => {
                    let node = verify_service.verify_room_node(node).await?;
                    db.add_room_node(node).await?
                }
                None => {
                    return Err(crate::Error::RoomUnknow(base64_encode(
                        &remote_room.room_id,
                    )))
                }
            }
        }

        Ok(())
    }

    async fn synchronise_room_data(
        remote_room: &RoomDefinitionLog,
        local_room_def: &Option<RoomDefinitionLog>,
        db: &GraphDatabaseService,
        query_service: &QueryService,
        verify_service: &SignatureVerificationService,
        log_service: &LogService,
    ) -> Result<bool, crate::Error> {
        let sync_history = match local_room_def {
            Some(local_room) => {
                !(remote_room.history_hash.is_some()
                    && local_room.history_hash.eq(&remote_room.history_hash)
                    && local_room.last_data_date.eq(&remote_room.last_data_date))
            }
            None => true,
        };
        if sync_history {
            Self::synchronise_history(
                remote_room.room_id,
                db,
                query_service,
                verify_service,
                log_service,
            )
            .await
        } else {
            Self::synchronise_last_day(
                remote_room,
                local_room_def,
                db,
                query_service,
                verify_service,
                log_service,
            )
            .await
        }
    }

    async fn synchronise_history(
        room_id: Uid,
        db: &GraphDatabaseService,
        query_service: &QueryService,
        verify_service: &SignatureVerificationService,
        log_service: &LogService,
    ) -> Result<bool, crate::Error> {
        let mut remote_log_receiver: Receiver<Result<Vec<DailyLog>, Error>> =
            Self::query_multiple(query_service, Query::RoomLog(room_id)).await;
        let mut remote_log: Vec<DailyLog> = Vec::new();
        while let Some(log) = remote_log_receiver.recv().await {
            match log {
                Ok(mut log) => remote_log.append(&mut log),
                Err(e) => return Err(crate::Error::from(e)),
            }
        }

        let mut local_log_receiver = db.get_room_log(room_id).await;
        let mut local_log: Vec<DailyLog> = Vec::new();
        while let Some(log) = local_log_receiver.recv().await {
            match log {
                Ok(mut log) => local_log.append(&mut log),
                Err(e) => return Err(crate::Error::from(e)),
            }
        }
        let mut local_map: HashMap<i64, HashMap<String, DailyLog>> =
            HashMap::with_capacity(local_log.len());

        for log in local_log {
            let room_entry = local_map.entry(log.date).or_default();

            room_entry.insert(log.entity.clone(), log);
        }
        let mut modified = false;
        for remote in &remote_log {
            let local_room_date = local_map.get(&remote.date);
            match local_room_date {
                Some(local_room_date) => {
                    let local_entity_log = local_room_date.get(&remote.entity);

                    match local_entity_log {
                        Some(local_log) => {
                            if !local_log.daily_hash.eq(&remote.daily_hash) {
                                if Self::synchronise_day(
                                    room_id,
                                    remote.entity.clone(),
                                    remote.date,
                                    db,
                                    query_service,
                                    verify_service,
                                    log_service,
                                )
                                .await?
                                {
                                    modified = true;
                                }
                            }
                        }
                        None => {
                            if Self::synchronise_day(
                                room_id,
                                remote.entity.clone(),
                                remote.date,
                                db,
                                query_service,
                                verify_service,
                                log_service,
                            )
                            .await?
                            {
                                modified = true;
                            }
                        }
                    }
                }
                None => {
                    if Self::synchronise_day(
                        room_id,
                        remote.entity.clone(),
                        remote.date,
                        db,
                        query_service,
                        verify_service,
                        log_service,
                    )
                    .await?
                    {
                        modified = true;
                    }
                }
            }
        }
        Ok(modified)
    }

    async fn synchronise_last_day(
        remote_room: &RoomDefinitionLog,
        local_room_def: &Option<RoomDefinitionLog>,
        db: &GraphDatabaseService,
        query_service: &QueryService,
        verify_service: &SignatureVerificationService,
        log_service: &LogService,
    ) -> Result<bool, crate::Error> {
        let sync_day = match local_room_def {
            Some(local_room) => {
                !(local_room.daily_hash.is_some()
                    && local_room.last_data_date.is_some()
                    && local_room.daily_hash.eq(&remote_room.daily_hash))
            }
            None => true,
        };

        if sync_day {
            let remote_log: Vec<DailyLog> = Self::query(
                query_service,
                Query::RoomLogAt(remote_room.room_id, remote_room.last_data_date.unwrap()),
            )
            .await?;

            for log in remote_log {
                Self::synchronise_day(
                    remote_room.room_id,
                    log.entity,
                    remote_room.last_data_date.unwrap(), //checked by sync_day
                    db,
                    query_service,
                    verify_service,
                    log_service,
                )
                .await?;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn synchronise_day(
        room_id: Uid,
        entity: String,
        date: i64,
        db: &GraphDatabaseService,
        query_service: &QueryService,
        verify_service: &SignatureVerificationService,
        log: &LogService,
    ) -> Result<bool, crate::Error> {
        let mut has_changes = false;

        //edge deletion
        let mut edge_deletion_recv: Receiver<Result<Vec<EdgeDeletionEntry>, Error>> =
            Self::query_multiple(
                query_service,
                Query::EdgeDeletionLog(room_id, entity.clone(), date),
            )
            .await;
        while let Some(edge_deletion) = edge_deletion_recv.recv().await {
            let edge_deletion = edge_deletion?;
            if !edge_deletion.is_empty() {
                has_changes = true;
                let edge_deletion = verify_service.verify_edge_log(edge_deletion).await?;
                db.delete_edges(edge_deletion).await?;
            }
        }

        //node deletion
        let mut node_deletion_recv: Receiver<Result<Vec<NodeDeletionEntry>, Error>> =
            Self::query_multiple(
                query_service,
                Query::NodeDeletionLog(room_id, entity.clone(), date),
            )
            .await;
        while let Some(node_deletion) = node_deletion_recv.recv().await {
            let node_deletion = node_deletion?;
            if !node_deletion.is_empty() {
                has_changes = true;
                let node_deletion = verify_service.verify_node_log(node_deletion).await?;
                db.delete_nodes(node_deletion).await?;
            }
        }
        //node insertion
        let mut remote_nodes_receiv: Receiver<Result<HashSet<NodeIdentifier>, Error>> =
            Self::query_multiple(
                query_service,
                Query::RoomDailyNodes(room_id, entity.clone(), date),
            )
            .await;
        let mut remote_nodes = HashSet::new();
        while let Some(nodes) = remote_nodes_receiv.recv().await {
            match nodes {
                Ok(nodes) => {
                    for node in nodes {
                        remote_nodes.insert(node);
                    }
                }
                Err(e) => return Err(crate::Error::from(e)),
            }
        }

        let filtered = db.filter_existing_node(remote_nodes).await?;
        if !filtered.is_empty() {
            has_changes = true;
        } else {
            return Ok(has_changes);
        }

        let batch_size = 2048;
        let mut node_list = Vec::with_capacity(batch_size);
        let mut edge_list = Vec::with_capacity(batch_size);
        let mut node_map = HashMap::with_capacity(batch_size);

        for node_to_insert in filtered {
            node_list.push(node_to_insert.id);
            edge_list.push((node_to_insert.id, node_to_insert.old_mdate));
            node_map.insert(node_to_insert.id, node_to_insert);
            if node_list.len() == batch_size {
                let mut result_recv: Receiver<Result<Vec<Node>, Error>> =
                    LocalPeerService::query_multiple(
                        query_service,
                        Query::Nodes(room_id, node_list.clone()),
                    )
                    .await;
                while let Some(nodes) = result_recv.recv().await {
                    let nodes = nodes?;
                    let nodes = verify_service.verify_nodes(nodes).await?;
                    let mut nodes_to_insert = Vec::with_capacity(nodes.len());
                    for mut node in nodes {
                        if let Some(mut nti) = node_map.remove(&node.id) {
                            node._local_id = nti.old_local_id;
                            nti.node = Some(node);
                            nodes_to_insert.push(nti);
                        }
                    }
                    let res = db.add_nodes(room_id, nodes_to_insert).await?;
                    if !res.is_empty() {
                        log.error(
                            "synchronise_day".to_string(),
                            crate::Error::NodeRejected(res.len(), uid_encode(&room_id), date),
                        )
                    }
                }
                let mut result_recv: Receiver<Result<Vec<Edge>, Error>> =
                    LocalPeerService::query_multiple(
                        query_service,
                        Query::Edges(room_id, edge_list.clone()),
                    )
                    .await;

                while let Some(edges) = result_recv.recv().await {
                    let edges = edges?;
                    let edges = verify_service.verify_edges(edges).await?;
                    let res = db.add_edges(room_id, edges).await?;
                    if !res.is_empty() {
                        log.error(
                            "synchronise_day".to_string(),
                            crate::Error::EdgeRejected(res.len(), uid_encode(&room_id), date),
                        )
                    }
                }
                node_list.clear();
                node_map.clear();
            }
        }

        if !node_list.is_empty() {
            let mut result_recv: Receiver<Result<Vec<Node>, Error>> =
                LocalPeerService::query_multiple(query_service, Query::Nodes(room_id, node_list))
                    .await;
            while let Some(nodes) = result_recv.recv().await {
                let nodes = nodes?;
                let nodes = verify_service.verify_nodes(nodes).await?;
                let mut nodes_to_insert = Vec::with_capacity(nodes.len());
                for mut node in nodes {
                    if let Some(mut nti) = node_map.remove(&node.id) {
                        node._local_id = nti.old_local_id;
                        nti.node = Some(node);
                        nodes_to_insert.push(nti);
                    }
                }
                let res = db.add_nodes(room_id, nodes_to_insert).await?;
                if !res.is_empty() {
                    log.error(
                        "synchronise_day".to_string(),
                        crate::Error::NodeRejected(res.len(), uid_encode(&room_id), date),
                    )
                }
            }

            let mut result_recv: Receiver<Result<Vec<Edge>, Error>> =
                LocalPeerService::query_multiple(
                    query_service,
                    Query::Edges(room_id, edge_list.clone()),
                )
                .await;

            while let Some(edges) = result_recv.recv().await {
                let edges = edges?;
                let edges = verify_service.verify_edges(edges).await?;
                let res = db.add_edges(room_id, edges).await?;
                if !res.is_empty() {
                    log.error(
                        "synchronise_day".to_string(),
                        crate::Error::EdgeRejected(res.len(), uid_encode(&room_id), date),
                    )
                }
            }
        }

        Ok(has_changes)
    }

    pub async fn send_event(
        event_sender: &Sender<RemoteEvent>,
        event: RemoteEvent,
    ) -> Result<(), mpsc::error::SendTimeoutError<RemoteEvent>> {
        event_sender
            .send_timeout(event, Duration::from_secs(NETWORK_TIMEOUT_SEC))
            .await
    }

    async fn query<T: DeserializeOwned + Send + 'static>(
        query_service: &QueryService,
        query: Query,
    ) -> Result<T, Error> {
        let (send, recieve) = oneshot::channel::<Result<T, Error>>();

        let answer: AnswerFn = Box::new(move |succes, _, serialized| {
            let answer = if succes {
                match bincode::deserialize::<T>(&serialized) {
                    Ok(result) => Ok(result),
                    Err(_) => Err(Error::Parsing),
                }
            } else {
                match bincode::deserialize::<Error>(&serialized) {
                    Ok(result) => Err(result),
                    Err(_) => Err(Error::Parsing),
                }
            };

            let _ = send.send(answer);
            Box::pin(async {})
        });

        query_service.send(QueryFn::Once(query, answer)).await;
        match timeout(Duration::from_secs(NETWORK_TIMEOUT_SEC), recieve).await {
            Ok(r) => match r {
                Ok(result) => result,
                Err(_) => Err(Error::Technical),
            },
            Err(_) => Err(Error::TimeOut),
        }
    }

    async fn query_multiple<T: DeserializeOwned + Send + 'static>(
        query_service: &QueryService,
        query: Query,
    ) -> mpsc::Receiver<Result<T, Error>> {
        let (sender, receiv) = mpsc::channel(1);
        let answer: AnswerMultipleFn = Box::new(move |succes, complete, serialized| {
            if !complete {
                let answer = if succes {
                    match bincode::deserialize::<T>(&serialized) {
                        Ok(result) => Ok(result),
                        Err(_) => Err(Error::Parsing),
                    }
                } else {
                    match bincode::deserialize::<Error>(&serialized) {
                        Ok(result) => Err(result),
                        Err(_) => Err(Error::Parsing),
                    }
                };
                let sender = sender.clone();
                Box::pin(async move {
                    let _ = sender.send(answer).await;
                })
            } else {
                Box::pin(async {})
            }
        });

        query_service.send(QueryFn::Multiple(query, answer)).await;
        receiv
    }

    ///
    /// cleanup locks that could have been acquired
    /// and ask the peer service to remove this peer
    ///
    pub async fn cleanup(lock_service: &RoomLockService, rooms: Vec<Uid>) {
        for room in rooms {
            lock_service.unlock(room).await;
        }
    }
}
