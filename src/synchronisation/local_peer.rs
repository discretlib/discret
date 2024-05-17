use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::Duration,
};

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
    cryptography::{base64_encode, random32},
    database::{
        daily_log::{DailyLog, RoomDefinitionLog},
        edge::EdgeDeletionEntry,
        graph_database::GraphDatabaseService,
        node::{NodeDeletionEntry, NodeIdentifier},
    },
    event_service::{EventService, EventServiceMessage},
    log_service::LogService,
};

use super::{
    node_full::FullNode, peer_service::PeerConnectionService,
    room_locking_service::RoomLockService, room_node::RoomNode, Answer, Error, LocalEvent,
    ProveAnswer, Query, QueryProtocol, RemoteEvent, NETWORK_TIMEOUT_SEC,
};

static QUERY_SEND_BUFFER: usize = 10;

pub type AnswerFn = Box<dyn FnOnce(bool, Vec<u8>) + Send + 'static>;

pub struct QueryService {
    sender: mpsc::Sender<(Query, AnswerFn)>,
}
impl QueryService {
    pub fn start(
        remote_sender: mpsc::Sender<QueryProtocol>,
        mut remote_receiver: mpsc::Receiver<Answer>,
        log_service: LogService,
    ) -> Self {
        let (sender, mut local_receiver) = mpsc::channel::<(Query, AnswerFn)>(QUERY_SEND_BUFFER);

        tokio::spawn(async move {
            let mut next_message_id: u64 = 0;
            let mut sent_query: HashMap<u64, AnswerFn> = HashMap::new();

            loop {
                tokio::select! {
                    msg = local_receiver.recv() =>{
                        match msg {
                            Some(msg) => {
                                let id = next_message_id;
                                let query = msg.0;
                                let query_prot = QueryProtocol { id, query };

                                if let Err(e)  = remote_sender.send(query_prot).await {
                                    log_service.error("QueryService".to_string(), crate::Error::SendError(e.to_string()));
                                    break;
                                }
                                let answer_func = msg.1;
                                sent_query.insert(id, answer_func);
                                next_message_id += 1;
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
                                    func(msg.success, msg.serialized);
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

    async fn send(&self, query: Query, answer: AnswerFn) {
        let _ = self.sender.send((query, answer)).await;
    }
}

pub struct LocalPeerService {}
impl LocalPeerService {
    pub fn start(
        mut peer: LocalPeer,
        mut remote_event: Receiver<RemoteEvent>,
        mut local_event: broadcast::Receiver<LocalEvent>,
        remote_key: Arc<Mutex<Vec<u8>>>,
        log_service: LogService,
        peer_service: PeerConnectionService,
        event_service: EventService,
    ) {
        let (lock_reply, mut lock_receiver) = mpsc::unbounded_channel::<Vec<u8>>();

        tokio::spawn(async move {
            let challenge = random32().to_vec();

            let ret: Result<(), crate::Error> = async {
                let proof: ProveAnswer =
                    peer.query(Query::ProveIdentity(challenge.clone())).await?;
                proof.verify(&challenge)?;
                {
                    let mut key = remote_key.lock().await;
                    *key = proof.verifying_key.clone();
                }

                peer.send_event(RemoteEvent::Ready)
                    .await
                    .map_err(|_| crate::Error::TimeOut("Ready".to_string()))?;

                peer_service
                    .connected(proof.verifying_key, peer.hardware_id.clone())
                    .await;
                Ok(())
            }
            .await;

            if let Err(e) = ret {
                log_service.error("LocalPeerServiceInit".to_string(), e);
                let key = remote_key.lock().await;
                peer_service.disconnect(key.clone(), peer.hardware_id).await;
                return;
            }

            let acquired_lock: Arc<Mutex<HashSet<Vec<u8>>>> =
                Arc::new(Mutex::new(HashSet::<Vec<u8>>::new()));
            loop {
                tokio::select! {
                    msg = remote_event.recv() =>{
                        match msg{
                            Some(msg) => {
                                if let Err(e) = Self::process_remote_event(msg, &mut peer, lock_reply.clone()).await{
                                    log_service.error("LocalPeerService remote event".to_string(),e);
                                    break;
                                }
                            }
                            None => break,
                        }
                    }

                    msg = local_event.recv() =>{
                        if let Ok(msg) = msg{
                            if let Err(e) = Self::process_local_event(msg, &remote_key, &mut peer).await{
                                log_service.error("LocalPeerService Local event".to_string(),e);
                                break;
                            }
                        }
                    }

                    msg = lock_receiver.recv() =>{
                        match msg{
                            Some(room) => {
                                if let Err(e) =Self::process_acquired_lock(room, &acquired_lock, &peer, &event_service).await{
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
            let mut rooms: Vec<Vec<u8>> = Vec::new();
            for room in acquere.iter() {
                rooms.push(room.clone());
            }
            peer.cleanup(rooms).await;
            let key = remote_key.lock().await;
            peer_service.disconnect(key.clone(), peer.hardware_id).await;
        });
    }

    async fn process_remote_event(
        event: RemoteEvent,
        peer: &mut LocalPeer,
        lock_reply: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<(), crate::Error> {
        match event {
            RemoteEvent::Ready => {
                let rooms: VecDeque<Vec<u8>> = peer.query(Query::RoomList).await?;
                for room in &rooms {
                    peer.remote_rooms.insert(room.clone());
                }
                peer.lock_service
                    .request_locks(peer.hardware_id.clone(), rooms, lock_reply.clone())
                    .await;
            }

            RemoteEvent::RoomDefinitionChanged(room) => {
                peer.remote_rooms.insert(room.clone());
                let mut q = VecDeque::new();
                q.push_back(room);
                peer.lock_service
                    .request_locks(peer.hardware_id.clone(), q, lock_reply)
                    .await;
            }
            RemoteEvent::RoomDataChanged(room) => {
                if peer.remote_rooms.contains(&room) {
                    let mut q = VecDeque::new();
                    q.push_back(room);
                    peer.lock_service
                        .request_locks(peer.hardware_id.clone(), q, lock_reply)
                        .await;
                }
            }
        }
        Ok(())
    }

    async fn process_local_event(
        msg: LocalEvent,
        remote_key: &Arc<Mutex<Vec<u8>>>,
        peer: &LocalPeer,
    ) -> Result<(), crate::Error> {
        match msg {
            LocalEvent::RoomDefinitionChanged(room) => {
                let key = remote_key.lock().await;
                if room.has_user(&key) {
                    peer.send_event(RemoteEvent::RoomDefinitionChanged(room.id))
                        .await
                        .map_err(|_| crate::Error::TimeOut("RoomDefinitionChanged".to_string()))?;
                }
            }
            LocalEvent::RoomDataChanged(rooms) => {
                for room in rooms {
                    if peer.remote_rooms.contains(&room) {
                        peer.send_event(RemoteEvent::RoomDataChanged(room))
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

    async fn process_acquired_lock(
        room: Vec<u8>,
        acquired_lock: &Arc<Mutex<HashSet<Vec<u8>>>>,
        peer: &LocalPeer,
        event_service: &EventService,
    ) -> Result<(), crate::Error> {
        acquired_lock.lock().await.insert(room.clone());

        let ret = match Self::synchronise_room(room.clone(), peer).await {
            Ok(_) => {
                event_service
                    .notify(EventServiceMessage::RoomSynchronized(room.clone()))
                    .await;
                Ok(())
            }
            Err(e) => Err(e),
        };

        peer.lock_service.unlock(room.clone()).await;
        acquired_lock.lock().await.remove(&room);

        ret
    }

    async fn synchronise_room(room_id: Vec<u8>, peer: &LocalPeer) -> Result<(), crate::Error> {
        let remote_room_def: Option<RoomDefinitionLog> =
            peer.query(Query::RoomDefinition(room_id.clone())).await?;
        let local_room_def = peer.db.get_room_definition(room_id.clone()).await?;

        if remote_room_def.is_none() {
            return Err(crate::Error::RoomUnknow(base64_encode(&room_id)));
        }
        let remote_room = remote_room_def.unwrap();
        Self::synchronise_room_definition(&remote_room, &local_room_def, peer).await?;
        if Self::synchronise_room_data(&remote_room, &local_room_def, peer).await? {
            peer.db.compute_daily_log().await;
        }
        Ok(())
    }

    async fn synchronise_room_definition(
        remote_room: &RoomDefinitionLog,
        local_room_def: &Option<RoomDefinitionLog>,
        peer: &LocalPeer,
    ) -> Result<(), crate::Error> {
        let load_room = match local_room_def {
            Some(local_room) => {
                if local_room.room_def_date < remote_room.room_def_date {
                    true
                } else {
                    false
                }
            }
            None => true,
        };

        if load_room {
            let node: Option<RoomNode> = peer
                .query(Query::RoomNode(remote_room.room_id.clone()))
                .await?;
            match node {
                Some(node) => peer.db.add_room_node(node).await?,
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
        peer: &LocalPeer,
    ) -> Result<bool, crate::Error> {
        let sync_history = match local_room_def {
            Some(local_room) => {
                if remote_room.history_hash.is_some()
                    && local_room.history_hash.eq(&remote_room.history_hash)
                    && local_room.last_data_date.eq(&remote_room.last_data_date)
                {
                    false
                } else {
                    true
                }
            }
            None => true,
        };
        if sync_history {
            Self::synchronise_history(&remote_room.room_id, peer).await
        } else {
            Self::synchronise_last_day(remote_room, local_room_def, peer).await
        }
    }

    async fn synchronise_history(
        room_id: &Vec<u8>,
        peer: &LocalPeer,
    ) -> Result<bool, crate::Error> {
        let remote_log: Vec<DailyLog> = peer.query(Query::RoomLog(room_id.clone())).await?;
        let local_log = peer.db.get_room_log(room_id.clone()).await?;

        let mut local_map = HashMap::with_capacity(local_log.len());
        for log in local_log {
            local_map.insert(log.date, log);
        }
        let mut modified = false;
        for remote in &remote_log {
            let local_log = local_map.get(&remote.date);
            match local_log {
                Some(local_log) => {
                    if !local_log.daily_hash.eq(&remote.daily_hash) {
                        if Self::synchronise_day(room_id, remote.date, peer).await? {
                            modified = true;
                        }
                    }
                }
                None => {
                    if Self::synchronise_day(room_id, remote.date, peer).await? {
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
        peer: &LocalPeer,
    ) -> Result<bool, crate::Error> {
        let sync_day = match local_room_def {
            Some(local_room) => {
                if local_room.daily_hash.is_some()
                    && local_room.last_data_date.is_some()
                    && local_room.daily_hash.eq(&remote_room.daily_hash)
                {
                    false
                } else {
                    true
                }
            }
            None => true,
        };

        if sync_day {
            Self::synchronise_day(
                &remote_room.room_id,
                remote_room.last_data_date.unwrap(), //checked by sync_day
                peer,
            )
            .await
        } else {
            Ok(false)
        }
    }

    async fn synchronise_day(
        room_id: &Vec<u8>,
        date: i64,
        peer: &LocalPeer,
    ) -> Result<bool, crate::Error> {
        let edge_deletion: Vec<EdgeDeletionEntry> = peer
            .query(Query::EdgeDeletionLog(room_id.clone(), date))
            .await?;
        peer.db.delete_edges(edge_deletion).await?;

        let node_deletion: Vec<NodeDeletionEntry> = peer
            .query(Query::NodeDeletionLog(room_id.clone(), date))
            .await?;
        let max_deletion = 512;
        let mut current = Vec::with_capacity(max_deletion);
        for node_del in node_deletion {
            current.push(node_del);
            if current.len() == max_deletion {
                peer.db.delete_nodes(current).await?;
                current = Vec::with_capacity(max_deletion);
            }
        }
        if !current.is_empty() {
            peer.db.delete_nodes(current).await?;
        }

        let remote_nodes: HashSet<NodeIdentifier> = peer
            .query(Query::RoomDailyNodes(room_id.clone(), date))
            .await?;

        let filtered = peer.db.filter_existing_node(remote_nodes, date).await?;
        let max_nodes = 128;
        let mut current_list = Vec::with_capacity(max_nodes);

        for node_identifier in filtered {
            current_list.push(node_identifier.id);
            if current_list.len() == max_nodes {
                let nodes: Vec<FullNode> = peer
                    .query(Query::FullNodes(room_id.clone(), current_list))
                    .await?;
                peer.db.add_full_nodes(room_id.clone(), nodes).await?;

                current_list = Vec::with_capacity(max_nodes);
            }
        }
        if !current_list.is_empty() {
            let nodes: Vec<FullNode> = peer
                .query(Query::FullNodes(room_id.clone(), current_list))
                .await?;
            peer.db.add_full_nodes(room_id.clone(), nodes).await?;
        }
        Ok(false)
    }
}

pub struct LocalPeer {
    pub hardware_id: Vec<u8>,
    pub remote_rooms: HashSet<Vec<u8>>,
    pub db: GraphDatabaseService,
    pub lock_service: RoomLockService,
    pub query_service: QueryService,
    pub event_sender: Sender<RemoteEvent>,
}
impl LocalPeer {
    pub async fn send_event(
        &self,
        event: RemoteEvent,
    ) -> Result<(), mpsc::error::SendTimeoutError<RemoteEvent>> {
        self.event_sender
            .send_timeout(event, Duration::from_secs(NETWORK_TIMEOUT_SEC))
            .await
    }

    async fn query<T: DeserializeOwned + Send + 'static>(&self, query: Query) -> Result<T, Error> {
        let (send, recieve) = oneshot::channel::<Result<T, Error>>();
        let answer: AnswerFn = Box::new(move |succes, serialized| {
            if succes {
                match bincode::deserialize::<T>(&serialized) {
                    Ok(result) => {
                        let _ = send.send(Ok(result));
                    }
                    Err(_) => {
                        let _ = send.send(Err(Error::Parsing));
                    }
                }
            } else {
                match bincode::deserialize::<Error>(&serialized) {
                    Ok(result) => {
                        let _ = send.send(Err(result));
                    }
                    Err(_) => {
                        let _ = send.send(Err(Error::Parsing));
                    }
                }
            };
        });

        self.query_service.send(query, answer).await;
        match timeout(Duration::from_secs(NETWORK_TIMEOUT_SEC), recieve).await {
            Ok(r) => match r {
                Ok(result) => return result,
                Err(_) => return Err(Error::Technical),
            },
            Err(_) => return Err(Error::TimeOut),
        }
    }

    ///
    /// cleanup locks that could have been acquired
    /// and ask the peer service to remove this peer
    ///
    pub async fn cleanup(&self, rooms: Vec<Vec<u8>>) {
        for room in rooms {
            self.lock_service.unlock(room).await;
        }
    }
}
