//recuperer les differents policy_groups
//synchroniser le security group
//si nouveau groupe
//nosynch alert
//pour chaque policy dans les groupes
//recupérer les droits sur les schemas
//synchroniser les shemas un a un qui ont un droit read
//updater le daily log

use std::{
    collections::{HashMap, HashSet, VecDeque},
    os::unix::process,
    time::Duration,
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};

use crate::{
    database::{daily_log::RoomLog, graph_database::GraphDatabaseService},
    date_utils::now,
    event_service::{EventService, EventServiceMessage},
};

#[derive(Serialize, Deserialize)]
pub enum Query {
    RoomLog(Vec<u8>),
}

#[derive(Serialize, Deserialize)]
pub struct QueryProtocol {
    id: u64,
    query: Query,
}

#[derive(Serialize, Deserialize)]
pub struct AnswerProtocol {
    id: u64,
    success: bool,
    serialized: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub enum Protocol {
    Answer(AnswerProtocol),
    Query(QueryProtocol),
}

#[derive(Serialize, Deserialize)]
pub enum ErrorType {
    Authorisation,
    RemoteTechnical,
    TimeOut,
    Parsing,
    Technical,
}

///
/// handle all inbound queries
///
#[derive(Clone)]
pub struct RemotePeerQueryService {
    verifying_key: Vec<u8>,
}
impl RemotePeerQueryService {
    pub fn new(peer: RemotePeerQueryHandler, mut receiver: mpsc::Receiver<QueryProtocol>) -> Self {
        let verifying_key = peer.verifying_key.clone();
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                match msg.query {
                    Query::RoomLog(room_id) => {
                        if peer.allowed_room.contains(&room_id) {
                            let res = peer.local_db.get_room_log(room_id).await;
                            match res {
                                Ok(log) => peer.send(msg.id, true, log).await,
                                Err(_) => {
                                    peer.send(msg.id, false, ErrorType::RemoteTechnical).await
                                }
                            };
                        } else {
                            peer.send(msg.id, false, ErrorType::Authorisation).await;
                        }
                    }
                }
            }
        });
        Self { verifying_key }
    }
}

pub struct RemotePeerQueryHandler {
    connection_id: i64,
    verifying_key: Vec<u8>,
    allowed_room: HashSet<Vec<u8>>,
    local_db: GraphDatabaseService,
    peer_mgmt_service: PeerConnectionService,
    reply: mpsc::Sender<Protocol>,
}
impl RemotePeerQueryHandler {
    async fn load_allowed_room(&mut self) {
        let r = self
            .local_db
            .get_room_for_user(self.verifying_key.clone())
            .await;
        match r {
            Ok(rooms) => {
                for room in rooms {
                    self.allowed_room.insert(room.room_id);
                }
            }
            Err(_) => self.allowed_room = HashSet::new(),
        }
    }
    //handle sending error by notifying the manager
    async fn send<T: Serialize>(&self, id: u64, success: bool, msg: T) {
        match bincode::serialize(&msg) {
            Ok(serialized) => {
                let answer = AnswerProtocol {
                    id,
                    success,
                    serialized,
                };
                if let Err(_) = self.reply.send(Protocol::Answer(answer)).await {
                    let _ = self
                        .peer_mgmt_service
                        .sender
                        .send(PeerConnectionMessage::DisconnectPeer(self.connection_id))
                        .await;
                }
            }
            Err(_) => {
                let _ = self
                    .peer_mgmt_service
                    .sender
                    .send(PeerConnectionMessage::DisconnectPeer(self.connection_id))
                    .await;
            }
        };
    }
}

static QUERY_SEND_BUFFER: usize = 10;

//queries have 10 seconds to answer before closing connection
static NETWORK_TIMEOUT_SEC: u64 = 10;

pub type AnswerFn = Box<dyn FnOnce(bool, Vec<u8>) + Send + 'static>;

pub struct LocalPeerQueryService {
    sender: mpsc::Sender<(Query, AnswerFn)>,
}
impl LocalPeerQueryService {
    pub fn new(
        remote_sender: mpsc::Sender<Protocol>,
        mut remote_receiver: mpsc::Receiver<AnswerProtocol>,
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
                                let _ = remote_sender.send(Protocol::Query(query_prot)).await;
                                let answer_func = msg.1;
                                sent_query.insert(id, answer_func);
                                next_message_id += 1;
                            },
                            None => break,
                        }
                    }
                    msg = remote_receiver.recv() =>{
                        match msg {
                            Some(msg) => {
                                if let Some(func) = sent_query.remove(&msg.id) {
                                    func(msg.success, msg.serialized);
                                }
                            }
                            None => break,
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

pub struct PeerSynchronisation {
    connection_id: i64,
    verifying_key: Vec<u8>,
    remote_rooms: HashSet<Vec<u8>>,
    local_db: GraphDatabaseService,
    peer_mgmt_service: PeerConnectionService,
    sync_lock: SynchLockService,
    query_service: LocalPeerQueryService,
    current_sync_room: Option<Vec<u8>>,
}
impl PeerSynchronisation {
    pub async fn get_room_log(&self, room_id: Vec<u8>) -> Result<Vec<RoomLog>, ErrorType> {
        let query = Query::RoomLog(room_id);
        self.query(query).await
    }

    async fn query<T: DeserializeOwned + Send + 'static>(
        &self,
        query: Query,
    ) -> Result<T, ErrorType> {
        let (send, recieve) = oneshot::channel::<Result<T, ErrorType>>();
        let answer: AnswerFn = Box::new(move |succes, serialized| {
            if succes {
                match bincode::deserialize::<T>(&serialized) {
                    Ok(result) => {
                        let _ = send.send(Ok(result));
                    }
                    Err(_) => {
                        let _ = send.send(Err(ErrorType::Parsing));
                    }
                }
            } else {
                match bincode::deserialize::<ErrorType>(&serialized) {
                    Ok(result) => {
                        let _ = send.send(Err(result));
                    }
                    Err(_) => {
                        let _ = send.send(Err(ErrorType::Parsing));
                    }
                }
            };
        });

        self.query_service.send(query, answer).await;

        match timeout(Duration::from_secs(NETWORK_TIMEOUT_SEC), recieve).await {
            Ok(r) => match r {
                Ok(result) => return result,
                Err(_) => return Err(ErrorType::Technical),
            },
            Err(_) => return Err(ErrorType::TimeOut),
        }
    }

    fn acquire_lock(&mut self, room_id: Vec<u8>) {
        todo!()
    }

    fn release_lock(&mut self) {
        todo!()
        // //release lock before closing
        // if let Some(synch) = self.current_sync_room {
        //     self.sync_lock
        // }
    }
}

enum PeerConnectionMessage {
    NewPeer(
        Vec<u8>,
        mpsc::Sender<Protocol>,
        mpsc::Receiver<QueryProtocol>,
    ),
    DisconnectPeer(i64),
}

static PEER_CHANNEL_SIZE: usize = 32;

///
/// Handle the creation and removal of peers
///
#[derive(Clone)]
pub struct PeerConnectionService {
    sender: mpsc::Sender<PeerConnectionMessage>,
}
impl PeerConnectionService {
    pub fn new(
        local_db: GraphDatabaseService,
        sync_lock: SynchLockService,
        event_service: EventService,
    ) -> Self {
        let (sender, mut receiver) = mpsc::channel::<PeerConnectionMessage>(PEER_CHANNEL_SIZE);
        let mgmt = Self { sender };
        let ret = mgmt.clone();
        tokio::spawn(async move {
            let mut peer_map = HashMap::new();
            let mut peer_id: i64 = 1;

            while let Some(msg) = receiver.recv().await {
                match msg {
                    PeerConnectionMessage::NewPeer(verifying_key, reply, receiver) => {
                        let peer = RemotePeerQueryHandler {
                            connection_id: peer_id,
                            verifying_key: verifying_key.clone(),
                            local_db: local_db.clone(),
                            allowed_room: HashSet::new(),
                            peer_mgmt_service: mgmt.clone(),
                            reply,
                        };

                        let peer_query_service = RemotePeerQueryService::new(peer, receiver);

                        peer_map.insert(peer_id, peer_query_service);

                        //notify connection
                        event_service
                            .notify(EventServiceMessage::PeerConnected(
                                verifying_key,
                                now(),
                                peer_id,
                            ))
                            .await;

                        peer_id += 1;
                    }
                    PeerConnectionMessage::DisconnectPeer(id) => {
                        if let Some(peer) = peer_map.remove(&id) {
                            //notify disconnect
                            event_service
                                .notify(EventServiceMessage::PeerDisconnected(
                                    peer.verifying_key.clone(),
                                    now(),
                                    id,
                                ))
                                .await;
                        }
                    }
                }
            }
        });
        ret
    }
}

pub enum SyncLockMessage {
    Lock(Vec<u8>, oneshot::Sender<()>),
    Unlock(Vec<u8>),
}

static LOCK_CHANNEL_SIZE: usize = 32;
#[derive(Clone)]

///
/// peer trying to synchronize room must first acquire a lock on the room to avoid having several peers trying to synchronize the same room at the same time
/// also limits the maximum number of rooms that can be synchronized at the same time.
///
pub struct SynchLockService {
    sender: mpsc::Sender<SyncLockMessage>,
}
impl SynchLockService {
    pub fn new(max_lock: usize) -> Self {
        let (sender, mut receiver) = mpsc::channel::<SyncLockMessage>(LOCK_CHANNEL_SIZE);
        tokio::spawn(async move {
            let mut lock: HashSet<Vec<u8>> = HashSet::new();
            let mut awaiting_lock: HashMap<Vec<u8>, VecDeque<oneshot::Sender<()>>> = HashMap::new();

            let mut avalaible = max_lock;
            let mut waiting_list: VecDeque<(Vec<u8>, oneshot::Sender<()>)> = VecDeque::new();

            while let Some(msg) = receiver.recv().await {
                match msg {
                    SyncLockMessage::Lock(id, reply) => {
                        if lock.contains(&id) {
                            let entry = awaiting_lock.entry(id).or_insert(VecDeque::new());
                            entry.push_back(reply)
                        } else if avalaible > 0 {
                            let r = reply.send(());
                            if let Ok(_) = r {
                                lock.insert(id);
                                avalaible -= 1;
                            }
                        } else {
                            waiting_list.push_back((id, reply));
                        }
                    }
                    SyncLockMessage::Unlock(id) => {
                        lock.remove(&id);
                        avalaible += 1;
                        if let Some(waiting) = awaiting_lock.get_mut(&id) {
                            if let Some(reply) = waiting.pop_front() {
                                let r = reply.send(());
                                if let Ok(_) = r {
                                    lock.insert(id);
                                    avalaible -= 1;
                                }
                            }
                        } else if let Some(entry) = waiting_list.pop_front() {
                            let r = entry.1.send(());
                            if let Ok(_) = r {
                                lock.insert(id);
                                avalaible -= 1;
                            }
                        }
                    }
                }
            }
        });
        Self { sender }
    }
}

/* struct syn {
    database: GraphDatabaseService,
}
impl syn {
    pub async fn synchronise_room(room_id: Vec<u8>) {
        //get local room log

        //get remote room log

        //timeout(Duration::from_secs(2), future)

        //compare hash
    }
}*/

//use std::collections::HashSet;
/*
use std::collections::HashSet;

fn main() {
    let s1: HashSet<i32> = [0, 1, 2, 3, 4].iter().cloned().collect();
    let s2: HashSet<i32> = [3, 4].iter().cloned().collect();
    let expected: HashSet<i32> = [0, 1, 2].iter().cloned().collect();
    assert_eq!(&s1 - &s2, expected);
}
*/
//If you want to perform this operation on vectors, you could convert to HashSet or BTreeSet and then create a vector from this:

// fn vect_difference(v1: &Vec<i32>, v2: &Vec<i32>) -> Vec<i32> {
//     let s1: HashSet<i32> = v1.iter().cloned().collect();
//     let s2: HashSet<i32> = v2.iter().cloned().collect();
//     (&s1 - &s2).iter().cloned().collect()
// }

//
