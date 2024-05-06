//recuperer les differents policy_groups
//synchroniser le security group
//si nouveau groupe
//nosynch alert
//pour chaque policy dans les groupes
//recupérer les droits sur les schemas
//synchroniser les shemas un a un qui ont un droit read
//updater le daily log

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::database::{daily_log::RoomLog, graph_database::GraphDatabaseService};

#[derive(Serialize, Deserialize)]
pub enum Query {
    RoomLog(Vec<u8>, u64),
}
#[derive(Serialize, Deserialize)]
pub enum Answer {
    RoomLog(Vec<RoomLog>, u64),
    Error(u64, ErrorType),
}

#[derive(Serialize, Deserialize)]
pub struct SerializedAnswer {
    id: u64,
    success: bool,
    serialized: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub enum OutboundAnswer {
    Serialized(SerializedAnswer),
}

#[derive(Serialize, Deserialize)]
pub enum ErrorType {
    Authorisation,
    Technical,
}

///
/// handle all inbound queries
///
#[derive(Clone)]
pub struct PeerQueryService {}
impl PeerQueryService {
    pub fn new(peer: PeerQuery, mut receiver: mpsc::Receiver<Query>) -> Self {
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                match msg {
                    Query::RoomLog(room_id, msg_id) => {
                        if peer.allowed_room.contains(&room_id) {
                            let res = peer.local_db.get_room_log(room_id).await;
                            match res {
                                Ok(log) => peer.send(msg_id, Answer::RoomLog(log, msg_id)).await,
                                Err(_) => {
                                    peer.send(msg_id, Answer::Error(msg_id, ErrorType::Technical))
                                        .await
                                }
                            };
                        } else {
                            peer.send(msg_id, Answer::Error(msg_id, ErrorType::Authorisation))
                                .await;
                        }
                    }
                }
            }
        });
        Self {}
    }
}

pub struct PeerQuery {
    connection_id: i64,
    verifying_key: Vec<u8>,
    allowed_room: HashSet<Vec<u8>>,
    local_db: GraphDatabaseService,
    peer_mgmt_service: PeerManagerService,
    reply: mpsc::Sender<OutboundAnswer>,
}
impl PeerQuery {
    async fn load_allowed_room(&mut self) {
        let r = self
            .local_db
            .get_room_for_user(self.verifying_key.clone())
            .await;
        match r {
            Ok(set) => self.allowed_room = set,
            Err(_) => self.allowed_room = HashSet::new(),
        }
    }
    //handle sending error by notifying the manager
    async fn send(&self, id: u64, msg: Answer) {
        match bincode::serialize(&msg) {
            Ok(serialized) => {
                let answer = match msg {
                    Answer::Error(_, _) => SerializedAnswer {
                        id,
                        success: false,
                        serialized,
                    },
                    _ => SerializedAnswer {
                        id,
                        success: true,
                        serialized,
                    },
                };
                if let Err(_) = self.reply.send(OutboundAnswer::Serialized(answer)).await {
                    let _ = self
                        .peer_mgmt_service
                        .sender
                        .send(PeerManagementMessage::PeerError(self.connection_id))
                        .await;
                }
            }
            Err(_) => {
                let _ = self
                    .peer_mgmt_service
                    .sender
                    .send(PeerManagementMessage::PeerError(self.connection_id))
                    .await;
            }
        };
    }
}

enum PeerManagementMessage {
    NewPeer(Vec<u8>, mpsc::Sender<OutboundAnswer>, mpsc::Receiver<Query>),
    PeerError(i64),
}

static PEER_CHANNEL_SIZE: usize = 32;

///
/// Handle the creation and removal of peers
///
#[derive(Clone)]
pub struct PeerManagerService {
    sender: mpsc::Sender<PeerManagementMessage>,
}
impl PeerManagerService {
    pub fn new(local_db: GraphDatabaseService, sync_lock: SynchLockService) -> Self {
        let (sender, mut receiver) = mpsc::channel::<PeerManagementMessage>(PEER_CHANNEL_SIZE);
        let mgmt = Self { sender };
        let ret = mgmt.clone();
        tokio::spawn(async move {
            let mut peer_map = HashMap::new();
            let mut peer_id: i64 = 1;

            while let Some(msg) = receiver.recv().await {
                match msg {
                    PeerManagementMessage::NewPeer(verifying_key, reply, receiver) => {
                        let peer = PeerQuery {
                            connection_id: peer_id,
                            verifying_key,
                            local_db: local_db.clone(),
                            allowed_room: HashSet::new(),
                            peer_mgmt_service: mgmt.clone(),
                            reply,
                        };
                        peer_map.insert(peer_id, peer);
                        peer_id += 1;
                        //notify
                    }
                    PeerManagementMessage::PeerError(id) => {
                        if let Some(peer) = peer_map.remove(&id) {
                            //notify
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
