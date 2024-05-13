//recuperer les differents policy_groups
//synchroniser le security group
//si nouveau groupe
//nosynch alert
//pour chaque policy dans les groupes
//recupérer les droits sur les schemas
//synchroniser les shemas un a un qui ont un droit read
//updater le daily log

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use serde::de::DeserializeOwned;
use tokio::{
    sync::{
        mpsc::{self, Receiver, Sender},
        oneshot, Mutex,
    },
    time::timeout,
};

use crate::database::{daily_log::RoomLog, graph_database::GraphDatabaseService};

use super::{
    peer_service::PeerConnectionService, room_lock::RoomLockService, AnswerProtocol, ErrorType,
    LocalEvent, Protocol, Query, QueryProtocol, RemoteEvent, NETWORK_TIMEOUT_SEC,
};

static QUERY_SEND_BUFFER: usize = 10;

pub type AnswerFn = Box<dyn FnOnce(bool, Vec<u8>) + Send + 'static>;

pub struct QueryService {
    sender: mpsc::Sender<(Query, AnswerFn)>,
}
impl QueryService {
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

pub struct LocalPeer {
    pub connection_id: usize,
    pub remote_verifying_key: Vec<u8>,
    pub remote_rooms: HashSet<Vec<u8>>,
    pub database_service: GraphDatabaseService,
    pub peer_mgmt_service: PeerConnectionService,
    pub lock_service: RoomLockService,
    pub query_service: QueryService,
    pub event_sender: Sender<RemoteEvent>,
}
impl LocalPeer {
    pub async fn start(
        peer: LocalPeer,
        mut remote_event: Receiver<RemoteEvent>,
        mut local_event: Receiver<LocalEvent>,
    ) {
        //retrieve remote;
        //request locks
        let (lock_reply, mut lock_receiver) = mpsc::unbounded_channel::<Vec<u8>>();

        tokio::spawn(async move {
            let room_list_rs: Result<Vec<Vec<u8>>, ErrorType> = peer.query(Query::RoomList).await;
            if room_list_rs.is_err() {
                peer.cleanup(Vec::new()).await;
                return;
            }
            let rooms = room_list_rs.unwrap().into_iter().collect();
            peer.lock_service
                .request_locks(peer.connection_id, rooms, lock_reply)
                .await;

            let acquired_lock: Arc<Mutex<HashSet<Vec<u8>>>> =
                Arc::new(Mutex::new(HashSet::<Vec<u8>>::new()));

            loop {
                tokio::select! {
                    msg = remote_event.recv() =>{
                        match msg{
                            Some(msg) => {Self::process_remote_event(msg, &peer).await;}
                            None => break,
                        }
                    }

                    msg = local_event.recv() =>{
                        match msg{
                            Some(msg) => {Self::process_local_event(msg, &peer).await;}
                            None => break,
                        }
                    }

                    msg = lock_receiver.recv() =>{
                        match msg{
                            Some(room) => {Self::process_acquired_lock(room, acquired_lock.clone(), &peer).await}
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
        });
    }

    pub async fn process_remote_event(msg: RemoteEvent, peer: &Self) {
        unimplemented!()
    }

    pub async fn process_local_event(msg: LocalEvent, peer: &Self) {
        unimplemented!()
    }

    pub async fn process_acquired_lock(
        lock: Vec<u8>,
        acquired_lock: Arc<Mutex<HashSet<Vec<u8>>>>,
        peer: &Self,
    ) {
        acquired_lock.lock().await.insert(lock.clone());
        unimplemented!();
        acquired_lock.lock().await.remove(&lock);
    }

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

    ///
    /// cleanup locks that could have been acquired
    /// and ask the peer service to remove this peer
    ///
    pub async fn cleanup(self, rooms: Vec<Vec<u8>>) {
        for room in rooms {
            self.lock_service.unlock(room).await;
        }
        self.peer_mgmt_service.disconnect(self.connection_id).await;
    }
}
