use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use tokio::sync::{broadcast, mpsc, Mutex};

use crate::{
    database::graph_database::GraphDatabaseService,
    date_utils::now,
    event_service::{EventService, EventServiceMessage},
    log_service::LogService,
};

use super::{
    local_peer::{LocalPeer, LocalPeerService, QueryService},
    remote_peer::{RemotePeerHandle, RemoteQueryService},
    room_lock::RoomLockService,
    Answer, LocalEvent, QueryProtocol, RemoteEvent,
};

pub enum PeerConnectionMessage {
    NewPeer(
        Vec<u8>,
        mpsc::Sender<Answer>,
        mpsc::Receiver<Answer>,
        mpsc::Sender<QueryProtocol>,
        mpsc::Receiver<QueryProtocol>,
        mpsc::Sender<RemoteEvent>,
        mpsc::Receiver<RemoteEvent>,
    ),
    PeerConnected(Vec<u8>, Vec<u8>),
    PeerDisconnected(Vec<u8>, Vec<u8>),
}

static PEER_CHANNEL_SIZE: usize = 32;

///
/// Handle the creation and removal of peers
///
#[derive(Clone)]
pub struct PeerConnectionService {
    pub sender: mpsc::Sender<PeerConnectionMessage>,
}
impl PeerConnectionService {
    pub fn start(
        local_db: GraphDatabaseService,
        event_service: EventService,
        log_service: LogService,
        max_concurent_synchronisation: usize,
    ) -> Self {
        let (sender, mut receiver) = mpsc::channel::<PeerConnectionMessage>(PEER_CHANNEL_SIZE);
        let (local_event_broadcast, _) = broadcast::channel::<LocalEvent>(16);
        let lock_service = RoomLockService::start(max_concurent_synchronisation);
        let peer_service = Self { sender };
        let ret = peer_service.clone();
        tokio::spawn(async move {
            let mut peer_map: HashMap<Vec<u8>, HashSet<Vec<u8>>> = HashMap::new();

            while let Some(msg) = receiver.recv().await {
                match msg {
                    PeerConnectionMessage::NewPeer(
                        hardware_id,
                        answer_sender,
                        answer_receiver,
                        query_sender,
                        query_receiver,
                        event_sender,
                        event_receiver,
                    ) => {
                        let verifying_key: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

                        RemoteQueryService::start(
                            RemotePeerHandle {
                                hardware_id: hardware_id.clone(),
                                local_db: local_db.clone(),
                                allowed_room: HashSet::new(),
                                reply: answer_sender,
                            },
                            query_receiver,
                            log_service.clone(),
                            peer_service.clone(),
                            verifying_key.clone(),
                        );

                        let local_peer = LocalPeer {
                            hardware_id: hardware_id.clone(),
                            remote_rooms: HashSet::new(),
                            database_service: local_db.clone(),
                            lock_service: lock_service.clone(),
                            query_service: QueryService::start(
                                query_sender,
                                answer_receiver,
                                log_service.clone(),
                            ),
                            event_sender,
                        };

                        LocalPeerService::start(
                            local_peer,
                            event_receiver,
                            local_event_broadcast.subscribe(),
                            verifying_key,
                            log_service.clone(),
                            peer_service.clone(),
                        );
                    }
                    PeerConnectionMessage::PeerConnected(verifying_key, hardware_id) => {
                        let entry = peer_map.entry(verifying_key.clone()).or_default();
                        entry.insert(hardware_id.clone());
                        let _ = event_service
                            .sender
                            .send(EventServiceMessage::PeerConnected(
                                verifying_key,
                                now(),
                                hardware_id,
                            ))
                            .await;
                    }

                    PeerConnectionMessage::PeerDisconnected(verifying_key, hardware_id) => {
                        let entry = peer_map.remove(&verifying_key);
                        if let Some(mut entries) = entry {
                            entries.remove(&hardware_id);
                            if !entries.is_empty() {
                                peer_map.insert(verifying_key.clone(), entries);
                            }
                        }

                        let _ = event_service
                            .sender
                            .send(EventServiceMessage::PeerDisconnected(
                                verifying_key,
                                now(),
                                hardware_id,
                            ))
                            .await;
                    }
                }
            }
        });
        ret
    }

    pub async fn disconnect(&self, verifying_key: Vec<u8>, hardware_id: Vec<u8>) {
        let _ = self
            .sender
            .send(PeerConnectionMessage::PeerDisconnected(
                verifying_key,
                hardware_id,
            ))
            .await;
    }

    pub async fn connected(&self, verifying_key: Vec<u8>, hardware_id: Vec<u8>) {
        let _ = self
            .sender
            .send(PeerConnectionMessage::PeerConnected(
                verifying_key,
                hardware_id,
            ))
            .await;
    }
}

#[cfg(test)]
use crate::{cryptography::random32, event_service::Event, log_service::Log};

#[cfg(test)]
type LogFn = Box<dyn Fn(Log) -> Result<(), String> + Send + 'static>;

#[cfg(test)]
type EventFn = Box<dyn Fn(Event) -> bool + Send + 'static>;

#[cfg(test)]
async fn listen_for_event(
    event_service: EventService,
    log_service: LogService,
    event_fn: EventFn,
    log_fn: LogFn,
) -> Result<(), String> {
    let mut events = event_service.subcribe().await;
    let mut log = log_service.subcribe().await;

    let res: tokio::task::JoinHandle<Result<(), String>> = tokio::spawn(async move {
        let mut success = false;
        let mut error = String::new();
        loop {
            tokio::select! {
                msg = events.recv() =>{
                    match msg{
                        Ok(event) => {
                            if event_fn(event){
                                success =true;
                                break;
                            }
                        }
                        Err(e) => {
                            error = e.to_string();
                            break;
                        },
                    }
                }
                msg = log.recv() =>{
                    match msg{
                        Ok(log) => {
                            if let Err(e) =  log_fn(log) {
                                error = e;
                                break;
                            }
                        }
                        Err(e) => {
                            error = e.to_string();
                            break;
                        },
                    }
                }
            }
        }
        if success {
            Ok(())
        } else {
            Err(error)
        }
    });
    res.await.unwrap()
}

#[cfg(test)]
async fn connect_peers(peer1: &PeerConnectionService, peer2: &PeerConnectionService) {
    let (peer1_answer_s, peer1_answer_r) = mpsc::channel::<Answer>(100);
    let (peer1_query_s, peer1_query_r) = mpsc::channel::<QueryProtocol>(100);
    let (peer1_event_s, peer1_event_r) = mpsc::channel::<RemoteEvent>(100);

    let (peer2_answer_s, peer2_answer_r) = mpsc::channel::<Answer>(100);
    let (peer2_query_s, peer2_query_r) = mpsc::channel::<QueryProtocol>(100);
    let (peer2_event_s, peer2_event_r) = mpsc::channel::<RemoteEvent>(100);

    let _ = peer1
        .sender
        .send(PeerConnectionMessage::NewPeer(
            random32().to_vec(),
            peer2_answer_s,
            peer1_answer_r,
            peer2_query_s,
            peer1_query_r,
            peer2_event_s,
            peer1_event_r,
        ))
        .await;

    let _ = peer2
        .sender
        .send(PeerConnectionMessage::NewPeer(
            random32().to_vec(),
            peer1_answer_s,
            peer2_answer_r,
            peer1_query_s,
            peer2_query_r,
            peer1_event_s,
            peer2_event_r,
        ))
        .await;
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::Duration};

    use crate::database::configuration::Configuration;

    use super::*;

    const DATA_PATH: &str = "test_data/synchronisation/peer_service/";
    fn init_database_path() {
        let path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path).unwrap();
    }

    struct Peer {
        event: EventService,
        log: LogService,
        db: GraphDatabaseService,
        peer_service: PeerConnectionService,
    }
    impl Peer {
        async fn new(path: PathBuf, model: &str) -> Self {
            let event = EventService::new();
            let db = GraphDatabaseService::start(
                "app",
                model,
                &random32(),
                path.clone(),
                Configuration::default(),
                event.clone(),
            )
            .await
            .unwrap();
            let log = LogService::start();
            let peer_service =
                PeerConnectionService::start(db.clone(), event.clone(), log.clone(), 10);
            Self {
                event,
                log,
                db,
                peer_service,
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connect() {
        init_database_path();
        let path: PathBuf = DATA_PATH.into();
        let model = "Person{name:String,}";

        let first_peer = Peer::new(path.clone(), model).await;
        let second_peer = Peer::new(path, model).await;

        let first_key = first_peer.db.verifying_key().clone();

        let event_fn: EventFn = Box::new(move |event| match event {
            Event::PeerConnected(id, _, _) => {
                assert_eq!(id, first_key);
                return true;
            }
            _ => return false,
        });

        let log_fn: LogFn = Box::new(|log| match log {
            Log::Error(_, src, e) => Err(format!("src:{} Err:{} ", src, e)),
            Log::Info(_, _) => Ok(()),
        });

        connect_peers(&first_peer.peer_service, &second_peer.peer_service).await;

        tokio::time::timeout(
            Duration::from_secs(1),
            listen_for_event(
                second_peer.event.clone(),
                second_peer.log.clone(),
                event_fn,
                log_fn,
            ),
        )
        .await
        .unwrap()
        .unwrap();
    }
}
