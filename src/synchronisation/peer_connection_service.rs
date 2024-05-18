use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use tokio::sync::{broadcast, mpsc, Mutex};

use crate::{
    database::graph_database::GraphDatabaseService,
    date_utils::now,
    event_service::{Event, EventService, EventServiceMessage},
    log_service::LogService,
};

use super::{
    peer_inbound_service::{LocalPeer, LocalPeerService, QueryService},
    peer_outbound_service::{RemotePeerHandle, RemoteQueryService},
    room_locking_service::RoomLockService,
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
        let (sender, mut connection_receiver) =
            mpsc::channel::<PeerConnectionMessage>(PEER_CHANNEL_SIZE);
        let (local_event_broadcast, _) = broadcast::channel::<LocalEvent>(16);
        let lock_service = RoomLockService::start(max_concurent_synchronisation);
        let peer_service = Self { sender };
        let ret = peer_service.clone();
        tokio::spawn(async move {
            let mut peer_map: HashMap<Vec<u8>, HashSet<Vec<u8>>> = HashMap::new();
            let mut event_receiver = event_service.subcribe().await;
            loop {
                tokio::select! {
                    msg = connection_receiver.recv() =>{
                        match msg{
                            Some(msg) =>{
                                Self::process_connection(
                                    msg,
                                    &local_db,
                                    &event_service,
                                    &log_service,
                                    &peer_service,
                                    &lock_service,
                                    local_event_broadcast.subscribe(),
                                    &mut peer_map,
                                ).await;
                            },
                            None => break,
                        }


                    }
                    msg = event_receiver.recv() =>{
                        match msg{
                            Ok(event) => {
                                Self::process_event(event, &local_event_broadcast, &log_service).await;
                            },
                            Err(e) => match e {
                                broadcast::error::RecvError::Closed => break,
                                broadcast::error::RecvError::Lagged(_) => {},
                            },
                        }
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

    async fn process_connection(
        msg: PeerConnectionMessage,
        local_db: &GraphDatabaseService,
        event_service: &EventService,
        log_service: &LogService,
        peer_service: &PeerConnectionService,
        lock_service: &RoomLockService,
        local_event_broadcast: broadcast::Receiver<LocalEvent>,
        peer_map: &mut HashMap<Vec<u8>, HashSet<Vec<u8>>>,
    ) {
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
                        db: local_db.clone(),
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
                    db: local_db.clone(),
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
                    local_event_broadcast,
                    verifying_key,
                    log_service.clone(),
                    peer_service.clone(),
                    event_service.clone(),
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

    async fn process_event(
        event: Event,
        local_event_broadcast: &broadcast::Sender<LocalEvent>,
        log_service: &LogService,
    ) {
        match event {
            Event::ComputedDailyLog(daily_log) => {
                match daily_log {
                    Ok(daily_log) => {
                        let mut rooms = Vec::new();
                        for room in daily_log.room_dates {
                            rooms.push(room.0);
                        }
                        let _ = local_event_broadcast.send(LocalEvent::RoomDataChanged(rooms));
                    }
                    Err(err) => {
                        log_service.error(
                            "ComputedDailyLog".to_string(),
                            crate::Error::ComputeDailyLog(err),
                        );
                    }
                };
            }
            Event::RoomModified(room) => {
                let _ = local_event_broadcast.send(LocalEvent::RoomDefinitionChanged(room));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
pub use crate::{log_service::Log, security::random32};

#[cfg(test)]
pub type LogFn = Box<dyn Fn(Log) -> Result<(), String> + Send + 'static>;

#[cfg(test)]
pub type EventFn = Box<dyn Fn(Event) -> bool + Send + 'static>;

#[cfg(test)]
pub async fn listen_for_event(
    event_service: EventService,
    log_service: LogService,
    remote_log_service: LogService,
    event_fn: EventFn,
    log_fn: LogFn,
) -> Result<(), String> {
    let mut events = event_service.subcribe().await;
    let mut log = log_service.subcribe().await;
    let mut remote_log = remote_log_service.subcribe().await;

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
                msg = remote_log.recv() =>{
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
pub async fn connect_peers(peer1: &PeerConnectionService, peer2: &PeerConnectionService) {
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
                first_peer.log.clone(),
                event_fn,
                log_fn,
            ),
        )
        .await
        .unwrap()
        .unwrap();
    }
}