use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use quinn::Connection;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};

use crate::{
    base64_encode,
    database::{
        graph_database::GraphDatabaseService,
        system_entities::{AllowedPeer, Peer},
    },
    date_utils::now,
    event_service::{Event, EventService, EventServiceMessage},
    log_service::LogService,
    security::{uid_encode, MeetingSecret, Uid},
    signature_verification_service::SignatureVerificationService,
    synchronisation::{
        peer_inbound_service::{LocalPeerService, QueryService},
        peer_outbound_service::{InboundQueryService, RemotePeerHandle},
        room_locking_service::RoomLockService,
        Answer, LocalEvent, QueryProtocol, RemoteEvent,
    },
    Parameters, ParametersAdd, Result,
};

pub enum PeerConnectionMessage {
    NewPeer(
        Option<Connection>,
        ConnectionInfo,
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

#[derive(Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub endpoint_id: Uid,
    pub connnection_id: Uid,
    pub verifying_key: Vec<u8>,
    pub hardware_key: Option<[u8; 32]>,
    pub hardware_name: Option<String>,
}

///
/// Handle the creation and removal of peers
///
#[derive(Clone)]
pub struct PeerConnectionService {
    pub sender: mpsc::Sender<PeerConnectionMessage>,
}
impl PeerConnectionService {
    pub fn start(
        verifying_key: Vec<u8>,
        meeting_secret: MeetingSecret,
        system_room_id: Uid,
        db: GraphDatabaseService,
        events: EventService,
        logs: LogService,
        verify_service: SignatureVerificationService,
        max_concurent_synchronisation: usize,
    ) -> Result<Self> {
        let (sender, mut connection_receiver) =
            mpsc::channel::<PeerConnectionMessage>(PEER_CHANNEL_SIZE);
        let (local_event_broadcast, _) = broadcast::channel::<LocalEvent>(16);
        let lock_service = RoomLockService::start(max_concurent_synchronisation);
        let peer_service = Self { sender };
        let ret = peer_service.clone();
        //let local_allowed_peer =    Self::init_local_peer(system_room_id, verifying_key, meeting_secret, &db)?;
        tokio::spawn(async move {
            let mut peer_map: HashMap<Vec<u8>, HashSet<Vec<u8>>> = HashMap::new();
            let mut event_receiver = events.subcribe().await;
            loop {
                tokio::select! {
                    msg = connection_receiver.recv() =>{
                        match msg{
                            Some(msg) =>{
                                Self::process_connection(
                                    msg,
                                    &db,
                                    &events,
                                    &logs,
                                    &peer_service,
                                    &lock_service,
                                    &verify_service,
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
                                Self::process_event(event, &local_event_broadcast, &logs).await;
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
        Ok(ret)
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
        verify_service: &SignatureVerificationService,
        local_event_broadcast: broadcast::Receiver<LocalEvent>,
        peer_map: &mut HashMap<Vec<u8>, HashSet<Vec<u8>>>,
    ) {
        match msg {
            PeerConnectionMessage::NewPeer(
                _connection,
                connection_info,
                answer_sender,
                answer_receiver,
                query_sender,
                query_receiver,
                event_sender,
                event_receiver,
            ) => {
                let verifying_key: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

                let inbound_query_service = InboundQueryService::start(
                    RemotePeerHandle {
                        hardware_id: connection_info.verifying_key.clone(),
                        db: local_db.clone(),
                        allowed_room: HashSet::new(),
                        reply: answer_sender,
                    },
                    query_receiver,
                    log_service.clone(),
                    peer_service.clone(),
                    verifying_key.clone(),
                );

                let query_service =
                    QueryService::start(query_sender, answer_receiver, log_service.clone());

                LocalPeerService::start(
                    event_receiver,
                    local_event_broadcast,
                    connection_info.verifying_key.clone(),
                    verifying_key.clone(),
                    local_db.clone(),
                    lock_service.clone(),
                    query_service,
                    event_sender.clone(),
                    log_service.clone(),
                    peer_service.clone(),
                    event_service.clone(),
                    inbound_query_service,
                    verify_service.clone(),
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

pub struct AllowedConnection {}
impl AllowedConnection {
    pub async fn load() {}
    pub async fn add() {}
    pub async fn create_invite() {}
    pub async fn add_invite() {}
}

#[cfg(test)]
pub use crate::{log_service::Log, security::random32};

#[cfg(test)]
pub type LogFn = Box<dyn Fn(Log) -> std::result::Result<(), String> + Send + 'static>;

#[cfg(test)]
pub type EventFn = Box<dyn Fn(Event) -> bool + Send + 'static>;

#[cfg(test)]
pub async fn listen_for_event(
    event_service: EventService,
    log_service: LogService,
    remote_log_service: LogService,
    event_fn: EventFn,
    log_fn: LogFn,
) -> std::result::Result<(), String> {
    let mut events = event_service.subcribe().await;
    let mut log = log_service.subcribe().await;
    let mut remote_log = remote_log_service.subcribe().await;

    let res: tokio::task::JoinHandle<std::result::Result<(), String>> = tokio::spawn(async move {
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
    use crate::security::new_uid;

    let (peer1_answer_s, peer1_answer_r) = mpsc::channel::<Answer>(100);
    let (peer1_query_s, peer1_query_r) = mpsc::channel::<QueryProtocol>(100);
    let (peer1_event_s, peer1_event_r) = mpsc::channel::<RemoteEvent>(100);

    let (peer2_answer_s, peer2_answer_r) = mpsc::channel::<Answer>(100);
    let (peer2_query_s, peer2_query_r) = mpsc::channel::<QueryProtocol>(100);
    let (peer2_event_s, peer2_event_r) = mpsc::channel::<RemoteEvent>(100);

    let info1 = ConnectionInfo {
        endpoint_id: new_uid(),
        connnection_id: new_uid(),
        verifying_key: random32().to_vec(),
        hardware_key: None,
        hardware_name: None,
    };

    let _ = peer1
        .sender
        .send(PeerConnectionMessage::NewPeer(
            None,
            info1,
            peer2_answer_s,
            peer1_answer_r,
            peer2_query_s,
            peer1_query_r,
            peer2_event_s,
            peer1_event_r,
        ))
        .await;

    let info1 = ConnectionInfo {
        endpoint_id: new_uid(),
        connnection_id: new_uid(),
        verifying_key: random32().to_vec(),
        hardware_key: None,
        hardware_name: None,
    };
    let _ = peer2
        .sender
        .send(PeerConnectionMessage::NewPeer(
            None,
            info1,
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

    use crate::configuration::Configuration;

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
        verifying_key: Vec<u8>,
        system_room_id: Uid,
    }
    impl Peer {
        async fn new(path: PathBuf, model: &str) -> Self {
            let event = EventService::new();
            let (db, verifying_key, system_room_id) = GraphDatabaseService::start(
                "app",
                model,
                &random32(),
                &random32(),
                path.clone(),
                &Configuration::default(),
                event.clone(),
            )
            .await
            .unwrap();
            let log = LogService::start();
            let peer_service = PeerConnectionService::start(
                verifying_key.clone(),
                MeetingSecret::new(random32()),
                system_room_id,
                db.clone(),
                event.clone(),
                log.clone(),
                SignatureVerificationService::start(2),
                10,
            )
            .unwrap();
            Self {
                event,
                log,
                db,
                peer_service,
                verifying_key,
                system_room_id,
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connect() {
        init_database_path();
        let path: PathBuf = DATA_PATH.into();
        let model = "{Person{name:String,}}";

        let first_peer = Peer::new(path.clone(), model).await;
        let second_peer = Peer::new(path, model).await;

        let first_key = first_peer.verifying_key.clone();

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
