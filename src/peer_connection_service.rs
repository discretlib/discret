use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use quinn::Connection;

use crate::{
    database::graph_database::GraphDatabaseService,
    date_utils::now,
    event_service::{Event, EventService, EventServiceMessage},
    log_service::LogService,
    network::{
        endpoint::DiscretEndpoint,
        multicast::{self, MulticastMessage},
        peer_manager::{self, PeerManager},
        ConnectionInfo,
    },
    security::{MeetingSecret, Uid},
    signature_verification_service::SignatureVerificationService,
    synchronisation::{
        peer_inbound_service::{LocalPeerService, QueryService},
        peer_outbound_service::{InboundQueryService, RemotePeerHandle},
        room_locking_service::RoomLockService,
        Answer, LocalEvent, QueryProtocol, RemoteEvent,
    },
    Result,
};
use tokio::{
    sync::{broadcast, mpsc, Mutex},
    time,
};

pub enum PeerConnectionMessage {
    NewConnection(
        Option<Connection>,
        ConnectionInfo,
        mpsc::Sender<Answer>,
        mpsc::Receiver<Answer>,
        mpsc::Sender<QueryProtocol>,
        mpsc::Receiver<QueryProtocol>,
        mpsc::Sender<RemoteEvent>,
        mpsc::Receiver<RemoteEvent>,
    ),
    ConnectionFailed(Uid, Uid),
    PeerConnected(Vec<u8>, Uid),
    PeerDisconnected(Vec<u8>, [u8; 32], Uid),
    NewPeer(Vec<Uid>),
    SendAnnounce(),
    MulticastMessage(MulticastMessage, SocketAddr),
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
    pub async fn start(
        verifying_key: Vec<u8>,
        meeting_secret: MeetingSecret,
        private_room_id: Uid,
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

        let endpoint =
            DiscretEndpoint::start(peer_service.clone(), logs.clone(), verifying_key.clone(), 8)
                .await?;

        let multicast_adress = SocketAddr::new(Ipv4Addr::new(224, 0, 0, 224).into(), 22402);
        let multicast_discovery = multicast::start_multicast_discovery(
            multicast_adress,
            peer_service.clone(),
            logs.clone(),
        )
        .await?;

        let mut peer_manager = PeerManager::new(
            endpoint,
            multicast_discovery,
            db.clone(),
            logs.clone(),
            verify_service.clone(),
            private_room_id,
            verifying_key.clone(),
            meeting_secret,
        )
        .await?;

        tokio::spawn(async move {
            let mut event_receiver = events.subcribe().await;
            loop {
                tokio::select! {
                    msg = connection_receiver.recv() =>{
                        match msg{
                            Some(msg) =>{
                                Self::process_peer_message(
                                    msg,
                                    &mut peer_manager,
                                    &db,
                                    &events,
                                    &logs,
                                    &peer_service,
                                    &lock_service,
                                    &verify_service,
                                    local_event_broadcast.subscribe(),
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

    pub async fn disconnect(
        &self,
        verifying_key: Vec<u8>,
        circuit_id: [u8; 32],
        connection_id: Uid,
    ) {
        let _ = self
            .sender
            .send(PeerConnectionMessage::PeerDisconnected(
                verifying_key,
                circuit_id,
                connection_id,
            ))
            .await;
    }

    pub async fn connected(&self, verifying_key: Vec<u8>, connection_id: Uid) {
        let _ = self
            .sender
            .send(PeerConnectionMessage::PeerConnected(
                verifying_key,
                connection_id,
            ))
            .await;
    }

    async fn process_peer_message(
        msg: PeerConnectionMessage,
        peer_manager: &mut PeerManager,
        local_db: &GraphDatabaseService,
        event_service: &EventService,
        log_service: &LogService,
        peer_service: &PeerConnectionService,
        lock_service: &RoomLockService,
        verify_service: &SignatureVerificationService,
        local_event_broadcast: broadcast::Receiver<LocalEvent>,
    ) {
        match msg {
            PeerConnectionMessage::NewConnection(
                connection,
                connection_info,
                answer_sender,
                answer_receiver,
                query_sender,
                query_receiver,
                event_sender,
                event_receiver,
            ) => {
                let circuit_id =
                    PeerManager::circuit_id(connection_info.endpoint_id, connection_info.remote_id);

                if let Some(hardware) = connection_info.hardware {
                    if !peer_manager
                        .validate_hardware(connection_info.endpoint_id, hardware, true)
                        .await
                    {
                        return;
                    }
                }

                if let Some(connection) = connection {
                    peer_manager.add_connection(
                        circuit_id,
                        connection,
                        connection_info.connnection_id,
                    )
                };

                let connection_id = connection_info.connnection_id;
                let verifying_key: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

                let inbound_query_service = InboundQueryService::start(
                    circuit_id,
                    connection_id,
                    RemotePeerHandle {
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
                    circuit_id,
                    connection_id,
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

            PeerConnectionMessage::PeerConnected(verifying_key, connection_id) => {
                let _ = event_service
                    .sender
                    .send(EventServiceMessage::PeerConnected(
                        verifying_key,
                        now(),
                        connection_id,
                    ))
                    .await;
            }

            PeerConnectionMessage::PeerDisconnected(verifying_key, circuit_id, connection_id) => {
                if peer_manager.disconnect(
                    circuit_id,
                    connection_id,
                    peer_manager::REASON_UNKNOWN,
                    "",
                ) {}
                let _ = event_service
                    .sender
                    .send(EventServiceMessage::PeerDisconnected(
                        verifying_key,
                        now(),
                        connection_id,
                    ))
                    .await;
            }
            PeerConnectionMessage::NewPeer(_peers) => {}

            PeerConnectionMessage::SendAnnounce() => {
                if let Err(e) = peer_manager.send_annouces().await {
                    log_service.error(
                        "PeerConnectionMessage::SendAnnounce".to_string(),
                        crate::Error::from(e),
                    );
                }
            }
            PeerConnectionMessage::MulticastMessage(message, address) => match message {
                MulticastMessage::ProbeLocalIp(probe_value) => {
                    println!("probe received {}", address);
                    let probed = peer_manager
                        .validate_probe(probe_value, address)
                        .await
                        .unwrap();
                    //ip have been retrieved and headers have been initialised, we can start sending anounce
                    if probed {
                        let service = peer_service.clone();
                        tokio::spawn(async move {
                            let mut interval = time::interval(Duration::from_secs(60));

                            loop {
                                interval.tick().await;
                                let _ = service
                                    .sender
                                    .send(PeerConnectionMessage::SendAnnounce())
                                    .await;
                            }
                        });
                    }
                }
                MulticastMessage::Annouce(a) => peer_manager.process_announce(a, address).await,
                MulticastMessage::InitiateConnection(header, token) => {
                    peer_manager
                        .process_initiate_connection(header, token, address)
                        .await
                }
            },

            PeerConnectionMessage::ConnectionFailed(endpoint_id, remote_id) => {
                peer_manager.clean_progress(endpoint_id, remote_id);
            }
        }
    }

    async fn process_event(
        event: Event,
        local_event_broadcast: &broadcast::Sender<LocalEvent>,
        log_service: &LogService,
    ) {
        match event {
            Event::DataChanged(daily_log) => {
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
    use crate::security::{self, new_uid};

    let (peer1_answer_s, peer1_answer_r) = mpsc::channel::<Answer>(100);
    let (peer1_query_s, peer1_query_r) = mpsc::channel::<QueryProtocol>(100);
    let (peer1_event_s, peer1_event_r) = mpsc::channel::<RemoteEvent>(100);

    let (peer2_answer_s, peer2_answer_r) = mpsc::channel::<Answer>(100);
    let (peer2_query_s, peer2_query_r) = mpsc::channel::<QueryProtocol>(100);
    let (peer2_event_s, peer2_event_r) = mpsc::channel::<RemoteEvent>(100);

    let info1 = ConnectionInfo {
        endpoint_id: new_uid(),
        remote_id: new_uid(),
        connnection_id: new_uid(),
        hardware: Some(security::HardwareFingerprint::new().unwrap()),
    };

    let _ = peer1
        .sender
        .send(PeerConnectionMessage::NewConnection(
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
        remote_id: new_uid(),
        connnection_id: new_uid(),

        hardware: Some(security::HardwareFingerprint::new().unwrap()),
    };
    let _ = peer2
        .sender
        .send(PeerConnectionMessage::NewConnection(
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

    use crate::{configuration::Configuration, Discret};

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
            .await
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

    #[tokio::test(flavor = "multi_thread")]
    async fn multicast_connect() {
        init_database_path();
        let path: PathBuf = DATA_PATH.into();
        let model = "{Person{name:String,}}";
        let key_material = random32();
        let _: Discret = Discret::new(
            model,
            "hello",
            &key_material,
            path,
            Configuration::default(),
        )
        .await
        .unwrap();

        let second_path: PathBuf = format!("{}/second", DATA_PATH).into();
        let discret2: Discret = Discret::new(
            model,
            "hello",
            &key_material,
            second_path,
            Configuration::default(),
        )
        .await
        .unwrap();
        let private_room_id = discret2.private_room();
        let mut events = discret2.subscribe_for_events().await;
        let handle = tokio::spawn(async move {
            loop {
                let event = events.recv().await;
                match event {
                    Ok(e) => match e {
                        Event::RoomSynchronized(room_id) => {
                            assert_eq!(room_id, private_room_id);
                            break;
                        }
                        _ => {}
                    },
                    Err(e) => println!("Error {}", e),
                }
            }
        });

        let s = tokio::time::timeout(Duration::from_secs(1), handle).await;

        assert!(s.is_ok());
    }
}
