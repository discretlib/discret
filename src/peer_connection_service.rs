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
        ConnectionInfo, ConnectionType,
    },
    security::{MeetingSecret, Uid},
    signature_verification_service::SignatureVerificationService,
    synchronisation::{
        peer_inbound_service::{LocalPeerService, QueryService},
        peer_outbound_service::{InboundQueryService, RemotePeerHandle},
        room_locking_service::RoomLockService,
        Answer, LocalEvent, QueryProtocol, RemoteEvent,
    },
    Configuration, Result,
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
        configuration: Configuration,
    ) -> Result<Self> {
        let (sender, mut connection_receiver) =
            mpsc::channel::<PeerConnectionMessage>(PEER_CHANNEL_SIZE);
        let (local_event_broadcast, _) = broadcast::channel::<LocalEvent>(16);
        let lock_service = RoomLockService::start(configuration.parallelism);
        let peer_service = Self { sender };
        let ret = peer_service.clone();

        let endpoint = DiscretEndpoint::start(
            peer_service.clone(),
            logs.clone(),
            verifying_key.clone(),
            configuration.parallelism + 1,
            configuration.max_object_size_in_kb * 1024 * 2,
        )
        .await?;

        let multicast_adress: SocketAddr = configuration.multicast_ipv4_group.parse()?; // SocketAddr::new(Ipv4Addr::new(224, 0, 0, 224).into(), 22402);
        let multicast_ipv4_interface: Ipv4Addr = configuration.multicast_ipv4_interface.parse()?;
        let multicast_discovery = multicast::start_multicast_discovery(
            multicast_adress,
            multicast_ipv4_interface,
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
                                let err = Self::process_peer_message(
                                    msg,
                                    &mut peer_manager,
                                    &db,
                                    &events,
                                    &logs,
                                    &peer_service,
                                    &lock_service,
                                    &verify_service,
                                    local_event_broadcast.subscribe(),
                                    &configuration
                                ).await;
                                if let Err(e) = err{
                                    logs.error("process_peer_message".to_string(), e);
                                }
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
        configuration: &Configuration,
    ) -> Result<()> {
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

                let expected_peer;
                match connection_info.conn_type.clone() {
                    ConnectionType::SelfPeer(_) => {
                        expected_peer = peer_manager
                            .get_self_peer_expected_key(connection_info.meeting_token)?;
                    }
                    ConnectionType::OtherPeer(verif_key) => {
                        expected_peer = peer_manager.get_other_peer_expected_key(
                            connection_info.meeting_token,
                            &verif_key,
                        )?;
                    }
                    ConnectionType::Invite(invite, verif_key) => {
                        peer_manager.validate_associated_owned_invite(
                            invite,
                            connection_info.meeting_token,
                        )?;
                        expected_peer = verif_key
                    }
                    ConnectionType::OwnedInvite(owned_invite, verif_key) => {
                        peer_manager.validate_associated_invite(
                            owned_invite,
                            connection_info.meeting_token,
                        )?;
                        expected_peer = verif_key
                    }
                }

                if let Some(conn) = connection {
                    peer_manager.add_connection(
                        circuit_id,
                        conn,
                        connection_info.conn_id,
                        connection_info.meeting_token,
                    )
                };

                let verifying_key: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

                let inbound_query_service = InboundQueryService::start(
                    circuit_id,
                    connection_info.conn_id,
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
                    connection_info.clone(),
                    expected_peer,
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
            PeerConnectionMessage::NewPeer(peers) => {
                if configuration.auto_allow_new_peers {
                } else {
                }
            }

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
                MulticastMessage::Annouce(a) => peer_manager.process_announce(a, address).await?,
                MulticastMessage::InitiateConnection(header, token) => {
                    peer_manager
                        .process_initiate_connection(header, token, address)
                        .await?
                }
            },

            PeerConnectionMessage::ConnectionFailed(endpoint_id, remote_id) => {
                peer_manager.clean_progress(endpoint_id, remote_id);
            }
        }
        Ok(())
    }

    async fn process_event(
        event: Event,
        local_event_broadcast: &broadcast::Sender<LocalEvent>,
        log_service: &LogService,
    ) {
        match event {
            Event::DataChanged(daily_log) => {
                match daily_log.as_ref() {
                    Ok(daily_log) => {
                        let mut rooms = Vec::new();
                        for room in &daily_log.room_dates {
                            rooms.push(room.0.clone());
                        }
                        let _ = local_event_broadcast.send(LocalEvent::RoomDataChanged(rooms));
                    }
                    Err(err) => {
                        log_service.error(
                            "ComputedDailyLog".to_string(),
                            crate::Error::ComputeDailyLog(err.to_string()),
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
