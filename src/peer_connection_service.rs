#[cfg(feature = "log")]
use log::error;

use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use quinn::Connection;

use crate::{
    database::node::Node,
    date_utils::now,
    discret::{DiscretParams, DiscretServices},
    event_service::{Event, EventServiceMessage},
    network::{
        endpoint::DiscretEndpoint,
        multicast::{self, MulticastMessage},
        peer_manager::{self, PeerManager, TokenType},
        Announce, AnnounceHeader, ConnectionInfo,
    },
    security::{uid_decode, HardwareFingerprint, MeetingSecret, MeetingToken, Uid},
    synchronisation::{
        peer_inbound_service::{LocalPeerService, QueryService},
        peer_outbound_service::{InboundQueryService, RemotePeerHandle},
        room_locking_service::RoomLockService,
        Answer, LocalEvent, QueryProtocol, RemoteEvent,
    },
    DefaultRoom, Result,
};
use tokio::{
    sync::{broadcast, mpsc, oneshot, Mutex},
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
    PeerConnectionFailed(Uid, Uid),
    PeerConnected(Vec<u8>, Uid),
    PeerDisconnected(Vec<u8>, [u8; 32], Uid),
    ValidateHardware([u8; 32], HardwareFingerprint, oneshot::Sender<Result<bool>>),
    InviteAccepted(TokenType, Node),
    NewPeer(Vec<Node>),
    SendAnnounce(),
    MulticastMessage(MulticastMessage, SocketAddr),
    CreateInvite(Option<DefaultRoom>, oneshot::Sender<Result<Vec<u8>>>),
    AcceptInvite(Vec<u8>),
    BeaconConnectionFailed(SocketAddr, String),
    BeaconConnected(SocketAddr, mpsc::Sender<Announce>),
    BeaconDisconnected(SocketAddr),
    BeaconInitiateConnection(SocketAddr, AnnounceHeader, MeetingToken),
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
        params: &DiscretParams,
        services: &DiscretServices,
        meeting_secret: MeetingSecret,
    ) -> Result<Self> {
        let (sender, mut connection_receiver) =
            mpsc::channel::<PeerConnectionMessage>(PEER_CHANNEL_SIZE);
        let (local_event_broadcast, _) = broadcast::channel::<LocalEvent>(16);
        let lock_service = RoomLockService::start(params.configuration.parallelism);
        let peer_service = Self { sender };
        let ret = peer_service.clone();

        let max_buffer_size = params.configuration.max_object_size_in_kb * 1024 * 2;

        let endpoint = DiscretEndpoint::start(
            peer_service.clone(),
            max_buffer_size as usize,
            &params.verifying_key,
        )
        .await?;

        let multicast_discovery = if params.configuration.enable_multicast {
            let multicast_adress: SocketAddr = params.configuration.multicast_ipv4_group.parse()?; // SocketAddr::new(Ipv4Addr::new(224, 0, 0, 224).into(), 22402);
            let multicast_ipv4_interface: Ipv4Addr =
                params.configuration.multicast_ipv4_interface.parse()?;
            let multicast_discovery = multicast::start_multicast_discovery(
                multicast_adress,
                multicast_ipv4_interface,
                peer_service.clone(),
            )
            .await?;
            Some(multicast_discovery)
        } else {
            None
        };

        let mut peer_manager = PeerManager::new(
            params,
            services,
            endpoint,
            multicast_discovery,
            meeting_secret,
        )
        .await?;

        peer_manager
            .init_hardware(params.hardware_fingerprint.clone())
            .await?;

        if params.configuration.enable_beacons {
            for beacon in &params.configuration.beacons {
                peer_manager
                    .add_beacon(&beacon.hostname, &beacon.cert_hash)
                    .await?;
            }
        }

        let service = peer_service.clone();
        let frequency = params.configuration.announce_frequency_in_ms;

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_millis(frequency));

            loop {
                interval.tick().await;
                let _ = service
                    .sender
                    .send(PeerConnectionMessage::SendAnnounce())
                    .await;
            }
        });

        let discret_params = params.clone();
        let discret_service = services.clone();
        tokio::spawn(async move {
            let mut event_receiver = discret_service.events.subcribe().await;
            loop {
                tokio::select! {
                    msg = connection_receiver.recv() =>{
                        match msg{
                            Some(msg) =>{
                                let err = Self::process_peer_message(
                                    msg,
                                    &mut peer_manager,
                                    &discret_params,
                                    &discret_service,
                                    &peer_service,
                                    &lock_service,
                                    local_event_broadcast.subscribe(),
                                ).await;
                                if let Err(_e) = err{
                                    #[cfg(feature = "log")]
                                    error!("Process_peer_message error: {_e}");

                                }
                            },
                            None => break,
                        }
                    }
                    msg = event_receiver.recv() =>{
                        match msg{
                            Ok(event) => {
                                Self::process_event(event, &local_event_broadcast).await;
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

    pub async fn invite_accepted(&self, token: TokenType, peer: Node) {
        let _ = self
            .sender
            .send(PeerConnectionMessage::InviteAccepted(token, peer))
            .await;
    }

    async fn process_peer_message(
        msg: PeerConnectionMessage,
        peer_manager: &mut PeerManager,
        discret_params: &DiscretParams,
        discret_services: &DiscretServices,
        peer_service: &PeerConnectionService,
        lock_service: &RoomLockService,
        local_event_broadcast: broadcast::Receiver<LocalEvent>,
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

                let token_type = peer_manager.get_token_type(
                    &connection_info.meeting_token,
                    &connection_info.peer_verifying_key,
                )?;

                if let Some(conn) = connection {
                    peer_manager.add_connection(
                        circuit_id,
                        conn,
                        connection_info.conn_id,
                        connection_info.meeting_token,
                    )
                };

                let remote_verifying_key: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
                let conn_ready = Arc::new(AtomicBool::new(true));

                let inbound_query_service = InboundQueryService::start(
                    discret_params.hardware_fingerprint.clone(),
                    circuit_id,
                    connection_info.conn_id,
                    RemotePeerHandle {
                        db: discret_services.database.clone(),
                        allowed_room: HashSet::new(),
                        verifying_key: discret_params.verifying_key.clone(),
                        reply: answer_sender,
                    },
                    query_receiver,
                    peer_service.clone(),
                    remote_verifying_key.clone(),
                    conn_ready.clone(),
                );

                let query_service = QueryService::start(query_sender, answer_receiver);

                LocalPeerService::start(
                    event_receiver,
                    local_event_broadcast,
                    circuit_id,
                    connection_info.clone(),
                    discret_params.verifying_key.clone(),
                    token_type,
                    remote_verifying_key.clone(),
                    conn_ready,
                    lock_service.clone(),
                    query_service,
                    event_sender.clone(),
                    peer_service.clone(),
                    inbound_query_service,
                    &discret_services,
                );
            }

            PeerConnectionMessage::PeerConnected(verifying_key, connection_id) => {
                let _ = discret_services
                    .events
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
                ) {
                    let _ = discret_services
                        .events
                        .sender
                        .send(EventServiceMessage::PeerDisconnected(
                            verifying_key,
                            now(),
                            connection_id,
                        ))
                        .await;
                }
            }

            PeerConnectionMessage::InviteAccepted(token, peer) => {
                if let Err(_e) = peer_manager.invite_accepted(token, peer).await {
                    #[cfg(feature = "log")]
                    error!("PeerConnectionMessage::InviteAccepted error: {_e}");
                }
            }

            PeerConnectionMessage::NewPeer(peers) => {
                if peer_manager
                    .add_new_peers(peers, discret_params.configuration.auto_allow_new_peers)
                    .await?
                {
                    let _ = discret_services
                        .events
                        .sender
                        .send(EventServiceMessage::PendingPeer())
                        .await;
                }
            }

            PeerConnectionMessage::SendAnnounce() => {
                if let Err(_e) = peer_manager.send_annouces().await {
                    #[cfg(feature = "log")]
                    error!("PeerConnectionMessage::SendAnnounce, error: {_e} ");
                }
            }
            PeerConnectionMessage::MulticastMessage(message, address) => match message {
                MulticastMessage::Annouce(a, port) => {
                    peer_manager
                        .multicast_announce(a, address, port, true)
                        .await?
                }
                MulticastMessage::InitiateConnection(header, token, port) => {
                    peer_manager
                        .multicast_initiate_connection(header, token, address, port, true)
                        .await?
                }
            },

            PeerConnectionMessage::PeerConnectionFailed(endpoint_id, remote_id) => {
                peer_manager.clean_progress(endpoint_id, remote_id);
            }
            PeerConnectionMessage::CreateInvite(default_room, reply) => {
                let s = peer_manager.create_invite(default_room).await;
                let _ = reply.send(s);
            }
            PeerConnectionMessage::AcceptInvite(invite) => {
                peer_manager.accept_invite(&invite).await?;
            }
            PeerConnectionMessage::ValidateHardware(circuit, fingerprint, reply) => {
                let valid = peer_manager
                    .validate_hardware(
                        &circuit,
                        fingerprint,
                        discret_params.configuration.auto_accept_local_device,
                    )
                    .await;
                if let Ok(val) = valid.as_ref() {
                    if !val {
                        let _ = discret_services
                            .events
                            .sender
                            .send(EventServiceMessage::PendingHardware())
                            .await;
                    }
                }
                let _ = reply.send(valid);
            }
            PeerConnectionMessage::BeaconConnectionFailed(address, error) => {
                peer_manager.beacon_connection_failed(address, error).await;
            }
            PeerConnectionMessage::BeaconConnected(address, sender) => {
                peer_manager.beacon_connected(address, sender).await?;
            }
            PeerConnectionMessage::BeaconDisconnected(address) => {
                peer_manager.beacon_disconnected(address).await;
            }
            PeerConnectionMessage::BeaconInitiateConnection(address, header, token) => {
                peer_manager
                    .beacon_initiate_connection(address, header, token)
                    .await?;
            }
        }
        Ok(())
    }

    async fn process_event(event: Event, local_event_broadcast: &broadcast::Sender<LocalEvent>) {
        match event {
            Event::DataChanged(data_modif) => {
                let mut rooms = Vec::new();
                for room in &data_modif.rooms {
                    rooms.push(uid_decode(room.0).unwrap());
                }
                let _ = local_event_broadcast.send(LocalEvent::RoomDataChanged(rooms));
            }
            Event::RoomModified(room) => {
                let _ = local_event_broadcast.send(LocalEvent::RoomDefinitionChanged(room));
            }
            _ => {}
        }
    }
}
