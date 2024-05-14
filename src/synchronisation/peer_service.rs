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
        lock_service: RoomLockService,
        event_service: EventService,
        log_service: LogService,
    ) -> Self {
        let (sender, mut receiver) = mpsc::channel::<PeerConnectionMessage>(PEER_CHANNEL_SIZE);
        let (local_event_broadcast, _) = broadcast::channel::<LocalEvent>(16);

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
}
