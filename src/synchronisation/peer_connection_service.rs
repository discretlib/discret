use std::collections::{HashMap, HashSet};

use tokio::sync::mpsc;

use crate::{
    database::graph_database::GraphDatabaseService,
    date_utils::now,
    event_service::{EventService, EventServiceMessage},
};

use super::{
    peer::{RemotePeerQueryHandler, RemotePeerQueryService},
    room_lock::RoomLockService,
    Protocol, QueryProtocol,
};

pub enum PeerConnectionMessage {
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
    pub sender: mpsc::Sender<PeerConnectionMessage>,
}
impl PeerConnectionService {
    pub fn new(
        local_db: GraphDatabaseService,
        _sync_lock: RoomLockService,
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
