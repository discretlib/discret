use std::collections::{HashSet, VecDeque};

use serde::Serialize;
use tokio::sync::mpsc;

use crate::database::graph_database::GraphDatabaseService;

use super::{
    peer_service::{PeerConnectionMessage, PeerConnectionService},
    AnswerProtocol, ErrorType, Protocol, Query, QueryProtocol,
};

///
/// handle all inbound queries
///
#[derive(Clone)]
pub struct QueryService {
    pub verifying_key: Vec<u8>,
}
impl QueryService {
    pub fn new(mut peer: RemotePeerHandle, mut receiver: mpsc::Receiver<QueryProtocol>) -> Self {
        let verifying_key = peer.verifying_key.clone();
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                match msg.query {
                    Query::RoomList => {
                        let res = peer.load_allowed_room().await;
                        match res {
                            Ok(room_list) => peer.send(msg.id, true, room_list).await,
                            Err(e) => peer.send(msg.id, false, e).await,
                        }
                    }
                    Query::RoomDefinition(room_id) => {
                        if peer.allowed_room.contains(&room_id) {
                            let res = peer.local_db.get_room_definition(room_id).await;
                            match res {
                                Ok(definition) => peer.send(msg.id, true, definition).await,
                                Err(_) => {
                                    peer.send(msg.id, false, ErrorType::RemoteTechnical).await
                                }
                            };
                        } else {
                            peer.send(msg.id, false, ErrorType::Authorisation).await;
                        }
                    }
                    Query::RoomLog(room_id) => {
                        if peer.allowed_room.contains(&room_id) {
                            let res = peer.local_db.get_room_log(room_id).await;
                            match res {
                                Ok(log) => peer.send(msg.id, true, log).await,
                                Err(_) => {
                                    peer.send(msg.id, false, ErrorType::RemoteTechnical).await
                                }
                            };
                        } else {
                            peer.send(msg.id, false, ErrorType::Authorisation).await;
                        }
                    }
                }
            }
        });
        Self { verifying_key }
    }
}

pub struct RemotePeerHandle {
    pub connection_id: usize,
    pub verifying_key: Vec<u8>,
    pub allowed_room: HashSet<Vec<u8>>,
    pub local_db: GraphDatabaseService,
    pub peer_mgmt_service: PeerConnectionService,
    pub reply: mpsc::Sender<Protocol>,
}
impl RemotePeerHandle {
    async fn load_allowed_room(&mut self) -> Result<VecDeque<Vec<u8>>, ErrorType> {
        let r = self
            .local_db
            .get_rooms_for_user(self.verifying_key.clone())
            .await;
        match r {
            Ok(rooms) => {
                if self.allowed_room.is_empty() {
                    for room in &rooms {
                        self.allowed_room.insert(room.clone());
                    }
                }
                Ok(rooms)
            }
            Err(_) => Err(ErrorType::RemoteTechnical),
        }
    }
    //handle sending error by notifying the manager
    async fn send<T: Serialize>(&self, id: u64, success: bool, msg: T) {
        match bincode::serialize(&msg) {
            Ok(serialized) => {
                let answer = AnswerProtocol {
                    id,
                    success,
                    serialized,
                };
                if let Err(_) = self.reply.send(Protocol::Answer(answer)).await {
                    let _ = self
                        .peer_mgmt_service
                        .sender
                        .send(PeerConnectionMessage::DisconnectPeer(self.connection_id))
                        .await;
                }
            }
            Err(_) => {
                let _ = self
                    .peer_mgmt_service
                    .sender
                    .send(PeerConnectionMessage::DisconnectPeer(self.connection_id))
                    .await;
            }
        };
    }
}
