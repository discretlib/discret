use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use serde::Serialize;
use tokio::sync::{mpsc, Mutex};

use crate::{database::graph_database::GraphDatabaseService, log_service::LogService};

use super::{
    peer_service::PeerConnectionService, Answer, Error, ProveAnswer, Query, QueryProtocol,
};

///
/// handle all inbound queries
///
#[derive(Clone)]
pub struct RemoteQueryService {}
impl RemoteQueryService {
    pub fn start(
        mut peer: RemotePeerHandle,
        mut receiver: mpsc::Receiver<QueryProtocol>,
        log_service: LogService,
        peer_service: PeerConnectionService,
        verifying_key: Arc<Mutex<Vec<u8>>>,
    ) {
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                match msg.query {
                    Query::ProveIdentity(challenge) => {
                        let res = peer.local_db.sign(challenge).await;
                        if let Err(e) = peer
                            .send(
                                msg.id,
                                true,
                                ProveAnswer {
                                    verifying_key: res.0,
                                    invitation: None,
                                    chall_signature: res.1,
                                },
                            )
                            .await
                        {
                            log_service.error("ProveIdentity".to_string(), e);
                            break;
                        }
                    }

                    Query::RoomList => {
                        let key = verifying_key.lock().await;
                        if !key.is_empty() {
                            let r = {
                                let res = peer.load_allowed_room(key.clone()).await;
                                match res {
                                    Ok(room_list) => peer.send(msg.id, true, room_list).await,
                                    Err(e) => {
                                        log_service.error("RoomList".to_string(), e.into());
                                        peer.send(msg.id, false, Error::RemoteTechnical).await
                                    }
                                }
                            };
                            if let Err(e) = r {
                                log_service.error("RoomList Channel".to_string(), e);
                                break;
                            }
                        };
                    }
                    Query::RoomDefinition(room_id) => {
                        let r = {
                            if peer.allowed_room.contains(&room_id) {
                                let res = peer.local_db.get_room_definition(room_id).await;
                                match res {
                                    Ok(definition) => peer.send(msg.id, true, definition).await,
                                    Err(e) => {
                                        log_service.error("RoomDefinition".to_string(), e.into());
                                        peer.send(msg.id, false, Error::RemoteTechnical).await
                                    }
                                }
                            } else {
                                peer.send(msg.id, false, Error::Authorisation).await
                            }
                        };
                        if let Err(e) = r {
                            log_service.error("RoomDefinition Channel".to_string(), e);
                            break;
                        }
                    }
                    Query::RoomLog(room_id) => {
                        let r = {
                            if peer.allowed_room.contains(&room_id) {
                                let res = peer.local_db.get_room_log(room_id).await;
                                match res {
                                    Ok(log) => peer.send(msg.id, true, log).await,
                                    Err(e) => {
                                        log_service.error("RoomLog Channel".to_string(), e.into());
                                        peer.send(msg.id, false, Error::RemoteTechnical).await
                                    }
                                }
                            } else {
                                peer.send(msg.id, false, Error::Authorisation).await
                            }
                        };
                        if let Err(e) = r {
                            log_service.error("RoomLog Channel".to_string(), e);
                            break;
                        }
                    }
                }
            }
            let key = verifying_key.lock().await;
            peer_service.disconnect(key.clone(), peer.hardware_id).await;
        });
    }
}

pub struct RemotePeerHandle {
    pub hardware_id: Vec<u8>,
    pub allowed_room: HashSet<Vec<u8>>,
    pub local_db: GraphDatabaseService,
    pub reply: mpsc::Sender<Answer>,
}
impl RemotePeerHandle {
    async fn load_allowed_room(
        &mut self,
        verifying_key: Vec<u8>,
    ) -> Result<VecDeque<Vec<u8>>, crate::Error> {
        let rooms = self.local_db.get_rooms_for_user(verifying_key).await?;
        if self.allowed_room.is_empty() {
            for room in &rooms {
                self.allowed_room.insert(room.clone());
            }
        }
        Ok(rooms)
    }

    async fn send<T: Serialize>(&self, id: u64, success: bool, msg: T) -> Result<(), crate::Error> {
        let serialized = bincode::serialize(&msg)?;
        let answer = Answer {
            id,
            success,
            serialized,
        };
        self.reply
            .send(answer)
            .await
            .map_err(|e| crate::Error::SendError(e.to_string()))
    }
}
