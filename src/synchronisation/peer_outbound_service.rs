use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use serde::Serialize;
use tokio::sync::{
    mpsc::{self, UnboundedSender},
    Mutex,
};

use crate::{
    database::graph_database::GraphDatabaseService, log_service::LogService,
    peer_connection_service::PeerConnectionService, security::Uid,
};

use super::{Answer, Error, ProveAnswer, Query, QueryProtocol};

///
/// handle all inbound queries
///
#[derive(Clone)]
pub struct InboundQueryService {
    room_sender: UnboundedSender<Uid>,
}
impl InboundQueryService {
    pub fn start(
        mut peer: RemotePeerHandle,
        mut receiver: mpsc::Receiver<QueryProtocol>,
        log_service: LogService,
        peer_service: PeerConnectionService,
        verifying_key: Arc<Mutex<Vec<u8>>>,
    ) -> Self {
        let (room_sender, mut room_receiver) = mpsc::unbounded_channel::<Uid>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = receiver.recv() =>{
                        match msg{
                            Some(msg) => {
                                if let Err(e)  = Self::process_inbound(msg, &mut peer, &log_service, &verifying_key).await{
                                    log_service.error("RemoteQueryService Channel Send".to_string(), e.into());
                                }
                            },
                            None => break,
                        }

                    }
                    msg = room_receiver.recv() =>{
                        match msg{
                            Some(uid) => peer.add_allowed_room(uid),
                            None => break,
                        }
                    }
                }
            }

            let key = verifying_key.lock().await;
            peer_service.disconnect(key.clone(), peer.hardware_id).await;
        });
        Self { room_sender }
    }

    pub async fn process_inbound(
        msg: QueryProtocol,
        peer: &mut RemotePeerHandle,
        log_service: &LogService,
        verifying_key: &Arc<Mutex<Vec<u8>>>,
    ) -> Result<(), crate::Error> {
        match msg.query {
            Query::ProveIdentity(challenge) => {
                let res = peer.db.sign(challenge).await;
                peer.send(
                    msg.id,
                    true,
                    ProveAnswer {
                        verifying_key: res.0,
                        invitation: None,
                        chall_signature: res.1,
                    },
                )
                .await
            }

            Query::RoomList => {
                let key = verifying_key.lock().await;
                if !key.is_empty() {
                    let res = peer.load_allowed_room(key.clone()).await;
                    match res {
                        Ok(room_list) => peer.send(msg.id, true, room_list).await?,
                        Err(e) => {
                            log_service.error("RoomList".to_string(), e.into());
                            peer.send(
                                msg.id,
                                false,
                                Error::RemoteTechnical("RoomList".to_string()),
                            )
                            .await?;
                        }
                    }
                }
                Ok(())
            }

            Query::RoomDefinition(room_id) => {
                if peer.allowed_room.contains(&room_id) {
                    let res = peer.db.get_room_definition(room_id).await;
                    match res {
                        Ok(definition) => peer.send(msg.id, true, definition).await?,
                        Err(e) => {
                            log_service.error("RoomDefinition".to_string(), e.into());
                            peer.send(
                                msg.id,
                                false,
                                Error::RemoteTechnical("RoomDefinition".to_string()),
                            )
                            .await?;
                        }
                    }
                } else {
                    peer.send(
                        msg.id,
                        false,
                        Error::Authorisation("RoomDefinition".to_string()),
                    )
                    .await?;
                }
                Ok(())
            }

            Query::RoomNode(room_id) => {
                if peer.allowed_room.contains(&room_id) {
                    let res = peer.db.get_room_node(room_id).await;
                    match res {
                        Ok(definition) => peer.send(msg.id, true, definition).await?,
                        Err(e) => {
                            log_service.error("RoomNode".to_string(), e.into());
                            peer.send(
                                msg.id,
                                false,
                                Error::RemoteTechnical("RoomNode".to_string()),
                            )
                            .await?;
                        }
                    }
                } else {
                    peer.send(msg.id, false, Error::Authorisation("RoomNode".to_string()))
                        .await?;
                }

                Ok(())
            }

            Query::RoomLog(room_id) => {
                if peer.allowed_room.contains(&room_id) {
                    let res = peer.db.get_room_log(room_id).await;
                    match res {
                        Ok(log) => peer.send(msg.id, true, log).await?,
                        Err(e) => {
                            log_service.error("RoomLog".to_string(), e.into());
                            peer.send(msg.id, false, Error::RemoteTechnical("RoomLog".to_string()))
                                .await?
                        }
                    }
                } else {
                    peer.send(msg.id, false, Error::Authorisation("RoomLog".to_string()))
                        .await?
                }

                Ok(())
            }
            Query::RoomDailyNodes(room_id, date) => {
                if peer.allowed_room.contains(&room_id) {
                    let res = peer.db.get_room_daily_nodes(room_id, date).await;
                    match res {
                        Ok(log) => peer.send(msg.id, true, log).await?,
                        Err(e) => {
                            log_service.error("RoomDailyNodes".to_string(), e.into());
                            peer.send(
                                msg.id,
                                false,
                                Error::RemoteTechnical("RoomDailyNodes".to_string()),
                            )
                            .await?
                        }
                    }
                } else {
                    peer.send(
                        msg.id,
                        false,
                        Error::Authorisation("RoomDailyNodes".to_string()),
                    )
                    .await?
                }
                Ok(())
            }
            Query::FullNodes(room_id, node_ids) => {
                if peer.allowed_room.contains(&room_id) {
                    let res = peer.db.get_full_nodes(room_id, node_ids).await;
                    match res {
                        Ok(log) => peer.send(msg.id, true, log).await?,
                        Err(e) => {
                            log_service.error("FullNodes".to_string(), e.into());
                            peer.send(
                                msg.id,
                                false,
                                Error::RemoteTechnical("FullNodes".to_string()),
                            )
                            .await?
                        }
                    }
                } else {
                    peer.send(msg.id, false, Error::Authorisation("FullNodes".to_string()))
                        .await?
                }
                Ok(())
            }
            Query::EdgeDeletionLog(room_id, date) => {
                if peer.allowed_room.contains(&room_id) {
                    let res = peer.db.get_room_edge_deletion_log(room_id, date).await;
                    match res {
                        Ok(log) => peer.send(msg.id, true, log).await?,
                        Err(e) => {
                            log_service.error("EdgeDeletionLog".to_string(), e.into());
                            peer.send(
                                msg.id,
                                false,
                                Error::RemoteTechnical("EdgeDeletionLog".to_string()),
                            )
                            .await?
                        }
                    }
                } else {
                    peer.send(
                        msg.id,
                        false,
                        Error::Authorisation("EdgeDeletionLog".to_string()),
                    )
                    .await?
                }
                Ok(())
            }
            Query::NodeDeletionLog(room_id, date) => {
                if peer.allowed_room.contains(&room_id) {
                    let res = peer.db.get_room_node_deletion_log(room_id, date).await;
                    match res {
                        Ok(log) => peer.send(msg.id, true, log).await?,
                        Err(e) => {
                            log_service.error("NodeDeletionLog".to_string(), e.into());
                            peer.send(
                                msg.id,
                                false,
                                Error::RemoteTechnical("NodeDeletionLog".to_string()),
                            )
                            .await?
                        }
                    }
                } else {
                    peer.send(
                        msg.id,
                        false,
                        Error::Authorisation("NodeDeletionLog".to_string()),
                    )
                    .await?
                }
                Ok(())
            }
        }
    }
    pub fn add_allowed_room(&self, room: Uid) {
        let _ = self.room_sender.send(room);
    }
}

pub struct RemotePeerHandle {
    pub hardware_id: Vec<u8>,
    pub allowed_room: HashSet<Uid>,
    pub db: GraphDatabaseService,
    pub reply: mpsc::Sender<Answer>,
}
impl RemotePeerHandle {
    fn add_allowed_room(&mut self, room: Uid) {
        self.allowed_room.insert(room);
    }

    async fn load_allowed_room(
        &mut self,
        verifying_key: Vec<u8>,
    ) -> Result<VecDeque<Uid>, crate::Error> {
        let rooms = self.db.get_rooms_for_user(verifying_key).await?;
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
