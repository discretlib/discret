use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use serde::Serialize;
use tokio::sync::{
    mpsc::{self, UnboundedSender},
    Mutex,
};

use crate::{
    base64_encode,
    database::graph_database::GraphDatabaseService,
    log_service::LogService,
    peer_connection_service::PeerConnectionService,
    security::{HardwareFingerprint, Uid},
};

use super::{Answer, Error, IdentityAnswer, Query, QueryProtocol};

///
/// handle all inbound queries
///
#[derive(Clone)]
pub struct InboundQueryService {
    room_sender: UnboundedSender<Uid>,
}
impl InboundQueryService {
    pub fn start(
        circuit_id: [u8; 32],
        conn_id: Uid,
        mut peer: RemotePeerHandle,
        mut receiver: mpsc::Receiver<QueryProtocol>,
        log_service: LogService,
        peer_service: PeerConnectionService,
        verifying_key: Arc<Mutex<Vec<u8>>>,
        conn_ready: Arc<AtomicBool>,
    ) -> Self {
        let (room_sender, mut room_receiver) = mpsc::unbounded_channel::<Uid>();
        let fingerprint = HardwareFingerprint::new().unwrap();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = receiver.recv() =>{
                        match msg{
                            Some(msg) => {
                                if let Err(e)  = Self::process_inbound(msg, &mut peer, &log_service, &verifying_key, &conn_ready,  &fingerprint).await{
                                    log_service.error("RemoteQueryService Channel Send".to_string(), e);
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
            peer_service
                .disconnect(key.clone(), circuit_id, conn_id)
                .await;
        });
        Self { room_sender }
    }

    pub async fn process_inbound(
        msg: QueryProtocol,
        peer: &mut RemotePeerHandle,
        logs: &LogService,
        verifying_key: &Arc<Mutex<Vec<u8>>>,
        conn_ready: &Arc<AtomicBool>,
        fingerprint: &HardwareFingerprint,
    ) -> Result<(), crate::Error> {
        match msg.query {
            Query::ProveIdentity(challenge) => {
                let res = peer.db.sign(challenge).await;
                let self_peer = peer
                    .db
                    .get_peer_node(peer.verifying_key.clone())
                    .await?
                    .unwrap();
                peer.send(
                    msg.id,
                    true,
                    true,
                    IdentityAnswer {
                        peer: self_peer,
                        chall_signature: res.1,
                    },
                )
                .await
            }

            Query::HardwareFingerprint() => {
                let key = verifying_key.lock().await;
                if !key.is_empty() {
                    if key.eq(&peer.verifying_key) {
                        peer.send(msg.id, true, true, fingerprint.clone()).await?;
                    } else {
                        return Err(crate::Error::SecurityViolation(format!(
                            "Query::HardwareFingerprint Peer with key {} is trying to get your hardware fingerprint",
                            base64_encode(&key)
                        )));
                    }
                }
                Ok(())
            }

            Query::RoomList => {
                let key = verifying_key.lock().await;

                if !key.is_empty() && conn_ready.load(Ordering::Relaxed) {
                    let init_rooms = peer.allowed_room.is_empty();

                    let mut res_reply = peer.db.get_rooms_for_peer(key.clone()).await;
                    while let Some(rooms) = res_reply.recv().await {
                        match rooms {
                            Ok(room_list) => {
                                if init_rooms {
                                    for room in &room_list {
                                        peer.allowed_room.insert(room.clone());
                                    }
                                }
                                peer.send(msg.id, true, false, room_list).await?;
                            }
                            Err(e) => {
                                logs.error("Query::RoomList".to_string(), e.into());
                                peer.send(
                                    msg.id,
                                    false,
                                    true,
                                    Error::RemoteTechnical("Query::RoomList".to_string()),
                                )
                                .await?;
                            }
                        }
                    }
                    peer.send(msg.id, true, true, "").await?;
                }
                Ok(())
            }

            Query::RoomDefinition(room_id) => {
                if peer.allowed_room.contains(&room_id) {
                    let res = peer.db.get_room_definition(room_id).await;
                    match res {
                        Ok(definition) => peer.send(msg.id, true, true, definition).await?,
                        Err(e) => {
                            logs.error("Query::RoomDefinition".to_string(), e.into());
                            peer.send(
                                msg.id,
                                false,
                                true,
                                Error::RemoteTechnical("Query::RoomDefinition".to_string()),
                            )
                            .await?;
                        }
                    }
                } else {
                    peer.send(
                        msg.id,
                        false,
                        true,
                        Error::Authorisation("Query::RoomDefinition".to_string()),
                    )
                    .await?;
                }
                Ok(())
            }

            Query::RoomNode(room_id) => {
                if peer.allowed_room.contains(&room_id) {
                    let res = peer.db.get_room_node(room_id).await;
                    match res {
                        Ok(definition) => peer.send(msg.id, true, true, definition).await?,
                        Err(e) => {
                            logs.error("Query::RoomNode".to_string(), e.into());
                            peer.send(
                                msg.id,
                                false,
                                true,
                                Error::RemoteTechnical("Query::RoomNode".to_string()),
                            )
                            .await?;
                        }
                    }
                } else {
                    peer.send(
                        msg.id,
                        false,
                        true,
                        Error::Authorisation("Query::RoomNode".to_string()),
                    )
                    .await?;
                }

                Ok(())
            }

            Query::RoomLog(room_id) => {
                if peer.allowed_room.contains(&room_id) {
                    let mut res_reply = peer.db.get_room_log(room_id).await;
                    while let Some(res) = res_reply.recv().await {
                        match res {
                            Ok(log) => peer.send(msg.id, true, false, log).await?,
                            Err(e) => {
                                logs.error("Query::RoomLog".to_string(), e.into());
                                peer.send(
                                    msg.id,
                                    false,
                                    true,
                                    Error::RemoteTechnical("Query::RoomLog".to_string()),
                                )
                                .await?
                            }
                        }
                    }
                    peer.send(msg.id, true, true, "").await?;
                } else {
                    peer.send(
                        msg.id,
                        false,
                        true,
                        Error::Authorisation("Query::RoomLog".to_string()),
                    )
                    .await?
                }

                Ok(())
            }

            Query::RoomLogAt(room_id, date) => {
                if peer.allowed_room.contains(&room_id) {
                    let res = peer.db.get_room_log_at(room_id, date).await;
                    match res {
                        Ok(log) => peer.send(msg.id, true, true, log).await?,
                        Err(e) => {
                            logs.error("Query::RoomLog".to_string(), e.into());
                            peer.send(
                                msg.id,
                                false,
                                true,
                                Error::RemoteTechnical("Query::RoomLog".to_string()),
                            )
                            .await?
                        }
                    }
                } else {
                    peer.send(
                        msg.id,
                        false,
                        true,
                        Error::Authorisation("Query::RoomLog".to_string()),
                    )
                    .await?
                }

                Ok(())
            }

            Query::RoomDailyNodes(room_id, entity, date) => {
                if peer.allowed_room.contains(&room_id) {
                    let mut res_reply = peer.db.get_room_daily_nodes(room_id, entity, date).await;
                    while let Some(res) = res_reply.recv().await {
                        match res {
                            Ok(log) => peer.send(msg.id, true, false, log).await?,
                            Err(e) => {
                                logs.error("Query::RoomDailyNodes".to_string(), e.into());
                                peer.send(
                                    msg.id,
                                    false,
                                    true,
                                    Error::RemoteTechnical("Query::RoomDailyNodes".to_string()),
                                )
                                .await?
                            }
                        }
                    }
                    peer.send(msg.id, true, true, "").await?;
                } else {
                    peer.send(
                        msg.id,
                        false,
                        true,
                        Error::Authorisation("Query::RoomDailyNodes".to_string()),
                    )
                    .await?
                }
                Ok(())
            }

            Query::Nodes(room_id, node_ids) => {
                if peer.allowed_room.contains(&room_id) {
                    let mut res_reply = peer.db.get_nodes(room_id, node_ids).await;
                    while let Some(res) = res_reply.recv().await {
                        match res {
                            Ok(log) => peer.send(msg.id, true, false, log).await?,
                            Err(e) => {
                                logs.error("Query::Nodes".to_string(), e.into());
                                peer.send(
                                    msg.id,
                                    false,
                                    true,
                                    Error::RemoteTechnical("Query::Nodes".to_string()),
                                )
                                .await?
                            }
                        }
                    }
                    peer.send(msg.id, true, true, "").await?;
                } else {
                    peer.send(
                        msg.id,
                        false,
                        true,
                        Error::Authorisation("Query::Nodes".to_string()),
                    )
                    .await?
                }
                Ok(())
            }

            Query::Edges(room_id, nodes) => {
                if peer.allowed_room.contains(&room_id) {
                    let mut res_reply = peer.db.get_edges(room_id, nodes).await;
                    while let Some(res) = res_reply.recv().await {
                        match res {
                            Ok(log) => peer.send(msg.id, true, false, log).await?,
                            Err(e) => {
                                logs.error("Query::Edges".to_string(), e.into());
                                peer.send(
                                    msg.id,
                                    false,
                                    true,
                                    Error::RemoteTechnical("Query::Edges".to_string()),
                                )
                                .await?
                            }
                        }
                    }
                    peer.send(msg.id, true, true, "").await?;
                } else {
                    peer.send(
                        msg.id,
                        false,
                        true,
                        Error::Authorisation("Query::Edges".to_string()),
                    )
                    .await?
                }
                Ok(())
            }

            Query::EdgeDeletionLog(room_id, entity, date) => {
                if peer.allowed_room.contains(&room_id) {
                    let mut res_reply = peer
                        .db
                        .get_room_edge_deletion_log(room_id, entity, date)
                        .await;

                    while let Some(res) = res_reply.recv().await {
                        match res {
                            Ok(log) => peer.send(msg.id, true, false, log).await?,
                            Err(e) => {
                                logs.error("Query::EdgeDeletionLog".to_string(), e.into());
                                peer.send(
                                    msg.id,
                                    true,
                                    false,
                                    Error::RemoteTechnical("Query::EdgeDeletionLog".to_string()),
                                )
                                .await?
                            }
                        }
                    }
                    peer.send(msg.id, true, true, "").await?;
                } else {
                    peer.send(
                        msg.id,
                        false,
                        true,
                        Error::Authorisation("Query::EdgeDeletionLog".to_string()),
                    )
                    .await?
                }
                Ok(())
            }
            Query::NodeDeletionLog(room_id, entity, date) => {
                if peer.allowed_room.contains(&room_id) {
                    let mut res_reply = peer
                        .db
                        .get_room_node_deletion_log(room_id, entity, date)
                        .await;
                    while let Some(res) = res_reply.recv().await {
                        match res {
                            Ok(log) => peer.send(msg.id, true, false, log).await?,
                            Err(e) => {
                                logs.error("Query::NodeDeletionLog".to_string(), e.into());
                                peer.send(
                                    msg.id,
                                    false,
                                    true,
                                    Error::RemoteTechnical("Query::NodeDeletionLog".to_string()),
                                )
                                .await?
                            }
                        }
                    }
                    peer.send(msg.id, true, true, "").await?;
                } else {
                    peer.send(
                        msg.id,
                        false,
                        true,
                        Error::Authorisation("Query::NodeDeletionLog".to_string()),
                    )
                    .await?
                }
                Ok(())
            }

            Query::PeersForRoom(room_id) => {
                if peer.allowed_room.contains(&room_id) {
                    let mut res_reply = peer.db.peers_for_room(room_id).await;

                    while let Some(res) = res_reply.recv().await {
                        match res {
                            Ok(log) => peer.send(msg.id, true, false, log).await?,
                            Err(e) => {
                                logs.error("Query::PeerNodes".to_string(), e.into());
                                peer.send(
                                    msg.id,
                                    false,
                                    true,
                                    Error::RemoteTechnical("Query::PeerNodes".to_string()),
                                )
                                .await?
                            }
                        }
                    }
                    peer.send(msg.id, true, true, "").await?;
                } else {
                    peer.send(
                        msg.id,
                        false,
                        true,
                        Error::Authorisation("Query::PeerNodes".to_string()),
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
    pub allowed_room: HashSet<Uid>,
    pub db: GraphDatabaseService,
    pub verifying_key: Vec<u8>,
    pub reply: mpsc::Sender<Answer>,
}
impl RemotePeerHandle {
    fn add_allowed_room(&mut self, room: Uid) {
        self.allowed_room.insert(room);
    }

    async fn send<T: Serialize>(
        &self,
        id: u64,
        success: bool,
        complete: bool,
        msg: T,
    ) -> Result<(), crate::Error> {
        let serialized = bincode::serialize(&msg)?;
        let answer = Answer {
            id,
            success,
            complete,
            serialized,
        };
        self.reply
            .send(answer)
            .await
            .map_err(|e| crate::Error::SendError(e.to_string()))
    }
}
