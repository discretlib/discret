use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{
    database::{node::Node, room::Room},
    security::{self, Uid},
};
use thiserror::Error;
pub mod node_full;
pub mod peer_inbound_service;
pub mod peer_outbound_service;
pub mod room_locking_service;

#[derive(Serialize, Deserialize, Debug, Error)]
pub enum Error {
    #[error("Authorisation for Query {0}")]
    Authorisation(String),

    #[error("RemoteTechnical for Query {0}")]
    RemoteTechnical(String),

    #[error("TimeOut ")]
    TimeOut,

    #[error("Parsing")]
    Parsing,

    #[error("Technical")]
    Technical,
}

/// Queries have 10 seconds to returns before closing connection
pub static NETWORK_TIMEOUT_SEC: u64 = 10;

#[derive(Serialize, Deserialize)]
pub enum Query {
    ProveIdentity(Vec<u8>),
    RoomList,
    RoomDefinition(Uid),
    RoomNode(Uid),
    RoomLog(Uid),
    RoomLogAt(Uid, i64),
    EdgeDeletionLog(Uid, String, i64),
    NodeDeletionLog(Uid, String, i64),
    RoomDailyNodes(Uid, String, i64),
    FullNodes(Uid, Vec<Uid>),
    PeersForRoom(Uid),
}

#[derive(Serialize, Deserialize)]
pub struct QueryProtocol {
    pub id: u64,
    pub query: Query,
}

#[derive(Serialize, Deserialize)]
pub struct Answer {
    pub id: u64,
    pub success: bool,
    pub complete: bool,
    pub serialized: Vec<u8>,
}

#[derive(Clone)]
pub enum LocalEvent {
    RoomDefinitionChanged(Arc<Room>),
    RoomDataChanged(Vec<Uid>),
}

#[derive(Serialize, Deserialize)]
pub enum RemoteEvent {
    Ready, //indicate that this end of the connection is ready to synchronize
    RoomDefinitionChanged(Uid),
    RoomDataChanged(Uid),
}

#[derive(Serialize, Deserialize)]
pub struct IdentityAnswer {
    pub peer: Node,
    pub chall_signature: Vec<u8>,
}
impl IdentityAnswer {
    pub fn verify(&self, challenge: &Vec<u8>) -> Result<(), security::Error> {
        let pub_key = security::import_verifying_key(&self.peer.verifying_key)?;
        pub_key.verify(challenge, &self.chall_signature)?;
        Ok(())
    }
}
