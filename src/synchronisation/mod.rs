use serde::{Deserialize, Serialize};

use crate::database::room::Room;

pub mod authorisation_node;
pub mod local_peer;
pub mod node_full;
pub mod peer_service;
pub mod remote_peer;
mod room_lock;

/// Queries have 10 seconds to returns before closing connection
pub static NETWORK_TIMEOUT_SEC: u64 = 10;

#[derive(Serialize, Deserialize)]
pub enum Query {
    RoomList,
    RoomDefinition(Vec<u8>),
    RoomLog(Vec<u8>),
}

#[derive(Serialize, Deserialize)]
pub struct QueryProtocol {
    id: u64,
    query: Query,
}

#[derive(Serialize, Deserialize)]
pub struct AnswerProtocol {
    id: u64,
    success: bool,
    serialized: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub enum Protocol {
    Answer(AnswerProtocol),
    Query(QueryProtocol),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ErrorType {
    Authorisation,
    RemoteTechnical,
    TimeOut,
    Parsing,
    Technical,
}
pub enum LocalEvent {
    RoomDefinitionChanged(Room),
    RoomDataChanged(Vec<u8>),
}

pub enum RemoteEvent {
    RoomDefinitionChanged(Vec<u8>),
    RoomDataChanged(Vec<u8>),
}
