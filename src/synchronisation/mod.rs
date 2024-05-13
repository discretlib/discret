use serde::{Deserialize, Serialize};

pub mod authorisation_node;
pub mod node_full;
pub mod peer;
pub mod peer_connection_service;
mod room_lock;

#[derive(Serialize, Deserialize)]
pub enum Query {
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

#[derive(Serialize, Deserialize)]
pub enum ErrorType {
    Authorisation,
    RemoteTechnical,
    TimeOut,
    Parsing,
    Technical,
}
