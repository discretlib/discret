use serde::{Deserialize, Serialize};

use crate::{cryptography, database::room::Room};
use thiserror::Error;
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
    ProveIdentity(Vec<u8>),
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
pub struct Answer {
    id: u64,
    success: bool,
    serialized: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Error)]
pub enum Error {
    #[error("Authorisation")]
    Authorisation,

    #[error("RemoteTechnical")]
    RemoteTechnical,

    #[error("TimeOut")]
    TimeOut,

    #[error("Parsing")]
    Parsing,

    #[error("Technical")]
    Technical,
}

#[derive(Clone)]
pub enum LocalEvent {
    RoomDefinitionChanged(Room),
    RoomDataChanged(Vec<u8>),
}

#[derive(Serialize, Deserialize)]
pub enum RemoteEvent {
    Ready, //indicate that this end of the connection is ready to synchronize
    RoomDefinitionChanged(Vec<u8>),
    RoomDataChanged(Vec<u8>),
}

#[derive(Serialize, Deserialize)]
pub struct ProveAnswer {
    pub verifying_key: Vec<u8>,
    pub invitation: Option<Vec<u8>>,
    pub chall_signature: Vec<u8>,
}
impl ProveAnswer {
    pub fn verify(&self, challenge: &Vec<u8>) -> Result<(), cryptography::Error> {
        let pub_key = cryptography::import_verifying_key(&self.verifying_key)?;
        pub_key.verify(challenge, &self.chall_signature)?;
        Ok(())
    }
}
