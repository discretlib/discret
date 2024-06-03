pub mod endpoint;
pub mod multicast;
pub mod peer_manager;
pub mod shared_buffers;
use serde::{Deserialize, Serialize};

use std::io;
use thiserror::Error;

use crate::{security::MeetingToken, Uid};

#[derive(Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub endpoint_id: Uid,
    pub remote_id: Uid,
    pub connnection_id: Uid,
    pub verifying_key: Vec<u8>,
    pub hardware_key: Option<[u8; 32]>,
    pub hardware_name: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AnnounceHeader {
    endpoint_id: Uid,
    port: u16,
    certificate_hash: [u8; 32],
    signature: Vec<u8>,
}
impl AnnounceHeader {
    pub fn hash_for_signature(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.endpoint_id);

        hasher.update(&self.port.to_le_bytes());
        hasher.update(&self.certificate_hash);
        *hasher.finalize().as_bytes()
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct Announce {
    pub header: AnnounceHeader,
    pub tokens: Vec<MeetingToken>,
}

pub const MAX_TOKENS: u8 = 255;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Rustls(#[from] rustls::Error),

    #[error(transparent)]
    AddrParse(#[from] std::net::AddrParseError),

    #[error(transparent)]
    QuinnConfig(#[from] quinn::crypto::rustls::NoInitialCipherSuite),

    #[error(transparent)]
    QuinnConnect(#[from] quinn::ConnectError),

    #[error(transparent)]
    QuinnConnection(#[from] quinn::ConnectionError),

    #[error(transparent)]
    Serialisation(#[from] Box<bincode::ErrorKind>),

    #[error(transparent)]
    SocketWrite(#[from] quinn::WriteError),

    #[error(transparent)]
    SocketRead(#[from] quinn::ReadExactError),

    #[error("Message size {0} is to long and is ignored. Maximum allowed: {1}")]
    MsgSerialisationToLong(usize, usize),

    #[error("Message size {0} is to long and is ignored. Maximum allowed: {1}")]
    MsgDeserialisationToLong(usize, usize),

    #[error("IPV6 is not supported on this device")]
    IPV6NotSuported(),

    #[error("Failed to connect to {0} after {1} try, reason: {2}")]
    ConnectionFailed(String, usize, String),

    #[error("Invalid Stream flag: {0}")]
    InvalidStream(u8),

    #[error("One or several Streams are missing")]
    MissingStream(),

    #[error("{0}")]
    UnacceptableBehavior(String),

    #[error("{0}")]
    Unknown(String),
}
