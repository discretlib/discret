pub mod endpoint;
pub mod error;
pub mod message;
pub mod multicast;
pub mod peer_connection_service;
use serde::{Deserialize, Serialize};
use std::io;
use thiserror::Error;

use crate::{security::MeetingToken, Uid};

#[derive(Serialize, Deserialize, Default)]
pub struct Announce {
    endpoint_id: Uid,
    port: u16,
    certificate_hash: [u8; 32],
    signature: Vec<u8>,
    tokens: Vec<MeetingToken>,
}
pub const MAX_TOKENS: u8 = 181;

pub const QUIC_MTU: usize = 2144;

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
#[cfg(test)]
mod test {

    use crate::security::{hash, MEETING_TOKEN_SIZE};

    use super::*;
    #[test]
    fn validate_maximum_announce_size() {
        let mut announce = Announce {
            ..Default::default()
        };
        announce.port = 8080;
        announce.certificate_hash = hash("bytes".as_bytes());
        announce.signature = [234; 64].to_vec();

        for i in 0..MAX_TOKENS {
            let token: MeetingToken = [i; MEETING_TOKEN_SIZE];
            announce.tokens.push(token);
        }

        let serialize = bincode::serialize(&announce).unwrap();

        assert!(QUIC_MTU >= serialize.len());
    }
}
