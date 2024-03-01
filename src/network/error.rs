use std::io;
use thiserror::Error;
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

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

    #[error("{0}")]
    UnacceptableBehavior(String),

    #[error("{0}")]
    Unknown(String),
}
