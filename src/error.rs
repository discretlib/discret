use std::io;
use thiserror::Error;
#[derive(Error, Debug)]
pub enum Error {
    #[error("No Vault defined for this pass phase")]
    VaultDontExists,
    #[error("A Vault allready exists for this pass phase")]
    VaultAllreadyExists,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid KeyPair")]
    InvalidKeyPair,
    #[error("Invalid Public Key")]
    InvalidPublicKey,

    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error(transparent)]
    ConnError(#[from] quinn::ConnectError),

    #[error(transparent)]
    ConnectionError(#[from] quinn::ConnectionError),

    #[error(transparent)]
    SerialisationError(#[from] Box<bincode::ErrorKind>),

    #[error(transparent)]
    SocketWriteError(#[from] quinn::WriteError),

    #[error(transparent)]
    SocketReadError(#[from] quinn::ReadExactError),

    #[error("Message size {0} is to long and is ignored. Maximum allowed: {1}")]
    MsgSerialisationToLong(usize, usize),

    #[error("Message size {0} is to long and is ignored. Maximum allowed: {1}")]
    MsgDeserialisationToLong(usize, usize),

    #[error("{0}")]
    Unknown(String),
}
