pub mod database_service;
pub mod datamodel;
pub mod edge_table;
pub mod node_table;
pub mod query_language;
pub mod security_policy;
pub mod synch_log;
use thiserror::Error;
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    CryptoError(#[from] crate::cryptography::Error),

    #[error("{0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("{0}")]
    JSONError(#[from] serde_json::Error),

    #[error("{0}")]
    PolicyError(String),

    #[error("{0}")]
    DatabaseWriteError(String),

    #[error("{0}")]
    InvalidNode(String),

    #[error("{0}")]
    IoError(#[from] std::io::Error),

    #[error("{0}")]
    DatabaseRowToLong(String),

    #[error(transparent)]
    AsyncRecvError(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("{0}")]
    TokioSendError(String),

    #[error(
        "id length must be between {} and {} bytes",
        crate::database::datamodel::DB_ID_MIN_SIZE,
        crate::database::datamodel::DB_ID_MAX_SIZE
    )]
    InvalidId(),

    #[error("database schema cannot be empty or have more than {0} characters")]
    InvalidNodeSchema(usize),
}
