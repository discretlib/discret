pub mod edge;
pub mod graph_database;
pub mod node;
pub mod query_language;
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
    Utf8Error(#[from] std::str::Utf8Error),

    #[error("{0}")]
    DatabaseRowToLong(String),

    #[error(transparent)]
    AsyncRecvError(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("{0}")]
    TokioSendError(String),

    #[error(
        "id length must be between {} and {} bytes",
        crate::database::graph_database::DB_ID_MIN_SIZE,
        crate::database::graph_database::DB_ID_MAX_SIZE
    )]
    InvalidId(),

    #[error("database schema cannot be empty or have more than {0} characters")]
    InvalidNodeSchema(usize),
}
