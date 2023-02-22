pub mod database_service;
pub mod datamodel;
pub mod edge_table;
pub mod node_table;
pub mod security_policy;
pub mod synch_log;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    CryptoError(#[from] crate::cryptography::Error),

    #[error(transparent)]
    DatabaseError(#[from] rusqlite::Error),

    #[error(transparent)]
    JSONError(#[from] serde_json::Error),

    #[error("{0}")]
    DatabaseWriteError(String),

    #[error("{0}")]
    InvalidNode(String),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error("{0}")]
    DatabaseRowToLong(String),
    #[error(transparent)]
    AsyncRecvError(#[from] tokio::sync::oneshot::error::RecvError),

    #[error(
        "database id length must be between  {} and {} bytes",
        crate::database::datamodel::DB_ID_MIN_SIZE,
        crate::database::datamodel::DB_ID_MAX_SIZE
    )]
    InvalidDatabaseId(),

    #[error("database schema cannot have more than {0} characters")]
    DatabaseSchemaTooLarge(usize),

    #[error("{0}")]
    Unknown(String),
}
