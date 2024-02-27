pub mod configuration;
pub mod deletion;
pub mod edge;
pub mod graph_database;
pub mod mutation_query;
pub mod node;
pub mod query;
pub mod query_language;
pub mod query_test;
pub mod sqlite_database;
use thiserror::Error;
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    CryptoError(#[from] crate::cryptography::Error),

    #[error("{0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("{0}")]
    ParsingError(#[from] query_language::Error),

    #[error("{0}")]
    JSONError(#[from] serde_json::Error),

    #[error("Invalid JSON Object {0}")]
    InvalidJsonObject(String),

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
    DatabaseSendError(String),

    #[error(
        "id length must be between {} and {} bytes",
        crate::database::sqlite_database::DB_ID_MIN_SIZE,
        crate::database::sqlite_database::DB_ID_MAX_SIZE
    )]
    InvalidId(),

    #[error("database schema cannot be empty or have more than {0} characters")]
    InvalidNodeSchema(usize),

    #[error("entity {0} with id {1} could not be found and cannot be updated")]
    InvalidMutationId(String, String),

    #[error("unknown entity {0} with id {1} and cannot be inserted in field {2}.{3}")]
    UnknownFieldEntity(String, String, String, String),

    #[error("unknown entity {0} with id {1}")]
    UnknownEntity(String, String),

    #[error("{0}")]
    QueryError(String),

    #[error("Missing parameter: '{0}', Cannot build SQL query parameters")]
    MissingParameter(String),
}
