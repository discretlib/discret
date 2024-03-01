pub mod authorisation;
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
    #[error(transparent)]
    Authorisation(#[from] authorisation::Error),

    #[error(transparent)]
    Cryptography(#[from] crate::cryptography::Error),

    #[error(transparent)]
    Database(#[from] rusqlite::Error),

    #[error(transparent)]
    Parsing(#[from] query_language::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("Invalid JSON Object {0}")]
    InvalidJsonObject(String),

    #[error("{0}")]
    DatabaseWrite(String),

    #[error("{0}")]
    InvalidNode(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error("{0}")]
    DatabaseRowToLong(String),

    #[error(transparent)]
    OneshotAsyncRecv(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("{0}")]
    DatabaseSend(String),

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
    Query(String),

    #[error("Missing parameter: '{0}', Cannot build SQL query parameters")]
    MissingParameter(String),
}
