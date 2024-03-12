pub mod authorisation;
pub mod authorisation_test;
pub mod configuration;
pub mod daily_log;
pub mod deletion;
pub mod edge;
pub mod event_service;
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
    ChannelSend(String),

    #[error(
        "id length must be between {} and {} bytes",
        crate::database::sqlite_database::DB_ID_MIN_SIZE,
        crate::database::sqlite_database::DB_ID_MAX_SIZE
    )]
    InvalidId(),

    #[error("Entity cannot be empty")]
    EmptyNodeEntity(),

    #[error("Edge label cannot be empty")]
    EmptyEdgeLabel(),

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

    #[error("Authorisation allready exists for this room")]
    AuthorisationExists(),

    #[error("This reference does not belong to this room")]
    NotBelongsTo(),

    #[error("Rights allreday exits for entity '{0}'")]
    RightsExists(String),

    #[error("A more recent User definition exists")]
    InvalidUserDate(),

    #[error("credential validity date is set before an existing credential validity")]
    InvalidCredentialDate(),

    #[error("system entity '{0}' cannot be mutated ouside a Room mutation")]
    InvalidAuthorisationMutation(String),

    #[error("not enough right to mutate entity '{0}' in room '{1}' ")]
    AuthorisationRejected(String, String),

    #[error("Authorisation model forbids deletion of {0} in entity {1}")]
    CannotRemove(String, String),

    #[error("Unknown room id {0} ")]
    UnknownRoom(String),

    #[error("User '{0}' does not belong to the parent rooms of room '{1}' ")]
    UserNotInParentRoom(String, String),

    #[error("Updates not allowed, Only inserts can be performed for this entity")]
    UpdateNotAllowed(),

    #[error("Deletes not allowed, Only inserts can be performed for this entity")]
    DeleteNotAllowed(),

    #[error("Entity right is missing an entity name")]
    EntityRightMissingName(),
}
