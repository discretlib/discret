pub mod authorisation_service;
pub mod authorisation_service_test;
pub mod daily_log;
pub mod deletion;
pub mod edge;
pub mod graph_database;
pub mod mutation_query;
pub mod node;
pub mod query;
pub mod query_language;
pub mod query_test;
pub mod room;
pub mod room_node;

pub mod sqlite_database;
pub mod system_entities;
use thiserror::Error;
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Cryptography(#[from] crate::security::Error),

    #[error(transparent)]
    Database(#[from] rusqlite::Error),

    #[error(transparent)]
    Parsing(#[from] query_language::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    OneshotAsyncRecv(#[from] tokio::sync::oneshot::error::RecvError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error("{0}")]
    DatabaseRowToLong(String),

    #[error("Invalid JSON Object {0}")]
    InvalidJsonObject(String),

    #[error("Cannot parse field {0} value into a {1}")]
    InvalidJsonFieldValue(String, String),

    #[error("Missing json field {0}")]
    MissingJsonField(String),

    #[error("Field is not an array {0}")]
    InvalidJSonArray(String),

    #[error("{0}")]
    DatabaseWrite(String),

    #[error("{0}")]
    InvalidNode(String),

    #[error("{0}")]
    ChannelSend(String),

    #[error("Entity cannot be empty")]
    EmptyNodeEntity(),

    #[error("Edge label cannot be empty")]
    EmptyEdgeLabel(),

    #[error("entity {0} with id {1} could not be found and cannot be updated")]
    InvalidMutationId(String, String),

    #[error("could not find id while querying entity {0}")]
    InvalidId(String),

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

    #[error("user not found in room {0}")]
    InvalidUser(String),

    #[error("A more recent User definition exists")]
    InvalidUserDate(),

    #[error("Entity Right validity date is set before an existing credential validity")]
    InvalidRightDate(),

    #[error("system entity '{0}' cannot be mutated ouside a Room mutation")]
    InvalidAuthorisationMutation(String),

    #[error("not enough right to mutate entity '{0}' in room '{1}' ")]
    AuthorisationRejected(String, String),

    #[error("Authorisation model forbids deletion of {0} in entity {1}")]
    CannotRemove(String, String),

    #[error("Unknown room id {0} ")]
    UnknownRoom(String),

    #[error("{0} Entity cannot have a room_id defined")]
    ForbiddenRoomId(String),

    #[error("Updates not allowed, Only inserts can be performed for this entity")]
    UpdateNotAllowed(),

    #[error("Deletes not allowed, Only inserts can be performed for this entity")]
    DeleteNotAllowed(),

    #[error("Entity right is missing an entity name")]
    EntityRightMissingName(),

    #[error("{0}")]
    InvalidFullNode(String),

    #[error("The requested node does not belong to the right room")]
    InvalidNodeRequest(),

    #[error("{0}")]
    QueryParsing(String),
}
