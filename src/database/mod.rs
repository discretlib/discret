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
use std::collections::HashMap;

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{base64_encode, Uid};
pub type Result<T> = std::result::Result<T, Error>;

pub const VEC_OVERHEAD: u64 = 4;
pub const MESSAGE_OVERHEAD: usize = 16;

///
/// helper structure to parse the query result
///
pub struct ResultParser {
    parsed: Value,
}
impl ResultParser {
    pub fn new(result: &str) -> std::result::Result<Self, crate::Error> {
        let parsed: Value = serde_json::from_str(result)?;
        Ok(Self { parsed })
    }
    ///
    /// consume the array found for the field and convert it to an array of the generic type T
    ///
    pub fn take_array<T: DeserializeOwned>(
        &mut self,
        field: &str,
    ) -> std::result::Result<Vec<T>, crate::Error> {
        let mut re = Vec::new();
        let obj = self.parsed.as_object_mut();
        if obj.is_none() {
            return Err(crate::Error::from(Error::InvalidJsonObject("".to_string())));
        }
        let obj = obj.unwrap();
        let f = obj.remove(field);
        if f.is_none() {
            return Err(crate::Error::from(Error::MissingJsonField(
                field.to_string(),
            )));
        }
        let f = f.unwrap();

        if let Value::Array(field_array) = f {
            for value in field_array {
                let entry: T = serde_json::from_value(value)?;
                re.push(entry);
            }
        } else {
            return Err(crate::Error::from(Error::InvalidJSonArray(
                field.to_string(),
            )));
        }

        Ok(re)
    }

    ///
    /// consume the object found for the field and convert it to an object of the generic type T
    ///
    pub fn take_object<T: DeserializeOwned>(
        &mut self,
        field: &str,
    ) -> std::result::Result<T, crate::Error> {
        let obj = self.parsed.as_object_mut();
        if obj.is_none() {
            return Err(crate::Error::from(Error::InvalidJsonObject("".to_string())));
        }
        let obj = obj.unwrap();
        let f = obj.remove(field);
        if f.is_none() {
            return Err(crate::Error::from(Error::MissingJsonField(
                field.to_string(),
            )));
        }
        let f = f.unwrap();

        let obj: T = serde_json::from_value(f)?;

        Ok(obj)
    }
}

#[derive(Serialize)]
pub struct DataModification {
    pub rooms: HashMap<String, HashMap<String, Vec<i64>>>,
}
impl DataModification {
    pub fn add(&mut self, room: Uid, entity: String, date: i64) {
        let room = self.rooms.entry(base64_encode(&room)).or_default();
        let entity = room.entry(entity).or_default();
        entity.push(date);
    }
}

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

    #[error(transparent)]
    Bincode(#[from] Box<bincode::ErrorKind>),

    #[error("Node len:{0} is larger than the maximum authorised: {1}")]
    NodeTooBig(u64, u64),

    #[error("Edge len:{0} is larger than the maximum authorised: {1}")]
    EdgeTooBig(usize, usize),

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
    InvalidPeerNode(String),

    #[error("Unknown Peer")]
    UnknownPeer(),

    #[error("{0}")]
    QueryParsing(String),

    #[error("An error occured while computing daily logs: {0}")]
    ComputeDailyLog(String),
}
#[cfg(test)]
mod tests {
    use crate::database::{node::Node, VEC_OVERHEAD};

    #[test]
    fn test_buffer_size() {
        let mut v = Vec::new();
        let node = Node {
            ..Default::default()
        };
        let node_size = bincode::serialized_size(&node).unwrap();
        println!("node: {}", node_size);
        v.push(node);

        let vec_size = bincode::serialized_size(&v).unwrap();
        println!("vec_: {}", vec_size);

        let capa = 2621440;
        let datav = vec![0; capa];

        let mut v = Vec::new();
        let mut size = 0;
        for i in 0..10 {
            let node = Node {
                _binary: Some(datav.clone()),
                _entity: i.to_string(),
                ..Default::default()
            };

            size += bincode::serialized_size(&node).unwrap();
            size += VEC_OVERHEAD;
            v.push(node);
        }
        println!("comp: {}", size);
        println!("repo: {}", bincode::serialized_size(&v).unwrap());
    }
}
