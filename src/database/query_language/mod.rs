pub mod data_model_parser;
pub mod data_model_parser_test;
pub mod deletion_parser;
pub mod mutation_parser;
pub mod parameter;
pub mod query_parser;
pub mod query_parser_test;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Number;
use thiserror::Error;

#[derive(Debug, Clone)]
pub enum FieldValue {
    Variable(String),
    Value(ParamValue),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParamValue {
    Boolean(bool),
    Integer(i64),
    Float(f64),
    String(String),
    Binary(String),
    Null,
}
impl ParamValue {
    pub fn as_boolean(&self) -> Option<bool> {
        if let Self::Boolean(e) = self {
            Some(*e)
        } else {
            None
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Float(e) => Some(*e as i64),
            Self::Integer(e) => Some(*e),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Float(e) => Some(*e),
            Self::Integer(e) => Some(*e as f64),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&String> {
        match self {
            ParamValue::String(e) => Some(e),
            ParamValue::Binary(e) => Some(e),
            _ => None,
        }
    }

    pub fn as_serde_json_value(&self) -> Result<serde_json::Value, Error> {
        match self {
            ParamValue::Boolean(v) => Ok(serde_json::Value::Bool(*v)),
            ParamValue::Integer(v) => Ok(serde_json::Value::Number(Number::from(*v))),
            ParamValue::Float(v) => {
                let number = Number::from_f64(*v);
                match number {
                    Some(e) => Ok(serde_json::Value::Number(e)),
                    None => Err(Error::InvalidFloat(*v)),
                }
            }
            ParamValue::String(v) => Ok(serde_json::Value::String(String::from(v))),
            ParamValue::Binary(v) => Ok(serde_json::Value::String(String::from(v))),
            ParamValue::Null => Ok(serde_json::Value::Null),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VariableType {
    Boolean(bool),
    Float(bool),
    Base64(bool),
    Json(bool),
    Integer(bool),
    String(bool),
    Binary(bool),
    Invalid,
}
impl fmt::Display for VariableType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldType {
    Array(String),
    Entity(String),
    Boolean,
    Float,
    Base64,
    Integer,
    String,
    Json,
}
impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    BoolParsing(#[from] std::str::ParseBoolError),

    #[error(transparent)]
    IntParsing(#[from] std::num::ParseIntError),

    #[error(transparent)]
    TryfromInt(#[from] std::num::TryFromIntError),

    #[error("{0}")]
    Parser(String),

    #[error("{0}")]
    InvalidQuery(String),

    #[error("Namespace: '{0}' does not exists")]
    NamespaceNotFound(String),

    #[error("{0}")]
    NamespaceUpdate(String),

    #[error("Entity: '{0}' does not exists")]
    EntityNotFound(String),

    #[error("Index '{0}' allready exists in entity {1}.{2}")]
    IndexAllreadyExists(String, String, String),

    #[error("'{0}' is allready defined as a '{1}' and is conflicting with a field that requires an '{2}' ")]
    ConflictingVariableType(String, String, String),

    #[error("Field {0} requires type '{1}' and but is used with type '{2}' ")]
    InvalidFieldType(String, String, String),

    #[error("'{0}' is not nullable")]
    NotNullable(String),

    #[error("{0}")]
    DuplicatedParameters(String),

    #[error("entity {0} is allready defined")]
    DuplicatedEntity(String),

    #[error("field {0} is allready defined")]
    DuplicatedField(String),

    #[error("field {0} is conflicting with a system field, you have to change its name")]
    SystemFieldConflict(String),

    #[error("Namespace: '{0}' does not exists")]
    MissingNamespace(String),

    #[error("Entity {0} is missing in the new data model")]
    MissingEntity(String),

    #[error("Field {0}.{1} is missing in the new data model")]
    MissingField(String, String),

    #[error("New field definition {0}.{1} is not nullable and needs a default value to ensure backward compatibility")]
    MissingDefaultValue(String, String),

    #[error("New field definition {0}.{1} is is tring to change the field type. old type:{2} new type:{3}")]
    CannotUpdateFieldType(String, String, String, String),

    #[error("Field {0}.{1} is in postion {2} and was expected in position '{3}'")]
    InvalidFieldOrdering(String, String, usize, usize),

    #[error("Namespace {0} is in postion {1} and was expected in position '{2}'")]
    InvalidNamespaceOrdering(String, usize, usize),

    #[error("Entity {0} is in postion {1} and was expected in position '{2}'")]
    InvalidEntityOrdering(String, String, String),

    #[error(transparent)]
    FloatParsing(#[from] std::num::ParseFloatError),

    #[error("filter on entity {0} can only use operations 'is null' of 'is not null' ")]
    InvalidEntityFilter(String),

    #[error("Parameter: '{0}' is missing")]
    MissingParameter(String),

    #[error("'{0}' is not a base64 value")]
    InvalidBase64(String),

    #[error("'{0}' is not valid JSON value")]
    InvalidJson(String),

    #[error("'{0}' is not a {1}. value:{2}")]
    ConflictingParameterType(String, String, String),

    #[error("field {0} default value is a '{1}' is not a {2}")]
    InvalidDefaultValue(String, String, String),

    #[error("float {0} is not a valid JSON float")]
    InvalidFloat(f64),

    #[error("name {0} cannot start with '_'. Names starting with '_' are reserved for the system")]
    InvalidName(String),

    #[error(" '{0}' is a reserved keyword")]
    ReservedKeyword(String),

    #[error(
        "{0}.{1} is required to create the entity. It is not nullable and has no default value"
    )]
    MissingUpdateField(String, String),

    #[error("'after' and 'before' parameter number '{0}' must have the '{1}' type to match the order by fields")]
    InvalidPagingValue(usize, String),

    #[error("'after' and 'before' parameters cannot be used on aggregate queries")]
    InvalidPagingQuery(),

    #[error("Nullable field '{0}' not found in the query")]
    UnknownNullableField(String),

    #[error("Field '{0}' has the type '{1}' and nullable is only valid for types that references an entity ")]
    InvalidNullableField(String, String),

    #[error("the provided parameters could not be parsed in a valid JSON object")]
    InvalidJsonParamObject(),

    #[error("the provided parameters '{0}' cannot be an object or an array ")]
    InvalidJsonParamField(String),
}
