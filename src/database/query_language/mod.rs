pub mod data_model;
pub mod deletion;
pub mod mutation;
pub mod parameter;
pub mod query;

use std::fmt;

use thiserror::Error;

#[derive(Debug)]
pub enum FieldValue {
    Variable(String),
    Value(Value),
}

#[derive(Debug)]
pub enum Value {
    Boolean(bool),
    Integer(i64),
    Float(f64),
    String(String),
    Null,
}

#[derive(Debug, PartialEq, Eq)]
pub enum VariableType {
    Boolean(bool),
    Float(bool),
    Hex(bool),
    Integer(bool),
    String(bool),
}
impl fmt::Display for VariableType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone)]
pub enum FieldType {
    Array(String),
    Entity(String),
    Boolean,
    Float,
    Hex,
    Integer,
    String,
}
impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    ParserError(String),

    #[error("{0}")]
    InvalidQuery(String),

    #[error("'{0}' is allready defined as a '{1}' and is conflicting with a field that requires an '{2}' ")]
    ConflictingVariableType(String, String, String),

    #[error("Field {0} requires type '{1}' and is used with type '{2}' ")]
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

    #[error(transparent)]
    ParseBoolError(#[from] std::str::ParseBoolError),

    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error(transparent)]
    ParseFloatError(#[from] std::num::ParseFloatError),

    #[error("{0}")]
    MissingParameter(String),

    #[error("'{0}' is not an hexadecimal value")]
    InvalidHex(String),

    #[error("Parameter '{0}' is not a {1}. Value:{2}")]
    ConflictingParameterType(String, String, String),
}
