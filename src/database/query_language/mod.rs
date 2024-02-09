pub mod data_model;
pub mod deletion;
pub mod mutation;
pub mod parameter;
pub mod query;
use std::{collections::HashMap, fmt};

use rusqlite::ToSql;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    ParserError(String),

    #[error("{0}")]
    InvalidQuery(String),

    #[error("'{0}' is allready defined as a '{1}' and is conflicting with a field that requires an '{2}' ")]
    ConflictingVariableType(String, String, String),

    #[error("variable '{0}' is not nullable")]
    VariableNotNullable(String),

    #[error("{0}")]
    DuplicatedParameters(String),

    #[error("entity {0} is allready defined")]
    DuplicatedEntity(String),

    #[error("field {0} is allready defined")]
    DuplicatedField(String),

    #[error(transparent)]
    ParseBoolError(#[from] std::str::ParseBoolError),

    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error(transparent)]
    ParseFloatError(#[from] std::num::ParseFloatError),

    #[error("{0}")]
    MissingParameter(String),

    #[error("UID '{0}' is not an hexadecimal string")]
    InvalidUID(String),

    #[error("Parameter '{0}' is not a {1}. Value:{2:#?}")]
    ConflictingParameterType(String, String, String),
}
