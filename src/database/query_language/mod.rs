pub mod data_model;
pub mod deletion;
pub mod mutation;
pub mod parameter;
pub mod query;

use std::fmt;

use serde_json::Number;
use thiserror::Error;

#[derive(Debug)]
pub enum FieldValue {
    Variable(String),
    Value(Value),
}

#[derive(Debug, Clone)]
pub enum Value {
    Boolean(bool),
    Integer(i64),
    Float(f64),
    String(String),
    Null,
}
impl Value {
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
        if let Self::String(e) = self {
            Some(e)
        } else {
            None
        }
    }

    pub fn as_serde_json_value(&self) -> Result<serde_json::Value, Error> {
        match self {
            Value::Boolean(v) => Ok(serde_json::Value::Bool(*v)),
            Value::Integer(v) => Ok(serde_json::Value::Number(Number::from(*v))),
            Value::Float(v) => {
                let number = Number::from_f64(*v);
                match number {
                    Some(e) => Ok(serde_json::Value::Number(e)),
                    None => Err(Error::InvalidFloat(*v)),
                }
            }
            Value::String(v) => Ok(serde_json::Value::String(String::from(v))),
            Value::Null => Ok(serde_json::Value::Null),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VariableType {
    Boolean(bool),
    Float(bool),
    Base64(bool),
    Integer(bool),
    String(bool),
}
impl fmt::Display for VariableType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    Array(String),
    Entity(String),
    Boolean,
    Float,
    Base64,
    Integer,
    String,
}
impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// #[derive(Debug)]
// pub struct ParsingError {
//     start: usize,
//     end: usize,
//     fragment: String,
//     msg: String,
// }
// impl ParsingError {
//     pub fn pest_parsing_error(msg: String) -> Self {
//         Self {
//             start: 0,
//             end: 0,
//             fragment: "".to_string(),
//             msg,
//         }
//     }

//     pub fn conflicting_variable_type(
//         defined_type: &VariableType,
//         new_type: &VariableType,
//         fragment: String,
//         start: usize,
//         end: usize,
//     ) -> Self {
//         let msg = format!(
//             "allready defined as a '{}' and is conflicting with a field that requires '{}'",
//             defined_type, new_type
//         );
//         Self {
//             start,
//             end,
//             fragment,
//             msg,
//         }
//     }
// }

// impl fmt::Display for ParsingError {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         if self.start == 0 {
//             write!(f, "{}", self.fragment)
//         } else {
//             write!(
//                 f,
//                 "'{}' {}. Position: {}-{}",
//                 self.fragment, self.msg, self.start, self.end
//             )
//         }
//     }
// }

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

    #[error("Entity {0} is missing in the new data model")]
    MissingEntity(String),

    #[error("Field {0}.{1} is missing in the new data model")]
    MissingField(String, String),

    #[error("New field definition {0}.{1} is not nullable and needs a default value to ensure backward compatibility")]
    MissingDefaultValue(String, String),

    #[error("New field definition {0}.{1} is is tring to change the field type. old type:{2} new type:{3}")]
    CannotUpdateFieldType(String, String, String, String),

    #[error(transparent)]
    BoolParsingError(#[from] std::str::ParseBoolError),

    #[error(transparent)]
    IntParsingError(#[from] std::num::ParseIntError),

    #[error(transparent)]
    FloatParsingError(#[from] std::num::ParseFloatError),

    #[error("{0}")]
    MissingParameter(String),

    #[error("'{0}' is not a base64 value")]
    InvalidBase64(String),

    #[error("'{0}' is not a {1}. value:{2}")]
    ConflictingParameterType(String, String, String),

    #[error("field {0} default value is a '{1}' is not a {2}")]
    InvalidDefaultValue(String, String, String),

    #[error("float {0} is not a valid JSON float")]
    InvalidFloat(f64),

    #[error("name {0} cannot start with '_'. Names starting with '_' are reserved for the system")]
    InvalidName(String),

    #[error(
        "{0}.{1} is required to create the entity. It is not nullable and has no default value"
    )]
    MissingUpdateField(String, String),
}
