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

#[derive(Debug, Clone, PartialEq, Eq)]
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

    #[error(transparent)]
    BoolParsingError(#[from] std::str::ParseBoolError),

    #[error(transparent)]
    IntParsingError(#[from] std::num::ParseIntError),

    #[error(transparent)]
    FloatParsingError(#[from] std::num::ParseFloatError),

    #[error("{0}")]
    MissingParameter(String),

    #[error("'{0}' is not an hexadecimal value")]
    InvalidHex(String),

    #[error("'{0}' is not a {1}. value:{2}")]
    ConflictingParameterType(String, String, String),

    #[error("field {0} default value is a '{1}' is not a {2}")]
    InvalidDefaultValue(String, String, String),
}
