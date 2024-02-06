pub mod data_model;
pub mod deletion;
pub mod mutation;
pub mod query;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    ParserError(String),
}
