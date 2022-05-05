use thiserror::Error;
#[derive(Error, Debug)]
pub enum Error {
    #[error("No Vault defined for this pass phase")]
    InvalidAccount,
    #[error("A Vault allready exists for this pass phase")]
    AccountExists,

    #[error(transparent)]
    CryptoError(#[from] crate::cryptography::Error),

    #[error(transparent)]
    DatabaseError(#[from] rusqlite::Error),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    NetworkError(#[from] crate::network::error::Error),

    #[error("{0}")]
    Unknown(String),
}
