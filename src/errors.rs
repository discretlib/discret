use std::net::IpAddr;
use thiserror::Error;
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("No Vault defined for this pass phase")]
    VaultDontExists,
    #[error("A Vault allready exists for this pass phase")]
    VaultAllreadyExists,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid KeyPair")]
    InvalidKeyPair,
    #[error("Invalid Public Key")]
    InvalidPublicKey,

    #[error("{0} is not a multicast adress")]
    InvalidMulticastAdress(IpAddr),

    #[error("unknown vaulterror")]
    Unknown,
}
