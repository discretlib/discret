use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("No Vault defined for this pass phase")]
    VaultDontExists,
    #[error("A Vault allready exists for this pass phase")]
    VaultAllreadyExists,
    #[error("unknown vaulterror")]
    Unknown,
}
