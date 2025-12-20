#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EnclaveError {
    #[error("Vsock error: {0}")]
    Vsock(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("NSM error: {0}")]
    Nsm(String),

    #[error("FROST error: {0}")]
    Frost(String),

    #[error("KMS error: {0}")]
    Kms(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, EnclaveError>;
