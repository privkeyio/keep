use thiserror::Error;

#[derive(Error, Debug)]
pub enum EnclaveError {
    #[error("Enclave connection failed: {0}")]
    Connection(String),

    #[error("Vsock error: {0}")]
    Vsock(String),

    #[error("Attestation verification failed: {0}")]
    Attestation(String),

    #[error("PCR mismatch: PCR{pcr} expected {expected}, got {actual}")]
    PcrMismatch {
        pcr: u32,
        expected: String,
        actual: String,
    },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Not in enclave environment")]
    NotInEnclave,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, EnclaveError>;
