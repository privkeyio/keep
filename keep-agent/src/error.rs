#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgentError {
    #[error("Attestation verification failed: {0}")]
    Attestation(String),

    #[error("PCR mismatch: PCR{pcr} expected {expected}, got {actual}")]
    PcrMismatch {
        pcr: u32,
        expected: String,
        actual: String,
    },

    #[error("Attestation timestamp out of range: {0}")]
    AttestationTimestamp(String),

    #[error("Session expired")]
    SessionExpired,

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("Scope violation: {0}")]
    ScopeViolation(String),

    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    #[error("Amount exceeded: requested {requested} sats, limit {limit} sats")]
    AmountExceeded { requested: u64, limit: u64 },

    #[error("Address not allowed: {0}")]
    AddressNotAllowed(String),

    #[error("Event kind not allowed: {0}")]
    EventKindNotAllowed(u16),

    #[error("Operation not allowed: {0}")]
    OperationNotAllowed(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Invalid session token")]
    InvalidToken,

    #[error("Keep error: {0}")]
    Keep(#[from] keep_core::error::KeepError),

    #[error("Nostr error: {0}")]
    Nostr(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, AgentError>;
