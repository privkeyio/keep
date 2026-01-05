#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum FrostNetError {
    #[error("Attestation verification failed: {0}")]
    Attestation(String),

    #[error("PCR mismatch: PCR{pcr} expected {expected}, got {actual}")]
    PcrMismatch {
        pcr: u32,
        expected: String,
        actual: String,
    },

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Session error: {0}")]
    Session(String),

    #[error("Peer error: {0}")]
    Peer(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Not enough peers online: need {needed}, have {available}")]
    InsufficientPeers { needed: usize, available: usize },

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Untrusted peer: {0}")]
    UntrustedPeer(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Replay detected: {0}")]
    ReplayDetected(String),

    #[error("Nonce already consumed for session: {0}")]
    NonceConsumed(String),

    #[error("Rehydration limit exceeded: {used}/{max} for session {session_id}")]
    RehydrationLimitExceeded {
        session_id: String,
        used: u16,
        max: u16,
    },

    #[error("Keep error: {0}")]
    Keep(#[from] keep_core::error::KeepError),

    #[error("Nostr error: {0}")]
    Nostr(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, FrostNetError>;
