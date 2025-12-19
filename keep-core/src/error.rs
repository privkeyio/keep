#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeepError {
    #[error("Invalid password")]
    InvalidPassword,

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption failed - wrong password or corrupted data")]
    DecryptionFailed,

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),

    #[error("Invalid nsec format")]
    InvalidNsec,

    #[error("Invalid npub format")]
    InvalidNpub,

    #[error("Keyring full (max {0} keys)")]
    KeyringFull(usize),

    #[error("Keep is locked")]
    Locked,

    #[error("Keep already exists at {0}")]
    AlreadyExists(String),

    #[error("Keep not found at {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, KeepError>;
