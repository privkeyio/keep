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

    #[error("FROST error: {0}")]
    Frost(String),

    #[error("Invalid network: {0}")]
    InvalidNetwork(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("Home directory not found")]
    HomeNotFound,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl From<redb::DatabaseError> for KeepError {
    fn from(e: redb::DatabaseError) -> Self {
        KeepError::Database(e.to_string())
    }
}

impl From<redb::TransactionError> for KeepError {
    fn from(e: redb::TransactionError) -> Self {
        KeepError::Database(e.to_string())
    }
}

impl From<redb::TableError> for KeepError {
    fn from(e: redb::TableError) -> Self {
        KeepError::Database(e.to_string())
    }
}

impl From<redb::StorageError> for KeepError {
    fn from(e: redb::StorageError) -> Self {
        KeepError::Database(e.to_string())
    }
}

impl From<redb::CommitError> for KeepError {
    fn from(e: redb::CommitError) -> Self {
        KeepError::Database(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, KeepError>;
