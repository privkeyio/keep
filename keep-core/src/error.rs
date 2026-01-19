// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error types for keep-core operations.

#![forbid(unsafe_code)]

use thiserror::Error;

/// Errors that can occur during Keep operations.
#[derive(Error, Debug)]
pub enum KeepError {
    /// The provided password is incorrect.
    #[error("Invalid password")]
    InvalidPassword,

    /// Too many failed authentication attempts. Contains seconds until retry.
    #[error("Rate limited: try again in {0} seconds")]
    RateLimited(u64),

    /// Encryption operation failed.
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption failed due to wrong password or corrupted data.
    #[error("Decryption failed - wrong password or corrupted data")]
    DecryptionFailed,

    /// The requested key was not found in storage.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// A key with this identifier already exists.
    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),

    /// The provided nsec string is malformed.
    #[error("Invalid nsec format")]
    InvalidNsec,

    /// The provided npub string is malformed.
    #[error("Invalid npub format")]
    InvalidNpub,

    /// The keyring has reached its maximum capacity.
    #[error("Keyring full (max {0} keys)")]
    KeyringFull(usize),

    /// Operation requires the Keep to be unlocked first.
    #[error("Keep is locked")]
    Locked,

    /// A Keep already exists at the specified path.
    #[error("Keep already exists at {0}")]
    AlreadyExists(String),

    /// No Keep found at the specified path.
    #[error("Keep not found at {0}")]
    NotFound(String),

    /// FROST threshold signature operation failed.
    #[error("FROST error: {0}")]
    Frost(String),

    /// The specified network is not supported.
    #[error("Invalid network: {0}")]
    InvalidNetwork(String),

    /// Database operation failed.
    #[error("Database error: {0}")]
    Database(String),

    /// Serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    /// Could not determine the user's home directory.
    #[error("Home directory not found")]
    HomeNotFound,

    /// File system I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic error for other failure modes.
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

/// A Result type alias for operations that can fail with [`KeepError`].
pub type Result<T> = std::result::Result<T, KeepError>;
