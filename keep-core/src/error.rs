// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error types for keep-core operations.

#![forbid(unsafe_code)]

use thiserror::Error;

/// Machine-readable error codes for programmatic handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum ErrorCode {
    E1001,
    E1002,
    E1003,
    E1004,
    E1005,
    E1006,
    E1007,
    E1008,
    E1009,
    E1010,
    E2001,
    E2002,
    E2003,
    E2004,
    E2005,
    E2006,
    E3001,
    E3002,
    E3003,
    E3004,
    E3005,
    E3006,
    E3007,
    E3008,
    E3009,
    E4001,
    E4002,
    E4003,
    E4004,
    E4005,
    E4006,
    E4007,
    E4008,
    E4009,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Storage operation errors.
#[derive(Error, Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum StorageError {
    #[error("[{code}] File not found: {path}")]
    FileNotFound { code: ErrorCode, path: String },
    #[error("[{code}] File already exists: {path}")]
    FileAlreadyExists { code: ErrorCode, path: String },
    #[error("[{code}] Permission denied: {path}")]
    PermissionDenied { code: ErrorCode, path: String },
    #[error("[{code}] Invalid file format: {reason}")]
    InvalidFormat { code: ErrorCode, reason: String },
    #[error("[{code}] Database error: {message}")]
    Database { code: ErrorCode, message: String },
    #[error("[{code}] IO error: {message}")]
    Io { code: ErrorCode, message: String },
    #[error("[{code}] Home directory not found")]
    HomeNotFound { code: ErrorCode },
    #[error("[{code}] Migration failed: {message}")]
    Migration { code: ErrorCode, message: String },
    #[error("[{code}] Serialization failed: {message}")]
    Serialization { code: ErrorCode, message: String },
    #[error("[{code}] Hidden volume full")]
    HiddenVolumeFull { code: ErrorCode },
}

#[allow(missing_docs)]
impl StorageError {
    pub fn file_not_found(path: impl Into<String>) -> Self {
        Self::FileNotFound {
            code: ErrorCode::E1001,
            path: path.into(),
        }
    }

    pub fn file_already_exists(path: impl Into<String>) -> Self {
        Self::FileAlreadyExists {
            code: ErrorCode::E1002,
            path: path.into(),
        }
    }

    pub fn permission_denied(path: impl Into<String>) -> Self {
        Self::PermissionDenied {
            code: ErrorCode::E1003,
            path: path.into(),
        }
    }

    pub fn invalid_format(reason: impl Into<String>) -> Self {
        Self::InvalidFormat {
            code: ErrorCode::E1004,
            reason: reason.into(),
        }
    }

    pub fn corrupted(message: impl Into<String>) -> Self {
        Self::invalid_format(message)
    }

    pub fn database(message: impl Into<String>) -> Self {
        Self::Database {
            code: ErrorCode::E1005,
            message: message.into(),
        }
    }

    pub fn io(message: impl Into<String>) -> Self {
        Self::Io {
            code: ErrorCode::E1006,
            message: message.into(),
        }
    }

    pub fn home_not_found() -> Self {
        Self::HomeNotFound {
            code: ErrorCode::E1007,
        }
    }

    pub fn migration(message: impl Into<String>) -> Self {
        Self::Migration {
            code: ErrorCode::E1008,
            message: message.into(),
        }
    }

    pub fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization {
            code: ErrorCode::E1009,
            message: message.into(),
        }
    }

    pub fn hidden_volume_full() -> Self {
        Self::HiddenVolumeFull {
            code: ErrorCode::E1010,
        }
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            Self::FileNotFound { code, .. }
            | Self::FileAlreadyExists { code, .. }
            | Self::PermissionDenied { code, .. }
            | Self::InvalidFormat { code, .. }
            | Self::Database { code, .. }
            | Self::Io { code, .. }
            | Self::HomeNotFound { code }
            | Self::Migration { code, .. }
            | Self::Serialization { code, .. }
            | Self::HiddenVolumeFull { code } => *code,
        }
    }
}

/// Cryptographic operation errors.
#[derive(Error, Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum CryptoError {
    #[error("[{code}] Encryption failed: {message}")]
    Encryption { code: ErrorCode, message: String },
    #[error("[{code}] Decryption failed: {message}")]
    Decryption { code: ErrorCode, message: String },
    #[error("[{code}] Invalid key: {message}")]
    InvalidKey { code: ErrorCode, message: String },
    #[error("[{code}] Key derivation failed: {message}")]
    KeyDerivation { code: ErrorCode, message: String },
    #[error("[{code}] Signature verification failed: {message}")]
    SignatureVerification { code: ErrorCode, message: String },
    #[error("[{code}] Invalid signature: {message}")]
    InvalidSignature { code: ErrorCode, message: String },
}

#[allow(missing_docs)]
impl CryptoError {
    pub fn encryption(message: impl Into<String>) -> Self {
        Self::Encryption {
            code: ErrorCode::E2001,
            message: message.into(),
        }
    }

    pub fn decryption(message: impl Into<String>) -> Self {
        Self::Decryption {
            code: ErrorCode::E2002,
            message: message.into(),
        }
    }

    pub fn invalid_key(message: impl Into<String>) -> Self {
        Self::InvalidKey {
            code: ErrorCode::E2003,
            message: message.into(),
        }
    }

    pub fn key_derivation(message: impl Into<String>) -> Self {
        Self::KeyDerivation {
            code: ErrorCode::E2004,
            message: message.into(),
        }
    }

    pub fn kdf(message: impl Into<String>) -> Self {
        Self::key_derivation(message)
    }

    pub fn signature_verification(message: impl Into<String>) -> Self {
        Self::SignatureVerification {
            code: ErrorCode::E2005,
            message: message.into(),
        }
    }

    pub fn invalid_signature(message: impl Into<String>) -> Self {
        Self::InvalidSignature {
            code: ErrorCode::E2006,
            message: message.into(),
        }
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Encryption { code, .. }
            | Self::Decryption { code, .. }
            | Self::InvalidKey { code, .. }
            | Self::KeyDerivation { code, .. }
            | Self::SignatureVerification { code, .. }
            | Self::InvalidSignature { code, .. } => *code,
        }
    }
}

/// FROST protocol errors.
#[derive(Error, Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum FrostError {
    #[error("[{code}] Threshold not met: need {needed}, have {available}")]
    ThresholdNotMet {
        code: ErrorCode,
        needed: u16,
        available: u16,
    },
    #[error("[{code}] Invalid share: {message}")]
    InvalidShare { code: ErrorCode, message: String },
    #[error("[{code}] Session error: {message}")]
    Session { code: ErrorCode, message: String },
    #[error("[{code}] Commitment error: {message}")]
    Commitment { code: ErrorCode, message: String },
    #[error("[{code}] Signature aggregation failed: {message}")]
    Aggregation { code: ErrorCode, message: String },
    #[error("[{code}] Invalid configuration: {message}")]
    InvalidConfig { code: ErrorCode, message: String },
    #[error("[{code}] DKG failed: {message}")]
    Dkg { code: ErrorCode, message: String },
    #[error("[{code}] Duplicate participant: {identifier}")]
    DuplicateParticipant { code: ErrorCode, identifier: u16 },
    #[error("[{code}] Unknown participant: {identifier}")]
    UnknownParticipant { code: ErrorCode, identifier: u16 },
}

#[allow(missing_docs)]
impl FrostError {
    pub fn threshold_not_met(needed: u16, available: u16) -> Self {
        Self::ThresholdNotMet {
            code: ErrorCode::E3001,
            needed,
            available,
        }
    }

    pub fn invalid_share(message: impl Into<String>) -> Self {
        Self::InvalidShare {
            code: ErrorCode::E3002,
            message: message.into(),
        }
    }

    pub fn session(message: impl Into<String>) -> Self {
        Self::Session {
            code: ErrorCode::E3003,
            message: message.into(),
        }
    }

    pub fn commitment(message: impl Into<String>) -> Self {
        Self::Commitment {
            code: ErrorCode::E3004,
            message: message.into(),
        }
    }

    pub fn aggregation(message: impl Into<String>) -> Self {
        Self::Aggregation {
            code: ErrorCode::E3005,
            message: message.into(),
        }
    }

    pub fn invalid_config(message: impl Into<String>) -> Self {
        Self::InvalidConfig {
            code: ErrorCode::E3006,
            message: message.into(),
        }
    }

    pub fn dkg(message: impl Into<String>) -> Self {
        Self::Dkg {
            code: ErrorCode::E3007,
            message: message.into(),
        }
    }

    pub fn duplicate_participant(identifier: u16) -> Self {
        Self::DuplicateParticipant {
            code: ErrorCode::E3008,
            identifier,
        }
    }

    pub fn unknown_participant(identifier: u16) -> Self {
        Self::UnknownParticipant {
            code: ErrorCode::E3009,
            identifier,
        }
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            Self::ThresholdNotMet { code, .. }
            | Self::InvalidShare { code, .. }
            | Self::Session { code, .. }
            | Self::Commitment { code, .. }
            | Self::Aggregation { code, .. }
            | Self::InvalidConfig { code, .. }
            | Self::Dkg { code, .. }
            | Self::DuplicateParticipant { code, .. }
            | Self::UnknownParticipant { code, .. } => *code,
        }
    }
}

/// Network operation errors.
#[derive(Error, Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum NetworkError {
    #[error("[{code}] Connection failed: {message}")]
    Connection { code: ErrorCode, message: String },
    #[error("[{code}] Relay error: {message}")]
    Relay { code: ErrorCode, message: String },
    #[error("[{code}] Request failed: {message}")]
    Request { code: ErrorCode, message: String },
    #[error("[{code}] Response error: {message}")]
    Response { code: ErrorCode, message: String },
    #[error("[{code}] Timeout: {message}")]
    Timeout { code: ErrorCode, message: String },
    #[error("[{code}] Attestation failed: {message}")]
    Attestation { code: ErrorCode, message: String },
    #[error("[{code}] Subscribe failed: {message}")]
    Subscribe { code: ErrorCode, message: String },
    #[error("[{code}] Publish failed: {message}")]
    Publish { code: ErrorCode, message: String },
    #[error("[{code}] Warden error: {message}")]
    Warden { code: ErrorCode, message: String },
}

#[allow(missing_docs)]
impl NetworkError {
    pub fn connection(message: impl Into<String>) -> Self {
        Self::Connection {
            code: ErrorCode::E4001,
            message: message.into(),
        }
    }

    pub fn relay(message: impl Into<String>) -> Self {
        Self::Relay {
            code: ErrorCode::E4002,
            message: message.into(),
        }
    }

    pub fn request(message: impl Into<String>) -> Self {
        Self::Request {
            code: ErrorCode::E4003,
            message: message.into(),
        }
    }

    pub fn response(message: impl Into<String>) -> Self {
        Self::Response {
            code: ErrorCode::E4004,
            message: message.into(),
        }
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Self::Timeout {
            code: ErrorCode::E4005,
            message: message.into(),
        }
    }

    pub fn attestation(message: impl Into<String>) -> Self {
        Self::Attestation {
            code: ErrorCode::E4006,
            message: message.into(),
        }
    }

    pub fn subscribe(message: impl Into<String>) -> Self {
        Self::Subscribe {
            code: ErrorCode::E4007,
            message: message.into(),
        }
    }

    pub fn publish(message: impl Into<String>) -> Self {
        Self::Publish {
            code: ErrorCode::E4008,
            message: message.into(),
        }
    }

    pub fn warden(message: impl Into<String>) -> Self {
        Self::Warden {
            code: ErrorCode::E4009,
            message: message.into(),
        }
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Connection { code, .. }
            | Self::Relay { code, .. }
            | Self::Request { code, .. }
            | Self::Response { code, .. }
            | Self::Timeout { code, .. }
            | Self::Attestation { code, .. }
            | Self::Subscribe { code, .. }
            | Self::Publish { code, .. }
            | Self::Warden { code, .. } => *code,
        }
    }
}

/// Keep operation errors.
#[derive(Error, Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum KeepError {
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Rate limited: try again in {0} seconds")]
    RateLimited(u64),
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
    #[error("Invalid network: {0}")]
    InvalidNetwork(String),
    #[error("Rotation failed: {0}")]
    RotationFailed(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Migration error: {0}")]
    Migration(String),
    #[error("Home directory not found")]
    HomeNotFound,
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("User rejected operation")]
    UserRejected,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    #[error("Runtime error: {0}")]
    Runtime(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("FROST error: {0}")]
    Frost(String),
    #[error(transparent)]
    StorageErr(#[from] StorageError),
    #[error(transparent)]
    CryptoErr(#[from] CryptoError),
    #[error(transparent)]
    FrostErr(#[from] FrostError),
    #[error(transparent)]
    NetworkErr(#[from] NetworkError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

#[allow(missing_docs)]
impl KeepError {
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::StorageErr(e) => Some(e.code()),
            Self::CryptoErr(e) => Some(e.code()),
            Self::FrostErr(e) => Some(e.code()),
            Self::NetworkErr(e) => Some(e.code()),
            _ => None,
        }
    }

    pub fn permission_denied(msg: impl Into<String>) -> Self {
        Self::PermissionDenied(msg.into())
    }

    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }

    pub fn not_implemented(msg: impl Into<String>) -> Self {
        Self::NotImplemented(msg.into())
    }

    pub fn runtime(msg: impl Into<String>) -> Self {
        Self::Runtime(msg.into())
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
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

/// Result type alias for Keep operations.
pub type Result<T> = std::result::Result<T, KeepError>;
