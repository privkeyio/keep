// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use thiserror::Error;

#[derive(Debug, Error, uniffi::Error)]
pub enum KeepMobileError {
    #[error("Not initialized - call initialize() first")]
    NotInitialized,

    #[error("Request not found")]
    RequestNotFound,

    #[error("Invalid session ID")]
    InvalidSession,

    #[error("Biometric authentication required")]
    BiometricRequired,

    #[error("Biometric authentication failed")]
    BiometricFailed,

    #[error("Storage error")]
    StorageError { msg: String },

    #[error("Key not found in storage")]
    StorageNotFound,

    #[error("Network error")]
    NetworkError { msg: String },

    #[error("FROST error")]
    FrostError { msg: String },

    #[error("Invalid share data")]
    InvalidShare { msg: String },

    #[error("Too many pending requests")]
    TooManyPendingRequests,

    #[error("Request timed out")]
    Timeout,

    #[error("Invalid relay URL")]
    InvalidRelayUrl { msg: String },

    #[error("Initialization failed")]
    InitializationFailed { msg: String },

    #[error("Operation not supported")]
    NotSupported { msg: String },

    #[error("Serialization error")]
    Serialization { msg: String },

    #[error("Pubkey mismatch")]
    PubkeyMismatch,

    #[error("Rate limited")]
    RateLimited,

    #[error("Invalid timestamp")]
    InvalidTimestamp,

    #[error("PSBT error")]
    PsbtError { msg: String },

    #[error("Policy violation: {reason}")]
    PolicyViolation { reason: String },

    #[error("Invalid policy bundle")]
    InvalidPolicy { msg: String },

    #[error("Policy signature verification failed")]
    PolicySignatureInvalid,

    #[error("Certificate pin mismatch")]
    CertificatePinMismatch {
        hostname: String,
        expected: String,
        actual: String,
    },
}

impl From<keep_frost_net::FrostNetError> for KeepMobileError {
    fn from(e: keep_frost_net::FrostNetError) -> Self {
        match e {
            keep_frost_net::FrostNetError::CertificatePinMismatch {
                hostname,
                expected,
                actual,
            } => KeepMobileError::CertificatePinMismatch {
                hostname,
                expected,
                actual,
            },
            keep_frost_net::FrostNetError::Timeout(_) => KeepMobileError::Timeout,
            other => KeepMobileError::NetworkError {
                msg: other.to_string(),
            },
        }
    }
}

impl From<keep_core::error::KeepError> for KeepMobileError {
    fn from(e: keep_core::error::KeepError) -> Self {
        KeepMobileError::FrostError { msg: e.to_string() }
    }
}
