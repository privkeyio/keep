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
    StorageError { message: String },

    #[error("Network error")]
    NetworkError { message: String },

    #[error("FROST error")]
    FrostError { message: String },

    #[error("Invalid share data")]
    InvalidShare { message: String },

    #[error("Too many pending requests")]
    TooManyPendingRequests,

    #[error("Request timed out")]
    Timeout,

    #[error("Invalid relay URL")]
    InvalidRelayUrl { message: String },

    #[error("Initialization failed")]
    InitializationFailed { message: String },

    #[error("Operation not supported")]
    NotSupported { message: String },

    #[error("Serialization error")]
    Serialization { message: String },

    #[error("Pubkey mismatch")]
    PubkeyMismatch,

    #[error("Rate limited")]
    RateLimited,

    #[error("Invalid timestamp")]
    InvalidTimestamp,
}

impl From<keep_frost_net::FrostNetError> for KeepMobileError {
    fn from(e: keep_frost_net::FrostNetError) -> Self {
        KeepMobileError::NetworkError {
            message: e.to_string(),
        }
    }
}

impl From<keep_core::error::KeepError> for KeepMobileError {
    fn from(e: keep_core::error::KeepError) -> Self {
        KeepMobileError::FrostError {
            message: e.to_string(),
        }
    }
}
