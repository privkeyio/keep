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
}

impl From<keep_frost_net::FrostNetError> for KeepMobileError {
    fn from(e: keep_frost_net::FrostNetError) -> Self {
        KeepMobileError::NetworkError { msg: e.to_string() }
    }
}

impl From<keep_core::error::KeepError> for KeepMobileError {
    fn from(e: keep_core::error::KeepError) -> Self {
        KeepMobileError::FrostError { msg: e.to_string() }
    }
}
