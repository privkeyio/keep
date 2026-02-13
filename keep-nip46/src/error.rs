// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use keep_core::error::KeepError;

pub type Result<T> = std::result::Result<T, KeepError>;

pub(crate) fn sanitize_error_for_client(e: &KeepError) -> &'static str {
    match e {
        KeepError::InvalidPassword => "Authentication failed",
        KeepError::RateLimited(_) => "Rate limited",
        KeepError::DecryptionFailed | KeepError::RotationFailed(_) => "Operation failed",
        KeepError::KeyNotFound(_) => "Key not found",
        KeepError::KeyAlreadyExists(_) => "Key already exists",
        KeepError::InvalidNsec | KeepError::InvalidNpub => "Invalid key format",
        KeepError::KeyringFull(_) => "Storage limit reached",
        KeepError::Locked => "Signer locked",
        KeepError::AlreadyExists(_) | KeepError::NotFound(_) => "Resource error",
        KeepError::InvalidNetwork(_) => "Invalid network",
        KeepError::Encryption(_) | KeepError::CryptoErr(_) => "Cryptographic operation failed",
        KeepError::Database(_) | KeepError::Migration(_) | KeepError::StorageErr(_) => {
            "Storage error"
        }
        KeepError::HomeNotFound | KeepError::Config(_) => "Configuration error",
        KeepError::CapacityExceeded(_) => "Capacity exceeded",
        KeepError::PermissionDenied(_) => "Permission denied",
        KeepError::UserRejected => "User rejected",
        KeepError::InvalidInput(_) => "Invalid input",
        KeepError::NotImplemented(_) => "Not supported",
        KeepError::Runtime(_) => "Internal error",
        KeepError::Frost(_) | KeepError::FrostErr(_) => "Signing protocol error",
        KeepError::NetworkErr(_) => "Network error",
        KeepError::Serialization(_) => "Data format error",
        KeepError::Io(_) => "IO error",
        _ => "Unknown error",
    }
}
