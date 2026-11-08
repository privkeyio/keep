// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use keep_core::error::KeepError;

pub type Result<T> = std::result::Result<T, KeepError>;

pub(crate) fn sanitize_error_for_client(e: &KeepError) -> &'static str {
    match e {
        KeepError::InvalidPassword => "Authentication failed",
        KeepError::RateLimited(_) => "Rate limited",
        KeepError::DecryptionFailed | KeepError::RotationFailed(_) => "Operation failed",
        KeepError::KeyNotFound(_) => "Key not found",
        KeepError::KeyAlreadyExists(_) => "Key already exists",
        KeepError::InvalidNsec | KeepError::InvalidNpub(_) => "Invalid key format",
        KeepError::KeyringFull(_) => "Storage limit reached",
        KeepError::Locked => "Signer locked",
        KeepError::AlreadyExists(_) | KeepError::NotFound(_) => "Resource error",
        KeepError::InvalidNetwork(_) => "Invalid network",
        KeepError::Encryption(_) | KeepError::Entropy(_) | KeepError::CryptoErr(_) => {
            "Cryptographic operation failed"
        }
        KeepError::Database(_)
        | KeepError::VaultAlreadyOpen(_)
        | KeepError::Migration(_)
        | KeepError::StorageErr(_) => "Storage error",
        KeepError::HomeNotFound | KeepError::Config(_) => "Configuration error",
        KeepError::CapacityExceeded(_) => "Capacity exceeded",
        KeepError::PermissionDenied(_) => "Permission denied",
        KeepError::UserRejected => "User rejected",
        KeepError::InvalidInput(m) if m == crate::handler::NIP98_AMBIGUOUS_TARGET => {
            crate::handler::NIP98_AMBIGUOUS_TARGET
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::NIP98_AMBIGUOUS_TARGET;

    #[test]
    fn only_the_fixed_nip98_refusal_reaches_the_client_verbatim() {
        let fixed = KeepError::InvalidInput(NIP98_AMBIGUOUS_TARGET.into());
        assert_eq!(sanitize_error_for_client(&fixed), NIP98_AMBIGUOUS_TARGET);
        let other = KeepError::InvalidInput("attacker text".into());
        assert_eq!(sanitize_error_for_client(&other), "Invalid input");
    }
}
