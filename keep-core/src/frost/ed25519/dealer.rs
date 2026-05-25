// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Trusted dealer key generation for FROST over Ed25519.
use frost::keys::{IdentifierList, KeyPackage, PublicKeyPackage};
use frost::rand_core::OsRng;
use frost_ed25519 as frost;

use crate::error::{KeepError, Result};
use crate::frost::share::{Ciphersuite, ShareMetadata, SharePackage};
use crate::frost::ThresholdConfig;

/// **WARNING: Testing/development only. Do not use in production.**
///
/// Generates the full private key on a single machine during key generation,
/// which creates a single point of compromise.
pub struct TrustedDealer {
    config: ThresholdConfig,
}

impl TrustedDealer {
    /// Create a new Ed25519 trusted dealer.
    pub fn new(config: ThresholdConfig) -> Self {
        Self { config }
    }

    /// The ciphersuite of shares produced by this dealer.
    pub const CIPHERSUITE: Ciphersuite = Ciphersuite::Ed25519;

    /// Generate a new threshold key and split into shares.
    pub fn generate(&self, name: &str) -> Result<(Vec<SharePackage>, PublicKeyPackage)> {
        let (shares, pubkey_pkg) = frost::keys::generate_with_dealer(
            self.config.total_shares,
            self.config.threshold,
            IdentifierList::Default,
            OsRng,
        )
        .map_err(|e| KeepError::Frost(format!("Key generation failed: {e}")))?;

        let group_pubkey = extract_group_pubkey(&pubkey_pkg)?;
        let pubkey_package_bytes = pubkey_pkg
            .serialize()
            .map_err(|e| KeepError::Frost(format!("Failed to serialize pubkey package: {e}")))?;

        let packages: Result<Vec<SharePackage>> = shares
            .into_iter()
            .map(|(_, secret_share)| {
                let key_package = KeyPackage::try_from(secret_share)
                    .map_err(|e| KeepError::Frost(format!("KeyPackage conversion failed: {e}")))?;
                let key_package_bytes = key_package.serialize().map_err(|e| {
                    KeepError::Frost(format!("Failed to serialize key package: {e}"))
                })?;

                let identifier = identifier_to_u16(key_package.identifier())?;

                let metadata = ShareMetadata::new(
                    identifier,
                    self.config.threshold,
                    self.config.total_shares,
                    group_pubkey,
                    name.to_string(),
                );

                Ok(SharePackage::from_bytes(
                    metadata,
                    key_package_bytes,
                    pubkey_package_bytes.clone(),
                ))
            })
            .collect();

        Ok((packages?, pubkey_pkg))
    }
}

fn identifier_to_u16(identifier: &frost::Identifier) -> Result<u16> {
    let bytes = identifier.serialize();
    if bytes.len() != 32 || bytes[2..].iter().any(|&b| b != 0) {
        return Err(KeepError::Frost(
            "FROST identifier does not fit in u16".into(),
        ));
    }
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn extract_group_pubkey(pubkey_pkg: &PublicKeyPackage) -> Result<[u8; 32]> {
    let verifying_key = pubkey_pkg.verifying_key();
    let serialized = verifying_key
        .serialize()
        .map_err(|e| KeepError::Frost(format!("Failed to serialize verifying key: {e}")))?;
    let bytes = serialized.as_slice();

    if bytes.len() != 32 {
        return Err(KeepError::Frost(format!(
            "Invalid Ed25519 group pubkey length: expected 32, got {}",
            bytes.len()
        )));
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(bytes);
    Ok(pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;
    use crate::frost::StoredShare;

    #[test]
    fn test_generate_two_of_three() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, pubkey_pkg) = dealer.generate("test").unwrap();

        assert_eq!(shares.len(), 3);
        for share in &shares {
            assert_eq!(share.metadata.threshold, 2);
            assert_eq!(share.group_pubkey(), shares[0].group_pubkey());
        }

        let vk_bytes = pubkey_pkg.verifying_key().serialize().unwrap();
        assert_eq!(vk_bytes.as_slice().len(), 32);
    }

    #[test]
    fn test_storage_roundtrip_binds_ciphersuite() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let key = SecretKey::generate().unwrap();

        let stored =
            StoredShare::encrypt_with_ciphersuite(&shares[0], Ciphersuite::Ed25519, &key).unwrap();
        assert_eq!(stored.ciphersuite, Ciphersuite::Ed25519);

        let restored = stored.decrypt(&key).unwrap();
        assert_eq!(restored.key_package_bytes(), shares[0].key_package_bytes());

        // Flipping the authenticated ciphersuite tag must break decryption.
        let mut tampered = stored.clone();
        tampered.ciphersuite = Ciphersuite::Secp256k1Tr;
        assert!(tampered.decrypt(&key).is_err());
    }
}
