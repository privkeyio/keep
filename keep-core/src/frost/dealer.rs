#![forbid(unsafe_code)]

use frost::keys::{IdentifierList, KeyPackage, PublicKeyPackage};
use frost::rand_core::OsRng;
use frost_secp256k1_tr as frost;

use crate::error::{KeepError, Result};

use super::share::{ShareMetadata, SharePackage};

#[derive(Clone, Copy)]
pub struct ThresholdConfig {
    pub threshold: u16,
    pub total_shares: u16,
}

impl ThresholdConfig {
    pub fn new(threshold: u16, total_shares: u16) -> Result<Self> {
        if threshold < 2 {
            return Err(KeepError::Frost("Threshold must be at least 2".into()));
        }
        if total_shares < threshold {
            return Err(KeepError::Frost("Total shares must be >= threshold".into()));
        }
        if total_shares > 255 {
            return Err(KeepError::Frost("Maximum 255 shares supported".into()));
        }

        Ok(Self {
            threshold,
            total_shares,
        })
    }

    pub fn two_of_three() -> Self {
        Self {
            threshold: 2,
            total_shares: 3,
        }
    }

    pub fn three_of_five() -> Self {
        Self {
            threshold: 3,
            total_shares: 5,
        }
    }
}

/// **WARNING: Testing/development only. Do not use in production.**
///
/// The trusted dealer approach generates the full private key on a single machine during
/// key generation, which creates a single point of compromise. If that machine is breached
/// during generation, all funds are at risk.
///
/// For production use, use distributed key generation (`keep frost network dkg`) where each
/// participant contributes entropy independently and the full private key is never computed
/// or exists on any single device.
pub struct TrustedDealer {
    config: ThresholdConfig,
}

impl TrustedDealer {
    pub fn new(config: ThresholdConfig) -> Self {
        Self { config }
    }

    pub fn generate(&self, name: &str) -> Result<(Vec<SharePackage>, PublicKeyPackage)> {
        let (shares, pubkey_pkg) = frost::keys::generate_with_dealer(
            self.config.total_shares,
            self.config.threshold,
            IdentifierList::Default,
            OsRng,
        )
        .map_err(|e| KeepError::Frost(format!("Key generation failed: {}", e)))?;

        let group_pubkey = extract_group_pubkey(&pubkey_pkg)?;

        let packages: Result<Vec<SharePackage>> = shares
            .into_iter()
            .enumerate()
            .map(|(idx, (_, secret_share))| {
                let key_package = KeyPackage::try_from(secret_share).map_err(|e| {
                    KeepError::Frost(format!("KeyPackage conversion failed: {}", e))
                })?;

                let identifier = (idx + 1) as u16;

                let metadata = ShareMetadata::new(
                    identifier,
                    self.config.threshold,
                    self.config.total_shares,
                    group_pubkey,
                    name.to_string(),
                );

                SharePackage::new(metadata, &key_package, &pubkey_pkg)
            })
            .collect();

        Ok((packages?, pubkey_pkg))
    }

    pub fn split_existing(
        &self,
        secret: &[u8; 32],
        name: &str,
    ) -> Result<(Vec<SharePackage>, PublicKeyPackage)> {
        let signing_key = frost::SigningKey::deserialize(secret)
            .map_err(|e| KeepError::Frost(format!("Invalid signing key: {}", e)))?;

        let (shares, pubkey_pkg) = frost::keys::split(
            &signing_key,
            self.config.total_shares,
            self.config.threshold,
            IdentifierList::Default,
            &mut OsRng,
        )
        .map_err(|e| KeepError::Frost(format!("Key split failed: {}", e)))?;

        let group_pubkey = extract_group_pubkey(&pubkey_pkg)?;

        let packages: Result<Vec<SharePackage>> = shares
            .into_iter()
            .enumerate()
            .map(|(idx, (_, secret_share))| {
                let key_package = KeyPackage::try_from(secret_share).map_err(|e| {
                    KeepError::Frost(format!("KeyPackage conversion failed: {}", e))
                })?;

                let identifier = (idx + 1) as u16;

                let metadata = ShareMetadata::new(
                    identifier,
                    self.config.threshold,
                    self.config.total_shares,
                    group_pubkey,
                    name.to_string(),
                );

                SharePackage::new(metadata, &key_package, &pubkey_pkg)
            })
            .collect();

        Ok((packages?, pubkey_pkg))
    }
}

fn extract_group_pubkey(pubkey_pkg: &PublicKeyPackage) -> Result<[u8; 32]> {
    let verifying_key = pubkey_pkg.verifying_key();
    let serialized = verifying_key
        .serialize()
        .map_err(|e| KeepError::Frost(format!("Failed to serialize verifying key: {}", e)))?;
    let bytes = serialized.as_slice();

    let mut pubkey = [0u8; 32];
    if bytes.len() == 33 {
        pubkey.copy_from_slice(&bytes[1..33]);
    } else if bytes.len() == 32 {
        pubkey.copy_from_slice(&bytes[0..32]);
    } else {
        return Err(KeepError::Frost(format!(
            "Invalid group pubkey length: expected 32 or 33, got {}",
            bytes.len()
        )));
    }
    Ok(pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_two_of_three() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, pubkey_pkg) = dealer.generate("test").unwrap();

        assert_eq!(shares.len(), 3);
        for share in &shares {
            assert_eq!(share.metadata.threshold, 2);
            assert_eq!(share.metadata.total_shares, 3);
            assert_eq!(share.group_pubkey(), shares[0].group_pubkey());
        }

        let vk = pubkey_pkg.verifying_key();
        let vk_bytes = vk.serialize().unwrap();
        assert_eq!(vk_bytes.as_slice().len(), 33);
    }

    #[test]
    fn test_split_preserves_pubkey() {
        use crate::crypto::random_bytes;

        let secret: [u8; 32] = random_bytes();
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);

        let (shares, pubkey_pkg) = dealer.split_existing(&secret, "split").unwrap();

        let expected_pubkey = pubkey_pkg.verifying_key().serialize().unwrap();
        let expected_slice = expected_pubkey.as_slice();
        assert_eq!(expected_slice.len(), 33);

        let mut expected_bytes = [0u8; 32];
        expected_bytes.copy_from_slice(&expected_slice[1..33]);

        assert_eq!(shares[0].group_pubkey(), &expected_bytes);
    }

    #[test]
    fn test_invalid_config() {
        assert!(ThresholdConfig::new(1, 3).is_err());
        assert!(ThresholdConfig::new(3, 2).is_err());
        assert!(ThresholdConfig::new(2, 256).is_err());
    }
}
