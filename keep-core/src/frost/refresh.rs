// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use frost::keys::refresh::{compute_refreshing_shares, refresh_share};
use frost::keys::{KeyPackage, PublicKeyPackage, SecretShare};
use frost::rand_core::OsRng;
use frost::Identifier;
use frost_secp256k1_tr as frost;

use crate::error::{KeepError, Result};

use super::share::{ShareMetadata, SharePackage};

/// Refresh all shares, producing new shares for the same group public key.
pub fn refresh_shares(
    shares: &[SharePackage],
) -> Result<(Vec<SharePackage>, PublicKeyPackage)> {
    if shares.is_empty() {
        return Err(KeepError::Frost("No shares provided".into()));
    }

    let threshold = shares[0].metadata.threshold;
    let total = shares[0].metadata.total_shares;
    let name = shares[0].metadata.name.clone();

    if (shares.len() as u16) < threshold {
        return Err(KeepError::Frost(format!(
            "Need at least {} shares to refresh, only {} available",
            threshold,
            shares.len()
        )));
    }
    let group_pubkey = *shares[0].group_pubkey();
    let pubkey_pkg = shares[0].pubkey_package()?;

    let key_packages: Vec<KeyPackage> = shares
        .iter()
        .map(|s| s.key_package())
        .collect::<Result<_>>()?;

    let identifiers: Vec<Identifier> = key_packages.iter().map(|kp| *kp.identifier()).collect();

    let (refreshing_shares, new_pubkey_pkg) =
        compute_refreshing_shares::<frost::Secp256K1Sha256TR, _>(
            pubkey_pkg,
            total,
            threshold,
            &identifiers,
            &mut OsRng,
        )
        .map_err(|e| KeepError::Frost(format!("Compute refreshing shares failed: {}", e)))?;

    let mut new_packages = Vec::with_capacity(shares.len());

    for ((share, current_kp), refreshing_share) in shares
        .iter()
        .zip(&key_packages)
        .zip(refreshing_shares)
    {
        let new_kp = refresh_share::<frost::Secp256K1Sha256TR>(refreshing_share, current_kp)
            .map_err(|e| KeepError::Frost(format!("Refresh share failed: {}", e)))?;

        let mut metadata = ShareMetadata::new(
            share.metadata.identifier,
            threshold,
            total,
            group_pubkey,
            name.clone(),
        );
        metadata.created_at = share.metadata.created_at;

        new_packages.push(SharePackage::new(metadata, &new_kp, &new_pubkey_pkg)?);
    }

    Ok((new_packages, new_pubkey_pkg))
}

/// Refresh a single share given a refreshing share from the trusted dealer.
pub fn refresh_single_share(
    share: &SharePackage,
    refreshing_share: SecretShare,
    new_pubkey_pkg: &PublicKeyPackage,
) -> Result<SharePackage> {
    let current_kp = share.key_package()?;

    let new_kp = refresh_share::<frost::Secp256K1Sha256TR>(refreshing_share, &current_kp)
        .map_err(|e| KeepError::Frost(format!("Refresh share failed: {}", e)))?;

    let metadata = ShareMetadata::new(
        share.metadata.identifier,
        share.metadata.threshold,
        share.metadata.total_shares,
        *share.group_pubkey(),
        share.metadata.name.clone(),
    );

    SharePackage::new(metadata, &new_kp, new_pubkey_pkg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{sign_with_local_shares, ThresholdConfig, TrustedDealer};

    #[test]
    fn test_refresh_shares_preserves_group_key() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let original_group_pubkey = *shares[0].group_pubkey();

        let (refreshed, _) = refresh_shares(&shares).unwrap();

        assert_eq!(refreshed.len(), 3);
        for share in &refreshed {
            assert_eq!(*share.group_pubkey(), original_group_pubkey);
            assert_eq!(share.metadata.threshold, 2);
            assert_eq!(share.metadata.total_shares, 3);
        }
    }

    #[test]
    fn test_refreshed_shares_can_sign() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let (refreshed, _) = refresh_shares(&shares).unwrap();

        let message = b"test message after refresh";
        let sig = sign_with_local_shares(&refreshed, message).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_old_shares_incompatible_with_new() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let (refreshed, _) = refresh_shares(&shares).unwrap();

        let old_kp = shares[0].key_package().unwrap();
        let new_kp = refreshed[0].key_package().unwrap();
        assert_ne!(
            old_kp.signing_share().serialize(),
            new_kp.signing_share().serialize()
        );
    }

    #[test]
    fn test_multiple_refreshes() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let original_pubkey = *shares[0].group_pubkey();

        let (refreshed1, _) = refresh_shares(&shares).unwrap();
        let (refreshed2, _) = refresh_shares(&refreshed1).unwrap();

        assert_eq!(*refreshed2[0].group_pubkey(), original_pubkey);

        let message = b"after double refresh";
        let sig = sign_with_local_shares(&refreshed2, message).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_refresh_empty_shares_fails() {
        let result = refresh_shares(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_refresh_three_of_five() {
        let config = ThresholdConfig::three_of_five();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test-3of5").unwrap();

        let original_pubkey = *shares[0].group_pubkey();
        let (refreshed, _) = refresh_shares(&shares).unwrap();

        assert_eq!(refreshed.len(), 5);
        assert_eq!(*refreshed[0].group_pubkey(), original_pubkey);

        let message = b"3-of-5 refresh test";
        let sig = sign_with_local_shares(&refreshed, message).unwrap();
        assert_eq!(sig.len(), 64);
    }
}
