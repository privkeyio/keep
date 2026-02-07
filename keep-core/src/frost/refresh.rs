// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frost::keys::refresh::{compute_refreshing_shares, refresh_share};
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::rand_core::OsRng;
use frost::Identifier;
use frost_secp256k1_tr as frost;
use zeroize::Zeroize;

use crate::error::{KeepError, Result};

use super::share::{ShareMetadata, SharePackage};

fn rebuild_metadata(
    share: &SharePackage,
    threshold: u16,
    total: u16,
    group_pubkey: [u8; 32],
    name: String,
) -> ShareMetadata {
    let mut metadata = ShareMetadata::new(
        share.metadata.identifier,
        threshold,
        total,
        group_pubkey,
        name,
    );
    metadata.created_at = share.metadata.created_at;
    metadata.last_used = share.metadata.last_used;
    metadata.sign_count = share.metadata.sign_count;
    metadata
}

/// Refresh all shares, producing new shares for the same group public key.
pub fn refresh_shares(shares: &[SharePackage]) -> Result<(Vec<SharePackage>, PublicKeyPackage)> {
    if shares.is_empty() {
        return Err(KeepError::Frost("No shares provided".into()));
    }

    let threshold = shares[0].metadata.threshold;
    let total = shares[0].metadata.total_shares;
    let name = shares[0].metadata.name.clone();

    let group_pubkey = *shares[0].group_pubkey();

    for share in &shares[1..] {
        if *share.group_pubkey() != group_pubkey {
            return Err(KeepError::Frost(
                "All shares must belong to the same group".into(),
            ));
        }
        if share.metadata.threshold != threshold {
            return Err(KeepError::Frost(
                "Inconsistent threshold across shares".into(),
            ));
        }
        if share.metadata.total_shares != total {
            return Err(KeepError::Frost(
                "Inconsistent total_shares across shares".into(),
            ));
        }
    }

    let share_count: u16 = shares
        .len()
        .try_into()
        .map_err(|_| KeepError::Frost("Too many shares".into()))?;
    if share_count < threshold {
        return Err(KeepError::Frost(format!(
            "Need at least {} shares to refresh, only {} available",
            threshold, share_count
        )));
    }

    let pubkey_pkg = shares[0].pubkey_package()?;

    let mut key_packages: Vec<KeyPackage> = shares
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

    if refreshing_shares.len() != identifiers.len() {
        return Err(KeepError::Frost(format!(
            "Expected {} refreshing shares, got {}",
            identifiers.len(),
            refreshing_shares.len()
        )));
    }

    let refreshing_by_id: BTreeMap<Identifier, _> =
        identifiers.iter().copied().zip(refreshing_shares).collect();

    let mut new_packages = Vec::with_capacity(shares.len());

    for (share, current_kp) in shares.iter().zip(&key_packages) {
        let id = *current_kp.identifier();
        let refreshing_share = refreshing_by_id.get(&id).ok_or_else(|| {
            KeepError::Frost(format!("No refreshing share for identifier {:?}", id))
        })?;

        let new_kp =
            refresh_share::<frost::Secp256K1Sha256TR>(refreshing_share.clone(), current_kp)
                .map_err(|e| KeepError::Frost(format!("Refresh share failed: {}", e)))?;

        if new_kp.identifier() != &id {
            return Err(KeepError::Frost(
                "refreshing share identifier does not match target share".into(),
            ));
        }

        let metadata = rebuild_metadata(share, threshold, total, group_pubkey, name.clone());
        new_packages.push(SharePackage::new(metadata, &new_kp, &new_pubkey_pkg)?);
    }

    key_packages.iter_mut().for_each(|kp| kp.zeroize());

    let new_group_pubkey = *new_packages[0].group_pubkey();
    if new_group_pubkey != group_pubkey {
        return Err(KeepError::Frost(
            "Group public key changed after refresh - aborting".into(),
        ));
    }

    Ok((new_packages, new_pubkey_pkg))
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
