// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
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
            "Need at least {threshold} shares to refresh, only {share_count} available"
        )));
    }

    let pubkey_pkg = shares[0].pubkey_package()?;
    let pubkey_pkg = PublicKeyPackage::new(
        pubkey_pkg.verifying_shares().clone(),
        *pubkey_pkg.verifying_key(),
        Some(threshold),
    );

    let mut key_packages: Vec<KeyPackage> = shares
        .iter()
        .map(|s| s.key_package())
        .collect::<Result<_>>()?;

    let identifiers: Vec<Identifier> = key_packages.iter().map(|kp| *kp.identifier()).collect();

    let (refreshing_shares, new_pubkey_pkg) =
        compute_refreshing_shares(pubkey_pkg, &identifiers, &mut OsRng)
            .map_err(|e| KeepError::Frost(format!("Compute refreshing shares failed: {e}")))?;

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
            KeepError::Frost(format!("No refreshing share for identifier {id:?}"))
        })?;

        let new_kp = refresh_share(refreshing_share.clone(), current_kp)
            .map_err(|e| KeepError::Frost(format!("Refresh share failed: {e}")))?;

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

    /// A pre-3.0 stored pubkey package decodes with `min_signers = None`, so
    /// refreshing a share loaded from disk must hit the `Some(threshold)`
    /// rebuild path before `compute_refreshing_shares`. Freshly
    /// dealt 3.0 packages already carry `Some`, so re-serialize each pubkey
    /// without `min_signers` to reproduce the legacy on-disk layout.
    #[test]
    fn test_refresh_with_legacy_pubkey_package() {
        use crate::frost::share::SharePackage;

        let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
        let (shares, _) = dealer.generate("legacy").unwrap();
        let group_pubkey = *shares[0].group_pubkey();

        let legacy: Vec<SharePackage> = shares
            .iter()
            .map(|s| {
                let pk = s.pubkey_package().unwrap();
                let old_pubkey =
                    PublicKeyPackage::new(pk.verifying_shares().clone(), *pk.verifying_key(), None)
                        .serialize()
                        .unwrap();
                SharePackage::from_bytes(
                    s.metadata.clone(),
                    s.key_package_bytes().to_vec(),
                    old_pubkey,
                )
            })
            .collect();

        assert!(legacy[0].pubkey_package().unwrap().min_signers().is_none());

        let (refreshed, _) = refresh_shares(&legacy).unwrap();
        assert_eq!(refreshed.len(), 3);
        for share in &refreshed {
            assert_eq!(*share.group_pubkey(), group_pubkey);
        }

        let sig = sign_with_local_shares(&refreshed, b"refresh after legacy load").unwrap();
        assert_eq!(sig.len(), 64);
    }

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

    /// **The security property #438 names**: an attacker who compromises a
    /// pre-refresh share MUST NOT be able to combine it with post-refresh
    /// shares to produce a valid signature. Otherwise proactive secret
    /// sharing is defeated — the refresh would be cosmetic, not protective.
    ///
    /// We model the attack: keep one old share, drop the rest, accept the
    /// refreshed shares as legitimate, then attempt to sign a quorum from
    /// the union. The protocol either fails outright or produces a
    /// signature that does NOT verify against the group pubkey.
    #[test]
    fn test_mixed_old_and_new_shares_cannot_produce_valid_signature() {
        use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey};

        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (mut old_shares, _) = dealer.generate("test-mixed").unwrap();
        let group_pubkey = *old_shares[0].group_pubkey();

        let (mut new_shares, _) = refresh_shares(&old_shares).unwrap();

        // BIP-340 schnorr signs a 32-byte message digest, and
        // `sign_with_local_shares` passes the bytes verbatim to FROST's
        // SigningPackage. Use a 32-byte digest as the message so the
        // signer and verifier agree on what was signed.
        let message_digest: [u8; 32] = {
            use sha2::Digest;
            sha2::Sha256::digest(b"attack: mix pre-refresh and post-refresh shares").into()
        };
        let message = message_digest.as_slice();

        let secp = Secp256k1::verification_only();
        let xonly = XOnlyPublicKey::from_slice(&group_pubkey)
            .expect("group pubkey is a valid x-only point");
        let msg = Message::from_digest(message_digest);

        // Control FIRST: 2 NEW shares MUST produce a valid signature
        // against the group pubkey. Proves the refresh is healthy so
        // the mixed-failure below is genuinely the security property,
        // not a setup bug. Drain the first two new shares to avoid
        // SharePackage's no-Clone constraint.
        let new_share_a = new_shares.remove(0);
        let new_share_b = new_shares.remove(0);
        let new_quorum = [new_share_a, new_share_b];
        let good_sig = sign_with_local_shares(&new_quorum, message)
            .expect("two fresh shares must produce a valid signature");
        let bip340 = bitcoin::secp256k1::schnorr::Signature::from_slice(&good_sig)
            .expect("64-byte schnorr signature");
        secp.verify_schnorr(&bip340, &msg, &xonly)
            .expect("control: two-of-three new shares MUST verify against the group pubkey");

        // Now the attack: pull one OLD share and pair it with one
        // surviving NEW share. Models a partially-compromised group
        // where the attacker still holds one old share post-refresh.
        let old_share_1 = old_shares.remove(0);
        let surviving_new_share = new_shares.remove(0); // was original index 2
        let mixed = [old_share_1, surviving_new_share];

        // The protocol either errors out OR produces a signature that
        // fails verification. Either outcome upholds the security
        // property; pin both.
        match sign_with_local_shares(&mixed, message) {
            Ok(sig) => {
                let bip340 = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig)
                    .expect("64-byte schnorr signature");
                let verified = secp.verify_schnorr(&bip340, &msg, &xonly).is_ok();
                assert!(
                    !verified,
                    "SECURITY VIOLATION: mixed old+new shares produced a signature \
                     that verifies against the group pubkey. Refresh did not actually \
                     rotate the shares."
                );
            }
            Err(_) => {
                // This is the EXPECTED path in normal operation: FROST's
                // `aggregate` verifies the signature internally and rejects
                // the cross-epoch mix before it ever returns bytes. The Ok
                // arm above is the regression tripwire for a cosmetic refresh,
                // so do not collapse this match to `unwrap_err()` even though
                // the Ok branch looks unreachable today.
            }
        }
    }
}
