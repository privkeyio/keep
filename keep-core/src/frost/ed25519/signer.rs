// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Offline t-of-n signing for FROST over Ed25519.
//!
//! Mirrors `crate::frost::signing::sign_with_local_shares` for the Ed25519
//! ciphersuite: a single caller holding a threshold of decrypted shares runs
//! both FROST rounds locally and aggregates a detached 64-byte signature.
use std::collections::BTreeMap;

use frost::rand_core::OsRng;
use frost::{keys::PublicKeyPackage, round1, round2, Identifier, SigningPackage};
use frost_ed25519 as frost;

use crate::error::{KeepError, Result};
use crate::frost::share::SharePackage;

/// Freshly generated, single-use FROST round-1 nonces for one participant.
///
/// # Nonce-reuse barrier (security-critical)
///
/// Reusing a Schnorr/FROST nonce across two signatures leaks the signer's
/// secret share. The Ed25519 signing path therefore accepts nonces *only*
/// through this type, and the only way to obtain one is [`FreshNonces::generate`],
/// which draws fresh randomness from the OS CSPRNG every call. There is no
/// constructor, setter, deserialization, or `From` impl that admits an
/// externally supplied or cached nonce.
///
/// This makes the nonce pre-exchange feature (which caches and replays nonces
/// for instant signing) structurally unreachable for Ed25519: that pool is
/// typed against `frost_secp256k1_tr::round1::SigningNonces`, a distinct type
/// that cannot be coerced into `frost_ed25519`'s nonces, and this module
/// exposes no API that would accept one even if it could. The "fresh per
/// session" invariant is thus enforced by the type system, not by convention.
struct FreshNonces {
    nonces: round1::SigningNonces,
    commitments: round1::SigningCommitments,
}

impl FreshNonces {
    /// Generate fresh single-use nonces for the given signing share.
    fn generate(signing_share: &frost::keys::SigningShare) -> Self {
        let (nonces, commitments) = round1::commit(signing_share, &mut OsRng);
        Self {
            nonces,
            commitments,
        }
    }
}

/// Sign `message` with a threshold of local Ed25519 shares (no network).
///
/// Generates fresh per-session nonces internally; see [`FreshNonces`] for the
/// nonce-reuse barrier. Returns a detached 64-byte Ed25519 signature over the
/// raw message bytes (RFC 8032), verifiable by [`verify`] and by any standard
/// Ed25519 verifier over the group verifying key.
pub fn sign_with_local_shares(shares: &[SharePackage], message: &[u8]) -> Result<[u8; 64]> {
    if shares.is_empty() {
        return Err(KeepError::Frost("No shares provided".into()));
    }

    let threshold = shares[0].metadata.threshold as usize;
    if shares.len() < threshold {
        return Err(KeepError::Frost(format!(
            "Need {} shares to sign, only {} provided",
            threshold,
            shares.len()
        )));
    }

    let signing_shares = &shares[..threshold];

    let group_pubkey = signing_shares[0].metadata.group_pubkey;
    let mut seen_ids = std::collections::HashSet::new();
    for share in signing_shares {
        if share.metadata.group_pubkey != group_pubkey {
            return Err(KeepError::Frost(
                "Shares belong to different groups".into(),
            ));
        }
        if !seen_ids.insert(share.metadata.identifier) {
            return Err(KeepError::Frost(
                "Duplicate share identifier".into(),
            ));
        }
    }

    let mut key_packages: BTreeMap<Identifier, frost::keys::KeyPackage> = BTreeMap::new();
    let mut fresh: BTreeMap<Identifier, FreshNonces> = BTreeMap::new();
    let mut commitments_map: BTreeMap<Identifier, round1::SigningCommitments> = BTreeMap::new();
    let mut verifying_shares: BTreeMap<Identifier, frost::keys::VerifyingShare> = BTreeMap::new();

    for share in signing_shares {
        let kp = ed25519_key_package(share)?;
        let id = *kp.identifier();
        let nonces = FreshNonces::generate(kp.signing_share());
        commitments_map.insert(id, nonces.commitments);
        verifying_shares.insert(id, *kp.verifying_share());
        fresh.insert(id, nonces);
        key_packages.insert(id, kp);
    }

    let signing_package = SigningPackage::new(commitments_map, message);

    let mut signature_shares: BTreeMap<Identifier, round2::SignatureShare> = BTreeMap::new();
    for (id, kp) in &key_packages {
        let nonces = fresh
            .remove(id)
            .ok_or_else(|| KeepError::Frost("Missing nonces for share".into()))?;
        let sig_share = round2::sign(&signing_package, &nonces.nonces, kp)
            .map_err(|e| KeepError::Frost(format!("Signing failed: {e}")))?;
        signature_shares.insert(*id, sig_share);
    }

    let first_kp = key_packages
        .values()
        .next()
        .ok_or_else(|| KeepError::Frost("No key packages".into()))?;
    let pubkey_pkg = PublicKeyPackage::new(verifying_shares, *first_kp.verifying_key());

    let signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_pkg)
        .map_err(|e| KeepError::Frost(format!("Aggregation failed: {e}")))?;

    let serialized = signature
        .serialize()
        .map_err(|e| KeepError::Frost(format!("Failed to serialize signature: {e}")))?;
    if serialized.len() != 64 {
        return Err(KeepError::Frost("Invalid signature length".into()));
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&serialized);
    Ok(sig_bytes)
}

/// Verify a detached Ed25519 signature against a 32-byte group verifying key.
pub fn verify(group_pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let verifying_key = frost::VerifyingKey::deserialize(group_pubkey)
        .map_err(|e| KeepError::Frost(format!("Invalid group pubkey: {e}")))?;
    let signature = frost::Signature::deserialize(signature)
        .map_err(|e| KeepError::Frost(format!("Invalid signature: {e}")))?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| KeepError::Frost("Signature verification failed".into()))
}

fn ed25519_key_package(share: &SharePackage) -> Result<frost::keys::KeyPackage> {
    frost::keys::KeyPackage::deserialize(share.key_package_bytes())
        .map_err(|e| KeepError::Frost(format!("Failed to deserialize key package: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::ed25519::TrustedDealer;
    use crate::frost::ThresholdConfig;

    #[test]
    fn test_sign_and_verify_two_of_three() {
        let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
        let (shares, pubkey_pkg) = dealer.generate("test").unwrap();

        let message = b"release v1.2.3 artifact";
        let sig = sign_with_local_shares(&shares[..2], message).unwrap();

        let group_pubkey = *shares[0].group_pubkey();
        verify(&group_pubkey, message, &sig).unwrap();

        // Group verifying key matches the dealer's public key package.
        let vk = pubkey_pkg.verifying_key().serialize().unwrap();
        assert_eq!(vk.as_slice(), &group_pubkey[..]);
    }

    #[test]
    fn test_verify_rejects_wrong_message() {
        let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
        let (shares, _) = dealer.generate("test").unwrap();

        let sig = sign_with_local_shares(&shares[..2], b"original").unwrap();
        let group_pubkey = *shares[0].group_pubkey();
        assert!(verify(&group_pubkey, b"tampered", &sig).is_err());
    }

    #[test]
    fn test_insufficient_shares_rejected() {
        let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
        let (shares, _) = dealer.generate("test").unwrap();
        assert!(sign_with_local_shares(&shares[..1], b"msg").is_err());
    }
}
