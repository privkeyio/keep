// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! FROST signing under a BIP-32 unhardened derivation path (#487, PR 2 of 4).
//!
//! Wire this into the existing FROST 2-round signing loop without touching
//! its network, storage, or wire format. Each participant applies ONE
//! composite BIP-32 scalar tweak to its own `KeyPackage` (signing share,
//! verifying share, and the group verifying key), then the standard
//! `frost::round1`/`round2`/`aggregate` runs against those tweaked packages.
//! The resulting BIP-340 aggregate signature verifies under the derived
//! child pubkey returned by
//! [`keep_bitcoin::frost_bip32::derive_path_composite`].
//!
//! Design notes for the review of #487:
//!
//! - **Composite tweak, one per signer.** BIP-32 unhardened tweaks compose
//!   additively over the group, so a single scalar `t_agg` applied to every
//!   share is enough; no per-signer tree walk. `derive_path_composite`
//!   double-checks the invariant `parent + t_agg·G == child` before we ever
//!   tweak a share, so a stale composite cannot silently produce signatures
//!   that verify under nothing.
//! - **Public accessors only.** The tweaked KeyPackages are rebuilt through
//!   `frost::keys::{SigningShare,VerifyingShare,VerifyingKey}::{serialize,deserialize}`
//!   and `KeyPackage::new`, all of which are on the public API of
//!   `frost-core`. No `internals` feature flag is required.
//! - **Signature verifier check.** After aggregation we independently
//!   verify the produced signature against the derived child pubkey using
//!   BIP-340. A tweak accounting mistake would fail this check, so a
//!   silently-wrong signature cannot escape the helper.

use std::collections::BTreeMap;

use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
use frost_secp256k1_tr::{
    self as frost,
    keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare},
    rand_core::OsRng,
    round1, round2, Identifier, SigningPackage, VerifyingKey,
};

use super::SharePackage;
use crate::error::{KeepError, Result};
use crate::frost_bip32::{derive_path_composite, deterministic_chaincode, CompositeDerivation};

/// Add the aggregate BIP-32 scalar tweak `t_agg` to every field of a
/// `KeyPackage`: `signing_share += t_agg`, `verifying_share += t_agg·G`,
/// `verifying_key += t_agg·G`. Returns the tweaked package.
///
/// The three additions must all be consistent for the standard FROST round
/// to produce a signature that verifies under the derived child pubkey.
/// The point-addition uses libsecp256k1 directly rather than
/// frost-secp256k1-tr's internal `Tweak` trait, which is BIP-341-specific
/// and does not accept a raw scalar.
fn tweak_key_package(kp: &KeyPackage, tweak: &[u8; 32]) -> Result<KeyPackage> {
    let secp = Secp256k1::verification_only();

    // Parity handling. `derive_path_composite` walks BIP-32 from the +even
    // lift of the x-only group pubkey, matching what every downstream wallet
    // (and every reference BIP-32 implementation) does when handed an xpub
    // shaped from an x-only key. But the FROST KeyPackage carries the
    // group's TRUE verifying_key, which can have either parity. If it is
    // odd-y, then `real_vk = -even_lift(x_only(real_vk))`, so applying the
    // primitive's `t` scalar directly lands on `real_vk + t·G = -(even_lift + (-t)·G)`
    // whose x-coordinate is x_only(even_lift + (-t)·G) — NOT
    // x_only(even_lift + t·G). To land the tweaked VK on the same x-only
    // child pubkey wallets derive, negate the tweak in the odd-y case. The
    // resulting KeyPackage will have `-(child_target)` as its VerifyingKey,
    // which BIP-340 accepts (verification is x-only, ignores sign).
    let vk_bytes_probe = kp
        .verifying_key()
        .serialize()
        .map_err(|e| KeepError::Frost(format!("verifying key serialize: {e}")))?;
    let real_vk_is_odd = vk_bytes_probe.first() == Some(&0x03);
    let mut effective_tweak = *tweak;
    if real_vk_is_odd {
        // Negate: n - t, using SecretKey's built-in modular negate (the
        // `negate` method returns -k mod n).
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&effective_tweak)
            .map_err(|e| KeepError::Frost(format!("aggregate tweak invalid: {e}")))?;
        effective_tweak = sk.negate().secret_bytes();
    }
    let tweak = &effective_tweak;

    // Convert the (possibly negated) aggregate tweak into a
    // bitcoin::secp256k1::Scalar for point additions and into a
    // bitcoin::secp256k1::SecretKey for the scalar addition on the signing
    // share. Both accept 32 big-endian bytes.
    let scalar = bitcoin::secp256k1::Scalar::from_be_bytes(*tweak).map_err(|_| {
        KeepError::Frost("BIP-32 aggregate tweak >= curve order; refusing to sign".into())
    })?;
    let tweak_sk = bitcoin::secp256k1::SecretKey::from_slice(tweak).map_err(|e| {
        KeepError::Frost(format!("BIP-32 aggregate tweak is not a valid scalar: {e}"))
    })?;

    // Signing share: raw 32-byte big-endian scalar. Add tweak modulo n via
    // SecretKey::add_tweak (we abuse the SecretKey type for its modular
    // arithmetic; the tweak itself is not a secret).
    let ss_bytes = kp.signing_share().serialize();
    let ss_sk = bitcoin::secp256k1::SecretKey::from_slice(&ss_bytes)
        .map_err(|e| KeepError::Frost(format!("signing share is not a valid scalar: {e}")))?;
    let tweaked_ss_sk = ss_sk
        .add_tweak(&bitcoin::secp256k1::Scalar::from_be_bytes(tweak_sk.secret_bytes()).unwrap())
        .map_err(|e| KeepError::Frost(format!("signing share + tweak invalid: {e}")))?;
    let tweaked_signing_share = SigningShare::deserialize(&tweaked_ss_sk.secret_bytes())
        .map_err(|e| KeepError::Frost(format!("tweaked signing share deserialize: {e}")))?;

    // Verifying share: 33-byte compressed pubkey. Add tweak·G via
    // PublicKey::add_exp_tweak.
    let vs_bytes = kp
        .verifying_share()
        .serialize()
        .map_err(|e| KeepError::Frost(format!("verifying share serialize: {e}")))?;
    let vs_pk = bitcoin::secp256k1::PublicKey::from_slice(&vs_bytes)
        .map_err(|e| KeepError::Frost(format!("verifying share is not a valid point: {e}")))?;
    let tweaked_vs_pk = vs_pk
        .add_exp_tweak(&secp, &scalar)
        .map_err(|e| KeepError::Frost(format!("verifying share + tweak·G invalid: {e}")))?;
    let tweaked_verifying_share = VerifyingShare::deserialize(&tweaked_vs_pk.serialize())
        .map_err(|e| KeepError::Frost(format!("tweaked verifying share deserialize: {e}")))?;

    // Verifying key (group-level): same shape as VerifyingShare — 33 bytes.
    let vk_bytes = kp
        .verifying_key()
        .serialize()
        .map_err(|e| KeepError::Frost(format!("verifying key serialize: {e}")))?;
    let vk_pk = bitcoin::secp256k1::PublicKey::from_slice(&vk_bytes)
        .map_err(|e| KeepError::Frost(format!("verifying key is not a valid point: {e}")))?;
    let tweaked_vk_pk = vk_pk
        .add_exp_tweak(&secp, &scalar)
        .map_err(|e| KeepError::Frost(format!("verifying key + tweak·G invalid: {e}")))?;
    let tweaked_verifying_key = VerifyingKey::deserialize(&tweaked_vk_pk.serialize())
        .map_err(|e| KeepError::Frost(format!("tweaked verifying key deserialize: {e}")))?;

    Ok(KeyPackage::new(
        *kp.identifier(),
        tweaked_signing_share,
        tweaked_verifying_share,
        tweaked_verifying_key,
        *kp.min_signers(),
    ))
}

/// Derive the child pubkey and aggregate tweak for a group at a given BIP-32
/// unhardened path, using the deterministic chaincode
/// (`keep_bitcoin::frost_bip32::deterministic_chaincode`).
pub fn derive_child(group_pubkey: &[u8; 32], path: &[u32]) -> Result<CompositeDerivation> {
    let cc = deterministic_chaincode(group_pubkey);
    derive_path_composite(group_pubkey, &cc, path)
        .map_err(|e| KeepError::Frost(format!("BIP-32 child derivation failed: {e}")))
}

/// Sign `message` under the FROST group's BIP-32 unhardened child key at
/// `path` using local shares (no network). Every share is tweaked by the
/// composite BIP-32 scalar tweak before running the standard round1/round2
/// aggregation, so the resulting BIP-340 signature verifies under the
/// derived child pubkey returned by [`derive_child`].
///
/// The returned signature is independently verified against the child key
/// before it leaves this function, so a tweak accounting mistake fails
/// closed rather than surfacing as a silently-wrong signature.
pub fn sign_with_local_shares_at_path(
    shares: &[SharePackage],
    message: &[u8],
    path: &[u32],
) -> Result<[u8; 64]> {
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

    let group_pubkey = shares[0].group_pubkey();
    let composite = derive_child(group_pubkey, path)?;

    // Deserialize + tweak every KeyPackage up front so a single bad share
    // fails before we mutate any signing state.
    let tweaked_kps: Vec<KeyPackage> = signing_shares
        .iter()
        .map(|s| tweak_key_package(&s.key_package()?, &composite.aggregate_tweak))
        .collect::<Result<Vec<_>>>()?;

    let mut nonces_map: BTreeMap<Identifier, round1::SigningNonces> = BTreeMap::new();
    let mut commitments_map: BTreeMap<Identifier, round1::SigningCommitments> = BTreeMap::new();
    let mut verifying_shares: BTreeMap<Identifier, VerifyingShare> = BTreeMap::new();

    for kp in &tweaked_kps {
        let (nonces, commitments) = round1::commit(kp.signing_share(), &mut OsRng);
        nonces_map.insert(*kp.identifier(), nonces);
        commitments_map.insert(*kp.identifier(), commitments);
        verifying_shares.insert(*kp.identifier(), *kp.verifying_share());
    }

    let signing_package = SigningPackage::new(commitments_map, message);

    let mut signature_shares: BTreeMap<Identifier, round2::SignatureShare> = BTreeMap::new();
    for kp in &tweaked_kps {
        let id = *kp.identifier();
        let nonces = nonces_map
            .remove(&id)
            .ok_or_else(|| KeepError::Frost("Missing nonces for share".into()))?;
        let sig_share = round2::sign(&signing_package, &nonces, kp)
            .map_err(|e| KeepError::Frost(format!("Signing failed: {e}")))?;
        signature_shares.insert(id, sig_share);
    }

    let pubkey_pkg = PublicKeyPackage::new(
        verifying_shares,
        *tweaked_kps[0].verifying_key(),
        Some(*tweaked_kps[0].min_signers()),
    );
    let signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_pkg)
        .map_err(|e| KeepError::Frost(format!("Aggregation failed: {e}")))?;

    let serialized = signature
        .serialize()
        .map_err(|e| KeepError::Frost(format!("Failed to serialize signature: {e}")))?;
    let bytes_slice = serialized.as_slice();
    if bytes_slice.len() != 64 {
        return Err(KeepError::Frost("Invalid signature length".into()));
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(bytes_slice);

    // Independent verification: the aggregate MUST verify under the derived
    // child pubkey using BIP-340. A wrong tweak on any share would break
    // this check, so we surface it as an explicit error rather than
    // returning a silently-wrong signature.
    let secp = Secp256k1::verification_only();
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| KeepError::Frost(format!("Aggregate signature is not schnorr-shaped: {e}")))?;
    let child_xonly = XOnlyPublicKey::from_slice(&composite.child_pubkey)
        .map_err(|e| KeepError::Frost(format!("Derived child pubkey invalid: {e}")))?;
    let msg = Message::from_digest_slice(message)
        .map_err(|e| KeepError::Frost(format!("Signable message must be 32 bytes: {e}")))?;
    secp.verify_schnorr(&sig, &msg, &child_xonly).map_err(|e| {
        KeepError::Frost(format!(
            "BIP-32 composed signing produced a signature that does not verify \
                 under the derived child pubkey: {e}"
        ))
    })?;

    Ok(sig_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{ThresholdConfig, TrustedDealer};

    fn make_shares(threshold: u16, total: u16) -> Vec<SharePackage> {
        let config = ThresholdConfig::new(threshold, total).unwrap();
        let dealer = TrustedDealer::new(config);
        let (shares, _pubkey_package) = dealer.generate("bip32-sign-test").unwrap();
        shares
    }

    /// The group pubkey exposed by a `SharePackage` is what every downstream
    /// caller identifies the group by. Derivation must produce a different
    /// x-only key at every leaf, and the signature we build must verify
    /// under that derived x-only key.
    #[test]
    fn signs_and_verifies_under_derived_child_pubkey_at_leaf() {
        let shares = make_shares(2, 3);
        let group = *shares[0].group_pubkey();
        let message = [0x11u8; 32];

        let sig = sign_with_local_shares_at_path(&shares[..2], &message, &[0, 5]).unwrap();

        let composite = derive_child(&group, &[0, 5]).unwrap();
        // Redundant with the check baked into the helper, but leaves an
        // explicit at-rest assertion in the test suite that a
        // /0/5-derived signature verifies where a /0/5-derived address
        // would receive to.
        let secp = Secp256k1::verification_only();
        let sig = Signature::from_slice(&sig).unwrap();
        let xonly = XOnlyPublicKey::from_slice(&composite.child_pubkey).unwrap();
        let msg = Message::from_digest(message);
        secp.verify_schnorr(&sig, &msg, &xonly).unwrap();
    }

    /// A signature produced under the child key MUST NOT verify under the
    /// group key. Otherwise the whole point of derivation (per-address
    /// signing keys) is defeated.
    #[test]
    fn child_signature_does_not_verify_under_group_pubkey() {
        let shares = make_shares(2, 3);
        let group = *shares[0].group_pubkey();
        let message = [0x22u8; 32];

        let sig = sign_with_local_shares_at_path(&shares[..2], &message, &[0, 7]).unwrap();

        let secp = Secp256k1::verification_only();
        let sig = Signature::from_slice(&sig).unwrap();
        let group_xonly = XOnlyPublicKey::from_slice(&group).unwrap();
        let msg = Message::from_digest(message);
        assert!(
            secp.verify_schnorr(&sig, &msg, &group_xonly).is_err(),
            "child-derived signature must not verify under the parent group key"
        );
    }

    /// External chain (`/0/N`) and internal chain (`/1/N`) at the same leaf
    /// index produce distinct signatures under distinct pubkeys. This is
    /// the property #487 needs to hold end-to-end: change and receive
    /// addresses become distinct AND separately spendable.
    #[test]
    fn external_and_internal_leaves_sign_under_distinct_child_pubkeys() {
        let shares = make_shares(2, 3);
        let group = *shares[0].group_pubkey();
        let message = [0x33u8; 32];

        let sig_ext = sign_with_local_shares_at_path(&shares[..2], &message, &[0, 4]).unwrap();
        let sig_int = sign_with_local_shares_at_path(&shares[..2], &message, &[1, 4]).unwrap();
        assert_ne!(sig_ext, sig_int);

        let ext_child = derive_child(&group, &[0, 4]).unwrap().child_pubkey;
        let int_child = derive_child(&group, &[1, 4]).unwrap().child_pubkey;
        assert_ne!(ext_child, int_child);
    }

    /// The 3-of-5 case at a two-level path, exercising a deeper walk than
    /// the 2-of-3 tests. Signature must still verify under the
    /// path-derived child pubkey with more signers reaching threshold.
    #[test]
    fn three_of_five_signs_and_verifies_at_two_level_path() {
        let shares = make_shares(3, 5);
        let group = *shares[0].group_pubkey();
        let message = [0x44u8; 32];

        let sig = sign_with_local_shares_at_path(&shares[..3], &message, &[1, 99]).unwrap();

        let composite = derive_child(&group, &[1, 99]).unwrap();
        let secp = Secp256k1::verification_only();
        let sig = Signature::from_slice(&sig).unwrap();
        let xonly = XOnlyPublicKey::from_slice(&composite.child_pubkey).unwrap();
        let msg = Message::from_digest(message);
        secp.verify_schnorr(&sig, &msg, &xonly).unwrap();
    }

    /// Fewer shares than the threshold refuses without ever computing a
    /// composite tweak or emitting a partial signature.
    #[test]
    fn below_threshold_refuses() {
        let shares = make_shares(2, 3);
        let message = [0x55u8; 32];
        let err = sign_with_local_shares_at_path(&shares[..1], &message, &[0, 0])
            .expect_err("below threshold must be refused");
        assert!(matches!(err, KeepError::Frost(_)));
    }

    /// Empty path refuses (matches the primitive) before any signing work.
    #[test]
    fn empty_path_refuses() {
        let shares = make_shares(2, 3);
        let message = [0x66u8; 32];
        let err = sign_with_local_shares_at_path(&shares[..2], &message, &[])
            .expect_err("empty path must be refused");
        assert!(matches!(err, KeepError::Frost(_)));
    }
}
