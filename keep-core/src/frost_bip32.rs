// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! BIP-32 child-key primitives for FROST group keys (#487, PR 1 of 4).
//!
//! A FROST group holds a single aggregated schnorr key. That key alone is not
//! a BIP-32 HD tree; it has no chaincode and no derivation path, so `wallet
//! descriptor` collapses `/0/*` and `/1/*` into the same address and every
//! receive plus every change output reuses the same script.
//!
//! This module ships the crypto foundation for a proper HD wallet on top of a
//! FROST group without touching signing, wire format, or the descriptor
//! emitter. Subsequent PRs (see #487) wire (a) FROST signing under the
//! composed BIP-32 + BIP-341 tweak, (b) the sign wire protocol carrying the
//! derivation path, and (c) descriptor emission using the resulting xpub. All
//! three depend on the primitives here matching a reference impl exactly.
//!
//! Design choices captured for the review of #487:
//!
//! - **Chaincode is deterministic from the group pubkey**, `sha256(DOMAIN ||
//!   group_pubkey_x_only)`. No storage bump, no protocol change, and the same
//!   chaincode falls out on every share by construction (it depends only on
//!   the public group key, which every share already carries). BIP-32
//!   chaincodes are not secret; they are part of the xpub. Using a
//!   deterministic derivation makes them shareable without a separate wire.
//! - **BIP-32 unhardened public derivation only**: hardened derivation needs
//!   the private key. FROST groups do not have one to hand around, so
//!   hardened derivation is architecturally out of scope for HD receive/
//!   change chains. This matches BIP-86 taproot single-sig practice (`/0/*`
//!   and `/1/*` are both unhardened).
//! - **X-only pubkeys** as the public interface: the group key surfaces
//!   everywhere in this codebase as a BIP-340 x-only 32-byte value, so the
//!   primitive returns x-only child pubkeys. Internally we work with the
//!   compressed 33-byte form because that is what `HMAC-SHA512` hashes in the
//!   BIP-32 spec. A bare x-only input (the group key, or a single-step
//!   `derive_child` parent) is lifted to its +even point (0x02 prefix), matching
//!   how BIP-340 recovers a key from an x-only value. Crucially, a multi-level
//!   `derive_path` walk carries each intermediate node's *true* compressed parity
//!   into the next HMAC, exactly as BIP-32 `ckd_pub` does; it does not re-lift
//!   intermediates to even, so derivation stays byte-for-byte conformant at every
//!   depth (a receive/change leaf under an odd-y `/0` or `/1` node still matches).
//!
//! Reference vectors are cross-checked against `bitcoin::bip32::Xpub::derive_pub`
//! in tests, so any drift from BIP-32 fails a unit test.

use bitcoin::hashes::{sha256, sha512, Hash as _, HashEngine as _, Hmac, HmacEngine};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

use crate::error::{KeepError, Result};

/// Local shim so downstream call sites (moved from keep-bitcoin in #487 PR2)
/// keep using the same variant name for BIP-32 pathing errors. Every
/// derivation failure is reported as `KeepError::Frost(...)` under the hood.
#[inline]
fn derivation_path_error(msg: impl Into<String>) -> KeepError {
    KeepError::Frost(msg.into())
}

/// Domain separator for the deterministic chaincode. Bumping the version tag
/// invalidates every previously derived child; keep it stable across releases.
const CHAINCODE_DOMAIN: &[u8] = b"keep-frost-bip32-chaincode-v1";

/// BIP-32 says child index >= 2^31 selects hardened derivation, which needs
/// the private key. FROST groups only ever do unhardened public derivation
/// (see the module doc), so every index must live below the hardened bit.
pub const HARDENED_INDEX_START: u32 = 0x8000_0000;

/// Maximum derivation-path length accepted by the path walkers. BIP-32's own
/// serialized `depth` field is a single byte, so 255 is the natural ceiling;
/// a real receive/change path is length 2. Bounding it keeps a wire-supplied
/// path (see #487) from forcing unbounded HMAC-SHA512 + EC work on a signer.
pub const MAX_DERIVATION_DEPTH: usize = 255;

/// Derive the deterministic 32-byte chaincode for a FROST group key.
///
/// `group_pubkey` is the BIP-340 x-only 32-byte aggregated FROST group key.
/// The result is a domain-separated sha256 hash so a chaincode collision
/// implies a sha256 collision.
pub fn deterministic_chaincode(group_pubkey: &[u8; 32]) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(CHAINCODE_DOMAIN);
    engine.input(group_pubkey);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Result of one BIP-32 unhardened public derivation step.
///
/// `tweak` is the scalar that must be added to the parent point (and, in the
/// FROST signing path, to every co-signer's share) to produce the child key.
/// `child_chaincode` feeds into the next derivation step along the path.
/// `child_pubkey` is the x-only 32-byte child public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildDerivation {
    /// Scalar tweak `IL` from BIP-32 (the left 32 bytes of the HMAC output).
    pub tweak: [u8; 32],
    /// Next-level chaincode `IR` from BIP-32 (the right 32 bytes).
    pub child_chaincode: [u8; 32],
    /// Child public key as a BIP-340 x-only 32-byte value.
    pub child_pubkey: [u8; 32],
}

/// Lift a BIP-340 x-only value to its +even (0x02 prefix) secp256k1 point,
/// which is how BIP-340 recovers a public key from a bare x-only value.
fn even_lift(xonly: &[u8; 32]) -> Result<PublicKey> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(xonly);
    PublicKey::from_slice(&compressed)
        .map_err(|e| derivation_path_error(format!("x-only pubkey not on curve: {e}")))
}

/// One BIP-32 unhardened `ckd_pub` step on a full parent point.
///
/// Serializes the parent with its *true* compressed parity (0x02 or 0x03) into
/// the HMAC, exactly as the spec requires, and returns the real child point so
/// callers can chain further steps without discarding parity. Returns the
/// scalar tweak `IL`, the child chaincode `IR`, and the child point.
fn ckd_pub_point(
    parent_point: &PublicKey,
    chaincode: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32], PublicKey)> {
    if index >= HARDENED_INDEX_START {
        return Err(derivation_path_error(format!(
            "hardened index {index} not supported for FROST groups; \
             only unhardened public derivation is meaningful without a group secret"
        )));
    }
    // BIP-32 unhardened: HMAC-SHA512(chaincode, ser_P(parent_point) || ser32(index)),
    // where ser_P is the 33-byte compressed pubkey carrying the parent's real parity.
    let compressed = parent_point.serialize();
    let mut engine = HmacEngine::<sha512::Hash>::new(chaincode);
    engine.input(&compressed);
    engine.input(&index.to_be_bytes());
    let i = Hmac::<sha512::Hash>::from_engine(engine).to_byte_array();

    let mut tweak = [0u8; 32];
    tweak.copy_from_slice(&i[..32]);
    let mut child_chaincode = [0u8; 32];
    child_chaincode.copy_from_slice(&i[32..]);

    let scalar = Scalar::from_be_bytes(tweak).map_err(|_| {
        // BIP-32 says: "In case parse256(IL) >= n or Ki is the point at infinity,
        // the resulting key is invalid, and one should proceed with the next
        // value for i." We surface this so callers can retry at their layer;
        // for the deterministic chaincode + reasonable indexes this has
        // never been observed in practice.
        derivation_path_error(format!(
            "BIP-32 child tweak >= curve order at index {index}; caller must skip to next index"
        ))
    })?;
    let secp = Secp256k1::verification_only();
    let child_point = parent_point.add_exp_tweak(&secp, &scalar).map_err(|e| {
        derivation_path_error(format!("BIP-32 child tweak produced invalid point: {e}"))
    })?;
    Ok((tweak, child_chaincode, child_point))
}

/// Derive one BIP-32 unhardened child of the given (parent_pubkey, chaincode)
/// pair. Refuses hardened indexes (>= 2^31) and refuses the vanishingly rare
/// case where the HMAC left-half scalar is >= n (spec-mandated retry with a
/// different path segment; we surface it as an error so callers can react).
///
/// `parent_pubkey` is a bare x-only value and is lifted to its +even point, so
/// this is only conformant as a single step off the group key. For a multi-level
/// walk use [`derive_path`], which threads each intermediate node's true parity;
/// re-feeding this function's x-only output as the next parent would force even
/// parity and diverge from BIP-32 whenever an intermediate node has odd y.
pub fn derive_child(
    parent_pubkey: &[u8; 32],
    chaincode: &[u8; 32],
    index: u32,
) -> Result<ChildDerivation> {
    let parent_point = even_lift(parent_pubkey)?;
    let (tweak, child_chaincode, child_point) = ckd_pub_point(&parent_point, chaincode, index)?;
    Ok(ChildDerivation {
        tweak,
        child_chaincode,
        child_pubkey: child_point.x_only_public_key().0.serialize(),
    })
}

/// Result of walking a full BIP-32 path, with the aggregate scalar tweak
/// needed to reproduce the terminal child key from the +even lift of the
/// group key. Used by FROST signing so every co-signer applies one
/// composite tweak to its share instead of walking the tree per signer.
///
/// BIP-32 unhardened tweaks compose additively over the group:
/// `child_final = group_lifted + t_agg·G (mod n)` where `t_agg = sum(t_i)`
/// with each `t_i` computed against the actual on-curve parent point at
/// its own depth. The stepwise tweaks are NOT interchangeable with the
/// aggregate at intermediate depths (the HMAC input at level `i+1` depends
/// on level `i`'s real parity, not on any x-only summary), so callers that
/// want the aggregate must use this walker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompositeDerivation {
    /// Aggregate BIP-32 scalar tweak: applying it once to every FROST
    /// signing share (mod n) and the group verifying key produces a
    /// tweaked signing set whose aggregate signature verifies under
    /// [`Self::child_pubkey`]. This is the single scalar the composed
    /// BIP-32 + BIP-341 sign path passes to `KeyPackage`.
    pub aggregate_tweak: [u8; 32],
    /// Terminal chaincode. Callers walking children below the terminal
    /// node (e.g. a wallet exposing further sub-paths) use it as the
    /// parent chaincode for the next step.
    pub terminal_chaincode: [u8; 32],
    /// Terminal x-only child public key: the address-forming key at the
    /// end of the path, and the key an aggregated signature must verify
    /// against.
    pub child_pubkey: [u8; 32],
}

/// Walk a BIP-32 path and return the aggregate scalar tweak plus the
/// terminal chaincode and x-only child pubkey. Refuses hardened indexes
/// and refuses paths whose stepwise tweaks aggregate to zero mod n (an
/// invalid signing key; also a BIP-32-spec-mandated retry condition).
pub fn derive_path_composite(
    group_pubkey: &[u8; 32],
    chaincode: &[u8; 32],
    path: &[u32],
) -> Result<CompositeDerivation> {
    if path.is_empty() {
        return Err(derivation_path_error(
            "derive_path_composite requires at least one index",
        ));
    }
    if path.len() > MAX_DERIVATION_DEPTH {
        return Err(derivation_path_error(format!(
            "derivation path length {} exceeds maximum {MAX_DERIVATION_DEPTH}",
            path.len()
        )));
    }
    let mut parent_point = even_lift(group_pubkey)?;
    let mut parent_chaincode = *chaincode;

    // Accumulate the scalar tweak in a SecretKey for modular add_tweak
    // arithmetic. The value is not a secret (chaincodes and unhardened
    // tweaks are public by construction), we just reuse the API surface
    // for its mod-n scalar addition. Seed with the first step's tweak.
    let first_index = path[0];
    let (first_tweak, first_cc, first_point) =
        ckd_pub_point(&parent_point, &parent_chaincode, first_index)?;
    let mut acc = SecretKey::from_slice(&first_tweak).map_err(|e| {
        derivation_path_error(format!("BIP-32 first tweak is not a valid scalar: {e}"))
    })?;
    parent_point = first_point;
    parent_chaincode = first_cc;

    for &index in &path[1..] {
        let (step_tweak, step_cc, step_point) =
            ckd_pub_point(&parent_point, &parent_chaincode, index)?;
        let step_scalar = Scalar::from_be_bytes(step_tweak).map_err(|_| {
            derivation_path_error(format!("BIP-32 step tweak >= curve order at index {index}"))
        })?;
        acc = acc.add_tweak(&step_scalar).map_err(|e| {
            derivation_path_error(format!(
                "BIP-32 aggregate tweak became invalid at index {index}: {e}"
            ))
        })?;
        parent_point = step_point;
        parent_chaincode = step_cc;
    }

    let aggregate_tweak = acc.secret_bytes();
    // Sanity-check invariant: applying the aggregate tweak to the +even
    // lift of the group key must reproduce the terminal child point.
    // Any drift here means the composite tweak cannot be used for FROST
    // signing under the derived child key, which is the whole point of
    // this helper. Refuse rather than return an unsigned-worthy tweak.
    let secp = Secp256k1::verification_only();
    let reproduced = even_lift(group_pubkey)?
        .add_exp_tweak(
            &secp,
            &Scalar::from_be_bytes(aggregate_tweak).map_err(|_| {
                derivation_path_error("aggregate tweak >= curve order after accumulation")
            })?,
        )
        .map_err(|e| {
            derivation_path_error(format!("aggregate tweak produced invalid point: {e}"))
        })?;
    if reproduced != parent_point {
        return Err(derivation_path_error(
            "composed BIP-32 tweak does not reproduce terminal child point; \
             signing under the aggregate would diverge from stepwise derivation",
        ));
    }

    Ok(CompositeDerivation {
        aggregate_tweak,
        terminal_chaincode: parent_chaincode,
        child_pubkey: parent_point.x_only_public_key().0.serialize(),
    })
}

/// Walk a full BIP-32 path (all unhardened) starting from the group key and
/// its deterministic chaincode, returning the terminal derivation. Convenience
/// wrapper: the descriptor path `m/0/*` at index N is `derive_path(&[0, N])`.
///
/// The group key is lifted to its +even point once; every intermediate node's
/// true compressed parity is then carried into the next HMAC, so the walk stays
/// byte-for-byte BIP-32 conformant even under odd-y intermediate nodes.
pub fn derive_path(
    group_pubkey: &[u8; 32],
    chaincode: &[u8; 32],
    path: &[u32],
) -> Result<ChildDerivation> {
    if path.is_empty() {
        return Err(derivation_path_error(
            "derive_path requires at least one index",
        ));
    }
    if path.len() > MAX_DERIVATION_DEPTH {
        return Err(derivation_path_error(format!(
            "derivation path length {} exceeds maximum {MAX_DERIVATION_DEPTH}",
            path.len()
        )));
    }
    let mut parent_point = even_lift(group_pubkey)?;
    let mut parent_chaincode = *chaincode;
    let mut last: Option<ChildDerivation> = None;
    for &index in path {
        let (tweak, child_chaincode, child_point) =
            ckd_pub_point(&parent_point, &parent_chaincode, index)?;
        parent_point = child_point;
        parent_chaincode = child_chaincode;
        last = Some(ChildDerivation {
            tweak,
            child_chaincode,
            child_pubkey: child_point.x_only_public_key().0.serialize(),
        });
    }
    Ok(last.expect("non-empty path always sets last"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::{ChainCode, ChildNumber, Xpub};
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::NetworkKind;

    /// A stable, well-formed FROST-group-shaped x-only pubkey. Generated from
    /// a fixed secret so the reference vectors below are reproducible.
    fn stable_group_pubkey() -> [u8; 32] {
        let secp = Secp256k1::signing_only();
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let (xonly, _) = sk.x_only_public_key(&secp);
        xonly.serialize()
    }

    /// #487 PR1: the same group pubkey always yields the same chaincode, so
    /// every share can reproduce it locally without a wire exchange.
    #[test]
    fn chaincode_is_deterministic() {
        let group = stable_group_pubkey();
        let cc1 = deterministic_chaincode(&group);
        let cc2 = deterministic_chaincode(&group);
        assert_eq!(cc1, cc2);
    }

    /// Two different group pubkeys must yield different chaincodes so a
    /// child derived from group A cannot accidentally match a child from B.
    #[test]
    fn chaincode_differs_per_group_pubkey() {
        let a = stable_group_pubkey();
        let mut b = a;
        b[0] ^= 0x01;
        assert_ne!(deterministic_chaincode(&a), deterministic_chaincode(&b));
    }

    /// Hardened indexes are refused, not silently accepted. This is
    /// architectural: without the group secret there is no meaningful
    /// hardened derivation.
    #[test]
    fn hardened_index_refused() {
        let group = stable_group_pubkey();
        let cc = deterministic_chaincode(&group);
        let err = derive_child(&group, &cc, HARDENED_INDEX_START)
            .expect_err("hardened index must be refused");
        assert!(matches!(err, KeepError::Frost(_)));
        // The last unhardened index still works.
        derive_child(&group, &cc, HARDENED_INDEX_START - 1).unwrap();
    }

    /// Different indexes off the same parent produce different child pubkeys
    /// (address diversity along the `/0/*` chain).
    #[test]
    fn distinct_indexes_yield_distinct_child_pubkeys() {
        let group = stable_group_pubkey();
        let cc = deterministic_chaincode(&group);
        let a = derive_child(&group, &cc, 0).unwrap().child_pubkey;
        let b = derive_child(&group, &cc, 1).unwrap().child_pubkey;
        let c = derive_child(&group, &cc, 2).unwrap().child_pubkey;
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    /// The external chain (`/0/N`) and internal chain (`/1/N`) at the same
    /// leaf index produce distinct child pubkeys, so `wallet descriptor`
    /// stops reusing addresses between receive and change once this
    /// derivation is wired in.
    #[test]
    fn external_and_internal_chains_diverge_at_matching_leaf() {
        let group = stable_group_pubkey();
        let cc = deterministic_chaincode(&group);
        for leaf in 0u32..8 {
            let external = derive_path(&group, &cc, &[0, leaf]).unwrap().child_pubkey;
            let internal = derive_path(&group, &cc, &[1, leaf]).unwrap().child_pubkey;
            assert_ne!(
                external, internal,
                "external and internal chain must diverge at leaf {leaf}"
            );
        }
    }

    /// Build the reference `bitcoin::bip32::Xpub` carrying our (group_pubkey,
    /// chaincode), rooted at the +even lift of the x-only group key, so we can
    /// hand it to bitcoin::bip32's normal `ckd_pub` path.
    fn ref_xpub_for(group: &[u8; 32], cc: &[u8; 32]) -> Xpub {
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(group);
        let parent_point = bitcoin::secp256k1::PublicKey::from_slice(&compressed).unwrap();
        Xpub {
            network: NetworkKind::Main,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            public_key: parent_point,
            chain_code: ChainCode::from(*cc),
        }
    }

    /// Assert our derivation matches `bitcoin::bip32::Xpub::derive_pub` byte for
    /// byte across a spread of single- and multi-level unhardened paths.
    fn assert_matches_bip32_reference(group: [u8; 32]) {
        let cc = deterministic_chaincode(&group);
        let xpub = ref_xpub_for(&group, &cc);
        let secp = Secp256k1::verification_only();

        for &path in &[
            &[0u32][..],
            &[1u32][..],
            &[0, 0][..],
            &[0, 1][..],
            &[1, 0][..],
            &[1, 42][..],
            &[0, 100_000][..],
        ] {
            let ours = derive_path(&group, &cc, path).unwrap();

            let bip32_path: bitcoin::bip32::DerivationPath = path
                .iter()
                .map(|i| ChildNumber::from_normal_idx(*i).unwrap())
                .collect::<Vec<_>>()
                .into();
            let ref_xpub = xpub.derive_pub(&secp, &bip32_path).unwrap();
            let (ref_xonly, _) = ref_xpub.public_key.x_only_public_key();

            assert_eq!(
                ours.child_pubkey,
                ref_xonly.serialize(),
                "path {path:?}: our child pubkey diverges from bitcoin::bip32"
            );
            assert_eq!(
                ours.child_chaincode,
                ref_xpub.chain_code.to_bytes(),
                "path {path:?}: our child chaincode diverges from bitcoin::bip32"
            );
        }
    }

    /// Reference vectors: our tweak-based child derivation MUST match
    /// `bitcoin::bip32::Xpub::derive_pub`, which is a widely deployed BIP-32
    /// implementation. If this test drifts, we've broken conformance and
    /// every downstream wallet importing our xpub would derive different
    /// addresses.
    #[test]
    fn matches_bitcoin_bip32_reference() {
        assert_matches_bip32_reference(stable_group_pubkey());
    }

    /// Regression for the parity-threading bug: a multi-level walk under an
    /// intermediate node with *odd* y must still match BIP-32. A fixed even-y
    /// key never exercises this, so search for a group key whose `/0` node is
    /// odd-y and assert conformance under it. If `derive_path` ever re-lifts
    /// intermediates to even, `/0/*` and `/1/*` here diverge from the reference.
    #[test]
    fn matches_bip32_reference_under_oddy_intermediate() {
        let secp = Secp256k1::new();
        let group = (1u8..=255)
            .find_map(|seed| {
                let sk = SecretKey::from_slice(&[seed; 32]).ok()?;
                let (xonly, _) = sk.x_only_public_key(&secp);
                let g = xonly.serialize();
                let cc = deterministic_chaincode(&g);
                let child0 = ref_xpub_for(&g, &cc)
                    .derive_pub(&secp, &[ChildNumber::from_normal_idx(0).unwrap()])
                    .unwrap();
                // Compressed prefix 0x03 == odd y on the `/0` node.
                (child0.public_key.serialize()[0] == 0x03).then_some(g)
            })
            .expect("some group key in range must have an odd-y /0 node");

        assert_matches_bip32_reference(group);
    }

    /// The tweak returned by `derive_child` MUST be exactly the scalar
    /// `parent_point + tweak * G = child_point` uses. Verify by applying it
    /// with libsecp256k1 directly and matching against the child pubkey.
    #[test]
    fn tweak_reproduces_child_when_applied_to_parent() {
        let group = stable_group_pubkey();
        let cc = deterministic_chaincode(&group);
        let step = derive_child(&group, &cc, 7).unwrap();

        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&group);
        let parent_point = bitcoin::secp256k1::PublicKey::from_slice(&compressed).unwrap();
        let secp = Secp256k1::verification_only();
        let scalar = Scalar::from_be_bytes(step.tweak).unwrap();
        let child_point = parent_point.add_exp_tweak(&secp, &scalar).unwrap();
        let (child_xonly, _) = child_point.x_only_public_key();
        assert_eq!(child_xonly.serialize(), step.child_pubkey);
    }

    /// Empty path is a caller error; we surface it clearly rather than
    /// silently returning the parent state as if a zero-step walk succeeded.
    #[test]
    fn empty_path_refused() {
        let group = stable_group_pubkey();
        let cc = deterministic_chaincode(&group);
        assert!(derive_path(&group, &cc, &[]).is_err());
        assert!(derive_path_composite(&group, &cc, &[]).is_err());
    }

    /// A path longer than `MAX_DERIVATION_DEPTH` is refused before doing the
    /// per-index HMAC + EC work, bounding CPU on a wire-supplied path.
    #[test]
    fn overlong_path_refused() {
        let group = stable_group_pubkey();
        let cc = deterministic_chaincode(&group);
        let too_long = vec![0u32; MAX_DERIVATION_DEPTH + 1];
        assert!(derive_path(&group, &cc, &too_long).is_err());
        assert!(derive_path_composite(&group, &cc, &too_long).is_err());
    }

    /// #487 PR2 core: the aggregate scalar tweak returned by
    /// `derive_path_composite` reproduces the same terminal child point as
    /// the stepwise walk. This is the invariant every co-signer relies on
    /// when applying ONE composite tweak to its share instead of walking
    /// the tree per signer.
    #[test]
    fn composite_tweak_reproduces_terminal_child_point() {
        let group = stable_group_pubkey();
        let cc = deterministic_chaincode(&group);
        for path in &[
            &[0u32][..],
            &[1u32][..],
            &[0, 0][..],
            &[0, 1][..],
            &[1, 0][..],
            &[1, 42][..],
            &[0, 100_000][..],
        ] {
            let stepwise = derive_path(&group, &cc, path).unwrap();
            let composite = derive_path_composite(&group, &cc, path).unwrap();

            // Composite and stepwise walks converge on the same terminal
            // (chaincode, x-only child pubkey), so callers of either
            // helper see a consistent tree.
            assert_eq!(
                composite.child_pubkey, stepwise.child_pubkey,
                "path {path:?}: composite child pubkey diverges from stepwise walk"
            );
            assert_eq!(
                composite.terminal_chaincode, stepwise.child_chaincode,
                "path {path:?}: composite chaincode diverges from stepwise walk"
            );

            // The aggregate tweak, applied once to the +even lift of the
            // group pubkey, reproduces the terminal child point. This is
            // the property the FROST signing path (PR 3 of #487) will
            // depend on for its one-tweak-per-share optimisation.
            let secp = Secp256k1::verification_only();
            let parent = even_lift(&group).unwrap();
            let scalar = Scalar::from_be_bytes(composite.aggregate_tweak).unwrap();
            let reproduced = parent.add_exp_tweak(&secp, &scalar).unwrap();
            assert_eq!(
                reproduced.x_only_public_key().0.serialize(),
                composite.child_pubkey,
                "path {path:?}: applying aggregate tweak to +even group does not reproduce child"
            );
        }
    }

    /// The aggregate tweak for a single-step path equals the stepwise
    /// tweak byte-for-byte: the composite walker MUST NOT drift away
    /// from the primitive for the trivial case.
    #[test]
    fn composite_matches_stepwise_tweak_at_depth_one() {
        let group = stable_group_pubkey();
        let cc = deterministic_chaincode(&group);
        for &index in &[0u32, 1, 2, 7, 42, 100_000] {
            let step = derive_child(&group, &cc, index).unwrap();
            let composite = derive_path_composite(&group, &cc, &[index]).unwrap();
            assert_eq!(step.tweak, composite.aggregate_tweak, "index {index}");
        }
    }

    /// Different composite paths must yield different aggregate tweaks:
    /// the whole point of derivation is address (and signing-key) diversity.
    #[test]
    fn composite_tweaks_differ_across_paths() {
        let group = stable_group_pubkey();
        let cc = deterministic_chaincode(&group);
        let a = derive_path_composite(&group, &cc, &[0, 0])
            .unwrap()
            .aggregate_tweak;
        let b = derive_path_composite(&group, &cc, &[0, 1])
            .unwrap()
            .aggregate_tweak;
        let c = derive_path_composite(&group, &cc, &[1, 0])
            .unwrap()
            .aggregate_tweak;
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }
}
