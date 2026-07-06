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
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1};

use crate::error::{BitcoinError, Result};

/// Domain separator for the deterministic chaincode. Bumping the version tag
/// invalidates every previously derived child; keep it stable across releases.
const CHAINCODE_DOMAIN: &[u8] = b"keep-frost-bip32-chaincode-v1";

/// BIP-32 says child index >= 2^31 selects hardened derivation, which needs
/// the private key. FROST groups only ever do unhardened public derivation
/// (see the module doc), so every index must live below the hardened bit.
pub const HARDENED_INDEX_START: u32 = 0x8000_0000;

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
        .map_err(|e| BitcoinError::DerivationPath(format!("x-only pubkey not on curve: {e}")))
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
        return Err(BitcoinError::DerivationPath(format!(
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
        BitcoinError::DerivationPath(format!(
            "BIP-32 child tweak >= curve order at index {index}; caller must skip to next index"
        ))
    })?;
    let secp = Secp256k1::verification_only();
    let child_point = parent_point.add_exp_tweak(&secp, &scalar).map_err(|e| {
        BitcoinError::DerivationPath(format!("BIP-32 child tweak produced invalid point: {e}"))
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
        return Err(BitcoinError::DerivationPath(
            "derive_path requires at least one index".into(),
        ));
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
        assert!(matches!(err, BitcoinError::DerivationPath(_)));
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
    }
}
