//! KeepNode threshold-OPRF unlock primitive (frost-gate v2), step 1: the secp256k1 OPRF
//! ciphersuite.
//!
//! RFC 9497 standardizes OPRF/VOPRF but defines no secp256k1 ciphersuite, so we bind the
//! generic 2HashDH construction to secp256k1 by implementing [`voprf::CipherSuite`] over
//! `k256::Secp256k1`. k256's `GroupDigest` (the `hash2curve` feature) provides the RFC 9380
//! `secp256k1_XMD:SHA-256_SSWU_RO_` hash-to-curve. voprf 0.5 implements `Group` for any `C`
//! where `C: GroupDigest` and `ProjectivePoint<C>: CofactorGroup + ToEncodedPoint<C>`;
//! `k256::Secp256k1` with `hash2curve` satisfies those bounds, so no upstream patch is needed.
//!
//! The suite `ID` is KeepNode-specific (no standard secp256k1 suite exists) and MUST be
//! pinned: it feeds the RFC 9497 context string / DST, so changing it changes every derived
//! key. This module is the single-server primitive only; the 2-of-3 threshold layer (Shamir
//! key-sharing + Lagrange combination + DLEQ verifiability) lands on top of it.
//!
//! Design + threat model: see SPIKE-frost-unlock-v2.

use voprf::CipherSuite;

/// KeepNode's secp256k1 OPRF ciphersuite: the RFC 9497 construction on secp256k1 with SHA-256.
#[derive(Debug, Clone, Copy)]
pub struct Secp256k1Sha256;

impl CipherSuite for Secp256k1Sha256 {
    const ID: &'static str = "secp256k1-SHA256";
    type Group = k256::Secp256k1;
    // sha2 0.10 to match voprf's digest 0.10 ecosystem (see Cargo.toml note).
    type Hash = sha2_010::Sha256;
}

/// 2-of-3 (configurable t-of-n) threshold layer over the secp256k1 OPRF.
///
/// The OPRF key is Shamir-shared across the share-holders (box / phone / replica). Each holder
/// returns a partial evaluation `s_i * B` of the client's blinded element `B`; a quorum is
/// combined in the exponent (Lagrange) to `B^s` WITHOUT reconstructing the key. The combined
/// element is fed back into voprf's unchanged `finalize`.
///
/// Vetted libraries do the dangerous parts: `vsss-rs` for the Shamir split and the in-exponent
/// Lagrange combination (`combine_shares_group`), `k256` for the group arithmetic, `voprf` for
/// blind/finalize. The only bespoke step is `s_i * B`.
///
/// DLEQ verifiability (a per-partial proof that a share-holder used its committed share) is a
/// deliberate follow-on, NOT a security gate for the core guarantee: a wrong partial yields a
/// wrong combined `B^s`, hence a wrong derived key, which LUKS rejects at the keyslot digest
/// check. So a misbehaving share-holder (a compromised own-device) causes a *failed unlock*,
/// never a key leak or silent corruption. DLEQ upgrades that fail-safe into a diagnosable,
/// DoS-resistant one; it does not change what an attacker can learn.
pub mod threshold {
    use super::Secp256k1Sha256;
    use crate::error::CryptoError;
    use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use k256::{EncodedPoint, ProjectivePoint, Scalar};
    use voprf::{BlindedElement, EvaluationElement};
    use vsss_rs::{
        DefaultShare, IdentifierPrimeField, ReadableShareSet, Share, ValueGroup, ValuePrimeField,
    };

    type Id = IdentifierPrimeField<Scalar>;
    /// A scalar share of the OPRF key (held by a box / phone / replica).
    pub type KeyShare = DefaultShare<Id, ValuePrimeField<Scalar>>;
    /// A share-holder's partial evaluation `s_i * B` (a group element, same identifier).
    pub type PartialEval = DefaultShare<Id, ValueGroup<ProjectivePoint>>;

    /// Split an OPRF key into `n` shares with threshold `t` over secp256k1's scalar field.
    ///
    /// SECURITY (caller contract): the returned [`KeyShare`]s hold plaintext scalar key shares.
    /// `KeyShare` is `Copy` and implements `Zeroize` but NOT `ZeroizeOnDrop`, so dropping a share
    /// (or any copy of one) leaves the secret scalar in memory. The caller OWNS the returned
    /// shares and MUST `zeroize()` each one (and any copy) once it is distributed to its holder.
    /// Treat each share as live key material until then.
    pub fn split_key(
        secret: &Scalar,
        t: usize,
        n: usize,
        rng: impl rand_core_06::RngCore + rand_core_06::CryptoRng,
    ) -> Result<Vec<KeyShare>, CryptoError> {
        use zeroize::Zeroize;
        // Our transient copy of the key; zeroize it once split. (The caller owns the original
        // `secret` and the returned shares, and is responsible for their secure handling.)
        let mut wrapped = IdentifierPrimeField(*secret);
        let res = vsss_rs::shamir::split_secret::<KeyShare>(t, n, &wrapped, rng)
            .map_err(|_| CryptoError::key_derivation("OPRF Shamir key split failed"));
        wrapped.0.zeroize();
        res
    }

    /// A share-holder's partial evaluation: `P_i = s_i * B`, carrying the same identifier so the
    /// combination knows its Lagrange index. The share `s_i` never leaves the holder.
    ///
    /// SECURITY: the transport layer that exposes this evaluation oracle to clients MUST enforce
    /// per-identity authentication and strict rate limiting. The OPRF-unlock's resistance to
    /// low-entropy-input guessing depends on bounding the number of evaluations an attacker can
    /// obtain; an unbounded or unauthenticated oracle reduces it to an offline brute force.
    pub fn partial_eval(
        share: &KeyShare,
        blinded: &BlindedElement<Secp256k1Sha256>,
    ) -> Result<PartialEval, CryptoError> {
        use zeroize::Zeroize;
        let b = point_from_bytes(blinded.serialize().as_slice())?;
        let mut s_i: Scalar = **share.value();
        let p_i = b * s_i;
        s_i.zeroize();
        Ok(DefaultShare::with_identifier_and_value(
            *share.identifier(),
            ValueGroup::from(p_i),
        ))
    }

    /// Combine partial evaluations into the evaluation element `B^s` (Lagrange in the exponent,
    /// via vsss-rs), then hand back a voprf `EvaluationElement` for `finalize`. The key is never
    /// reconstructed.
    ///
    /// `threshold` MUST equal the `t` passed to [`split_key`]. This check is defense-in-depth, not
    /// the security boundary: with fewer than `t` partials Shamir interpolates a wrong key, which
    /// yields a wrong derived key that LUKS rejects at the keyslot digest. vsss-rs `combine()`
    /// already rejects zero/duplicate identifiers and fewer than two shares, so no extra dedup is
    /// done here.
    pub fn combine(
        partials: &[PartialEval],
        threshold: usize,
    ) -> Result<EvaluationElement<Secp256k1Sha256>, CryptoError> {
        if partials.len() < threshold {
            return Err(CryptoError::invalid_key(
                "OPRF combine: fewer partial evaluations than the configured threshold",
            ));
        }
        let bs: ValueGroup<ProjectivePoint> = partials.combine().map_err(|_| {
            CryptoError::key_derivation("OPRF partial-evaluation combination failed")
        })?;
        EvaluationElement::deserialize(bs.0.to_encoded_point(true).as_bytes())
            .map_err(|_| CryptoError::invalid_key("OPRF combined evaluation element is invalid"))
    }

    pub(crate) fn point_from_bytes(bytes: &[u8]) -> Result<ProjectivePoint, CryptoError> {
        use k256::elliptic_curve::group::Group;
        let ep = EncodedPoint::from_bytes(bytes)
            .map_err(|_| CryptoError::invalid_key("OPRF point: malformed SEC1 encoding"))?;
        let p = Option::<ProjectivePoint>::from(ProjectivePoint::from_encoded_point(&ep))
            .ok_or_else(|| CryptoError::invalid_key("OPRF point: not a valid curve point"))?;
        // Defense in depth: reject the identity (the sole caller already passes voprf-validated
        // bytes, but never let an identity element through if this is reused on raw input).
        if bool::from(p.is_identity()) {
            return Err(CryptoError::invalid_key(
                "OPRF point: identity element rejected",
            ));
        }
        Ok(p)
    }
}

/// Derive a 32-byte LUKS key from an OPRF output via HKDF (RFC 5869).
///
/// `Hkdf::new(None, ...)` runs HKDF-Extract with a zero salt, then Expand. The OPRF `Finalize`
/// output is already a uniform SHA-256 PRF value, so Extract is not strictly required, but a
/// zero-salt Extract is sound. The `info` is built INJECTIVELY (length-prefixed) so two distinct
/// `(volume_id, epoch)` pairs can never collide into the same key: a fixed label, then the
/// big-endian length of `volume_id`, then `volume_id`, then the big-endian `epoch`. This
/// separates multiple volumes and supports rotation without changing the OPRF key. Feed the
/// result to a LUKS2 keyslot (`cryptsetup luksFormat/open --key-file - --keyfile-size 32`).
pub fn derive_luks_key(
    oprf_output: &[u8],
    volume_id: &str,
    epoch: u32,
) -> zeroize::Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(25 + volume_id.len() + 4);
    info.extend_from_slice(b"keep-node/luks/v1");
    info.extend_from_slice(&(volume_id.len() as u64).to_be_bytes());
    info.extend_from_slice(volume_id.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());
    // hkdf 0.12 exposes no handle to the extracted PRK held inside `Hkdf` and does not zeroize it
    // on drop, so the PRK cannot be wiped cleanly here. Acceptable for a spike: the PRK is a
    // one-way HKDF-Extract of the already-uniform OPRF output, not the OPRF key itself.
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, oprf_output);
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut key[..])
        .expect("32 bytes is within HKDF output limit");
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use voprf::{OprfClient, OprfServer};

    /// Full single-server OPRF round-trip on secp256k1: blind -> blind_evaluate -> finalize.
    /// The same input under the same key must reproduce the same output (the PRF property the
    /// LUKS key derivation relies on), while a different input must not.
    #[test]
    fn secp256k1_oprf_round_trip() {
        // rand_core 0.6 OsRng to match voprf's rng traits (digest 0.10 ecosystem).
        let mut rng = rand_core_06::OsRng;
        let input: &[u8] = b"keep-node-vault-v1";

        let server = OprfServer::<Secp256k1Sha256>::new(&mut rng).expect("server key");

        let b1 = OprfClient::<Secp256k1Sha256>::blind(input, &mut rng).expect("blind");
        let e1 = server.blind_evaluate(&b1.message);
        let out1 = b1.state.finalize(input, &e1).expect("finalize");

        // Fresh blind, same key + input -> same OPRF output (stable derived key).
        let b2 = OprfClient::<Secp256k1Sha256>::blind(input, &mut rng).expect("blind");
        let e2 = server.blind_evaluate(&b2.message);
        let out2 = b2.state.finalize(input, &e2).expect("finalize");
        assert_eq!(
            out1, out2,
            "same input + key must give a stable OPRF output"
        );

        // Different input -> different output.
        let other: &[u8] = b"keep-node-other";
        let b3 = OprfClient::<Secp256k1Sha256>::blind(other, &mut rng).expect("blind");
        let e3 = server.blind_evaluate(&b3.message);
        let out3 = b3.state.finalize(other, &e3).expect("finalize");
        assert_ne!(out1, out3, "different input must give a different output");
    }

    /// Correctness oracle for the threshold layer: for the SAME blinded element, the 2-of-3
    /// threshold combination must produce exactly the same OPRF output as a single-key server
    /// holding the un-split key, for every quorum pair. If they match, the in-exponent Lagrange
    /// combination is correct and no party ever reconstructed the key.
    #[test]
    fn threshold_matches_single_key() {
        use k256::Scalar;
        let mut rng = rand_core_06::OsRng;
        let input: &[u8] = b"keep-node-vault-v1";

        // One key, two ways: a single-key voprf server, and a 2-of-3 Shamir split of the same key.
        let s = <Scalar as k256::elliptic_curve::Field>::random(&mut rng);
        let server = OprfServer::<Secp256k1Sha256>::new_with_key(s.to_bytes().as_slice())
            .expect("server from key");
        let shares = threshold::split_key(&s, 2, 3, &mut rng).expect("split");
        assert_eq!(shares.len(), 3);

        // One blind; evaluate it both ways and finalize with the same client state.
        let b = OprfClient::<Secp256k1Sha256>::blind(input, &mut rng).expect("blind");
        let single = b
            .state
            .finalize(input, &server.blind_evaluate(&b.message))
            .expect("single finalize");

        for (i, j) in [(0, 1), (0, 2), (1, 2)] {
            let p_i = threshold::partial_eval(&shares[i], &b.message).expect("partial i");
            let p_j = threshold::partial_eval(&shares[j], &b.message).expect("partial j");
            let eval = threshold::combine(&[p_i, p_j], 2).expect("combine");
            let thresh = b.state.finalize(input, &eval).expect("threshold finalize");
            assert_eq!(
                single, thresh,
                "quorum {{{i},{j}}} must equal the single-key output"
            );

            // End to end: the LUKS key derived from the threshold output matches the single-key
            // one, and is a stable 32 bytes.
            let k_single = derive_luks_key(single.as_slice(), "vault0", 1);
            let k_thresh = derive_luks_key(thresh.as_slice(), "vault0", 1);
            assert_eq!(*k_single, *k_thresh);
            assert_eq!(k_thresh.len(), 32);
        }
    }

    #[test]
    fn luks_key_derivation_is_stable_and_domain_separated() {
        let out = b"oprf-output-bytes-for-the-kdf-test--";
        let k = derive_luks_key(out, "vault0", 1);
        assert_eq!(*k, *derive_luks_key(out, "vault0", 1), "stable");
        assert_ne!(
            *k,
            *derive_luks_key(out, "vault1", 1),
            "separated by volume id"
        );
        assert_ne!(*k, *derive_luks_key(out, "vault0", 2), "separated by epoch");
        // Injectivity: a volume_id containing the old '/' separator must NOT collide with a
        // different (volume_id, epoch) pair (the length-prefixed info prevents this).
        assert_ne!(
            *derive_luks_key(out, "a/b", 1),
            *derive_luks_key(out, "a", 1),
            "length-prefixed info is injective over volume_id"
        );
    }

    /// Fail-safe: a quorum that mixes in a share from a DIFFERENT key (a foreign/wrong share)
    /// must produce a different combined evaluation, hence a different OPRF output and a different
    /// derived LUKS key, than the correct quorum. This validates the documented "wrong partial =>
    /// wrong key, LUKS rejects" guarantee.
    #[test]
    fn foreign_share_yields_different_key() {
        use k256::Scalar;
        let mut rng = rand_core_06::OsRng;
        let input: &[u8] = b"keep-node-vault-v1";

        let s = <Scalar as k256::elliptic_curve::Field>::random(&mut rng);
        let shares = threshold::split_key(&s, 2, 3, &mut rng).expect("split");

        // A second, independent key split with the SAME identifiers/threshold/n.
        let s_other = <Scalar as k256::elliptic_curve::Field>::random(&mut rng);
        let shares_other = threshold::split_key(&s_other, 2, 3, &mut rng).expect("split other");

        // One blind; evaluate the correct and the mixed quorum against the SAME blinded element
        // and finalize both with the same client state.
        let b = OprfClient::<Secp256k1Sha256>::blind(input, &mut rng).expect("blind");

        // Correct quorum {0,1} from the real key.
        let good = threshold::combine(
            &[
                threshold::partial_eval(&shares[0], &b.message).expect("p0"),
                threshold::partial_eval(&shares[1], &b.message).expect("p1"),
            ],
            2,
        )
        .expect("combine good");

        // Mixed quorum: one real share + one foreign share (a wrong/compromised holder). Still a
        // valid group element, just interpolating the wrong key.
        let bad = threshold::combine(
            &[
                threshold::partial_eval(&shares[0], &b.message).expect("p0"),
                threshold::partial_eval(&shares_other[1], &b.message).expect("p1 foreign"),
            ],
            2,
        )
        .expect("combine bad");

        let out_good = b.state.finalize(input, &good).expect("finalize good");
        let out_bad = b.state.finalize(input, &bad).expect("finalize bad");

        assert_ne!(
            out_good, out_bad,
            "a foreign share in the quorum must change the OPRF output"
        );
        assert_ne!(
            *derive_luks_key(out_good.as_slice(), "vault0", 1),
            *derive_luks_key(out_bad.as_slice(), "vault0", 1),
            "a foreign share must change the derived LUKS key (LUKS would reject it)"
        );
    }

    /// `combine` with fewer partials than the configured threshold must return Err.
    #[test]
    fn combine_below_threshold_errors() {
        use k256::Scalar;
        let mut rng = rand_core_06::OsRng;
        let input: &[u8] = b"keep-node-vault-v1";

        let s = <Scalar as k256::elliptic_curve::Field>::random(&mut rng);
        let shares = threshold::split_key(&s, 2, 3, &mut rng).expect("split");
        let b = OprfClient::<Secp256k1Sha256>::blind(input, &mut rng).expect("blind");
        let p0 = threshold::partial_eval(&shares[0], &b.message).expect("p0");

        assert!(
            threshold::combine(&[p0], 2).is_err(),
            "a single partial against threshold 2 must be rejected"
        );
    }

    /// `split_key` with invalid parameters (t > n, t < 2) must return Err.
    #[test]
    fn split_key_rejects_invalid_params() {
        use k256::Scalar;
        let mut rng = rand_core_06::OsRng;
        let s = <Scalar as k256::elliptic_curve::Field>::random(&mut rng);

        assert!(
            threshold::split_key(&s, 4, 3, &mut rng).is_err(),
            "t > n must be rejected"
        );
        assert!(
            threshold::split_key(&s, 1, 3, &mut rng).is_err(),
            "t < 2 must be rejected"
        );
    }

    /// `point_from_bytes` (exercised via `partial_eval`'s point parsing) must reject malformed and
    /// identity encodings. We test the parser directly through a crafted blinded-element path:
    /// the identity point and garbage bytes must both fail to decode to a usable curve point.
    #[test]
    fn point_parsing_rejects_bad_and_identity() {
        use k256::elliptic_curve::group::Group;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::ProjectivePoint;

        // Identity (point at infinity) encodes to a single 0x00 byte in SEC1 and from_encoded_point
        // accepts it, so point_from_bytes' explicit identity rejection is what must guard this case.
        let id_bytes = <ProjectivePoint as Group>::identity().to_encoded_point(true);
        assert!(
            threshold::point_from_bytes(id_bytes.as_bytes()).is_err(),
            "identity element must be rejected by point_from_bytes"
        );

        // Garbage compressed point: valid prefix tag, but x is not on the curve.
        let mut garbage = [0u8; 33];
        garbage[0] = 0x02;
        garbage[1..].fill(0xff);
        assert!(
            threshold::point_from_bytes(&garbage).is_err(),
            "an off-curve x must be rejected by point_from_bytes"
        );
    }
}
