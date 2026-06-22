//! KeepNode threshold-OPRF unlock primitive (frost-gate v2), step 1: the secp256k1 OPRF
//! ciphersuite.
//!
//! RFC 9497 standardizes OPRF/VOPRF but defines no secp256k1 ciphersuite, so we bind the
//! generic 2HashDH construction to secp256k1 by implementing [`voprf::CipherSuite`] over
//! `k256::Secp256k1`. k256's `GroupDigest` provides the RFC 9380
//! `secp256k1_XMD:SHA-256_SSWU_RO_` hash-to-curve, and voprf's `Group` is blanket-implemented
//! for any `GroupDigest`, so no upstream patch is needed.
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
    pub fn split_key(
        secret: &Scalar,
        t: usize,
        n: usize,
        rng: impl rand_core_06::RngCore + rand_core_06::CryptoRng,
    ) -> Result<Vec<KeyShare>, String> {
        vsss_rs::shamir::split_secret::<KeyShare>(t, n, &IdentifierPrimeField(*secret), rng)
            .map_err(|e| format!("split: {e:?}"))
    }

    /// A share-holder's partial evaluation: `P_i = s_i * B`, carrying the same identifier so the
    /// combination knows its Lagrange index. The share `s_i` never leaves the holder.
    pub fn partial_eval(
        share: &KeyShare,
        blinded: &BlindedElement<Secp256k1Sha256>,
    ) -> Result<PartialEval, String> {
        let b = point_from_bytes(blinded.serialize().as_slice())?;
        let s_i: Scalar = **share.value();
        Ok(DefaultShare::with_identifier_and_value(
            *share.identifier(),
            ValueGroup::from(b * s_i),
        ))
    }

    /// Combine >= t partial evaluations into the evaluation element `B^s` (Lagrange in the
    /// exponent, via vsss-rs), then hand back a voprf `EvaluationElement` for `finalize`. The
    /// key is never reconstructed.
    pub fn combine(partials: &[PartialEval]) -> Result<EvaluationElement<Secp256k1Sha256>, String> {
        let bs: ValueGroup<ProjectivePoint> =
            partials.combine().map_err(|e| format!("combine: {e:?}"))?;
        EvaluationElement::deserialize(bs.0.to_encoded_point(true).as_bytes())
            .map_err(|e| format!("deserialize eval: {e:?}"))
    }

    fn point_from_bytes(bytes: &[u8]) -> Result<ProjectivePoint, String> {
        let ep = EncodedPoint::from_bytes(bytes).map_err(|e| format!("encoded point: {e:?}"))?;
        Option::<ProjectivePoint>::from(ProjectivePoint::from_encoded_point(&ep))
            .ok_or_else(|| "bad point".into())
    }
}

/// Derive a 32-byte LUKS key from an OPRF output via HKDF-Expand (RFC 5869).
///
/// The OPRF `Finalize` output is already uniform and high-entropy, so HKDF-Extract is not
/// needed; HKDF-Expand with a domain-separating `info` is sufficient. The `info` separates
/// multiple volumes and supports rotation without changing the OPRF key:
/// `keep-node/luks/v1/<volume_id>/<epoch>`. Feed the result to a LUKS2 keyslot
/// (`cryptsetup luksFormat/open --key-file - --keyfile-size 32`).
pub fn derive_luks_key(oprf_output: &[u8], volume_id: &str, epoch: u32) -> [u8; 32] {
    let info = format!("keep-node/luks/v1/{volume_id}/{epoch}");
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, oprf_output);
    let mut key = [0u8; 32];
    hk.expand(info.as_bytes(), &mut key)
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
            let eval = threshold::combine(&[p_i, p_j]).expect("combine");
            let thresh = b.state.finalize(input, &eval).expect("threshold finalize");
            assert_eq!(
                single, thresh,
                "quorum {{{i},{j}}} must equal the single-key output"
            );

            // End to end: the LUKS key derived from the threshold output matches the single-key
            // one, and is a stable 32 bytes.
            let k_single = derive_luks_key(single.as_slice(), "vault0", 1);
            let k_thresh = derive_luks_key(thresh.as_slice(), "vault0", 1);
            assert_eq!(k_single, k_thresh);
            assert_eq!(k_thresh.len(), 32);
        }
    }

    #[test]
    fn luks_key_derivation_is_stable_and_domain_separated() {
        let out = b"oprf-output-bytes-for-the-kdf-test--";
        let k = derive_luks_key(out, "vault0", 1);
        assert_eq!(k, derive_luks_key(out, "vault0", 1), "stable");
        assert_ne!(
            k,
            derive_luks_key(out, "vault1", 1),
            "separated by volume id"
        );
        assert_ne!(k, derive_luks_key(out, "vault0", 2), "separated by epoch");
    }
}
