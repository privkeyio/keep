//! Threshold Oblivious PRF over secp256k1, for deriving a symmetric key from a t-of-n quorum
//! without any single party reconstructing the key.
//!
//! RFC 9497 standardizes the OPRF/VOPRF construction but defines no secp256k1 ciphersuite, so the
//! generic 2HashDH construction is bound to secp256k1 by implementing [`voprf::CipherSuite`] over
//! `k256::Secp256k1`. k256's `GroupDigest` (the `hash2curve` feature) provides the RFC 9380
//! `secp256k1_XMD:SHA-256_SSWU_RO_` hash-to-curve. voprf implements `Group` for any `C` where
//! `C: GroupDigest` and `ProjectivePoint<C>: CofactorGroup + ToEncodedPoint<C>`, which
//! `k256::Secp256k1` satisfies, so no upstream changes are required.
//!
//! The suite `ID` is non-standard (RFC 9497 defines no secp256k1 suite) and is pinned here. It
//! feeds the RFC 9497 context string / DST, so it must never change once it has derived keys that
//! protect data: changing it changes every derived key.
//!
//! This module provides the ciphersuite, the [`threshold`] layer (Shamir-shared key, in-exponent
//! Lagrange combination of partial evaluations), and [`derive_luks_key`].

use voprf::CipherSuite;

/// The secp256k1 OPRF ciphersuite: the RFC 9497 construction on secp256k1 with SHA-256.
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

    /// Wire layout of a serialized partial: a 32-byte identifier scalar followed by a 33-byte
    /// compressed point. Named once so `serialize_partial`/`deserialize_partial` can't drift.
    pub(super) const ID_LEN: usize = 32;
    const POINT_LEN: usize = 33;
    /// Total serialized-partial length (`ID_LEN + POINT_LEN`).
    pub(super) const PARTIAL_LEN: usize = ID_LEN + POINT_LEN;
    /// Serialized SECRET key-share length: a 32-byte identifier scalar followed by a 32-byte
    /// value scalar (`ID_LEN + ID_LEN`).
    pub const KEY_SHARE_LEN: usize = ID_LEN + ID_LEN;

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
        use k256::elliptic_curve::group::Group;
        use zeroize::Zeroize;
        let b = point_from_bytes(blinded.serialize().as_slice())?;
        let mut s_i: Scalar = **share.value();
        let p_i = b * s_i;
        s_i.zeroize();
        // Unreachable today (`b` is non-identity and `s_i` non-zero on a prime-order curve), but
        // guard so an identity partial can never reach the fixed-size `serialize_partial`.
        if bool::from(p_i.is_identity()) {
            return Err(CryptoError::invalid_key(
                "OPRF partial: identity evaluation rejected",
            ));
        }
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

    /// Wire encoding of a partial evaluation: the 32-byte identifier scalar (the Shamir
    /// x-coordinate, needed for the Lagrange combine) followed by the 33-byte compressed point
    /// `s_i * B`. The point reveals nothing about `s_i` (discrete log), so this is not secret.
    pub(super) fn serialize_partial(p: &PartialEval) -> [u8; PARTIAL_LEN] {
        use k256::elliptic_curve::PrimeField;
        let mut out = [0u8; PARTIAL_LEN];
        out[..ID_LEN].copy_from_slice(p.identifier().0.to_repr().as_slice());
        out[ID_LEN..].copy_from_slice(p.value().0.to_encoded_point(true).as_bytes());
        out
    }

    /// Inverse of [`serialize_partial`]. A forged identifier or point only interpolates the wrong
    /// key (LUKS rejects it); it cannot leak key material, consistent with the module's fail-safe
    /// model. Identity points are rejected by [`point_from_bytes`].
    pub(super) fn deserialize_partial(bytes: &[u8]) -> Result<PartialEval, CryptoError> {
        use k256::elliptic_curve::PrimeField;
        if bytes.len() != PARTIAL_LEN {
            return Err(CryptoError::invalid_key("OPRF partial: wrong length"));
        }
        let mut repr = k256::FieldBytes::default();
        repr.copy_from_slice(&bytes[..ID_LEN]);
        let id = Option::<Scalar>::from(Scalar::from_repr(repr))
            .ok_or_else(|| CryptoError::invalid_key("OPRF partial: non-canonical identifier"))?;
        // Reject the zero identifier (the secret's own evaluation point) explicitly at this trust
        // boundary rather than relying on `combine()`'s internal zero/duplicate rejection.
        if bool::from(id.is_zero()) {
            return Err(CryptoError::invalid_key("OPRF partial: zero identifier"));
        }
        let point = point_from_bytes(&bytes[ID_LEN..])?;
        Ok(DefaultShare::with_identifier_and_value(
            IdentifierPrimeField(id),
            ValueGroup::from(point),
        ))
    }

    /// Parse a canonical secp256k1 scalar from its 32-byte big-endian representation, zeroizing the
    /// transient buffer (the bytes may be secret key material). Rejects a non-canonical encoding.
    fn scalar_from_repr(b: &[u8]) -> Result<Scalar, CryptoError> {
        use k256::elliptic_curve::PrimeField;
        use zeroize::Zeroize;
        let mut repr = k256::FieldBytes::default();
        repr.copy_from_slice(b);
        let s = Option::<Scalar>::from(Scalar::from_repr(repr));
        repr.as_mut_slice().zeroize();
        s.ok_or_else(|| CryptoError::invalid_key("OPRF: non-canonical scalar"))
    }

    /// Serialize a SECRET key share: the 32-byte identifier scalar followed by the 32-byte value
    /// scalar.
    ///
    /// SECURITY: the output is live key material (the holder's Shamir share). The returned buffer
    /// is `Zeroizing`, but any copy the caller makes (when sealing to the TPM or placing it in an
    /// enrollment message) MUST itself be zeroized once consumed. Used to TPM-seal the box's share
    /// and to carry a share inside the separately encrypted enrollment message.
    pub fn serialize_key_share(share: &KeyShare) -> zeroize::Zeroizing<[u8; KEY_SHARE_LEN]> {
        use k256::elliptic_curve::PrimeField;
        let mut out = zeroize::Zeroizing::new([0u8; KEY_SHARE_LEN]);
        out[..ID_LEN].copy_from_slice(share.identifier().0.to_repr().as_slice());
        out[ID_LEN..].copy_from_slice((**share.value()).to_repr().as_slice());
        out
    }

    /// Inverse of [`serialize_key_share`]. Rejects a wrong length, a non-canonical scalar, or a
    /// zero identifier (Shamir's `x = 0` is the secret's own point, never a valid share index).
    pub fn deserialize_key_share(bytes: &[u8]) -> Result<KeyShare, CryptoError> {
        if bytes.len() != KEY_SHARE_LEN {
            return Err(CryptoError::invalid_key("OPRF key share: wrong length"));
        }
        let id = scalar_from_repr(&bytes[..ID_LEN])?;
        if bool::from(id.is_zero()) {
            return Err(CryptoError::invalid_key("OPRF key share: zero identifier"));
        }
        let value = scalar_from_repr(&bytes[ID_LEN..])?;
        // `ValuePrimeField` is a type alias for `IdentifierPrimeField`, so the value wrapper is
        // constructed with the same tuple struct.
        Ok(DefaultShare::with_identifier_and_value(
            IdentifierPrimeField(id),
            IdentifierPrimeField(value),
        ))
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
    // The `hkdf` crate exposes no handle to the extracted PRK held inside `Hkdf` and does not
    // zeroize it on drop, so the PRK is not wiped here. The PRK is a one-way HKDF-Extract of the
    // already-uniform OPRF output, not the OPRF key, so it exposes no recoverable key material.
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, oprf_output);
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut key[..])
        .expect("32 bytes is within HKDF output limit");
    key
}

/// Byte-oriented client/holder API for the threshold-OPRF unlock.
///
/// Keeps the voprf/vsss/k256 stack behind an opaque-bytes boundary so a transport
/// (`keep-frost-net`) and callers (`keep-node`) shuttle wire bytes without depending on the OPRF
/// crate ecosystem. The box is the client ([`blind`] then [`Client::finalize_luks_key`]); the
/// box / phone / replica are holders ([`evaluate`]). No holder, and not the client, ever
/// reconstructs the key.
pub mod unlock {
    use super::derive_luks_key;
    use super::threshold::{self, KeyShare};
    use super::Secp256k1Sha256;
    use crate::error::CryptoError;
    use voprf::{BlindedElement, OprfClient};

    /// Client state for one unlock attempt: the voprf blinding secret plus the unlock input,
    /// both needed at [`Client::finalize_luks_key`]. The input is a fixed, low-entropy label, so
    /// the eval oracle MUST be authenticated and rate-limited (see [`evaluate`]).
    pub struct Client {
        state: OprfClient<Secp256k1Sha256>,
        input: Vec<u8>,
    }

    /// Blind the unlock `input`. Returns the [`Client`] (kept until finalize) and the wire bytes
    /// of the blinded element to send to each holder.
    pub fn blind(input: &[u8]) -> Result<(Client, Vec<u8>), CryptoError> {
        let mut rng = rand_core_06::OsRng;
        let res = OprfClient::<Secp256k1Sha256>::blind(input, &mut rng)
            .map_err(|_| CryptoError::key_derivation("OPRF blind failed"))?;
        Ok((
            Client {
                state: res.state,
                input: input.to_vec(),
            },
            res.message.serialize().to_vec(),
        ))
    }

    impl Client {
        /// Combine holder partial evaluations (each as wire bytes from [`evaluate`]) into the OPRF
        /// output and derive the 32-byte LUKS key. `threshold` MUST equal the `t` used at split.
        pub fn finalize_luks_key(
            &self,
            partials: &[impl AsRef<[u8]>],
            threshold: usize,
            volume_id: &str,
            epoch: u32,
        ) -> Result<zeroize::Zeroizing<[u8; 32]>, CryptoError> {
            let parts = partials
                .iter()
                .map(|p| threshold::deserialize_partial(p.as_ref()))
                .collect::<Result<Vec<_>, _>>()?;
            let eval = threshold::combine(&parts, threshold)?;
            let out = self
                .state
                .finalize(&self.input, &eval)
                .map_err(|_| CryptoError::key_derivation("OPRF finalize failed"))?;
            Ok(derive_luks_key(out.as_slice(), volume_id, epoch))
        }
    }

    /// Holder side: evaluate the client's blinded element (wire bytes from [`blind`]) with this
    /// holder's key share, returning the partial evaluation as wire bytes. The share never leaves
    /// the holder.
    ///
    /// SECURITY: the transport exposing this oracle MUST authenticate the caller and strictly
    /// rate-limit it. Bounding evaluations is what keeps the fixed, low-entropy unlock input from
    /// being brute-forced offline (see [`super::threshold::partial_eval`]).
    pub fn evaluate(
        share: &KeyShare,
        blinded: &[u8],
    ) -> Result<[u8; threshold::PARTIAL_LEN], CryptoError> {
        let be = BlindedElement::<Secp256k1Sha256>::deserialize(blinded)
            .map_err(|_| CryptoError::invalid_key("OPRF blinded element: malformed"))?;
        let partial = threshold::partial_eval(share, &be)?;
        Ok(threshold::serialize_partial(&partial))
    }

    /// Provision a fresh OPRF key for a new volume: generate a random key, split it `t`-of-`n`, and
    /// derive the 32-byte LUKS key it produces for `(input, volume_id, epoch)`.
    ///
    /// The LUKS key is derived through the quorum path using the freshly split shares (`t` partials
    /// combined in the exponent), so it is identical to the key every future 2-of-3 unlock will
    /// derive, by construction. The transient secret is zeroized before returning.
    ///
    /// SECURITY: the returned shares are live key material; the caller OWNS them and MUST zeroize
    /// each once it is sealed (the box's own share) or distributed to its holder (see
    /// [`threshold::split_key`]). The returned LUKS key is `Zeroizing`.
    pub fn provision(
        input: &[u8],
        volume_id: &str,
        epoch: u32,
        t: usize,
        n: usize,
    ) -> Result<(zeroize::Zeroizing<[u8; 32]>, Vec<KeyShare>), CryptoError> {
        use k256::elliptic_curve::Field;
        use k256::Scalar;
        use zeroize::Zeroize;

        let mut rng = rand_core_06::OsRng;
        let mut secret = Scalar::random(&mut rng);
        let split = threshold::split_key(&secret, t, n, rng);
        // The secret is no longer needed once split: the shares carry it (t-of-n). Wipe our copy
        // regardless of whether the split succeeded.
        secret.zeroize();
        let shares = split?;

        // Derive K_luks via the quorum path with our own shares, so it matches a future unlock.
        let (client, blinded) = blind(input)?;
        let mut partials = Vec::with_capacity(t);
        for share in shares.iter().take(t) {
            partials.push(evaluate(share, &blinded)?.to_vec());
        }
        let k_luks = client.finalize_luks_key(&partials, t, volume_id, epoch)?;
        Ok((k_luks, shares))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use voprf::{OprfClient, OprfServer};

    /// One key, two ways: a single-key voprf server and a 2-of-3 Shamir split of the SAME key, for
    /// the tests that cross-check the threshold path against the un-split key.
    fn single_key_server_and_2of3_shares() -> (OprfServer<Secp256k1Sha256>, Vec<threshold::KeyShare>)
    {
        use k256::Scalar;
        let mut rng = rand_core_06::OsRng;
        let s = <Scalar as k256::elliptic_curve::Field>::random(&mut rng);
        let server = OprfServer::<Secp256k1Sha256>::new_with_key(s.to_bytes().as_slice())
            .expect("server from key");
        let shares = threshold::split_key(&s, 2, 3, &mut rng).expect("split");
        (server, shares)
    }

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
        let mut rng = rand_core_06::OsRng;
        let input: &[u8] = b"keep-node-vault-v1";

        let (server, shares) = single_key_server_and_2of3_shares();
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

    /// End-to-end through the byte-oriented [`unlock`] API: for every 2-of-3 quorum, the LUKS key
    /// derived from `blind -> evaluate (wire bytes) -> finalize_luks_key` must equal the key from a
    /// single-key server holding the un-split key. This exercises the wire serialization of the
    /// blinded element and the partial evaluations, with a fresh blind per quorum.
    #[test]
    fn unlock_wire_api_matches_single_key() {
        let mut rng = rand_core_06::OsRng;
        let input: &[u8] = b"keep-node-vault-v1";

        let (server, shares) = single_key_server_and_2of3_shares();

        let b = OprfClient::<Secp256k1Sha256>::blind(input, &mut rng).expect("blind");
        let single = b
            .state
            .finalize(input, &server.blind_evaluate(&b.message))
            .expect("single finalize");
        let k_single = derive_luks_key(single.as_slice(), "vault0", 1);

        for (i, j) in [(0, 1), (0, 2), (1, 2)] {
            let (client, wire) = unlock::blind(input).expect("blind");
            let p_i = unlock::evaluate(&shares[i], &wire).expect("eval i");
            let p_j = unlock::evaluate(&shares[j], &wire).expect("eval j");
            let k = client
                .finalize_luks_key(&[p_i, p_j], 2, "vault0", 1)
                .expect("finalize");
            assert_eq!(
                *k, *k_single,
                "quorum {{{i},{j}}} via wire API must match single key"
            );
        }
    }

    /// The holder oracle must reject a malformed blinded element, and finalize must reject a
    /// malformed partial (wrong length / off-curve point), rather than panic.
    #[test]
    fn unlock_wire_api_rejects_malformed_input() {
        use k256::Scalar;
        let mut rng = rand_core_06::OsRng;
        let s = <Scalar as k256::elliptic_curve::Field>::random(&mut rng);
        let shares = threshold::split_key(&s, 2, 3, &mut rng).expect("split");

        assert!(
            unlock::evaluate(&shares[0], &[0u8; 10]).is_err(),
            "malformed blinded element must be rejected"
        );

        let (client, wire) = unlock::blind(b"keep-node-vault-v1").expect("blind");
        let good = unlock::evaluate(&shares[0], &wire).expect("eval");
        assert!(
            client
                .finalize_luks_key(&[good.to_vec(), vec![0u8; 10]], 2, "vault0", 1)
                .is_err(),
            "a wrong-length partial must be rejected"
        );

        // A correct-length partial carrying an off-curve point (the deserialize path that the
        // wrong-length branch above does not reach) must also be rejected, not panic.
        let mut bad_point = good;
        bad_point[threshold::ID_LEN] = 0x02; // valid compressed prefix...
        bad_point[threshold::ID_LEN + 1..].fill(0xff); // ...over an x that is not on the curve
        assert!(
            client
                .finalize_luks_key(&[good.to_vec(), bad_point.to_vec()], 2, "vault0", 1)
                .is_err(),
            "a correct-length partial with an off-curve point must be rejected"
        );
    }

    /// Security: a single compromised holder must not be able to forge a quorum by replaying its
    /// own partial. Two partials with the SAME identifier must be rejected by the combine (vsss-rs
    /// rejects duplicate identifiers), so finalize must `Err` rather than derive a key.
    #[test]
    fn unlock_wire_api_rejects_duplicate_identifier() {
        use k256::Scalar;
        let mut rng = rand_core_06::OsRng;
        let s = <Scalar as k256::elliptic_curve::Field>::random(&mut rng);
        let shares = threshold::split_key(&s, 2, 3, &mut rng).expect("split");

        let (client, wire) = unlock::blind(b"keep-node-vault-v1").expect("blind");
        let p0 = unlock::evaluate(&shares[0], &wire).expect("eval");
        assert!(
            client.finalize_luks_key(&[p0, p0], 2, "vault0", 1).is_err(),
            "a replayed partial (duplicate identifier) must not forge a quorum"
        );
    }

    /// `provision` returns a LUKS key that every 2-of-3 quorum unlock with the produced shares
    /// reproduces, so the volume formatted at provisioning time opens on every future unlock.
    #[test]
    fn provision_matches_every_quorum_unlock() {
        let input: &[u8] = b"keep-node-vault-v1";
        let (k_luks, shares) = unlock::provision(input, "vault0", 1, 2, 3).expect("provision");
        assert_eq!(shares.len(), 3);
        assert_eq!(k_luks.len(), 32);

        for (i, j) in [(0, 1), (0, 2), (1, 2)] {
            let (client, blinded) = unlock::blind(input).expect("blind");
            let pi = unlock::evaluate(&shares[i], &blinded).expect("pi");
            let pj = unlock::evaluate(&shares[j], &blinded).expect("pj");
            let k = client
                .finalize_luks_key(&[pi.to_vec(), pj.to_vec()], 2, "vault0", 1)
                .expect("finalize");
            assert_eq!(
                *k, *k_luks,
                "quorum {{{i},{j}}} must reproduce the provisioned LUKS key"
            );
        }
    }

    /// A key share that is serialized then deserialized must behave identically to the original:
    /// it produces the same partial evaluation. Malformed encodings are rejected.
    #[test]
    fn key_share_serialization_round_trips() {
        use k256::Scalar;
        let mut rng = rand_core_06::OsRng;
        let input: &[u8] = b"keep-node-vault-v1";
        let s = <Scalar as k256::elliptic_curve::Field>::random(&mut rng);
        let shares = threshold::split_key(&s, 2, 3, &mut rng).expect("split");
        let b = OprfClient::<Secp256k1Sha256>::blind(input, &mut rng).expect("blind");

        for share in &shares {
            let bytes = threshold::serialize_key_share(share);
            assert_eq!(bytes.len(), threshold::KEY_SHARE_LEN);
            let restored = threshold::deserialize_key_share(&bytes[..]).expect("deserialize");
            let p_orig = threshold::partial_eval(share, &b.message).expect("p orig");
            let p_restored = threshold::partial_eval(&restored, &b.message).expect("p restored");
            assert_eq!(
                threshold::serialize_partial(&p_orig),
                threshold::serialize_partial(&p_restored),
                "restored share must produce the same partial evaluation"
            );
        }

        assert!(
            threshold::deserialize_key_share(&[0u8; 10]).is_err(),
            "wrong length must be rejected"
        );
        let mut zero_id = [1u8; threshold::KEY_SHARE_LEN];
        zero_id[..32].fill(0);
        assert!(
            threshold::deserialize_key_share(&zero_id).is_err(),
            "zero identifier must be rejected"
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

    /// `deserialize_partial` must reject the zero identifier (the secret's own evaluation point),
    /// independent of `combine()`'s internal duplicate/zero rejection.
    #[test]
    fn deserialize_partial_rejects_zero_identifier() {
        use k256::Scalar;
        let mut rng = rand_core_06::OsRng;
        let s = <Scalar as k256::elliptic_curve::Field>::random(&mut rng);
        let shares = threshold::split_key(&s, 2, 3, &mut rng).expect("split");
        let (_client, wire) = unlock::blind(b"keep-node-vault-v1").expect("blind");
        let mut bytes = unlock::evaluate(&shares[0], &wire).expect("eval");
        bytes[..threshold::ID_LEN].fill(0); // zero the identifier, keep the valid point
        assert!(
            threshold::deserialize_partial(&bytes).is_err(),
            "a zero identifier must be rejected"
        );
    }
}
