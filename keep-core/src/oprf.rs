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
        assert_eq!(out1, out2, "same input + key must give a stable OPRF output");

        // Different input -> different output.
        let other: &[u8] = b"keep-node-other";
        let b3 = OprfClient::<Secp256k1Sha256>::blind(other, &mut rng).expect("blind");
        let e3 = server.blind_evaluate(&b3.message);
        let out3 = b3.state.finalize(other, &e3).expect("finalize");
        assert_ne!(out1, out3, "different input must give a different output");
    }
}
