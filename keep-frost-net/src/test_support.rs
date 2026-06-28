//! Shared test-support helpers for building synthetic TPM quote evidence.
//!
//! Gated behind `cfg(test)` for this crate's own unit tests and the `testing`
//! feature for the integration-test binary, so the `TPMS_ATTEST` wire format
//! lives in exactly one place. A divergence between the verifier's unit tests
//! and the end-to-end attestation tests would otherwise let a quote builder
//! drift silently, masking a real attestation regression.

use p256::ecdsa::SigningKey;

/// Marshalled `TPML_PCR_SELECTION` for the SHA-256 bank over a single PCR.
pub fn one_pcr_selection() -> Vec<u8> {
    hex::decode("00000001000b03800000").unwrap()
}

/// Build a self-consistent, signed `TPMS_ATTEST` quote over one PCR bound to
/// `nonce`, signed with `sk`. Mirrors the producer's exact wire format.
pub fn build_signed_quote(
    nonce: &[u8],
    pcr_select: &[u8],
    pcr_value: &[u8; 32],
    sk: &SigningKey,
) -> (Vec<u8>, Vec<u8>) {
    use p256::ecdsa::{signature::Signer, Signature};
    use sha2::{Digest, Sha256};

    let mut attest = Vec::new();
    attest.extend_from_slice(&0xFF54_4347u32.to_be_bytes()); // TPM_GENERATED
    attest.extend_from_slice(&0x8018u16.to_be_bytes()); // TPM_ST_ATTEST_QUOTE
    attest.extend_from_slice(&0u16.to_be_bytes()); // TPM2B_NAME qualifiedSigner: empty
    attest.extend_from_slice(&(nonce.len() as u16).to_be_bytes()); // TPM2B_DATA extraData
    attest.extend_from_slice(nonce);
    attest.extend_from_slice(&[0u8; 17]); // TPMS_CLOCK_INFO
    attest.extend_from_slice(&[0u8; 8]); // firmwareVersion
    attest.extend_from_slice(pcr_select); // TPML_PCR_SELECTION (== pinned selection)
    let digest = Sha256::digest(pcr_value);
    attest.extend_from_slice(&(digest.len() as u16).to_be_bytes()); // TPM2B_DIGEST pcrDigest
    attest.extend_from_slice(&digest);

    let sig: Signature = sk.sign(&attest); // ECDSA-P256 over SHA-256(attest)
    (attest, sig.to_bytes().to_vec())
}
