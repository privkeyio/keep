// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use sha2::{Digest, Sha256};

use crate::error::{FrostNetError, Result};
use crate::protocol::EnclaveAttestation;

// Only the Nitro document verifier checks an enclave attestation's timestamp;
// the non-Nitro build fails closed before any timestamp check, so these are
// gated to avoid dead-code warnings there.
#[cfg(feature = "nitro-attestation")]
pub const ATTESTATION_MAX_AGE_SECS: u64 = 300;
#[cfg(feature = "nitro-attestation")]
pub const ATTESTATION_MAX_FUTURE_SECS: u64 = 30;

#[derive(Clone, Debug)]
pub struct ExpectedPcrs {
    pub pcr0: [u8; 48],
    pub pcr1: [u8; 48],
    pub pcr2: [u8; 48],
}

impl ExpectedPcrs {
    pub fn new(pcr0: [u8; 48], pcr1: [u8; 48], pcr2: [u8; 48]) -> Self {
        Self { pcr0, pcr1, pcr2 }
    }

    pub fn from_hex(pcr0: &str, pcr1: &str, pcr2: &str) -> Result<Self> {
        let parse = |s: &str| -> Result<[u8; 48]> {
            let bytes = hex::decode(s)
                .map_err(|e| FrostNetError::Attestation(format!("Invalid hex: {e}")))?;
            bytes
                .try_into()
                .map_err(|_| FrostNetError::Attestation("PCR must be 48 bytes".into()))
        };
        let pcr0 = parse(pcr0)?;
        if pcr0.iter().all(|&b| b == 0) {
            return Err(FrostNetError::Attestation(
                "PCR0 is all zeros, which indicates a debug-mode enclave; refusing to pin it. \
                 Use the explicit insecure path if you genuinely intend a debug enclave."
                    .into(),
            ));
        }
        Ok(Self {
            pcr0,
            pcr1: parse(pcr1)?,
            pcr2: parse(pcr2)?,
        })
    }
}

pub fn derive_attestation_nonce(group_pubkey: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"keep-frost-attestation-nonce-v1");
    hasher.update(group_pubkey);
    hasher.finalize().into()
}

/// Announce-bound attestation nonce for the TPM-quote path: binds the quote to a SPECIFIC announce
/// (its share index and timestamp), not just the group, so a valid quote cannot be lifted into a
/// different/forged announce. The quote producer MUST quote with this exact value as
/// `qualifyingData`, computed from the same announce it ships the quote in. (The Nitro path keeps
/// the group-only nonce above, whose value is coordinated with the enclave producer.)
pub fn derive_announce_attestation_nonce(
    group_pubkey: &[u8; 32],
    share_index: u16,
    timestamp: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"keep-frost-attestation-nonce-v2");
    hasher.update(group_pubkey);
    hasher.update(share_index.to_be_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(feature = "nitro-attestation")]
pub fn verify_peer_attestation(
    attestation: &EnclaveAttestation,
    expected_pcrs: &ExpectedPcrs,
    group_pubkey: &[u8; 32],
) -> Result<()> {
    use keep_enclave_host::{AttestationVerifier, ExpectedPcrs as HostPcrs};

    let host_pcrs = HostPcrs::new(expected_pcrs.pcr0, expected_pcrs.pcr1, expected_pcrs.pcr2);
    let verifier = AttestationVerifier::new(host_pcrs);
    let nonce = derive_attestation_nonce(group_pubkey);

    let verified = verifier
        .verify(&attestation.document, &nonce)
        .map_err(|e| FrostNetError::Attestation(format!("Document verification failed: {e}")))?;

    if verified.pcrs.get(&0).map(|v: &Vec<u8>| v.as_slice()) != Some(&attestation.pcr0[..]) {
        return Err(FrostNetError::Attestation(
            "PCR0 mismatch between document and claimed value".into(),
        ));
    }
    if verified.pcrs.get(&1).map(|v: &Vec<u8>| v.as_slice()) != Some(&attestation.pcr1[..]) {
        return Err(FrostNetError::Attestation(
            "PCR1 mismatch between document and claimed value".into(),
        ));
    }
    if verified.pcrs.get(&2).map(|v: &Vec<u8>| v.as_slice()) != Some(&attestation.pcr2[..]) {
        return Err(FrostNetError::Attestation(
            "PCR2 mismatch between document and claimed value".into(),
        ));
    }

    verify_attestation_timestamp_ms(verified.timestamp)?;

    Ok(())
}

/// Without the `nitro-attestation` feature there is no Nitro document verifier
/// compiled in, so a peer's enclave attestation cannot be cryptographically
/// verified. Fail closed: refuse it. The previous stub compared only the
/// attacker-supplied PCR *claims* against the (public) expected values and
/// returned `Ok`, which any forger could satisfy by echoing the expected PCRs.
/// A node that cannot verify Nitro evidence must reject it, never admit it on
/// trust.
#[cfg(not(feature = "nitro-attestation"))]
pub fn verify_peer_attestation(
    _attestation: &EnclaveAttestation,
    _expected_pcrs: &ExpectedPcrs,
    _group_pubkey: &[u8; 32],
) -> Result<()> {
    Err(FrostNetError::Attestation(
        "enclave (Nitro) attestation cannot be verified: this build lacks the \
         nitro-attestation feature"
            .into(),
    ))
}

#[cfg(feature = "nitro-attestation")]
pub(crate) fn verify_attestation_timestamp_ms(timestamp_ms: u64) -> Result<()> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| FrostNetError::Attestation("System clock error".into()))?
        .as_millis() as u64;

    let max_age_ms = ATTESTATION_MAX_AGE_SECS * 1000;
    let max_future_ms = ATTESTATION_MAX_FUTURE_SECS * 1000;

    if timestamp_ms < now_ms.saturating_sub(max_age_ms) {
        let age_secs = now_ms.saturating_sub(timestamp_ms) / 1000;
        return Err(FrostNetError::Attestation(format!(
            "Attestation timestamp too old: {age_secs}s (max {ATTESTATION_MAX_AGE_SECS}s)"
        )));
    }

    if timestamp_ms > now_ms.saturating_add(max_future_ms) {
        let future_secs = timestamp_ms.saturating_sub(now_ms) / 1000;
        return Err(FrostNetError::Attestation(format!(
            "Attestation timestamp in future: {future_secs}s (max {ATTESTATION_MAX_FUTURE_SECS}s)"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_timestamp_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    #[test]
    fn test_expected_pcrs_from_hex() {
        let pcr0 = "9".repeat(96);
        let pcr1 = "1".repeat(96);
        let pcr2 = "2".repeat(96);
        let pcrs = ExpectedPcrs::from_hex(&pcr0, &pcr1, &pcr2).unwrap();
        assert_eq!(pcrs.pcr0[0], 0x99);
        assert_eq!(pcrs.pcr1[0], 0x11);
        assert_eq!(pcrs.pcr2[0], 0x22);
    }

    #[test]
    fn test_expected_pcrs_from_hex_rejects_all_zero_pcr0() {
        let result = ExpectedPcrs::from_hex(&"0".repeat(96), &"1".repeat(96), &"2".repeat(96));
        assert!(result.is_err());
    }

    #[test]
    fn test_expected_pcrs_from_hex_invalid_length() {
        let pcr0 = "00".repeat(47);
        let pcr1 = "1".repeat(96);
        let pcr2 = "2".repeat(96);
        let result = ExpectedPcrs::from_hex(&pcr0, &pcr1, &pcr2);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_attestation_nonce() {
        let group_pubkey = [1u8; 32];
        let nonce = derive_attestation_nonce(&group_pubkey);
        assert_eq!(nonce.len(), 32);

        let nonce2 = derive_attestation_nonce(&group_pubkey);
        assert_eq!(nonce, nonce2);

        let different_group = [2u8; 32];
        let nonce3 = derive_attestation_nonce(&different_group);
        assert_ne!(nonce, nonce3);
    }

    #[test]
    fn test_derive_announce_attestation_nonce_binds_to_announce() {
        let g = [1u8; 32];
        let base = derive_announce_attestation_nonce(&g, 2, 1000);
        assert_eq!(base.len(), 32);
        // Deterministic for the same announce.
        assert_eq!(base, derive_announce_attestation_nonce(&g, 2, 1000));
        // Bound to share index and timestamp, so a quote cannot be lifted to a different announce.
        assert_ne!(base, derive_announce_attestation_nonce(&g, 3, 1000));
        assert_ne!(base, derive_announce_attestation_nonce(&g, 2, 1001));
        assert_ne!(base, derive_announce_attestation_nonce(&[2u8; 32], 2, 1000));
        // Domain-separated from the group-only (Nitro) nonce.
        assert_ne!(base, derive_attestation_nonce(&g));
    }

    #[cfg(not(feature = "nitro-attestation"))]
    mod non_nitro_tests {
        use super::*;

        /// Without the nitro-attestation feature there is no document verifier,
        /// so verify_peer_attestation fails closed for ANY input, including one
        /// whose claimed PCRs and timestamp are otherwise valid, rather than the
        /// old stub that returned Ok on a matching (forgeable) PCR claim.
        #[test]
        fn verify_peer_attestation_fails_closed_without_nitro() {
            let attestation = EnclaveAttestation::new(
                vec![],
                vec![0u8; 48],
                vec![1u8; 48],
                vec![2u8; 48],
                vec![],
                current_timestamp_ms(),
            );
            // PCRs and timestamp all "match"/are fresh; the old stub returned Ok.
            let expected = ExpectedPcrs::new([0u8; 48], [1u8; 48], [2u8; 48]);
            let result = verify_peer_attestation(&attestation, &expected, &[0u8; 32]);
            match result.unwrap_err() {
                FrostNetError::Attestation(msg) => {
                    assert!(msg.contains("nitro-attestation"))
                }
                e => panic!("Expected fail-closed Attestation error, got {:?}", e),
            }
        }
    }

    #[cfg(feature = "nitro-attestation")]
    mod nitro_tests {
        use super::*;

        #[test]
        fn test_verify_peer_attestation_invalid_document() {
            let attestation = EnclaveAttestation::new(
                vec![0u8; 100],
                vec![0u8; 48],
                vec![1u8; 48],
                vec![2u8; 48],
                vec![],
                current_timestamp_ms(),
            );
            let expected = ExpectedPcrs::new([0u8; 48], [1u8; 48], [2u8; 48]);
            let group_pubkey = [0u8; 32];
            let result = verify_peer_attestation(&attestation, &expected, &group_pubkey);
            assert!(result.is_err());
            match result.unwrap_err() {
                FrostNetError::Attestation(msg) => {
                    assert!(msg.contains("Document verification failed"))
                }
                e => panic!("Expected Attestation error, got {e:?}"),
            }
        }

        #[test]
        fn test_verify_peer_attestation_empty_document() {
            let attestation = EnclaveAttestation::new(
                vec![],
                vec![0u8; 48],
                vec![1u8; 48],
                vec![2u8; 48],
                vec![],
                current_timestamp_ms(),
            );
            let expected = ExpectedPcrs::new([0u8; 48], [1u8; 48], [2u8; 48]);
            let group_pubkey = [0u8; 32];
            let result = verify_peer_attestation(&attestation, &expected, &group_pubkey);
            assert!(result.is_err());
        }
    }
}
