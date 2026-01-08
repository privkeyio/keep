#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

use crate::error::{FrostNetError, Result};
use crate::protocol::EnclaveAttestation;

pub const ATTESTATION_MAX_AGE_SECS: u64 = 300;
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
                .map_err(|e| FrostNetError::Attestation(format!("Invalid hex: {}", e)))?;
            bytes
                .try_into()
                .map_err(|_| FrostNetError::Attestation("PCR must be 48 bytes".into()))
        };
        Ok(Self {
            pcr0: parse(pcr0)?,
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

#[cfg(feature = "nitro-attestation")]
pub fn verify_peer_attestation(
    attestation: &EnclaveAttestation,
    expected_pcrs: &ExpectedPcrs,
    group_pubkey: &[u8; 32],
) -> Result<()> {
    use keep_enclave_host::{AttestationVerifier, ExpectedPcrs as HostPcrs};

    let host_pcrs = HostPcrs::new(expected_pcrs.pcr0, expected_pcrs.pcr1, expected_pcrs.pcr2);
    let verifier = AttestationVerifier::new(Some(host_pcrs));
    let nonce = derive_attestation_nonce(group_pubkey);

    let verified = verifier
        .verify(&attestation.document, &nonce)
        .map_err(|e| FrostNetError::Attestation(format!("Document verification failed: {}", e)))?;

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

#[cfg(not(feature = "nitro-attestation"))]
pub fn verify_peer_attestation(
    attestation: &EnclaveAttestation,
    expected_pcrs: &ExpectedPcrs,
    _group_pubkey: &[u8; 32],
) -> Result<()> {
    verify_pcr(&attestation.pcr0, 0, &expected_pcrs.pcr0)?;
    verify_pcr(&attestation.pcr1, 1, &expected_pcrs.pcr1)?;
    verify_pcr(&attestation.pcr2, 2, &expected_pcrs.pcr2)?;
    verify_attestation_timestamp_ms(attestation.timestamp)?;
    Ok(())
}

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
            "Attestation timestamp too old: {}s (max {}s)",
            age_secs, ATTESTATION_MAX_AGE_SECS
        )));
    }

    if timestamp_ms > now_ms.saturating_add(max_future_ms) {
        let future_secs = timestamp_ms.saturating_sub(now_ms) / 1000;
        return Err(FrostNetError::Attestation(format!(
            "Attestation timestamp in future: {}s (max {}s)",
            future_secs, ATTESTATION_MAX_FUTURE_SECS
        )));
    }

    Ok(())
}

#[cfg(not(feature = "nitro-attestation"))]
fn verify_pcr(actual: &[u8], index: u32, expected: &[u8; 48]) -> Result<()> {
    if actual.len() != 48 {
        return Err(FrostNetError::PcrMismatch {
            pcr: index,
            expected: hex::encode(expected),
            actual: format!("invalid length: {}", actual.len()),
        });
    }
    if actual != expected {
        return Err(FrostNetError::PcrMismatch {
            pcr: index,
            expected: hex::encode(expected),
            actual: hex::encode(actual),
        });
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
        let pcr0 = "0".repeat(96);
        let pcr1 = "1".repeat(96);
        let pcr2 = "2".repeat(96);
        let pcrs = ExpectedPcrs::from_hex(&pcr0, &pcr1, &pcr2).unwrap();
        assert_eq!(pcrs.pcr0[0], 0x00);
        assert_eq!(pcrs.pcr1[0], 0x11);
        assert_eq!(pcrs.pcr2[0], 0x22);
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

    #[cfg(not(feature = "nitro-attestation"))]
    mod non_nitro_tests {
        use super::*;

        #[test]
        fn test_verify_peer_attestation_success() {
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
            assert!(verify_peer_attestation(&attestation, &expected, &group_pubkey).is_ok());
        }

        #[test]
        fn test_verify_peer_attestation_mismatch() {
            let attestation = EnclaveAttestation::new(
                vec![],
                vec![0u8; 48],
                vec![99u8; 48],
                vec![2u8; 48],
                vec![],
                current_timestamp_ms(),
            );
            let expected = ExpectedPcrs::new([0u8; 48], [1u8; 48], [2u8; 48]);
            let group_pubkey = [0u8; 32];
            let result = verify_peer_attestation(&attestation, &expected, &group_pubkey);
            assert!(result.is_err());
            match result.unwrap_err() {
                FrostNetError::PcrMismatch { pcr, .. } => assert_eq!(pcr, 1),
                _ => panic!("Expected PcrMismatch error"),
            }
        }

        #[test]
        fn test_verify_peer_attestation_invalid_length() {
            let attestation = EnclaveAttestation::new(
                vec![],
                vec![0u8; 32],
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
                FrostNetError::PcrMismatch { pcr, actual, .. } => {
                    assert_eq!(pcr, 0);
                    assert!(actual.contains("invalid length"));
                }
                _ => panic!("Expected PcrMismatch error"),
            }
        }

        #[test]
        fn test_verify_peer_attestation_timestamp_too_old() {
            let old_timestamp = current_timestamp_ms() - (ATTESTATION_MAX_AGE_SECS + 60) * 1000;
            let attestation = EnclaveAttestation::new(
                vec![],
                vec![0u8; 48],
                vec![1u8; 48],
                vec![2u8; 48],
                vec![],
                old_timestamp,
            );
            let expected = ExpectedPcrs::new([0u8; 48], [1u8; 48], [2u8; 48]);
            let group_pubkey = [0u8; 32];
            let result = verify_peer_attestation(&attestation, &expected, &group_pubkey);
            assert!(result.is_err());
            match result.unwrap_err() {
                FrostNetError::Attestation(msg) => assert!(msg.contains("too old")),
                e => panic!("Expected Attestation error, got {:?}", e),
            }
        }

        #[test]
        fn test_verify_peer_attestation_timestamp_in_future() {
            let future_timestamp =
                current_timestamp_ms() + (ATTESTATION_MAX_FUTURE_SECS + 60) * 1000;
            let attestation = EnclaveAttestation::new(
                vec![],
                vec![0u8; 48],
                vec![1u8; 48],
                vec![2u8; 48],
                vec![],
                future_timestamp,
            );
            let expected = ExpectedPcrs::new([0u8; 48], [1u8; 48], [2u8; 48]);
            let group_pubkey = [0u8; 32];
            let result = verify_peer_attestation(&attestation, &expected, &group_pubkey);
            assert!(result.is_err());
            match result.unwrap_err() {
                FrostNetError::Attestation(msg) => assert!(msg.contains("future")),
                e => panic!("Expected Attestation error, got {:?}", e),
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
                e => panic!("Expected Attestation error, got {:?}", e),
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
