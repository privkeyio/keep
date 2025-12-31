#![forbid(unsafe_code)]

use crate::error::{AgentError, Result};
use std::collections::HashMap;

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
                .map_err(|e| AgentError::Attestation(format!("Invalid hex: {}", e)))?;
            bytes
                .try_into()
                .map_err(|_| AgentError::Attestation("PCR must be 48 bytes".into()))
        };
        Ok(Self {
            pcr0: parse(pcr0)?,
            pcr1: parse(pcr1)?,
            pcr2: parse(pcr2)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PeerAttestation {
    pub document: Vec<u8>,
    pub pcrs: HashMap<u32, Vec<u8>>,
    pub enclave_pubkey: Vec<u8>,
    pub timestamp: u64,
}

impl PeerAttestation {
    pub fn new(document: Vec<u8>) -> Self {
        Self {
            document,
            pcrs: HashMap::new(),
            enclave_pubkey: Vec::new(),
            timestamp: 0,
        }
    }

    pub fn with_pcrs(mut self, pcrs: HashMap<u32, Vec<u8>>) -> Self {
        self.pcrs = pcrs;
        self
    }

    pub fn with_enclave_pubkey(mut self, pubkey: Vec<u8>) -> Self {
        self.enclave_pubkey = pubkey;
        self
    }

    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }
}

pub fn verify_peer_attestation(
    attestation: &PeerAttestation,
    expected_pcrs: &ExpectedPcrs,
) -> Result<()> {
    verify_pcr(&attestation.pcrs, 0, &expected_pcrs.pcr0)?;
    verify_pcr(&attestation.pcrs, 1, &expected_pcrs.pcr1)?;
    verify_pcr(&attestation.pcrs, 2, &expected_pcrs.pcr2)?;
    Ok(())
}

fn verify_pcr(pcrs: &HashMap<u32, Vec<u8>>, index: u32, expected: &[u8; 48]) -> Result<()> {
    let actual = pcrs
        .get(&index)
        .ok_or_else(|| AgentError::Attestation(format!("Missing PCR{}", index)))?;

    if actual.len() != 48 {
        return Err(AgentError::PcrMismatch {
            pcr: index,
            expected: hex::encode(expected),
            actual: format!("invalid length: {}", actual.len()),
        });
    }

    if actual.as_slice() != expected {
        return Err(AgentError::PcrMismatch {
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

    fn zero_pcr() -> [u8; 48] {
        [0u8; 48]
    }

    fn test_pcrs() -> HashMap<u32, Vec<u8>> {
        let mut pcrs = HashMap::new();
        pcrs.insert(0, vec![0u8; 48]);
        pcrs.insert(1, vec![1u8; 48]);
        pcrs.insert(2, vec![2u8; 48]);
        pcrs
    }

    #[test]
    fn test_verify_peer_attestation_success() {
        let attestation = PeerAttestation::new(vec![]).with_pcrs(test_pcrs());
        let expected = ExpectedPcrs::new([0u8; 48], [1u8; 48], [2u8; 48]);
        assert!(verify_peer_attestation(&attestation, &expected).is_ok());
    }

    #[test]
    fn test_verify_peer_attestation_mismatch() {
        let attestation = PeerAttestation::new(vec![]).with_pcrs(test_pcrs());
        let expected = ExpectedPcrs::new(zero_pcr(), zero_pcr(), zero_pcr());
        let result = verify_peer_attestation(&attestation, &expected);
        assert!(result.is_err());
        match result.unwrap_err() {
            AgentError::PcrMismatch { pcr, .. } => assert_eq!(pcr, 1),
            _ => panic!("Expected PcrMismatch error"),
        }
    }

    #[test]
    fn test_verify_peer_attestation_missing_pcr() {
        let mut pcrs = HashMap::new();
        pcrs.insert(0, vec![0u8; 48]);
        let attestation = PeerAttestation::new(vec![]).with_pcrs(pcrs);
        let expected = ExpectedPcrs::new(zero_pcr(), zero_pcr(), zero_pcr());
        let result = verify_peer_attestation(&attestation, &expected);
        assert!(result.is_err());
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
}
