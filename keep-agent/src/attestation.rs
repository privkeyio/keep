#![forbid(unsafe_code)]

use crate::error::{AgentError, Result};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

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

/// Configuration for peer attestation verification.
///
/// Controls timestamp freshness validation and other verification parameters.
#[derive(Clone, Debug)]
pub struct VerificationConfig {
    /// Maximum allowed clock skew between attestation timestamp and system time.
    /// Attestations older than `now - max_clock_skew` or newer than `now + max_clock_skew`
    /// will be rejected. Default is 5 minutes.
    pub max_clock_skew: Duration,
    /// Whether to skip timestamp verification. Default is false.
    /// Set to true only if timestamp verification is performed upstream.
    pub skip_timestamp_check: bool,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            max_clock_skew: Duration::from_secs(300), // 5 minutes
            skip_timestamp_check: false,
        }
    }
}

impl VerificationConfig {
    /// Create a new verification config with custom clock skew threshold.
    pub fn with_clock_skew(max_clock_skew: Duration) -> Self {
        Self {
            max_clock_skew,
            skip_timestamp_check: false,
        }
    }

    /// Create a config that skips timestamp verification.
    ///
    /// Use this only when timestamp verification is performed upstream,
    /// such as when the attestation document has already been fully validated
    /// by an AWS Nitro attestation verifier.
    pub fn skip_timestamp() -> Self {
        Self {
            max_clock_skew: Duration::default(),
            skip_timestamp_check: true,
        }
    }
}

/// Pre-parsed attestation data from a FROST peer enclave.
///
/// # Document Authenticity
///
/// This struct contains pre-parsed fields extracted from an attestation document.
/// **Important**: The `verify_peer_attestation` function only validates PCR values
/// and timestamp freshness against the fields in this struct. It does NOT verify:
///
/// - The cryptographic signature of the attestation document
/// - The certificate chain back to the AWS Nitro root CA
/// - That the `enclave_pubkey` and other fields were actually signed by the enclave
///
/// **Callers must ensure document authenticity before constructing `PeerAttestation`**.
/// For AWS Nitro attestations, use `keep_enclave::host::AttestationVerifier` to
/// verify the raw COSE document and certificate chain before extracting these fields.
/// The `document` field is retained for audit/debugging purposes but is not validated here.
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

/// Verify a peer's attestation against expected PCR values and timestamp freshness.
///
/// # Arguments
///
/// * `attestation` - Pre-parsed attestation data from the peer
/// * `expected_pcrs` - Expected PCR values to match
/// * `config` - Verification configuration (timestamp skew, etc.)
///
/// # Document Signature Verification
///
/// This function validates PCR values and timestamp freshness only. It does NOT
/// verify the cryptographic authenticity of the attestation document. Document
/// signature verification (COSE signature, certificate chain to AWS Nitro root CA)
/// must be performed upstream before constructing `PeerAttestation`. See the
/// `keep_enclave::host::AttestationVerifier` for full attestation document verification.
///
/// # Errors
///
/// Returns an error if:
/// - Any PCR value doesn't match the expected value
/// - The attestation timestamp is outside the allowed clock skew window
pub fn verify_peer_attestation(
    attestation: &PeerAttestation,
    expected_pcrs: &ExpectedPcrs,
    config: &VerificationConfig,
) -> Result<()> {
    // Verify PCR values
    verify_pcr(&attestation.pcrs, 0, &expected_pcrs.pcr0)?;
    verify_pcr(&attestation.pcrs, 1, &expected_pcrs.pcr1)?;
    verify_pcr(&attestation.pcrs, 2, &expected_pcrs.pcr2)?;

    // Verify timestamp freshness unless explicitly skipped
    // Note: Document signature verification (proving the timestamp was signed by the enclave)
    // is NOT performed here. Callers must verify the attestation document signature upstream
    // using keep_enclave::host::AttestationVerifier or equivalent before trusting timestamp.
    if !config.skip_timestamp_check {
        verify_timestamp_freshness(attestation.timestamp, config.max_clock_skew)?;
    }

    Ok(())
}

/// Verify that the attestation timestamp is within the allowed clock skew window.
fn verify_timestamp_freshness(attestation_timestamp: u64, max_skew: Duration) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgentError::Attestation("System clock error".into()))?
        .as_millis() as u64;

    let skew_ms = max_skew.as_millis() as u64;

    // Check if attestation is too old
    if attestation_timestamp < now.saturating_sub(skew_ms) {
        let age_secs = (now.saturating_sub(attestation_timestamp)) / 1000;
        return Err(AgentError::AttestationTimestamp(format!(
            "attestation is {}s old, exceeds max skew of {}s",
            age_secs,
            max_skew.as_secs()
        )));
    }

    // Check if attestation is from the future (beyond allowed skew)
    if attestation_timestamp > now.saturating_add(skew_ms) {
        let future_secs = (attestation_timestamp.saturating_sub(now)) / 1000;
        return Err(AgentError::AttestationTimestamp(format!(
            "attestation is {}s in the future, exceeds max skew of {}s",
            future_secs,
            max_skew.as_secs()
        )));
    }

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

    if !bool::from(actual.as_slice().ct_eq(expected)) {
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

    fn current_timestamp_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    #[test]
    fn test_verify_peer_attestation_success() {
        let attestation = PeerAttestation::new(vec![])
            .with_pcrs(test_pcrs())
            .with_timestamp(current_timestamp_ms());
        let expected = ExpectedPcrs::new([0u8; 48], [1u8; 48], [2u8; 48]);
        let config = VerificationConfig::default();
        assert!(verify_peer_attestation(&attestation, &expected, &config).is_ok());
    }

    #[test]
    fn test_verify_peer_attestation_mismatch() {
        let attestation = PeerAttestation::new(vec![])
            .with_pcrs(test_pcrs())
            .with_timestamp(current_timestamp_ms());
        let expected = ExpectedPcrs::new(zero_pcr(), zero_pcr(), zero_pcr());
        let config = VerificationConfig::default();
        let result = verify_peer_attestation(&attestation, &expected, &config);
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
        let attestation = PeerAttestation::new(vec![])
            .with_pcrs(pcrs)
            .with_timestamp(current_timestamp_ms());
        let expected = ExpectedPcrs::new(zero_pcr(), zero_pcr(), zero_pcr());
        let config = VerificationConfig::default();
        let result = verify_peer_attestation(&attestation, &expected, &config);
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

    #[test]
    fn test_timestamp_within_skew_passes() {
        let now = current_timestamp_ms();
        // Attestation from 1 minute ago should pass with default 5 min skew
        let attestation = PeerAttestation::new(vec![])
            .with_pcrs(test_pcrs())
            .with_timestamp(now - 60_000);
        let expected = ExpectedPcrs::new([0u8; 48], [1u8; 48], [2u8; 48]);
        let config = VerificationConfig::default();
        assert!(verify_peer_attestation(&attestation, &expected, &config).is_ok());
    }

    #[test]
    fn test_timestamp_too_old_fails() {
        let now = current_timestamp_ms();
        // Attestation from 10 minutes ago should fail with default 5 min skew
        let attestation = PeerAttestation::new(vec![])
            .with_pcrs(test_pcrs())
            .with_timestamp(now - 600_000);
        let expected = ExpectedPcrs::new([0u8; 48], [1u8; 48], [2u8; 48]);
        let config = VerificationConfig::default();
        let result = verify_peer_attestation(&attestation, &expected, &config);
        assert!(result.is_err());
        match result.unwrap_err() {
            AgentError::AttestationTimestamp(msg) => {
                assert!(msg.contains("old"));
            }
            e => panic!("Expected AttestationTimestamp error, got {:?}", e),
        }
    }

    #[test]
    fn test_timestamp_too_far_in_future_fails() {
        let now = current_timestamp_ms();
        // Attestation from 10 minutes in the future should fail with default 5 min skew
        let attestation = PeerAttestation::new(vec![])
            .with_pcrs(test_pcrs())
            .with_timestamp(now + 600_000);
        let expected = ExpectedPcrs::new([0u8; 48], [1u8; 48], [2u8; 48]);
        let config = VerificationConfig::default();
        let result = verify_peer_attestation(&attestation, &expected, &config);
        assert!(result.is_err());
        match result.unwrap_err() {
            AgentError::AttestationTimestamp(msg) => {
                assert!(msg.contains("future"));
            }
            e => panic!("Expected AttestationTimestamp error, got {:?}", e),
        }
    }

    #[test]
    fn test_custom_clock_skew() {
        let now = current_timestamp_ms();
        // With 30 second skew, 1 minute old should fail
        let attestation = PeerAttestation::new(vec![])
            .with_pcrs(test_pcrs())
            .with_timestamp(now - 60_000);
        let expected = ExpectedPcrs::new([0u8; 48], [1u8; 48], [2u8; 48]);
        let config = VerificationConfig::with_clock_skew(Duration::from_secs(30));
        let result = verify_peer_attestation(&attestation, &expected, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_skip_timestamp_check() {
        let now = current_timestamp_ms();
        // Very old attestation should pass when timestamp check is skipped
        let attestation = PeerAttestation::new(vec![])
            .with_pcrs(test_pcrs())
            .with_timestamp(now - 3_600_000); // 1 hour old
        let expected = ExpectedPcrs::new([0u8; 48], [1u8; 48], [2u8; 48]);
        let config = VerificationConfig::skip_timestamp();
        assert!(verify_peer_attestation(&attestation, &expected, &config).is_ok());
    }

    #[test]
    fn test_verification_config_default() {
        let config = VerificationConfig::default();
        assert_eq!(config.max_clock_skew.as_secs(), 300);
        assert!(!config.skip_timestamp_check);
    }
}
