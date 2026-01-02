#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningAuditEntry {
    pub timestamp_ms: u64,
    pub key_id: String,
    pub message_hash: [u8; 32],
    pub signature_hash: [u8; 32],
    pub session_id: Option<[u8; 32]>,
    pub participant_index: Option<u16>,
    pub operation: SigningOperation,
    pub hmac: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SigningOperation {
    SingleSign,
    PsbtSign { inputs_signed: usize },
    FrostRound1,
    FrostRound2,
}

impl SigningAuditEntry {
    #[allow(clippy::too_many_arguments)]
    fn compute_hmac(
        hmac_key: &[u8],
        timestamp_ms: u64,
        key_id: &str,
        message_hash: &[u8; 32],
        signature_hash: &[u8; 32],
        session_id: Option<&[u8; 32]>,
        participant_index: Option<u16>,
        operation: &SigningOperation,
    ) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(hmac_key)
            .expect("HMAC accepts any key length");

        mac.update(&timestamp_ms.to_le_bytes());
        mac.update(key_id.as_bytes());
        mac.update(&(key_id.len() as u32).to_le_bytes());
        mac.update(message_hash);
        mac.update(signature_hash);

        if let Some(sid) = session_id {
            mac.update(&[1u8]);
            mac.update(sid);
        } else {
            mac.update(&[0u8]);
        }

        if let Some(idx) = participant_index {
            mac.update(&[1u8]);
            mac.update(&idx.to_le_bytes());
        } else {
            mac.update(&[0u8]);
        }

        mac.update(&operation.to_bytes());

        let result = mac.finalize();
        let mut hmac_out = [0u8; 32];
        hmac_out.copy_from_slice(&result.into_bytes());
        hmac_out
    }

    pub fn verify(&self, hmac_key: &[u8]) -> bool {
        let expected = Self::compute_hmac(
            hmac_key,
            self.timestamp_ms,
            &self.key_id,
            &self.message_hash,
            &self.signature_hash,
            self.session_id.as_ref(),
            self.participant_index,
            &self.operation,
        );
        constant_time_eq(&self.hmac, &expected)
    }
}

impl SigningOperation {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            SigningOperation::SingleSign => vec![0],
            SigningOperation::PsbtSign { inputs_signed } => {
                let mut bytes = vec![1];
                bytes.extend_from_slice(&(*inputs_signed as u32).to_le_bytes());
                bytes
            }
            SigningOperation::FrostRound1 => vec![2],
            SigningOperation::FrostRound2 => vec![3],
        }
    }
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningAuditLog {
    hmac_key: [u8; 32],
    #[zeroize(skip)]
    entries: VecDeque<SigningAuditEntry>,
    #[zeroize(skip)]
    max_entries: usize,
}

impl SigningAuditLog {
    pub fn new(hmac_key: [u8; 32]) -> Self {
        Self {
            hmac_key,
            entries: VecDeque::with_capacity(1000),
            max_entries: 1000,
        }
    }

    pub fn log_single_sign(
        &mut self,
        key_id: &str,
        message: &[u8],
        signature: &[u8; 64],
    ) {
        self.log_entry(
            key_id,
            message,
            Some(signature),
            None,
            None,
            SigningOperation::SingleSign,
        );
    }

    pub fn log_psbt_sign(
        &mut self,
        key_id: &str,
        psbt_bytes: &[u8],
        inputs_signed: usize,
    ) {
        self.log_entry(
            key_id,
            psbt_bytes,
            None,
            None,
            None,
            SigningOperation::PsbtSign { inputs_signed },
        );
    }

    pub fn log_frost_round1(
        &mut self,
        key_id: &str,
        message: &[u8],
        session_id: [u8; 32],
    ) {
        self.log_entry(
            key_id,
            message,
            None,
            Some(session_id),
            None,
            SigningOperation::FrostRound1,
        );
    }

    pub fn log_frost_round2(
        &mut self,
        key_id: &str,
        session_id: [u8; 32],
        signature_share: &[u8],
    ) {
        // Hash the signature share and store it in the signature_hash field
        let share_hash = hash_bytes(signature_share);
        let mut sig_array = [0u8; 64];
        sig_array[..32].copy_from_slice(&share_hash);

        self.log_entry(
            key_id,
            &[],
            Some(&sig_array),
            Some(session_id),
            None,
            SigningOperation::FrostRound2,
        );
    }

    fn log_entry(
        &mut self,
        key_id: &str,
        message: &[u8],
        signature: Option<&[u8; 64]>,
        session_id: Option<[u8; 32]>,
        participant_index: Option<u16>,
        operation: SigningOperation,
    ) {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let message_hash = hash_bytes(message);
        let signature_hash = signature.map(|s| hash_bytes(s)).unwrap_or([0u8; 32]);

        let hmac = SigningAuditEntry::compute_hmac(
            &self.hmac_key,
            timestamp_ms,
            key_id,
            &message_hash,
            &signature_hash,
            session_id.as_ref(),
            participant_index,
            &operation,
        );

        let entry = SigningAuditEntry {
            timestamp_ms,
            key_id: key_id.to_string(),
            message_hash,
            signature_hash,
            session_id,
            participant_index,
            operation,
            hmac,
        };

        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    pub fn entries(&self) -> impl Iterator<Item = &SigningAuditEntry> {
        self.entries.iter()
    }

    pub fn verify_all(&self) -> bool {
        self.entries.iter().all(|e| e.verify(&self.hmac_key))
    }

    pub fn serialize_entries(&self) -> Vec<u8> {
        let entries: Vec<_> = self.entries.iter().cloned().collect();
        serde_json::to_vec(&entries).unwrap_or_default()
    }
}

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_sign_audit() {
        let hmac_key = [42u8; 32];
        let mut log = SigningAuditLog::new(hmac_key);

        let message = b"test message";
        let signature = [1u8; 64];

        log.log_single_sign("test-key", message, &signature);

        assert_eq!(log.entries.len(), 1);
        assert!(log.verify_all());
    }

    #[test]
    fn test_tampered_entry_fails() {
        let hmac_key = [42u8; 32];
        let mut log = SigningAuditLog::new(hmac_key);

        log.log_single_sign("test-key", b"msg", &[1u8; 64]);

        log.entries.back_mut().unwrap().timestamp_ms = 999;
        assert!(!log.verify_all());
    }

    #[test]
    fn test_frost_audit() {
        let hmac_key = [42u8; 32];
        let mut log = SigningAuditLog::new(hmac_key);

        let session_id = [1u8; 32];
        log.log_frost_round1("frost-key", b"message", session_id);
        log.log_frost_round2("frost-key", session_id, &[2u8; 32]);

        assert_eq!(log.entries.len(), 2);
        assert!(log.verify_all());
    }
}
