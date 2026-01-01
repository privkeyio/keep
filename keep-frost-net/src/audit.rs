#![forbid(unsafe_code)]
#![allow(unused_assignments)]

use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningAuditEntry {
    pub timestamp_ms: u64,
    pub session_id: [u8; 32],
    pub message_hash: [u8; 32],
    pub signature_hash: [u8; 32],
    pub participant_indices: Vec<u16>,
    pub our_index: u16,
    pub operation: SigningOperation,
    pub hmac: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SigningOperation {
    SignRequestInitiated,
    CommitmentSent,
    SignatureShareSent,
    SignatureCompleted,
    SignatureReceived,
}

impl SigningAuditEntry {
    #[allow(clippy::too_many_arguments)]
    fn compute_hmac(
        hmac_key: &[u8],
        timestamp_ms: u64,
        session_id: &[u8; 32],
        message_hash: &[u8; 32],
        signature_hash: &[u8; 32],
        participant_indices: &[u16],
        our_index: u16,
        operation: &SigningOperation,
    ) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC accepts any key length");

        mac.update(&timestamp_ms.to_le_bytes());
        mac.update(session_id);
        mac.update(message_hash);
        mac.update(signature_hash);
        for idx in participant_indices {
            mac.update(&idx.to_le_bytes());
        }
        mac.update(&our_index.to_le_bytes());
        mac.update(&[operation.discriminant()]);

        let result = mac.finalize();
        let mut hmac_out = [0u8; 32];
        hmac_out.copy_from_slice(&result.into_bytes());
        hmac_out
    }

    pub fn verify(&self, hmac_key: &[u8]) -> bool {
        let expected = Self::compute_hmac(
            hmac_key,
            self.timestamp_ms,
            &self.session_id,
            &self.message_hash,
            &self.signature_hash,
            &self.participant_indices,
            self.our_index,
            &self.operation,
        );
        constant_time_eq(&self.hmac, &expected)
    }
}

impl SigningOperation {
    fn discriminant(&self) -> u8 {
        match self {
            SigningOperation::SignRequestInitiated => 0,
            SigningOperation::CommitmentSent => 1,
            SigningOperation::SignatureShareSent => 2,
            SigningOperation::SignatureCompleted => 3,
            SigningOperation::SignatureReceived => 4,
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
    entries: Arc<RwLock<VecDeque<SigningAuditEntry>>>,
    #[zeroize(skip)]
    max_entries: usize,
}

impl SigningAuditLog {
    pub fn new(hmac_key: [u8; 32]) -> Self {
        Self {
            hmac_key,
            entries: Arc::new(RwLock::new(VecDeque::new())),
            max_entries: 10000,
        }
    }

    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = max;
        self
    }

    pub fn log_signing_operation(
        &self,
        session_id: [u8; 32],
        message: &[u8],
        signature: Option<&[u8; 64]>,
        participant_indices: Vec<u16>,
        our_index: u16,
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
            &session_id,
            &message_hash,
            &signature_hash,
            &participant_indices,
            our_index,
            &operation,
        );

        let entry = SigningAuditEntry {
            timestamp_ms,
            session_id,
            message_hash,
            signature_hash,
            participant_indices: participant_indices.clone(),
            our_index,
            operation: operation.clone(),
            hmac,
        };

        info!(
            session_id = %hex::encode(session_id),
            message_hash = %hex::encode(message_hash),
            signature_hash = %hex::encode(signature_hash),
            participants = ?participant_indices,
            our_index = our_index,
            operation = ?operation,
            hmac = %hex::encode(hmac),
            "Signing audit log entry"
        );

        let mut entries = self.entries.write();
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    pub fn entries(&self) -> Vec<SigningAuditEntry> {
        self.entries.read().iter().cloned().collect()
    }

    pub fn verify_all(&self) -> bool {
        self.entries.read().iter().all(|e| e.verify(&self.hmac_key))
    }

    pub fn get_entries_for_session(&self, session_id: &[u8; 32]) -> Vec<SigningAuditEntry> {
        self.entries
            .read()
            .iter()
            .filter(|e| &e.session_id == session_id)
            .cloned()
            .collect()
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
    fn test_audit_entry_hmac_verification() {
        let hmac_key = [42u8; 32];
        let log = SigningAuditLog::new(hmac_key);

        let session_id = [1u8; 32];
        let message = b"test message";
        let signature = [2u8; 64];

        log.log_signing_operation(
            session_id,
            message,
            Some(&signature),
            vec![1, 2, 3],
            1,
            SigningOperation::SignatureCompleted,
        );

        assert!(log.verify_all());
    }

    #[test]
    fn test_tampered_entry_fails_verification() {
        let hmac_key = [42u8; 32];
        let log = SigningAuditLog::new(hmac_key);

        let session_id = [1u8; 32];
        let message = b"test message";
        let signature = [2u8; 64];

        log.log_signing_operation(
            session_id,
            message,
            Some(&signature),
            vec![1, 2, 3],
            1,
            SigningOperation::SignatureCompleted,
        );

        {
            let mut entries = log.entries.write();
            entries[0].timestamp_ms = 999;
        }

        assert!(!log.verify_all());
    }

    #[test]
    fn test_max_entries_limit() {
        let hmac_key = [42u8; 32];
        let log = SigningAuditLog::new(hmac_key).with_max_entries(3);

        for i in 0..5u8 {
            log.log_signing_operation(
                [i; 32],
                &[i],
                None,
                vec![1],
                1,
                SigningOperation::CommitmentSent,
            );
        }

        let entries = log.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].session_id[0], 2);
    }
}
