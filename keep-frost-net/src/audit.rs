// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![allow(unused_assignments)]

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
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
    /// Which peer asked for this signature, by share index.
    ///
    /// Set on the entries written while handling an inbound request, where the
    /// index has been resolved against the signature-verified peer list and is
    /// therefore an identity rather than a claim. `None` elsewhere in the
    /// session's lifecycle, and on requests this node initiated itself.
    ///
    /// Deliberately not copied onto every entry. The requester is a property of
    /// the session, every entry already carries the session id, and duplicating
    /// it would mean threading mutable state through the session layer to
    /// restate something a join already answers.
    pub requester: Option<u16>,
    pub hmac: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SigningOperation {
    SignRequestInitiated,
    CommitmentSent,
    SignatureShareSent,
    SignatureCompleted,
    SignatureReceived,
    /// A sign request this node refused before taking part.
    ///
    /// Every other variant records something that happened. Without this one
    /// the log answers "what did we sign" but not "what were we asked to sign
    /// and declined", so a peer probing a co-signer leaves no durable trace:
    /// the refusal path emits a warning and nothing else, and warnings are not
    /// evidence a holder still has next week.
    ///
    /// Carries no reason. The message a policy returns is a formatted string
    /// that a custom hook could build from requester-supplied content, and an
    /// audit log is the wrong place to accept text an adversary influences.
    /// The session id and message hash already identify which request was
    /// refused; the reason stays in the log line.
    SignRequestRefused,
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
        requester: Option<u16>,
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
        // Tagged rather than written only when present. With this field last,
        // an untagged form is already unambiguous, since an absent requester
        // contributes no bytes and share index 0 contributes two. The tag makes
        // that independent of position: these fields are concatenated without
        // delimiters, so appending anything after an untagged optional would
        // let "nobody recorded" followed by the next field collide with "peer 0
        // asked". Paying one byte now avoids a silent reattribution later.
        match requester {
            Some(idx) => {
                mac.update(&[1u8]);
                mac.update(&idx.to_le_bytes());
            }
            None => mac.update(&[0u8]),
        }

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
            self.requester,
        );
        bool::from(self.hmac.ct_eq(&expected))
    }
}

impl SigningOperation {
    /// Stable wire numbering for the entry HMAC.
    ///
    /// These values are covered by the HMAC, so they are append-only: renumber
    /// one and every entry already written under the old numbering fails
    /// verification, which reads as tampering rather than as a version skew.
    /// New operations take the next unused value and nothing else moves.
    fn discriminant(&self) -> u8 {
        match self {
            SigningOperation::SignRequestInitiated => 0,
            SigningOperation::CommitmentSent => 1,
            SigningOperation::SignatureShareSent => 2,
            SigningOperation::SignatureCompleted => 3,
            SigningOperation::SignatureReceived => 4,
            SigningOperation::SignRequestRefused => 5,
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningAuditLog {
    hmac_key: [u8; 32],
    #[zeroize(skip)]
    entries: Arc<RwLock<VecDeque<SigningAuditEntry>>>,
    /// Refusals live in their own ring so they cannot evict the entries above.
    ///
    /// The two streams have different bounds in practice. Accepted-path entries
    /// are limited by how many sessions can be open at once, while a refusal
    /// creates no session, so a peer can trigger one per request indefinitely.
    /// Sharing a single queue means a flood of refusals walks the whole history
    /// out of a FIFO, and it does that precisely on the node that has co-signing
    /// switched off, which is the configuration whose history is worth keeping.
    /// Recording refusals is only an improvement if it cannot destroy the record
    /// it was added to strengthen.
    #[zeroize(skip)]
    refusals: Arc<RwLock<VecDeque<SigningAuditEntry>>>,
    #[zeroize(skip)]
    max_entries: usize,
    #[zeroize(skip)]
    max_refusals: usize,
}

impl SigningAuditLog {
    pub fn new(hmac_key: [u8; 32]) -> Self {
        Self {
            hmac_key,
            entries: Arc::new(RwLock::new(VecDeque::new())),
            refusals: Arc::new(RwLock::new(VecDeque::new())),
            max_entries: 10000,
            // Enough to show a probe pattern and its shape over time; small
            // enough that the refusal stream is a bounded annex rather than a
            // second full-sized log.
            max_refusals: 1000,
        }
    }

    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = max;
        self
    }

    pub fn with_max_refusals(mut self, max: usize) -> Self {
        self.max_refusals = max;
        self
    }

    fn is_refusal(operation: &SigningOperation) -> bool {
        matches!(operation, SigningOperation::SignRequestRefused)
    }

    // Same reason as `compute_hmac` above: these are the fields of one audit
    // record, and grouping them into a struct would add a type whose only
    // purpose is to satisfy a lint about how they are passed.
    #[allow(clippy::too_many_arguments)]
    pub fn log_signing_operation(
        &self,
        session_id: [u8; 32],
        message: &[u8],
        signature: Option<&[u8; 64]>,
        participant_indices: Vec<u16>,
        our_index: u16,
        operation: SigningOperation,
        requester: Option<u16>,
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
            requester,
        );

        let entry = SigningAuditEntry {
            timestamp_ms,
            session_id,
            message_hash,
            signature_hash,
            participant_indices: participant_indices.clone(),
            our_index,
            operation: operation.clone(),
            requester,
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

        let (ring, cap) = if Self::is_refusal(&entry.operation) {
            (&self.refusals, self.max_refusals)
        } else {
            (&self.entries, self.max_entries)
        };
        let mut ring = ring.write();
        if ring.len() >= cap {
            ring.pop_front();
        }
        ring.push_back(entry);
    }

    /// Both rings, oldest first.
    ///
    /// Merged on the recorded timestamp rather than concatenated, so a caller
    /// reading the log still sees one chronological account. Splitting the
    /// storage is a retention decision and should not change what the log reads
    /// like.
    pub fn entries(&self) -> Vec<SigningAuditEntry> {
        let mut all: Vec<SigningAuditEntry> = self
            .entries
            .read()
            .iter()
            .chain(self.refusals.read().iter())
            .cloned()
            .collect();
        all.sort_by_key(|e| e.timestamp_ms);
        all
    }

    /// Refusals only, oldest first.
    pub fn refusals(&self) -> Vec<SigningAuditEntry> {
        self.refusals.read().iter().cloned().collect()
    }

    pub fn verify_all(&self) -> bool {
        self.entries
            .read()
            .iter()
            .chain(self.refusals.read().iter())
            .all(|e| e.verify(&self.hmac_key))
    }

    pub fn get_entries_for_session(&self, session_id: &[u8; 32]) -> Vec<SigningAuditEntry> {
        let mut found: Vec<SigningAuditEntry> = self
            .entries
            .read()
            .iter()
            .chain(self.refusals.read().iter())
            .filter(|e| &e.session_id == session_id)
            .cloned()
            .collect();
        found.sort_by_key(|e| e.timestamp_ms);
        found
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

    /// A flood of refusals must not walk accepted-path history out of the log.
    ///
    /// This is the property the separate ring exists for. Refusals create no
    /// session, so a peer can trigger them without limit, while accepted-path
    /// entries are bounded by how many sessions can be open. In one shared FIFO
    /// the unbounded stream evicts the bounded one, and it does that on the
    /// node that has co-signing switched off, whose history is the history most
    /// worth having.
    #[test]
    fn refusals_cannot_evict_accepted_entries() {
        let log = SigningAuditLog::new([7u8; 32])
            .with_max_entries(8)
            .with_max_refusals(4);

        let kept = [1u8; 32];
        log.log_signing_operation(
            kept,
            b"real",
            None,
            vec![1, 2],
            1,
            SigningOperation::CommitmentSent,
            None,
        );

        // Far past the refusal cap: under a shared queue this would evict the
        // entry above several times over.
        for i in 0..50u8 {
            log.log_signing_operation(
                [i; 32],
                b"probe",
                None,
                vec![1, 2],
                1,
                SigningOperation::SignRequestRefused,
                None,
            );
        }

        assert!(
            log.get_entries_for_session(&kept)
                .iter()
                .any(|e| matches!(e.operation, SigningOperation::CommitmentSent)),
            "the accepted entry must survive a refusal flood"
        );
        assert_eq!(
            log.refusals().len(),
            4,
            "refusals stay inside their own bound"
        );
        assert!(log.verify_all(), "both rings must remain verifiable");
    }

    /// Operation discriminants feed the entry HMAC, so a collision would let a
    /// swapped operation verify. Nothing else pins this: the log writes and
    /// verifies through the same function, so it agrees with itself either way.
    #[test]
    fn operation_discriminants_are_distinct() {
        let all = [
            SigningOperation::SignRequestInitiated,
            SigningOperation::CommitmentSent,
            SigningOperation::SignatureShareSent,
            SigningOperation::SignatureCompleted,
            SigningOperation::SignatureReceived,
            SigningOperation::SignRequestRefused,
        ];
        let mut seen = std::collections::HashSet::new();
        for op in &all {
            assert!(
                seen.insert(op.discriminant()),
                "discriminant {} is used twice; these are covered by the entry HMAC, \
                 so a duplicate lets one operation verify as another",
                op.discriminant()
            );
        }
    }

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
            None,
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
            None,
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
                None,
            );
        }

        let entries = log.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].session_id[0], 2);
    }

    /// Reattributing an entry must break its HMAC.
    ///
    /// A field the HMAC does not cover is a field anyone with write access can
    /// change, and "which peer asked for this" is exactly the claim an audit
    /// log exists to make unforgeable. Storing it without binding it would look
    /// identical in the API and mean nothing.
    #[test]
    fn the_requester_is_covered_by_the_entry_hmac() {
        let key = [9u8; 32];
        let log = SigningAuditLog::new(key);
        log.log_signing_operation(
            [1u8; 32],
            b"m",
            None,
            vec![1, 2],
            1,
            SigningOperation::CommitmentSent,
            Some(2),
        );

        let mut entry = log.entries().into_iter().next().expect("one entry");
        assert!(entry.verify(&key), "as written it verifies");

        entry.requester = Some(3);
        assert!(
            !entry.verify(&key),
            "pointing the entry at a different peer must invalidate it"
        );
    }

    /// An absent requester must not be interchangeable with share index 0.
    ///
    /// Pins the property rather than the encoding. It holds for the tagged form
    /// in use and also for an untagged one while this field stays last, so this
    /// test does not by itself justify the tag; it fails only if the requester
    /// stops being covered at all. The tag is defence against a later field
    /// being appended after it, which is a change no test here would catch.
    #[test]
    fn an_absent_requester_is_distinct_from_peer_zero() {
        let key = [9u8; 32];
        let log = SigningAuditLog::new(key);
        log.log_signing_operation(
            [1u8; 32],
            b"m",
            None,
            vec![1],
            1,
            SigningOperation::CommitmentSent,
            None,
        );

        let mut entry = log.entries().into_iter().next().expect("one entry");
        entry.requester = Some(0);
        assert!(
            !entry.verify(&key),
            "an unattributed entry must not verify as one attributed to peer 0"
        );
    }
}
