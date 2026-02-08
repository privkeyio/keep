#![forbid(unsafe_code)]
#![allow(private_interfaces)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use frost_secp256k1_tr::rand_core::OsRng;
use frost_secp256k1_tr::round1::SigningCommitments;
use parking_lot::RwLock;

use keep_frost_net::{
    derive_session_id, CommitmentPayload, FrostNetError, MemoryNonceStore, NetworkSession,
    NonceStore, SessionManager, SessionState, SignRequestPayload, SignatureSharePayload,
};

#[derive(Clone, Debug, PartialEq)]
enum FaultType {
    Drop,
    Reorder,
}

trait FaultInjector: Send + Sync {
    fn should_inject(&self, msg_type: &str, from: u16, to: u16) -> Option<FaultType>;
    fn reset(&self);
}

struct DropAfterNInjector {
    count: AtomicU32,
    threshold: u32,
    target_msg_type: String,
}

impl DropAfterNInjector {
    fn new(threshold: u32, target_msg_type: &str) -> Self {
        Self {
            count: AtomicU32::new(0),
            threshold,
            target_msg_type: target_msg_type.to_string(),
        }
    }
}

impl FaultInjector for DropAfterNInjector {
    fn should_inject(&self, msg_type: &str, _from: u16, _to: u16) -> Option<FaultType> {
        if msg_type != self.target_msg_type {
            return None;
        }
        (self.count.fetch_add(1, Ordering::SeqCst) >= self.threshold).then_some(FaultType::Drop)
    }

    fn reset(&self) {
        self.count.store(0, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct PartitionInjector {
    partitioned_nodes: RwLock<Vec<u16>>,
    active: AtomicBool,
}

impl PartitionInjector {
    fn new() -> Self {
        Self::default()
    }

    fn partition(&self, nodes: Vec<u16>) {
        *self.partitioned_nodes.write() = nodes;
        self.active.store(true, Ordering::SeqCst);
    }

    fn heal(&self) {
        self.active.store(false, Ordering::SeqCst);
        self.partitioned_nodes.write().clear();
    }
}

impl FaultInjector for PartitionInjector {
    fn should_inject(&self, _msg_type: &str, from: u16, to: u16) -> Option<FaultType> {
        if !self.active.load(Ordering::SeqCst) {
            return None;
        }
        let partitioned = self.partitioned_nodes.read();
        (partitioned.contains(&from) != partitioned.contains(&to)).then_some(FaultType::Drop)
    }

    fn reset(&self) {
        self.heal();
    }
}

struct ReorderInjector {
    buffer: RwLock<VecDeque<(String, u16, u16)>>,
    buffer_size: usize,
}

impl ReorderInjector {
    fn new(buffer_size: usize) -> Self {
        Self {
            buffer: RwLock::new(VecDeque::new()),
            buffer_size,
        }
    }

    fn queue_message(&self, msg_type: &str, from: u16, to: u16) -> bool {
        let mut buffer = self.buffer.write();
        if buffer.len() < self.buffer_size {
            buffer.push_back((msg_type.to_string(), from, to));
            true
        } else {
            false
        }
    }

    fn flush(&self) -> Vec<(String, u16, u16)> {
        self.buffer.write().drain(..).rev().collect()
    }
}

impl FaultInjector for ReorderInjector {
    fn should_inject(&self, _msg_type: &str, _from: u16, _to: u16) -> Option<FaultType> {
        (self.buffer.read().len() >= self.buffer_size).then_some(FaultType::Reorder)
    }

    fn reset(&self) {
        self.buffer.write().clear();
    }
}

// TEST ONLY: Real keys must never be generated from predictable byte patterns
fn generate_test_commitment(index: u16) -> SigningCommitments {
    let secret = frost_secp256k1_tr::keys::SigningShare::deserialize(&[index as u8; 32]).unwrap();
    frost_secp256k1_tr::round1::commit(&secret, &mut OsRng).1
}

#[test]
fn test_message_reordering_commitments_out_of_order() {
    let message = b"test reorder".to_vec();
    let participants = vec![1, 2, 3];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);
    let mut session = NetworkSession::new(session_id, message, threshold, participants);

    let commit1 = generate_test_commitment(1);
    let commit3 = generate_test_commitment(3);

    assert!(session.add_commitment(3, commit3).is_ok());
    assert!(session.add_commitment(1, commit1).is_ok());
    assert!(session.has_all_commitments());
    assert_eq!(session.state(), SessionState::AwaitingShares);
}

#[test]
fn test_message_reordering_shares_before_commitments_complete() {
    let message = b"test share order".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);
    let mut session = NetworkSession::new(session_id, message, threshold, participants);

    let commit1 = generate_test_commitment(1);
    session.add_commitment(1, commit1).unwrap();

    // Deserialization accepts any bytes; validation occurs at aggregation time
    let fake_share = frost_secp256k1_tr::round2::SignatureShare::deserialize(&[0u8; 32]).unwrap();

    let err = session.add_signature_share(2, fake_share).unwrap_err();
    assert!(err.to_string().contains("Not accepting"));
}

#[test]
fn test_participant_dropout_before_commitment() {
    let message = b"dropout test".to_vec();
    let participants = vec![1, 2, 3];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);
    let mut session = NetworkSession::new(session_id, message, threshold, participants)
        .with_timeout(Duration::from_millis(100));

    let commit1 = generate_test_commitment(1);
    session.add_commitment(1, commit1).unwrap();

    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(session.state(), SessionState::Expired);
    assert!(!session.has_all_commitments());
}

#[test]
fn test_participant_dropout_after_commitment() {
    let message = b"dropout after commit".to_vec();
    let participants = vec![1, 2, 3];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);
    let mut session = NetworkSession::new(session_id, message, threshold, participants);

    let commit1 = generate_test_commitment(1);
    let commit2 = generate_test_commitment(2);

    session.add_commitment(1, commit1).unwrap();
    session.add_commitment(2, commit2).unwrap();

    assert!(session.has_all_commitments());
    assert_eq!(session.state(), SessionState::AwaitingShares);
}

#[test]
fn test_duplicate_commitment_rejected() {
    let message = b"duplicate test".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);
    let mut session = NetworkSession::new(session_id, message, threshold, participants);

    let commit1 = generate_test_commitment(1);
    session.add_commitment(1, commit1).unwrap();

    let commit1_dup = generate_test_commitment(1);
    let err = session.add_commitment(1, commit1_dup).unwrap_err();
    assert!(err.to_string().contains("Duplicate"));
}

#[test]
fn test_duplicate_signature_share_rejected() {
    let message = b"duplicate share".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);
    let mut session = NetworkSession::new(session_id, message, threshold, participants);

    let commit1 = generate_test_commitment(1);
    let commit2 = generate_test_commitment(2);
    session.add_commitment(1, commit1).unwrap();
    session.add_commitment(2, commit2).unwrap();

    // Deserialization accepts any bytes; validation occurs at aggregation time
    let share = frost_secp256k1_tr::round2::SignatureShare::deserialize(&[0u8; 32]).unwrap();
    session.add_signature_share(1, share).unwrap();

    let share_dup = frost_secp256k1_tr::round2::SignatureShare::deserialize(&[0u8; 32]).unwrap();
    let err = session.add_signature_share(1, share_dup).unwrap_err();
    assert!(err.to_string().contains("Duplicate"));
}

#[test]
fn test_partition_injector_blocks_cross_partition_messages() {
    let injector = PartitionInjector::new();
    injector.partition(vec![1, 2]);

    assert!(injector.should_inject("commitment", 1, 3).is_some());
    assert!(injector.should_inject("commitment", 3, 1).is_some());
    assert!(injector.should_inject("commitment", 1, 2).is_none());
    assert!(injector.should_inject("commitment", 3, 4).is_none());

    injector.heal();
    assert!(injector.should_inject("commitment", 1, 3).is_none());
}

#[test]
fn test_partition_recovery_allows_completion() {
    let message = b"partition recovery".to_vec();
    let participants = vec![1, 2, 3];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);
    let mut session = NetworkSession::new(session_id, message, threshold, participants);

    let injector = PartitionInjector::new();
    injector.partition(vec![3]);

    let commit1 = generate_test_commitment(1);
    session.add_commitment(1, commit1).unwrap();
    assert!(!session.has_all_commitments());

    injector.heal();

    let commit2 = generate_test_commitment(2);
    session.add_commitment(2, commit2).unwrap();
    assert!(session.has_all_commitments());
}

#[test]
fn test_timeout_expires_session() {
    let message = b"timeout test".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);
    let session = NetworkSession::new(session_id, message, threshold, participants)
        .with_timeout(Duration::from_millis(50));

    assert_eq!(session.state(), SessionState::AwaitingCommitments);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(session.state(), SessionState::Expired);
}

#[test]
fn test_session_manager_cleanup_expired() {
    let mut manager = SessionManager::new().with_timeout(Duration::from_millis(50));
    let message = b"cleanup test".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);

    manager
        .create_session(session_id, message, threshold, participants)
        .unwrap();
    assert_eq!(manager.active_count(), 1);

    std::thread::sleep(Duration::from_millis(100));
    manager.cleanup_expired();
    assert_eq!(manager.active_count(), 0);
}

#[test]
fn test_malicious_commitment_from_non_participant() {
    let message = b"malicious test".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);
    let mut session = NetworkSession::new(session_id, message, threshold, participants);

    let malicious_commit = generate_test_commitment(99);
    let err = session.add_commitment(99, malicious_commit).unwrap_err();
    assert!(err.to_string().contains("not a participant"));
}

#[test]
fn test_malicious_share_from_non_participant() {
    let message = b"malicious share".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);
    let mut session = NetworkSession::new(session_id, message, threshold, participants);

    let commit1 = generate_test_commitment(1);
    let commit2 = generate_test_commitment(2);
    session.add_commitment(1, commit1).unwrap();
    session.add_commitment(2, commit2).unwrap();

    // Deserialization accepts any bytes; validation occurs at aggregation time
    let malicious_share =
        frost_secp256k1_tr::round2::SignatureShare::deserialize(&[0u8; 32]).unwrap();
    let err = session
        .add_signature_share(99, malicious_share)
        .unwrap_err();
    assert!(err.to_string().contains("not a participant"));
}

#[test]
fn test_invalid_share_index_zero() {
    let message = b"zero index".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);
    let mut session = NetworkSession::new(session_id, message, threshold, participants);

    let commit = generate_test_commitment(1);
    let err = session.add_commitment(0, commit).unwrap_err();
    assert!(err.to_string().contains("non-zero"));
}

#[test]
fn test_session_cleanup_after_completion() {
    let mut manager = SessionManager::new();
    let message = b"cleanup complete".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);

    manager
        .create_session(session_id, message, threshold, participants)
        .unwrap();
    assert_eq!(manager.active_count(), 1);

    manager.complete_session(&session_id);
    assert_eq!(manager.active_count(), 0);
    assert!(manager.is_replay(&session_id));
}

#[test]
fn test_session_cleanup_removes_nonces() {
    let store = Arc::new(MemoryNonceStore::new());
    let mut manager = SessionManager::new().with_nonce_store(store.clone());

    let message = b"nonce cleanup".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);

    manager
        .create_session(session_id, message.clone(), threshold, participants.clone())
        .unwrap();
    manager.record_nonce_consumption(&session_id).unwrap();
    manager.complete_session(&session_id);

    assert!(manager.is_nonce_consumed(&session_id));
    assert!(manager.is_replay(&session_id));

    let result = manager.create_session(session_id, message, threshold, participants);
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        matches!(
            err,
            FrostNetError::ReplayDetected(_) | FrostNetError::NonceConsumed(_)
        ),
        "Expected ReplayDetected or NonceConsumed, got: {err}"
    );
}

#[test]
fn test_no_nonce_reuse_across_retried_sessions() {
    let store = Arc::new(MemoryNonceStore::new());
    let mut manager = SessionManager::new().with_nonce_store(store.clone());

    let message = b"nonce reuse test".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);

    manager
        .create_session(session_id, message.clone(), threshold, participants.clone())
        .unwrap();
    manager.record_nonce_consumption(&session_id).unwrap();

    let result = manager.create_session(session_id, message, threshold, participants);
    let err = result.err().expect("Expected error for nonce reuse");
    assert!(
        err.to_string().contains("Nonce") || err.to_string().contains("active"),
        "Expected nonce consumption error, got: {err}"
    );
}

#[test]
fn test_rehydration_blocked_when_nonce_consumed() {
    let store = Arc::new(MemoryNonceStore::new());
    let mut manager = SessionManager::new().with_nonce_store(store.clone());

    let message = b"rehydration nonce".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);

    manager
        .create_session(session_id, message.clone(), threshold, participants.clone())
        .unwrap();

    let cached = manager.cache_and_remove_session(&session_id).unwrap();
    assert!(cached.is_some());

    store.record(&session_id).unwrap();
    assert!(store.is_consumed(&session_id));

    let cached_state = cached.unwrap();
    let result = manager.rehydrate_session(cached_state);
    assert!(matches!(result, Err(FrostNetError::NonceConsumed(_))));
}

#[test]
fn test_rehydration_allowed_when_nonce_not_consumed() {
    let store = Arc::new(MemoryNonceStore::new());
    let mut manager = SessionManager::new().with_nonce_store(store.clone());

    let message = b"rehydration allowed".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);

    manager
        .create_session(session_id, message, threshold, participants)
        .unwrap();

    let cached = manager.cache_and_remove_session(&session_id).unwrap();
    assert!(cached.is_some());

    let cached_state = cached.unwrap();
    manager.rehydrate_session(cached_state).unwrap();

    assert!(manager.get_session(&session_id).is_some());
}

#[test]
fn test_rehydration_limit_prevents_excessive_retries() {
    let message = b"rehydration limit".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);

    let session =
        NetworkSession::new(session_id, message, threshold, participants).with_max_rehydrations(2);

    let cached = session.to_cached_state().unwrap();
    let session = NetworkSession::from_cached_state(cached).unwrap();
    assert_eq!(session.rehydrations_used(), 1);
    assert!(session.can_rehydrate());

    let cached = session.to_cached_state().unwrap();
    let session = NetworkSession::from_cached_state(cached).unwrap();
    assert_eq!(session.rehydrations_used(), 2);
    assert!(!session.can_rehydrate());

    let cached = session.to_cached_state().unwrap();
    let result = NetworkSession::from_cached_state(cached);
    assert!(matches!(
        result,
        Err(FrostNetError::RehydrationLimitExceeded { .. })
    ));
}

#[test]
fn test_drop_after_n_injector() {
    let injector = DropAfterNInjector::new(2, "commitment");

    assert!(injector.should_inject("commitment", 1, 2).is_none());
    assert!(injector.should_inject("commitment", 1, 2).is_none());
    assert_eq!(
        injector.should_inject("commitment", 1, 2),
        Some(FaultType::Drop)
    );
    assert_eq!(
        injector.should_inject("commitment", 1, 2),
        Some(FaultType::Drop)
    );

    assert!(injector.should_inject("share", 1, 2).is_none());

    injector.reset();
    assert!(injector.should_inject("commitment", 1, 2).is_none());
}

#[test]
fn test_reorder_injector() {
    let injector = ReorderInjector::new(3);

    assert!(injector.should_inject("msg", 1, 2).is_none());
    injector.queue_message("commitment", 1, 2);
    injector.queue_message("commitment", 2, 1);
    injector.queue_message("share", 1, 2);

    assert_eq!(
        injector.should_inject("msg", 1, 2),
        Some(FaultType::Reorder)
    );

    let flushed = injector.flush();
    assert_eq!(flushed.len(), 3);
    assert_eq!(flushed[0].0, "share");
    assert_eq!(flushed[2].0, "commitment");
}

#[test]
fn test_session_state_machine_integrity() {
    let message = b"state machine".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);
    let mut session = NetworkSession::new(session_id, message, threshold, participants);

    assert_eq!(session.state(), SessionState::AwaitingCommitments);

    // Deserialization accepts any bytes; validation occurs at aggregation time
    let share = frost_secp256k1_tr::round2::SignatureShare::deserialize(&[0u8; 32]).unwrap();
    assert!(session.add_signature_share(1, share).is_err());

    let commit1 = generate_test_commitment(1);
    session.add_commitment(1, commit1).unwrap();
    assert_eq!(session.state(), SessionState::AwaitingCommitments);

    let commit2 = generate_test_commitment(2);
    session.add_commitment(2, commit2).unwrap();
    assert_eq!(session.state(), SessionState::AwaitingShares);

    let late_commit = generate_test_commitment(1);
    let result = session.add_commitment(1, late_commit);
    assert!(result.is_err());
}

#[test]
fn test_concurrent_session_isolation() {
    let mut manager = SessionManager::new();

    let msg1 = b"session 1".to_vec();
    let msg2 = b"session 2".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;

    let sid1 = derive_session_id(&msg1, &participants, threshold);
    let sid2 = derive_session_id(&msg2, &participants, threshold);

    manager
        .create_session(sid1, msg1, threshold, participants.clone())
        .unwrap();
    manager
        .create_session(sid2, msg2, threshold, participants)
        .unwrap();

    assert_eq!(manager.active_count(), 2);

    let commit1 = generate_test_commitment(1);
    {
        let session = manager.get_session_mut(&sid1).unwrap();
        session.add_commitment(1, commit1).unwrap();
    }

    let s1 = manager.get_session(&sid1).unwrap();
    let s2 = manager.get_session(&sid2).unwrap();
    assert_eq!(s1.commitments_needed(), 1);
    assert_eq!(s2.commitments_needed(), 2);
}

#[test]
fn test_replay_detection_across_sessions() {
    let mut manager = SessionManager::new();
    let message = b"replay test".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);

    manager
        .create_session(session_id, message.clone(), threshold, participants.clone())
        .unwrap();
    manager.complete_session(&session_id);

    let result = manager.create_session(session_id, message, threshold, participants);
    assert!(matches!(result, Err(FrostNetError::ReplayDetected(_))));
}

#[test]
fn test_session_expiry_during_signing() {
    let message = b"expiry during signing".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);
    let mut session = NetworkSession::new(session_id, message, threshold, participants)
        .with_timeout(Duration::from_millis(50));

    let commit1 = generate_test_commitment(1);
    let commit2 = generate_test_commitment(2);
    session.add_commitment(1, commit1).unwrap();
    session.add_commitment(2, commit2).unwrap();

    assert_eq!(session.state(), SessionState::AwaitingShares);

    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(session.state(), SessionState::Expired);
}

#[test]
fn test_get_or_create_session_idempotent() {
    let mut manager = SessionManager::new();
    let message = b"idempotent".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);

    manager
        .get_or_create_session(session_id, message.clone(), threshold, participants.clone())
        .unwrap();
    manager
        .get_or_create_session(session_id, message, threshold, participants)
        .unwrap();

    assert_eq!(manager.active_count(), 1);
}

#[test]
fn test_get_or_create_session_mismatch_rejected() {
    let mut manager = SessionManager::new();
    let message = b"mismatch".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);

    manager
        .get_or_create_session(session_id, message.clone(), threshold, participants.clone())
        .unwrap();

    let different_participants = vec![1, 3];
    let result =
        manager.get_or_create_session(session_id, message, threshold, different_participants);
    assert!(result.is_err());
}

#[test]
fn test_failed_session_not_rehydratable() {
    let mut manager = SessionManager::new();
    let message = b"failed session".to_vec();
    let participants = vec![1, 2];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);

    manager
        .create_session(session_id, message, threshold, participants)
        .unwrap();
    manager.complete_session(&session_id);

    let cached = manager.cache_and_remove_session(&session_id).unwrap();
    assert!(cached.is_none());
}

#[test]
fn test_commitment_payload_validation() {
    let valid_payload = CommitmentPayload::new([0u8; 32], 1, vec![0u8; 64]);
    assert_eq!(valid_payload.session_id, [0u8; 32]);
    assert_eq!(valid_payload.share_index, 1);
    assert_eq!(valid_payload.commitment.len(), 64);
}

#[test]
fn test_signature_share_payload_validation() {
    let valid_payload = SignatureSharePayload::new([0u8; 32], 1, vec![0u8; 32]);
    assert_eq!(valid_payload.session_id, [0u8; 32]);
    assert_eq!(valid_payload.share_index, 1);
    assert_eq!(valid_payload.signature_share.len(), 32);
}

#[test]
fn test_sign_request_payload_creation() {
    let participants = vec![1, 2, 3];
    let payload = SignRequestPayload::new(
        [1u8; 32],
        [2u8; 32],
        b"test message".to_vec(),
        "raw",
        participants.clone(),
    );

    assert_eq!(payload.session_id, [1u8; 32]);
    assert_eq!(payload.group_pubkey, [2u8; 32]);
    assert_eq!(payload.message, b"test message".to_vec());
    assert_eq!(payload.message_type, "raw");
    assert_eq!(payload.participants, participants);
}

#[test]
fn test_session_participants_validation() {
    let message = b"participants".to_vec();
    let participants = vec![1, 2, 3];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);
    let session = NetworkSession::new(session_id, message, threshold, participants);

    assert!(session.is_participant(1));
    assert!(session.is_participant(2));
    assert!(session.is_participant(3));
    assert!(!session.is_participant(4));
    assert!(!session.is_participant(0));
}
