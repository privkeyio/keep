#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use frost_secp256k1_tr::{
    keys::PublicKeyPackage,
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Identifier, Signature, SigningPackage,
};

use crate::error::{FrostNetError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    AwaitingCommitments,
    AwaitingShares,
    Complete,
    Failed,
    Expired,
}

pub struct NetworkSession {
    session_id: [u8; 32],
    message: Vec<u8>,
    threshold: u16,
    participants: Vec<u16>,
    state: SessionState,
    created_at: Instant,
    timeout: Duration,
    commitments: BTreeMap<Identifier, SigningCommitments>,
    signature_shares: BTreeMap<Identifier, SignatureShare>,
    our_nonces: Option<SigningNonces>,
    our_commitment: Option<SigningCommitments>,
    signature: Option<Signature>,
}

impl NetworkSession {
    pub fn new(
        session_id: [u8; 32],
        message: Vec<u8>,
        threshold: u16,
        participants: Vec<u16>,
    ) -> Self {
        Self {
            session_id,
            message,
            threshold,
            participants,
            state: SessionState::AwaitingCommitments,
            created_at: Instant::now(),
            timeout: Duration::from_secs(30),
            commitments: BTreeMap::new(),
            signature_shares: BTreeMap::new(),
            our_nonces: None,
            our_commitment: None,
            signature: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    pub fn message(&self) -> &[u8] {
        &self.message
    }

    pub fn state(&self) -> SessionState {
        if self.created_at.elapsed() > self.timeout && self.state != SessionState::Complete {
            return SessionState::Expired;
        }
        self.state
    }

    pub fn is_participant(&self, share_index: u16) -> bool {
        self.participants.contains(&share_index)
    }

    pub fn participants(&self) -> &[u16] {
        &self.participants
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    pub fn set_our_nonces(&mut self, nonces: SigningNonces) {
        self.our_nonces = Some(nonces);
    }

    pub fn our_nonces(&self) -> Option<&SigningNonces> {
        self.our_nonces.as_ref()
    }

    pub fn set_our_commitment(&mut self, commitment: SigningCommitments) {
        self.our_commitment = Some(commitment);
    }

    pub fn our_commitment(&self) -> Option<&SigningCommitments> {
        self.our_commitment.as_ref()
    }

    pub fn add_commitment(
        &mut self,
        share_index: u16,
        commitment: SigningCommitments,
    ) -> Result<()> {
        if share_index == 0 {
            return Err(FrostNetError::Protocol(
                "Invalid share_index: must be non-zero".into(),
            ));
        }

        if self.state != SessionState::AwaitingCommitments {
            return Err(FrostNetError::Session("Not accepting commitments".into()));
        }

        if !self.is_participant(share_index) {
            return Err(FrostNetError::Session(format!(
                "Share {} not a participant",
                share_index
            )));
        }

        let id = Identifier::try_from(share_index)
            .map_err(|e| FrostNetError::Crypto(format!("Invalid identifier: {}", e)))?;

        if self.commitments.contains_key(&id) {
            return Err(FrostNetError::Session("Duplicate commitment".into()));
        }

        self.commitments.insert(id, commitment);

        if self.commitments.len() >= self.threshold as usize {
            self.state = SessionState::AwaitingShares;
        }

        Ok(())
    }

    pub fn commitments_needed(&self) -> usize {
        self.threshold.saturating_sub(self.commitments.len() as u16) as usize
    }

    pub fn has_all_commitments(&self) -> bool {
        self.commitments.len() >= self.threshold as usize
    }

    pub fn get_signing_package(&self) -> Result<SigningPackage> {
        if !self.has_all_commitments() {
            return Err(FrostNetError::Session("Not enough commitments".into()));
        }

        Ok(SigningPackage::new(self.commitments.clone(), &self.message))
    }

    pub fn add_signature_share(&mut self, share_index: u16, share: SignatureShare) -> Result<()> {
        if share_index == 0 {
            return Err(FrostNetError::Protocol(
                "Invalid share_index: must be non-zero".into(),
            ));
        }

        if self.state != SessionState::AwaitingShares {
            return Err(FrostNetError::Session("Not accepting shares".into()));
        }

        if !self.is_participant(share_index) {
            return Err(FrostNetError::Session(format!(
                "Share {} not a participant",
                share_index
            )));
        }

        let id = Identifier::try_from(share_index)
            .map_err(|e| FrostNetError::Crypto(format!("Invalid identifier: {}", e)))?;

        if self.signature_shares.contains_key(&id) {
            return Err(FrostNetError::Session("Duplicate signature share".into()));
        }

        self.signature_shares.insert(id, share);
        Ok(())
    }

    pub fn shares_needed(&self) -> usize {
        self.threshold
            .saturating_sub(self.signature_shares.len() as u16) as usize
    }

    pub fn has_all_shares(&self) -> bool {
        self.signature_shares.len() >= self.threshold as usize
    }

    pub fn try_aggregate(&mut self, pubkey_pkg: &PublicKeyPackage) -> Result<Option<[u8; 64]>> {
        if !self.has_all_shares() {
            return Ok(None);
        }

        let signing_package = self.get_signing_package()?;

        match frost_secp256k1_tr::aggregate(&signing_package, &self.signature_shares, pubkey_pkg) {
            Ok(signature) => {
                let serialized = signature
                    .serialize()
                    .map_err(|e| FrostNetError::Crypto(format!("Serialize signature: {}", e)))?;

                let bytes = serialized.as_slice();
                if bytes.len() != 64 {
                    return Err(FrostNetError::Crypto("Invalid signature length".into()));
                }

                let mut result = [0u8; 64];
                result.copy_from_slice(bytes);

                self.signature = Some(signature);
                self.state = SessionState::Complete;

                Ok(Some(result))
            }
            Err(e) => {
                self.state = SessionState::Failed;
                Err(FrostNetError::Crypto(format!("Aggregation failed: {}", e)))
            }
        }
    }

    pub fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    pub fn is_complete(&self) -> bool {
        self.state == SessionState::Complete
    }

    pub fn is_expired(&self) -> bool {
        self.state() == SessionState::Expired
    }

    pub fn elapsed(&self) -> Duration {
        self.created_at.elapsed()
    }
}

pub struct SessionManager {
    active_sessions: HashMap<[u8; 32], NetworkSession>,
    completed_sessions: HashSet<[u8; 32]>,
    completed_order: VecDeque<[u8; 32]>,
    max_completed_history: usize,
    session_timeout: Duration,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            active_sessions: HashMap::new(),
            completed_sessions: HashSet::new(),
            completed_order: VecDeque::new(),
            max_completed_history: 1000,
            session_timeout: Duration::from_secs(300),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = timeout;
        self
    }

    pub fn create_session(
        &mut self,
        session_id: [u8; 32],
        message: Vec<u8>,
        threshold: u16,
        participants: Vec<u16>,
    ) -> Result<&mut NetworkSession> {
        if self.completed_sessions.contains(&session_id) {
            return Err(FrostNetError::ReplayDetected(hex::encode(session_id)));
        }

        if self.active_sessions.contains_key(&session_id) {
            let session = self.active_sessions.get(&session_id).unwrap();
            if !session.is_expired() {
                return Err(FrostNetError::Session("Session already active".into()));
            }
            self.active_sessions.remove(&session_id);
        }

        let session = NetworkSession::new(session_id, message, threshold, participants)
            .with_timeout(self.session_timeout);

        self.active_sessions.insert(session_id, session);
        Ok(self.active_sessions.get_mut(&session_id).unwrap())
    }

    pub fn get_session(&self, session_id: &[u8; 32]) -> Option<&NetworkSession> {
        self.active_sessions.get(session_id)
    }

    pub fn get_session_mut(&mut self, session_id: &[u8; 32]) -> Option<&mut NetworkSession> {
        self.active_sessions.get_mut(session_id)
    }

    pub fn get_or_create_session(
        &mut self,
        session_id: [u8; 32],
        message: Vec<u8>,
        threshold: u16,
        participants: Vec<u16>,
    ) -> Result<&mut NetworkSession> {
        if self.completed_sessions.contains(&session_id) {
            return Err(FrostNetError::ReplayDetected(hex::encode(session_id)));
        }

        if let Some(existing) = self.active_sessions.get(&session_id) {
            if existing.message() != message
                || existing.threshold() != threshold
                || existing.participants() != participants
            {
                return Err(FrostNetError::Session("Session parameters mismatch".into()));
            }
        } else {
            let session = NetworkSession::new(session_id, message, threshold, participants)
                .with_timeout(self.session_timeout);
            self.active_sessions.insert(session_id, session);
        }

        Ok(self.active_sessions.get_mut(&session_id).unwrap())
    }

    pub fn complete_session(&mut self, session_id: &[u8; 32]) {
        self.active_sessions.remove(session_id);

        if !self.completed_sessions.contains(session_id) {
            self.completed_sessions.insert(*session_id);
            self.completed_order.push_back(*session_id);
        }

        while self.completed_sessions.len() > self.max_completed_history {
            if let Some(oldest) = self.completed_order.pop_front() {
                self.completed_sessions.remove(&oldest);
            } else {
                break;
            }
        }
    }

    pub fn cleanup_expired(&mut self) {
        let expired: Vec<[u8; 32]> = self
            .active_sessions
            .iter()
            .filter(|(_id, session): &(&[u8; 32], &NetworkSession)| session.is_expired())
            .map(|(id, _session)| *id)
            .collect();

        for id in expired {
            self.active_sessions.remove(&id);
        }
    }

    pub fn active_count(&self) -> usize {
        self.active_sessions.len()
    }

    pub fn is_replay(&self, session_id: &[u8; 32]) -> bool {
        self.completed_sessions.contains(session_id)
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle() {
        let session_id = [1u8; 32];
        let message = b"test message".to_vec();
        let session = NetworkSession::new(session_id, message, 2, vec![1, 2, 3]);

        assert_eq!(session.state(), SessionState::AwaitingCommitments);
        assert_eq!(session.commitments_needed(), 2);
    }

    #[test]
    fn test_session_manager_replay_protection() {
        let mut manager = SessionManager::new();
        let session_id = [1u8; 32];

        manager
            .create_session(session_id, vec![], 2, vec![1, 2])
            .unwrap();
        manager.complete_session(&session_id);

        let result = manager.create_session(session_id, vec![], 2, vec![1, 2]);
        assert!(result.is_err());
        assert!(manager.is_replay(&session_id));
    }

    #[test]
    fn test_participant_check() {
        let session = NetworkSession::new([1u8; 32], vec![], 2, vec![1, 2, 3]);
        assert!(session.is_participant(1));
        assert!(session.is_participant(2));
        assert!(!session.is_participant(4));
    }
}
