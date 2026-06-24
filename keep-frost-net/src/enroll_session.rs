// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Dealer-side session state for the trusted-dealer OPRF enrollment.
//!
//! The "box" (dealer) has already generated an OPRF secret and Shamir-split it;
//! it distributes each remote FROST peer (holder) that peer's secret key share
//! and collects an acknowledgement from each. This session tracks the expected
//! target indices and the set that has acked, completing once every target has
//! acknowledged. Mirrors [`crate::oprf_session::OprfUnlockSessionManager`]; the
//! holder keeps no enrollment session.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::error::{FrostNetError, Result};

/// Domain-separated session id for an OPRF enrollment, binding the dealer's
/// group and target set. Mirrors [`crate::oprf_session::derive_oprf_session_id`].
pub fn derive_oprf_enroll_session_id(
    group_pubkey: &[u8; 32],
    targets: &[u16],
    nonce: u64,
) -> [u8; 32] {
    let mut sorted_targets = targets.to_vec();
    sorted_targets.sort();

    let mut preimage = Vec::with_capacity(64 + targets.len() * 2);
    preimage.extend_from_slice(b"keep-frost-oprf-enroll-v1");
    preimage.extend_from_slice(group_pubkey);
    preimage.extend_from_slice(&nonce.to_be_bytes());
    preimage.extend_from_slice(&(sorted_targets.len() as u16).to_be_bytes());
    for t in &sorted_targets {
        preimage.extend_from_slice(&t.to_be_bytes());
    }

    keep_core::crypto::blake2b_256(&preimage)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OprfEnrollSessionState {
    Collecting,
    Complete,
    Failed(String),
    Expired,
}

/// Dealer-side state for one enrollment round. Tracks the target indices the
/// dealer expects acks from and which have acked; completes once all are in.
pub struct OprfEnrollSession {
    session_id: [u8; 32],
    group_pubkey: [u8; 32],
    expected: HashSet<u16>,
    acked: HashSet<u16>,
    threshold: u16,
    total: u16,
    state: OprfEnrollSessionState,
    created_at: Instant,
    timeout: Duration,
}

impl OprfEnrollSession {
    pub fn new(
        session_id: [u8; 32],
        group_pubkey: [u8; 32],
        expected: HashSet<u16>,
        threshold: u16,
        total: u16,
    ) -> Self {
        Self {
            session_id,
            group_pubkey,
            expected,
            acked: HashSet::new(),
            threshold,
            total,
            state: OprfEnrollSessionState::Collecting,
            created_at: Instant::now(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    pub fn group_pubkey(&self) -> &[u8; 32] {
        &self.group_pubkey
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    pub fn total(&self) -> u16 {
        self.total
    }

    pub fn state(&self) -> OprfEnrollSessionState {
        if self.created_at.elapsed() > self.timeout
            && self.state == OprfEnrollSessionState::Collecting
        {
            return OprfEnrollSessionState::Expired;
        }
        self.state.clone()
    }

    pub fn is_target(&self, share_index: u16) -> bool {
        self.expected.contains(&share_index)
    }

    /// Record one holder ack. Rejects a non-expected target, a duplicate, or an
    /// ack on a session no longer collecting. Flips to `Complete` once every
    /// expected target has acked.
    pub fn record_ack(&mut self, share_index: u16) -> Result<()> {
        if share_index == 0 {
            return Err(FrostNetError::Protocol(
                "Invalid share_index: must be non-zero".into(),
            ));
        }
        if self.state != OprfEnrollSessionState::Collecting {
            return Err(FrostNetError::Session(
                "Not accepting OPRF enrollment acks".into(),
            ));
        }
        if !self.expected.contains(&share_index) {
            return Err(FrostNetError::Session(format!(
                "Share {share_index} not an enrollment target"
            )));
        }
        if !self.acked.insert(share_index) {
            return Err(FrostNetError::Session(
                "Duplicate OPRF enrollment ack".into(),
            ));
        }
        if self.acked.len() == self.expected.len() {
            self.state = OprfEnrollSessionState::Complete;
        }
        Ok(())
    }

    pub fn has_all_acks(&self) -> bool {
        !self.expected.is_empty() && self.acked.len() == self.expected.len()
    }

    pub fn is_complete(&self) -> bool {
        self.state == OprfEnrollSessionState::Complete
    }

    pub fn is_expired(&self) -> bool {
        self.state() == OprfEnrollSessionState::Expired
    }
}

pub struct OprfEnrollSessionManager {
    active_sessions: HashMap<[u8; 32], OprfEnrollSession>,
    session_timeout: Duration,
}

impl OprfEnrollSessionManager {
    pub fn new() -> Self {
        Self {
            active_sessions: HashMap::new(),
            session_timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = timeout;
        self
    }

    const MAX_ACTIVE_SESSIONS: usize = 256;

    pub fn create_session(
        &mut self,
        session_id: [u8; 32],
        group_pubkey: [u8; 32],
        expected: HashSet<u16>,
        threshold: u16,
        total: u16,
    ) -> Result<&mut OprfEnrollSession> {
        if let Some(existing) = self.active_sessions.get(&session_id) {
            if !existing.is_expired() {
                return Err(FrostNetError::Session(
                    "OPRF enrollment session already active".into(),
                ));
            }
            self.active_sessions.remove(&session_id);
        }

        self.cleanup_expired();
        if self.active_sessions.len() >= Self::MAX_ACTIVE_SESSIONS {
            return Err(FrostNetError::Session(
                "Too many active OPRF enrollment sessions".into(),
            ));
        }

        let session = OprfEnrollSession::new(session_id, group_pubkey, expected, threshold, total)
            .with_timeout(self.session_timeout);

        self.active_sessions.insert(session_id, session);
        Ok(self
            .active_sessions
            .get_mut(&session_id)
            .expect("just inserted"))
    }

    pub fn get_session(&self, session_id: &[u8; 32]) -> Option<&OprfEnrollSession> {
        self.active_sessions.get(session_id)
    }

    pub fn get_session_mut(&mut self, session_id: &[u8; 32]) -> Option<&mut OprfEnrollSession> {
        self.active_sessions.get_mut(session_id)
    }

    pub fn complete_session(&mut self, session_id: &[u8; 32]) {
        self.active_sessions.remove(session_id);
    }

    pub fn cleanup_expired(&mut self) {
        self.active_sessions
            .retain(|_, session| !session.is_expired());
    }
}

impl Default for OprfEnrollSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_2_targets() -> OprfEnrollSession {
        let expected: HashSet<u16> = [2u16, 3u16].into_iter().collect();
        OprfEnrollSession::new([0x11u8; 32], [0x22u8; 32], expected, 2, 3)
    }

    #[test]
    fn record_ack_accepts_expected_targets_and_completes() {
        let mut session = session_2_targets();
        assert!(!session.has_all_acks());

        session.record_ack(2).expect("first expected ack");
        assert!(!session.has_all_acks(), "one of two acks must not complete");
        assert!(!session.is_complete());

        session.record_ack(3).expect("second expected ack");
        assert!(session.has_all_acks(), "all expected acks present");
        assert!(session.is_complete());
        assert_eq!(session.state(), OprfEnrollSessionState::Complete);
    }

    #[test]
    fn record_ack_rejects_unexpected_target() {
        let mut session = session_2_targets();
        assert!(
            session.record_ack(4).is_err(),
            "a non-target share index must be rejected"
        );
        assert!(
            session.record_ack(0).is_err(),
            "a zero share index must be rejected"
        );
        assert!(!session.has_all_acks());
    }

    #[test]
    fn record_ack_rejects_duplicate() {
        let mut session = session_2_targets();
        session.record_ack(2).expect("first ack");
        assert!(
            session.record_ack(2).is_err(),
            "a duplicate ack must be rejected"
        );
        assert!(!session.has_all_acks());
    }

    #[test]
    fn record_ack_rejected_after_complete() {
        let mut session = session_2_targets();
        session.record_ack(2).unwrap();
        session.record_ack(3).unwrap();
        assert!(session.is_complete());
        // A late ack on a completed session is refused (no longer collecting).
        assert!(session.record_ack(2).is_err());
    }

    #[test]
    fn derive_enroll_session_id_is_deterministic_and_input_sensitive() {
        let g = [0x01u8; 32];
        assert_eq!(
            derive_oprf_enroll_session_id(&g, &[2, 3], 7),
            derive_oprf_enroll_session_id(&g, &[3, 2], 7),
            "target order must not matter"
        );
        assert_ne!(
            derive_oprf_enroll_session_id(&g, &[2, 3], 7),
            derive_oprf_enroll_session_id(&g, &[2, 3], 8),
            "a different nonce must yield a distinct id"
        );
        assert_ne!(
            derive_oprf_enroll_session_id(&g, &[2, 3], 7),
            derive_oprf_enroll_session_id(&[0x02u8; 32], &[2, 3], 7),
            "a different group must yield a distinct id"
        );
    }

    #[test]
    fn manager_lifecycle_and_duplicate_guard() {
        let mut mgr = OprfEnrollSessionManager::new();
        let sid = [0x44u8; 32];
        let expected: HashSet<u16> = [2u16, 3u16].into_iter().collect();
        mgr.create_session(sid, [0x22u8; 32], expected.clone(), 2, 3)
            .unwrap();
        assert!(mgr.get_session(&sid).is_some());

        assert!(
            mgr.create_session(sid, [0x22u8; 32], expected, 2, 3)
                .is_err(),
            "a duplicate active session id must be refused"
        );

        mgr.complete_session(&sid);
        assert!(mgr.get_session(&sid).is_none());
    }
}
