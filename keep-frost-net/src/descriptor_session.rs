// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::error::{FrostNetError, Result};
use crate::protocol::{WalletPolicy, DESCRIPTOR_SESSION_TIMEOUT_SECS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorSessionState {
    Proposed,
    Finalized,
    Complete,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct XpubContribution {
    pub account_xpub: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct FinalizedDescriptor {
    pub external: String,
    pub internal: String,
    pub policy_hash: [u8; 32],
}

pub struct DescriptorSession {
    session_id: [u8; 32],
    group_pubkey: [u8; 32],
    policy: WalletPolicy,
    network: String,
    contributions: BTreeMap<u16, XpubContribution>,
    expected_contributors: HashSet<u16>,
    descriptor: Option<FinalizedDescriptor>,
    acks: HashSet<u16>,
    expected_acks: HashSet<u16>,
    state: DescriptorSessionState,
    created_at: Instant,
    timeout: Duration,
}

impl DescriptorSession {
    pub fn new(
        session_id: [u8; 32],
        group_pubkey: [u8; 32],
        policy: WalletPolicy,
        network: String,
        expected_contributors: HashSet<u16>,
        expected_acks: HashSet<u16>,
        timeout: Duration,
    ) -> Self {
        Self {
            session_id,
            group_pubkey,
            policy,
            network,
            contributions: BTreeMap::new(),
            expected_contributors,
            descriptor: None,
            acks: HashSet::new(),
            expected_acks,
            state: DescriptorSessionState::Proposed,
            created_at: Instant::now(),
            timeout,
        }
    }

    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    pub fn group_pubkey(&self) -> &[u8; 32] {
        &self.group_pubkey
    }

    pub fn policy(&self) -> &WalletPolicy {
        &self.policy
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn state(&self) -> &DescriptorSessionState {
        &self.state
    }

    pub fn add_contribution(
        &mut self,
        share_index: u16,
        xpub: String,
        fingerprint: String,
    ) -> Result<()> {
        if self.state != DescriptorSessionState::Proposed {
            return Err(FrostNetError::Session("Not accepting contributions".into()));
        }

        if !self.expected_contributors.contains(&share_index) {
            return Err(FrostNetError::Session(format!(
                "Share {share_index} not an expected contributor"
            )));
        }

        if self.contributions.contains_key(&share_index) {
            return Err(FrostNetError::Session("Duplicate contribution".into()));
        }

        self.contributions.insert(
            share_index,
            XpubContribution {
                account_xpub: xpub,
                fingerprint,
            },
        );

        Ok(())
    }

    pub fn has_all_contributions(&self) -> bool {
        self.expected_contributors
            .iter()
            .all(|idx| self.contributions.contains_key(idx))
    }

    pub fn contributions(&self) -> &BTreeMap<u16, XpubContribution> {
        &self.contributions
    }

    pub fn set_finalized(&mut self, descriptor: FinalizedDescriptor) -> Result<()> {
        if self.state != DescriptorSessionState::Proposed {
            return Err(FrostNetError::Session(
                "Can only finalize from Proposed state".into(),
            ));
        }

        self.descriptor = Some(descriptor);
        self.state = DescriptorSessionState::Finalized;
        Ok(())
    }

    pub fn add_ack(&mut self, share_index: u16, descriptor_hash: [u8; 32]) -> Result<()> {
        if self.state != DescriptorSessionState::Finalized {
            return Err(FrostNetError::Session("Not accepting ACKs".into()));
        }

        if !self.expected_acks.contains(&share_index) {
            return Err(FrostNetError::Session(format!(
                "Share {share_index} not an expected ACK sender"
            )));
        }

        let finalized = self
            .descriptor
            .as_ref()
            .ok_or_else(|| FrostNetError::Session("No finalized descriptor".into()))?;

        let mut hasher = Sha256::new();
        hasher.update(finalized.external.as_bytes());
        let expected_hash: [u8; 32] = hasher.finalize().into();

        if descriptor_hash != expected_hash {
            return Err(FrostNetError::Session("Descriptor hash mismatch".into()));
        }

        self.acks.insert(share_index);

        if self.has_all_acks() {
            self.state = DescriptorSessionState::Complete;
        }

        Ok(())
    }

    pub fn has_all_acks(&self) -> bool {
        self.expected_acks.iter().all(|idx| self.acks.contains(idx))
    }

    pub fn descriptor(&self) -> Option<&FinalizedDescriptor> {
        self.descriptor.as_ref()
    }

    pub fn is_complete(&self) -> bool {
        self.state == DescriptorSessionState::Complete
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.timeout
    }

    pub fn fail(&mut self, reason: String) {
        self.state = DescriptorSessionState::Failed(reason);
    }
}

pub struct DescriptorSessionManager {
    sessions: HashMap<[u8; 32], DescriptorSession>,
    default_timeout: Duration,
}

impl DescriptorSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            default_timeout: Duration::from_secs(DESCRIPTOR_SESSION_TIMEOUT_SECS),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            default_timeout: timeout,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_session(
        &mut self,
        session_id: [u8; 32],
        group_pubkey: [u8; 32],
        policy: WalletPolicy,
        network: String,
        expected_contributors: HashSet<u16>,
        expected_acks: HashSet<u16>,
    ) -> Result<&mut DescriptorSession> {
        if self.sessions.contains_key(&session_id) {
            let session = self.sessions.get(&session_id).unwrap();
            if !session.is_expired() {
                return Err(FrostNetError::Session(
                    "Descriptor session already active".into(),
                ));
            }
            self.sessions.remove(&session_id);
        }

        let session = DescriptorSession::new(
            session_id,
            group_pubkey,
            policy,
            network,
            expected_contributors,
            expected_acks,
            self.default_timeout,
        );

        self.sessions.insert(session_id, session);
        Ok(self.sessions.get_mut(&session_id).unwrap())
    }

    pub fn get_session(&self, session_id: &[u8; 32]) -> Option<&DescriptorSession> {
        self.sessions.get(session_id)
    }

    pub fn get_session_mut(&mut self, session_id: &[u8; 32]) -> Option<&mut DescriptorSession> {
        self.sessions.get_mut(session_id)
    }

    pub fn remove_session(&mut self, session_id: &[u8; 32]) {
        self.sessions.remove(session_id);
    }

    pub fn cleanup_expired(&mut self) {
        let expired: Vec<[u8; 32]> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.is_expired())
            .map(|(id, _)| *id)
            .collect();

        for id in expired {
            self.sessions.remove(&id);
        }
    }
}

impl Default for DescriptorSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn derive_descriptor_session_id(
    group_pubkey: &[u8; 32],
    policy: &WalletPolicy,
    created_at: u64,
) -> [u8; 32] {
    let canonical_json =
        serde_json::to_string(policy).expect("WalletPolicy serialization should not fail");

    let mut hasher = Sha256::new();
    hasher.update(group_pubkey);
    hasher.update(canonical_json.as_bytes());
    hasher.update(created_at.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{KeySlot, PolicyTier};

    fn test_policy() -> WalletPolicy {
        WalletPolicy {
            recovery_tiers: vec![PolicyTier {
                threshold: 2,
                key_slots: vec![
                    KeySlot::Participant { share_index: 1 },
                    KeySlot::Participant { share_index: 2 },
                    KeySlot::Participant { share_index: 3 },
                ],
                timelock_months: 6,
            }],
        }
    }

    fn test_session() -> DescriptorSession {
        let policy = test_policy();
        let contributors: HashSet<u16> = [1, 2, 3].into();
        let acks: HashSet<u16> = [1, 2, 3].into();
        DescriptorSession::new(
            [1u8; 32],
            [2u8; 32],
            policy,
            "signet".into(),
            contributors,
            acks,
            Duration::from_secs(600),
        )
    }

    fn descriptor_hash(external: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(external.as_bytes());
        hasher.finalize().into()
    }

    #[test]
    fn test_session_creation_and_state() {
        let session = test_session();
        assert_eq!(*session.state(), DescriptorSessionState::Proposed);
        assert_eq!(session.session_id(), &[1u8; 32]);
        assert_eq!(session.group_pubkey(), &[2u8; 32]);
        assert_eq!(session.network(), "signet");
        assert!(!session.is_complete());
        assert!(!session.is_expired());
        assert!(session.descriptor().is_none());
    }

    #[test]
    fn test_add_contribution_flow() {
        let mut session = test_session();

        session
            .add_contribution(1, "xpub1...".into(), "aabbccdd".into())
            .unwrap();
        assert!(!session.has_all_contributions());

        session
            .add_contribution(2, "xpub2...".into(), "11223344".into())
            .unwrap();
        assert!(!session.has_all_contributions());

        session
            .add_contribution(3, "xpub3...".into(), "55667788".into())
            .unwrap();
        assert!(session.has_all_contributions());

        assert_eq!(session.contributions().len(), 3);
    }

    #[test]
    fn test_duplicate_contribution_rejected() {
        let mut session = test_session();

        session
            .add_contribution(1, "xpub1...".into(), "aabbccdd".into())
            .unwrap();

        let result = session.add_contribution(1, "xpub1-dup...".into(), "aabbccdd".into());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Duplicate"));
    }

    #[test]
    fn test_unexpected_contributor_rejected() {
        let mut session = test_session();

        let result = session.add_contribution(99, "xpub99...".into(), "deadbeef".into());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not an expected contributor"));
    }

    #[test]
    fn test_finalization() {
        let mut session = test_session();

        session
            .add_contribution(1, "xpub1...".into(), "aabbccdd".into())
            .unwrap();
        session
            .add_contribution(2, "xpub2...".into(), "11223344".into())
            .unwrap();
        session
            .add_contribution(3, "xpub3...".into(), "55667788".into())
            .unwrap();

        let finalized = FinalizedDescriptor {
            external: "tr(frost_key,{pk(xpub1),pk(xpub2)})".into(),
            internal: "tr(frost_key,{pk(xpub1),pk(xpub2)})/1".into(),
            policy_hash: [0xAA; 32],
        };

        session.set_finalized(finalized).unwrap();
        assert_eq!(*session.state(), DescriptorSessionState::Finalized);
        assert!(session.descriptor().is_some());

        let desc = session.descriptor().unwrap();
        assert!(desc.external.contains("frost_key"));
    }

    #[test]
    fn test_finalization_wrong_state() {
        let mut session = test_session();
        session.fail("test failure".into());

        let finalized = FinalizedDescriptor {
            external: "tr(...)".into(),
            internal: "tr(...)/1".into(),
            policy_hash: [0; 32],
        };

        let result = session.set_finalized(finalized);
        assert!(result.is_err());
    }

    #[test]
    fn test_ack_flow_and_completion() {
        let mut session = test_session();

        session
            .add_contribution(1, "xpub1".into(), "aa".into())
            .unwrap();
        session
            .add_contribution(2, "xpub2".into(), "bb".into())
            .unwrap();
        session
            .add_contribution(3, "xpub3".into(), "cc".into())
            .unwrap();

        let external = "tr(frost_key,{pk(xpub1),pk(xpub2)})";
        let finalized = FinalizedDescriptor {
            external: external.into(),
            internal: "tr(frost_key,{pk(xpub1),pk(xpub2)})/1".into(),
            policy_hash: [0xAA; 32],
        };
        session.set_finalized(finalized).unwrap();

        let hash = descriptor_hash(external);

        session.add_ack(1, hash).unwrap();
        assert!(!session.is_complete());

        session.add_ack(2, hash).unwrap();
        assert!(!session.is_complete());

        session.add_ack(3, hash).unwrap();
        assert!(session.is_complete());
        assert_eq!(*session.state(), DescriptorSessionState::Complete);
    }

    #[test]
    fn test_ack_wrong_hash() {
        let mut session = test_session();

        session
            .add_contribution(1, "xpub1".into(), "aa".into())
            .unwrap();
        session
            .add_contribution(2, "xpub2".into(), "bb".into())
            .unwrap();
        session
            .add_contribution(3, "xpub3".into(), "cc".into())
            .unwrap();

        let finalized = FinalizedDescriptor {
            external: "tr(frost_key)".into(),
            internal: "tr(frost_key)/1".into(),
            policy_hash: [0; 32],
        };
        session.set_finalized(finalized).unwrap();

        let wrong_hash = [0xFF; 32];
        let result = session.add_ack(1, wrong_hash);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("hash mismatch"));
    }

    #[test]
    fn test_ack_wrong_state() {
        let mut session = test_session();

        let result = session.add_ack(1, [0; 32]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Not accepting ACKs"));
    }

    #[test]
    fn test_expiration() {
        let policy = test_policy();
        let contributors: HashSet<u16> = [1, 2].into();
        let acks: HashSet<u16> = [1, 2].into();
        let session = DescriptorSession::new(
            [1u8; 32],
            [2u8; 32],
            policy,
            "signet".into(),
            contributors,
            acks,
            Duration::from_millis(1),
        );

        std::thread::sleep(Duration::from_millis(10));
        assert!(session.is_expired());
    }

    #[test]
    fn test_contribution_rejected_after_finalized() {
        let mut session = test_session();

        session
            .add_contribution(1, "xpub1".into(), "aa".into())
            .unwrap();
        session
            .add_contribution(2, "xpub2".into(), "bb".into())
            .unwrap();
        session
            .add_contribution(3, "xpub3".into(), "cc".into())
            .unwrap();

        let finalized = FinalizedDescriptor {
            external: "tr(...)".into(),
            internal: "tr(...)/1".into(),
            policy_hash: [0; 32],
        };
        session.set_finalized(finalized).unwrap();

        let result = session.add_contribution(1, "xpub1-new".into(), "aa".into());
        assert!(result.is_err());
    }

    #[test]
    fn test_fail_transition() {
        let mut session = test_session();
        session.fail("validation error".into());
        assert_eq!(
            *session.state(),
            DescriptorSessionState::Failed("validation error".into())
        );
    }

    #[test]
    fn test_session_manager_create_and_get() {
        let mut manager = DescriptorSessionManager::new();
        let policy = test_policy();

        manager
            .create_session(
                [1u8; 32],
                [2u8; 32],
                policy,
                "signet".into(),
                [1, 2, 3].into(),
                [1, 2, 3].into(),
            )
            .unwrap();

        assert!(manager.get_session(&[1u8; 32]).is_some());
        assert!(manager.get_session(&[99u8; 32]).is_none());
    }

    #[test]
    fn test_session_manager_duplicate_rejected() {
        let mut manager = DescriptorSessionManager::new();
        let policy = test_policy();

        manager
            .create_session(
                [1u8; 32],
                [2u8; 32],
                policy.clone(),
                "signet".into(),
                [1, 2].into(),
                [1, 2].into(),
            )
            .unwrap();

        let result = manager.create_session(
            [1u8; 32],
            [2u8; 32],
            policy,
            "signet".into(),
            [1, 2].into(),
            [1, 2].into(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_session_manager_remove() {
        let mut manager = DescriptorSessionManager::new();
        let policy = test_policy();

        manager
            .create_session(
                [1u8; 32],
                [2u8; 32],
                policy,
                "signet".into(),
                [1, 2].into(),
                [1, 2].into(),
            )
            .unwrap();

        manager.remove_session(&[1u8; 32]);
        assert!(manager.get_session(&[1u8; 32]).is_none());
    }

    #[test]
    fn test_session_manager_cleanup_expired() {
        let mut manager = DescriptorSessionManager::with_timeout(Duration::from_millis(1));
        let policy = test_policy();

        manager
            .create_session(
                [1u8; 32],
                [2u8; 32],
                policy,
                "signet".into(),
                [1, 2].into(),
                [1, 2].into(),
            )
            .unwrap();

        std::thread::sleep(Duration::from_millis(10));
        manager.cleanup_expired();
        assert!(manager.get_session(&[1u8; 32]).is_none());
    }

    #[test]
    fn test_derive_descriptor_session_id_deterministic() {
        let group_pubkey = [1u8; 32];
        let policy = test_policy();
        let created_at = 1234567890u64;

        let id1 = derive_descriptor_session_id(&group_pubkey, &policy, created_at);
        let id2 = derive_descriptor_session_id(&group_pubkey, &policy, created_at);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_derive_descriptor_session_id_different_params() {
        let group_pubkey = [1u8; 32];
        let policy = test_policy();

        let id1 = derive_descriptor_session_id(&group_pubkey, &policy, 1000);
        let id2 = derive_descriptor_session_id(&group_pubkey, &policy, 2000);
        assert_ne!(id1, id2);

        let id3 = derive_descriptor_session_id(&[2u8; 32], &policy, 1000);
        assert_ne!(id1, id3);

        let different_policy = WalletPolicy {
            recovery_tiers: vec![],
        };
        let id4 = derive_descriptor_session_id(&group_pubkey, &different_policy, 1000);
        assert_ne!(id1, id4);
    }

    #[test]
    fn test_session_manager_get_mut() {
        let mut manager = DescriptorSessionManager::new();
        let policy = test_policy();

        manager
            .create_session(
                [1u8; 32],
                [2u8; 32],
                policy,
                "signet".into(),
                [1, 2].into(),
                [1, 2].into(),
            )
            .unwrap();

        let session = manager.get_session_mut(&[1u8; 32]).unwrap();
        session
            .add_contribution(1, "xpub1".into(), "aa".into())
            .unwrap();

        let session = manager.get_session(&[1u8; 32]).unwrap();
        assert_eq!(session.contributions().len(), 1);
    }

    #[test]
    fn test_session_manager_default() {
        let manager = DescriptorSessionManager::default();
        assert!(manager.get_session(&[0u8; 32]).is_none());
    }
}
