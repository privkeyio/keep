// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

pub use keep_core::frost::{
    sign_with_local_shares, SessionState, SharePackage, SigningSession, StoredShare,
};

use crate::error::{AgentError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostCommitment {
    pub session_id: String,
    pub participant_id: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostSignatureShare {
    pub session_id: String,
    pub participant_id: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostSigningRequest {
    pub session_id: String,
    pub message: Vec<u8>,
    pub participants: Vec<u16>,
}

pub struct FrostParticipant {
    share_index: u16,
    share: SharePackage,
}

impl FrostParticipant {
    pub fn new(share_index: u16, share: SharePackage) -> Self {
        Self { share_index, share }
    }

    pub fn share_index(&self) -> u16 {
        self.share_index
    }

    pub fn group_pubkey(&self) -> [u8; 32] {
        self.share.metadata.group_pubkey
    }

    pub fn generate_commitment(&self, session: &mut SigningSession) -> Result<FrostCommitment> {
        let kp = self
            .share
            .key_package()
            .map_err(|e| AgentError::Other(e.to_string()))?;

        let commitment = session
            .generate_commitment(&kp)
            .map_err(|e| AgentError::Other(e.to_string()))?;

        let serialized = commitment
            .serialize()
            .map_err(|e| AgentError::Other(format!("Serialize failed: {}", e)))?;

        Ok(FrostCommitment {
            session_id: hex::encode(session.session_id()),
            participant_id: self.share_index,
            data: serialized.to_vec(),
        })
    }

    pub fn generate_signature_share(
        &self,
        session: &mut SigningSession,
    ) -> Result<FrostSignatureShare> {
        let kp = self
            .share
            .key_package()
            .map_err(|e| AgentError::Other(e.to_string()))?;

        let share = session
            .generate_signature_share(&kp)
            .map_err(|e| AgentError::Other(e.to_string()))?;

        Ok(FrostSignatureShare {
            session_id: hex::encode(session.session_id()),
            participant_id: self.share_index,
            data: share.serialize().to_vec(),
        })
    }
}

pub struct FrostCoordinator {
    session_id: String,
    threshold: u16,
    participants: Vec<u16>,
    commitments_received: HashSet<u16>,
    shares_received: HashSet<u16>,
}

impl FrostCoordinator {
    pub fn new(session_id: String, threshold: u16, participants: Vec<u16>) -> Self {
        Self {
            session_id,
            threshold,
            participants,
            commitments_received: HashSet::new(),
            shares_received: HashSet::new(),
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn add_commitment(&mut self, commitment: &FrostCommitment) -> Result<bool> {
        if commitment.session_id != self.session_id {
            return Err(AgentError::Other("Session ID mismatch".into()));
        }

        if !self.participants.contains(&commitment.participant_id) {
            return Err(AgentError::Other("Unknown participant".into()));
        }

        if self
            .commitments_received
            .contains(&commitment.participant_id)
        {
            return Err(AgentError::Other("Duplicate commitment".into()));
        }

        self.commitments_received.insert(commitment.participant_id);
        Ok(self.commitments_received.len() >= self.threshold as usize)
    }

    pub fn add_signature_share(&mut self, share: &FrostSignatureShare) -> Result<bool> {
        if share.session_id != self.session_id {
            return Err(AgentError::Other("Session ID mismatch".into()));
        }

        if !self.participants.contains(&share.participant_id) {
            return Err(AgentError::Other("Unknown participant".into()));
        }

        if self.shares_received.contains(&share.participant_id) {
            return Err(AgentError::Other("Duplicate signature share".into()));
        }

        self.shares_received.insert(share.participant_id);
        Ok(self.shares_received.len() >= self.threshold as usize)
    }

    pub fn commitments_received(&self) -> usize {
        self.commitments_received.len()
    }

    pub fn shares_received(&self) -> usize {
        self.shares_received.len()
    }

    pub fn is_ready_for_shares(&self) -> bool {
        self.commitments_received.len() >= self.threshold as usize
    }

    pub fn is_complete(&self) -> bool {
        self.shares_received.len() >= self.threshold as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keep_core::frost::{ThresholdConfig, TrustedDealer};

    #[test]
    fn test_frost_participant() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (mut shares, _) = dealer.generate("test").unwrap();

        let share = shares.remove(0);
        let participant = FrostParticipant::new(1, share);
        assert_eq!(participant.share_index(), 1);
    }

    #[test]
    fn test_frost_coordinator() {
        let mut coordinator = FrostCoordinator::new("test_session".to_string(), 2, vec![1, 2, 3]);

        let c1 = FrostCommitment {
            session_id: "test_session".to_string(),
            participant_id: 1,
            data: vec![0; 64],
        };
        let c2 = FrostCommitment {
            session_id: "test_session".to_string(),
            participant_id: 2,
            data: vec![0; 64],
        };

        assert!(!coordinator.add_commitment(&c1).unwrap());
        assert!(coordinator.add_commitment(&c2).unwrap());
        assert!(coordinator.is_ready_for_shares());
    }
}
