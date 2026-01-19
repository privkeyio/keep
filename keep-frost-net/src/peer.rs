// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use nostr_sdk::PublicKey;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerStatus {
    Online,
    Offline,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationStatus {
    /// Attestation was verified successfully against expected PCRs.
    Verified,
    /// Peer did not provide attestation data.
    NotProvided,
    /// Attestation verification failed.
    Failed(String),
    /// Node is not configured to verify attestations (no expected PCRs set).
    NotConfigured,
}

#[derive(Clone, Debug)]
pub struct Peer {
    pub pubkey: PublicKey,
    pub share_index: u16,
    pub verifying_share: Option<[u8; 33]>,
    pub capabilities: Vec<String>,
    pub name: Option<String>,
    pub last_seen: Instant,
    pub status: PeerStatus,
    pub protocol_version: u8,
    pub attestation_status: AttestationStatus,
}

impl Peer {
    pub fn new(pubkey: PublicKey, share_index: u16) -> Self {
        Self {
            pubkey,
            share_index,
            verifying_share: None,
            capabilities: vec!["sign".into()],
            name: None,
            last_seen: Instant::now(),
            status: PeerStatus::Online,
            protocol_version: crate::KFP_VERSION,
            attestation_status: AttestationStatus::NotProvided,
        }
    }

    pub fn with_attestation_status(mut self, status: AttestationStatus) -> Self {
        self.attestation_status = status;
        self
    }

    pub fn is_attested(&self) -> bool {
        matches!(
            self.attestation_status,
            AttestationStatus::Verified | AttestationStatus::NotConfigured
        )
    }

    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    pub fn with_capabilities(mut self, caps: Vec<String>) -> Self {
        self.capabilities = caps;
        self
    }

    pub fn with_verifying_share(mut self, verifying_share: [u8; 33]) -> Self {
        self.verifying_share = Some(verifying_share);
        self
    }

    pub fn can_sign(&self) -> bool {
        self.capabilities.contains(&"sign".to_string())
    }

    pub fn is_online(&self, offline_threshold: Duration) -> bool {
        self.status == PeerStatus::Online && self.last_seen.elapsed() < offline_threshold
    }

    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
        self.status = PeerStatus::Online;
    }
}

pub struct PeerManager {
    peers: HashMap<u16, Peer>,
    our_share_index: u16,
    offline_threshold: Duration,
}

impl PeerManager {
    pub fn new(our_share_index: u16) -> Self {
        Self {
            peers: HashMap::new(),
            our_share_index,
            offline_threshold: Duration::from_secs(60),
        }
    }

    pub fn with_offline_threshold(mut self, threshold: Duration) -> Self {
        self.offline_threshold = threshold;
        self
    }

    pub fn add_peer(&mut self, peer: Peer) {
        if peer.share_index != self.our_share_index {
            self.peers.insert(peer.share_index, peer);
        }
    }

    pub fn update_last_seen(&mut self, share_index: u16) {
        if let Some(peer) = self.peers.get_mut(&share_index) {
            peer.touch();
        }
    }

    pub fn mark_offline(&mut self, share_index: u16) {
        if let Some(peer) = self.peers.get_mut(&share_index) {
            peer.status = PeerStatus::Offline;
        }
    }

    pub fn get_peer(&self, share_index: u16) -> Option<&Peer> {
        self.peers.get(&share_index)
    }

    pub fn get_peer_by_pubkey(&self, pubkey: &PublicKey) -> Option<&Peer> {
        self.peers.values().find(|p| &p.pubkey == pubkey)
    }

    pub fn is_trusted_peer(&self, pubkey: &PublicKey) -> bool {
        self.peers.values().any(|p| &p.pubkey == pubkey)
    }

    pub fn get_online_peers(&self) -> Vec<&Peer> {
        self.peers
            .values()
            .filter(|p| p.is_online(self.offline_threshold))
            .collect()
    }

    pub fn get_signing_peers(&self) -> Vec<&Peer> {
        self.get_online_peers()
            .into_iter()
            .filter(|p| p.can_sign())
            .collect()
    }

    /// Returns signing peers that have verified attestation.
    ///
    /// Useful for "soft attestation" mode where attestation is tracked but not
    /// strictly required - allows preferring attested peers when available.
    /// When attestation is required via `KfpNode::with_expected_pcrs()`, this
    /// returns the same result as `get_signing_peers()` since unattested peers
    /// are rejected at announce time.
    pub fn get_attested_signing_peers(&self) -> Vec<&Peer> {
        self.get_signing_peers()
            .into_iter()
            .filter(|p| p.is_attested())
            .collect()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn online_count(&self) -> usize {
        self.get_online_peers().len()
    }

    pub fn select_participants(&self, threshold: usize) -> Option<Vec<u16>> {
        let mut others: Vec<u16> = self
            .get_signing_peers()
            .into_iter()
            .map(|p| p.share_index)
            .collect();

        others.sort();

        if others.len() + 1 < threshold {
            return None;
        }

        let mut participants = vec![self.our_share_index];
        for idx in others {
            if participants.len() >= threshold {
                break;
            }
            participants.push(idx);
        }
        participants.sort();
        Some(participants)
    }

    pub fn remove_stale_peers(&mut self, max_offline_duration: Duration) {
        self.peers.retain(|_, peer| {
            peer.status != PeerStatus::Offline || peer.last_seen.elapsed() < max_offline_duration
        });
    }

    pub fn all_peers(&self) -> Vec<&Peer> {
        self.peers.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::Keys;

    #[test]
    fn test_peer_manager_basic() {
        let mut pm = PeerManager::new(1);

        let keys2 = Keys::generate();
        let peer2 = Peer::new(keys2.public_key(), 2).with_name("peer2");
        pm.add_peer(peer2);

        let keys3 = Keys::generate();
        let peer3 = Peer::new(keys3.public_key(), 3).with_name("peer3");
        pm.add_peer(peer3);

        assert_eq!(pm.peer_count(), 2);
        assert_eq!(pm.online_count(), 2);

        pm.mark_offline(3);
        assert_eq!(pm.online_count(), 1);
    }

    #[test]
    fn test_select_participants() {
        let mut pm = PeerManager::new(1);

        let keys2 = Keys::generate();
        pm.add_peer(Peer::new(keys2.public_key(), 2));

        let keys3 = Keys::generate();
        pm.add_peer(Peer::new(keys3.public_key(), 3));

        let participants = pm.select_participants(2).unwrap();
        assert_eq!(participants.len(), 2);
        assert!(participants.contains(&1));
    }

    #[test]
    fn test_peer_ignores_self() {
        let mut pm = PeerManager::new(1);

        let keys = Keys::generate();
        let self_peer = Peer::new(keys.public_key(), 1);
        pm.add_peer(self_peer);

        assert_eq!(pm.peer_count(), 0);
    }
}
