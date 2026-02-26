// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;
use std::time::{Duration, Instant};

use keep_bitcoin::recovery::{RecoveryConfig, RecoveryTier as BitcoinRecoveryTier, SpendingTier};
use keep_bitcoin::{xpub_to_x_only, DescriptorExport, Network};
use nostr_sdk::PublicKey;
use sha2::{Digest, Sha256};

use crate::error::{FrostNetError, Result};
use crate::protocol::{
    KeySlot, WalletPolicy, DESCRIPTOR_ACK_PHASE_TIMEOUT_SECS, DESCRIPTOR_CONTRIBUTION_TIMEOUT_SECS,
    DESCRIPTOR_FINALIZE_TIMEOUT_SECS, DESCRIPTOR_SESSION_TIMEOUT_SECS, MAX_FINGERPRINT_LENGTH,
    MAX_XPUB_LENGTH,
};

const MAX_SESSIONS: usize = 64;
const REAP_GRACE_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorSessionState {
    Proposed,
    Finalized,
    Complete,
    Failed(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    initiator: Option<PublicKey>,
    contributions: BTreeMap<u16, XpubContribution>,
    expected_contributors: HashSet<u16>,
    descriptor: Option<FinalizedDescriptor>,
    acks: HashSet<u16>,
    nacks: HashSet<u16>,
    expected_acks: HashSet<u16>,
    state: DescriptorSessionState,
    created_at: Instant,
    contributions_complete_at: Option<Instant>,
    finalized_at: Option<Instant>,
    timeout: Duration,
    contribution_timeout: Duration,
    finalize_timeout: Duration,
    ack_phase_timeout: Duration,
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
            initiator: None,
            contributions: BTreeMap::new(),
            expected_contributors,
            descriptor: None,
            acks: HashSet::new(),
            nacks: HashSet::new(),
            expected_acks,
            state: DescriptorSessionState::Proposed,
            created_at: Instant::now(),
            contributions_complete_at: None,
            finalized_at: None,
            timeout,
            contribution_timeout: Duration::from_secs(DESCRIPTOR_CONTRIBUTION_TIMEOUT_SECS),
            finalize_timeout: Duration::from_secs(DESCRIPTOR_FINALIZE_TIMEOUT_SECS),
            ack_phase_timeout: Duration::from_secs(DESCRIPTOR_ACK_PHASE_TIMEOUT_SECS),
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

    pub fn initiator(&self) -> Option<&PublicKey> {
        self.initiator.as_ref()
    }

    pub fn set_initiator(&mut self, initiator: PublicKey) {
        if self.initiator.is_none() {
            self.initiator = Some(initiator);
        }
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

        if xpub.len() > MAX_XPUB_LENGTH {
            return Err(FrostNetError::Session("xpub exceeds maximum length".into()));
        }
        if fingerprint.len() != MAX_FINGERPRINT_LENGTH
            || !fingerprint.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(FrostNetError::Session(
                "fingerprint must be exactly 8 hex characters".into(),
            ));
        }
        let is_mainnet = self.network == "bitcoin";
        let valid_prefixes: &[&str] = if is_mainnet {
            &["xpub"]
        } else {
            &["tpub", "Vpub", "Upub"]
        };
        if !valid_prefixes.iter().any(|p| xpub.starts_with(p)) {
            return Err(FrostNetError::Session(format!(
                "xpub must start with one of {:?} for network '{}'",
                valid_prefixes, self.network
            )));
        }

        if self.contributions.values().any(|c| c.account_xpub == xpub) {
            return Err(FrostNetError::Session(
                "Duplicate xpub: another participant already contributed this key".into(),
            ));
        }

        self.contributions.insert(
            share_index,
            XpubContribution {
                account_xpub: xpub,
                fingerprint,
            },
        );

        if self.has_all_contributions() {
            self.contributions_complete_at = Some(Instant::now());
        }

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

        if !self.has_all_contributions() {
            let missing: Vec<u16> = self
                .expected_contributors
                .iter()
                .filter(|idx| !self.contributions.contains_key(idx))
                .copied()
                .collect();
            return Err(FrostNetError::Session(format!(
                "Missing contributions from share(s): {missing:?}"
            )));
        }

        self.descriptor = Some(descriptor);
        self.state = DescriptorSessionState::Finalized;
        self.finalized_at = Some(Instant::now());
        Ok(())
    }

    pub fn add_ack(
        &mut self,
        share_index: u16,
        descriptor_hash: [u8; 32],
        key_proof_psbt: &[u8],
    ) -> Result<()> {
        if self.state != DescriptorSessionState::Finalized {
            return Err(FrostNetError::Session("Not accepting ACKs".into()));
        }

        if !self.expected_acks.contains(&share_index) {
            return Err(FrostNetError::Session(format!(
                "Share {share_index} not an expected ACK sender"
            )));
        }

        if self.acks.contains(&share_index) {
            return Ok(());
        }

        let finalized = self
            .descriptor
            .as_ref()
            .ok_or_else(|| FrostNetError::Session("No finalized descriptor".into()))?;

        let mut hasher = Sha256::new();
        hasher.update(finalized.external.as_bytes());
        hasher.update(finalized.internal.as_bytes());
        hasher.update(finalized.policy_hash);
        let expected_hash: [u8; 32] = hasher.finalize().into();

        if descriptor_hash != expected_hash {
            return Err(FrostNetError::Session("Descriptor hash mismatch".into()));
        }

        let contrib = self.contributions.get(&share_index).ok_or_else(|| {
            FrostNetError::Session(format!("No xpub contribution for share {share_index}"))
        })?;
        let network = parse_network(&self.network)?;
        keep_bitcoin::verify_key_proof(
            &self.session_id,
            share_index,
            &contrib.account_xpub,
            key_proof_psbt,
            network,
        )
        .map_err(|e| FrostNetError::Session(format!("Key proof invalid: {e}")))?;

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
        self.expired_phase().is_some()
    }

    pub fn expired_phase(&self) -> Option<&'static str> {
        if self.created_at.elapsed() > self.timeout {
            return Some("session");
        }
        match self.state {
            DescriptorSessionState::Proposed => {
                if let Some(complete_at) = self.contributions_complete_at {
                    if complete_at.elapsed() > self.finalize_timeout {
                        return Some("finalize");
                    }
                } else if self.created_at.elapsed() > self.contribution_timeout {
                    return Some("contribution");
                }
                None
            }
            DescriptorSessionState::Finalized => {
                let Some(fin_at) = self.finalized_at else {
                    return Some("session");
                };
                if fin_at.elapsed() > self.ack_phase_timeout {
                    return Some("ack");
                }
                None
            }
            DescriptorSessionState::Complete | DescriptorSessionState::Failed(_) => {
                if self.created_at.elapsed() > self.timeout + Duration::from_secs(REAP_GRACE_SECS) {
                    return Some("reap");
                }
                None
            }
        }
    }

    pub fn is_participant(&self, share_index: u16) -> bool {
        self.expected_contributors.contains(&share_index)
            || self.expected_acks.contains(&share_index)
    }

    pub fn has_nacked(&self, share_index: u16) -> bool {
        self.nacks.contains(&share_index)
    }

    pub fn add_nack(&mut self, share_index: u16) {
        self.nacks.insert(share_index);
    }

    pub fn is_failed(&self) -> bool {
        matches!(self.state, DescriptorSessionState::Failed(_))
    }

    pub fn fail(&mut self, reason: String) {
        if !self.is_complete() && !self.is_failed() {
            self.state = DescriptorSessionState::Failed(reason);
        }
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

    pub fn session_count(&self) -> usize {
        self.sessions.len()
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
        if let Some(existing) = self.sessions.get(&session_id) {
            if !existing.is_expired() {
                return Err(FrostNetError::Session(
                    "Descriptor session already active".into(),
                ));
            }
            self.sessions.remove(&session_id);
        }

        let _ = self.cleanup_expired();

        if self.sessions.len() >= MAX_SESSIONS {
            return Err(FrostNetError::Session(
                "Maximum number of descriptor sessions reached".into(),
            ));
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
        self.sessions
            .get_mut(&session_id)
            .ok_or_else(|| FrostNetError::Session("Failed to retrieve created session".into()))
    }

    pub fn get_session(&self, session_id: &[u8; 32]) -> Option<&DescriptorSession> {
        self.sessions.get(session_id).filter(|s| !s.is_expired())
    }

    pub fn get_session_mut(&mut self, session_id: &[u8; 32]) -> Option<&mut DescriptorSession> {
        self.sessions
            .get_mut(session_id)
            .filter(|s| !s.is_expired())
    }

    pub fn remove_session(&mut self, session_id: &[u8; 32]) {
        self.sessions.remove(session_id);
    }

    pub fn cleanup_expired(&mut self) -> Vec<([u8; 32], String)> {
        let mut expired = Vec::new();
        self.sessions.retain(|id, session| {
            if let Some(phase) = session.expired_phase() {
                expired.push((*id, format!("timeout:{phase}")));
                false
            } else {
                true
            }
        });
        expired
    }
}

impl Default for DescriptorSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

fn hash_policy(hasher: &mut Sha256, policy: &WalletPolicy) {
    hasher.update((policy.recovery_tiers.len() as u32).to_le_bytes());
    for tier in &policy.recovery_tiers {
        hasher.update(tier.threshold.to_le_bytes());
        hasher.update(tier.timelock_months.to_le_bytes());
        hasher.update((tier.key_slots.len() as u32).to_le_bytes());
        for slot in &tier.key_slots {
            match slot {
                KeySlot::Participant { share_index } => {
                    hasher.update([0x01]);
                    hasher.update(share_index.to_le_bytes());
                }
                KeySlot::External { xpub, fingerprint } => {
                    hasher.update([0x02]);
                    hasher.update((xpub.len() as u32).to_le_bytes());
                    hasher.update(xpub.as_bytes());
                    hasher.update((fingerprint.len() as u32).to_le_bytes());
                    hasher.update(fingerprint.as_bytes());
                }
            }
        }
    }
}

pub fn participant_indices(policy: &WalletPolicy) -> HashSet<u16> {
    policy
        .recovery_tiers
        .iter()
        .flat_map(|t| t.key_slots.iter())
        .filter_map(|s| match s {
            KeySlot::Participant { share_index } => Some(*share_index),
            _ => None,
        })
        .collect()
}

pub fn derive_policy_hash(policy: &WalletPolicy) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"keep/descriptor-policy/v1");
    hash_policy(&mut hasher, policy);
    hasher.finalize().into()
}

pub fn derive_descriptor_session_id(
    group_pubkey: &[u8; 32],
    policy: &WalletPolicy,
    created_at: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"keep/descriptor-session/v1");
    hasher.update(group_pubkey);
    hash_policy(&mut hasher, policy);
    hasher.update(created_at.to_le_bytes());
    hasher.finalize().into()
}

pub(crate) fn parse_network(network_str: &str) -> Result<Network> {
    Network::from_str(network_str)
        .map_err(|_| FrostNetError::Session(format!("unknown network: {network_str}")))
}

pub fn reconstruct_descriptor(
    group_pubkey: &[u8; 32],
    policy: &WalletPolicy,
    contributions: &BTreeMap<u16, XpubContribution>,
    network_str: &str,
) -> Result<(String, String)> {
    let network = parse_network(network_str)?;

    let config = if policy.recovery_tiers.is_empty() {
        None
    } else {
        let mut recovery_tiers = Vec::with_capacity(policy.recovery_tiers.len());
        for tier in &policy.recovery_tiers {
            let mut keys = Vec::with_capacity(tier.key_slots.len());
            for slot in &tier.key_slots {
                let xpub = match slot {
                    KeySlot::Participant { share_index } => {
                        let contrib = contributions.get(share_index).ok_or_else(|| {
                            FrostNetError::Session(format!(
                                "missing xpub contribution for share {share_index}"
                            ))
                        })?;
                        &contrib.account_xpub
                    }
                    KeySlot::External { xpub, .. } => xpub,
                };
                let x_only = xpub_to_x_only(xpub, network)
                    .map_err(|e| FrostNetError::Session(format!("xpub conversion failed: {e}")))?;
                keys.push(x_only);
            }
            recovery_tiers.push(BitcoinRecoveryTier {
                keys,
                threshold: tier.threshold,
                timelock_months: tier.timelock_months,
            });
        }
        Some(RecoveryConfig {
            primary: SpendingTier {
                keys: vec![*group_pubkey],
                threshold: 1,
            },
            recovery_tiers,
            network,
        })
    };

    let export = DescriptorExport::from_frost_wallet(group_pubkey, config.as_ref(), network)
        .map_err(|e| FrostNetError::Session(format!("descriptor construction failed: {e}")))?;
    let internal = export
        .internal_descriptor()
        .map_err(|e| FrostNetError::Session(format!("internal descriptor failed: {e}")))?;
    Ok((export.external_descriptor().to_string(), internal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{KeySlot, PolicyTier};

    #[test]
    fn test_initiator_stored() {
        let session = test_session();
        assert!(session.initiator().is_none());

        let mut session = test_session();
        let keys = nostr_sdk::Keys::generate();
        session.set_initiator(keys.public_key());
        assert_eq!(session.initiator(), Some(&keys.public_key()));
    }

    #[test]
    fn test_invalid_xpub_prefix_rejected() {
        let mut session = test_session();
        let result = session.add_contribution(1, "invalidprefix123".into(), "aabbccdd".into());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("xpub must start with"));
    }

    #[test]
    fn test_xpub_network_mismatch_rejected() {
        // signet session should reject xpub (mainnet) prefix
        let mut session = test_session(); // network = "signet"
        let result = session.add_contribution(1, "xpub1zzzzzzzzzzzzzzz".into(), "aabbccdd".into());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("tpub"));
        assert!(err.contains("signet"));
    }

    #[test]
    fn test_session_manager_max_sessions() {
        let mut manager = DescriptorSessionManager::new();
        let policy = test_policy();

        for i in 0..MAX_SESSIONS {
            let mut id = [0u8; 32];
            id[0] = (i & 0xFF) as u8;
            id[1] = ((i >> 8) & 0xFF) as u8;
            manager
                .create_session(
                    id,
                    [2u8; 32],
                    policy.clone(),
                    "signet".into(),
                    [1, 2].into(),
                    [1, 2].into(),
                )
                .unwrap();
        }

        let result = manager.create_session(
            [0xFF; 32],
            [2u8; 32],
            policy,
            "signet".into(),
            [1, 2].into(),
            [1, 2].into(),
        );
        assert!(result.is_err());
    }

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

    fn descriptor_hash(external: &str, internal: &str, policy_hash: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(external.as_bytes());
        hasher.update(internal.as_bytes());
        hasher.update(policy_hash);
        hasher.finalize().into()
    }

    fn real_xpub(seed: u8) -> (String, String, [u8; 32]) {
        use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
        use bitcoin::secp256k1::Secp256k1;
        let secp = Secp256k1::new();
        let secret = [seed; 32];
        let master = Xpriv::new_master(bitcoin::Network::Signet, &secret).unwrap();
        let path = DerivationPath::from_str("m/86'/1'/0'").unwrap();
        let account = master.derive_priv(&secp, &path).unwrap();
        let xpub = Xpub::from_priv(&secp, &account);
        let fp = master.fingerprint(&secp);
        (xpub.to_string(), fp.to_string(), secret)
    }

    fn sign_proof(
        session_id: &[u8; 32],
        share_index: u16,
        xpub: &str,
        secret: &[u8; 32],
    ) -> Vec<u8> {
        let mut psbt = keep_bitcoin::build_key_proof_psbt(
            session_id,
            share_index,
            xpub,
            keep_bitcoin::Network::Signet,
        )
        .unwrap();
        keep_bitcoin::sign_key_proof(&mut psbt, secret, keep_bitcoin::Network::Signet).unwrap()
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
            .add_contribution(1, "tpub1zzzzzzzzzzzzzzz".into(), "aabbccdd".into())
            .unwrap();
        assert!(!session.has_all_contributions());

        session
            .add_contribution(2, "tpub2zzzzzzzzzzzzzzz".into(), "11223344".into())
            .unwrap();
        assert!(!session.has_all_contributions());

        session
            .add_contribution(3, "tpub3zzzzzzzzzzzzzzz".into(), "55667788".into())
            .unwrap();
        assert!(session.has_all_contributions());

        assert_eq!(session.contributions().len(), 3);
    }

    #[test]
    fn test_duplicate_contribution_rejected() {
        let mut session = test_session();

        session
            .add_contribution(1, "tpub1zzzzzzzzzzzzzzz".into(), "aabbccdd".into())
            .unwrap();

        let result = session.add_contribution(1, "tpub1dupzzzzzzzzzzzz".into(), "aabbccdd".into());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Duplicate"));
    }

    #[test]
    fn test_unexpected_contributor_rejected() {
        let mut session = test_session();

        let result = session.add_contribution(99, "tpub99zzzzzzzzzzzzzz".into(), "deadbeef".into());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not an expected contributor"));
    }

    #[test]
    fn test_finalization() {
        let mut session = test_session();

        session
            .add_contribution(1, "tpub1zzzzzzzzzzzzzzz".into(), "aabbccdd".into())
            .unwrap();
        session
            .add_contribution(2, "tpub2zzzzzzzzzzzzzzz".into(), "11223344".into())
            .unwrap();
        session
            .add_contribution(3, "tpub3zzzzzzzzzzzzzzz".into(), "55667788".into())
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
        let session_id = *session.session_id();

        let (xpub1, fp1, secret1) = real_xpub(41);
        let (xpub2, fp2, secret2) = real_xpub(42);
        let (xpub3, fp3, secret3) = real_xpub(43);

        session.add_contribution(1, xpub1.clone(), fp1).unwrap();
        session.add_contribution(2, xpub2.clone(), fp2).unwrap();
        session.add_contribution(3, xpub3.clone(), fp3).unwrap();

        let external = "tr(frost_key,{pk(xpub1),pk(xpub2)})";
        let internal = "tr(frost_key,{pk(xpub1),pk(xpub2)})/1";
        let policy_hash = [0xAA; 32];
        let finalized = FinalizedDescriptor {
            external: external.into(),
            internal: internal.into(),
            policy_hash,
        };
        session.set_finalized(finalized).unwrap();

        let hash = descriptor_hash(external, internal, &policy_hash);

        let proof1 = sign_proof(&session_id, 1, &xpub1, &secret1);
        let proof2 = sign_proof(&session_id, 2, &xpub2, &secret2);
        let proof3 = sign_proof(&session_id, 3, &xpub3, &secret3);

        session.add_ack(1, hash, &proof1).unwrap();
        assert!(!session.is_complete());

        session.add_ack(2, hash, &proof2).unwrap();
        assert!(!session.is_complete());

        session.add_ack(3, hash, &proof3).unwrap();
        assert!(session.is_complete());
        assert_eq!(*session.state(), DescriptorSessionState::Complete);
    }

    #[test]
    fn test_ack_wrong_hash() {
        let mut session = test_session();
        let session_id = *session.session_id();

        let (xpub1, fp1, secret1) = real_xpub(41);
        let (xpub2, fp2, _) = real_xpub(42);
        let (xpub3, fp3, _) = real_xpub(43);

        session.add_contribution(1, xpub1.clone(), fp1).unwrap();
        session.add_contribution(2, xpub2, fp2).unwrap();
        session.add_contribution(3, xpub3, fp3).unwrap();

        let finalized = FinalizedDescriptor {
            external: "tr(frost_key)".into(),
            internal: "tr(frost_key)/1".into(),
            policy_hash: [0; 32],
        };
        session.set_finalized(finalized).unwrap();

        let proof1 = sign_proof(&session_id, 1, &xpub1, &secret1);
        let wrong_hash = [0xFF; 32];
        let result = session.add_ack(1, wrong_hash, &proof1);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("hash mismatch"));
    }

    #[test]
    fn test_ack_wrong_state() {
        let mut session = test_session();

        let result = session.add_ack(1, [0; 32], &[]);
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
            .add_contribution(1, "tpub1".into(), "aabb0011".into())
            .unwrap();
        session
            .add_contribution(2, "tpub2".into(), "bbcc2233".into())
            .unwrap();
        session
            .add_contribution(3, "tpub3".into(), "ccdd4455".into())
            .unwrap();

        let finalized = FinalizedDescriptor {
            external: "tr(...)".into(),
            internal: "tr(...)/1".into(),
            policy_hash: [0; 32],
        };
        session.set_finalized(finalized).unwrap();

        let result = session.add_contribution(1, "tpub1newzzzzzzzzzzzzz".into(), "aabb0011".into());
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
        let expired = manager.cleanup_expired();
        assert!(!expired.is_empty());
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
            .add_contribution(1, "tpub1".into(), "aabb0011".into())
            .unwrap();

        let session = manager.get_session(&[1u8; 32]).unwrap();
        assert_eq!(session.contributions().len(), 1);
    }

    #[test]
    fn test_session_manager_default() {
        let manager = DescriptorSessionManager::default();
        assert!(manager.get_session(&[0u8; 32]).is_none());
    }

    #[test]
    fn test_contribution_phase_timeout() {
        let policy = test_policy();
        let contributors: HashSet<u16> = [1, 2, 3].into();
        let acks: HashSet<u16> = [1, 2, 3].into();
        let mut session = DescriptorSession::new(
            [1u8; 32],
            [2u8; 32],
            policy,
            "signet".into(),
            contributors,
            acks,
            Duration::from_secs(600),
        );
        session.contribution_timeout = Duration::from_millis(1);

        session
            .add_contribution(1, "tpub1zzzzzzzzzzzzzzz".into(), "aabbccdd".into())
            .unwrap();

        std::thread::sleep(Duration::from_millis(10));
        assert!(session.is_expired());
        assert_eq!(session.expired_phase(), Some("contribution"));
    }

    #[test]
    fn test_finalize_phase_timeout() {
        let policy = test_policy();
        let contributors: HashSet<u16> = [1, 2, 3].into();
        let acks: HashSet<u16> = [1, 2, 3].into();
        let mut session = DescriptorSession::new(
            [1u8; 32],
            [2u8; 32],
            policy,
            "signet".into(),
            contributors,
            acks,
            Duration::from_secs(600),
        );
        session.finalize_timeout = Duration::from_millis(1);

        session
            .add_contribution(1, "tpub1zzzzzzzzzzzzzzz".into(), "aabbccdd".into())
            .unwrap();
        session
            .add_contribution(2, "tpub2zzzzzzzzzzzzzzz".into(), "11223344".into())
            .unwrap();
        session
            .add_contribution(3, "tpub3zzzzzzzzzzzzzzz".into(), "55667788".into())
            .unwrap();
        assert!(session.contributions_complete_at.is_some());

        std::thread::sleep(Duration::from_millis(10));
        assert!(session.is_expired());
        assert_eq!(session.expired_phase(), Some("finalize"));
    }

    #[test]
    fn test_ack_phase_timeout() {
        let policy = test_policy();
        let contributors: HashSet<u16> = [1, 2, 3].into();
        let acks: HashSet<u16> = [1, 2, 3].into();
        let mut session = DescriptorSession::new(
            [1u8; 32],
            [2u8; 32],
            policy,
            "signet".into(),
            contributors,
            acks,
            Duration::from_secs(600),
        );
        session.ack_phase_timeout = Duration::from_millis(1);

        session
            .add_contribution(1, "tpub1zzzzzzzzzzzzzzz".into(), "aabbccdd".into())
            .unwrap();
        session
            .add_contribution(2, "tpub2zzzzzzzzzzzzzzz".into(), "11223344".into())
            .unwrap();
        session
            .add_contribution(3, "tpub3zzzzzzzzzzzzzzz".into(), "55667788".into())
            .unwrap();

        let finalized = FinalizedDescriptor {
            external: "tr(frost_key)".into(),
            internal: "tr(frost_key)/1".into(),
            policy_hash: [0; 32],
        };
        session.set_finalized(finalized).unwrap();
        assert!(session.finalized_at.is_some());

        std::thread::sleep(Duration::from_millis(10));
        assert!(session.is_expired());
        assert_eq!(session.expired_phase(), Some("ack"));
    }

    #[test]
    fn test_cleanup_returns_phase_reasons() {
        let mut manager = DescriptorSessionManager::with_timeout(Duration::from_secs(600));
        let policy = test_policy();

        {
            let session = manager
                .create_session(
                    [1u8; 32],
                    [2u8; 32],
                    policy,
                    "signet".into(),
                    [1, 2, 3].into(),
                    [1, 2, 3].into(),
                )
                .unwrap();
            session.contribution_timeout = Duration::from_millis(1);
        }

        std::thread::sleep(Duration::from_millis(10));
        let expired = manager.cleanup_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, [1u8; 32]);
        assert_eq!(expired[0].1, "timeout:contribution");
    }

    #[test]
    fn test_duplicate_xpub_across_participants_rejected() {
        let mut session = test_session();

        session
            .add_contribution(1, "tpub1zzzzzzzzzzzzzzz".into(), "aabbccdd".into())
            .unwrap();

        let result = session.add_contribution(2, "tpub1zzzzzzzzzzzzzzz".into(), "11223344".into());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Duplicate xpub"));
    }
}
