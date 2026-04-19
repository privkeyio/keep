// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! Session state machine for WDC PSBT coordination (recovery tier / scriptpath spends).
//!
//! State flow:
//!
//! ```text
//!              add_signature (>=1)
//!   Proposed ─────────────────────► Signing
//!                                       │  set_finalized (threshold met)
//!                                       ▼
//!                                   Finalized
//!
//!   Any state ── abort() / timeout ──► Aborted(reason)
//! ```
//!
//! The signer identity is a `SignerId` (either a FROST share index or an
//! external xpub fingerprint) — either kind can participate in a recovery
//! scriptpath spend, since the recovery key holders may not be in the FROST
//! group.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{FrostNetError, Result};
use crate::protocol::{
    is_valid_fingerprint, MAX_PARTICIPANTS, MAX_PSBT_SIZE, PSBT_FINALIZE_PHASE_TIMEOUT_SECS,
    PSBT_PROPOSE_ACK_PHASE_TIMEOUT_SECS, PSBT_SESSION_MAX_TIMEOUT_SECS, PSBT_SESSION_TIMEOUT_SECS,
    PSBT_SIGNING_PHASE_TIMEOUT_SECS,
};

const MAX_SESSIONS: usize = 32;
const REAP_GRACE_SECS: u64 = 60;

/// Identifies a participant in a PSBT coordination session.
///
/// Recovery tiers can contain a mix of FROST participants and external xpubs,
/// so signer identity is either a share index or an xpub fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignerId {
    Share(u16),
    Fingerprint(String),
}

impl SignerId {
    pub fn share(index: u16) -> Self {
        SignerId::Share(index)
    }

    pub fn fingerprint<S: Into<String>>(fp: S) -> Self {
        SignerId::Fingerprint(fp.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PsbtSessionState {
    Proposed,
    Signing,
    Finalized,
    Aborted(String),
}

/// A PSBT coordination session for a recovery tier spend.
#[derive(Debug)]
pub struct PsbtSession {
    session_id: [u8; 32],
    group_pubkey: [u8; 32],
    descriptor_hash: [u8; 32],
    tier_index: u32,
    proposal_psbt: Vec<u8>,
    current_psbt: Vec<u8>,
    required_threshold: u32,
    expected_signers: HashSet<SignerId>,
    received_sigs: HashMap<SignerId, Vec<u8>>,
    partial_psbts: HashMap<SignerId, Vec<u8>>,
    initiator: Option<PublicKey>,
    final_tx: Option<Vec<u8>>,
    txid: Option<[u8; 32]>,
    state: PsbtSessionState,
    finalizing: bool,
    created_at: Instant,
    first_sig_at: Option<Instant>,
    finalized_at: Option<Instant>,
    timeout: Duration,
    signing_timeout: Duration,
    finalize_timeout: Duration,
}

impl PsbtSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: [u8; 32],
        group_pubkey: [u8; 32],
        descriptor_hash: [u8; 32],
        tier_index: u32,
        psbt: Vec<u8>,
        required_threshold: u32,
        expected_signers: HashSet<SignerId>,
        timeout: Duration,
    ) -> Result<Self> {
        if psbt.is_empty() {
            return Err(FrostNetError::Session("PSBT must not be empty".into()));
        }
        if psbt.len() > MAX_PSBT_SIZE {
            return Err(FrostNetError::Session("PSBT exceeds maximum size".into()));
        }
        if required_threshold == 0 {
            return Err(FrostNetError::Session(
                "required_threshold must be non-zero".into(),
            ));
        }
        if expected_signers.is_empty() {
            return Err(FrostNetError::Session(
                "At least one expected signer is required".into(),
            ));
        }
        if expected_signers.len() > MAX_PARTICIPANTS {
            return Err(FrostNetError::Session("Too many expected signers".into()));
        }
        if required_threshold as usize > expected_signers.len() {
            return Err(FrostNetError::Session(
                "required_threshold exceeds number of expected signers".into(),
            ));
        }
        for s in &expected_signers {
            match s {
                SignerId::Share(i) if *i == 0 => {
                    return Err(FrostNetError::Session(
                        "Expected signer share index must be non-zero".into(),
                    ));
                }
                SignerId::Fingerprint(fp) if !is_valid_fingerprint(fp) => {
                    return Err(FrostNetError::Session(
                        "Expected signer fingerprint must be 8 hex characters".into(),
                    ));
                }
                _ => {}
            }
        }

        Ok(Self {
            session_id,
            group_pubkey,
            descriptor_hash,
            tier_index,
            current_psbt: psbt.clone(),
            proposal_psbt: psbt,
            required_threshold,
            expected_signers,
            received_sigs: HashMap::new(),
            partial_psbts: HashMap::new(),
            initiator: None,
            final_tx: None,
            txid: None,
            state: PsbtSessionState::Proposed,
            finalizing: false,
            created_at: Instant::now(),
            first_sig_at: None,
            finalized_at: None,
            timeout,
            signing_timeout: Duration::from_secs(PSBT_SIGNING_PHASE_TIMEOUT_SECS),
            finalize_timeout: Duration::from_secs(PSBT_FINALIZE_PHASE_TIMEOUT_SECS),
        })
    }

    pub fn set_initiator(&mut self, pubkey: PublicKey) {
        self.initiator = Some(pubkey);
    }

    pub fn initiator(&self) -> Option<&PublicKey> {
        self.initiator.as_ref()
    }

    pub fn partial_psbts(&self) -> &HashMap<SignerId, Vec<u8>> {
        &self.partial_psbts
    }

    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    pub fn group_pubkey(&self) -> &[u8; 32] {
        &self.group_pubkey
    }

    pub fn descriptor_hash(&self) -> &[u8; 32] {
        &self.descriptor_hash
    }

    pub fn tier_index(&self) -> u32 {
        self.tier_index
    }

    pub fn proposal_psbt(&self) -> &[u8] {
        &self.proposal_psbt
    }

    pub fn current_psbt(&self) -> &[u8] {
        &self.current_psbt
    }

    pub fn state(&self) -> &PsbtSessionState {
        &self.state
    }

    pub fn required_threshold(&self) -> u32 {
        self.required_threshold
    }

    pub fn expected_signers(&self) -> &HashSet<SignerId> {
        &self.expected_signers
    }

    pub fn signature_count(&self) -> usize {
        self.received_sigs.len()
    }

    pub fn has_signed(&self, signer: &SignerId) -> bool {
        self.received_sigs.contains_key(signer)
    }

    pub fn threshold_met(&self) -> bool {
        self.received_sigs.len() as u32 >= self.required_threshold
    }

    pub fn final_tx(&self) -> Option<&[u8]> {
        self.final_tx.as_deref()
    }

    pub fn txid(&self) -> Option<&[u8; 32]> {
        self.txid.as_ref()
    }

    /// Add a signature contribution from a signer. The merged PSBT is stored
    /// in `partial_psbts` keyed by signer; `current_psbt` is set from the
    /// first signer's contribution and retained for snapshot display only.
    /// Subsequent signatures do not overwrite `current_psbt`; the proposer
    /// aggregates from `partial_psbts` at finalization time.
    pub fn add_signature(
        &mut self,
        signer: SignerId,
        merged_psbt: Vec<u8>,
        signer_marker: Vec<u8>,
    ) -> Result<()> {
        match &self.state {
            PsbtSessionState::Aborted(r) => {
                return Err(FrostNetError::Session(format!("Session aborted: {r}")));
            }
            PsbtSessionState::Finalized => {
                return Err(FrostNetError::Session(
                    "Session already finalized; not accepting signatures".into(),
                ));
            }
            _ => {}
        }

        if !self.expected_signers.contains(&signer) {
            return Err(FrostNetError::Session(
                "Signer is not expected in this session".into(),
            ));
        }

        if merged_psbt.is_empty() {
            return Err(FrostNetError::Session("PSBT must not be empty".into()));
        }
        if merged_psbt.len() > MAX_PSBT_SIZE {
            return Err(FrostNetError::Session("PSBT exceeds maximum size".into()));
        }

        if self.received_sigs.contains_key(&signer) {
            return Err(FrostNetError::Session(
                "Duplicate signature from this signer".into(),
            ));
        }

        let first_signer = self.received_sigs.is_empty();
        self.received_sigs.insert(signer.clone(), signer_marker);
        self.partial_psbts.insert(signer, merged_psbt.clone());
        if first_signer {
            self.current_psbt = merged_psbt;
        }

        if self.state == PsbtSessionState::Proposed {
            self.state = PsbtSessionState::Signing;
            self.first_sig_at = Some(Instant::now());
        }

        Ok(())
    }

    /// Roll back a locally-recorded signature. Intended for the caller that
    /// optimistically committed a contribution under `add_signature` and
    /// then saw the wire send fail; keeps local state consistent with what
    /// other peers have observed. If the rollback empties the signature set
    /// the session transitions back to `Proposed`.
    pub fn remove_signature(&mut self, signer: &SignerId) -> bool {
        let removed = self.received_sigs.remove(signer).is_some();
        self.partial_psbts.remove(signer);
        if removed {
            if self.received_sigs.is_empty() {
                self.current_psbt = self.proposal_psbt.clone();
                self.first_sig_at = None;
                if matches!(self.state, PsbtSessionState::Signing) {
                    self.state = PsbtSessionState::Proposed;
                }
            } else if let Some(remaining) = self.partial_psbts.values().next().cloned() {
                self.current_psbt = remaining;
            }
        }
        removed
    }

    /// Atomic claim-to-finalize check, intended to gate a single caller when
    /// concurrent signatures cross the threshold. Returns `true` exactly once
    /// per session: when the session is in `Signing`, threshold is met, and
    /// finalization has not yet been claimed. On `true`, callers must follow
    /// through with `set_finalized` or call `clear_finalizing` on failure.
    pub fn begin_finalize(&mut self) -> bool {
        if self.finalizing {
            return false;
        }
        if !matches!(self.state, PsbtSessionState::Signing) {
            return false;
        }
        if !self.threshold_met() {
            return false;
        }
        self.finalizing = true;
        true
    }

    /// Release the `begin_finalize` claim after a finalize attempt failed
    /// before it could call `set_finalized`. Safe to call when no claim is
    /// held.
    pub fn clear_finalizing(&mut self) {
        self.finalizing = false;
    }

    /// Transition to Finalized state with an optional final (signed) tx.
    ///
    /// Must be called while the session is in `Signing` state and the
    /// signature threshold has been met.
    pub fn set_finalized(
        &mut self,
        finalized_psbt: Vec<u8>,
        final_tx: Option<(Vec<u8>, [u8; 32])>,
    ) -> Result<()> {
        match &self.state {
            PsbtSessionState::Aborted(r) => {
                return Err(FrostNetError::Session(format!("Session aborted: {r}")));
            }
            PsbtSessionState::Finalized => {
                return Err(FrostNetError::Session("Session already finalized".into()));
            }
            PsbtSessionState::Proposed => {
                return Err(FrostNetError::Session(
                    "Cannot finalize from Proposed; need at least one signature".into(),
                ));
            }
            PsbtSessionState::Signing => {}
        }

        if !self.threshold_met() {
            return Err(FrostNetError::Session(
                "Cannot finalize: signature threshold not yet met".into(),
            ));
        }

        if finalized_psbt.is_empty() {
            return Err(FrostNetError::Session("PSBT must not be empty".into()));
        }
        if finalized_psbt.len() > MAX_PSBT_SIZE {
            return Err(FrostNetError::Session("PSBT exceeds maximum size".into()));
        }
        if let Some((tx, _)) = &final_tx {
            if tx.is_empty() {
                return Err(FrostNetError::Session(
                    "final_tx must not be empty when provided".into(),
                ));
            }
            if tx.len() > MAX_PSBT_SIZE {
                return Err(FrostNetError::Session(
                    "final_tx exceeds maximum size".into(),
                ));
            }
        }

        self.current_psbt = finalized_psbt;
        match final_tx {
            Some((tx, id)) => {
                self.final_tx = Some(tx);
                self.txid = Some(id);
            }
            None => {
                self.final_tx = None;
                self.txid = None;
            }
        }
        self.state = PsbtSessionState::Finalized;
        self.finalized_at = Some(Instant::now());
        Ok(())
    }

    pub fn abort(&mut self, reason: String) {
        if !matches!(
            self.state,
            PsbtSessionState::Aborted(_) | PsbtSessionState::Finalized
        ) {
            self.state = PsbtSessionState::Aborted(reason);
            self.finalizing = false;
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            PsbtSessionState::Finalized | PsbtSessionState::Aborted(_)
        )
    }

    pub fn expired_phase(&self) -> Option<&'static str> {
        match self.state {
            PsbtSessionState::Finalized | PsbtSessionState::Aborted(_) => {
                if self.created_at.elapsed() > self.timeout + Duration::from_secs(REAP_GRACE_SECS) {
                    Some("reap")
                } else {
                    None
                }
            }
            PsbtSessionState::Proposed => {
                if self.created_at.elapsed() > self.timeout {
                    Some("session")
                } else if self.created_at.elapsed()
                    > Duration::from_secs(PSBT_PROPOSE_ACK_PHASE_TIMEOUT_SECS)
                {
                    Some("propose")
                } else {
                    None
                }
            }
            PsbtSessionState::Signing => {
                if self.created_at.elapsed() > self.timeout {
                    return Some("session");
                }
                let first = self.first_sig_at.unwrap_or(self.created_at);
                if self.threshold_met() && first.elapsed() > self.finalize_timeout {
                    Some("finalize")
                } else if first.elapsed() > self.signing_timeout {
                    Some("signing")
                } else {
                    None
                }
            }
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expired_phase().is_some()
    }
}

#[derive(Debug)]
pub struct PsbtSessionManager {
    sessions: HashMap<[u8; 32], PsbtSession>,
    default_timeout: Duration,
}

impl PsbtSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            default_timeout: Duration::from_secs(PSBT_SESSION_TIMEOUT_SECS),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Result<Self> {
        validate_timeout(timeout)?;
        Ok(Self {
            sessions: HashMap::new(),
            default_timeout: timeout,
        })
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn get_session(&self, session_id: &[u8; 32]) -> Option<&PsbtSession> {
        self.sessions.get(session_id).filter(|s| !s.is_expired())
    }

    pub fn get_session_mut(&mut self, session_id: &[u8; 32]) -> Option<&mut PsbtSession> {
        self.sessions
            .get_mut(session_id)
            .filter(|s| !s.is_expired())
    }

    pub fn remove_session(&mut self, session_id: &[u8; 32]) {
        self.sessions.remove(session_id);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_session(
        &mut self,
        session_id: [u8; 32],
        group_pubkey: [u8; 32],
        descriptor_hash: [u8; 32],
        tier_index: u32,
        psbt: Vec<u8>,
        required_threshold: u32,
        expected_signers: HashSet<SignerId>,
        timeout: Option<Duration>,
    ) -> Result<&mut PsbtSession> {
        if let Some(existing) = self.sessions.get(&session_id) {
            let aborted = matches!(existing.state(), PsbtSessionState::Aborted(_));
            if !existing.is_expired() && !aborted {
                return Err(FrostNetError::Session("PSBT session already active".into()));
            }
            self.sessions.remove(&session_id);
        }

        self.cleanup_expired();

        if self.sessions.len() >= MAX_SESSIONS {
            return Err(FrostNetError::Session(
                "Maximum number of PSBT sessions reached".into(),
            ));
        }

        let effective = match timeout {
            Some(t) => validate_timeout(t)?,
            None => self.default_timeout,
        };

        let session = PsbtSession::new(
            session_id,
            group_pubkey,
            descriptor_hash,
            tier_index,
            psbt,
            required_threshold,
            expected_signers,
            effective,
        )?;

        self.sessions.insert(session_id, session);
        Ok(self.sessions.get_mut(&session_id).unwrap())
    }

    pub fn cleanup_expired(&mut self) -> Vec<([u8; 32], String)> {
        let mut expired = Vec::new();
        self.sessions.retain(|id, s| {
            if let Some(phase) = s.expired_phase() {
                expired.push((*id, format!("timeout:{phase}")));
                false
            } else {
                true
            }
        });
        expired
    }
}

impl Default for PsbtSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_timeout(t: Duration) -> Result<Duration> {
    if t.is_zero() {
        return Err(FrostNetError::Session(
            "PSBT session timeout must be non-zero".into(),
        ));
    }
    if t.as_secs() > PSBT_SESSION_MAX_TIMEOUT_SECS {
        return Err(FrostNetError::Session(format!(
            "PSBT session timeout {}s exceeds maximum {}s",
            t.as_secs(),
            PSBT_SESSION_MAX_TIMEOUT_SECS
        )));
    }
    Ok(t)
}

/// Deterministic session id for a PSBT coordination session. Derived from the
/// group pubkey, descriptor hash, tier index, proposal PSBT bytes and
/// creation timestamp so it's stable per proposal but unique across retries.
pub fn derive_psbt_session_id(
    group_pubkey: &[u8; 32],
    descriptor_hash: &[u8; 32],
    tier_index: u32,
    psbt: &[u8],
    created_at: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"keep/psbt-session/v1");
    h.update(group_pubkey);
    h.update(descriptor_hash);
    h.update(tier_index.to_le_bytes());
    h.update((psbt.len() as u64).to_le_bytes());
    h.update(psbt);
    h.update(created_at.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_signers() -> HashSet<SignerId> {
        let mut s = HashSet::new();
        s.insert(SignerId::Share(1));
        s.insert(SignerId::Share(2));
        s.insert(SignerId::Fingerprint("aabbccdd".to_string()));
        s
    }

    fn new_session() -> PsbtSession {
        PsbtSession::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            0,
            vec![0x70, 0x73, 0x62, 0x74, 0xff],
            2,
            sample_signers(),
            Duration::from_secs(60),
        )
        .unwrap()
    }

    #[test]
    fn test_new_session_initial_state() {
        let s = new_session();
        assert_eq!(s.state(), &PsbtSessionState::Proposed);
        assert_eq!(s.signature_count(), 0);
        assert!(!s.threshold_met());
        assert!(!s.is_terminal());
    }

    #[test]
    fn test_rejects_empty_psbt() {
        let err = PsbtSession::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            0,
            vec![],
            1,
            sample_signers(),
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_rejects_oversized_psbt() {
        let err = PsbtSession::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            0,
            vec![0u8; MAX_PSBT_SIZE + 1],
            1,
            sample_signers(),
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(err.to_string().contains("maximum"));
    }

    #[test]
    fn test_rejects_zero_threshold() {
        let err = PsbtSession::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            0,
            vec![0x70, 0x73, 0x62, 0x74, 0xff],
            0,
            sample_signers(),
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(err.to_string().contains("non-zero"));
    }

    #[test]
    fn test_rejects_threshold_exceeds_signers() {
        let err = PsbtSession::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            0,
            vec![0x70, 0x73, 0x62, 0x74, 0xff],
            10,
            sample_signers(),
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn test_rejects_empty_signers() {
        let err = PsbtSession::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            0,
            vec![0x70, 0x73, 0x62, 0x74, 0xff],
            1,
            HashSet::new(),
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(err.to_string().contains("expected signer"));
    }

    #[test]
    fn test_rejects_bad_fingerprint() {
        let mut signers = HashSet::new();
        signers.insert(SignerId::Fingerprint("xx".to_string()));
        let err = PsbtSession::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            0,
            vec![0x70, 0x73, 0x62, 0x74, 0xff],
            1,
            signers,
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(err.to_string().contains("fingerprint"));
    }

    #[test]
    fn test_rejects_zero_share_index_signer() {
        let mut signers = HashSet::new();
        signers.insert(SignerId::Share(0));
        let err = PsbtSession::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            0,
            vec![0x70, 0x73, 0x62, 0x74, 0xff],
            1,
            signers,
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(err.to_string().contains("non-zero"));
    }

    #[test]
    fn test_add_signature_transitions_to_signing() {
        let mut s = new_session();
        s.add_signature(SignerId::Share(1), vec![1, 2, 3, 4], vec![0xaa])
            .unwrap();
        assert_eq!(s.state(), &PsbtSessionState::Signing);
        assert_eq!(s.signature_count(), 1);
        assert!(s.has_signed(&SignerId::Share(1)));
    }

    #[test]
    fn test_threshold_met_after_required_sigs() {
        let mut s = new_session();
        s.add_signature(SignerId::Share(1), vec![1; 4], vec![0xaa])
            .unwrap();
        assert!(!s.threshold_met());
        s.add_signature(SignerId::Share(2), vec![2; 4], vec![0xbb])
            .unwrap();
        assert!(s.threshold_met());
    }

    #[test]
    fn test_reject_duplicate_signer() {
        let mut s = new_session();
        s.add_signature(SignerId::Share(1), vec![1; 4], vec![0xaa])
            .unwrap();
        let err = s
            .add_signature(SignerId::Share(1), vec![2; 4], vec![0xbb])
            .unwrap_err();
        assert!(err.to_string().contains("Duplicate"));
    }

    #[test]
    fn test_reject_unexpected_signer() {
        let mut s = new_session();
        let err = s
            .add_signature(SignerId::Share(99), vec![1; 4], vec![0xaa])
            .unwrap_err();
        assert!(err.to_string().contains("not expected"));
    }

    fn finalize_ready_session() -> PsbtSession {
        let mut s = new_session();
        s.add_signature(SignerId::Share(1), vec![1; 4], vec![0xaa])
            .unwrap();
        s.add_signature(SignerId::Share(2), vec![2; 4], vec![0xbb])
            .unwrap();
        s
    }

    #[test]
    fn test_set_finalized_from_signing() {
        let mut s = finalize_ready_session();
        s.set_finalized(vec![9; 4], Some((vec![8; 4], [0xcc; 32])))
            .unwrap();
        assert_eq!(s.state(), &PsbtSessionState::Finalized);
        assert_eq!(s.final_tx(), Some(&[8, 8, 8, 8][..]));
        assert_eq!(s.txid(), Some(&[0xcc; 32]));
    }

    #[test]
    fn test_set_finalized_from_proposed_rejected() {
        let mut s = new_session();
        let err = s.set_finalized(vec![9; 4], None).unwrap_err();
        assert!(err.to_string().contains("Proposed"));
    }

    #[test]
    fn test_set_finalized_below_threshold_rejected() {
        let mut s = new_session();
        s.add_signature(SignerId::Share(1), vec![1; 4], vec![0xaa])
            .unwrap();
        let err = s.set_finalized(vec![9; 4], None).unwrap_err();
        assert!(err.to_string().contains("threshold"));
    }

    #[test]
    fn test_cannot_finalize_twice() {
        let mut s = finalize_ready_session();
        s.set_finalized(vec![9; 4], None).unwrap();
        let err = s.set_finalized(vec![7; 4], None).unwrap_err();
        assert!(err.to_string().contains("already finalized"));
    }

    #[test]
    fn test_cannot_sign_after_finalize() {
        let mut s = finalize_ready_session();
        s.set_finalized(vec![9; 4], None).unwrap();
        let err = s
            .add_signature(SignerId::Share(3), vec![1; 4], vec![0xaa])
            .unwrap_err();
        assert!(err.to_string().contains("already finalized"));
    }

    #[test]
    fn test_abort_blocks_further_changes() {
        let mut s = new_session();
        s.abort("user cancelled".into());
        assert!(matches!(s.state(), PsbtSessionState::Aborted(r) if r == "user cancelled"));
        let err = s
            .add_signature(SignerId::Share(1), vec![1; 4], vec![0xaa])
            .unwrap_err();
        assert!(err.to_string().contains("aborted"));
        let err2 = s.set_finalized(vec![1; 4], None).unwrap_err();
        assert!(err2.to_string().contains("aborted"));
    }

    #[test]
    fn test_abort_after_finalize_is_noop() {
        let mut s = finalize_ready_session();
        s.set_finalized(vec![1; 4], None).unwrap();
        s.abort("too late".into());
        assert_eq!(s.state(), &PsbtSessionState::Finalized);
    }

    #[test]
    fn test_partial_psbts_stored_per_signer() {
        let mut s = new_session();
        s.add_signature(SignerId::Share(1), vec![1, 1, 1, 1], vec![0xaa])
            .unwrap();
        s.add_signature(SignerId::Share(2), vec![2, 2, 2, 2], vec![0xbb])
            .unwrap();
        assert_eq!(
            s.partial_psbts()
                .get(&SignerId::Share(1))
                .map(Vec::as_slice),
            Some(&[1, 1, 1, 1][..])
        );
        assert_eq!(
            s.partial_psbts()
                .get(&SignerId::Share(2))
                .map(Vec::as_slice),
            Some(&[2, 2, 2, 2][..])
        );
        assert_eq!(s.current_psbt(), &[1, 1, 1, 1][..]);
    }

    #[test]
    fn test_external_fingerprint_signer_accepted() {
        let mut s = new_session();
        s.add_signature(
            SignerId::Fingerprint("aabbccdd".into()),
            vec![1; 4],
            vec![0xaa],
        )
        .unwrap();
        assert_eq!(s.signature_count(), 1);
    }

    #[test]
    fn test_manager_max_sessions() {
        let mut m = PsbtSessionManager::new();
        for i in 0..MAX_SESSIONS {
            let mut sid = [0u8; 32];
            sid[0] = (i & 0xff) as u8;
            sid[1] = ((i >> 8) & 0xff) as u8;
            m.create_session(
                sid,
                [2u8; 32],
                [3u8; 32],
                0,
                vec![0x70, 0x73, 0x62, 0x74, 0xff],
                1,
                sample_signers(),
                None,
            )
            .unwrap();
        }
        let err = m
            .create_session(
                [0xff; 32],
                [2u8; 32],
                [3u8; 32],
                0,
                vec![0x70, 0x73, 0x62, 0x74, 0xff],
                1,
                sample_signers(),
                None,
            )
            .unwrap_err();
        assert!(err.to_string().contains("Maximum"));
    }

    #[test]
    fn test_manager_duplicate_session_rejected() {
        let mut m = PsbtSessionManager::new();
        m.create_session(
            [5u8; 32],
            [2u8; 32],
            [3u8; 32],
            0,
            vec![0x70, 0x73, 0x62, 0x74, 0xff],
            1,
            sample_signers(),
            None,
        )
        .unwrap();
        let err = m
            .create_session(
                [5u8; 32],
                [2u8; 32],
                [3u8; 32],
                0,
                vec![0x70, 0x73, 0x62, 0x74, 0xff],
                1,
                sample_signers(),
                None,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already active"));
    }

    #[test]
    fn test_manager_with_timeout_rejects_zero() {
        let err = PsbtSessionManager::with_timeout(Duration::from_secs(0)).unwrap_err();
        assert!(err.to_string().contains("non-zero"));
    }

    #[test]
    fn test_manager_with_timeout_rejects_too_large() {
        let err = PsbtSessionManager::with_timeout(Duration::from_secs(
            PSBT_SESSION_MAX_TIMEOUT_SECS + 1,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn test_derive_session_id_deterministic() {
        let a = derive_psbt_session_id(&[1u8; 32], &[2u8; 32], 0, b"psbt", 100);
        let b = derive_psbt_session_id(&[1u8; 32], &[2u8; 32], 0, b"psbt", 100);
        assert_eq!(a, b);
    }

    #[test]
    fn test_derive_session_id_changes_on_tier() {
        let a = derive_psbt_session_id(&[1u8; 32], &[2u8; 32], 0, b"psbt", 100);
        let b = derive_psbt_session_id(&[1u8; 32], &[2u8; 32], 1, b"psbt", 100);
        assert_ne!(a, b);
    }

    #[test]
    fn test_derive_session_id_changes_on_psbt() {
        let a = derive_psbt_session_id(&[1u8; 32], &[2u8; 32], 0, b"psbt1", 100);
        let b = derive_psbt_session_id(&[1u8; 32], &[2u8; 32], 0, b"psbt2", 100);
        assert_ne!(a, b);
    }

    #[test]
    fn test_cannot_add_signature_above_psbt_size() {
        let mut s = new_session();
        let err = s
            .add_signature(SignerId::Share(1), vec![0u8; MAX_PSBT_SIZE + 1], vec![0xaa])
            .unwrap_err();
        assert!(err.to_string().contains("maximum"));
    }

    #[test]
    fn test_proposal_psbt_preserved_after_signatures() {
        let mut s = new_session();
        let original = s.proposal_psbt().to_vec();
        s.add_signature(SignerId::Share(1), vec![9; 8], vec![0xaa])
            .unwrap();
        assert_eq!(s.proposal_psbt(), &original[..]);
        assert_eq!(s.current_psbt(), &[9; 8][..]);
    }
}
