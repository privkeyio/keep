// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use frost_secp256k1_tr::{
    keys::PublicKeyPackage,
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Identifier, Signature, SigningPackage,
};
use serde::{Deserialize, Serialize};

use crate::error::{FrostNetError, Result};
use crate::nonce_store::NonceStore;
use crate::protocol::KFP_VERSION;

pub fn derive_session_id(message: &[u8], participants: &[u16], threshold: u16) -> [u8; 32] {
    derive_session_id_salted(message, participants, threshold, &[])
}

/// Like [`derive_session_id`] but folds an extra `salt` into the preimage.
/// Signing failover uses a per-attempt salt so a re-sample over the same
/// participant set produces a distinct session id (and a distinct fresh nonce)
/// instead of colliding with the just-completed attempt's id and tripping the
/// replay guard. The salt is still bound to message+participants+threshold, so
/// it does not weaken replay protection against genuine external replays.
pub fn derive_session_id_salted(
    message: &[u8],
    participants: &[u16],
    threshold: u16,
    salt: &[u8],
) -> [u8; 32] {
    let mut sorted_participants = participants.to_vec();
    sorted_participants.sort();

    let mut preimage = Vec::with_capacity(64 + message.len() + participants.len() * 2 + salt.len());
    preimage.extend_from_slice(b"keep-frost-session-v1");
    preimage.push(KFP_VERSION);
    preimage.extend_from_slice(&threshold.to_be_bytes());
    preimage.extend_from_slice(&(sorted_participants.len() as u16).to_be_bytes());
    for p in &sorted_participants {
        preimage.extend_from_slice(&p.to_be_bytes());
    }
    preimage.extend_from_slice(&(message.len() as u32).to_be_bytes());
    preimage.extend_from_slice(message);
    if !salt.is_empty() {
        preimage.extend_from_slice(&(salt.len() as u32).to_be_bytes());
        preimage.extend_from_slice(salt);
    }

    keep_core::crypto::blake2b_256(&preimage)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    AwaitingCommitments,
    AwaitingShares,
    Complete,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedSessionState {
    session_id: [u8; 32],
    message: Vec<u8>,
    #[serde(default)]
    message_type: String,
    threshold: u16,
    participants: Vec<u16>,
    state: SessionState,
    commitments: Vec<(Vec<u8>, Vec<u8>)>,
    signature_shares: Vec<(Vec<u8>, Vec<u8>)>,
    our_nonces: Option<Vec<u8>>,
    our_commitment: Option<Vec<u8>>,
    rehydrations_used: u16,
    max_rehydrations: u16,
}

impl CachedSessionState {
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
}

pub struct NetworkSession {
    session_id: [u8; 32],
    message: Vec<u8>,
    message_type: String,
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
    rehydrations_used: u16,
    max_rehydrations: u16,
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
            message_type: String::new(),
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
            rehydrations_used: 0,
            max_rehydrations: 3,
        }
    }

    pub fn with_max_rehydrations(mut self, max: u16) -> Self {
        self.max_rehydrations = max;
        self
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

    /// Requester-supplied domain label for `message`. Empty when unknown (e.g.
    /// a session predating the label or rehydrated from older cache state).
    pub fn message_type(&self) -> &str {
        &self.message_type
    }

    pub fn set_message_type(&mut self, message_type: String) {
        self.message_type = message_type;
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

        // Accept commitments regardless of strict ordering. Real relays reorder
        // events, so a participant's commitment can arrive after we've already
        // started collecting shares (or after another participant's share).
        // Only refuse once the session is settled; aggregation is separately
        // gated on every participant having both a commitment and a share.
        if matches!(
            self.state(),
            SessionState::Complete | SessionState::Failed | SessionState::Expired
        ) {
            return Err(FrostNetError::Session("Not accepting commitments".into()));
        }

        if !self.is_participant(share_index) {
            return Err(FrostNetError::Session(format!(
                "Share {share_index} not a participant"
            )));
        }

        let id = Identifier::try_from(share_index)
            .map_err(|e| FrostNetError::Crypto(format!("Invalid identifier: {e}")))?;

        if self.commitments.contains_key(&id) {
            return Err(FrostNetError::Session("Duplicate commitment".into()));
        }

        self.commitments.insert(id, commitment);

        if self.state == SessionState::AwaitingCommitments
            && self.commitments.len() >= self.threshold as usize
        {
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

    /// Participant indices (excluding `our_index`) for which `has_entry`
    /// reports no contribution. A participant index that fails `Identifier`
    /// conversion (only index 0, which is invalid for FROST and is rejected by
    /// `add_commitment`/`add_signature_share`, so it can't appear in a valid
    /// session) is treated as missing: it could never have contributed, and
    /// reporting it to failover just adds it to the excluded set where it
    /// matches no real peer, so this is harmless rather than a silent error.
    fn participants_missing<F>(&self, our_index: u16, has_entry: F) -> Vec<u16>
    where
        F: Fn(&Identifier) -> bool,
    {
        self.participants
            .iter()
            .copied()
            .filter(|&idx| idx != our_index)
            .filter(|&idx| {
                Identifier::try_from(idx)
                    .map(|id| !has_entry(&id))
                    .unwrap_or(true)
            })
            .collect()
    }

    /// Participant indices (excluding `our_index`) that have not submitted a
    /// commitment. Used by failover to exclude only peers that demonstrably
    /// failed to respond, leaving responsive peers eligible for the retry.
    pub fn uncommitted_participants(&self, our_index: u16) -> Vec<u16> {
        self.participants_missing(our_index, |id| self.commitments.contains_key(id))
    }

    /// Participant indices (excluding `our_index`) that have not submitted a
    /// signature share. Used by failover when commitments were pre-exchanged
    /// (so `uncommitted_participants` is empty) but some signers never produced
    /// a share before the round timed out.
    pub fn participants_missing_shares(&self, our_index: u16) -> Vec<u16> {
        self.participants_missing(our_index, |id| self.signature_shares.contains_key(id))
    }

    /// Build the FROST signing package from the collected commitments.
    ///
    /// Correctness invariant (load-bearing now that delivery order is relaxed):
    /// every signer must sign over the *identical* commitment subset. A
    /// `SigningPackage` built from a different commitment set produces shares
    /// that aggregation will reject. The session only admits exactly `threshold`
    /// participants, so the commitment map must not exceed that count.
    pub fn get_signing_package(&self) -> Result<SigningPackage> {
        if !self.has_all_commitments() {
            return Err(FrostNetError::Session("Not enough commitments".into()));
        }

        debug_assert!(
            self.commitments.len() == self.threshold as usize,
            "signing package must cover exactly `threshold` commitments; \
             signers diverging on the commitment subset will fail aggregation"
        );

        Ok(SigningPackage::new(self.commitments.clone(), &self.message))
    }

    pub fn add_signature_share(&mut self, share_index: u16, share: SignatureShare) -> Result<()> {
        if share_index == 0 {
            return Err(FrostNetError::Protocol(
                "Invalid share_index: must be non-zero".into(),
            ));
        }

        // Buffer shares even if a peer's share arrives before all commitments
        // (relay reordering). Aggregation is gated on every participant having
        // both a commitment and a share, so holding an early share is safe.
        if matches!(
            self.state(),
            SessionState::Complete | SessionState::Failed | SessionState::Expired
        ) {
            return Err(FrostNetError::Session("Not accepting shares".into()));
        }

        if !self.is_participant(share_index) {
            return Err(FrostNetError::Session(format!(
                "Share {share_index} not a participant"
            )));
        }

        let id = Identifier::try_from(share_index)
            .map_err(|e| FrostNetError::Crypto(format!("Invalid identifier: {e}")))?;

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

    /// Every participant has provided both a commitment and a signature share,
    /// so the commitment set and the share set match exactly, the precondition
    /// for `frost::aggregate`. Gating on this (rather than a bare share count)
    /// makes the coordinator tolerant of reordered relay delivery: a share that
    /// arrives before its commitment is held until the commitment shows up,
    /// instead of triggering an aggregate over a mismatched id set.
    pub fn ready_to_aggregate(&self) -> bool {
        self.participants.iter().all(|&p| {
            Identifier::try_from(p)
                .map(|id| {
                    self.commitments.contains_key(&id) && self.signature_shares.contains_key(&id)
                })
                .unwrap_or(false)
        })
    }

    pub fn try_aggregate(&mut self, pubkey_pkg: &PublicKeyPackage) -> Result<Option<[u8; 64]>> {
        if !self.ready_to_aggregate() {
            return Ok(None);
        }

        let signing_package = self.get_signing_package()?;

        match frost_secp256k1_tr::aggregate(&signing_package, &self.signature_shares, pubkey_pkg) {
            Ok(signature) => {
                pubkey_pkg
                    .verifying_key()
                    .verify(&self.message, &signature)
                    .map_err(|e| {
                        self.state = SessionState::Failed;
                        FrostNetError::Crypto(format!("Signature verification failed: {e}"))
                    })?;

                let serialized = signature
                    .serialize()
                    .map_err(|e| FrostNetError::Crypto(format!("Serialize signature: {e}")))?;

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
                let commit_ids: Vec<String> = self
                    .commitments
                    .keys()
                    .map(|id| hex::encode(id.serialize()))
                    .collect();
                let share_ids: Vec<String> = self
                    .signature_shares
                    .keys()
                    .map(|id| hex::encode(id.serialize()))
                    .collect();
                self.state = SessionState::Failed;
                Err(FrostNetError::Crypto(format!(
                    "Aggregation failed: {e} (commitment_ids={commit_ids:?} share_ids={share_ids:?})"
                )))
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

    pub fn take_our_nonces(&mut self) -> Option<SigningNonces> {
        self.our_nonces.take()
    }

    pub fn rehydrations_used(&self) -> u16 {
        self.rehydrations_used
    }

    pub fn max_rehydrations(&self) -> u16 {
        self.max_rehydrations
    }

    pub fn can_rehydrate(&self) -> bool {
        self.rehydrations_used < self.max_rehydrations
    }

    pub fn to_cached_state(&self) -> Result<CachedSessionState> {
        let commitments = self
            .commitments
            .iter()
            .map(|(id, c)| {
                let c_bytes = c
                    .serialize()
                    .map_err(|e| FrostNetError::Crypto(format!("Serialize commitment: {e}")))?;
                Ok((id.serialize(), c_bytes))
            })
            .collect::<Result<Vec<_>>>()?;

        let signature_shares = self
            .signature_shares
            .iter()
            .map(|(id, s)| (id.serialize(), s.serialize()))
            .collect::<Vec<_>>();

        let our_nonces = self
            .our_nonces
            .as_ref()
            .map(|n| {
                n.serialize()
                    .map_err(|e| FrostNetError::Crypto(format!("Serialize nonces: {e}")))
            })
            .transpose()?;

        let our_commitment = self
            .our_commitment
            .as_ref()
            .map(|c| {
                c.serialize()
                    .map_err(|e| FrostNetError::Crypto(format!("Serialize commitment: {e}")))
            })
            .transpose()?;

        Ok(CachedSessionState {
            session_id: self.session_id,
            message: self.message.clone(),
            message_type: self.message_type.clone(),
            threshold: self.threshold,
            participants: self.participants.clone(),
            state: self.state,
            commitments,
            signature_shares,
            our_nonces,
            our_commitment,
            rehydrations_used: self.rehydrations_used,
            max_rehydrations: self.max_rehydrations,
        })
    }

    const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
    const MAX_PARTICIPANTS: usize = 256;
    const MAX_COMMITMENTS: usize = 256;
    const MAX_SIGNATURE_SHARES: usize = 256;

    pub fn from_cached_state(cached: CachedSessionState) -> Result<Self> {
        if cached.message.len() > Self::MAX_MESSAGE_SIZE {
            return Err(FrostNetError::Session(format!(
                "Message too large: {} bytes (max {})",
                cached.message.len(),
                Self::MAX_MESSAGE_SIZE
            )));
        }

        if cached.participants.len() > Self::MAX_PARTICIPANTS {
            return Err(FrostNetError::Session(format!(
                "Too many participants: {} (max {})",
                cached.participants.len(),
                Self::MAX_PARTICIPANTS
            )));
        }

        if cached.commitments.len() > Self::MAX_COMMITMENTS {
            return Err(FrostNetError::Session(format!(
                "Too many commitments: {} (max {})",
                cached.commitments.len(),
                Self::MAX_COMMITMENTS
            )));
        }

        if cached.signature_shares.len() > Self::MAX_SIGNATURE_SHARES {
            return Err(FrostNetError::Session(format!(
                "Too many signature shares: {} (max {})",
                cached.signature_shares.len(),
                Self::MAX_SIGNATURE_SHARES
            )));
        }

        let expected_id =
            derive_session_id(&cached.message, &cached.participants, cached.threshold);
        if cached.session_id != expected_id {
            return Err(FrostNetError::Session(format!(
                "Session ID mismatch: expected {}, got {}",
                hex::encode(expected_id),
                hex::encode(cached.session_id)
            )));
        }

        if cached.rehydrations_used >= cached.max_rehydrations {
            return Err(FrostNetError::RehydrationLimitExceeded {
                session_id: hex::encode(cached.session_id),
                used: cached.rehydrations_used,
                max: cached.max_rehydrations,
            });
        }

        let mut commitments = BTreeMap::new();
        for (id_bytes, c_bytes) in cached.commitments {
            let id = Identifier::deserialize(&id_bytes)
                .map_err(|e| FrostNetError::Crypto(format!("Deserialize identifier: {e}")))?;
            let commitment = SigningCommitments::deserialize(&c_bytes)
                .map_err(|e| FrostNetError::Crypto(format!("Deserialize commitment: {e}")))?;
            commitments.insert(id, commitment);
        }

        let mut signature_shares = BTreeMap::new();
        for (id_bytes, s_bytes) in cached.signature_shares {
            let id = Identifier::deserialize(&id_bytes)
                .map_err(|e| FrostNetError::Crypto(format!("Deserialize identifier: {e}")))?;
            let share = SignatureShare::deserialize(&s_bytes)
                .map_err(|e| FrostNetError::Crypto(format!("Deserialize share: {e}")))?;
            signature_shares.insert(id, share);
        }

        let our_nonces = cached
            .our_nonces
            .map(|bytes| {
                SigningNonces::deserialize(&bytes)
                    .map_err(|e| FrostNetError::Crypto(format!("Deserialize nonces: {e}")))
            })
            .transpose()?;

        let our_commitment = cached
            .our_commitment
            .map(|bytes| {
                SigningCommitments::deserialize(&bytes)
                    .map_err(|e| FrostNetError::Crypto(format!("Deserialize commitment: {e}")))
            })
            .transpose()?;

        Ok(Self {
            session_id: cached.session_id,
            message: cached.message,
            message_type: cached.message_type,
            threshold: cached.threshold,
            participants: cached.participants,
            state: cached.state,
            created_at: Instant::now(),
            timeout: Duration::from_secs(30),
            commitments,
            signature_shares,
            our_nonces,
            our_commitment,
            signature: None,
            rehydrations_used: cached.rehydrations_used + 1,
            max_rehydrations: cached.max_rehydrations,
        })
    }
}

pub struct SessionManager {
    active_sessions: HashMap<[u8; 32], NetworkSession>,
    completed_sessions: HashSet<[u8; 32]>,
    completed_order: VecDeque<[u8; 32]>,
    max_completed_history: usize,
    session_timeout: Duration,
    nonce_store: Option<Arc<dyn NonceStore>>,
    max_rehydrations: u16,
}

fn validate_session_id(
    session_id: [u8; 32],
    message: &[u8],
    participants: &[u16],
    threshold: u16,
    salt: &[u8],
) -> Result<()> {
    let expected_id = derive_session_id_salted(message, participants, threshold, salt);
    if session_id != expected_id {
        return Err(FrostNetError::Session(format!(
            "Session ID mismatch: expected {}, got {}",
            hex::encode(expected_id),
            hex::encode(session_id)
        )));
    }
    Ok(())
}

impl SessionManager {
    const MAX_ACTIVE_SESSIONS: usize = 256;

    pub fn new() -> Self {
        Self {
            active_sessions: HashMap::new(),
            completed_sessions: HashSet::new(),
            completed_order: VecDeque::new(),
            max_completed_history: 1000,
            // A responder creates a fresh session per failover attempt (each
            // attempt rederives a distinct session id from its participant set),
            // so a responder session only needs to outlive a single requester
            // round, not the whole failover window. Bound it to the round
            // timeout plus margin for clock skew and relay latency. A consumed
            // single-use nonce held by an abandoned session is then released in
            // ~SIGNING_ROUND_TIMEOUT rather than ~60s, so a burst of failovers
            // can't drain responder nonce pools or fill the session table while
            // requesters abandon rounds after SIGNING_ROUND_TIMEOUT.
            session_timeout: crate::node::SIGNING_ROUND_TIMEOUT
                .saturating_add(Duration::from_secs(5)),
            nonce_store: None,
            max_rehydrations: 3,
        }
    }

    pub fn with_nonce_store(mut self, store: Arc<dyn NonceStore>) -> Self {
        self.nonce_store = Some(store);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = timeout;
        self
    }

    pub fn with_max_rehydrations(mut self, max: u16) -> Self {
        self.max_rehydrations = max;
        self
    }

    pub fn create_session(
        &mut self,
        session_id: [u8; 32],
        message: Vec<u8>,
        threshold: u16,
        participants: Vec<u16>,
    ) -> Result<&mut NetworkSession> {
        self.create_session_salted(session_id, message, threshold, participants, &[])
    }

    pub fn create_session_salted(
        &mut self,
        session_id: [u8; 32],
        message: Vec<u8>,
        threshold: u16,
        participants: Vec<u16>,
        salt: &[u8],
    ) -> Result<&mut NetworkSession> {
        validate_session_id(session_id, &message, &participants, threshold, salt)?;

        if self.completed_sessions.contains(&session_id) {
            return Err(FrostNetError::ReplayDetected(hex::encode(session_id)));
        }

        if let Some(ref store) = self.nonce_store {
            if store.is_consumed(&session_id) {
                return Err(FrostNetError::NonceConsumed(hex::encode(session_id)));
            }
        }

        if let Some(existing) = self.active_sessions.get(&session_id) {
            if !existing.is_expired() {
                return Err(FrostNetError::Session("Session already active".into()));
            }
            self.active_sessions.remove(&session_id);
        }

        self.cleanup_expired();
        if self.active_sessions.len() >= Self::MAX_ACTIVE_SESSIONS {
            return Err(FrostNetError::Session("Too many active sessions".into()));
        }

        let session = NetworkSession::new(session_id, message, threshold, participants)
            .with_timeout(self.session_timeout);

        self.active_sessions.insert(session_id, session);
        Ok(self
            .active_sessions
            .get_mut(&session_id)
            .expect("just inserted"))
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
        self.get_or_create_session_salted(session_id, message, threshold, participants, &[])
    }

    pub fn get_or_create_session_salted(
        &mut self,
        session_id: [u8; 32],
        message: Vec<u8>,
        threshold: u16,
        participants: Vec<u16>,
        salt: &[u8],
    ) -> Result<&mut NetworkSession> {
        validate_session_id(session_id, &message, &participants, threshold, salt)?;

        if self.completed_sessions.contains(&session_id) {
            return Err(FrostNetError::ReplayDetected(hex::encode(session_id)));
        }

        if let Some(ref store) = self.nonce_store {
            if store.is_consumed(&session_id) {
                return Err(FrostNetError::NonceConsumed(hex::encode(session_id)));
            }
        }

        if let Some(existing) = self.active_sessions.get(&session_id) {
            if !existing.is_expired() {
                if existing.message() != message
                    || existing.threshold() != threshold
                    || existing.participants() != participants
                {
                    return Err(FrostNetError::Session("Session parameters mismatch".into()));
                }
                return Ok(self
                    .active_sessions
                    .get_mut(&session_id)
                    .expect("just checked"));
            }
            self.active_sessions.remove(&session_id);
        }

        self.cleanup_expired();
        if self.active_sessions.len() >= Self::MAX_ACTIVE_SESSIONS {
            return Err(FrostNetError::Session("Too many active sessions".into()));
        }
        let session = NetworkSession::new(session_id, message, threshold, participants)
            .with_timeout(self.session_timeout);
        self.active_sessions.insert(session_id, session);

        Ok(self
            .active_sessions
            .get_mut(&session_id)
            .expect("just inserted"))
    }

    pub fn abandon_session(&mut self, session_id: &[u8; 32]) {
        self.active_sessions.remove(session_id);
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
        self.active_sessions
            .retain(|_, session| !session.is_expired());
    }

    pub fn active_count(&self) -> usize {
        self.active_sessions.len()
    }

    pub fn is_replay(&self, session_id: &[u8; 32]) -> bool {
        self.completed_sessions.contains(session_id)
    }

    pub fn is_nonce_consumed(&self, session_id: &[u8; 32]) -> bool {
        if let Some(ref store) = self.nonce_store {
            return store.is_consumed(session_id);
        }
        false
    }

    pub fn record_nonce_consumption(&self, session_id: &[u8; 32]) -> Result<()> {
        if let Some(ref store) = self.nonce_store {
            store.record(session_id)?;
        }
        Ok(())
    }

    pub fn rehydrate_session(&mut self, cached: CachedSessionState) -> Result<&mut NetworkSession> {
        let session_id = *cached.session_id();

        if self.completed_sessions.contains(&session_id) {
            return Err(FrostNetError::ReplayDetected(hex::encode(session_id)));
        }

        if let Some(ref store) = self.nonce_store {
            if store.is_consumed(&session_id) {
                return Err(FrostNetError::NonceConsumed(hex::encode(session_id)));
            }
        }

        if let Some(existing) = self.active_sessions.get(&session_id) {
            if !existing.is_expired() {
                return Err(FrostNetError::Session("Session already active".into()));
            }
            self.active_sessions.remove(&session_id);
        }

        self.cleanup_expired();
        if self.active_sessions.len() >= Self::MAX_ACTIVE_SESSIONS {
            return Err(FrostNetError::Session("Too many active sessions".into()));
        }

        let mut session = NetworkSession::from_cached_state(cached)?;
        session.timeout = self.session_timeout;

        self.active_sessions.insert(session_id, session);
        Ok(self
            .active_sessions
            .get_mut(&session_id)
            .expect("just inserted"))
    }

    pub fn cache_and_remove_session(
        &mut self,
        session_id: &[u8; 32],
    ) -> Result<Option<CachedSessionState>> {
        if let Some(session) = self.active_sessions.get(session_id) {
            let state = session.state();
            if state == SessionState::Complete || state == SessionState::Failed {
                self.active_sessions.remove(session_id);
                return Ok(None);
            }
            if !session.can_rehydrate() {
                self.active_sessions.remove(session_id);
                return Ok(None);
            }
            let cached = session.to_cached_state()?;
            self.active_sessions.remove(session_id);
            Ok(Some(cached))
        } else {
            Ok(None)
        }
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
    use crate::nonce_store::MemoryNonceStore;

    #[test]
    fn test_session_lifecycle() {
        let message = b"test message".to_vec();
        let participants = vec![1, 2, 3];
        let threshold = 2;
        let session_id = derive_session_id(&message, &participants, threshold);
        let session = NetworkSession::new(session_id, message, threshold, participants);

        assert_eq!(session.state(), SessionState::AwaitingCommitments);
        assert_eq!(session.commitments_needed(), 2);
    }

    // Relays reorder events: a participant's signature share can arrive before
    // its commitment. The session must buffer both and aggregate only once
    // every participant has both; never aggregate a share whose commitment is
    // missing (which used to produce `Aggregation failed: Unknown identifier`).
    #[test]
    fn test_aggregation_tolerates_reordered_share_before_commitment() {
        use frost_secp256k1_tr::rand_core::OsRng;
        use keep_core::frost::{ThresholdConfig, TrustedDealer};

        let (shares, pubkey_pkg) = TrustedDealer::new(ThresholdConfig::two_of_three())
            .generate("reorder-test")
            .unwrap();

        // Participants 1 and 2 (identifiers from shares[0], shares[1]).
        let kp1 = shares[0].key_package().unwrap();
        let kp2 = shares[1].key_package().unwrap();
        let (nonces1, commit1) =
            frost_secp256k1_tr::round1::commit(kp1.signing_share(), &mut OsRng);
        let (nonces2, commit2) =
            frost_secp256k1_tr::round1::commit(kp2.signing_share(), &mut OsRng);

        let message = b"reorder message".to_vec();
        let participants = vec![1u16, 2u16];
        let threshold = 2u16;
        let session_id = derive_session_id(&message, &participants, threshold);

        // Both signers sign over the same full commitment set.
        let mut commit_map = BTreeMap::new();
        commit_map.insert(Identifier::try_from(1u16).unwrap(), commit1);
        commit_map.insert(Identifier::try_from(2u16).unwrap(), commit2);
        let signing_package = SigningPackage::new(commit_map, &message);
        let share1 = frost_secp256k1_tr::round2::sign(&signing_package, &nonces1, &kp1).unwrap();
        let share2 = frost_secp256k1_tr::round2::sign(&signing_package, &nonces2, &kp2).unwrap();

        let mut session = NetworkSession::new(session_id, message, threshold, participants);

        // Worst-case ordering: a share arrives before any commitment.
        session.add_signature_share(1, share1).unwrap();
        assert!(
            session.try_aggregate(&pubkey_pkg).unwrap().is_none(),
            "must not aggregate with a share but no matching commitment"
        );

        session.add_commitment(2, commit2).unwrap();
        session.add_signature_share(2, share2).unwrap();
        // Threshold shares present, but participant 1's commitment is still
        // missing: must hold, not error.
        assert!(
            session.try_aggregate(&pubkey_pkg).unwrap().is_none(),
            "must not aggregate until every participant has a commitment"
        );

        // The late commitment completes the set.
        session.add_commitment(1, commit1).unwrap();
        let sig = session
            .try_aggregate(&pubkey_pkg)
            .expect("aggregate must not error")
            .expect("aggregate must produce a signature");
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_session_manager_replay_protection() {
        let mut manager = SessionManager::new();
        let message = vec![];
        let participants = vec![1, 2];
        let threshold = 2;
        let session_id = derive_session_id(&message, &participants, threshold);

        manager
            .create_session(session_id, message.clone(), threshold, participants.clone())
            .unwrap();
        manager.complete_session(&session_id);

        let result = manager.create_session(session_id, message, threshold, participants);
        assert!(result.is_err());
        assert!(manager.is_replay(&session_id));
    }

    #[test]
    fn test_participant_check() {
        let message = vec![];
        let participants = vec![1, 2, 3];
        let threshold = 2;
        let session_id = derive_session_id(&message, &participants, threshold);
        let session = NetworkSession::new(session_id, message, threshold, participants);
        assert!(session.is_participant(1));
        assert!(session.is_participant(2));
        assert!(!session.is_participant(4));
    }

    #[test]
    fn test_derive_session_id_deterministic() {
        let message = b"test message".to_vec();
        let participants = vec![1, 2, 3];
        let threshold = 2;

        let id1 = derive_session_id(&message, &participants, threshold);
        let id2 = derive_session_id(&message, &participants, threshold);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_derive_session_id_sorted_participants() {
        let message = b"test".to_vec();

        let id1 = derive_session_id(&message, &[1, 2, 3], 2);
        let id2 = derive_session_id(&message, &[3, 1, 2], 2);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_derive_session_id_different_params() {
        let message = b"test".to_vec();
        let participants = vec![1, 2, 3];

        let id1 = derive_session_id(&message, &participants, 2);
        let id2 = derive_session_id(&message, &participants, 3);
        assert_ne!(id1, id2);

        let id3 = derive_session_id(&message, &[1, 2], 2);
        assert_ne!(id1, id3);

        let id4 = derive_session_id(b"other", &participants, 2);
        assert_ne!(id1, id4);
    }

    #[test]
    fn test_session_id_mismatch_rejected() {
        let mut manager = SessionManager::new();
        let bad_session_id = [0u8; 32];

        let result = manager.create_session(bad_session_id, vec![], 2, vec![1, 2]);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("mismatch"));
    }

    #[test]
    fn test_nonce_consumption_tracking() {
        let store = Arc::new(MemoryNonceStore::new());
        let mut manager = SessionManager::new().with_nonce_store(store.clone());

        let message = vec![];
        let participants = vec![1, 2];
        let session_id = derive_session_id(&message, &participants, 2);

        manager.record_nonce_consumption(&session_id).unwrap();
        assert!(manager.is_nonce_consumed(&session_id));

        let result = manager.create_session(session_id, message, 2, participants);
        assert!(matches!(result, Err(FrostNetError::NonceConsumed(_))));
    }

    #[test]
    fn test_nonce_consumption_blocks_get_or_create() {
        let store = Arc::new(MemoryNonceStore::new());
        let mut manager = SessionManager::new().with_nonce_store(store.clone());

        let message = vec![];
        let participants = vec![1, 2];
        let session_id = derive_session_id(&message, &participants, 2);

        store.record(&session_id).unwrap();

        let result = manager.get_or_create_session(session_id, message, 2, participants);
        assert!(matches!(result, Err(FrostNetError::NonceConsumed(_))));
    }

    #[test]
    fn test_session_without_nonce_store() {
        let mut manager = SessionManager::new();
        let message = vec![];
        let participants = vec![1, 2];
        let session_id = derive_session_id(&message, &participants, 2);

        assert!(!manager.is_nonce_consumed(&session_id));
        manager.record_nonce_consumption(&session_id).unwrap();

        manager
            .create_session(session_id, message, 2, participants)
            .unwrap();
    }

    #[test]
    fn test_session_rehydration_tracking() {
        let message = b"test".to_vec();
        let participants = vec![1, 2];
        let session_id = derive_session_id(&message, &participants, 2);
        let session = NetworkSession::new(session_id, message, 2, participants);
        assert_eq!(session.rehydrations_used(), 0);
        assert_eq!(session.max_rehydrations(), 3);
        assert!(session.can_rehydrate());
    }

    #[test]
    fn test_session_cache_and_rehydrate() {
        let message = b"test".to_vec();
        let participants = vec![1, 2];
        let session_id = derive_session_id(&message, &participants, 2);
        let session = NetworkSession::new(session_id, message.clone(), 2, participants.clone());
        let cached = session.to_cached_state().unwrap();

        assert_eq!(*cached.session_id(), session_id);

        let rehydrated = NetworkSession::from_cached_state(cached).unwrap();
        assert_eq!(*rehydrated.session_id(), session_id);
        assert_eq!(rehydrated.message(), message.as_slice());
        assert_eq!(rehydrated.threshold(), 2);
        assert_eq!(rehydrated.participants(), participants.as_slice());
        assert_eq!(rehydrated.rehydrations_used(), 1);
        assert!(rehydrated.can_rehydrate());
    }

    #[test]
    fn test_rehydration_limit_enforcement() {
        let message = b"test".to_vec();
        let participants = vec![1, 2];
        let session_id = derive_session_id(&message, &participants, 2);
        let session =
            NetworkSession::new(session_id, message, 2, participants).with_max_rehydrations(2);

        let cached = session.to_cached_state().unwrap();
        let session = NetworkSession::from_cached_state(cached).unwrap();
        assert_eq!(session.rehydrations_used(), 1);

        let cached = session.to_cached_state().unwrap();
        let session = NetworkSession::from_cached_state(cached).unwrap();
        assert_eq!(session.rehydrations_used(), 2);
        assert!(!session.can_rehydrate());

        let cached = session.to_cached_state().unwrap();
        let result = NetworkSession::from_cached_state(cached);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_manager_rehydration() {
        let mut manager = SessionManager::new().with_max_rehydrations(3);
        let message = b"test".to_vec();
        let participants = vec![1, 2];
        let session_id = derive_session_id(&message, &participants, 2);

        manager
            .create_session(session_id, message, 2, participants)
            .unwrap();

        let cached = manager.cache_and_remove_session(&session_id).unwrap();
        assert!(cached.is_some());
        assert!(manager.get_session(&session_id).is_none());

        let cached = cached.unwrap();
        manager.rehydrate_session(cached).unwrap();
        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.rehydrations_used(), 1);
    }

    #[test]
    fn test_cached_session_state_serialization() {
        let message = b"test".to_vec();
        let participants = vec![1, 2];
        let session_id = derive_session_id(&message, &participants, 2);
        let mut session = NetworkSession::new(session_id, message.clone(), 2, participants);
        session.set_message_type("nostr-event".to_string());
        let cached = session.to_cached_state().unwrap();

        let json = serde_json::to_string(&cached).unwrap();
        let deserialized: CachedSessionState = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.session_id(), cached.session_id());
        let rehydrated = NetworkSession::from_cached_state(deserialized).unwrap();
        assert_eq!(*rehydrated.session_id(), session_id);
        assert_eq!(rehydrated.message(), message.as_slice());
        assert_eq!(rehydrated.message_type(), "nostr-event");
    }

    #[test]
    fn test_cached_state_defaults_empty_message_type() {
        // Cache state predating the message_type field deserializes with an
        // empty label rather than failing (serde default).
        let message = b"test".to_vec();
        let participants = vec![1, 2];
        let session_id = derive_session_id(&message, &participants, 2);
        let session = NetworkSession::new(session_id, message, 2, participants);
        let cached = session.to_cached_state().unwrap();

        let mut value = serde_json::to_value(&cached).unwrap();
        value.as_object_mut().unwrap().remove("message_type");
        let legacy: CachedSessionState = serde_json::from_value(value).unwrap();
        assert_eq!(legacy.message_type, "");
    }

    #[test]
    fn test_expired_session_can_be_cached() {
        let mut manager = SessionManager::new().with_timeout(Duration::from_millis(1));
        let message = b"test".to_vec();
        let participants = vec![1, 2];
        let session_id = derive_session_id(&message, &participants, 2);

        manager
            .create_session(session_id, message, 2, participants)
            .unwrap();

        std::thread::sleep(Duration::from_millis(10));

        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.state(), SessionState::Expired);

        let cached = manager.cache_and_remove_session(&session_id).unwrap();
        assert!(cached.is_some());
        assert!(manager.get_session(&session_id).is_none());
    }
}
