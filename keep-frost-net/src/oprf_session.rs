// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Box-side session state for the threshold-OPRF unlock and the holder-side
//! rate limiter that bounds the evaluation oracle.
//!
//! Mirrors the ECDH session machinery ([`crate::ecdh`]) but with a hard
//! asymmetry: only the initiator (the "box") holds blinding state. The box owns
//! the [`keep_core::oprf::unlock::Client`], collects holder partial evaluations
//! as 65-byte wire `Vec<u8>` keyed by FROST share index, and on quorum derives
//! the LUKS key locally. Holders keep no unlock session; they only answer the
//! eval oracle, which the [`OprfEvalRateLimiter`] keeps bounded.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use nostr_sdk::PublicKey;
use zeroize::Zeroizing;

use keep_core::oprf::unlock::Client;

use crate::error::{FrostNetError, Result};
use crate::protocol::OPRF_PARTIAL_LEN;

/// Domain-separated session id for an OPRF unlock, binding the blinded element
/// to the participant set. Mirrors [`crate::ecdh::derive_ecdh_session_id`].
pub fn derive_oprf_session_id(blinded: &[u8; 33], participants: &[u16]) -> [u8; 32] {
    let mut sorted_participants = participants.to_vec();
    sorted_participants.sort();

    let mut preimage = Vec::with_capacity(64 + participants.len() * 2);
    preimage.extend_from_slice(b"keep-frost-oprf-v1");
    preimage.extend_from_slice(blinded);
    preimage.extend_from_slice(&(sorted_participants.len() as u16).to_be_bytes());
    for p in &sorted_participants {
        preimage.extend_from_slice(&p.to_be_bytes());
    }

    keep_core::crypto::blake2b_256(&preimage)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OprfUnlockSessionState {
    Collecting,
    Complete,
    Failed(String),
    Expired,
}

/// Box-side state for one unlock attempt. Owns the OPRF [`Client`] (the blinding
/// secret), collects holder partials keyed by share index, and derives the LUKS
/// key once a quorum is present. The derived key never crosses the wire.
pub struct OprfUnlockSession {
    session_id: [u8; 32],
    client: Client,
    threshold: usize,
    participants: Vec<u16>,
    volume_id: String,
    epoch: u32,
    state: OprfUnlockSessionState,
    created_at: Instant,
    timeout: Duration,
    partials: BTreeMap<u16, Vec<u8>>,
}

impl OprfUnlockSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: [u8; 32],
        client: Client,
        threshold: usize,
        participants: Vec<u16>,
        volume_id: String,
        epoch: u32,
    ) -> Self {
        Self {
            session_id,
            client,
            threshold,
            participants,
            volume_id,
            epoch,
            state: OprfUnlockSessionState::Collecting,
            created_at: Instant::now(),
            timeout: Duration::from_secs(30),
            partials: BTreeMap::new(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn participants(&self) -> &[u16] {
        &self.participants
    }

    pub fn volume_id(&self) -> &str {
        &self.volume_id
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn state(&self) -> OprfUnlockSessionState {
        if self.created_at.elapsed() > self.timeout
            && self.state == OprfUnlockSessionState::Collecting
        {
            return OprfUnlockSessionState::Expired;
        }
        self.state.clone()
    }

    pub fn is_participant(&self, share_index: u16) -> bool {
        self.participants.contains(&share_index)
    }

    /// Record one holder partial. Rejects a non-participant, a duplicate share
    /// index, or a wrong-length partial (the OPRF wire encoding is fixed-size).
    pub fn add_partial(&mut self, share_index: u16, partial: Vec<u8>) -> Result<()> {
        if share_index == 0 {
            return Err(FrostNetError::Protocol(
                "Invalid share_index: must be non-zero".into(),
            ));
        }
        if self.state != OprfUnlockSessionState::Collecting {
            return Err(FrostNetError::Session("Not accepting OPRF partials".into()));
        }
        if !self.is_participant(share_index) {
            return Err(FrostNetError::Session(format!(
                "Share {share_index} not a participant"
            )));
        }
        if partial.len() != OPRF_PARTIAL_LEN {
            return Err(FrostNetError::Protocol(
                "Invalid OPRF partial length".into(),
            ));
        }
        if self.partials.contains_key(&share_index) {
            return Err(FrostNetError::Session("Duplicate OPRF partial".into()));
        }
        self.partials.insert(share_index, partial);
        Ok(())
    }

    pub fn has_quorum(&self) -> bool {
        self.partials.len() >= self.threshold
    }

    /// Derive the LUKS key once a quorum of partials is present. Below quorum
    /// returns `Ok(None)`; a finalize failure marks the session `Failed` and
    /// surfaces the error.
    pub fn try_finalize(&mut self) -> Result<Option<Zeroizing<[u8; 32]>>> {
        if !self.has_quorum() {
            return Ok(None);
        }

        let parts: Vec<Vec<u8>> = self.partials.values().cloned().collect();
        match self
            .client
            .finalize_luks_key(&parts, self.threshold, &self.volume_id, self.epoch)
        {
            Ok(key) => {
                self.state = OprfUnlockSessionState::Complete;
                Ok(Some(key))
            }
            Err(e) => {
                let msg = e.to_string();
                self.state = OprfUnlockSessionState::Failed(msg.clone());
                Err(FrostNetError::Crypto(msg))
            }
        }
    }

    pub fn is_complete(&self) -> bool {
        self.state == OprfUnlockSessionState::Complete
    }

    pub fn is_expired(&self) -> bool {
        self.state() == OprfUnlockSessionState::Expired
    }
}

pub struct OprfUnlockSessionManager {
    active_sessions: HashMap<[u8; 32], OprfUnlockSession>,
    session_timeout: Duration,
}

impl OprfUnlockSessionManager {
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
        client: Client,
        threshold: usize,
        participants: Vec<u16>,
        volume_id: String,
        epoch: u32,
    ) -> Result<&mut OprfUnlockSession> {
        if let Some(existing) = self.active_sessions.get(&session_id) {
            if !existing.is_expired() {
                return Err(FrostNetError::Session(
                    "OPRF unlock session already active".into(),
                ));
            }
            self.active_sessions.remove(&session_id);
        }

        self.cleanup_expired();
        if self.active_sessions.len() >= Self::MAX_ACTIVE_SESSIONS {
            return Err(FrostNetError::Session(
                "Too many active OPRF unlock sessions".into(),
            ));
        }

        let session = OprfUnlockSession::new(
            session_id,
            client,
            threshold,
            participants,
            volume_id,
            epoch,
        )
        .with_timeout(self.session_timeout);

        self.active_sessions.insert(session_id, session);
        Ok(self
            .active_sessions
            .get_mut(&session_id)
            .expect("just inserted"))
    }

    pub fn get_session(&self, session_id: &[u8; 32]) -> Option<&OprfUnlockSession> {
        self.active_sessions.get(session_id)
    }

    pub fn get_session_mut(&mut self, session_id: &[u8; 32]) -> Option<&mut OprfUnlockSession> {
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

impl Default for OprfUnlockSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-requester sliding-window rate limiter for the holder-side OPRF evaluation
/// oracle.
///
/// SECURITY: the OPRF-unlock input is a fixed, low-entropy label, so the
/// unlock's resistance to offline guessing depends on bounding how many
/// evaluations any one identity can obtain (see
/// `keep_core::oprf::threshold::partial_eval`). This caps each requester at
/// [`MAX_OPRF_EVALS_PER_WINDOW`] evaluations per [`OPRF_EVAL_WINDOW`]; beyond
/// that the holder refuses with [`FrostNetError::RateLimited`].
///
/// Memory ceiling: tracked identities are pruned lazily once their window
/// empties, and the table is capped at [`MAX_TRACKED_REQUESTERS`]. If a
/// finer-grained guarantee is ever needed (e.g. global eval budget), upgrade
/// this to a token-bucket keyed by both identity and group.
pub const MAX_OPRF_EVALS_PER_WINDOW: u32 = 8;
pub const OPRF_EVAL_WINDOW: Duration = Duration::from_secs(60);
const MAX_TRACKED_REQUESTERS: usize = 1024;

pub struct OprfEvalRateLimiter {
    window: Duration,
    max_per_window: u32,
    events: HashMap<PublicKey, Vec<Instant>>,
}

impl OprfEvalRateLimiter {
    pub fn new() -> Self {
        Self {
            window: OPRF_EVAL_WINDOW,
            max_per_window: MAX_OPRF_EVALS_PER_WINDOW,
            events: HashMap::new(),
        }
    }

    /// Record an evaluation request from `requester` at the current instant.
    /// Returns `true` if it is within the per-window budget, `false` if the
    /// requester has exceeded [`MAX_OPRF_EVALS_PER_WINDOW`].
    pub fn check_and_record(&mut self, requester: PublicKey) -> bool {
        self.check_and_record_at(requester, Instant::now())
    }

    /// Time-injectable core of [`check_and_record`], exposed for deterministic
    /// tests of the window logic.
    pub fn check_and_record_at(&mut self, requester: PublicKey, now: Instant) -> bool {
        let window = self.window;
        let cutoff = now.checked_sub(window);

        // Bound memory: drop identities whose window has fully emptied before
        // inserting a new one.
        if self.events.len() >= MAX_TRACKED_REQUESTERS && !self.events.contains_key(&requester) {
            self.events.retain(|_, ts| {
                ts.retain(|&t| cutoff.map(|c| t >= c).unwrap_or(true));
                !ts.is_empty()
            });
        }

        let entry = self.events.entry(requester).or_default();
        entry.retain(|&t| cutoff.map(|c| t >= c).unwrap_or(true));

        if entry.len() as u32 >= self.max_per_window {
            return false;
        }
        entry.push(now);
        true
    }
}

impl Default for OprfEvalRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keep_core::oprf::threshold;
    use keep_core::oprf::unlock;

    // rand_core 0.6 OsRng, reached through k256's elliptic-curve re-export so no
    // extra dependency is pulled in (split_key wants the rand_core 0.6 traits).
    use k256::elliptic_curve::rand_core::OsRng;

    fn split_2of3() -> Vec<threshold::KeyShare> {
        use k256::Scalar;
        let mut rng = OsRng;
        let s = <Scalar as k256::elliptic_curve::Field>::random(&mut rng);
        threshold::split_key(&s, 2, 3, rng).expect("split")
    }

    /// End-to-end through the box session: a real `unlock::Client` plus two real
    /// partials must finalize to the SAME LUKS key that a different quorum of the
    /// SAME key split derives directly through the byte API. Because `finalize`
    /// strips the per-attempt blinding, the same input + key yields a stable
    /// OPRF output, so every 2-of-3 quorum must land on one key. This mirrors the
    /// oracle in `keep-core/src/oprf.rs` `unlock_wire_api_matches_single_key`
    /// using only the public `keep_core::oprf` surface.
    #[test]
    fn session_finalizes_matching_other_quorum() {
        let input: &[u8] = b"keep-node-vault-v1";
        let shares = split_2of3();

        // Reference key: a fresh blind, the {0,2} quorum, finalized directly.
        let (ref_client, ref_blinded) = unlock::blind(input).expect("blind");
        let rp0 = unlock::evaluate(&shares[0], &ref_blinded).expect("p0");
        let rp2 = unlock::evaluate(&shares[2], &ref_blinded).expect("p2");
        let k_ref = ref_client
            .finalize_luks_key(&[rp0.to_vec(), rp2.to_vec()], 2, "vault0", 1)
            .expect("reference finalize");

        // Box session: independent fresh blind, the {1,2} quorum.
        let (client, blinded) = unlock::blind(input).expect("blind");
        let p0 = unlock::evaluate(&shares[0], &blinded).expect("p0");
        let p1 = unlock::evaluate(&shares[1], &blinded).expect("p1");

        let session_id = [0x11u8; 32];
        let mut session =
            OprfUnlockSession::new(session_id, client, 2, vec![1, 2, 3], "vault0".into(), 1);

        session.add_partial(1, p0.to_vec()).unwrap();
        assert!(
            session.try_finalize().unwrap().is_none(),
            "1/2 partials must not finalize"
        );
        session.add_partial(2, p1.to_vec()).unwrap();
        assert!(session.has_quorum());

        let k = session
            .try_finalize()
            .unwrap()
            .expect("quorum must finalize");
        assert_eq!(
            *k, *k_ref,
            "every 2-of-3 quorum must derive the same LUKS key"
        );
        assert_eq!(k.len(), 32);
        assert!(session.is_complete());
    }

    /// `add_partial` rejects a duplicate share index and a wrong-length partial.
    #[test]
    fn add_partial_rejects_duplicate_and_wrong_length() {
        let shares = split_2of3();
        let (client, blinded) = unlock::blind(b"keep-node-vault-v1").expect("blind");
        let p0 = unlock::evaluate(&shares[0], &blinded).expect("p0");

        let mut session =
            OprfUnlockSession::new([0x22u8; 32], client, 2, vec![1, 2, 3], "vault0".into(), 1);

        session.add_partial(1, p0.to_vec()).unwrap();
        assert!(
            session.add_partial(1, p0.to_vec()).is_err(),
            "duplicate share index must be rejected"
        );
        assert!(
            session.add_partial(2, vec![0u8; 64]).is_err(),
            "a 64-byte partial must be rejected"
        );
        assert!(
            session.add_partial(2, vec![0u8; 66]).is_err(),
            "a 66-byte partial must be rejected"
        );
        assert!(
            session.add_partial(4, p0.to_vec()).is_err(),
            "a non-participant share index must be rejected"
        );
    }

    /// Below quorum, `try_finalize` short-circuits to `Ok(None)` rather than
    /// fabricating a key.
    #[test]
    fn try_finalize_below_quorum_returns_none() {
        let shares = split_2of3();
        let (client, blinded) = unlock::blind(b"keep-node-vault-v1").expect("blind");
        let p0 = unlock::evaluate(&shares[0], &blinded).expect("p0");

        let mut session =
            OprfUnlockSession::new([0x33u8; 32], client, 2, vec![1, 2, 3], "vault0".into(), 1);
        session.add_partial(1, p0.to_vec()).unwrap();

        assert!(!session.has_quorum());
        assert!(session.try_finalize().unwrap().is_none());
        assert_eq!(session.state(), OprfUnlockSessionState::Collecting);
    }

    /// Rate limiter: `MAX + 1` requests from one identity rejects the last, a
    /// different identity is unaffected, and the window resets once it elapses.
    #[test]
    fn rate_limiter_bounds_per_identity_and_resets() {
        let mut rl = OprfEvalRateLimiter::new();
        let a = nostr_sdk::Keys::generate().public_key();
        let b = nostr_sdk::Keys::generate().public_key();

        let base = Instant::now();
        for i in 0..MAX_OPRF_EVALS_PER_WINDOW {
            assert!(
                rl.check_and_record_at(a, base + Duration::from_millis(i as u64)),
                "request {i} within budget must be allowed"
            );
        }
        // The (MAX+1)th from the same identity, still inside the window, is rejected.
        assert!(
            !rl.check_and_record_at(
                a,
                base + Duration::from_millis(MAX_OPRF_EVALS_PER_WINDOW as u64)
            ),
            "exceeding the per-window budget must be rejected"
        );

        // A different identity is unaffected.
        assert!(
            rl.check_and_record_at(b, base + Duration::from_millis(1)),
            "a distinct identity must not be rate limited by another's usage"
        );

        // After the window fully elapses, the first identity resets.
        assert!(
            rl.check_and_record_at(a, base + OPRF_EVAL_WINDOW + Duration::from_secs(1)),
            "the budget must reset after the window elapses"
        );
    }

    #[test]
    fn derive_oprf_session_id_is_deterministic_and_input_sensitive() {
        let blinded = [0x02u8; 33];
        assert_eq!(
            derive_oprf_session_id(&blinded, &[1, 2, 3]),
            derive_oprf_session_id(&blinded, &[3, 2, 1]),
            "participant order must not matter"
        );
        assert_ne!(
            derive_oprf_session_id(&blinded, &[1, 2, 3]),
            derive_oprf_session_id(&[0x03u8; 33], &[1, 2, 3]),
            "a different blinded element must yield a distinct id"
        );
        assert_ne!(
            derive_oprf_session_id(&blinded, &[1, 2, 3]),
            derive_oprf_session_id(&blinded, &[1, 2, 4]),
            "a different participant set must yield a distinct id"
        );
    }

    #[test]
    fn manager_lifecycle_and_duplicate_guard() {
        let shares = split_2of3();
        let (client, blinded) = unlock::blind(b"keep-node-vault-v1").expect("blind");
        let _ = unlock::evaluate(&shares[0], &blinded).expect("p0");

        let mut mgr = OprfUnlockSessionManager::new();
        let sid = [0x44u8; 32];
        mgr.create_session(sid, client, 2, vec![1, 2, 3], "vault0".into(), 1)
            .unwrap();
        assert!(mgr.get_session(&sid).is_some());

        // A duplicate active session id is refused.
        let (client2, _) = unlock::blind(b"keep-node-vault-v1").expect("blind");
        assert!(mgr
            .create_session(sid, client2, 2, vec![1, 2, 3], "vault0".into(), 1)
            .is_err());

        mgr.complete_session(&sid);
        assert!(mgr.get_session(&sid).is_none());
    }
}
