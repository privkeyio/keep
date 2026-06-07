// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use frost_secp256k1_tr::Identifier;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar};

use crate::error::{FrostNetError, Result};

pub fn derive_ecdh_session_id(recipient_pubkey: &[u8; 33], participants: &[u16]) -> [u8; 32] {
    let mut sorted_participants = participants.to_vec();
    sorted_participants.sort();

    let mut preimage = Vec::with_capacity(64 + participants.len() * 2);
    preimage.extend_from_slice(b"keep-frost-ecdh-v1");
    preimage.extend_from_slice(recipient_pubkey);
    preimage.extend_from_slice(&(sorted_participants.len() as u16).to_be_bytes());
    for p in &sorted_participants {
        preimage.extend_from_slice(&p.to_be_bytes());
    }

    keep_core::crypto::blake2b_256(&preimage)
}

pub fn compute_partial_ecdh(
    signing_share: &[u8; 32],
    recipient_pubkey: &[u8; 33],
) -> Result<[u8; 33]> {
    let scalar = Scalar::from_repr((*signing_share).into());
    let scalar = Option::<Scalar>::from(scalar)
        .ok_or_else(|| FrostNetError::Crypto("Invalid signing share scalar".into()))?;

    let point = AffinePoint::from_bytes(recipient_pubkey.into());
    let point = Option::<AffinePoint>::from(point)
        .ok_or_else(|| FrostNetError::Crypto("Invalid recipient pubkey".into()))?;

    let partial = ProjectivePoint::from(point) * scalar;
    let partial_affine = partial.to_affine();

    let bytes = partial_affine.to_bytes();
    let mut result = [0u8; 33];
    result.copy_from_slice(&bytes);
    Ok(result)
}

pub fn lagrange_coefficient(identifier: u16, all_identifiers: &[u16]) -> Result<Scalar> {
    let id = Identifier::try_from(identifier)
        .map_err(|e| FrostNetError::Crypto(format!("Invalid identifier: {e}")))?;
    let id_scalar = id.to_scalar();

    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;

    for &other_id in all_identifiers {
        if other_id == identifier {
            continue;
        }
        let other = Identifier::try_from(other_id)
            .map_err(|e| FrostNetError::Crypto(format!("Invalid identifier: {e}")))?;
        let other_scalar = other.to_scalar();

        numerator *= other_scalar;
        denominator *= other_scalar - id_scalar;
    }

    let denominator_inv = Option::<Scalar>::from(denominator.invert())
        .ok_or_else(|| FrostNetError::Crypto("Lagrange coefficient: zero denominator".into()))?;

    Ok(numerator * denominator_inv)
}

pub fn aggregate_ecdh_shares(
    partial_points: &[(u16, [u8; 33])],
    participants: &[u16],
) -> Result<[u8; 32]> {
    if partial_points.is_empty() {
        return Err(FrostNetError::Crypto(
            "Need at least 1 partial point".into(),
        ));
    }

    let mut result = ProjectivePoint::IDENTITY;

    for (share_index, partial_bytes) in partial_points {
        let partial = AffinePoint::from_bytes(partial_bytes.into());
        let partial = Option::<AffinePoint>::from(partial)
            .ok_or_else(|| FrostNetError::Crypto("Invalid partial point".into()))?;

        let coeff = lagrange_coefficient(*share_index, participants)?;

        result += ProjectivePoint::from(partial) * coeff;
    }

    let result_affine = result.to_affine();
    let compressed = result_affine.to_bytes();

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&compressed[1..33]);
    Ok(shared_secret)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdhSessionState {
    AwaitingShares,
    Complete,
    Failed,
    Expired,
}

pub struct EcdhSession {
    session_id: [u8; 32],
    recipient_pubkey: [u8; 33],
    participants: Vec<u16>,
    threshold: u16,
    state: EcdhSessionState,
    created_at: Instant,
    timeout: Duration,
    partial_points: BTreeMap<Identifier, [u8; 33]>,
    shared_secret: Option<Zeroizing<[u8; 32]>>,
}

impl EcdhSession {
    pub fn new(
        session_id: [u8; 32],
        recipient_pubkey: [u8; 33],
        threshold: u16,
        participants: Vec<u16>,
    ) -> Self {
        Self {
            session_id,
            recipient_pubkey,
            participants,
            threshold,
            state: EcdhSessionState::AwaitingShares,
            created_at: Instant::now(),
            timeout: Duration::from_secs(30),
            partial_points: BTreeMap::new(),
            shared_secret: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    pub fn recipient_pubkey(&self) -> &[u8; 33] {
        &self.recipient_pubkey
    }

    pub fn participants(&self) -> &[u16] {
        &self.participants
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    pub fn state(&self) -> EcdhSessionState {
        if self.created_at.elapsed() > self.timeout && self.state != EcdhSessionState::Complete {
            return EcdhSessionState::Expired;
        }
        self.state
    }

    pub fn is_participant(&self, share_index: u16) -> bool {
        self.participants.contains(&share_index)
    }

    pub fn add_partial(&mut self, share_index: u16, partial_point: [u8; 33]) -> Result<()> {
        if share_index == 0 {
            return Err(FrostNetError::Protocol(
                "Invalid share_index: must be non-zero".into(),
            ));
        }

        if self.state != EcdhSessionState::AwaitingShares {
            return Err(FrostNetError::Session("Not accepting ECDH shares".into()));
        }

        if !self.is_participant(share_index) {
            return Err(FrostNetError::Session(format!(
                "Share {share_index} not a participant"
            )));
        }

        let id = Identifier::try_from(share_index)
            .map_err(|e| FrostNetError::Crypto(format!("Invalid identifier: {e}")))?;

        if self.partial_points.contains_key(&id) {
            return Err(FrostNetError::Session("Duplicate ECDH share".into()));
        }

        self.partial_points.insert(id, partial_point);
        Ok(())
    }

    pub fn has_all_shares(&self) -> bool {
        self.partial_points.len() >= self.threshold as usize
    }

    pub fn try_complete(&mut self) -> Result<Option<Zeroizing<[u8; 32]>>> {
        if !self.has_all_shares() {
            return Ok(None);
        }

        let partial_vec: Vec<(u16, [u8; 33])> = self
            .partial_points
            .iter()
            .map(|(id, p)| {
                let id_bytes = id.serialize();
                let len = id_bytes.len();
                let share_index = u16::from_be_bytes([id_bytes[len - 2], id_bytes[len - 1]]);
                (share_index, *p)
            })
            .collect();

        match aggregate_ecdh_shares(&partial_vec, &self.participants) {
            Ok(shared_secret) => {
                let secret = Zeroizing::new(shared_secret);
                self.state = EcdhSessionState::Complete;
                self.shared_secret = Some(secret.clone());
                Ok(Some(secret))
            }
            Err(e) => {
                self.state = EcdhSessionState::Failed;
                Err(e)
            }
        }
    }

    pub fn shared_secret(&self) -> Option<&[u8; 32]> {
        self.shared_secret.as_deref()
    }

    pub fn is_complete(&self) -> bool {
        self.state == EcdhSessionState::Complete
    }

    pub fn is_expired(&self) -> bool {
        self.state() == EcdhSessionState::Expired
    }
}

pub struct EcdhSessionManager {
    active_sessions: HashMap<[u8; 32], EcdhSession>,
    session_timeout: Duration,
}

impl EcdhSessionManager {
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
        recipient_pubkey: [u8; 33],
        threshold: u16,
        participants: Vec<u16>,
    ) -> Result<&mut EcdhSession> {
        if let Some(existing) = self.active_sessions.get(&session_id) {
            if !existing.is_expired() {
                return Err(FrostNetError::Session("ECDH session already active".into()));
            }
            self.active_sessions.remove(&session_id);
        }

        self.cleanup_expired();
        if self.active_sessions.len() >= Self::MAX_ACTIVE_SESSIONS {
            return Err(FrostNetError::Session(
                "Too many active ECDH sessions".into(),
            ));
        }

        let session = EcdhSession::new(session_id, recipient_pubkey, threshold, participants)
            .with_timeout(self.session_timeout);

        self.active_sessions.insert(session_id, session);
        Ok(self
            .active_sessions
            .get_mut(&session_id)
            .expect("just inserted"))
    }

    pub fn get_session(&self, session_id: &[u8; 32]) -> Option<&EcdhSession> {
        self.active_sessions.get(session_id)
    }

    pub fn get_session_mut(&mut self, session_id: &[u8; 32]) -> Option<&mut EcdhSession> {
        self.active_sessions.get_mut(session_id)
    }

    pub fn get_or_create_session(
        &mut self,
        session_id: [u8; 32],
        recipient_pubkey: [u8; 33],
        threshold: u16,
        participants: Vec<u16>,
    ) -> Result<&mut EcdhSession> {
        if let Some(existing) = self.active_sessions.get(&session_id) {
            if existing.is_expired() {
                self.active_sessions.remove(&session_id);
            } else if existing.recipient_pubkey() != &recipient_pubkey
                || existing.threshold() != threshold
                || existing.participants() != participants
            {
                return Err(FrostNetError::Session(
                    "ECDH session parameters mismatch".into(),
                ));
            } else {
                return Ok(self
                    .active_sessions
                    .get_mut(&session_id)
                    .expect("just checked"));
            }
        }

        self.cleanup_expired();
        if self.active_sessions.len() >= Self::MAX_ACTIVE_SESSIONS {
            return Err(FrostNetError::Session(
                "Too many active ECDH sessions".into(),
            ));
        }
        let session = EcdhSession::new(session_id, recipient_pubkey, threshold, participants)
            .with_timeout(self.session_timeout);
        self.active_sessions.insert(session_id, session);

        Ok(self
            .active_sessions
            .get_mut(&session_id)
            .expect("just inserted"))
    }

    pub fn complete_session(&mut self, session_id: &[u8; 32]) {
        self.active_sessions.remove(session_id);
    }

    pub fn cleanup_expired(&mut self) {
        self.active_sessions
            .retain(|_, session| !session.is_expired());
    }
}

impl Default for EcdhSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Valid SEC1-compressed secp256k1 point reused as the recipient pubkey
    /// across the ECDH tests.
    fn test_pubkey() -> [u8; 33] {
        hex::decode("02bc52210b20d3fb89326463a3518674c7edde65794a7765c7f3a9119b20bfc6de")
            .unwrap()
            .try_into()
            .unwrap()
    }

    /// Deterministic, valid (sub-group-order) signing-share scalar. The `seed`
    /// only perturbs the high byte so every value stays well below the
    /// secp256k1 group order while remaining distinct per test.
    fn test_scalar(seed: u8) -> [u8; 32] {
        let mut s = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
            0xf0, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
            0xd0, 0xe0, 0xf0, 0x01,
        ];
        s[0] = seed;
        s
    }

    #[test]
    fn test_derive_ecdh_session_id_deterministic() {
        let recipient = [0x02u8; 33];
        let participants = vec![1, 2, 3];

        let id1 = derive_ecdh_session_id(&recipient, &participants);
        let id2 = derive_ecdh_session_id(&recipient, &participants);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_derive_ecdh_session_id_sorted_participants() {
        let recipient = [0x02u8; 33];

        let id1 = derive_ecdh_session_id(&recipient, &[1, 2, 3]);
        let id2 = derive_ecdh_session_id(&recipient, &[3, 1, 2]);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_single_party_ecdh() {
        let signing_share = test_scalar(0x11);
        let recipient_pk = test_pubkey();
        let partial = compute_partial_ecdh(&signing_share, &recipient_pk).unwrap();
        let result = aggregate_ecdh_shares(&[(1u16, partial)], &[1u16]);
        assert!(
            result.is_ok(),
            "single-party aggregate failed: {:?}",
            result.err()
        );

        let session_id = [0u8; 32];
        let mut session = EcdhSession::new(session_id, recipient_pk, 1, vec![1]);
        session.add_partial(1, partial).unwrap();
        let secret = session.try_complete().expect("try_complete should succeed");
        assert!(
            secret.is_some(),
            "single-party session should produce secret"
        );
    }

    #[test]
    fn test_lagrange_coefficient() {
        let participants = vec![1, 2, 3];

        let coeff1 = lagrange_coefficient(1, &participants).unwrap();
        let coeff2 = lagrange_coefficient(2, &participants).unwrap();
        let coeff3 = lagrange_coefficient(3, &participants).unwrap();

        assert_ne!(coeff1, Scalar::ZERO);
        assert_ne!(coeff2, Scalar::ZERO);
        assert_ne!(coeff3, Scalar::ZERO);
    }

    // === #417 round 2: targeted unit tests killing surviving mutations ===

    /// `derive_ecdh_session_id` must factor in EVERY input: the domain tag,
    /// recipient pubkey, and participant set. A regression that drops any
    /// component or replaces the digest with a constant would let an attacker
    /// confuse two distinct sessions into the same id.
    #[test]
    fn derive_ecdh_session_id_distinguishes_each_input_component() {
        let id_a = derive_ecdh_session_id(&[0x02u8; 33], &[1, 2, 3]);
        let id_b = derive_ecdh_session_id(&[0x03u8; 33], &[1, 2, 3]);
        assert_ne!(
            id_a, id_b,
            "different recipient pubkey must yield distinct id"
        );

        let id_c = derive_ecdh_session_id(&[0x02u8; 33], &[1, 2]);
        let id_d = derive_ecdh_session_id(&[0x02u8; 33], &[1, 2, 4]);
        assert_ne!(
            id_a, id_c,
            "different participant count must yield distinct id"
        );
        // id_a and id_d share the same participant count (3) but differ in a
        // single value — this pins the per-participant value loop, which a
        // count-only comparison would leave unguarded.
        assert_ne!(
            id_a, id_d,
            "different participant value must yield distinct id"
        );

        // A constant-return mutation would land all the above on the same
        // pinned bytes; this assertion locks it down.
        assert_ne!(id_a, [1u8; 32]);
        assert_ne!(id_a, [0u8; 32]);
    }

    /// `compute_partial_ecdh` returns a non-zero compressed point for a valid
    /// scalar+point pair. A "return Ok([0; 33])" regression would silently
    /// produce a zero share that aggregates to the curve identity (or fails).
    #[test]
    fn compute_partial_ecdh_returns_nonzero_compressed_point() {
        let scalar = test_scalar(0x11);
        let pk = test_pubkey();
        let result = compute_partial_ecdh(&scalar, &pk).unwrap();
        assert_ne!(
            result, [0u8; 33],
            "partial point must not be the zero pattern"
        );
        // First byte is the SEC1 compressed prefix; must be 0x02 or 0x03.
        assert!(
            result[0] == 0x02 || result[0] == 0x03,
            "first byte must be a valid SEC1 prefix, got {:#x}",
            result[0]
        );
    }

    /// `compute_partial_ecdh` rejects malformed inputs. A regression that
    /// short-circuits to `Ok([0; 33])` would silently mask a corrupt
    /// scalar/pubkey on the wire.
    #[test]
    fn compute_partial_ecdh_rejects_invalid_inputs() {
        let valid_pk = test_pubkey();
        // 0xff*32 is greater than the secp256k1 group order, an invalid
        // scalar repr that must surface a Crypto error.
        assert!(compute_partial_ecdh(&[0xffu8; 32], &valid_pk).is_err());

        // 0xff*33 is not a valid SEC1 compressed point.
        let scalar = [0x01u8; 32];
        assert!(compute_partial_ecdh(&scalar, &[0xffu8; 33]).is_err());
    }

    /// `lagrange_coefficient` must return the textbook value for the
    /// standard 2-of-2 case: coeffs are (id_j) / (id_j - id_i), so over
    /// `{1, 2}` we get `coeff(1) = 2 / (2 - 1) = 2` and `coeff(2) = 1 / (1 - 2) = -1`.
    /// A mutation that swaps multiplication for addition would shift the
    /// algebra; pinning these closes the `*=` / `-` mutations directly.
    #[test]
    fn lagrange_coefficient_matches_known_2of2_values() {
        let participants = vec![1u16, 2];
        let c1 = lagrange_coefficient(1, &participants).unwrap();
        let c2 = lagrange_coefficient(2, &participants).unwrap();

        // c1 = 2 (the Scalar form), c2 = -1.
        let two = Scalar::from(2u64);
        let neg_one = -Scalar::ONE;
        assert_eq!(c1, two, "coeff(1) over {{1,2}} must equal 2");
        assert_eq!(c2, neg_one, "coeff(2) over {{1,2}} must equal -1");

        // Sum of coefficients over the full participant set must be 1
        // (basic Lagrange interpolation invariant) — this catches a
        // shift in the numerator/denominator math.
        assert_eq!(c1 + c2, Scalar::ONE);
    }

    /// `lagrange_coefficient` surfaces an error for an out-of-range identifier.
    /// Index 0 cannot map to a FROST `Identifier`, so the `try_from` guard must
    /// short-circuit instead of silently producing a bogus coefficient.
    #[test]
    fn lagrange_coefficient_rejects_invalid_identifier() {
        assert!(lagrange_coefficient(0, &[0, 1]).is_err());
    }

    /// `aggregate_ecdh_shares` errors on empty input. A regression to
    /// `Ok([0; 32])` would silently return a fake secret to callers.
    #[test]
    fn aggregate_ecdh_shares_rejects_empty_input() {
        let err = aggregate_ecdh_shares(&[], &[1u16]);
        assert!(
            err.is_err(),
            "empty partial set must surface a Crypto error"
        );
    }

    /// Pin that the aggregated single-party result matches recipient_pk * scalar
    /// — the exact ECDH equation. A `Ok([0; 32])` regression in
    /// `aggregate_ecdh_shares` or `Ok([0; 33])` in `compute_partial_ecdh`
    /// would both fail this end-to-end check.
    #[test]
    fn aggregate_ecdh_shares_matches_direct_ecdh_in_single_party_case() {
        let scalar = test_scalar(0x10);
        let pk = test_pubkey();

        let partial = compute_partial_ecdh(&scalar, &pk).unwrap();
        let result = aggregate_ecdh_shares(&[(1u16, partial)], &[1u16]).unwrap();

        // Independent computation: shared = (recipient_pk) * scalar in
        // projective form, then take the x-coordinate of the affine.
        let scalar_field = Option::<Scalar>::from(Scalar::from_repr(scalar.into())).unwrap();
        let pk_point = Option::<AffinePoint>::from(AffinePoint::from_bytes((&pk).into())).unwrap();
        let direct = (ProjectivePoint::from(pk_point) * scalar_field).to_affine();
        let direct_bytes = direct.to_bytes();
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&direct_bytes[1..33]);

        assert_eq!(
            result, expected,
            "single-party aggregate must match direct ECDH"
        );
    }

    fn fixture_session() -> EcdhSession {
        EcdhSession::new([0xAA; 32], [0x02u8; 33], 2, vec![1, 2, 3])
    }

    /// Accessors must return the underlying values verbatim. A mutation that
    /// replaces them with a `Box::leak`'d constant would let a caller act
    /// on a session under the wrong identity.
    #[test]
    fn ecdh_session_accessors_return_construction_inputs() {
        let s = fixture_session();
        assert_eq!(s.session_id(), &[0xAA; 32]);
        assert_eq!(s.recipient_pubkey(), &[0x02u8; 33]);
        assert_eq!(s.participants(), &[1, 2, 3]);
        assert_eq!(s.threshold(), 2);
    }

    /// `is_participant` is a real gate — the rejection branch in
    /// `add_partial` depends on it. A `true`-return regression would
    /// silently accept shares from peers not in the participant list.
    #[test]
    fn ecdh_session_is_participant_distinguishes_members_from_outsiders() {
        let s = fixture_session();
        assert!(s.is_participant(1));
        assert!(s.is_participant(2));
        assert!(s.is_participant(3));
        assert!(!s.is_participant(4));
        assert!(!s.is_participant(0));
        assert!(!s.is_participant(99));
    }

    /// `add_partial` rejection paths — each is a real correctness gate. A
    /// regression that swaps `==` for `!=` or `!` would silently accept
    /// the wrong input and corrupt the aggregation.
    #[test]
    fn ecdh_session_add_partial_rejects_invalid_shares() {
        let mut s = fixture_session();

        // share_index == 0 is rejected.
        assert!(s.add_partial(0, [0u8; 33]).is_err());

        // Non-participant share is rejected.
        assert!(s.add_partial(7, [0u8; 33]).is_err());

        // First valid contribution accepted.
        let valid_partial = [0x02u8; 33];
        assert!(s.add_partial(1, valid_partial).is_ok());

        // Duplicate from the same share is rejected.
        assert!(s.add_partial(1, valid_partial).is_err());

        // Once state moves to Complete or Failed, no more contributions.
        s.state = EcdhSessionState::Complete;
        assert!(s.add_partial(2, valid_partial).is_err());
        s.state = EcdhSessionState::Failed;
        assert!(s.add_partial(2, valid_partial).is_err());
    }

    /// `has_all_shares` is the threshold gate driving `try_complete`'s
    /// short-circuit. A `true`-return regression would attempt aggregation
    /// on an under-threshold set, producing garbage or crashing.
    #[test]
    fn ecdh_session_has_all_shares_compares_against_threshold() {
        let mut s = fixture_session();
        let p = [0x02u8; 33];
        assert!(!s.has_all_shares());
        s.add_partial(1, p).unwrap();
        assert!(
            !s.has_all_shares(),
            "1/2 collected — must still be below threshold"
        );
        s.add_partial(2, p).unwrap();
        assert!(s.has_all_shares(), "2/2 collected — threshold met");
    }

    /// `try_complete` returns `Ok(None)` short-circuit when below threshold.
    /// A "replace with `Ok(Some(constant))`" regression would emit a fake
    /// shared secret before all shares arrive.
    #[test]
    fn ecdh_session_try_complete_short_circuits_below_threshold() {
        let mut s = fixture_session();
        s.add_partial(1, [0x02u8; 33]).unwrap();
        let r = s.try_complete().unwrap();
        assert!(
            r.is_none(),
            "1/2 collected — must return None, not a fabricated secret"
        );
        assert_eq!(s.state(), EcdhSessionState::AwaitingShares);
    }

    /// `is_complete` and `is_expired` predicates must reflect the actual
    /// state. A `true`-return regression on either would make callers
    /// believe the session has shipped its shared secret when it hasn't.
    #[test]
    fn ecdh_session_complete_and_expired_predicates_track_state() {
        let mut s = fixture_session();
        assert!(!s.is_complete());
        assert!(!s.is_expired());
        s.state = EcdhSessionState::Complete;
        assert!(s.is_complete());
        assert!(!s.is_expired());
    }

    /// `shared_secret()` returns `None` before completion and the actual
    /// stored bytes after. A `None`-return regression would defeat every
    /// downstream caller that consumes the derived secret; a "leak a
    /// constant" regression would silently hand the same canary secret to
    /// every caller regardless of which session they queried.
    #[test]
    fn ecdh_session_shared_secret_returns_stored_value_only_after_completion() {
        let scalar = test_scalar(0x21);
        let pk = test_pubkey();
        let partial = compute_partial_ecdh(&scalar, &pk).unwrap();

        let mut s = EcdhSession::new([0; 32], pk, 1, vec![1]);
        assert!(
            s.shared_secret().is_none(),
            "no secret before any partial is contributed"
        );

        s.add_partial(1, partial).unwrap();
        let returned = s
            .try_complete()
            .unwrap()
            .expect("single-party completion must yield a secret");

        let stored = s
            .shared_secret()
            .expect("Complete state must expose the secret");
        assert_eq!(
            stored, &*returned,
            "shared_secret() must return the same bytes try_complete handed back, not a leaked constant"
        );
        assert_ne!(stored, &[0u8; 32]);
        assert_ne!(stored, &[1u8; 32]);
    }

    /// `state()` reports `Expired` when the session deadline passes — but
    /// NOT when state is already `Complete`. A `&&` ↔ `||` mutation in
    /// the expiry check would either expire complete sessions
    /// (returning the wrong state to callers polling for the secret) or
    /// never expire incomplete ones.
    #[test]
    fn ecdh_session_state_expires_only_when_not_complete() {
        let mut s = EcdhSession::new([0; 32], [0x02u8; 33], 2, vec![1, 2]);
        s.timeout = Duration::from_nanos(1);
        std::thread::sleep(Duration::from_millis(2));

        assert_eq!(
            s.state(),
            EcdhSessionState::Expired,
            "past-deadline incomplete session must report Expired"
        );

        s.state = EcdhSessionState::Complete;
        assert_eq!(
            s.state(),
            EcdhSessionState::Complete,
            "Complete sessions must NOT flip to Expired even past deadline"
        );
    }

    /// `EcdhSessionManager::get_session{,_mut}` returns the stored session
    /// by id. A `None`-return regression would force every consumer to
    /// re-create the session, breaking the in-flight share collection.
    #[test]
    fn ecdh_session_manager_lookup_returns_stored_session() {
        let mut mgr = EcdhSessionManager::new();
        let sid = [0x11; 32];
        mgr.create_session(sid, [0x02u8; 33], 2, vec![1, 2])
            .unwrap();

        assert!(mgr.get_session(&sid).is_some());
        assert!(mgr.get_session_mut(&sid).is_some());
        // A different id must not collide.
        assert!(mgr.get_session(&[0x22; 32]).is_none());
    }

    /// `create_session` refuses a duplicate active session id. A `delete !`
    /// regression on the `is_expired` guard would allow a duplicate to
    /// silently replace an active session, dropping its collected shares.
    #[test]
    fn ecdh_session_manager_create_session_refuses_duplicate_active() {
        let mut mgr = EcdhSessionManager::new();
        let sid = [0x11; 32];
        mgr.create_session(sid, [0x02u8; 33], 2, vec![1, 2])
            .unwrap();
        assert!(mgr
            .create_session(sid, [0x02u8; 33], 2, vec![1, 2])
            .is_err());
    }

    /// `get_or_create_session` returns the existing session ONLY when every
    /// parameter matches. The `||` chain has 3 != checks; a `&&` swap would
    /// allow returning a session under conflicting parameters, fabricating
    /// state for a different protocol context.
    #[test]
    fn ecdh_session_manager_get_or_create_rejects_parameter_mismatch() {
        let mut mgr = EcdhSessionManager::new();
        let sid = [0x33; 32];
        mgr.get_or_create_session(sid, [0x02u8; 33], 2, vec![1, 2])
            .unwrap();

        // Same id, different recipient.
        assert!(
            mgr.get_or_create_session(sid, [0x03u8; 33], 2, vec![1, 2])
                .is_err(),
            "different recipient pubkey must surface mismatch"
        );
        // Same id, different threshold.
        assert!(
            mgr.get_or_create_session(sid, [0x02u8; 33], 3, vec![1, 2])
                .is_err(),
            "different threshold must surface mismatch"
        );
        // Same id, different participants.
        assert!(
            mgr.get_or_create_session(sid, [0x02u8; 33], 2, vec![1, 3])
                .is_err(),
            "different participants must surface mismatch"
        );
        // Same id, all parameters match — returns the same session.
        assert!(mgr
            .get_or_create_session(sid, [0x02u8; 33], 2, vec![1, 2])
            .is_ok());
    }

    /// `complete_session` and `cleanup_expired` are the lifecycle exits. A
    /// no-op regression on either would silently leak EcdhSession state
    /// past its useful lifetime, exhausting the MAX_ACTIVE_SESSIONS cap.
    #[test]
    fn ecdh_session_manager_lifecycle_evicts_completed_and_expired() {
        let mut mgr = EcdhSessionManager::new().with_timeout(Duration::from_nanos(1));

        let sid_done = [0xAA; 32];
        mgr.create_session(sid_done, [0x02u8; 33], 2, vec![1, 2])
            .unwrap();
        assert!(mgr.get_session(&sid_done).is_some());
        mgr.complete_session(&sid_done);
        assert!(
            mgr.get_session(&sid_done).is_none(),
            "complete_session must remove the entry"
        );

        let sid_exp = [0xBB; 32];
        mgr.create_session(sid_exp, [0x02u8; 33], 2, vec![1, 2])
            .unwrap();
        std::thread::sleep(Duration::from_millis(2));
        mgr.cleanup_expired();
        assert!(
            mgr.get_session(&sid_exp).is_none(),
            "cleanup_expired must drop sessions past their deadline"
        );
    }

    /// `create_session` may reuse an id whose prior session has EXPIRED,
    /// replacing the stale entry instead of reporting "already active". This
    /// pins the `is_expired()` guard: a regression that treats an expired
    /// duplicate as still-active would reject the second create.
    #[test]
    fn ecdh_session_manager_create_session_replaces_expired_duplicate() {
        let mut mgr = EcdhSessionManager::new().with_timeout(Duration::from_nanos(1));
        let sid = [0x44; 32];
        mgr.create_session(sid, [0x02u8; 33], 2, vec![1, 2])
            .unwrap();
        std::thread::sleep(Duration::from_millis(2));

        // The prior entry is now expired, so a fresh create must succeed by
        // evicting it; the new participant set proves the entry was replaced.
        assert!(mgr.create_session(sid, [0x02u8; 33], 2, vec![1, 3]).is_ok());
        assert_eq!(mgr.get_session(&sid).unwrap().participants(), &[1, 3]);
    }

    /// `create_session` enforces the `MAX_ACTIVE_SESSIONS` cap once the table
    /// is full of live sessions. A regression that drops the bound would let an
    /// adversary exhaust memory by opening unbounded concurrent sessions.
    #[test]
    fn ecdh_session_manager_enforces_max_active_sessions() {
        let mut mgr = EcdhSessionManager::new();
        for i in 0..EcdhSessionManager::MAX_ACTIVE_SESSIONS {
            let mut sid = [0u8; 32];
            sid[0] = i as u8;
            mgr.create_session(sid, [0x02u8; 33], 2, vec![1, 2])
                .unwrap();
        }

        // A new distinct id beyond the cap must be rejected.
        let mut sid = [0u8; 32];
        sid[1] = 1;
        assert!(mgr
            .create_session(sid, [0x02u8; 33], 2, vec![1, 2])
            .is_err());
    }
}
