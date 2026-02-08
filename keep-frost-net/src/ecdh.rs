// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

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
    if partial_points.len() < 2 {
        return Err(FrostNetError::Crypto(
            "Need at least 2 partial points".into(),
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
    shared_secret: Option<[u8; 32]>,
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

    pub fn try_complete(&mut self) -> Result<Option<[u8; 32]>> {
        if !self.has_all_shares() {
            return Ok(None);
        }

        let partial_vec: Vec<(u16, [u8; 33])> = self
            .partial_points
            .iter()
            .map(|(id, p)| {
                let id_bytes = id.serialize();
                let share_index = u16::from_be_bytes([id_bytes[0], id_bytes[1]]);
                (share_index, *p)
            })
            .collect();

        match aggregate_ecdh_shares(&partial_vec, &self.participants) {
            Ok(shared_secret) => {
                self.shared_secret = Some(shared_secret);
                self.state = EcdhSessionState::Complete;
                Ok(Some(shared_secret))
            }
            Err(e) => {
                self.state = EcdhSessionState::Failed;
                Err(e)
            }
        }
    }

    pub fn shared_secret(&self) -> Option<&[u8; 32]> {
        self.shared_secret.as_ref()
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

    pub fn create_session(
        &mut self,
        session_id: [u8; 32],
        recipient_pubkey: [u8; 33],
        threshold: u16,
        participants: Vec<u16>,
    ) -> Result<&mut EcdhSession> {
        if self.active_sessions.contains_key(&session_id) {
            let session = self.active_sessions.get(&session_id).unwrap();
            if !session.is_expired() {
                return Err(FrostNetError::Session("ECDH session already active".into()));
            }
            self.active_sessions.remove(&session_id);
        }

        let session = EcdhSession::new(session_id, recipient_pubkey, threshold, participants)
            .with_timeout(self.session_timeout);

        self.active_sessions.insert(session_id, session);
        Ok(self.active_sessions.get_mut(&session_id).unwrap())
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
            if existing.recipient_pubkey() != &recipient_pubkey
                || existing.participants() != participants
            {
                return Err(FrostNetError::Session(
                    "ECDH session parameters mismatch".into(),
                ));
            }
        } else {
            let session = EcdhSession::new(session_id, recipient_pubkey, threshold, participants)
                .with_timeout(self.session_timeout);
            self.active_sessions.insert(session_id, session);
        }

        Ok(self.active_sessions.get_mut(&session_id).unwrap())
    }

    pub fn complete_session(&mut self, session_id: &[u8; 32]) {
        self.active_sessions.remove(session_id);
    }

    pub fn cleanup_expired(&mut self) {
        let expired: Vec<[u8; 32]> = self
            .active_sessions
            .iter()
            .filter(|(_, session)| session.is_expired())
            .map(|(id, _)| *id)
            .collect();

        for id in expired {
            self.active_sessions.remove(&id);
        }
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
    fn test_lagrange_coefficient() {
        let participants = vec![1, 2, 3];

        let coeff1 = lagrange_coefficient(1, &participants).unwrap();
        let coeff2 = lagrange_coefficient(2, &participants).unwrap();
        let coeff3 = lagrange_coefficient(3, &participants).unwrap();

        assert_ne!(coeff1, Scalar::ZERO);
        assert_ne!(coeff2, Scalar::ZERO);
        assert_ne!(coeff3, Scalar::ZERO);
    }
}
