//! FROST signing session management.

#![forbid(unsafe_code)]
#![allow(unused_assignments)]

use std::collections::BTreeMap;

use frost::{
    keys::{KeyPackage, PublicKeyPackage},
    rand_core::OsRng,
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Identifier, Signature, SigningPackage,
};
use frost_secp256k1_tr as frost;
use zeroize::ZeroizeOnDrop;

use crate::crypto;
use crate::error::{KeepError, Result};

/// State of a signing session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Collecting round 1 commitments from participants.
    CollectingCommitments,
    /// Collecting round 2 signature shares.
    CollectingShares,
    /// Signing completed successfully.
    Complete,
    /// Signing failed.
    Failed,
}

/// A FROST signing session.
///
/// Manages the two-round signing protocol state and collected data.
#[derive(ZeroizeOnDrop)]
pub struct SigningSession {
    #[zeroize(skip)]
    session_id: [u8; 32],
    #[zeroize(skip)]
    message: Vec<u8>,
    #[zeroize(skip)]
    threshold: u16,
    #[zeroize(skip)]
    state: SessionState,

    #[zeroize(skip)]
    commitments: BTreeMap<Identifier, SigningCommitments>,
    #[zeroize(skip)]
    signature_shares: BTreeMap<Identifier, SignatureShare>,

    our_nonces: Option<SigningNonces>,

    #[zeroize(skip)]
    signature: Option<Signature>,
}

impl SigningSession {
    /// Create a new signing session.
    pub fn new(message: Vec<u8>, threshold: u16) -> Self {
        let session_id = Self::compute_session_id(&message);

        Self {
            session_id,
            message,
            threshold,
            state: SessionState::CollectingCommitments,
            commitments: BTreeMap::new(),
            signature_shares: BTreeMap::new(),
            our_nonces: None,
            signature: None,
        }
    }

    fn compute_session_id(message: &[u8]) -> [u8; 32] {
        let timestamp = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let random: [u8; 16] = crypto::random_bytes();

        let mut preimage = Vec::with_capacity(message.len() + 24);
        preimage.extend_from_slice(message);
        preimage.extend_from_slice(&timestamp.to_le_bytes());
        preimage.extend_from_slice(&random);

        crypto::blake2b_256(&preimage)
    }

    /// The session ID.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// The current session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Generate our commitment (round 1). Must not have been called before.
    pub fn generate_commitment(&mut self, key_package: &KeyPackage) -> Result<SigningCommitments> {
        if self.state != SessionState::CollectingCommitments {
            return Err(KeepError::Frost(
                "Invalid session state for commitment".into(),
            ));
        }

        if self.our_nonces.is_some() {
            return Err(KeepError::Frost(
                "Commitment already generated for this session".into(),
            ));
        }

        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut OsRng);

        self.our_nonces = Some(nonces);
        self.commitments
            .insert(*key_package.identifier(), commitments);

        Ok(commitments)
    }

    /// Add another participant's commitment.
    pub fn add_commitment(&mut self, id: Identifier, commitment: SigningCommitments) -> Result<()> {
        if self.state != SessionState::CollectingCommitments {
            return Err(KeepError::Frost("Not collecting commitments".into()));
        }

        if self.commitments.contains_key(&id) {
            return Err(KeepError::Frost("Duplicate commitment".into()));
        }

        self.commitments.insert(id, commitment);

        if self.commitments.len() >= self.threshold as usize {
            self.state = SessionState::CollectingShares;
        }

        Ok(())
    }

    /// Commitments still needed to reach threshold.
    pub fn commitments_needed(&self) -> usize {
        self.threshold as usize - self.commitments.len()
    }

    /// Generate our signature share (round 2).
    pub fn generate_signature_share(&mut self, key_package: &KeyPackage) -> Result<SignatureShare> {
        if self.state != SessionState::CollectingShares {
            return Err(KeepError::Frost(
                "Not ready to generate signature share".into(),
            ));
        }

        let nonces = self
            .our_nonces
            .take()
            .ok_or_else(|| KeepError::Frost("No nonces available - already used?".into()))?;

        let signing_package = SigningPackage::new(self.commitments.clone(), &self.message);

        let share = frost::round2::sign(&signing_package, &nonces, key_package)
            .map_err(|e| KeepError::Frost(format!("Signing failed: {}", e)))?;

        self.signature_shares
            .insert(*key_package.identifier(), share);

        Ok(share)
    }

    /// Add another participant's signature share.
    /// Returns the aggregated signature when threshold is met.
    pub fn add_signature_share(
        &mut self,
        id: Identifier,
        share: SignatureShare,
        pubkey_pkg: &PublicKeyPackage,
    ) -> Result<Option<Signature>> {
        if self.state != SessionState::CollectingShares {
            return Err(KeepError::Frost("Not collecting signature shares".into()));
        }

        if self.signature_shares.contains_key(&id) {
            return Err(KeepError::Frost("Duplicate signature share".into()));
        }

        self.signature_shares.insert(id, share);

        if self.signature_shares.len() >= self.threshold as usize {
            let signing_package = SigningPackage::new(self.commitments.clone(), &self.message);

            match frost::aggregate(&signing_package, &self.signature_shares, pubkey_pkg) {
                Ok(signature) => {
                    self.signature = Some(signature);
                    self.state = SessionState::Complete;
                    return Ok(Some(signature));
                }
                Err(e) => {
                    self.state = SessionState::Failed;
                    return Err(KeepError::Frost(format!("Aggregation failed: {}", e)));
                }
            }
        }

        Ok(None)
    }

    /// Signature shares still needed to reach threshold.
    pub fn shares_needed(&self) -> usize {
        self.threshold as usize - self.signature_shares.len()
    }

    /// The signature bytes, if signing is complete.
    pub fn signature_bytes(&self) -> Result<Option<[u8; 64]>> {
        match &self.signature {
            Some(s) => {
                let serialized = s.serialize().map_err(|e| {
                    KeepError::Frost(format!("Failed to serialize signature: {}", e))
                })?;
                let bytes_slice = serialized.as_slice();
                if bytes_slice.len() != 64 {
                    return Err(KeepError::Frost("Invalid signature length".into()));
                }
                let mut bytes = [0u8; 64];
                bytes.copy_from_slice(bytes_slice);
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    /// Returns true if signing completed successfully.
    pub fn is_complete(&self) -> bool {
        self.state == SessionState::Complete
    }
}

/// Sign using local shares only (no network). Requires threshold shares.
pub fn sign_with_local_shares(shares: &[super::SharePackage], message: &[u8]) -> Result<[u8; 64]> {
    use frost::{keys::PublicKeyPackage, round1, round2};

    if shares.is_empty() {
        return Err(KeepError::Frost("No shares provided".into()));
    }

    let threshold = shares[0].metadata.threshold as usize;
    if shares.len() < threshold {
        return Err(KeepError::Frost(format!(
            "Need {} shares to sign, only {} provided",
            threshold,
            shares.len()
        )));
    }

    let signing_shares = &shares[..threshold];

    let mut nonces_map: BTreeMap<Identifier, round1::SigningNonces> = BTreeMap::new();
    let mut commitments_map: BTreeMap<Identifier, round1::SigningCommitments> = BTreeMap::new();
    let mut verifying_shares: BTreeMap<Identifier, frost::keys::VerifyingShare> = BTreeMap::new();

    for share in signing_shares {
        let kp = share.key_package()?;
        let (nonces, commitments) = round1::commit(kp.signing_share(), &mut OsRng);
        nonces_map.insert(*kp.identifier(), nonces);
        commitments_map.insert(*kp.identifier(), commitments);
        verifying_shares.insert(*kp.identifier(), *kp.verifying_share());
    }

    let signing_package = SigningPackage::new(commitments_map, message);

    let mut signature_shares: BTreeMap<Identifier, round2::SignatureShare> = BTreeMap::new();

    for share in signing_shares {
        let kp = share.key_package()?;
        let id = *kp.identifier();
        let nonces = nonces_map
            .remove(&id)
            .ok_or_else(|| KeepError::Frost("Missing nonces for share".into()))?;
        let sig_share = round2::sign(&signing_package, &nonces, &kp)
            .map_err(|e| KeepError::Frost(format!("Signing failed: {}", e)))?;
        signature_shares.insert(id, sig_share);
    }

    let first_kp = signing_shares[0].key_package()?;
    let pubkey_pkg = PublicKeyPackage::new(verifying_shares, *first_kp.verifying_key());
    let signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_pkg)
        .map_err(|e| KeepError::Frost(format!("Aggregation failed: {}", e)))?;

    let serialized = signature
        .serialize()
        .map_err(|e| KeepError::Frost(format!("Failed to serialize signature: {}", e)))?;
    let bytes_slice = serialized.as_slice();
    if bytes_slice.len() != 64 {
        return Err(KeepError::Frost("Invalid signature length".into()));
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(bytes_slice);
    Ok(sig_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{ThresholdConfig, TrustedDealer};

    #[test]
    fn test_signing_session_two_of_three() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, pubkey_pkg) = dealer.generate("test").unwrap();

        let message = b"test message to sign".to_vec();

        let kp0 = shares[0].key_package().unwrap();
        let kp1 = shares[1].key_package().unwrap();

        let mut session0 = SigningSession::new(message.clone(), 2);
        let mut session1 = SigningSession::new(message.clone(), 2);
        session1.session_id = session0.session_id;

        let commit0 = session0.generate_commitment(&kp0).unwrap();
        let commit1 = session1.generate_commitment(&kp1).unwrap();

        session0.add_commitment(*kp1.identifier(), commit1).unwrap();
        session1.add_commitment(*kp0.identifier(), commit0).unwrap();

        assert_eq!(session0.state(), SessionState::CollectingShares);
        assert_eq!(session1.state(), SessionState::CollectingShares);

        let share0 = session0.generate_signature_share(&kp0).unwrap();
        let share1 = session1.generate_signature_share(&kp1).unwrap();

        session0
            .add_signature_share(*kp1.identifier(), share1, &pubkey_pkg)
            .unwrap();
        let result = session1
            .add_signature_share(*kp0.identifier(), share0, &pubkey_pkg)
            .unwrap();

        assert!(session0.is_complete());
        assert!(result.is_some());

        let sig_bytes = session0.signature_bytes().unwrap().unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }

    #[test]
    fn test_nonce_single_use() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let message = b"test message".to_vec();
        let kp = shares[0].key_package().unwrap();

        let mut session = SigningSession::new(message, 2);
        let _ = session.generate_commitment(&kp).unwrap();

        let result = session.generate_commitment(&kp);
        assert!(result.is_err());
    }
}
