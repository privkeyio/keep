//! FROST signing coordinator for multi-party signing sessions.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frost::{
    rand_core::OsRng,
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Identifier, Signature, SigningPackage,
};
use frost_secp256k1_tr as frost;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{KeepError, Result};
use crate::frost::{FrostMessage, FrostMessageType, SharePackage};

/// Coordinates a FROST signing session between multiple participants.
// False positive from zeroize_derive: fields with #[zeroize(skip)] trigger unused_assignments
// in generated Drop impl. The allow must be ABOVE derive to apply to generated code.
#[allow(unused_assignments)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Coordinator {
    #[zeroize(skip)]
    session_id: [u8; 32],
    #[zeroize(skip)]
    message: Vec<u8>,
    #[zeroize(skip)]
    threshold: u16,
    #[zeroize(skip)]
    commitments: BTreeMap<Identifier, SigningCommitments>,
    #[zeroize(skip)]
    signature_shares: BTreeMap<Identifier, SignatureShare>,
    #[zeroize(skip)]
    our_identifier: Option<Identifier>,
    our_nonces: Option<SigningNonces>,
}

impl Coordinator {
    /// Create a new signing coordinator.
    pub fn new(message: Vec<u8>, threshold: u16) -> Self {
        Self {
            session_id: crate::crypto::random_bytes(),
            message,
            threshold,
            commitments: BTreeMap::new(),
            signature_shares: BTreeMap::new(),
            our_identifier: None,
            our_nonces: None,
        }
    }

    /// The session ID.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Add a local share and generate its commitment.
    pub fn add_local_share(&mut self, share: &SharePackage) -> Result<FrostMessage> {
        let kp = share.key_package()?;
        let id = *kp.identifier();

        let (nonces, commitment) = frost::round1::commit(kp.signing_share(), &mut OsRng);

        self.our_identifier = Some(id);
        self.our_nonces = Some(nonces);
        self.commitments.insert(id, commitment);

        let commit_bytes = commitment
            .serialize()
            .map_err(|e| KeepError::Frost(format!("Serialize commitment: {}", e)))?;

        Ok(FrostMessage::commitment(
            &self.session_id,
            share.metadata.identifier,
            &commit_bytes,
        ))
    }

    /// Add a remote participant's commitment.
    pub fn add_remote_commitment(&mut self, msg: &FrostMessage) -> Result<()> {
        if msg.msg_type != FrostMessageType::Round1Commitment {
            return Err(KeepError::Frost("Expected commitment message".into()));
        }

        if msg.session_id != hex::encode(self.session_id) {
            return Err(KeepError::Frost("Session ID mismatch".into()));
        }

        let payload = msg.payload_bytes()?;
        let commitment = SigningCommitments::deserialize(&payload)
            .map_err(|e| KeepError::Frost(format!("Invalid commitment: {}", e)))?;

        let id = Identifier::try_from(msg.identifier)
            .map_err(|e| KeepError::Frost(format!("Invalid identifier: {}", e)))?;

        self.commitments.insert(id, commitment);
        Ok(())
    }

    /// Returns true if threshold commitments collected.
    pub fn has_enough_commitments(&self) -> bool {
        self.commitments.len() >= self.threshold as usize
    }

    /// Generate our signature share (round 2).
    pub fn generate_signature_share(&mut self, share: &SharePackage) -> Result<FrostMessage> {
        if !self.has_enough_commitments() {
            return Err(KeepError::Frost(format!(
                "Need {} commitments, have {}",
                self.threshold,
                self.commitments.len()
            )));
        }

        let kp = share.key_package()?;
        let our_id = self
            .our_identifier
            .take()
            .ok_or_else(|| KeepError::Frost("No identifier available".into()))?;
        let nonces = self
            .our_nonces
            .take()
            .ok_or_else(|| KeepError::Frost("No nonces available".into()))?;

        let signing_package = SigningPackage::new(self.commitments.clone(), &self.message);

        let sig_share = frost::round2::sign(&signing_package, &nonces, &kp)
            .map_err(|e| KeepError::Frost(format!("Sign failed: {}", e)))?;

        self.signature_shares.insert(our_id, sig_share);

        let share_bytes = sig_share.serialize();

        Ok(FrostMessage::signature_share(
            &self.session_id,
            share.metadata.identifier,
            &share_bytes,
        ))
    }

    /// Add a remote participant's signature share.
    pub fn add_remote_signature_share(&mut self, msg: &FrostMessage) -> Result<()> {
        if msg.msg_type != FrostMessageType::Round2Share {
            return Err(KeepError::Frost("Expected signature share message".into()));
        }

        if msg.session_id != hex::encode(self.session_id) {
            return Err(KeepError::Frost("Session ID mismatch".into()));
        }

        let payload = msg.payload_bytes()?;
        let sig_share = SignatureShare::deserialize(&payload)
            .map_err(|e| KeepError::Frost(format!("Invalid signature share: {}", e)))?;

        let id = Identifier::try_from(msg.identifier)
            .map_err(|e| KeepError::Frost(format!("Invalid identifier: {}", e)))?;

        self.signature_shares.insert(id, sig_share);
        Ok(())
    }

    /// Returns true if threshold shares collected.
    pub fn has_enough_shares(&self) -> bool {
        self.signature_shares.len() >= self.threshold as usize
    }

    /// Aggregate shares into a complete Schnorr signature.
    pub fn aggregate(&self, share: &SharePackage) -> Result<Signature> {
        if !self.has_enough_shares() {
            return Err(KeepError::Frost(format!(
                "Need {} shares, have {}",
                self.threshold,
                self.signature_shares.len()
            )));
        }

        let signing_package = SigningPackage::new(self.commitments.clone(), &self.message);
        let pubkey_pkg = share.pubkey_package()?;

        frost::aggregate(&signing_package, &self.signature_shares, &pubkey_pkg)
            .map_err(|e| KeepError::Frost(format!("Aggregation failed: {}", e)))
    }

    /// Aggregate shares and return the 64-byte signature.
    pub fn aggregate_to_bytes(&self, share: &SharePackage) -> Result<[u8; 64]> {
        let signature = self.aggregate(share)?;
        let serialized = signature
            .serialize()
            .map_err(|e| KeepError::Frost(format!("Serialize signature: {}", e)))?;

        let bytes = serialized.as_slice();
        if bytes.len() != 64 {
            return Err(KeepError::Frost("Invalid signature length".into()));
        }

        let mut result = [0u8; 64];
        result.copy_from_slice(bytes);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{ThresholdConfig, TrustedDealer};

    #[test]
    fn test_coordinator_local_only() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let message = b"test message".to_vec();
        let mut coord = Coordinator::new(message, 2);

        let _msg1 = coord.add_local_share(&shares[0]).unwrap();

        let kp1 = shares[1].key_package().unwrap();
        let (nonces1, commit1) = frost::round1::commit(kp1.signing_share(), &mut OsRng);
        let commit1_bytes = commit1.serialize().unwrap();
        let msg1 = FrostMessage::commitment(coord.session_id(), 2, &commit1_bytes);
        coord.add_remote_commitment(&msg1).unwrap();

        assert!(coord.has_enough_commitments());

        let _our_share_msg = coord.generate_signature_share(&shares[0]).unwrap();

        let signing_package = SigningPackage::new(coord.commitments.clone(), b"test message");
        let sig_share1 = frost::round2::sign(&signing_package, &nonces1, &kp1).unwrap();
        let share1_bytes = sig_share1.serialize();
        let share_msg1 = FrostMessage::signature_share(coord.session_id(), 2, &share1_bytes);
        coord.add_remote_signature_share(&share_msg1).unwrap();

        assert!(coord.has_enough_shares());

        let sig_bytes = coord.aggregate_to_bytes(&shares[0]).unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }
}
