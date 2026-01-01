#![forbid(unsafe_code)]

use k256::schnorr::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

use crate::error::{FrostNetError, Result};

const PROOF_DOMAIN_TAG: &[u8] = b"keep-frost-announce-proof-v1";

pub fn compute_proof_message(
    group_pubkey: &[u8; 32],
    share_index: u16,
    verifying_share: &[u8; 33],
    timestamp: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROOF_DOMAIN_TAG);
    hasher.update(group_pubkey);
    hasher.update(share_index.to_be_bytes());
    hasher.update(verifying_share);
    hasher.update(timestamp.to_be_bytes());
    hasher.finalize().into()
}

pub fn sign_proof(
    signing_share_bytes: &[u8; 32],
    group_pubkey: &[u8; 32],
    share_index: u16,
    verifying_share: &[u8; 33],
    timestamp: u64,
) -> Result<[u8; 64]> {
    let message = compute_proof_message(group_pubkey, share_index, verifying_share, timestamp);
    let signing_key = SigningKey::from_bytes(signing_share_bytes)
        .map_err(|e| FrostNetError::Crypto(format!("Invalid signing share: {}", e)))?;
    let signature = signing_key.sign(&message);
    Ok(signature.to_bytes())
}

pub fn verify_proof(
    verifying_share: &[u8; 33],
    proof_signature: &[u8; 64],
    group_pubkey: &[u8; 32],
    share_index: u16,
    timestamp: u64,
) -> Result<()> {
    let message = compute_proof_message(group_pubkey, share_index, verifying_share, timestamp);
    let x_only: [u8; 32] = verifying_share[1..33]
        .try_into()
        .expect("slice of correct length");
    let verifying_key = VerifyingKey::from_bytes(&x_only)
        .map_err(|e| FrostNetError::Crypto(format!("Invalid verifying share: {}", e)))?;
    let signature = Signature::try_from(proof_signature.as_slice())
        .map_err(|e| FrostNetError::Crypto(format!("Invalid proof signature: {}", e)))?;
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| FrostNetError::Crypto("Proof-of-share verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_compressed_pubkey(verifying_key: &VerifyingKey) -> [u8; 33] {
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..33].copy_from_slice(&verifying_key.to_bytes());
        compressed
    }

    #[test]
    fn test_proof_roundtrip() {
        let signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();

        let mut signing_share = [0u8; 32];
        signing_share.copy_from_slice(&signing_key.to_bytes());

        let verifying_share = to_compressed_pubkey(&verifying_key);

        let group_pubkey = [1u8; 32];
        let share_index = 1u16;
        let timestamp = 1234567890u64;

        let signature = sign_proof(
            &signing_share,
            &group_pubkey,
            share_index,
            &verifying_share,
            timestamp,
        )
        .unwrap();

        verify_proof(
            &verifying_share,
            &signature,
            &group_pubkey,
            share_index,
            timestamp,
        )
        .unwrap();
    }

    #[test]
    fn test_proof_fails_with_wrong_share() {
        let signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();

        let mut signing_share = [0u8; 32];
        signing_share.copy_from_slice(&signing_key.to_bytes());

        let verifying_share = to_compressed_pubkey(&verifying_key);

        let group_pubkey = [1u8; 32];
        let share_index = 1u16;
        let timestamp = 1234567890u64;

        let signature = sign_proof(
            &signing_share,
            &group_pubkey,
            share_index,
            &verifying_share,
            timestamp,
        )
        .unwrap();

        let wrong_signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let wrong_verifying_key = wrong_signing_key.verifying_key();
        let wrong_verifying_share = to_compressed_pubkey(&wrong_verifying_key);

        let result = verify_proof(
            &wrong_verifying_share,
            &signature,
            &group_pubkey,
            share_index,
            timestamp,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_fails_with_wrong_index() {
        let signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();

        let mut signing_share = [0u8; 32];
        signing_share.copy_from_slice(&signing_key.to_bytes());

        let verifying_share = to_compressed_pubkey(&verifying_key);

        let group_pubkey = [1u8; 32];
        let share_index = 1u16;
        let timestamp = 1234567890u64;

        let signature = sign_proof(
            &signing_share,
            &group_pubkey,
            share_index,
            &verifying_share,
            timestamp,
        )
        .unwrap();

        let result = verify_proof(&verifying_share, &signature, &group_pubkey, 2u16, timestamp);
        assert!(result.is_err());
    }
}
