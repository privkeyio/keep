// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use crate::error::{EnclaveError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const POLICY_BINDING_DOMAIN: &[u8] = b"keep-enclave-policy-v1";
const MAX_SEALED_KEY_LEN: usize = 4096;

pub fn policy_binding_hash(policy_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_BINDING_DOMAIN);
    hasher.update(policy_bytes);
    hasher.finalize().into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    pub encrypted_data_key: Vec<u8>,
    pub encrypted_wallet_key: Vec<u8>,
    pub nonce: [u8; 12],
    pub policy_hash: [u8; 32],
}

pub trait KmsProvider: Send + Sync {
    fn generate_data_key(&self) -> Result<DataKeyResult>;
    fn decrypt_data_key(
        &self,
        encrypted_key: &[u8],
        attestation_doc: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
}

pub struct DataKeyResult {
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub struct EnvelopeEncryption<K: KmsProvider> {
    kms: K,
}

impl<K: KmsProvider> EnvelopeEncryption<K> {
    pub fn new(kms: K) -> Self {
        Self { kms }
    }

    pub fn encrypt_for_enclave(
        &self,
        wallet_key: &[u8],
        policy_bytes: &[u8],
    ) -> Result<EncryptedWallet> {
        let policy_hash = policy_binding_hash(policy_bytes);
        let body = Zeroizing::new(sealed_body(wallet_key, policy_bytes)?);
        let data_key_result = self.kms.generate_data_key()?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| EnclaveError::Kms(format!("Failed to generate nonce: {e}")))?;

        let cipher = Aes256Gcm::new_from_slice(&data_key_result.plaintext)
            .map_err(|e| EnclaveError::Kms(format!("Invalid key: {e}")))?;

        let encrypted_wallet_key = cipher
            .encrypt(
                &Nonce::from(nonce_bytes),
                Payload {
                    msg: body.as_ref(),
                    aad: &policy_hash,
                },
            )
            .map_err(|_| EnclaveError::Kms("Encryption failed".into()))?;

        let mut plaintext = data_key_result.plaintext;
        plaintext.zeroize();

        Ok(EncryptedWallet {
            encrypted_data_key: data_key_result.ciphertext,
            encrypted_wallet_key,
            nonce: nonce_bytes,
            policy_hash,
        })
    }

    pub fn decrypt_in_enclave(
        &self,
        encrypted: &EncryptedWallet,
        attestation_doc: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut data_key = self
            .kms
            .decrypt_data_key(&encrypted.encrypted_data_key, attestation_doc)?;
        let opened = open_sealed_wallet(&data_key, encrypted);
        data_key.zeroize();
        opened.map(|(key, _policy)| key.to_vec())
    }
}

fn sealed_body(wallet_key: &[u8], policy_bytes: &[u8]) -> Result<Vec<u8>> {
    if wallet_key.is_empty() || wallet_key.len() > MAX_SEALED_KEY_LEN || policy_bytes.is_empty() {
        return Err(EnclaveError::Kms("Invalid sealed wallet".into()));
    }
    let len = u32::try_from(wallet_key.len())
        .map_err(|_| EnclaveError::Kms("Invalid sealed wallet".into()))?;
    let mut body = Vec::with_capacity(4 + wallet_key.len() + policy_bytes.len());
    body.extend_from_slice(&len.to_le_bytes());
    body.extend_from_slice(wallet_key);
    body.extend_from_slice(policy_bytes);
    Ok(body)
}

fn open_sealed_wallet(
    data_key: &[u8],
    encrypted: &EncryptedWallet,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let cipher = Aes256Gcm::new_from_slice(data_key)
        .map_err(|e| EnclaveError::Kms(format!("Invalid key: {e}")))?;
    let plain = cipher
        .decrypt(
            &Nonce::from(encrypted.nonce),
            Payload {
                msg: encrypted.encrypted_wallet_key.as_ref(),
                aad: &encrypted.policy_hash,
            },
        )
        .map_err(|_| EnclaveError::Kms("Decryption failed".into()))?;
    let plain = Zeroizing::new(plain);
    if plain.len() < 4 {
        return Err(EnclaveError::Kms("Decryption failed".into()));
    }
    let len = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
    if len == 0 || len > MAX_SEALED_KEY_LEN || plain.len() < 4 + len {
        return Err(EnclaveError::Kms("Decryption failed".into()));
    }
    let policy = plain[4 + len..].to_vec();
    if policy.is_empty() {
        return Err(EnclaveError::Kms("Decryption failed".into()));
    }
    let computed = policy_binding_hash(&policy);
    if !bool::from(computed.ct_eq(&encrypted.policy_hash)) {
        return Err(EnclaveError::Kms("Decryption failed".into()));
    }
    Ok((Zeroizing::new(plain[4..4 + len].to_vec()), policy))
}

pub struct MockKmsProvider {
    master_key: [u8; 32],
}

impl MockKmsProvider {
    pub fn new() -> Self {
        let mut master_key = [0u8; 32];
        getrandom::fill(&mut master_key).expect("Failed to generate master key");
        Self { master_key }
    }

    pub fn with_key(master_key: [u8; 32]) -> Self {
        Self { master_key }
    }
}

impl Default for MockKmsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KmsProvider for MockKmsProvider {
    fn generate_data_key(&self) -> Result<DataKeyResult> {
        let mut plaintext = vec![0u8; 32];
        getrandom::fill(&mut plaintext)
            .map_err(|e| EnclaveError::Kms(format!("Failed to generate data key: {e}")))?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| EnclaveError::Kms(format!("Failed to generate nonce: {e}")))?;

        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|e| EnclaveError::Kms(format!("Invalid master key: {e}")))?;

        let nonce = &Nonce::from(nonce_bytes);
        let mut ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| EnclaveError::Kms(format!("Failed to encrypt data key: {e}")))?;

        ciphertext.splice(0..0, nonce_bytes.iter().cloned());

        Ok(DataKeyResult {
            plaintext,
            ciphertext,
        })
    }

    fn decrypt_data_key(
        &self,
        encrypted_key: &[u8],
        _attestation_doc: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if encrypted_key.len() < 12 {
            return Err(EnclaveError::Kms("Invalid encrypted key".into()));
        }

        let nonce = &Nonce::try_from(&encrypted_key[..12]).expect("slice is exactly 12 bytes");
        let ciphertext = &encrypted_key[12..];

        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|e| EnclaveError::Kms(format!("Invalid master key: {e}")))?;

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| EnclaveError::Kms(format!("Failed to decrypt data key: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_encryption_roundtrip() {
        let kms = MockKmsProvider::new();
        let envelope = EnvelopeEncryption::new(kms);

        let wallet_key = b"my_secret_wallet_key_32_bytes!!!";
        let encrypted = envelope.encrypt_for_enclave(wallet_key, b"policy").unwrap();

        assert!(!encrypted.encrypted_wallet_key.is_empty());
        assert!(!encrypted.encrypted_data_key.is_empty());

        let decrypted = envelope.decrypt_in_enclave(&encrypted, None).unwrap();
        assert_eq!(decrypted, wallet_key);
    }

    #[test]
    fn test_different_master_keys_fail() {
        let kms1 = MockKmsProvider::new();
        let kms2 = MockKmsProvider::new();

        let envelope1 = EnvelopeEncryption::new(kms1);
        let envelope2 = EnvelopeEncryption::new(kms2);

        let wallet_key = b"my_secret_wallet_key_32_bytes!!!";
        let encrypted = envelope1
            .encrypt_for_enclave(wallet_key, b"policy")
            .unwrap();

        let result = envelope2.decrypt_in_enclave(&encrypted, None);
        assert!(result.is_err());
    }

    #[test]
    fn the_policy_binding_hash_is_stable() {
        let hash = policy_binding_hash(b"keep-enclave-policy-vector");
        assert_eq!(
            hex::encode(hash),
            "a334882cee0e99d085bf384f3ab99165cb0e7a211f09a2c559f5f9986b84a538"
        );
    }

    #[test]
    fn a_known_ciphertext_opens() {
        let policy_hash: [u8; 32] =
            hex::decode("bc70690ba73998f7d68b22cab7142c66cb66a17d49e04931efebc1b54160cdde")
                .unwrap()
                .try_into()
                .unwrap();
        let encrypted = EncryptedWallet {
            encrypted_data_key: Vec::new(),
            encrypted_wallet_key: hex::decode("cddb7aa5af39d9deefcec117ccb67b3b65e5ad28a89c")
                .unwrap(),
            nonce: [11u8; 12],
            policy_hash,
        };
        let (key, policy) = open_sealed_wallet(&[99u8; 32], &encrypted).unwrap();
        assert_eq!(key.as_slice(), b"k");
        assert_eq!(policy, b"p");
        assert_eq!(policy_hash, policy_binding_hash(b"p"));
    }

    #[test]
    fn the_sealed_body_is_the_key_then_the_policy() {
        let body = sealed_body(b"k", b"p").unwrap();
        assert_eq!(body, [1, 0, 0, 0, b'k', b'p']);
    }

    #[test]
    fn a_tampered_policy_hash_does_not_open() {
        let kms = MockKmsProvider::new();
        let envelope = EnvelopeEncryption::new(kms);
        let mut encrypted = envelope
            .encrypt_for_enclave(b"my_secret_wallet_key_32_bytes!!!", b"policy")
            .unwrap();
        encrypted.policy_hash[0] ^= 0xff;
        assert!(envelope.decrypt_in_enclave(&encrypted, None).is_err());
    }
}
