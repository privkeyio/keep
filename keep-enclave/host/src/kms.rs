// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::error::{EnclaveError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    pub encrypted_data_key: Vec<u8>,
    pub encrypted_wallet_key: Vec<u8>,
    pub nonce: [u8; 12],
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

    pub fn encrypt_for_enclave(&self, wallet_key: &[u8]) -> Result<EncryptedWallet> {
        let data_key_result = self.kms.generate_data_key()?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| EnclaveError::Kms(format!("Failed to generate nonce: {e}")))?;

        let cipher = Aes256Gcm::new_from_slice(&data_key_result.plaintext)
            .map_err(|e| EnclaveError::Kms(format!("Invalid key: {e}")))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted_wallet_key = cipher
            .encrypt(nonce, wallet_key)
            .map_err(|e| EnclaveError::Kms(format!("Encryption failed: {e}")))?;

        let mut plaintext = data_key_result.plaintext;
        plaintext.zeroize();

        Ok(EncryptedWallet {
            encrypted_data_key: data_key_result.ciphertext,
            encrypted_wallet_key,
            nonce: nonce_bytes,
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

        let cipher = Aes256Gcm::new_from_slice(&data_key)
            .map_err(|e| EnclaveError::Kms(format!("Invalid key: {e}")))?;

        let nonce = Nonce::from_slice(&encrypted.nonce);
        let wallet_key = cipher
            .decrypt(nonce, encrypted.encrypted_wallet_key.as_ref())
            .map_err(|e| EnclaveError::Kms(format!("Decryption failed: {e}")))?;

        data_key.zeroize();

        Ok(wallet_key)
    }
}

pub struct MockKmsProvider {
    master_key: [u8; 32],
}

impl MockKmsProvider {
    pub fn new() -> Self {
        let mut master_key = [0u8; 32];
        getrandom::getrandom(&mut master_key).expect("Failed to generate master key");
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
        getrandom::getrandom(&mut plaintext)
            .map_err(|e| EnclaveError::Kms(format!("Failed to generate data key: {e}")))?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| EnclaveError::Kms(format!("Failed to generate nonce: {e}")))?;

        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|e| EnclaveError::Kms(format!("Invalid master key: {e}")))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
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

        let nonce = Nonce::from_slice(&encrypted_key[..12]);
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
        let encrypted = envelope.encrypt_for_enclave(wallet_key).unwrap();

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
        let encrypted = envelope1.encrypt_for_enclave(wallet_key).unwrap();

        let result = envelope2.decrypt_in_enclave(&encrypted, None);
        assert!(result.is_err());
    }
}
