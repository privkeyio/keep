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
const WARDEN_BINDING_DOMAIN: &[u8] = b"keep-enclave-policy-v2";
const POLICY_UPDATE_DOMAIN: &[u8] = b"keep-enclave-policy-update-v1";
const MAX_SEALED_KEY_LEN: usize = 4096;
const WARDEN_LEN: usize = 32 + 8;

/// The key allowed to sign a new policy for a sealed key, and how many times it
/// has. A key sealed without one keeps its policy for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Warden {
    /// BIP340 x-only public key.
    pub pubkey: [u8; 32],
    pub epoch: u64,
}

/// The hash a sealed blob is bound to: the policy alone, or with a warden the
/// warden's key, its epoch and the policy, under another domain so neither
/// can pass for the other.
pub fn sealed_policy_hash(warden: Option<&Warden>, policy_bytes: &[u8]) -> [u8; 32] {
    match warden {
        None => policy_binding_hash(policy_bytes),
        Some(warden) => {
            let mut hasher = Sha256::new();
            hasher.update(WARDEN_BINDING_DOMAIN);
            hasher.update(warden.pubkey);
            hasher.update(warden.epoch.to_le_bytes());
            hasher.update(policy_bytes);
            hasher.finalize().into()
        }
    }
}

/// What the warden signs, with BIP340 over these 32 bytes, to move the blob
/// `old` to `new_policy_hash`, the `sealed_policy_hash` of the new policy at
/// the next epoch. The hash of the whole blob names that one blob, so the
/// signature moves no other.
pub fn policy_update_message(old: &EncryptedWallet, new_policy_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_UPDATE_DOMAIN);
    let mut blob = Sha256::new();
    blob.update((old.encrypted_data_key.len() as u64).to_le_bytes());
    blob.update(&old.encrypted_data_key);
    blob.update(old.nonce);
    blob.update(old.policy_hash);
    blob.update(&old.encrypted_wallet_key);
    hasher.update(blob.finalize());
    hasher.update(new_policy_hash);
    hasher.finalize().into()
}

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
        self.seal(wallet_key, None, policy_bytes)
    }

    /// Seal like `encrypt_for_enclave`, naming `warden_pubkey` as the key that
    /// may sign a new policy for this blob through `UpdateSealedPolicy`,
    /// starting at epoch 0.
    pub fn encrypt_for_enclave_with_warden(
        &self,
        wallet_key: &[u8],
        policy_bytes: &[u8],
        warden_pubkey: [u8; 32],
    ) -> Result<EncryptedWallet> {
        let warden = Warden {
            pubkey: warden_pubkey,
            epoch: 0,
        };
        self.seal(wallet_key, Some(&warden), policy_bytes)
    }

    fn seal(
        &self,
        wallet_key: &[u8],
        warden: Option<&Warden>,
        policy_bytes: &[u8],
    ) -> Result<EncryptedWallet> {
        let policy_hash = sealed_policy_hash(warden, policy_bytes);
        let body = Zeroizing::new(sealed_body(wallet_key, warden, policy_bytes)?);
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
        opened.map(|(key, _policy, _warden)| key.to_vec())
    }
}

fn sealed_body(wallet_key: &[u8], warden: Option<&Warden>, policy_bytes: &[u8]) -> Result<Vec<u8>> {
    if wallet_key.is_empty() || wallet_key.len() > MAX_SEALED_KEY_LEN || policy_bytes.is_empty() {
        return Err(EnclaveError::Kms("Invalid sealed wallet".into()));
    }
    let len = u32::try_from(wallet_key.len())
        .map_err(|_| EnclaveError::Kms("Invalid sealed wallet".into()))?;
    let mut body = Vec::with_capacity(4 + wallet_key.len() + WARDEN_LEN + policy_bytes.len());
    body.extend_from_slice(&len.to_le_bytes());
    body.extend_from_slice(wallet_key);
    if let Some(warden) = warden {
        body.extend_from_slice(&warden.pubkey);
        body.extend_from_slice(&warden.epoch.to_le_bytes());
    }
    body.extend_from_slice(policy_bytes);
    Ok(body)
}

type Opened = (Zeroizing<Vec<u8>>, Vec<u8>, Option<Warden>);

fn open_sealed_wallet(data_key: &[u8], encrypted: &EncryptedWallet) -> Result<Opened> {
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
    let rest = &plain[4 + len..];
    let bound = |warden: Option<&Warden>, policy: &[u8]| {
        !policy.is_empty()
            && bool::from(sealed_policy_hash(warden, policy).ct_eq(&encrypted.policy_hash))
    };
    let (warden, policy) = if bound(None, rest) {
        (None, rest)
    } else if rest.len() > WARDEN_LEN {
        let (head, policy) = rest.split_at(WARDEN_LEN);
        let warden = Warden {
            pubkey: head[..32].try_into().expect("32 bytes"),
            epoch: u64::from_le_bytes(head[32..].try_into().expect("8 bytes")),
        };
        if !bound(Some(&warden), policy) {
            return Err(EnclaveError::Kms("Decryption failed".into()));
        }
        (Some(warden), policy)
    } else {
        return Err(EnclaveError::Kms("Decryption failed".into()));
    };
    Ok((
        Zeroizing::new(plain[4..4 + len].to_vec()),
        policy.to_vec(),
        warden,
    ))
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
    fn the_warden_hashes_match_the_other_side() {
        let warden = Warden {
            pubkey: [1u8; 32],
            epoch: u64::MAX - 7,
        };
        let hash = sealed_policy_hash(Some(&warden), b"policy");
        let old = EncryptedWallet {
            encrypted_data_key: vec![2],
            encrypted_wallet_key: vec![3, 4],
            nonce: [5u8; 12],
            policy_hash: [6u8; 32],
        };
        let message = policy_update_message(&old, &hash);
        assert_eq!(
            format!("{}{}", hex::encode(hash), hex::encode(message)),
            "6d7bb60fecc9191f94832db9a65e05dfed71ab157b08c744d427d898fd1307790333fbbe2fba890ed303a51f568b2939fb23e9c457ab4b2e7702a9ed4e48b0c1"
        );
    }

    #[test]
    fn a_key_sealed_with_a_warden_binds_the_warden_and_epoch_zero() {
        let envelope = EnvelopeEncryption::new(MockKmsProvider::new());
        let encrypted = envelope
            .encrypt_for_enclave_with_warden(b"key", b"policy", [7u8; 32])
            .unwrap();
        let warden = Warden {
            pubkey: [7u8; 32],
            epoch: 0,
        };
        assert_eq!(
            encrypted.policy_hash,
            sealed_policy_hash(Some(&warden), b"policy")
        );
        assert_eq!(
            envelope.decrypt_in_enclave(&encrypted, None).unwrap(),
            b"key"
        );
    }

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
        let (key, policy, _) = open_sealed_wallet(&[99u8; 32], &encrypted).unwrap();
        assert_eq!(key.as_slice(), b"k");
        assert_eq!(policy, b"p");
        assert_eq!(policy_hash, policy_binding_hash(b"p"));
    }

    #[test]
    fn the_sealed_body_is_the_key_then_the_policy() {
        let body = sealed_body(b"k", None, b"p").unwrap();
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
