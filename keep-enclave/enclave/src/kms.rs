// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use crate::error::{EnclaveError, Result};
use crate::mlock::MlockedBox;
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

pub struct EnclaveKms {
    ephemeral_secret: MlockedBox<32>,
}

impl EnclaveKms {
    pub fn new(ephemeral_secret: &mut [u8; 32]) -> Self {
        Self {
            ephemeral_secret: MlockedBox::new(ephemeral_secret),
        }
    }

    pub fn ephemeral_pubkey(&self) -> Result<[u8; 32]> {
        use k256::schnorr::SigningKey;
        let sk = SigningKey::from_bytes(&*self.ephemeral_secret)
            .map_err(|e| EnclaveError::InvalidKey(format!("Invalid ephemeral secret: {}", e)))?;
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&sk.verifying_key().to_bytes());
        Ok(pubkey)
    }

    pub fn decrypt_wallet_key(
        &self,
        encrypted: &EncryptedWallet,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        let mut data_key = self.decrypt_data_key(&encrypted.encrypted_data_key)?;
        let opened = open_sealed_wallet(&data_key, encrypted);
        data_key.zeroize();
        opened
    }

    #[cfg(target_os = "linux")]
    fn decrypt_data_key(&self, encrypted_key: &[u8]) -> Result<Vec<u8>> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

        let fd = nsm_init();
        if fd < 0 {
            return self.mock_decrypt_data_key(encrypted_key);
        }

        let pubkey = self.ephemeral_pubkey()?;
        let request = Request::Attestation {
            user_data: None,
            nonce: None,
            public_key: Some(pubkey.to_vec().into()),
        };

        let response = nsm_process_request(fd, request);
        nsm_exit(fd);

        match response {
            Response::Attestation { document } => {
                self.kms_decrypt_with_attestation(encrypted_key, &document)
            }
            Response::Error(e) => Err(EnclaveError::Kms(format!("Attestation failed: {:?}", e))),
            _ => Err(EnclaveError::Kms("Unexpected NSM response".into())),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn decrypt_data_key(&self, encrypted_key: &[u8]) -> Result<Vec<u8>> {
        self.mock_decrypt_data_key(encrypted_key)
    }

    #[cfg(target_os = "linux")]
    fn kms_decrypt_with_attestation(
        &self,
        encrypted_key: &[u8],
        _attestation_doc: &[u8],
    ) -> Result<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let credentials = crate::aws_credentials::fetch_credentials()?;
        let kmstool = crate::kmstool::KmsTool::new(credentials);

        let ciphertext_b64 = STANDARD.encode(encrypted_key);
        kmstool.decrypt(&ciphertext_b64)
    }

    fn mock_decrypt_data_key(&self, encrypted_key: &[u8]) -> Result<Vec<u8>> {
        if encrypted_key.len() < 12 {
            return Err(EnclaveError::Kms("Invalid encrypted key format".into()));
        }

        let nonce = &Nonce::try_from(&encrypted_key[..12]).expect("slice is exactly 12 bytes");
        let ciphertext = &encrypted_key[12..];

        let cipher = Aes256Gcm::new_from_slice(&*self.ephemeral_secret)
            .map_err(|e| EnclaveError::Kms(format!("Invalid ephemeral key: {}", e)))?;

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| EnclaveError::Kms(format!("Data key decryption failed: {}", e)))
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
        .map_err(|e| EnclaveError::Kms(format!("Invalid data key: {}", e)))?;
    let nonce = &Nonce::from(encrypted.nonce);
    let plain = cipher
        .decrypt(
            nonce,
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

pub(crate) fn seal_wallet(
    data_key: &[u8],
    wallet_key: &[u8],
    policy_bytes: &[u8],
    nonce: [u8; 12],
) -> Result<EncryptedWallet> {
    let policy_hash = policy_binding_hash(policy_bytes);
    let body = Zeroizing::new(sealed_body(wallet_key, policy_bytes)?);
    let cipher = Aes256Gcm::new_from_slice(data_key)
        .map_err(|e| EnclaveError::Kms(format!("Invalid data key: {}", e)))?;
    let encrypted_wallet_key = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: body.as_ref(),
                aad: &policy_hash,
            },
        )
        .map_err(|_| EnclaveError::Kms("Encryption failed".into()))?;
    Ok(EncryptedWallet {
        encrypted_data_key: Vec::new(),
        encrypted_wallet_key,
        nonce,
        policy_hash,
    })
}

#[cfg(test)]
pub(crate) fn seal_for_test(
    ephemeral: &[u8; 32],
    wallet_key: &[u8],
    policy_bytes: &[u8],
) -> EncryptedWallet {
    let data_key = [99u8; 32];
    let nonce_bytes: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let cipher = Aes256Gcm::new_from_slice(ephemeral).expect("ephemeral key");
    let mut encrypted_data_key = cipher
        .encrypt(&Nonce::from(nonce_bytes), data_key.as_slice())
        .expect("data key seal");
    let mut prefixed = nonce_bytes.to_vec();
    prefixed.append(&mut encrypted_data_key);
    let mut sealed = seal_wallet(data_key.as_slice(), wallet_key, policy_bytes, [11u8; 12])
        .expect("wallet seal");
    sealed.encrypted_data_key = prefixed;
    sealed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_binding_hash_is_stable() {
        let hash = policy_binding_hash(b"keep-enclave-policy-vector");
        assert_eq!(
            hex::encode(hash),
            "a334882cee0e99d085bf384f3ab99165cb0e7a211f09a2c559f5f9986b84a538"
        );
    }

    #[test]
    fn the_sealed_body_is_the_key_then_the_policy() {
        let body = sealed_body(b"k", b"p").unwrap();
        assert_eq!(body, [1, 0, 0, 0, b'k', b'p']);
    }

    #[test]
    fn test_mock_decrypt_roundtrip() {
        let mut ephemeral_secret = [42u8; 32];
        let ephemeral_secret_copy = ephemeral_secret;
        let kms = EnclaveKms::new(&mut ephemeral_secret);
        let wallet_key = b"my_secret_wallet_key_32_bytes!!!";
        let encrypted = seal_for_test(&ephemeral_secret_copy, wallet_key, b"policy");

        let (decrypted, policy) = kms.decrypt_wallet_key(&encrypted).unwrap();
        assert_eq!(decrypted.as_slice(), wallet_key);
        assert_eq!(policy, b"policy");
    }

    #[test]
    fn a_tampered_policy_hash_does_not_open() {
        let mut ephemeral_secret = [42u8; 32];
        let ephemeral_secret_copy = ephemeral_secret;
        let kms = EnclaveKms::new(&mut ephemeral_secret);
        let mut encrypted = seal_for_test(
            &ephemeral_secret_copy,
            b"secret-key-material-32-bytes!!",
            b"policy",
        );
        encrypted.policy_hash[0] ^= 0xff;
        assert!(kms.decrypt_wallet_key(&encrypted).is_err());
    }

    #[test]
    fn test_wrong_ephemeral_key_fails() {
        let ephemeral_secret = [42u8; 32];
        let mut wrong_secret = [99u8; 32];
        let kms = EnclaveKms::new(&mut wrong_secret);
        let encrypted = seal_for_test(&ephemeral_secret, b"secret", b"policy");
        assert!(kms.decrypt_wallet_key(&encrypted).is_err());
    }
}
