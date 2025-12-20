#![forbid(unsafe_code)]

use crate::error::{EnclaveError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    pub encrypted_data_key: Vec<u8>,
    pub encrypted_wallet_key: Vec<u8>,
    pub nonce: [u8; 12],
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EnclaveKms {
    ephemeral_secret: [u8; 32],
}

impl EnclaveKms {
    pub fn new(ephemeral_secret: [u8; 32]) -> Self {
        Self { ephemeral_secret }
    }

    pub fn ephemeral_pubkey(&self) -> [u8; 32] {
        use k256::schnorr::SigningKey;
        if let Ok(sk) = SigningKey::from_bytes(&self.ephemeral_secret) {
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&sk.verifying_key().to_bytes());
            pubkey
        } else {
            [0u8; 32]
        }
    }

    pub fn decrypt_wallet_key(&self, encrypted: &EncryptedWallet) -> Result<Vec<u8>> {
        let mut data_key = self.decrypt_data_key(&encrypted.encrypted_data_key)?;

        let cipher = ChaCha20Poly1305::new_from_slice(&data_key)
            .map_err(|e| EnclaveError::Kms(format!("Invalid data key: {}", e)))?;

        let nonce = Nonce::from_slice(&encrypted.nonce);
        let wallet_key = cipher
            .decrypt(nonce, encrypted.encrypted_wallet_key.as_ref())
            .map_err(|e| EnclaveError::Kms(format!("Decryption failed: {}", e)))?;

        data_key.zeroize();

        Ok(wallet_key)
    }

    #[cfg(target_os = "linux")]
    fn decrypt_data_key(&self, encrypted_key: &[u8]) -> Result<Vec<u8>> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

        let fd = nsm_init();
        if fd < 0 {
            return Err(EnclaveError::Kms("Failed to initialize NSM".into()));
        }

        let pubkey = self.ephemeral_pubkey();
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
        _encrypted_key: &[u8],
        _attestation_doc: &[u8],
    ) -> Result<Vec<u8>> {
        Err(EnclaveError::Kms(
            "Real KMS integration requires vsock proxy to parent".into(),
        ))
    }

    fn mock_decrypt_data_key(&self, encrypted_key: &[u8]) -> Result<Vec<u8>> {
        if encrypted_key.len() < 12 {
            return Err(EnclaveError::Kms("Invalid encrypted key format".into()));
        }

        let nonce = Nonce::from_slice(&encrypted_key[..12]);
        let ciphertext = &encrypted_key[12..];

        let cipher = ChaCha20Poly1305::new_from_slice(&self.ephemeral_secret)
            .map_err(|e| EnclaveError::Kms(format!("Invalid ephemeral key: {}", e)))?;

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| EnclaveError::Kms(format!("Data key decryption failed: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::KeyInit;

    fn encrypt_data_key(master_key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let nonce_bytes: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let cipher = ChaCha20Poly1305::new_from_slice(master_key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ciphertext = cipher.encrypt(nonce, plaintext).unwrap();
        let mut result = nonce_bytes.to_vec();
        result.append(&mut ciphertext);
        result
    }

    fn encrypt_wallet_key(data_key: &[u8], wallet_key: &[u8], nonce: &[u8; 12]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(data_key).unwrap();
        let n = Nonce::from_slice(nonce);
        cipher.encrypt(n, wallet_key).unwrap()
    }

    #[test]
    fn test_mock_decrypt_roundtrip() {
        let ephemeral_secret = [42u8; 32];
        let kms = EnclaveKms::new(ephemeral_secret);

        let data_key = [99u8; 32];
        let wallet_key = b"my_secret_wallet_key_32_bytes!!!";
        let nonce: [u8; 12] = [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22];

        let encrypted_data_key = encrypt_data_key(&ephemeral_secret, &data_key);
        let encrypted_wallet_key = encrypt_wallet_key(&data_key, wallet_key, &nonce);

        let encrypted = EncryptedWallet {
            encrypted_data_key,
            encrypted_wallet_key,
            nonce,
        };

        let decrypted = kms.decrypt_wallet_key(&encrypted).unwrap();
        assert_eq!(decrypted, wallet_key);
    }

    #[test]
    fn test_wrong_ephemeral_key_fails() {
        let ephemeral_secret = [42u8; 32];
        let wrong_secret = [99u8; 32];
        let kms = EnclaveKms::new(wrong_secret);

        let data_key = [88u8; 32];
        let wallet_key = b"secret";
        let nonce: [u8; 12] = [1; 12];

        let encrypted_data_key = encrypt_data_key(&ephemeral_secret, &data_key);
        let encrypted_wallet_key = encrypt_wallet_key(&data_key, wallet_key, &nonce);

        let encrypted = EncryptedWallet {
            encrypted_data_key,
            encrypted_wallet_key,
            nonce,
        };

        let result = kms.decrypt_wallet_key(&encrypted);
        assert!(result.is_err());
    }
}
