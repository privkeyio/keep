// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::error::Result;
use crate::protocol::{NetworkParam, PolicyConfig, SigningRequest};

pub trait SignerBackend: Send + Sync {
    fn generate_key(&self, name: &str) -> Result<Vec<u8>>;
    fn import_key(&self, name: &str, secret: &[u8]) -> Result<Vec<u8>>;
    fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>>;
    fn sign(&self, request: SigningRequest) -> Result<[u8; 64]>;
    fn sign_psbt(
        &self,
        key_id: &str,
        psbt_bytes: &[u8],
        network: NetworkParam,
    ) -> Result<(Vec<u8>, usize)>;
    fn set_policy(&self, config: PolicyConfig) -> Result<()>;
}

impl SignerBackend for crate::EnclaveClient {
    fn generate_key(&self, name: &str) -> Result<Vec<u8>> {
        crate::EnclaveClient::generate_key(self, name)
    }

    fn import_key(&self, name: &str, secret: &[u8]) -> Result<Vec<u8>> {
        crate::EnclaveClient::import_key(self, name, secret)
    }

    fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>> {
        crate::EnclaveClient::get_public_key(self, key_id)
    }

    fn sign(&self, request: SigningRequest) -> Result<[u8; 64]> {
        crate::EnclaveClient::sign(self, request)
    }

    fn sign_psbt(
        &self,
        key_id: &str,
        psbt_bytes: &[u8],
        network: NetworkParam,
    ) -> Result<(Vec<u8>, usize)> {
        crate::EnclaveClient::sign_psbt(self, key_id, psbt_bytes, network)
    }

    fn set_policy(&self, config: PolicyConfig) -> Result<()> {
        crate::EnclaveClient::set_policy(self, config)
    }
}

impl SignerBackend for crate::MockEnclaveClient {
    fn generate_key(&self, name: &str) -> Result<Vec<u8>> {
        use crate::protocol::{EnclaveRequest, EnclaveResponse};
        match self.process_request(EnclaveRequest::GenerateKey {
            name: name.to_string(),
        }) {
            EnclaveResponse::PublicKey { pubkey, .. } => Ok(pubkey),
            EnclaveResponse::Error { message, .. } => Err(crate::EnclaveError::InvalidKey(message)),
            _ => Err(crate::EnclaveError::InvalidKey(
                "Unexpected response".into(),
            )),
        }
    }

    fn import_key(&self, name: &str, secret: &[u8]) -> Result<Vec<u8>> {
        use crate::protocol::{EnclaveRequest, EnclaveResponse};
        match self.process_request(EnclaveRequest::ImportKey {
            name: name.to_string(),
            secret: secret.to_vec(),
        }) {
            EnclaveResponse::PublicKey { pubkey, .. } => Ok(pubkey),
            EnclaveResponse::Error { message, .. } => Err(crate::EnclaveError::InvalidKey(message)),
            _ => Err(crate::EnclaveError::InvalidKey(
                "Unexpected response".into(),
            )),
        }
    }

    fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>> {
        use crate::protocol::{EnclaveRequest, EnclaveResponse};
        match self.process_request(EnclaveRequest::GetPublicKey {
            key_id: key_id.to_string(),
        }) {
            EnclaveResponse::PublicKey { pubkey, .. } => Ok(pubkey),
            EnclaveResponse::Error { message, .. } => Err(crate::EnclaveError::InvalidKey(message)),
            _ => Err(crate::EnclaveError::InvalidKey(
                "Unexpected response".into(),
            )),
        }
    }

    fn sign(&self, request: SigningRequest) -> Result<[u8; 64]> {
        use crate::protocol::{EnclaveRequest, EnclaveResponse};
        match self.process_request(EnclaveRequest::Sign(request)) {
            EnclaveResponse::Signature { signature } => {
                if signature.len() != 64 {
                    return Err(crate::EnclaveError::Signing(
                        "Invalid signature length".into(),
                    ));
                }
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&signature);
                Ok(sig)
            }
            EnclaveResponse::Error { message, .. } => Err(crate::EnclaveError::Signing(message)),
            _ => Err(crate::EnclaveError::Signing("Unexpected response".into())),
        }
    }

    fn sign_psbt(
        &self,
        key_id: &str,
        psbt_bytes: &[u8],
        network: NetworkParam,
    ) -> Result<(Vec<u8>, usize)> {
        use crate::protocol::{EnclaveRequest, EnclaveResponse, PsbtSigningRequest};
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).ok();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok();
        match self.process_request(EnclaveRequest::SignPsbt(PsbtSigningRequest {
            key_id: key_id.to_string(),
            psbt: psbt_bytes.to_vec(),
            network,
            nonce: Some(nonce),
            timestamp,
        })) {
            EnclaveResponse::SignedPsbt {
                psbt,
                signed_inputs,
            } => Ok((psbt, signed_inputs)),
            EnclaveResponse::Error { message, .. } => Err(crate::EnclaveError::Signing(message)),
            _ => Err(crate::EnclaveError::Signing("Unexpected response".into())),
        }
    }

    fn set_policy(&self, config: PolicyConfig) -> Result<()> {
        use crate::protocol::{EnclaveRequest, EnclaveResponse};
        match self.process_request(EnclaveRequest::SetPolicy(config)) {
            EnclaveResponse::PolicySet => Ok(()),
            EnclaveResponse::Error { message, .. } => {
                Err(crate::EnclaveError::PolicyConfig(message))
            }
            _ => Err(crate::EnclaveError::PolicyConfig(
                "Unexpected response".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockEnclaveClient;
    use tempfile::tempdir;

    #[test]
    fn test_backend_generate_and_sign() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.redb");
        let backend: Box<dyn SignerBackend> = Box::new(MockEnclaveClient::with_path(&path));

        let pubkey = backend.generate_key("test").unwrap();
        assert_eq!(pubkey.len(), 32);

        let request = SigningRequest {
            key_id: "test".to_string(),
            message: b"hello".to_vec(),
            event_kind: None,
            amount_sats: None,
            destination: None,
            nonce: None,
            timestamp: None,
        };
        let sig = backend.sign(request).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_backend_trait_object() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.redb");
        let backend: &dyn SignerBackend = &MockEnclaveClient::with_path(&path);

        let pubkey = backend.generate_key("key1").unwrap();
        assert_eq!(pubkey.len(), 32);

        let retrieved = backend.get_public_key("key1").unwrap();
        assert_eq!(pubkey, retrieved);
    }
}
