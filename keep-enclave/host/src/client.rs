// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::error::{EnclaveError, Result};
use crate::protocol::{
    EnclaveRequest, EnclaveResponse, ErrorCode, NetworkParam, PolicyConfig, PsbtSigningRequest,
    SigningRequest, ENCLAVE_CID, VSOCK_PORT,
};
use tracing::{debug, warn};

const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;
const IO_TIMEOUT_SECS: u64 = 60;

pub struct EnclaveClient {
    cid: u32,
    port: u32,
}

impl EnclaveClient {
    pub fn new() -> Self {
        Self {
            cid: ENCLAVE_CID,
            port: VSOCK_PORT,
        }
    }

    pub fn with_cid(cid: u32) -> Self {
        Self {
            cid,
            port: VSOCK_PORT,
        }
    }

    #[cfg(target_os = "linux")]
    fn send_request(&self, request: &EnclaveRequest) -> Result<EnclaveResponse> {
        use std::io::{Read, Write};
        use std::time::Duration;

        let mut stream = vsock::VsockStream::connect_with_cid_port(self.cid, self.port)
            .map_err(|e| EnclaveError::Vsock(format!("Connection failed: {}", e)))?;

        stream
            .set_read_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
            .map_err(|e| EnclaveError::Vsock(format!("Set read timeout failed: {}", e)))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
            .map_err(|e| EnclaveError::Vsock(format!("Set write timeout failed: {}", e)))?;

        let request_bytes = postcard::to_allocvec(request)
            .map_err(|e| EnclaveError::Serialization(format!("Request encode failed: {}", e)))?;

        let len = request_bytes.len() as u32;
        stream
            .write_all(&len.to_le_bytes())
            .map_err(|e| EnclaveError::Vsock(format!("Write length failed: {}", e)))?;
        stream
            .write_all(&request_bytes)
            .map_err(|e| EnclaveError::Vsock(format!("Write request failed: {}", e)))?;

        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| EnclaveError::Vsock(format!("Read length failed: {}", e)))?;
        let response_len = u32::from_le_bytes(len_buf) as usize;

        if response_len == 0 || response_len > MAX_RESPONSE_SIZE {
            return Err(EnclaveError::Vsock(format!(
                "Invalid response size: {} (max: {})",
                response_len, MAX_RESPONSE_SIZE
            )));
        }

        let mut response_bytes = vec![0u8; response_len];
        stream
            .read_exact(&mut response_bytes)
            .map_err(|e| EnclaveError::Vsock(format!("Read response failed: {}", e)))?;

        let response: EnclaveResponse = postcard::from_bytes(&response_bytes)
            .map_err(|e| EnclaveError::Serialization(format!("Response decode failed: {}", e)))?;

        Ok(response)
    }

    #[cfg(not(target_os = "linux"))]
    fn send_request(&self, _request: &EnclaveRequest) -> Result<EnclaveResponse> {
        Err(EnclaveError::NotInEnclave)
    }

    pub fn get_attestation(&self, nonce: [u8; 32]) -> Result<Vec<u8>> {
        debug!("Requesting attestation from enclave");
        let request = EnclaveRequest::GetAttestation { nonce };
        let response = self.send_request(&request)?;

        match response {
            EnclaveResponse::Attestation { document } => Ok(document),
            EnclaveResponse::Error { code, message } => {
                warn!(?code, message, "Attestation request failed");
                Err(EnclaveError::Attestation(message))
            }
            _ => Err(EnclaveError::Attestation("Unexpected response".into())),
        }
    }

    pub fn generate_key(&self, name: &str) -> Result<Vec<u8>> {
        debug!(name, "Generating key in enclave");
        let request = EnclaveRequest::GenerateKey {
            name: name.to_string(),
        };
        let response = self.send_request(&request)?;

        match response {
            EnclaveResponse::PublicKey { pubkey, .. } => Ok(pubkey),
            EnclaveResponse::Error { code, message } => {
                warn!(?code, message, "Key generation failed");
                Err(EnclaveError::InvalidKey(message))
            }
            _ => Err(EnclaveError::InvalidKey("Unexpected response".into())),
        }
    }

    pub fn import_key(&self, name: &str, secret: &[u8]) -> Result<Vec<u8>> {
        debug!(name, "Importing key to enclave");
        let request = EnclaveRequest::ImportKey {
            name: name.to_string(),
            secret: secret.to_vec(),
        };
        let response = self.send_request(&request)?;

        match response {
            EnclaveResponse::PublicKey { pubkey, .. } => Ok(pubkey),
            EnclaveResponse::Error { code, message } => {
                warn!(?code, message, "Key import failed");
                Err(EnclaveError::InvalidKey(message))
            }
            _ => Err(EnclaveError::InvalidKey("Unexpected response".into())),
        }
    }

    pub fn import_encrypted_key(
        &self,
        name: &str,
        encrypted: crate::kms::EncryptedWallet,
    ) -> Result<Vec<u8>> {
        debug!(name, "Importing encrypted key to enclave");
        let request = EnclaveRequest::ImportEncryptedKey {
            name: name.to_string(),
            encrypted,
        };
        let response = self.send_request(&request)?;

        match response {
            EnclaveResponse::PublicKey { pubkey, .. } => Ok(pubkey),
            EnclaveResponse::Error { code, message } => {
                warn!(?code, message, "Encrypted key import failed");
                Err(EnclaveError::InvalidKey(message))
            }
            _ => Err(EnclaveError::InvalidKey("Unexpected response".into())),
        }
    }

    pub fn sign(&self, request: SigningRequest) -> Result<[u8; 64]> {
        debug!(key_id = %request.key_id, "Signing in enclave");
        let response = self.send_request(&EnclaveRequest::Sign(request))?;

        match response {
            EnclaveResponse::Signature { signature } => {
                if signature.len() != 64 {
                    return Err(EnclaveError::Signing("Invalid signature length".into()));
                }
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&signature);
                Ok(sig)
            }
            EnclaveResponse::Error { code, message } => match code {
                ErrorCode::PolicyDenied => Err(EnclaveError::PolicyDenied(message)),
                ErrorCode::RateLimitExceeded => Err(EnclaveError::RateLimitExceeded),
                ErrorCode::KeyNotFound => Err(EnclaveError::InvalidKey(message)),
                _ => Err(EnclaveError::Signing(message)),
            },
            _ => Err(EnclaveError::Signing("Unexpected response".into())),
        }
    }

    pub fn sign_psbt(
        &self,
        key_id: &str,
        psbt_bytes: &[u8],
        network: NetworkParam,
    ) -> Result<(Vec<u8>, usize)> {
        debug!(key_id, "Signing PSBT in enclave");
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).ok();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok();
        let request = EnclaveRequest::SignPsbt(PsbtSigningRequest {
            key_id: key_id.to_string(),
            psbt: psbt_bytes.to_vec(),
            network,
            nonce: Some(nonce),
            timestamp,
        });
        let response = self.send_request(&request)?;

        match response {
            EnclaveResponse::SignedPsbt {
                psbt,
                signed_inputs,
            } => Ok((psbt, signed_inputs)),
            EnclaveResponse::Error { code, message } => match code {
                ErrorCode::PolicyDenied => Err(EnclaveError::PolicyDenied(message)),
                ErrorCode::RateLimitExceeded => Err(EnclaveError::RateLimitExceeded),
                _ => Err(EnclaveError::Signing(message)),
            },
            _ => Err(EnclaveError::Signing("Unexpected response".into())),
        }
    }

    pub fn set_policy(&self, config: PolicyConfig) -> Result<()> {
        debug!("Setting policy in enclave");
        let request = EnclaveRequest::SetPolicy(config);
        let response = self.send_request(&request)?;

        match response {
            EnclaveResponse::PolicySet => Ok(()),
            EnclaveResponse::Error { message, .. } => Err(EnclaveError::PolicyConfig(format!(
                "Policy set failed: {}",
                message
            ))),
            _ => Err(EnclaveError::PolicyConfig("Unexpected response".into())),
        }
    }

    pub fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>> {
        debug!(key_id, "Getting public key from enclave");
        let request = EnclaveRequest::GetPublicKey {
            key_id: key_id.to_string(),
        };
        let response = self.send_request(&request)?;

        match response {
            EnclaveResponse::PublicKey { pubkey, .. } => Ok(pubkey),
            EnclaveResponse::Error { code, message } => {
                warn!(?code, message, "Get public key failed");
                Err(EnclaveError::InvalidKey(message))
            }
            _ => Err(EnclaveError::InvalidKey("Unexpected response".into())),
        }
    }

    pub fn frost_round1(&self, key_id: &str, message: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        debug!(key_id, "FROST round 1 in enclave");
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).ok();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok();
        let request = EnclaveRequest::FrostRound1 {
            key_id: key_id.to_string(),
            message: message.to_vec(),
            nonce: Some(nonce),
            timestamp,
        };
        let response = self.send_request(&request)?;

        match response {
            EnclaveResponse::FrostCommitment {
                commitment,
                nonces_id,
            } => Ok((commitment, nonces_id)),
            EnclaveResponse::Error { code, message } => {
                warn!(?code, message, "FROST round 1 failed");
                Err(EnclaveError::Signing(message))
            }
            _ => Err(EnclaveError::Signing("Unexpected response".into())),
        }
    }

    pub fn frost_add_commitment(
        &self,
        session_id: [u8; 32],
        identifier: &[u8],
        commitment: &[u8],
    ) -> Result<()> {
        debug!("Adding FROST commitment");
        let request = EnclaveRequest::FrostAddCommitment {
            session_id,
            identifier: identifier.to_vec(),
            commitment: commitment.to_vec(),
        };
        let response = self.send_request(&request)?;

        match response {
            EnclaveResponse::PolicySet => Ok(()),
            EnclaveResponse::Error { code, message } => {
                warn!(?code, message, "FROST add commitment failed");
                Err(EnclaveError::Signing(message))
            }
            _ => Err(EnclaveError::Signing("Unexpected response".into())),
        }
    }

    pub fn frost_round2(&self, session_id: [u8; 32]) -> Result<Vec<u8>> {
        debug!("FROST round 2 in enclave");
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).ok();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok();
        let request = EnclaveRequest::FrostRound2 {
            session_id,
            nonce: Some(nonce),
            timestamp,
        };
        let response = self.send_request(&request)?;

        match response {
            EnclaveResponse::FrostShare { share } => Ok(share),
            EnclaveResponse::Error { code, message } => {
                warn!(?code, message, "FROST round 2 failed");
                Err(EnclaveError::Signing(message))
            }
            _ => Err(EnclaveError::Signing("Unexpected response".into())),
        }
    }

    pub fn import_frost_key(
        &self,
        name: &str,
        key_package: &[u8],
        pubkey_package: &[u8],
    ) -> Result<Vec<u8>> {
        debug!(name, "Importing FROST key to enclave");
        let request = EnclaveRequest::ImportFrostKey {
            name: name.to_string(),
            key_package: key_package.to_vec(),
            pubkey_package: pubkey_package.to_vec(),
        };
        let response = self.send_request(&request)?;

        match response {
            EnclaveResponse::PublicKey { pubkey, .. } => Ok(pubkey),
            EnclaveResponse::Error { code, message } => {
                warn!(?code, message, "Import FROST key failed");
                Err(EnclaveError::Signing(message))
            }
            _ => Err(EnclaveError::Signing("Unexpected response".into())),
        }
    }
}

impl Default for EnclaveClient {
    fn default() -> Self {
        Self::new()
    }
}
