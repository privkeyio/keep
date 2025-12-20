use crate::error::{EnclaveError, Result};
use crate::protocol::{
    EnclaveRequest, EnclaveResponse, ErrorCode, PolicyConfig, PsbtSigningRequest, SigningRequest,
    ENCLAVE_CID, VSOCK_PORT,
};
use tracing::{debug, warn};

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

        let mut stream = vsock::VsockStream::connect_with_cid_port(self.cid, self.port)
            .map_err(|e| EnclaveError::Vsock(format!("Connection failed: {}", e)))?;

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

    pub fn generate_key(&self, name: &str) -> Result<[u8; 32]> {
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

    pub fn import_key(&self, name: &str, secret: &[u8]) -> Result<[u8; 32]> {
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

    pub fn sign_psbt(&self, key_id: &str, psbt: &[u8]) -> Result<(Vec<u8>, usize)> {
        debug!(key_id, "Signing PSBT in enclave");
        let request = EnclaveRequest::SignPsbt(PsbtSigningRequest {
            key_id: key_id.to_string(),
            psbt: psbt.to_vec(),
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
            EnclaveResponse::Error { message, .. } => {
                Err(EnclaveError::Attestation(format!("Policy set failed: {}", message)))
            }
            _ => Err(EnclaveError::Attestation("Unexpected response".into())),
        }
    }

    pub fn get_public_key(&self, key_id: &str) -> Result<[u8; 32]> {
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

    pub fn frost_round1(&self, key_id: &str, message: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        debug!(key_id, "FROST round 1 in enclave");
        let request = EnclaveRequest::FrostRound1 {
            key_id: key_id.to_string(),
            message: message.to_vec(),
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

    pub fn frost_round2(&self, commitments: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        debug!("FROST round 2 in enclave");
        let request = EnclaveRequest::FrostRound2 {
            commitments: commitments.to_vec(),
            message: message.to_vec(),
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
}

impl Default for EnclaveClient {
    fn default() -> Self {
        Self::new()
    }
}
