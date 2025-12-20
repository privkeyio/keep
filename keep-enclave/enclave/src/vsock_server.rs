#![forbid(unsafe_code)]

use crate::error::{EnclaveError, Result};
use crate::kms::{EncryptedWallet, EnclaveKms};
use crate::policy::{PolicyConfig, PolicyDecision, PolicyEngine, SigningContext};
use crate::signer::{EnclaveSigner, PsbtData};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const VSOCK_PORT: u32 = 5000;
const MAX_REQUEST_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnclaveRequest {
    GetAttestation { nonce: [u8; 32] },
    GenerateKey { name: String },
    ImportKey { name: String, secret: Vec<u8> },
    ImportEncryptedKey { name: String, encrypted: EncryptedWallet },
    Sign(SigningRequest),
    SignPsbt(PsbtSigningRequest),
    SetPolicy(PolicyConfig),
    GetPublicKey { key_id: String },
    FrostRound1 { key_id: String, message: Vec<u8> },
    FrostRound2 { commitments: Vec<u8>, message: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningRequest {
    pub key_id: String,
    pub message: Vec<u8>,
    pub event_kind: Option<u32>,
    pub amount_sats: Option<u64>,
    pub destination: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtSigningRequest {
    pub key_id: String,
    pub psbt: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnclaveResponse {
    Attestation { document: Vec<u8> },
    PublicKey { pubkey: Vec<u8>, name: String },
    Signature { signature: Vec<u8> },
    SignedPsbt { psbt: Vec<u8>, signed_inputs: usize },
    PolicySet,
    FrostCommitment { commitment: Vec<u8>, nonces_id: Vec<u8> },
    FrostShare { share: Vec<u8> },
    Error { code: ErrorCode, message: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ErrorCode {
    InvalidRequest,
    PolicyDenied,
    RateLimitExceeded,
    KeyNotFound,
    SigningFailed,
    InternalError,
}

pub struct VsockServer {
    signer: EnclaveSigner,
    policy_engine: PolicyEngine,
    kms: EnclaveKms,
}

impl VsockServer {
    pub fn new() -> Result<Self> {
        let signer = EnclaveSigner::new()?;
        let ephemeral_secret = signer.ephemeral_secret();
        Ok(Self {
            signer,
            policy_engine: PolicyEngine::new(),
            kms: EnclaveKms::new(ephemeral_secret),
        })
    }

    #[cfg(target_os = "linux")]
    pub fn run(&mut self) -> Result<()> {
        use std::io::{Read, Write};
        use vsock::VsockListener;

        let listener = VsockListener::bind_with_cid_port(vsock::VMADDR_CID_ANY, VSOCK_PORT)
            .map_err(|e| EnclaveError::Vsock(format!("Bind failed: {}", e)))?;

        for stream in listener.incoming() {
            let mut stream = stream.map_err(|e| EnclaveError::Vsock(format!("Accept failed: {}", e)))?;

            let mut len_buf = [0u8; 4];
            if stream.read_exact(&mut len_buf).is_err() {
                continue;
            }
            let request_len = u32::from_le_bytes(len_buf) as usize;

            if request_len == 0 || request_len > MAX_REQUEST_SIZE {
                let response = EnclaveResponse::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("Invalid request size: {} (max: {})", request_len, MAX_REQUEST_SIZE),
                };
                if let Ok(response_bytes) = postcard::to_allocvec(&response) {
                    let len = response_bytes.len() as u32;
                    let _ = stream.write_all(&len.to_le_bytes());
                    let _ = stream.write_all(&response_bytes);
                }
                continue;
            }

            let mut request_bytes = vec![0u8; request_len];
            if stream.read_exact(&mut request_bytes).is_err() {
                continue;
            }

            let response = match postcard::from_bytes::<EnclaveRequest>(&request_bytes) {
                Ok(request) => self.handle_request(request),
                Err(e) => EnclaveResponse::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("Decode failed: {}", e),
                },
            };

            let response_bytes = match postcard::to_allocvec(&response) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let len = response_bytes.len() as u32;
            let _ = stream.write_all(&len.to_le_bytes());
            let _ = stream.write_all(&response_bytes);
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn run(&mut self) -> Result<()> {
        Err(EnclaveError::Vsock("Not in enclave environment".into()))
    }

    fn handle_request(&mut self, request: EnclaveRequest) -> EnclaveResponse {
        match request {
            EnclaveRequest::GetAttestation { nonce } => self.handle_attestation(nonce),
            EnclaveRequest::GenerateKey { name } => self.handle_generate_key(&name),
            EnclaveRequest::ImportKey { name, secret } => self.handle_import_key(&name, &secret),
            EnclaveRequest::ImportEncryptedKey { name, encrypted } => {
                self.handle_import_encrypted_key(&name, &encrypted)
            }
            EnclaveRequest::Sign(req) => self.handle_sign(req),
            EnclaveRequest::SignPsbt(req) => self.handle_sign_psbt(req),
            EnclaveRequest::SetPolicy(config) => self.handle_set_policy(config),
            EnclaveRequest::GetPublicKey { key_id } => self.handle_get_public_key(&key_id),
            EnclaveRequest::FrostRound1 { key_id, message } => {
                self.handle_frost_round1(&key_id, &message)
            }
            EnclaveRequest::FrostRound2 {
                commitments,
                message,
            } => self.handle_frost_round2(&commitments, &message),
        }
    }

    #[cfg(target_os = "linux")]
    fn handle_attestation(&self, nonce: [u8; 32]) -> EnclaveResponse {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

        let ephemeral_pubkey = match self.signer.get_ephemeral_pubkey() {
            Ok(pk) => pk,
            Err(e) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InternalError,
                    message: format!("Failed to get ephemeral pubkey: {}", e),
                };
            }
        };

        let fd = nsm_init();
        if fd < 0 {
            return EnclaveResponse::Error {
                code: ErrorCode::InternalError,
                message: "Failed to initialize NSM".into(),
            };
        }

        let request = Request::Attestation {
            user_data: None,
            nonce: Some(nonce.to_vec().into()),
            public_key: Some(ephemeral_pubkey.to_vec().into()),
        };

        let response = nsm_process_request(fd, request);
        nsm_exit(fd);

        match response {
            Response::Attestation { document } => EnclaveResponse::Attestation { document },
            Response::Error(e) => EnclaveResponse::Error {
                code: ErrorCode::InternalError,
                message: format!("NSM attestation failed: {:?}", e),
            },
            _ => EnclaveResponse::Error {
                code: ErrorCode::InternalError,
                message: "Unexpected NSM response".into(),
            },
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn handle_attestation(&self, _nonce: [u8; 32]) -> EnclaveResponse {
        EnclaveResponse::Error {
            code: ErrorCode::InternalError,
            message: "Attestation not available outside enclave".into(),
        }
    }

    fn handle_generate_key(&mut self, name: &str) -> EnclaveResponse {
        match self.signer.generate_key(name) {
            Ok(pubkey) => EnclaveResponse::PublicKey {
                pubkey: pubkey.to_vec(),
                name: name.to_string(),
            },
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::InternalError,
                message: e.to_string(),
            },
        }
    }

    fn handle_import_key(&mut self, name: &str, secret: &[u8]) -> EnclaveResponse {
        match self.signer.import_key(name, secret) {
            Ok(pubkey) => EnclaveResponse::PublicKey {
                pubkey: pubkey.to_vec(),
                name: name.to_string(),
            },
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                message: e.to_string(),
            },
        }
    }

    fn handle_import_encrypted_key(
        &mut self,
        name: &str,
        encrypted: &EncryptedWallet,
    ) -> EnclaveResponse {
        let secret = match self.kms.decrypt_wallet_key(encrypted) {
            Ok(s) => s,
            Err(e) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("KMS decryption failed: {}", e),
                };
            }
        };

        match self.signer.import_key(name, &secret) {
            Ok(pubkey) => EnclaveResponse::PublicKey {
                pubkey: pubkey.to_vec(),
                name: name.to_string(),
            },
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                message: e.to_string(),
            },
        }
    }

    fn handle_sign(&mut self, req: SigningRequest) -> EnclaveResponse {
        let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InternalError,
                    message: "System clock error".into(),
                };
            }
        };

        let ctx = SigningContext {
            key_id: &req.key_id,
            amount_sats: req.amount_sats,
            destination: req.destination.as_deref(),
            event_kind: req.event_kind,
            timestamp,
        };

        match self.policy_engine.evaluate(&ctx) {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny(reason) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::PolicyDenied,
                    message: reason.to_string(),
                };
            }
            PolicyDecision::RequireApproval => {
                return EnclaveResponse::Error {
                    code: ErrorCode::PolicyDenied,
                    message: "Requires approval".into(),
                };
            }
        }

        match self.signer.sign(&req.key_id, &req.message) {
            Ok(signature) => {
                self.policy_engine.record_operation(&req.key_id);
                EnclaveResponse::Signature { signature: signature.to_vec() }
            }
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::SigningFailed,
                message: e.to_string(),
            },
        }
    }

    fn handle_sign_psbt(&mut self, req: PsbtSigningRequest) -> EnclaveResponse {
        let psbt_data: PsbtData = match postcard::from_bytes(&req.psbt) {
            Ok(p) => p,
            Err(e) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("Invalid PSBT: {}", e),
                };
            }
        };

        let total_spend: u64 = psbt_data
            .outputs
            .iter()
            .filter(|o| !o.is_change)
            .map(|o| o.amount_sats)
            .sum();

        let first_destination = psbt_data
            .outputs
            .iter()
            .filter(|o| !o.is_change)
            .find_map(|o| o.address.clone());

        let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InternalError,
                    message: "System clock error".into(),
                };
            }
        };

        let ctx = SigningContext {
            key_id: &req.key_id,
            amount_sats: Some(total_spend),
            destination: first_destination.as_deref(),
            event_kind: None,
            timestamp,
        };

        match self.policy_engine.evaluate(&ctx) {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny(reason) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::PolicyDenied,
                    message: reason.to_string(),
                };
            }
            PolicyDecision::RequireApproval => {
                return EnclaveResponse::Error {
                    code: ErrorCode::PolicyDenied,
                    message: "Requires approval".into(),
                };
            }
        }

        match self.signer.sign_psbt(&req.key_id, &req.psbt) {
            Ok((signed_psbt, signed_inputs)) => {
                self.policy_engine.record_operation(&req.key_id);
                EnclaveResponse::SignedPsbt {
                    psbt: signed_psbt,
                    signed_inputs,
                }
            }
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::SigningFailed,
                message: e.to_string(),
            },
        }
    }

    fn handle_set_policy(&mut self, config: PolicyConfig) -> EnclaveResponse {
        self.policy_engine.set_policies(config);
        EnclaveResponse::PolicySet
    }

    fn handle_get_public_key(&self, key_id: &str) -> EnclaveResponse {
        match self.signer.get_public_key(key_id) {
            Ok(pubkey) => EnclaveResponse::PublicKey {
                pubkey: pubkey.to_vec(),
                name: key_id.to_string(),
            },
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::KeyNotFound,
                message: e.to_string(),
            },
        }
    }

    fn handle_frost_round1(&mut self, key_id: &str, message: &[u8]) -> EnclaveResponse {
        match self.signer.frost_round1(key_id, message) {
            Ok((commitment, nonces_id)) => EnclaveResponse::FrostCommitment {
                commitment,
                nonces_id: nonces_id.to_vec(),
            },
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::SigningFailed,
                message: e.to_string(),
            },
        }
    }

    fn handle_frost_round2(&mut self, commitments: &[u8], message: &[u8]) -> EnclaveResponse {
        match self.signer.frost_round2(commitments, message) {
            Ok(share) => EnclaveResponse::FrostShare { share },
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::SigningFailed,
                message: e.to_string(),
            },
        }
    }
}
