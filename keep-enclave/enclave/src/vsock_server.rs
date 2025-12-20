use crate::error::{EnclaveError, Result};
use crate::policy::{PolicyConfig, PolicyDecision, PolicyEngine, SigningContext};
use crate::signer::EnclaveSigner;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const VSOCK_PORT: u32 = 5000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnclaveRequest {
    GetAttestation { nonce: [u8; 32] },
    GenerateKey { name: String },
    ImportKey { name: String, secret: Vec<u8> },
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
    PublicKey { pubkey: [u8; 32], name: String },
    Signature { signature: [u8; 64] },
    SignedPsbt { psbt: Vec<u8>, signed_inputs: usize },
    PolicySet,
    FrostCommitment { commitment: Vec<u8>, nonces_id: [u8; 32] },
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
}

impl VsockServer {
    pub fn new() -> Result<Self> {
        Ok(Self {
            signer: EnclaveSigner::new(),
            policy_engine: PolicyEngine::new(),
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
        use aws_nitro_enclaves_nsm_api::driver::nsm_process_request;

        let ephemeral_pubkey = self.signer.get_ephemeral_pubkey();

        let request = Request::Attestation {
            user_data: None,
            nonce: Some(nonce.to_vec().into()),
            public_key: Some(ephemeral_pubkey.to_vec().into()),
        };

        match nsm_process_request(request) {
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
                pubkey,
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
                pubkey,
                name: name.to_string(),
            },
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                message: e.to_string(),
            },
        }
    }

    fn handle_sign(&mut self, req: SigningRequest) -> EnclaveResponse {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

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
                EnclaveResponse::Signature { signature }
            }
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::SigningFailed,
                message: e.to_string(),
            },
        }
    }

    fn handle_sign_psbt(&mut self, req: PsbtSigningRequest) -> EnclaveResponse {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let ctx = SigningContext {
            key_id: &req.key_id,
            amount_sats: None,
            destination: None,
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
                pubkey,
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
                nonces_id,
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
