// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use crate::error::{EnclaveError, Result};
use crate::kms::{EncryptedWallet, EnclaveKms};
use crate::policy::{PolicyConfig, PolicyDecision, PolicyEngine, SigningContext};
use crate::signer::EnclaveSigner;
use bitcoin::Network;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const VSOCK_PORT: u32 = 5000;
const MAX_REQUEST_SIZE: usize = 1024 * 1024;
const CONNECTION_TIMEOUT_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnclaveRequest {
    GetAttestation { nonce: [u8; 32] },
    GenerateKey { name: String },
    ImportKey { name: String, secret: Vec<u8> },
    ImportEncryptedKey { name: String, encrypted: EncryptedWallet },
    ImportFrostKey { name: String, key_package: Vec<u8>, pubkey_package: Vec<u8> },
    Sign(SigningRequest),
    SignPsbt(PsbtSigningRequest),
    SetPolicy(PolicyConfig),
    GetPublicKey { key_id: String },
    FrostRound1 { key_id: String, message: Vec<u8>, nonce: Option<[u8; 32]>, timestamp: Option<u64> },
    FrostAddCommitment { session_id: [u8; 32], identifier: Vec<u8>, commitment: Vec<u8> },
    FrostRound2 { session_id: [u8; 32], nonce: Option<[u8; 32]>, timestamp: Option<u64> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningRequest {
    pub key_id: String,
    pub message: Vec<u8>,
    pub event_kind: Option<u32>,
    pub amount_sats: Option<u64>,
    pub destination: Option<String>,
    pub nonce: Option<[u8; 32]>,
    pub timestamp: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtSigningRequest {
    pub key_id: String,
    pub psbt: Vec<u8>,
    pub network: NetworkParam,
    pub nonce: Option<[u8; 32]>,
    pub timestamp: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NetworkParam {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}

impl From<NetworkParam> for Network {
    fn from(p: NetworkParam) -> Network {
        match p {
            NetworkParam::Bitcoin => Network::Bitcoin,
            NetworkParam::Testnet => Network::Testnet,
            NetworkParam::Signet => Network::Signet,
            NetworkParam::Regtest => Network::Regtest,
        }
    }
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

const MAX_NONCES: usize = 10000;
const MAX_REQUEST_AGE_SECS: u64 = 300;

pub struct VsockServer {
    signer: EnclaveSigner,
    policy_engine: PolicyEngine,
    kms: EnclaveKms,
    used_nonces: std::collections::HashMap<[u8; 32], u64>,
    policy_initialized: bool,
}

impl VsockServer {
    pub fn new() -> Result<Self> {
        let signer = EnclaveSigner::new()?;
        let kms = signer.create_kms();
        Ok(Self {
            signer,
            policy_engine: PolicyEngine::new(),
            kms,
            used_nonces: std::collections::HashMap::new(),
            policy_initialized: false,
        })
    }

    fn validate_replay_protection(&mut self, nonce: Option<[u8; 32]>, req_timestamp: Option<u64>) -> std::result::Result<(), &'static str> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| "System clock error")?;

        if let Some(ts) = req_timestamp {
            if now > ts && now - ts > MAX_REQUEST_AGE_SECS {
                return Err("Request expired");
            }
            if ts > now + 60 {
                return Err("Request timestamp in future");
            }
        }

        self.used_nonces.retain(|_, &mut ts| now.saturating_sub(ts) < MAX_REQUEST_AGE_SECS);

        if let Some(n) = nonce {
            if self.used_nonces.contains_key(&n) {
                return Err("Nonce already used");
            }
            if self.used_nonces.len() >= MAX_NONCES {
                if let Some(oldest_key) = self.used_nonces.iter()
                    .min_by_key(|(_, &ts)| ts)
                    .map(|(k, _)| *k)
                {
                    self.used_nonces.remove(&oldest_key);
                }
            }
            self.used_nonces.insert(n, now);
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn run(&mut self) -> Result<()> {
        use std::io::{Read, Write};
        use std::time::Duration;
        use vsock::VsockListener;

        let listener = VsockListener::bind_with_cid_port(vsock::VMADDR_CID_ANY, VSOCK_PORT)
            .map_err(|e| EnclaveError::Vsock(format!("Bind failed: {}", e)))?;

        for stream in listener.incoming() {
            let mut stream = stream.map_err(|e| EnclaveError::Vsock(format!("Accept failed: {}", e)))?;

            // Set connection timeout to prevent DoS via connection holding
            let timeout = Some(Duration::from_secs(CONNECTION_TIMEOUT_SECS));
            let _ = stream.set_read_timeout(timeout);
            let _ = stream.set_write_timeout(timeout);

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
            EnclaveRequest::ImportFrostKey { name, key_package, pubkey_package } => {
                self.handle_import_frost_key(&name, key_package, pubkey_package)
            }
            EnclaveRequest::Sign(req) => self.handle_sign(req),
            EnclaveRequest::SignPsbt(req) => self.handle_sign_psbt(req),
            EnclaveRequest::SetPolicy(config) => self.handle_set_policy(config),
            EnclaveRequest::GetPublicKey { key_id } => self.handle_get_public_key(&key_id),
            EnclaveRequest::FrostRound1 { key_id, message, nonce, timestamp } => {
                self.handle_frost_round1(&key_id, &message, nonce, timestamp)
            }
            EnclaveRequest::FrostAddCommitment { session_id, identifier, commitment } => {
                self.handle_frost_add_commitment(session_id, &identifier, &commitment)
            }
            EnclaveRequest::FrostRound2 { session_id, nonce, timestamp } => {
                self.handle_frost_round2(session_id, nonce, timestamp)
            }
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

    #[cfg(feature = "allow-plaintext-import")]
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

    #[cfg(not(feature = "allow-plaintext-import"))]
    fn handle_import_key(&mut self, _name: &str, _secret: &[u8]) -> EnclaveResponse {
        EnclaveResponse::Error {
            code: ErrorCode::PolicyDenied,
            message: "Plaintext import disabled. Use ImportEncryptedKey.".into(),
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
        if let Err(e) = self.validate_replay_protection(req.nonce, req.timestamp) {
            return EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                message: e.into(),
            };
        }

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
        if let Err(e) = self.validate_replay_protection(req.nonce, req.timestamp) {
            return EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                message: e.into(),
            };
        }

        let network: Network = req.network.into();

        let analysis = match self.signer.analyze_psbt_for_key(&req.key_id, &req.psbt, network) {
            Ok(a) => a,
            Err(e) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("PSBT analysis failed: {}", e),
                };
            }
        };

        let total_spend: u64 = analysis
            .destinations
            .iter()
            .filter(|d| !d.is_change)
            .map(|d| d.amount_sats)
            .sum();

        let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InternalError,
                    message: "System clock error".into(),
                };
            }
        };

        for dest in &analysis.destinations {
            if dest.is_change {
                continue;
            }
            let addr = dest.address.as_deref();
            let ctx = SigningContext {
                key_id: &req.key_id,
                amount_sats: Some(total_spend),
                destination: addr,
                event_kind: None,
                timestamp,
            };

            match self.policy_engine.evaluate(&ctx) {
                PolicyDecision::Allow => {}
                PolicyDecision::Deny(reason) => {
                    return EnclaveResponse::Error {
                        code: ErrorCode::PolicyDenied,
                        message: format!("Destination {:?} denied: {}", addr, reason),
                    };
                }
                PolicyDecision::RequireApproval => {
                    return EnclaveResponse::Error {
                        code: ErrorCode::PolicyDenied,
                        message: format!("Destination {:?} requires approval", addr),
                    };
                }
            }
        }

        match self.signer.sign_psbt(&req.key_id, &req.psbt, network) {
            Ok((signed_psbt, signed_inputs, _)) => {
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
        if self.policy_initialized {
            return EnclaveResponse::Error {
                code: ErrorCode::PolicyDenied,
                message: "Policy already initialized; runtime changes not permitted".to_string(),
            };
        }
        self.policy_engine.set_policies(config);
        self.policy_initialized = true;
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

    fn handle_import_frost_key(
        &mut self,
        name: &str,
        key_package: Vec<u8>,
        pubkey_package: Vec<u8>,
    ) -> EnclaveResponse {
        match self.signer.import_frost_key(name, key_package, pubkey_package) {
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

    fn handle_frost_round1(
        &mut self,
        key_id: &str,
        message: &[u8],
        nonce: Option<[u8; 32]>,
        timestamp: Option<u64>,
    ) -> EnclaveResponse {
        if let Err(e) = self.validate_replay_protection(nonce, timestamp) {
            return EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                message: e.into(),
            };
        }

        match self.signer.frost_round1(key_id, message) {
            Ok((commitment, session_id)) => EnclaveResponse::FrostCommitment {
                commitment,
                nonces_id: session_id.to_vec(),
            },
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::SigningFailed,
                message: e.to_string(),
            },
        }
    }

    fn handle_frost_add_commitment(
        &mut self,
        session_id: [u8; 32],
        identifier: &[u8],
        commitment: &[u8],
    ) -> EnclaveResponse {
        match self.signer.frost_add_commitment(session_id, identifier, commitment) {
            Ok(()) => EnclaveResponse::PolicySet,
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::SigningFailed,
                message: e.to_string(),
            },
        }
    }

    fn handle_frost_round2(
        &mut self,
        session_id: [u8; 32],
        nonce: Option<[u8; 32]>,
        timestamp: Option<u64>,
    ) -> EnclaveResponse {
        if let Err(e) = self.validate_replay_protection(nonce, timestamp) {
            return EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                message: e.into(),
            };
        }

        match self.signer.frost_round2(session_id) {
            Ok(share) => EnclaveResponse::FrostShare { share },
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::SigningFailed,
                message: e.to_string(),
            },
        }
    }
}
