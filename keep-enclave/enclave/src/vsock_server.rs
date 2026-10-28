// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use crate::error::{EnclaveError, Result};
use crate::kms::{EncryptedWallet, EnclaveKms};
use crate::policy::{PolicyConfig, PolicyDecision, PolicyEngine, SigningContext};
use crate::psbt::PsbtAnalysis;
use crate::signer::EnclaveSigner;
use bitcoin::Network;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

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
    /// A FROST key package sealed with its policy, like `ImportEncryptedKey`.
    /// The public key package is public and travels in the clear.
    ImportEncryptedFrostKey {
        name: String,
        encrypted: EncryptedWallet,
        pubkey_package: Vec<u8>,
    },
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
    policy_sealed: bool,
    sealed_policy_hash: [u8; 32],
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
            policy_sealed: false,
            sealed_policy_hash: [0u8; 32],
        })
    }

    fn policy_required(&self) -> Option<EnclaveResponse> {
        if self.policy_initialized {
            return None;
        }
        Some(EnclaveResponse::Error {
            code: ErrorCode::PolicyDenied,
            message: "no policy loaded".into(),
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
            EnclaveRequest::ImportEncryptedFrostKey {
                name,
                encrypted,
                pubkey_package,
            } => self.handle_import_encrypted_frost_key(&name, &encrypted, pubkey_package),
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
        let (secret, policy) = match self.open_sealed(encrypted) {
            Ok(opened) => opened,
            Err(response) => return response,
        };
        if secret.len() != 32 {
            return EnclaveResponse::Error {
                code: ErrorCode::PolicyDenied,
                message: "policy denies request".into(),
            };
        }
        match self.signer.import_key(name, &secret) {
            Ok(pubkey) => {
                self.adopt_sealed_policy(policy, encrypted.policy_hash);
                EnclaveResponse::PublicKey {
                    pubkey: pubkey.to_vec(),
                    name: name.to_string(),
                }
            }
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                message: e.to_string(),
            },
        }
    }

    /// Import a FROST share sealed with its policy. The sealed body holds the
    /// serialized key package, which a 32-byte wallet secret never parses
    /// as, and which `ImportEncryptedKey` refuses for its length, so neither
    /// kind of blob imports as the other.
    fn handle_import_encrypted_frost_key(
        &mut self,
        name: &str,
        encrypted: &EncryptedWallet,
        pubkey_package: Vec<u8>,
    ) -> EnclaveResponse {
        let (mut key_package, policy) = match self.open_sealed(encrypted) {
            Ok(opened) => opened,
            Err(response) => return response,
        };
        match self
            .signer
            .import_frost_key(name, std::mem::take(&mut *key_package), pubkey_package)
        {
            Ok(pubkey) => {
                self.adopt_sealed_policy(policy, encrypted.policy_hash);
                EnclaveResponse::PublicKey {
                    pubkey: pubkey.to_vec(),
                    name: name.to_string(),
                }
            }
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                message: e.to_string(),
            },
        }
    }

    /// Decrypt a sealed key and its policy, refusing an empty policy and,
    /// once a policy is sealed, any other policy.
    fn open_sealed(
        &self,
        encrypted: &EncryptedWallet,
    ) -> std::result::Result<(zeroize::Zeroizing<Vec<u8>>, PolicyConfig), EnclaveResponse> {
        let (secret, policy_bytes) = match self.kms.decrypt_wallet_key(encrypted) {
            Ok(opened) => opened,
            Err(e) => {
                return Err(EnclaveResponse::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("KMS decryption failed: {}", e),
                });
            }
        };
        let policy = match postcard::from_bytes::<PolicyConfig>(&policy_bytes) {
            Ok(policy) => policy,
            Err(_) => {
                return Err(EnclaveResponse::Error {
                    code: ErrorCode::InvalidRequest,
                    message: "KMS decryption failed: invalid sealed wallet".into(),
                });
            }
        };
        if policy.policies.is_empty() {
            return Err(EnclaveResponse::Error {
                code: ErrorCode::PolicyDenied,
                message: "policy denies request".into(),
            });
        }
        if self.policy_sealed && !bool::from(encrypted.policy_hash.ct_eq(&self.sealed_policy_hash))
        {
            return Err(EnclaveResponse::Error {
                code: ErrorCode::PolicyDenied,
                message: "Policy is sealed to the key".into(),
            });
        }
        Ok((secret, policy))
    }

    /// Load the policy of the first sealed key imported, replacing any host
    /// policy, and refuse every other policy from then on.
    fn adopt_sealed_policy(&mut self, policy: PolicyConfig, policy_hash: [u8; 32]) {
        if !self.policy_sealed {
            self.policy_engine.set_policies(policy);
            self.policy_initialized = true;
            self.policy_sealed = true;
            self.sealed_policy_hash = policy_hash;
        }
    }

    fn handle_sign(&mut self, req: SigningRequest) -> EnclaveResponse {
        if let Some(denied) = self.policy_required() {
            return denied;
        }
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

        let pubkey = match self.pubkey_for(&req.key_id) {
            Ok(pubkey) => pubkey,
            Err(response) => return response,
        };

        let ctx = SigningContext {
            pubkey,
            amount_sats: req.amount_sats,
            fee_sats: None,
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
                self.policy_engine.record_operation(&pubkey);
                EnclaveResponse::Signature { signature: signature.to_vec() }
            }
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::SigningFailed,
                message: e.to_string(),
            },
        }
    }

    fn handle_sign_psbt(&mut self, req: PsbtSigningRequest) -> EnclaveResponse {
        if let Some(denied) = self.policy_required() {
            return denied;
        }
        if let Err(e) = self.validate_replay_protection(req.nonce, req.timestamp) {
            return EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                message: e.into(),
            };
        }

        let pubkey = match self.pubkey_for(&req.key_id) {
            Ok(pubkey) => pubkey,
            Err(response) => return response,
        };

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

        let total_spend = analysis.leaving_wallet_sats();

        let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InternalError,
                    message: "System clock error".into(),
                };
            }
        };

        if let Some(denied) =
            self.enforce_destination_policies(&analysis, pubkey, total_spend, timestamp)
        {
            return denied;
        }

        match self.signer.sign_psbt(&req.key_id, &req.psbt, network) {
            Ok((signed_psbt, signed_inputs)) => {
                self.policy_engine.record_operation(&pubkey);
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

    /// Evaluate the policy engine against each non-change destination, or once
    /// with no destination when nothing but the fee leaves the wallet, so the
    /// amount, rate and time rules always apply. An output with no address is
    /// named `script:<hex>`, so an allowlist refuses it unless that name is
    /// listed. Returns the error response
    /// to send back if any evaluation is denied or requires approval.
    fn enforce_destination_policies(
        &mut self,
        analysis: &PsbtAnalysis,
        pubkey: [u8; 32],
        total_spend: u64,
        timestamp: u64,
    ) -> Option<EnclaveResponse> {
        if analysis.fee_sats > 0 && !self.policy_engine.bounds_fee() {
            return Some(EnclaveResponse::Error {
                code: ErrorCode::PolicyDenied,
                message: "fee is not bounded".into(),
            });
        }
        let named: Vec<String> = analysis
            .destinations
            .iter()
            .filter(|d| !d.is_change)
            .map(|d| match &d.address {
                Some(address) => address.clone(),
                None => format!("script:{}", d.script_hex),
            })
            .collect();
        let destinations: Vec<Option<&str>> = if named.is_empty() {
            vec![None]
        } else {
            named.iter().map(|s| Some(s.as_str())).collect()
        };
        for addr in destinations {
            let ctx = SigningContext {
                pubkey,
                amount_sats: Some(total_spend),
                fee_sats: Some(analysis.fee_sats),
                destination: addr,
                event_kind: None,
                timestamp,
            };

            match self.policy_engine.evaluate(&ctx) {
                PolicyDecision::Allow => {}
                PolicyDecision::Deny(reason) => {
                    return Some(EnclaveResponse::Error {
                        code: ErrorCode::PolicyDenied,
                        message: format!("Destination {:?} denied: {}", addr, reason),
                    });
                }
                PolicyDecision::RequireApproval => {
                    return Some(EnclaveResponse::Error {
                        code: ErrorCode::PolicyDenied,
                        message: format!("Destination {:?} requires approval", addr),
                    });
                }
            }
        }
        None
    }

    fn handle_set_policy(&mut self, config: PolicyConfig) -> EnclaveResponse {
        if self.policy_sealed {
            return EnclaveResponse::Error {
                code: ErrorCode::PolicyDenied,
                message: "Policy is sealed to the key".into(),
            };
        }
        if config.policies.is_empty() {
            return EnclaveResponse::Error {
                code: ErrorCode::PolicyDenied,
                message: "policy denies request".into(),
            };
        }
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
        match self.pubkey_for(key_id) {
            Ok(pubkey) => EnclaveResponse::PublicKey {
                pubkey: pubkey.to_vec(),
                name: key_id.to_string(),
            },
            Err(response) => response,
        }
    }

    /// The public key of the signing key named `key_id`, which its rate
    /// limits count against, or the response refusing an unknown name.
    fn pubkey_for(&self, key_id: &str) -> std::result::Result<[u8; 32], EnclaveResponse> {
        self.signer
            .get_public_key(key_id)
            .map_err(|e| EnclaveResponse::Error {
                code: ErrorCode::KeyNotFound,
                message: e.to_string(),
            })
    }

    #[cfg(feature = "allow-plaintext-import")]
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

    #[cfg(not(feature = "allow-plaintext-import"))]
    fn handle_import_frost_key(
        &mut self,
        _name: &str,
        _key_package: Vec<u8>,
        _pubkey_package: Vec<u8>,
    ) -> EnclaveResponse {
        EnclaveResponse::Error {
            code: ErrorCode::PolicyDenied,
            message: "Plaintext import disabled. Use ImportEncryptedFrostKey.".into(),
        }
    }

    /// Hold a FROST request for the share's group key to the policy. A FROST
    /// message is opaque to the enclave, so it is judged with no amount,
    /// destination or event kind, like a `Sign` request that names none.
    fn frost_policy(&mut self, pubkey: [u8; 32]) -> Option<EnclaveResponse> {
        let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => {
                return Some(EnclaveResponse::Error {
                    code: ErrorCode::InternalError,
                    message: "System clock error".into(),
                });
            }
        };
        let ctx = SigningContext {
            pubkey,
            amount_sats: None,
            fee_sats: None,
            destination: None,
            event_kind: None,
            timestamp,
        };
        match self.policy_engine.evaluate(&ctx) {
            PolicyDecision::Allow => None,
            PolicyDecision::Deny(reason) => Some(EnclaveResponse::Error {
                code: ErrorCode::PolicyDenied,
                message: reason.to_string(),
            }),
            PolicyDecision::RequireApproval => Some(EnclaveResponse::Error {
                code: ErrorCode::PolicyDenied,
                message: "Requires approval".into(),
            }),
        }
    }

    fn handle_frost_round1(
        &mut self,
        key_id: &str,
        message: &[u8],
        nonce: Option<[u8; 32]>,
        timestamp: Option<u64>,
    ) -> EnclaveResponse {
        if let Some(denied) = self.policy_required() {
            return denied;
        }
        if let Err(e) = self.validate_replay_protection(nonce, timestamp) {
            return EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                message: e.into(),
            };
        }

        let pubkey = match self.signer.frost_public_key(key_id) {
            Ok(pubkey) => pubkey,
            Err(e) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::KeyNotFound,
                    message: e.to_string(),
                };
            }
        };
        if let Some(denied) = self.frost_policy(pubkey) {
            return denied;
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
        if let Some(denied) = self.policy_required() {
            return denied;
        }
        if let Err(e) = self.validate_replay_protection(nonce, timestamp) {
            return EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                message: e.into(),
            };
        }

        // Judged again here, where the share is made: opening a session spends
        // nothing, so several opened together must not all be signed. A
        // refused session is closed, so its nonces are never used.
        let pubkey = match self.signer.frost_session_pubkey(&session_id) {
            Ok(pubkey) => pubkey,
            Err(e) => {
                self.signer.drop_frost_session(&session_id);
                return EnclaveResponse::Error {
                    code: ErrorCode::SigningFailed,
                    message: e.to_string(),
                };
            }
        };
        if let Some(denied) = self.frost_policy(pubkey) {
            self.signer.drop_frost_session(&session_id);
            return denied;
        }

        match self.signer.frost_round2(session_id) {
            Ok(share) => {
                self.policy_engine.record_operation(&pubkey);
                EnclaveResponse::FrostShare { share }
            }
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::SigningFailed,
                message: e.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Policy, PolicyAction, PolicyRule};
    use crate::psbt::fixtures::*;
    use bitcoin::psbt::Psbt;
    use bitcoin::{Address, ScriptBuf};
    use std::time::Duration;

    const WIRE_DIGEST: &str = "e07732b1b0bb25bccb7c26b722dcd96cfd47044aa74e6a3565007ec3f42d78b5";

    /// One of every request, response and policy rule, encoded as they go
    /// over vsock. The host and the enclave each define these types, and
    /// postcard numbers enum variants by position, so both crates pin the
    /// same bytes: a variant or field moved on one side alone fails here.
    fn wire_sample() -> Vec<u8> {
        let wallet = EncryptedWallet {
            encrypted_data_key: vec![1],
            encrypted_wallet_key: vec![2],
            nonce: [3u8; 12],
            policy_hash: [4u8; 32],
        };
        let rules = vec![
            PolicyRule::MaxAmountSats(u64::MAX),
            PolicyRule::MaxPerMinute(2),
            PolicyRule::MaxPerHour(3),
            PolicyRule::MaxPerDay(u32::MAX),
            PolicyRule::AddressAllowlist(vec!["a".into()]),
            PolicyRule::AddressBlocklist(vec!["b".into()]),
            PolicyRule::AllowedHours { start: 5, end: 6 },
            PolicyRule::BlockWeekends,
            PolicyRule::AllowedEventKinds(vec![u32::MAX]),
            PolicyRule::And(vec![PolicyRule::MaxPerDay(8)]),
            PolicyRule::Or(vec![PolicyRule::MaxPerDay(9)]),
            PolicyRule::MaxFeeSats(1 << 50),
        ];
        let policies = PolicyConfig {
            policies: [
                PolicyAction::Allow,
                PolicyAction::Deny,
                PolicyAction::RequireApproval,
            ]
            .into_iter()
            .map(|action| Policy {
                name: "p".into(),
                rules: rules.clone(),
                action,
            })
            .collect(),
        };
        let requests = vec![
            EnclaveRequest::GetAttestation { nonce: [11u8; 32] },
            EnclaveRequest::GenerateKey { name: "g".into() },
            EnclaveRequest::ImportKey {
                name: "i".into(),
                secret: vec![12],
            },
            EnclaveRequest::ImportEncryptedKey {
                name: "e".into(),
                encrypted: wallet.clone(),
            },
            EnclaveRequest::ImportFrostKey {
                name: "f".into(),
                key_package: vec![13],
                pubkey_package: vec![14],
            },
            EnclaveRequest::Sign(SigningRequest {
                key_id: "s".into(),
                message: vec![15],
                event_kind: Some(u32::MAX),
                amount_sats: Some(u64::MAX),
                destination: Some("d".into()),
                nonce: Some([18u8; 32]),
                timestamp: Some(u64::MAX - 19),
            }),
            EnclaveRequest::SignPsbt(PsbtSigningRequest {
                key_id: "p".into(),
                psbt: vec![20],
                network: NetworkParam::Signet,
                nonce: None,
                timestamp: Some(1 << 40),
            }),
            EnclaveRequest::SetPolicy(policies),
            EnclaveRequest::GetPublicKey { key_id: "k".into() },
            EnclaveRequest::FrostRound1 {
                key_id: "r".into(),
                message: vec![22],
                nonce: Some([23u8; 32]),
                timestamp: Some(24),
            },
            EnclaveRequest::FrostAddCommitment {
                session_id: [25u8; 32],
                identifier: vec![26],
                commitment: vec![27],
            },
            EnclaveRequest::FrostRound2 {
                session_id: [28u8; 32],
                nonce: None,
                timestamp: None,
            },
            EnclaveRequest::ImportEncryptedFrostKey {
                name: "x".into(),
                encrypted: wallet,
                pubkey_package: vec![29],
            },
        ];
        let responses = vec![
            EnclaveResponse::Attestation { document: vec![30] },
            EnclaveResponse::PublicKey {
                pubkey: vec![31],
                name: "n".into(),
            },
            EnclaveResponse::Signature {
                signature: vec![32],
            },
            EnclaveResponse::SignedPsbt {
                psbt: vec![33],
                signed_inputs: usize::MAX,
            },
            EnclaveResponse::PolicySet,
            EnclaveResponse::FrostCommitment {
                commitment: vec![35],
                nonces_id: vec![36],
            },
            EnclaveResponse::FrostShare { share: vec![37] },
        ]
        .into_iter()
        .chain(
            [
                ErrorCode::InvalidRequest,
                ErrorCode::PolicyDenied,
                ErrorCode::RateLimitExceeded,
                ErrorCode::KeyNotFound,
                ErrorCode::SigningFailed,
                ErrorCode::InternalError,
            ]
            .into_iter()
            .map(|code| EnclaveResponse::Error {
                code,
                message: "m".into(),
            }),
        );
        let networks = [
            NetworkParam::Bitcoin,
            NetworkParam::Testnet,
            NetworkParam::Signet,
            NetworkParam::Regtest,
        ];
        let mut bytes = Vec::new();
        for request in requests {
            bytes.extend(postcard::to_allocvec(&request).unwrap());
        }
        for response in responses {
            bytes.extend(postcard::to_allocvec(&response).unwrap());
        }
        bytes.extend(postcard::to_allocvec(&networks).unwrap());
        bytes
    }

    #[test]
    fn the_wire_format_matches_the_other_side() {
        let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(wire_sample()).into();
        assert_eq!(hex::encode(digest), WIRE_DIGEST);
    }

    fn server(rules: Vec<PolicyRule>) -> VsockServer {
        let signer = EnclaveSigner::with_ephemeral_secret([42u8; 32]);
        let kms = signer.create_kms();
        let mut server = VsockServer {
            signer,
            policy_engine: PolicyEngine::new(),
            kms,
            used_nonces: std::collections::HashMap::new(),
            policy_initialized: false,
            policy_sealed: false,
            sealed_policy_hash: [0u8; 32],
        };
        server.handle_set_policy(PolicyConfig {
            policies: vec![Policy {
                name: "limits".into(),
                rules,
                action: PolicyAction::Deny,
            }],
        });
        server.signer.import_key("k", &SECRET).unwrap();
        server
    }

    fn sign(server: &mut VsockServer, psbt: &Psbt) -> EnclaveResponse {
        server.handle_sign_psbt(PsbtSigningRequest {
            key_id: "k".into(),
            psbt: psbt.serialize(),
            network: NetworkParam::Bitcoin,
            nonce: None,
            timestamp: None,
        })
    }

    fn denied(response: &EnclaveResponse) -> bool {
        matches!(
            response,
            EnclaveResponse::Error {
                code: ErrorCode::PolicyDenied,
                ..
            }
        )
    }

    fn address(spk: &ScriptBuf) -> String {
        Address::from_script(spk, Network::Bitcoin).unwrap().to_string()
    }

    #[test]
    fn a_spend_within_policy_is_signed() {
        let to = p2tr(other_key());
        let mut server = server(vec![
            PolicyRule::MaxAmountSats(50_000),
            PolicyRule::AddressAllowlist(vec![address(&to)]),
        ]);
        let psbt = psbt(&[(p2tr(x_only(&SECRET)), 45_000)], &[(to, 44_000)]);
        match sign(&mut server, &psbt) {
            EnclaveResponse::SignedPsbt { signed_inputs, .. } => assert_eq!(signed_inputs, 1),
            other => panic!("expected a signed PSBT, got {other:?}"),
        }
    }

    #[test]
    fn the_fee_counts_toward_the_amount_limit() {
        let mut server = server(vec![PolicyRule::MaxAmountSats(50_000)]);
        let psbt = psbt(
            &[(p2tr(x_only(&SECRET)), 100_000)],
            &[(p2tr(other_key()), 40_000)],
        );
        assert!(denied(&sign(&mut server, &psbt)));
    }

    #[test]
    fn an_output_without_an_address_fails_the_allowlist() {
        let to = p2tr(other_key());
        let mut server = server(vec![PolicyRule::AddressAllowlist(vec![address(&to)])]);
        let psbt = psbt(
            &[(p2tr(x_only(&SECRET)), 50_000)],
            &[(to, 40_000), (ScriptBuf::new_op_return([1u8, 2, 3]), 0)],
        );
        assert!(denied(&sign(&mut server, &psbt)));
    }

    #[test]
    fn an_allowlist_alone_does_not_authorize_a_fee() {
        let to = p2tr(other_key());
        let mut server = server(vec![PolicyRule::AddressAllowlist(vec![address(&to)])]);
        let psbt = psbt(&[(p2tr(x_only(&SECRET)), 50_000)], &[(to, 40_000)]);
        assert!(denied(&sign(&mut server, &psbt)));
    }

    #[test]
    fn a_fee_cap_allows_a_small_fee_and_refuses_a_large_one() {
        let to = p2tr(other_key());
        let mut server = server(vec![
            PolicyRule::AddressAllowlist(vec![address(&to)]),
            PolicyRule::MaxFeeSats(1_000),
        ]);
        let small = psbt(&[(p2tr(x_only(&SECRET)), 50_000)], &[(to.clone(), 49_000)]);
        match sign(&mut server, &small) {
            EnclaveResponse::SignedPsbt { signed_inputs, .. } => assert_eq!(signed_inputs, 1),
            other => panic!("expected a signed PSBT, got {other:?}"),
        }
        let large = psbt(&[(p2tr(x_only(&SECRET)), 50_000)], &[(to, 40_000)]);
        assert!(denied(&sign(&mut server, &large)));
    }

    #[test]
    fn an_allow_amount_cap_does_not_bound_the_fee() {
        let to = p2tr(other_key());
        let mut server = bare();
        server.handle_set_policy(PolicyConfig {
            policies: vec![
                Policy {
                    name: "cap".into(),
                    rules: vec![PolicyRule::MaxAmountSats(1_000)],
                    action: PolicyAction::Allow,
                },
                Policy {
                    name: "dest".into(),
                    rules: vec![PolicyRule::AddressAllowlist(vec![address(&to)])],
                    action: PolicyAction::Deny,
                },
            ],
        });
        server.signer.import_key("k", &SECRET).unwrap();
        let psbt = psbt(&[(p2tr(x_only(&SECRET)), 50_000)], &[(to, 1)]);
        assert!(denied(&sign(&mut server, &psbt)));
    }

    #[test]
    fn a_fee_cap_after_a_skippable_rule_does_not_bound_the_fee() {
        let to = p2tr(other_key());
        let other = p2tr(x_only(&[9u8; 32]));
        let mut server = bare();
        server.handle_set_policy(PolicyConfig {
            policies: vec![
                Policy {
                    name: "cap".into(),
                    rules: vec![
                        PolicyRule::AddressAllowlist(vec![address(&other)]),
                        PolicyRule::MaxFeeSats(1_000),
                    ],
                    action: PolicyAction::Allow,
                },
                Policy {
                    name: "dest".into(),
                    rules: vec![PolicyRule::AddressAllowlist(vec![address(&to)])],
                    action: PolicyAction::Deny,
                },
            ],
        });
        server.signer.import_key("k", &SECRET).unwrap();
        let psbt = psbt(&[(p2tr(x_only(&SECRET)), 50_000)], &[(to, 1)]);
        assert!(denied(&sign(&mut server, &psbt)));
    }

    #[test]
    fn an_or_with_an_allowlist_does_not_bound_the_fee() {
        let to = p2tr(other_key());
        let mut server = server(vec![PolicyRule::Or(vec![
            PolicyRule::AddressAllowlist(vec![address(&to)]),
            PolicyRule::MaxAmountSats(1_000_000),
        ])]);
        let psbt = psbt(&[(p2tr(x_only(&SECRET)), 50_000)], &[(to, 40_000)]);
        assert!(denied(&sign(&mut server, &psbt)));
    }

    #[test]
    fn the_policy_applies_when_only_the_fee_leaves() {
        let (change, fp, path) = child(&SECRET, Network::Bitcoin, "m/86'/0'/0'/1/0");
        let mut server = server(vec![PolicyRule::MaxAmountSats(500)]);
        let mut psbt = psbt(&[(p2tr(x_only(&SECRET)), 100_000)], &[(p2tr(change), 99_000)]);
        psbt.outputs[0]
            .tap_key_origins
            .insert(change, (vec![], (fp, path)));
        assert!(denied(&sign(&mut server, &psbt)));
    }

    fn bare() -> VsockServer {
        let signer = EnclaveSigner::with_ephemeral_secret([42u8; 32]);
        let kms = signer.create_kms();
        VsockServer {
            signer,
            policy_engine: PolicyEngine::new(),
            kms,
            used_nonces: std::collections::HashMap::new(),
            policy_initialized: false,
            policy_sealed: false,
            sealed_policy_hash: [0u8; 32],
        }
    }

    fn rate_bytes(max: u32) -> Vec<u8> {
        postcard::to_allocvec(&PolicyConfig {
            policies: vec![Policy {
                name: "rate".into(),
                rules: vec![PolicyRule::MaxPerMinute(max)],
                action: PolicyAction::Deny,
            }],
        })
        .unwrap()
    }

    fn limit_bytes(max: u64) -> Vec<u8> {
        postcard::to_allocvec(&PolicyConfig {
            policies: vec![Policy {
                name: "limit".into(),
                rules: vec![PolicyRule::MaxAmountSats(max)],
                action: PolicyAction::Deny,
            }],
        })
        .unwrap()
    }

    fn sign_amount(server: &mut VsockServer, amount: u64) -> EnclaveResponse {
        server.handle_sign(SigningRequest {
            key_id: "k".into(),
            message: vec![1u8; 32],
            event_kind: None,
            amount_sats: Some(amount),
            destination: None,
            nonce: None,
            timestamp: None,
        })
    }

    #[test]
    fn signing_is_refused_until_a_policy_is_loaded() {
        let mut server = bare();
        assert!(denied(&sign_amount(&mut server, 1)));
        assert!(denied(&server.handle_frost_round1("k", &[1u8; 32], None, None)));
        assert!(denied(&server.handle_frost_round2([0u8; 32], None, None)));
        assert!(denied(&server.handle_set_policy(PolicyConfig { policies: vec![] })));
        assert!(denied(&sign_amount(&mut server, 1)));
    }

    #[test]
    fn a_sealed_policy_replaces_a_looser_host_policy() {
        let mut server = bare();
        server.handle_set_policy(PolicyConfig {
            policies: vec![Policy {
                name: "loose".into(),
                rules: vec![PolicyRule::MaxAmountSats(1_000_000)],
                action: PolicyAction::Deny,
            }],
        });
        let blob = crate::kms::seal_for_test(&[42u8; 32], &SECRET, &limit_bytes(1_000));
        match server.handle_import_encrypted_key("k", &blob) {
            EnclaveResponse::PublicKey { .. } => {}
            other => panic!("expected the key to import, got {other:?}"),
        }
        assert!(matches!(
            sign_amount(&mut server, 500),
            EnclaveResponse::Signature { .. }
        ));
        assert!(denied(&sign_amount(&mut server, 2_000)));
        assert!(denied(&server.handle_set_policy(PolicyConfig {
            policies: vec![Policy {
                name: "looser".into(),
                rules: vec![PolicyRule::MaxAmountSats(1_000_000)],
                action: PolicyAction::Deny,
            }],
        })));
    }

    #[test]
    fn a_sealed_rate_limit_replaces_a_seeded_bucket() {
        let mut server = bare();
        server.handle_set_policy(PolicyConfig {
            policies: vec![Policy {
                name: "loose".into(),
                rules: vec![PolicyRule::MaxPerMinute(1_000_000)],
                action: PolicyAction::Deny,
            }],
        });
        server.signer.import_key("k", &SECRET).unwrap();
        server.policy_engine.advance_clock(Duration::from_secs(60));
        assert!(signed(&sign_amount(&mut server, 1)));
        let blob = crate::kms::seal_for_test(&[42u8; 32], &SECRET, &rate_bytes(1));
        imported(server.handle_import_encrypted_key("k", &blob));
        assert!(denied(&sign_amount(&mut server, 1)));
        server.policy_engine.advance_clock(Duration::from_secs(60));
        assert!(signed(&sign_amount(&mut server, 1)));
        assert!(denied(&sign_amount(&mut server, 1)));
    }

    fn signed(response: &EnclaveResponse) -> bool {
        matches!(response, EnclaveResponse::Signature { .. })
    }

    fn imported(response: EnclaveResponse) {
        match response {
            EnclaveResponse::PublicKey { .. } => {}
            other => panic!("expected the key to import, got {other:?}"),
        }
    }

    fn sign_as(server: &mut VsockServer, key_id: &str, amount: u64) -> EnclaveResponse {
        server.handle_sign(SigningRequest {
            key_id: key_id.into(),
            message: vec![1u8; 32],
            event_kind: None,
            amount_sats: Some(amount),
            destination: None,
            nonce: None,
            timestamp: None,
        })
    }

    fn sealed_rules(rules: Vec<PolicyRule>) -> VsockServer {
        let bytes = postcard::to_allocvec(&PolicyConfig {
            policies: vec![Policy {
                name: "sealed".into(),
                rules,
                action: PolicyAction::Deny,
            }],
        })
        .unwrap();
        let blob = crate::kms::seal_for_test(&[42u8; 32], &SECRET, &bytes);
        let mut server = bare();
        imported(server.handle_import_encrypted_key("k", &blob));
        server
    }

    #[test]
    fn a_restarted_enclave_starts_its_rate_limits_empty() {
        let mut server = sealed_rules(vec![PolicyRule::MaxPerMinute(2)]);
        assert!(denied(&sign_amount(&mut server, 1)));
        server.policy_engine.advance_clock(Duration::from_secs(30));
        assert!(signed(&sign_amount(&mut server, 1)));
        assert!(denied(&sign_amount(&mut server, 1)));
    }

    #[test]
    fn one_secret_under_two_names_shares_its_rate_limit() {
        let blob = crate::kms::seal_for_test(&[42u8; 32], &SECRET, &rate_bytes(1));
        let mut server = bare();
        imported(server.handle_import_encrypted_key("k", &blob));
        imported(server.handle_import_encrypted_key("again", &blob));
        server.policy_engine.advance_clock(Duration::from_secs(60));
        assert!(signed(&sign_as(&mut server, "k", 1)));
        assert!(denied(&sign_as(&mut server, "again", 1)));
    }

    #[test]
    fn a_second_rate_rule_on_a_key_is_held_to_its_own_maximum() {
        let mut server = sealed_rules(vec![
            PolicyRule::MaxPerMinute(100),
            PolicyRule::MaxPerMinute(2),
        ]);
        server.policy_engine.advance_clock(Duration::from_secs(60));
        assert!(signed(&sign_amount(&mut server, 1)));
        assert!(signed(&sign_amount(&mut server, 1)));
        assert!(denied(&sign_amount(&mut server, 1)));
    }

    #[test]
    fn a_signature_counts_against_a_rate_rule_its_branch_skipped() {
        let mut server = sealed_rules(vec![PolicyRule::Or(vec![
            PolicyRule::MaxAmountSats(10),
            PolicyRule::MaxPerMinute(2),
        ])]);
        server.policy_engine.advance_clock(Duration::from_secs(60));
        assert!(signed(&sign_amount(&mut server, 5)));
        assert!(signed(&sign_amount(&mut server, 5)));
        assert!(denied(&sign_amount(&mut server, 100)));
    }

    #[test]
    fn a_psbt_counts_once_however_many_destinations_it_pays() {
        let mut server = server(vec![
            PolicyRule::MaxFeeSats(5_000),
            PolicyRule::MaxPerMinute(2),
        ]);
        server.policy_engine.advance_clock(Duration::from_secs(60));
        let psbt = psbt(
            &[(p2tr(x_only(&SECRET)), 100_000)],
            &[
                (p2tr(other_key()), 49_000),
                (p2tr(x_only(&[8u8; 32])), 49_000),
            ],
        );
        for _ in 0..2 {
            match sign(&mut server, &psbt) {
                EnclaveResponse::SignedPsbt { .. } => {}
                other => panic!("expected a signed PSBT, got {other:?}"),
            }
        }
        assert!(denied(&sign(&mut server, &psbt)));
    }

    #[test]
    fn a_refused_request_spends_no_rate_limit() {
        let mut server = sealed_rules(vec![
            PolicyRule::MaxPerMinute(1),
            PolicyRule::MaxAmountSats(10),
        ]);
        server.policy_engine.advance_clock(Duration::from_secs(60));
        assert!(denied(&sign_amount(&mut server, 100)));
        assert!(signed(&sign_amount(&mut server, 5)));
        assert!(denied(&sign_amount(&mut server, 5)));
    }

    #[test]
    fn a_psbt_with_an_unknown_key_is_refused_as_not_found() {
        let mut server = server(vec![PolicyRule::MaxAmountSats(1_000_000)]);
        let psbt = psbt(
            &[(p2tr(x_only(&SECRET)), 50_000)],
            &[(p2tr(other_key()), 49_000)],
        );
        let response = server.handle_sign_psbt(PsbtSigningRequest {
            key_id: "missing".into(),
            psbt: psbt.serialize(),
            network: NetworkParam::Bitcoin,
            nonce: None,
            timestamp: None,
        });
        assert!(matches!(
            response,
            EnclaveResponse::Error {
                code: ErrorCode::KeyNotFound,
                ..
            }
        ));
    }

    #[test]
    fn signing_with_an_unknown_key_is_refused_before_the_policy() {
        let mut server = sealed_rules(vec![PolicyRule::MaxPerMinute(1)]);
        server.policy_engine.advance_clock(Duration::from_secs(60));
        assert!(matches!(
            sign_as(&mut server, "missing", 1),
            EnclaveResponse::Error {
                code: ErrorCode::KeyNotFound,
                ..
            }
        ));
        assert!(signed(&sign_amount(&mut server, 1)));
    }

    #[test]
    fn a_restart_loads_the_sealed_policy() {
        let blob = crate::kms::seal_for_test(&[42u8; 32], &SECRET, &limit_bytes(1_000));
        let mut restarted = bare();
        match restarted.handle_import_encrypted_key("k", &blob) {
            EnclaveResponse::PublicKey { .. } => {}
            other => panic!("expected the key to import, got {other:?}"),
        }
        assert!(matches!(
            sign_amount(&mut restarted, 500),
            EnclaveResponse::Signature { .. }
        ));
        assert!(denied(&sign_amount(&mut restarted, 2_000)));
    }

    #[test]
    fn a_tampered_policy_hash_does_not_import() {
        let mut blob = crate::kms::seal_for_test(&[42u8; 32], &SECRET, &limit_bytes(1_000));
        blob.policy_hash[0] ^= 0xff;
        let mut server = bare();
        assert!(matches!(
            server.handle_import_encrypted_key("k", &blob),
            EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                ..
            }
        ));
        assert!(matches!(
            server.handle_get_public_key("k"),
            EnclaveResponse::Error {
                code: ErrorCode::KeyNotFound,
                ..
            }
        ));
    }

    #[test]
    fn a_second_sealed_policy_is_refused() {
        let mut server = bare();
        let first = crate::kms::seal_for_test(&[42u8; 32], &SECRET, &limit_bytes(1_000));
        assert!(matches!(
            server.handle_import_encrypted_key("k", &first),
            EnclaveResponse::PublicKey { .. }
        ));
        let second = crate::kms::seal_for_test(&[42u8; 32], &SECRET, &limit_bytes(1_000_000));
        assert!(denied(&server.handle_import_encrypted_key("other", &second)));
        assert!(denied(&sign_amount(&mut server, 2_000)));
    }

    #[test]
    fn a_rejected_key_does_not_seal_the_policy() {
        let blob = crate::kms::seal_for_test(&[42u8; 32], &[0u8; 32], &limit_bytes(1_000_000));
        let mut server = bare();
        assert!(matches!(
            server.handle_import_encrypted_key("k", &blob),
            EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                ..
            }
        ));
        assert!(matches!(
            server.handle_set_policy(PolicyConfig {
                policies: vec![Policy {
                    name: "limit".into(),
                    rules: vec![PolicyRule::MaxAmountSats(1_000)],
                    action: PolicyAction::Deny,
                }],
            }),
            EnclaveResponse::PolicySet
        ));
    }

    #[test]
    fn an_empty_sealed_policy_does_not_load_the_key() {
        let empty = postcard::to_allocvec(&PolicyConfig { policies: vec![] }).unwrap();
        let blob = crate::kms::seal_for_test(&[42u8; 32], &SECRET, &empty);
        let mut server = bare();
        assert!(denied(&server.handle_import_encrypted_key("k", &blob)));
        assert!(matches!(
            server.handle_get_public_key("k"),
            EnclaveResponse::Error {
                code: ErrorCode::KeyNotFound,
                ..
            }
        ));
        assert!(denied(&sign_amount(&mut server, 1)));
    }

    type FrostKeys = (
        frost_secp256k1_tr::keys::KeyPackage,
        frost_secp256k1_tr::keys::KeyPackage,
        Vec<u8>,
    );

    /// Our share, the other signer's share and the serialized public key
    /// package of a fresh 2-of-2 group.
    #[allow(clippy::disallowed_methods)]
    fn frost_group() -> FrostKeys {
        use frost_secp256k1_tr::keys::{generate_with_dealer, IdentifierList, KeyPackage};
        let (shares, pubkey_package) =
            generate_with_dealer(2, 2, IdentifierList::Default, &mut rand_core::OsRng).unwrap();
        let mut packages = shares
            .into_values()
            .map(|secret| KeyPackage::try_from(secret).unwrap());
        let ours = packages.next().unwrap();
        let theirs = packages.next().unwrap();
        (ours, theirs, pubkey_package.serialize().unwrap())
    }

    fn policy_bytes(rules: Vec<PolicyRule>) -> Vec<u8> {
        postcard::to_allocvec(&PolicyConfig {
            policies: vec![Policy {
                name: "sealed".into(),
                rules,
                action: PolicyAction::Deny,
            }],
        })
        .unwrap()
    }

    fn sealed_frost(rules: Vec<PolicyRule>) -> (VsockServer, frost_secp256k1_tr::keys::KeyPackage) {
        let (ours, theirs, pubkeys) = frost_group();
        let blob = crate::kms::seal_for_test(
            &[42u8; 32],
            &ours.serialize().unwrap(),
            &policy_bytes(rules),
        );
        let mut server = bare();
        imported(server.handle_import_encrypted_frost_key("g", &blob, pubkeys));
        (server, theirs)
    }

    /// Open a session for `message`, returning its id or the refusal.
    fn open(
        server: &mut VsockServer,
        message: &[u8],
    ) -> std::result::Result<[u8; 32], EnclaveResponse> {
        match server.handle_frost_round1("g", message, None, None) {
            EnclaveResponse::FrostCommitment { nonces_id, .. } => Ok(nonces_id.try_into().unwrap()),
            other => Err(other),
        }
    }

    #[allow(clippy::disallowed_methods)]
    fn finish(
        server: &mut VsockServer,
        session: [u8; 32],
        theirs: &frost_secp256k1_tr::keys::KeyPackage,
    ) -> EnclaveResponse {
        let (_, commitment) =
            frost_secp256k1_tr::round1::commit(theirs.signing_share(), &mut rand_core::OsRng);
        assert!(matches!(
            server.handle_frost_add_commitment(
                session,
                &theirs.identifier().serialize(),
                &commitment.serialize().unwrap(),
            ),
            EnclaveResponse::PolicySet
        ));
        server.handle_frost_round2(session, None, None)
    }

    fn shared(response: &EnclaveResponse) -> bool {
        matches!(response, EnclaveResponse::FrostShare { .. })
    }

    #[cfg(not(feature = "allow-plaintext-import"))]
    #[test]
    fn a_frost_share_in_the_clear_is_refused() {
        let (ours, _, pubkeys) = frost_group();
        let mut server = server(vec![PolicyRule::MaxPerMinute(1_000)]);
        assert!(denied(&server.handle_import_frost_key(
            "g",
            ours.serialize().unwrap(),
            pubkeys,
        )));
        assert!(server.signer.frost_public_key("g").is_err());
    }

    #[test]
    fn a_sealed_frost_share_seals_its_policy() {
        let (mut server, _) = sealed_frost(vec![PolicyRule::MaxPerMinute(1)]);
        assert!(server.signer.frost_public_key("g").is_ok());
        assert!(denied(&server.handle_set_policy(PolicyConfig {
            policies: vec![Policy {
                name: "looser".into(),
                rules: vec![PolicyRule::MaxPerMinute(1_000)],
                action: PolicyAction::Deny,
            }],
        })));
    }

    #[test]
    fn a_frost_share_under_another_sealed_policy_is_refused() {
        let blob = crate::kms::seal_for_test(&[42u8; 32], &SECRET, &rate_bytes(1));
        let mut server = bare();
        imported(server.handle_import_encrypted_key("k", &blob));
        let (ours, _, pubkeys) = frost_group();
        let looser = crate::kms::seal_for_test(
            &[42u8; 32],
            &ours.serialize().unwrap(),
            &policy_bytes(vec![PolicyRule::MaxPerMinute(1_000)]),
        );
        let refused = server.handle_import_encrypted_frost_key("g", &looser, pubkeys);
        assert!(denied(&refused));
        assert!(server.signer.frost_public_key("g").is_err());
    }

    #[test]
    fn a_wallet_blob_and_a_frost_blob_do_not_import_as_each_other() {
        let rules = policy_bytes(vec![PolicyRule::MaxPerMinute(1)]);
        let (ours, _, pubkeys) = frost_group();
        let wallet = crate::kms::seal_for_test(&[42u8; 32], &SECRET, &rules);
        let share = crate::kms::seal_for_test(&[42u8; 32], &ours.serialize().unwrap(), &rules);
        let mut server = bare();
        assert!(!matches!(
            server.handle_import_encrypted_frost_key("g", &wallet, pubkeys),
            EnclaveResponse::PublicKey { .. }
        ));
        assert!(!matches!(
            server.handle_import_encrypted_key("k", &share),
            EnclaveResponse::PublicKey { .. }
        ));
        assert!(server.signer.frost_public_key("g").is_err());
        assert!(server.signer.get_public_key("k").is_err());
    }

    #[test]
    fn a_frost_round_is_held_to_the_time_rules() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let hour = (now.as_secs() / 3600 % 24) as u8;
        let (mut server, _) = sealed_frost(vec![PolicyRule::AllowedHours {
            start: (hour + 2) % 24,
            end: (hour + 3) % 24,
        }]);
        assert!(denied(&open(&mut server, b"msg").unwrap_err()));
    }

    #[test]
    fn a_frost_share_counts_against_the_rate_limit() {
        let (mut server, theirs) = sealed_frost(vec![PolicyRule::MaxPerMinute(1)]);
        assert!(denied(&open(&mut server, b"early").unwrap_err()));
        server.policy_engine.advance_clock(Duration::from_secs(60));
        let session = open(&mut server, b"first").unwrap();
        assert!(shared(&finish(&mut server, session, &theirs)));
        assert!(denied(&open(&mut server, b"second").unwrap_err()));
    }

    #[test]
    fn sessions_opened_together_are_not_all_signed() {
        let (mut server, theirs) = sealed_frost(vec![PolicyRule::MaxPerMinute(1)]);
        server.policy_engine.advance_clock(Duration::from_secs(60));
        let first = open(&mut server, b"first").unwrap();
        let second = open(&mut server, b"second").unwrap();
        assert!(shared(&finish(&mut server, first, &theirs)));
        assert!(denied(&finish(&mut server, second, &theirs)));
        assert!(server.signer.frost_session_pubkey(&second).is_err());
    }

    #[test]
    fn a_session_is_not_signed_with_a_share_imported_over_its_own() {
        let rules = policy_bytes(vec![PolicyRule::MaxPerMinute(10)]);
        let (first, first_theirs, first_pubkeys) = frost_group();
        let (second, _, second_pubkeys) = frost_group();
        let mut server = bare();
        let seal = |share: &frost_secp256k1_tr::keys::KeyPackage| {
            crate::kms::seal_for_test(&[42u8; 32], &share.serialize().unwrap(), &rules)
        };
        imported(server.handle_import_encrypted_frost_key("g", &seal(&first), first_pubkeys));
        server.policy_engine.advance_clock(Duration::from_secs(60));
        let session = open(&mut server, b"msg").unwrap();
        imported(server.handle_import_encrypted_frost_key("g", &seal(&second), second_pubkeys));
        assert!(!shared(&finish(&mut server, session, &first_theirs)));
        assert!(server.signer.frost_session_pubkey(&session).is_err());
    }
}
