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
        let (secret, policy_bytes) = match self.kms.decrypt_wallet_key(encrypted) {
            Ok(opened) => opened,
            Err(e) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("KMS decryption failed: {}", e),
                };
            }
        };
        let policy = match postcard::from_bytes::<PolicyConfig>(&policy_bytes) {
            Ok(policy) => policy,
            Err(_) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InvalidRequest,
                    message: "KMS decryption failed: invalid sealed wallet".into(),
                };
            }
        };
        if policy.policies.is_empty() || secret.len() != 32 {
            return EnclaveResponse::Error {
                code: ErrorCode::PolicyDenied,
                message: "policy denies request".into(),
            };
        }
        if self.policy_sealed && !bool::from(encrypted.policy_hash.ct_eq(&self.sealed_policy_hash))
        {
            return EnclaveResponse::Error {
                code: ErrorCode::PolicyDenied,
                message: "Policy is sealed to the key".into(),
            };
        }

        match self.signer.import_key(name, &secret) {
            Ok(pubkey) => {
                if !self.policy_sealed {
                    self.policy_engine.set_policies(policy);
                    self.policy_initialized = true;
                    self.policy_sealed = true;
                    self.sealed_policy_hash = encrypted.policy_hash;
                }
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

        let ctx = SigningContext {
            key_id: &req.key_id,
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
        if let Some(denied) = self.policy_required() {
            return denied;
        }
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
            self.enforce_destination_policies(&analysis, &req.key_id, total_spend, timestamp)
        {
            return denied;
        }

        match self.signer.sign_psbt(&req.key_id, &req.psbt, network) {
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

    /// Evaluate the policy engine against each non-change destination, or once
    /// with no destination when nothing but the fee leaves the wallet, so the
    /// amount, rate and time rules always apply. An output with no address is
    /// named `script:<hex>`, so an allowlist refuses it unless that name is
    /// listed. Returns the error response
    /// to send back if any evaluation is denied or requires approval.
    fn enforce_destination_policies(
        &mut self,
        analysis: &PsbtAnalysis,
        key_id: &str,
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
                key_id,
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
        if let Some(denied) = self.policy_required() {
            return denied;
        }
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
        if let Some(denied) = self.policy_required() {
            return denied;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Policy, PolicyAction, PolicyRule};
    use crate::psbt::fixtures::*;
    use bitcoin::psbt::Psbt;
    use bitcoin::{Address, ScriptBuf};

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
        let _ = sign_amount(&mut server, 1);
        let blob = crate::kms::seal_for_test(&[42u8; 32], &SECRET, &rate_bytes(1));
        match server.handle_import_encrypted_key("k", &blob) {
            EnclaveResponse::PublicKey { .. } => {}
            other => panic!("expected the key to import, got {other:?}"),
        }
        assert!(matches!(
            sign_amount(&mut server, 1),
            EnclaveResponse::Signature { .. }
        ));
        assert!(denied(&sign_amount(&mut server, 1)));
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
}
