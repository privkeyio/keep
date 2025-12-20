#![forbid(unsafe_code)]

use crate::kms::EncryptedWallet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnclaveRequest {
    GetAttestation {
        nonce: [u8; 32],
    },
    GenerateKey {
        name: String,
    },
    ImportKey {
        name: String,
        secret: Vec<u8>,
    },
    ImportEncryptedKey {
        name: String,
        encrypted: EncryptedWallet,
    },
    Sign(SigningRequest),
    SignPsbt(PsbtSigningRequest),
    SetPolicy(PolicyConfig),
    GetPublicKey {
        key_id: String,
    },
    ImportFrostKey {
        name: String,
        key_package: Vec<u8>,
        pubkey_package: Vec<u8>,
    },
    FrostRound1 {
        key_id: String,
        message: Vec<u8>,
        nonce: Option<[u8; 32]>,
        timestamp: Option<u64>,
    },
    FrostAddCommitment {
        session_id: [u8; 32],
        identifier: Vec<u8>,
        commitment: Vec<u8>,
    },
    FrostRound2 {
        session_id: [u8; 32],
        nonce: Option<[u8; 32]>,
        timestamp: Option<u64>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnclaveResponse {
    Attestation {
        document: Vec<u8>,
    },
    PublicKey {
        pubkey: Vec<u8>,
        name: String,
    },
    Signature {
        signature: Vec<u8>,
    },
    SignedPsbt {
        psbt: Vec<u8>,
        signed_inputs: usize,
    },
    PolicySet,
    FrostCommitment {
        commitment: Vec<u8>,
        nonces_id: Vec<u8>,
    },
    FrostShare {
        share: Vec<u8>,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidRequest,
    PolicyDenied,
    RateLimitExceeded,
    KeyNotFound,
    SigningFailed,
    InternalError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub rules: Vec<PolicyRule>,
    pub action: PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyRule {
    MaxAmountSats(u64),
    MaxPerMinute(u32),
    MaxPerHour(u32),
    MaxPerDay(u32),
    AddressAllowlist(Vec<String>),
    AddressBlocklist(Vec<String>),
    AllowedHours { start: u8, end: u8 },
    BlockWeekends,
    AllowedEventKinds(Vec<u32>),
    And(Vec<PolicyRule>),
    Or(Vec<PolicyRule>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow,
    Deny,
    RequireApproval,
}

pub const VSOCK_PORT: u32 = 5000;
pub const ENCLAVE_CID: u32 = 16;
