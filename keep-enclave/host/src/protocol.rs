use serde::{Deserialize, Serialize};

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
    Signature { signature: Vec<u8> },
    SignedPsbt { psbt: Vec<u8>, signed_inputs: usize },
    PolicySet,
    FrostCommitment { commitment: Vec<u8>, nonces_id: [u8; 32] },
    FrostShare { share: Vec<u8> },
    Error { code: ErrorCode, message: String },
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
