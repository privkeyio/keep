// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
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
    ImportFrostKey {
        name: String,
        key_package: Vec<u8>,
        pubkey_package: Vec<u8>,
    },
    Sign(SigningRequest),
    SignPsbt(PsbtSigningRequest),
    SetPolicy(PolicyConfig),
    GetPublicKey {
        key_id: String,
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
    /// A FROST key package sealed with its policy, like `ImportEncryptedKey`.
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
    MaxFeeSats(u64),
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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

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
        let digest: [u8; 32] = sha2::Sha256::digest(wire_sample()).into();
        assert_eq!(hex::encode(digest), WIRE_DIGEST);
    }

    #[test]
    fn max_fee_keeps_the_previous_rule_indexes() {
        let allow = postcard::to_allocvec(&PolicyRule::AddressAllowlist(vec!["a".into()])).unwrap();
        assert_eq!(allow[0], 4);
        let fee = postcard::to_allocvec(&PolicyRule::MaxFeeSats(9)).unwrap();
        assert_eq!(fee[0], 11);
    }
}
