// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use serde::{Deserialize, Serialize};

pub const KFP_EVENT_KIND: u16 = 24242;
pub const KFP_VERSION: u8 = 1;
pub const DEFAULT_REPLAY_WINDOW_SECS: u64 = 300;

pub const MAX_MESSAGE_SIZE: usize = 65536;
pub const MAX_COMMITMENT_SIZE: usize = 128;
pub const MAX_SIGNATURE_SHARE_SIZE: usize = 64;
pub const MAX_PARTICIPANTS: usize = 255;
pub const MAX_NAME_LENGTH: usize = 256;
pub const MAX_CAPABILITY_LENGTH: usize = 64;
pub const MAX_CAPABILITIES: usize = 32;
pub const MAX_ERROR_CODE_LENGTH: usize = 64;
pub const MAX_ERROR_MESSAGE_LENGTH: usize = 1024;
pub const MAX_MESSAGE_TYPE_LENGTH: usize = 64;
pub const MAX_RECOVERY_TIERS: usize = 10;
pub const MAX_KEYS_PER_TIER: usize = 20;
pub const MAX_XPUB_LENGTH: usize = 256;
pub const MAX_FINGERPRINT_LENGTH: usize = 8;
pub const DESCRIPTOR_SESSION_TIMEOUT_SECS: u64 = 600;
pub const MAX_DESCRIPTOR_LENGTH: usize = 4096;
pub const VALID_NETWORKS: &[&str] = &["bitcoin", "testnet", "signet", "regtest"];

const MAX_FUTURE_SKEW_SECS: u64 = 30;

fn within_replay_window(created_at: u64, window_secs: u64) -> bool {
    let now = chrono::Utc::now().timestamp() as u64;
    let min_valid = now.saturating_sub(window_secs);
    let max_valid = now.saturating_add(MAX_FUTURE_SKEW_SECS);
    created_at >= min_valid && created_at <= max_valid
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KfpMessage {
    Announce(AnnouncePayload),
    SignRequest(SignRequestPayload),
    Commitment(CommitmentPayload),
    SignatureShare(SignatureSharePayload),
    SignatureComplete(SignatureCompletePayload),
    EcdhRequest(EcdhRequestPayload),
    EcdhShare(EcdhSharePayload),
    EcdhComplete(EcdhCompletePayload),
    RefreshRequest(RefreshRequestPayload),
    RefreshRound1(RefreshRound1Payload),
    RefreshRound2(RefreshRound2Payload),
    RefreshComplete(RefreshCompletePayload),
    DescriptorPropose(DescriptorProposePayload),
    DescriptorContribute(DescriptorContributePayload),
    DescriptorFinalize(DescriptorFinalizePayload),
    DescriptorAck(DescriptorAckPayload),
    Ping(PingPayload),
    Pong(PongPayload),
    Error(ErrorPayload),
}

impl KfpMessage {
    pub fn message_type(&self) -> &'static str {
        match self {
            KfpMessage::Announce(_) => "announce",
            KfpMessage::SignRequest(_) => "sign_request",
            KfpMessage::Commitment(_) => "commitment",
            KfpMessage::SignatureShare(_) => "signature_share",
            KfpMessage::SignatureComplete(_) => "signature_complete",
            KfpMessage::EcdhRequest(_) => "ecdh_request",
            KfpMessage::EcdhShare(_) => "ecdh_share",
            KfpMessage::EcdhComplete(_) => "ecdh_complete",
            KfpMessage::RefreshRequest(_) => "refresh_request",
            KfpMessage::RefreshRound1(_) => "refresh_round1",
            KfpMessage::RefreshRound2(_) => "refresh_round2",
            KfpMessage::RefreshComplete(_) => "refresh_complete",
            KfpMessage::DescriptorPropose(_) => "descriptor_propose",
            KfpMessage::DescriptorContribute(_) => "descriptor_contribute",
            KfpMessage::DescriptorFinalize(_) => "descriptor_finalize",
            KfpMessage::DescriptorAck(_) => "descriptor_ack",
            KfpMessage::Ping(_) => "ping",
            KfpMessage::Pong(_) => "pong",
            KfpMessage::Error(_) => "error",
        }
    }

    pub fn session_id(&self) -> Option<&[u8; 32]> {
        match self {
            KfpMessage::SignRequest(p) => Some(&p.session_id),
            KfpMessage::Commitment(p) => Some(&p.session_id),
            KfpMessage::SignatureShare(p) => Some(&p.session_id),
            KfpMessage::SignatureComplete(p) => Some(&p.session_id),
            KfpMessage::EcdhRequest(p) => Some(&p.session_id),
            KfpMessage::EcdhShare(p) => Some(&p.session_id),
            KfpMessage::EcdhComplete(p) => Some(&p.session_id),
            KfpMessage::RefreshRequest(p) => Some(&p.session_id),
            KfpMessage::RefreshRound1(p) => Some(&p.session_id),
            KfpMessage::RefreshRound2(p) => Some(&p.session_id),
            KfpMessage::RefreshComplete(p) => Some(&p.session_id),
            KfpMessage::DescriptorPropose(p) => Some(&p.session_id),
            KfpMessage::DescriptorContribute(p) => Some(&p.session_id),
            KfpMessage::DescriptorFinalize(p) => Some(&p.session_id),
            KfpMessage::DescriptorAck(p) => Some(&p.session_id),
            KfpMessage::Error(p) => p.session_id.as_ref(),
            _ => None,
        }
    }

    pub fn group_pubkey(&self) -> Option<&[u8; 32]> {
        match self {
            KfpMessage::Announce(p) => Some(&p.group_pubkey),
            KfpMessage::SignRequest(p) => Some(&p.group_pubkey),
            KfpMessage::EcdhRequest(p) => Some(&p.group_pubkey),
            KfpMessage::RefreshRequest(p) => Some(&p.group_pubkey),
            KfpMessage::DescriptorPropose(p) => Some(&p.group_pubkey),
            KfpMessage::DescriptorContribute(p) => Some(&p.group_pubkey),
            KfpMessage::DescriptorFinalize(p) => Some(&p.group_pubkey),
            KfpMessage::DescriptorAck(p) => Some(&p.group_pubkey),
            _ => None,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        use serde::de::Error;
        let msg: Self = serde_json::from_str(json)?;
        msg.validate().map_err(serde_json::Error::custom)?;
        Ok(msg)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            KfpMessage::Announce(p) => {
                if p.share_index == 0 {
                    return Err("share_index must be non-zero");
                }
                if let Some(ref name) = p.name {
                    if name.len() > MAX_NAME_LENGTH {
                        return Err("Name exceeds maximum length");
                    }
                }
                if p.capabilities.len() > MAX_CAPABILITIES {
                    return Err("Too many capabilities");
                }
                for cap in &p.capabilities {
                    if cap.len() > MAX_CAPABILITY_LENGTH {
                        return Err("Capability string exceeds maximum length");
                    }
                }
            }
            KfpMessage::SignRequest(p) => {
                if p.message.len() > MAX_MESSAGE_SIZE {
                    return Err("Message exceeds maximum size");
                }
                if p.message_type.len() > MAX_MESSAGE_TYPE_LENGTH {
                    return Err("Message type exceeds maximum length");
                }
                if p.participants.len() > MAX_PARTICIPANTS {
                    return Err("Participants list exceeds maximum size");
                }
            }
            KfpMessage::Commitment(p) => {
                if p.commitment.len() > MAX_COMMITMENT_SIZE {
                    return Err("Commitment exceeds maximum size");
                }
            }
            KfpMessage::SignatureShare(p) => {
                if p.signature_share.len() > MAX_SIGNATURE_SHARE_SIZE {
                    return Err("Signature share exceeds maximum size");
                }
            }
            KfpMessage::Error(p) => {
                if p.code.len() > MAX_ERROR_CODE_LENGTH {
                    return Err("Error code exceeds maximum length");
                }
                if p.message.len() > MAX_ERROR_MESSAGE_LENGTH {
                    return Err("Error message exceeds maximum length");
                }
            }
            KfpMessage::EcdhRequest(p) => {
                if p.participants.len() > MAX_PARTICIPANTS {
                    return Err("Participants list exceeds maximum size");
                }
            }
            KfpMessage::EcdhShare(p) => {
                if p.partial_point.len() != 33 {
                    return Err("Invalid partial point size");
                }
            }
            KfpMessage::EcdhComplete(p) => {
                if p.shared_secret.len() != 32 {
                    return Err("Invalid shared secret size");
                }
            }
            KfpMessage::RefreshRequest(p) => {
                if p.participants.len() > MAX_PARTICIPANTS {
                    return Err("Participants list exceeds maximum size");
                }
                if p.participants.len() < 2 {
                    return Err("Refresh requires at least 2 participants");
                }
                if p.participants.contains(&0) {
                    return Err("Participant index must be non-zero");
                }
                let unique: std::collections::HashSet<_> = p.participants.iter().collect();
                if unique.len() != p.participants.len() {
                    return Err("Duplicate participant indices");
                }
            }
            KfpMessage::RefreshRound1(p) => {
                if p.package.is_empty() {
                    return Err("Package must not be empty");
                }
                if p.package.len() > MAX_MESSAGE_SIZE {
                    return Err("Round1 package exceeds maximum size");
                }
                if p.share_index == 0 {
                    return Err("share_index must be non-zero");
                }
            }
            KfpMessage::RefreshRound2(p) => {
                if p.package.is_empty() {
                    return Err("Package must not be empty");
                }
                if p.package.len() > MAX_MESSAGE_SIZE {
                    return Err("Round2 package exceeds maximum size");
                }
                if p.share_index == 0 {
                    return Err("share_index must be non-zero");
                }
                if p.target_index == 0 {
                    return Err("target_index must be non-zero");
                }
                if p.share_index == p.target_index {
                    return Err("share_index must differ from target_index");
                }
            }
            KfpMessage::RefreshComplete(p) => {
                if p.share_index == 0 {
                    return Err("share_index must be non-zero");
                }
            }
            KfpMessage::DescriptorPropose(p) => {
                if !VALID_NETWORKS.contains(&p.network.as_str()) {
                    return Err("Invalid network value");
                }
                if p.initiator_xpub.is_empty() {
                    return Err("Initiator xpub cannot be empty");
                }
                if p.initiator_xpub.len() > MAX_XPUB_LENGTH {
                    return Err("Initiator xpub exceeds maximum length");
                }
                if p.initiator_fingerprint.is_empty() {
                    return Err("Initiator fingerprint cannot be empty");
                }
                if p.initiator_fingerprint.len() > MAX_FINGERPRINT_LENGTH {
                    return Err("Initiator fingerprint exceeds maximum length");
                }
                if p.policy.recovery_tiers.is_empty() {
                    return Err("Policy must have at least one recovery tier");
                }
                if p.policy.recovery_tiers.len() > MAX_RECOVERY_TIERS {
                    return Err("Too many recovery tiers");
                }
                for tier in &p.policy.recovery_tiers {
                    if tier.key_slots.len() > MAX_KEYS_PER_TIER {
                        return Err("Too many keys in tier");
                    }
                    if tier.threshold == 0 {
                        return Err("Tier threshold must be non-zero");
                    }
                    if tier.timelock_months == 0 {
                        return Err("Tier timelock must be non-zero");
                    }
                    if tier.threshold as usize > tier.key_slots.len() {
                        return Err("Tier threshold exceeds number of key slots");
                    }
                    for slot in &tier.key_slots {
                        if let KeySlot::External { xpub, fingerprint } = slot {
                            if xpub.len() > MAX_XPUB_LENGTH {
                                return Err("External xpub exceeds maximum length");
                            }
                            if fingerprint.len() > MAX_FINGERPRINT_LENGTH {
                                return Err("External fingerprint exceeds maximum length");
                            }
                        }
                    }
                }
            }
            KfpMessage::DescriptorContribute(p) => {
                if p.share_index == 0 {
                    return Err("share_index must be non-zero");
                }
                if p.account_xpub.is_empty() {
                    return Err("Account xpub cannot be empty");
                }
                if p.account_xpub.len() > MAX_XPUB_LENGTH {
                    return Err("Account xpub exceeds maximum length");
                }
                if p.fingerprint.is_empty() {
                    return Err("Fingerprint cannot be empty");
                }
                if p.fingerprint.len() > MAX_FINGERPRINT_LENGTH {
                    return Err("Fingerprint exceeds maximum length");
                }
            }
            KfpMessage::DescriptorFinalize(p) => {
                if p.external_descriptor.is_empty() {
                    return Err("External descriptor cannot be empty");
                }
                if p.internal_descriptor.is_empty() {
                    return Err("Internal descriptor cannot be empty");
                }
                if p.external_descriptor.len() > MAX_DESCRIPTOR_LENGTH {
                    return Err("External descriptor exceeds maximum length");
                }
                if p.internal_descriptor.len() > MAX_DESCRIPTOR_LENGTH {
                    return Err("Internal descriptor exceeds maximum length");
                }
                if p.contributions.len() > MAX_PARTICIPANTS {
                    return Err("Too many contributions in finalize payload");
                }
                for contrib in p.contributions.values() {
                    if contrib.account_xpub.len() > MAX_XPUB_LENGTH {
                        return Err("Contribution xpub exceeds maximum length");
                    }
                    if contrib.fingerprint.len() > MAX_FINGERPRINT_LENGTH {
                        return Err("Contribution fingerprint exceeds maximum length");
                    }
                }
            }
            KfpMessage::DescriptorAck(_) => {}
            _ => {}
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnnouncePayload {
    pub version: u8,
    #[serde(with = "hex_bytes")]
    pub group_pubkey: [u8; 32],
    pub share_index: u16,
    #[serde(with = "hex_bytes_33")]
    pub verifying_share: [u8; 33],
    #[serde(with = "hex_bytes_64")]
    pub proof_signature: [u8; 64],
    pub timestamp: u64,
    pub capabilities: Vec<String>,
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<EnclaveAttestation>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnclaveAttestation {
    #[serde(with = "base64_vec")]
    pub document: Vec<u8>,
    #[serde(with = "hex_vec")]
    pub pcr0: Vec<u8>,
    #[serde(with = "hex_vec")]
    pub pcr1: Vec<u8>,
    #[serde(with = "hex_vec")]
    pub pcr2: Vec<u8>,
    #[serde(with = "hex_vec")]
    pub enclave_pubkey: Vec<u8>,
    pub timestamp: u64,
}

impl EnclaveAttestation {
    pub fn new(
        document: Vec<u8>,
        pcr0: Vec<u8>,
        pcr1: Vec<u8>,
        pcr2: Vec<u8>,
        enclave_pubkey: Vec<u8>,
        timestamp: u64,
    ) -> Self {
        Self {
            document,
            pcr0,
            pcr1,
            pcr2,
            enclave_pubkey,
            timestamp,
        }
    }

    pub fn pcrs_map(&self) -> std::collections::HashMap<u32, Vec<u8>> {
        let mut map = std::collections::HashMap::new();
        map.insert(0, self.pcr0.clone());
        map.insert(1, self.pcr1.clone());
        map.insert(2, self.pcr2.clone());
        map
    }
}

impl AnnouncePayload {
    pub fn new(
        group_pubkey: [u8; 32],
        share_index: u16,
        verifying_share: [u8; 33],
        proof_signature: [u8; 64],
        timestamp: u64,
    ) -> Self {
        Self {
            version: KFP_VERSION,
            group_pubkey,
            share_index,
            verifying_share,
            proof_signature,
            timestamp,
            capabilities: vec!["sign".into()],
            name: None,
            attestation: None,
        }
    }

    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    pub fn with_capabilities(mut self, caps: Vec<String>) -> Self {
        self.capabilities = caps;
        self
    }

    pub fn with_attestation(mut self, attestation: EnclaveAttestation) -> Self {
        self.attestation = Some(attestation);
        self
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignRequestPayload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub group_pubkey: [u8; 32],
    #[serde(with = "hex_vec")]
    pub message: Vec<u8>,
    pub message_type: String,
    pub participants: Vec<u16>,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl SignRequestPayload {
    pub fn new(
        session_id: [u8; 32],
        group_pubkey: [u8; 32],
        message: Vec<u8>,
        message_type: &str,
        participants: Vec<u16>,
    ) -> Self {
        Self {
            session_id,
            group_pubkey,
            message,
            message_type: message_type.to_string(),
            participants,
            created_at: chrono::Utc::now().timestamp() as u64,
            metadata: None,
        }
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn is_within_replay_window(&self, window_secs: u64) -> bool {
        within_replay_window(self.created_at, window_secs)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CommitmentPayload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    pub share_index: u16,
    #[serde(with = "hex_vec")]
    pub commitment: Vec<u8>,
}

impl CommitmentPayload {
    pub fn new(session_id: [u8; 32], share_index: u16, commitment: Vec<u8>) -> Self {
        Self {
            session_id,
            share_index,
            commitment,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignatureSharePayload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    pub share_index: u16,
    #[serde(with = "hex_vec")]
    pub signature_share: Vec<u8>,
}

impl SignatureSharePayload {
    pub fn new(session_id: [u8; 32], share_index: u16, signature_share: Vec<u8>) -> Self {
        Self {
            session_id,
            share_index,
            signature_share,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignatureCompletePayload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    #[serde(with = "hex_bytes_64")]
    pub signature: [u8; 64],
    #[serde(with = "hex_bytes")]
    pub message_hash: [u8; 32],
}

impl SignatureCompletePayload {
    pub fn new(session_id: [u8; 32], signature: [u8; 64], message_hash: [u8; 32]) -> Self {
        Self {
            session_id,
            signature,
            message_hash,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PingPayload {
    #[serde(with = "hex_bytes")]
    pub challenge: [u8; 32],
    pub timestamp: u64,
}

impl PingPayload {
    pub fn new() -> Self {
        Self {
            challenge: keep_core::crypto::random_bytes::<32>(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }
}

impl Default for PingPayload {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PongPayload {
    #[serde(with = "hex_bytes")]
    pub challenge: [u8; 32],
    pub timestamp: u64,
}

impl PongPayload {
    pub fn from_ping(ping: &PingPayload) -> Self {
        Self {
            challenge: ping.challenge,
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ErrorPayload {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "hex_bytes_option")]
    pub session_id: Option<[u8; 32]>,
    pub code: String,
    pub message: String,
}

impl ErrorPayload {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            session_id: None,
            code: code.to_string(),
            message: message.to_string(),
        }
    }

    pub fn with_session(mut self, session_id: [u8; 32]) -> Self {
        self.session_id = Some(session_id);
        self
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EcdhRequestPayload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub group_pubkey: [u8; 32],
    #[serde(with = "hex_bytes_33")]
    pub recipient_pubkey: [u8; 33],
    pub participants: Vec<u16>,
    pub created_at: u64,
}

impl EcdhRequestPayload {
    pub fn new(
        session_id: [u8; 32],
        group_pubkey: [u8; 32],
        recipient_pubkey: [u8; 33],
        participants: Vec<u16>,
    ) -> Self {
        Self {
            session_id,
            group_pubkey,
            recipient_pubkey,
            participants,
            created_at: chrono::Utc::now().timestamp() as u64,
        }
    }

    pub fn is_within_replay_window(&self, window_secs: u64) -> bool {
        within_replay_window(self.created_at, window_secs)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EcdhSharePayload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    pub share_index: u16,
    #[serde(with = "hex_vec")]
    pub partial_point: Vec<u8>,
}

impl EcdhSharePayload {
    pub fn new(session_id: [u8; 32], share_index: u16, partial_point: Vec<u8>) -> Self {
        Self {
            session_id,
            share_index,
            partial_point,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EcdhCompletePayload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    #[serde(with = "hex_vec")]
    pub shared_secret: Vec<u8>,
}

impl EcdhCompletePayload {
    pub fn new(session_id: [u8; 32], shared_secret: [u8; 32]) -> Self {
        Self {
            session_id,
            shared_secret: shared_secret.to_vec(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RefreshRequestPayload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub group_pubkey: [u8; 32],
    pub participants: Vec<u16>,
    pub created_at: u64,
}

impl RefreshRequestPayload {
    pub fn new(session_id: [u8; 32], group_pubkey: [u8; 32], participants: Vec<u16>) -> Self {
        Self {
            session_id,
            group_pubkey,
            participants,
            created_at: chrono::Utc::now().timestamp() as u64,
        }
    }

    pub fn is_within_replay_window(&self, window_secs: u64) -> bool {
        within_replay_window(self.created_at, window_secs)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RefreshRound1Payload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    pub share_index: u16,
    #[serde(with = "hex_vec")]
    pub package: Vec<u8>,
    pub created_at: u64,
}

impl RefreshRound1Payload {
    pub fn new(session_id: [u8; 32], share_index: u16, package: Vec<u8>) -> Self {
        Self {
            session_id,
            share_index,
            package,
            created_at: chrono::Utc::now().timestamp() as u64,
        }
    }

    pub fn is_within_replay_window(&self, window_secs: u64) -> bool {
        within_replay_window(self.created_at, window_secs)
    }
}

impl std::fmt::Debug for RefreshRound1Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshRound1Payload")
            .field("session_id", &hex::encode(self.session_id))
            .field("share_index", &self.share_index)
            .field("package", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RefreshRound2Payload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    pub share_index: u16,
    pub target_index: u16,
    #[serde(with = "hex_vec")]
    pub package: Vec<u8>,
    pub created_at: u64,
}

impl RefreshRound2Payload {
    pub fn new(
        session_id: [u8; 32],
        share_index: u16,
        target_index: u16,
        package: Vec<u8>,
    ) -> Self {
        Self {
            session_id,
            share_index,
            target_index,
            package,
            created_at: chrono::Utc::now().timestamp() as u64,
        }
    }

    pub fn is_within_replay_window(&self, window_secs: u64) -> bool {
        within_replay_window(self.created_at, window_secs)
    }
}

impl std::fmt::Debug for RefreshRound2Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshRound2Payload")
            .field("session_id", &hex::encode(self.session_id))
            .field("share_index", &self.share_index)
            .field("target_index", &self.target_index)
            .field("package", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RefreshCompletePayload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    pub share_index: u16,
    pub success: bool,
    pub created_at: u64,
}

impl RefreshCompletePayload {
    pub fn new(session_id: [u8; 32], share_index: u16, success: bool) -> Self {
        Self {
            session_id,
            share_index,
            success,
            created_at: chrono::Utc::now().timestamp() as u64,
        }
    }

    pub fn is_within_replay_window(&self, window_secs: u64) -> bool {
        within_replay_window(self.created_at, window_secs)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WalletPolicy {
    pub recovery_tiers: Vec<PolicyTier>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PolicyTier {
    pub threshold: u32,
    pub key_slots: Vec<KeySlot>,
    pub timelock_months: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeySlot {
    Participant { share_index: u16 },
    External { xpub: String, fingerprint: String },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DescriptorProposePayload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub group_pubkey: [u8; 32],
    pub created_at: u64,
    pub network: String,
    pub policy: WalletPolicy,
    pub initiator_xpub: String,
    pub initiator_fingerprint: String,
}

impl DescriptorProposePayload {
    pub fn new(
        session_id: [u8; 32],
        group_pubkey: [u8; 32],
        network: &str,
        policy: WalletPolicy,
        initiator_xpub: &str,
        initiator_fingerprint: &str,
    ) -> Self {
        Self {
            session_id,
            group_pubkey,
            created_at: chrono::Utc::now().timestamp() as u64,
            network: network.to_string(),
            policy,
            initiator_xpub: initiator_xpub.to_string(),
            initiator_fingerprint: initiator_fingerprint.to_string(),
        }
    }

    pub fn is_within_replay_window(&self, window_secs: u64) -> bool {
        within_replay_window(self.created_at, window_secs)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DescriptorContributePayload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub group_pubkey: [u8; 32],
    pub share_index: u16,
    pub account_xpub: String,
    pub fingerprint: String,
    pub created_at: u64,
}

impl DescriptorContributePayload {
    pub fn new(
        session_id: [u8; 32],
        group_pubkey: [u8; 32],
        share_index: u16,
        account_xpub: &str,
        fingerprint: &str,
    ) -> Self {
        Self {
            session_id,
            group_pubkey,
            share_index,
            account_xpub: account_xpub.to_string(),
            fingerprint: fingerprint.to_string(),
            created_at: chrono::Utc::now().timestamp() as u64,
        }
    }

    pub fn is_within_replay_window(&self, window_secs: u64) -> bool {
        within_replay_window(self.created_at, window_secs)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DescriptorFinalizePayload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub group_pubkey: [u8; 32],
    pub external_descriptor: String,
    pub internal_descriptor: String,
    #[serde(with = "hex_bytes")]
    pub policy_hash: [u8; 32],
    pub contributions: std::collections::BTreeMap<u16, crate::descriptor_session::XpubContribution>,
    pub created_at: u64,
}

impl DescriptorFinalizePayload {
    pub fn new(
        session_id: [u8; 32],
        group_pubkey: [u8; 32],
        external_descriptor: &str,
        internal_descriptor: &str,
        policy_hash: [u8; 32],
        contributions: std::collections::BTreeMap<u16, crate::descriptor_session::XpubContribution>,
    ) -> Self {
        Self {
            session_id,
            group_pubkey,
            external_descriptor: external_descriptor.to_string(),
            internal_descriptor: internal_descriptor.to_string(),
            policy_hash,
            contributions,
            created_at: chrono::Utc::now().timestamp() as u64,
        }
    }

    pub fn is_within_replay_window(&self, window_secs: u64) -> bool {
        within_replay_window(self.created_at, window_secs)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DescriptorAckPayload {
    #[serde(with = "hex_bytes")]
    pub session_id: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub group_pubkey: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub descriptor_hash: [u8; 32],
    pub created_at: u64,
}

impl DescriptorAckPayload {
    pub fn new(session_id: [u8; 32], group_pubkey: [u8; 32], descriptor_hash: [u8; 32]) -> Self {
        Self {
            session_id,
            group_pubkey,
            descriptor_hash,
            created_at: chrono::Utc::now().timestamp() as u64,
        }
    }

    pub fn is_within_replay_window(&self, window_secs: u64) -> bool {
        within_replay_window(self.created_at, window_secs)
    }
}

macro_rules! hex_bytes_serde {
    ($mod_name:ident, $size:expr) => {
        mod $mod_name {
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S>(bytes: &[u8; $size], serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&hex::encode(bytes))
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; $size], D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom(format!("expected {} bytes", $size)))
            }
        }
    };
}

hex_bytes_serde!(hex_bytes, 32);
hex_bytes_serde!(hex_bytes_33, 33);
hex_bytes_serde!(hex_bytes_64, 64);

mod hex_bytes_option {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

mod base64_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use base64::Engine;
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use base64::Engine;
        let s = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_announce_serialization() {
        let payload =
            AnnouncePayload::new([1u8; 32], 1, [2u8; 33], [3u8; 64], 1234567890).with_name("test");
        let msg = KfpMessage::Announce(payload);

        let json = msg.to_json().unwrap();
        let parsed: KfpMessage = KfpMessage::from_json(&json).unwrap();

        match parsed {
            KfpMessage::Announce(p) => {
                assert_eq!(p.share_index, 1);
                assert_eq!(p.name, Some("test".into()));
                assert_eq!(p.verifying_share, [2u8; 33]);
                assert_eq!(p.proof_signature, [3u8; 64]);
                assert_eq!(p.timestamp, 1234567890);
            }
            _ => panic!("expected Announce"),
        }
    }

    #[test]
    fn test_sign_request_serialization() {
        let payload =
            SignRequestPayload::new([2u8; 32], [3u8; 32], vec![4, 5, 6], "raw", vec![1, 2]);

        let msg = KfpMessage::SignRequest(payload);
        let json = msg.to_json().unwrap();
        let parsed: KfpMessage = KfpMessage::from_json(&json).unwrap();

        match parsed {
            KfpMessage::SignRequest(p) => {
                assert_eq!(p.message, vec![4, 5, 6]);
                assert_eq!(p.participants, vec![1, 2]);
            }
            _ => panic!("expected SignRequest"),
        }
    }

    #[test]
    fn test_message_type() {
        let msg = KfpMessage::Ping(PingPayload::new());
        assert_eq!(msg.message_type(), "ping");
    }

    #[test]
    fn test_message_size_limit() {
        let oversized_message = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let payload =
            SignRequestPayload::new([1u8; 32], [2u8; 32], oversized_message, "raw", vec![1, 2]);
        let msg = KfpMessage::SignRequest(payload);
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_participants_limit() {
        let too_many_participants: Vec<u16> = (0..=MAX_PARTICIPANTS as u16).collect();
        let payload = SignRequestPayload::new(
            [1u8; 32],
            [2u8; 32],
            vec![1, 2, 3],
            "raw",
            too_many_participants,
        );
        let msg = KfpMessage::SignRequest(payload);
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_commitment_size_limit() {
        let oversized_commitment = vec![0u8; MAX_COMMITMENT_SIZE + 1];
        let payload = CommitmentPayload::new([1u8; 32], 1, oversized_commitment);
        let msg = KfpMessage::Commitment(payload);
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_signature_share_size_limit() {
        let oversized_share = vec![0u8; MAX_SIGNATURE_SHARE_SIZE + 1];
        let payload = SignatureSharePayload::new([1u8; 32], 1, oversized_share);
        let msg = KfpMessage::SignatureShare(payload);
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_valid_message_passes_validation() {
        let payload =
            SignRequestPayload::new([1u8; 32], [2u8; 32], vec![1, 2, 3], "raw", vec![1, 2]);
        let msg = KfpMessage::SignRequest(payload);
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn test_announce_name_limit() {
        let oversized_name = "a".repeat(MAX_NAME_LENGTH + 1);
        let payload = AnnouncePayload::new([1u8; 32], 1, [2u8; 33], [3u8; 64], 1234567890)
            .with_name(&oversized_name);
        let msg = KfpMessage::Announce(payload);
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_announce_capabilities_count_limit() {
        let too_many_caps: Vec<String> =
            (0..=MAX_CAPABILITIES).map(|i| format!("cap{i}")).collect();
        let mut payload = AnnouncePayload::new([1u8; 32], 1, [2u8; 33], [3u8; 64], 1234567890);
        payload.capabilities = too_many_caps;
        let msg = KfpMessage::Announce(payload);
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_announce_capability_length_limit() {
        let oversized_cap = "a".repeat(MAX_CAPABILITY_LENGTH + 1);
        let mut payload = AnnouncePayload::new([1u8; 32], 1, [2u8; 33], [3u8; 64], 1234567890);
        payload.capabilities = vec![oversized_cap];
        let msg = KfpMessage::Announce(payload);
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_error_code_limit() {
        let oversized_code = "a".repeat(MAX_ERROR_CODE_LENGTH + 1);
        let payload = ErrorPayload::new(&oversized_code, "test");
        let msg = KfpMessage::Error(payload);
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_error_message_limit() {
        let oversized_message = "a".repeat(MAX_ERROR_MESSAGE_LENGTH + 1);
        let payload = ErrorPayload::new("test", &oversized_message);
        let msg = KfpMessage::Error(payload);
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_valid_announce_passes_validation() {
        let payload = AnnouncePayload::new([1u8; 32], 1, [2u8; 33], [3u8; 64], 1234567890)
            .with_name("Test Node")
            .with_capabilities(vec!["sign".into()]);
        let msg = KfpMessage::Announce(payload);
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn test_valid_error_passes_validation() {
        let payload = ErrorPayload::new("invalid_session", "Session not found");
        let msg = KfpMessage::Error(payload);
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn test_message_type_limit() {
        let oversized_type = "a".repeat(MAX_MESSAGE_TYPE_LENGTH + 1);
        let payload = SignRequestPayload::new(
            [1u8; 32],
            [2u8; 32],
            vec![1, 2, 3],
            &oversized_type,
            vec![1, 2],
        );
        let msg = KfpMessage::SignRequest(payload);
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_replay_window_validation() {
        let payload =
            SignRequestPayload::new([1u8; 32], [2u8; 32], vec![3, 4, 5], "raw", vec![1, 2]);

        assert!(payload.is_within_replay_window(DEFAULT_REPLAY_WINDOW_SECS));
        assert!(payload.is_within_replay_window(60));
        assert!(payload.is_within_replay_window(1));

        let mut old_payload = payload.clone();
        old_payload.created_at = chrono::Utc::now().timestamp() as u64 - 400;
        assert!(!old_payload.is_within_replay_window(DEFAULT_REPLAY_WINDOW_SECS));
        assert!(old_payload.is_within_replay_window(500));

        let mut slight_future = payload.clone();
        slight_future.created_at = chrono::Utc::now().timestamp() as u64 + 10;
        assert!(slight_future.is_within_replay_window(DEFAULT_REPLAY_WINDOW_SECS));

        let mut far_future = payload.clone();
        far_future.created_at = chrono::Utc::now().timestamp() as u64 + 400;
        assert!(!far_future.is_within_replay_window(DEFAULT_REPLAY_WINDOW_SECS));
        assert!(!far_future.is_within_replay_window(500));
    }

    #[test]
    fn test_announce_with_attestation_serialization() {
        let attestation = EnclaveAttestation::new(
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            vec![0u8; 48],
            vec![1u8; 48],
            vec![2u8; 48],
            vec![3u8; 32],
            1234567890,
        );
        let payload = AnnouncePayload::new([1u8; 32], 1, [2u8; 33], [3u8; 64], 1234567890)
            .with_name("test-enclave")
            .with_attestation(attestation);
        let msg = KfpMessage::Announce(payload);

        let json = msg.to_json().unwrap();
        let parsed: KfpMessage = KfpMessage::from_json(&json).unwrap();

        match parsed {
            KfpMessage::Announce(p) => {
                assert_eq!(p.share_index, 1);
                assert_eq!(p.name, Some("test-enclave".into()));
                let att = p.attestation.expect("attestation should be present");
                assert_eq!(att.document, vec![0xDE, 0xAD, 0xBE, 0xEF]);
                assert_eq!(att.pcr0.len(), 48);
                assert_eq!(att.pcr1.len(), 48);
                assert_eq!(att.pcr2.len(), 48);
                assert_eq!(att.pcr0[0], 0);
                assert_eq!(att.pcr1[0], 1);
                assert_eq!(att.pcr2[0], 2);
                assert_eq!(att.enclave_pubkey.len(), 32);
                assert_eq!(att.timestamp, 1234567890);
            }
            _ => panic!("expected Announce"),
        }
    }

    #[test]
    fn test_announce_without_attestation_serialization() {
        let payload = AnnouncePayload::new([1u8; 32], 1, [2u8; 33], [3u8; 64], 1234567890);
        let msg = KfpMessage::Announce(payload);

        let json = msg.to_json().unwrap();
        assert!(!json.contains("attestation"));

        let parsed: KfpMessage = KfpMessage::from_json(&json).unwrap();
        match parsed {
            KfpMessage::Announce(p) => {
                assert!(p.attestation.is_none());
            }
            _ => panic!("expected Announce"),
        }
    }
}
