#![forbid(unsafe_code)]

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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KfpMessage {
    Announce(AnnouncePayload),
    SignRequest(SignRequestPayload),
    Commitment(CommitmentPayload),
    SignatureShare(SignatureSharePayload),
    SignatureComplete(SignatureCompletePayload),
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
            KfpMessage::Error(p) => p.session_id.as_ref(),
            _ => None,
        }
    }

    pub fn group_pubkey(&self) -> Option<&[u8; 32]> {
        match self {
            KfpMessage::Announce(p) => Some(&p.group_pubkey),
            KfpMessage::SignRequest(p) => Some(&p.group_pubkey),
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
        let now = chrono::Utc::now().timestamp() as u64;
        let min_valid = now.saturating_sub(window_secs);
        let max_valid = now.saturating_add(window_secs);
        self.created_at >= min_valid && self.created_at <= max_valid
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

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod hex_bytes_33 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 33 bytes"))
    }
}

mod hex_bytes_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

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
        let too_many_caps: Vec<String> = (0..=MAX_CAPABILITIES)
            .map(|i| format!("cap{}", i))
            .collect();
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

        let mut future_payload = payload.clone();
        future_payload.created_at = chrono::Utc::now().timestamp() as u64 + 400;
        assert!(!future_payload.is_within_replay_window(DEFAULT_REPLAY_WINDOW_SECS));
        assert!(future_payload.is_within_replay_window(500));
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
