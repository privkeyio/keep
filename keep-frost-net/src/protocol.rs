#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub const KFP_EVENT_KIND: u16 = 24242;
pub const KFP_VERSION: u8 = 1;

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
        serde_json::from_str(json)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnnouncePayload {
    pub version: u8,
    #[serde(with = "hex_bytes")]
    pub group_pubkey: [u8; 32],
    pub share_index: u16,
    pub capabilities: Vec<String>,
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<EnclaveAttestation>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnclaveAttestation {
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
        pcr0: Vec<u8>,
        pcr1: Vec<u8>,
        pcr2: Vec<u8>,
        enclave_pubkey: Vec<u8>,
        timestamp: u64,
    ) -> Self {
        Self {
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
    pub fn new(group_pubkey: [u8; 32], share_index: u16) -> Self {
        Self {
            version: KFP_VERSION,
            group_pubkey,
            share_index,
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
    pub timestamp: u64,
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
            timestamp: chrono::Utc::now().timestamp() as u64,
            metadata: None,
        }
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_announce_serialization() {
        let payload = AnnouncePayload::new([1u8; 32], 1).with_name("test");
        let msg = KfpMessage::Announce(payload);

        let json = msg.to_json().unwrap();
        let parsed: KfpMessage = KfpMessage::from_json(&json).unwrap();

        match parsed {
            KfpMessage::Announce(p) => {
                assert_eq!(p.share_index, 1);
                assert_eq!(p.name, Some("test".into()));
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
    fn test_announce_with_attestation_serialization() {
        let attestation = EnclaveAttestation::new(
            vec![0u8; 48],
            vec![1u8; 48],
            vec![2u8; 48],
            vec![3u8; 32],
            1234567890,
        );
        let payload = AnnouncePayload::new([1u8; 32], 1)
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
        let payload = AnnouncePayload::new([1u8; 32], 1);
        let msg = KfpMessage::Announce(payload);

        let json = msg.to_json().unwrap();
        assert!(!json.contains("attestation")); // skip_serializing_if works

        let parsed: KfpMessage = KfpMessage::from_json(&json).unwrap();
        match parsed {
            KfpMessage::Announce(p) => {
                assert!(p.attestation.is_none());
            }
            _ => panic!("expected Announce"),
        }
    }
}
