#![forbid(unsafe_code)]

use bech32::{Bech32m, Hrp};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::{KeepError, Result};

use super::share::SharePackage;

const SHARE_HRP: &str = "kshare";
const MAX_FRAME_COUNT: usize = 100;
const MAX_ASSEMBLED_SIZE: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
pub struct ShareExport {
    pub version: u8,
    pub threshold: u16,
    pub total: u16,
    pub identifier: u16,
    pub group_pubkey: String,
    pub encrypted_share: String,
    pub nonce: String,
    pub salt: String,
}

impl ShareExport {
    pub fn from_share(share: &SharePackage, passphrase: &str) -> Result<Self> {
        let salt: [u8; 32] = crypto::random_bytes();
        let key = crypto::derive_key(passphrase.as_bytes(), &salt, crypto::Argon2Params::DEFAULT)?;

        let key_package = share.key_package()?;
        let key_bytes = key_package
            .serialize()
            .map_err(|e| KeepError::Frost(format!("Serialization failed: {}", e)))?;

        let encrypted = crypto::encrypt(&key_bytes, &key)?;

        Ok(Self {
            version: 1,
            threshold: share.metadata.threshold,
            total: share.metadata.total_shares,
            identifier: share.metadata.identifier,
            group_pubkey: hex::encode(share.metadata.group_pubkey),
            encrypted_share: hex::encode(&encrypted.ciphertext),
            nonce: hex::encode(encrypted.nonce),
            salt: hex::encode(salt),
        })
    }

    pub fn to_share(&self, passphrase: &str, name: &str) -> Result<SharePackage> {
        const INVALID_SHARE: &str = "Invalid or corrupted share data";

        if self.version != 1 {
            return Err(KeepError::Frost(format!(
                "Unsupported version: {}",
                self.version
            )));
        }

        let salt_bytes =
            hex::decode(&self.salt).map_err(|_| KeepError::Frost(INVALID_SHARE.into()))?;
        if salt_bytes.len() != 32 {
            return Err(KeepError::Frost(INVALID_SHARE.into()));
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&salt_bytes);

        let key = crypto::derive_key(passphrase.as_bytes(), &salt, crypto::Argon2Params::DEFAULT)?;

        let nonce_bytes =
            hex::decode(&self.nonce).map_err(|_| KeepError::Frost(INVALID_SHARE.into()))?;
        if nonce_bytes.len() != 24 {
            return Err(KeepError::Frost(INVALID_SHARE.into()));
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_bytes);

        let ciphertext = hex::decode(&self.encrypted_share)
            .map_err(|_| KeepError::Frost(INVALID_SHARE.into()))?;

        let encrypted = crypto::EncryptedData { ciphertext, nonce };
        let decrypted = crypto::decrypt(&encrypted, &key)?;
        let key_bytes = decrypted.as_slice()?;

        let key_package = frost_secp256k1_tr::keys::KeyPackage::deserialize(&key_bytes)
            .map_err(|e| KeepError::Frost(format!("Failed to deserialize key package: {}", e)))?;

        let group_pubkey_bytes =
            hex::decode(&self.group_pubkey).map_err(|_| KeepError::Frost(INVALID_SHARE.into()))?;
        if group_pubkey_bytes.len() != 32 {
            return Err(KeepError::Frost(INVALID_SHARE.into()));
        }
        let mut group_pubkey = [0u8; 32];
        group_pubkey.copy_from_slice(&group_pubkey_bytes);

        let pubkey_package = derive_pubkey_package(&key_package)?;

        let metadata = super::share::ShareMetadata::new(
            self.identifier,
            self.threshold,
            self.total,
            group_pubkey,
            name.to_string(),
        );

        SharePackage::new(metadata, &key_package, &pubkey_package)
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| KeepError::Frost(format!("JSON serialization failed: {}", e)))
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| KeepError::Frost(format!("JSON deserialization failed: {}", e)))
    }

    pub fn to_bech32(&self) -> Result<String> {
        let json = self.to_json()?;
        let hrp =
            Hrp::parse(SHARE_HRP).map_err(|e| KeepError::Frost(format!("Invalid HRP: {}", e)))?;
        bech32::encode::<Bech32m>(hrp, json.as_bytes())
            .map_err(|e| KeepError::Frost(format!("Bech32 encoding failed: {}", e)))
    }

    pub fn from_bech32(encoded: &str) -> Result<Self> {
        let (hrp, data) = bech32::decode(encoded)
            .map_err(|e| KeepError::Frost(format!("Bech32 decoding failed: {}", e)))?;

        if hrp.as_str() != SHARE_HRP {
            return Err(KeepError::Frost(format!(
                "Invalid prefix: expected {}, got {}",
                SHARE_HRP,
                hrp.as_str()
            )));
        }

        let json = String::from_utf8(data)
            .map_err(|_| KeepError::Frost("Invalid UTF-8 in share".into()))?;

        Self::from_json(&json)
    }
}

fn derive_pubkey_package(
    key_package: &frost_secp256k1_tr::keys::KeyPackage,
) -> Result<frost_secp256k1_tr::keys::PublicKeyPackage> {
    use frost_secp256k1_tr::keys::PublicKeyPackage;
    use std::collections::BTreeMap;

    let verifying_share = key_package.verifying_share();
    let verifying_key = key_package.verifying_key();

    let mut verifying_shares = BTreeMap::new();
    verifying_shares.insert(*key_package.identifier(), *verifying_share);

    Ok(PublicKeyPackage::new(verifying_shares, *verifying_key))
}

#[derive(Serialize, Deserialize)]
pub struct FrostMessage {
    #[serde(rename = "type")]
    pub msg_type: FrostMessageType,
    pub session_id: String,
    pub identifier: u16,
    pub payload: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FrostMessageType {
    Round1Commitment,
    Round2Share,
}

impl FrostMessage {
    pub fn commitment(session_id: &[u8; 32], identifier: u16, commitment_bytes: &[u8]) -> Self {
        Self {
            msg_type: FrostMessageType::Round1Commitment,
            session_id: hex::encode(session_id),
            identifier,
            payload: hex::encode(commitment_bytes),
        }
    }

    pub fn signature_share(session_id: &[u8; 32], identifier: u16, share_bytes: &[u8]) -> Self {
        Self {
            msg_type: FrostMessageType::Round2Share,
            session_id: hex::encode(session_id),
            identifier,
            payload: hex::encode(share_bytes),
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| KeepError::Frost(format!("JSON encode failed: {}", e)))
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| KeepError::Frost(format!("JSON decode failed: {}", e)))
    }

    pub fn payload_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.payload).map_err(|_| KeepError::Frost("Invalid payload hex".into()))
    }

    pub fn session_id_bytes(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(&self.session_id)
            .map_err(|_| KeepError::Frost("Invalid session_id hex".into()))?;
        if bytes.len() != 32 {
            return Err(KeepError::Frost("Invalid session_id length".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl ShareExport {
    pub fn to_animated_frames(&self, max_bytes: usize) -> Result<Vec<String>> {
        let full = self.to_json()?;

        if full.len() <= max_bytes {
            return Ok(vec![full]);
        }

        let total_frames = full.len().div_ceil(max_bytes);
        let frames: Vec<String> = full
            .as_bytes()
            .chunks(max_bytes)
            .enumerate()
            .map(|(i, chunk)| {
                let chunk_hex = hex::encode(chunk);
                format!(
                    "{{\"f\":{},\"t\":{},\"d\":\"{}\"}}",
                    i, total_frames, chunk_hex
                )
            })
            .collect();

        Ok(frames)
    }

    pub fn from_animated_frames(frames: &[String]) -> Result<Self> {
        if frames.is_empty() {
            return Err(KeepError::Frost("No frames provided".into()));
        }

        if frames.len() > MAX_FRAME_COUNT {
            return Err(KeepError::Frost("Too many frames".into()));
        }

        if frames.len() == 1 {
            if let Ok(export) = Self::from_json(&frames[0]) {
                return Ok(export);
            }
        }

        let mut sorted: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut total_size = 0usize;
        let mut seen_indices = std::collections::HashSet::new();

        for frame in frames {
            let parsed: serde_json::Value = serde_json::from_str(frame)
                .map_err(|e| KeepError::Frost(format!("Invalid frame JSON: {}", e)))?;

            let idx = parsed["f"]
                .as_u64()
                .ok_or_else(|| KeepError::Frost("Missing frame index".into()))?
                as usize;

            if idx >= MAX_FRAME_COUNT {
                return Err(KeepError::Frost("Frame index out of range".into()));
            }

            if !seen_indices.insert(idx) {
                return Err(KeepError::Frost("Duplicate frame index".into()));
            }

            let data_hex = parsed["d"]
                .as_str()
                .ok_or_else(|| KeepError::Frost("Missing frame data".into()))?;
            let data = hex::decode(data_hex)
                .map_err(|_| KeepError::Frost("Invalid frame data hex".into()))?;

            total_size = total_size
                .checked_add(data.len())
                .ok_or_else(|| KeepError::Frost("Total size overflow".into()))?;

            if total_size > MAX_ASSEMBLED_SIZE {
                return Err(KeepError::Frost("Assembled data too large".into()));
            }

            sorted.push((idx, data));
        }

        sorted.sort_by_key(|(idx, _)| *idx);

        let full_bytes: Vec<u8> = sorted.into_iter().flat_map(|(_, data)| data).collect();
        let full_json = String::from_utf8(full_bytes)
            .map_err(|_| KeepError::Frost("Invalid UTF-8 in assembled frames".into()))?;

        Self::from_json(&full_json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{ThresholdConfig, TrustedDealer};

    #[test]
    fn test_share_export_roundtrip() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let passphrase = "test passphrase";
        let export = ShareExport::from_share(&shares[0], passphrase).unwrap();

        let json = export.to_json().unwrap();
        let reimported = ShareExport::from_json(&json).unwrap();
        let share = reimported.to_share(passphrase, "imported").unwrap();

        assert_eq!(share.metadata.threshold, shares[0].metadata.threshold);
        assert_eq!(share.metadata.identifier, shares[0].metadata.identifier);
        assert_eq!(share.group_pubkey(), shares[0].group_pubkey());
    }

    #[test]
    fn test_bech32_roundtrip() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let export = ShareExport::from_share(&shares[0], "pass").unwrap();
        let encoded = export.to_bech32().unwrap();

        assert!(encoded.starts_with(SHARE_HRP));

        let decoded = ShareExport::from_bech32(&encoded).unwrap();
        assert_eq!(decoded.identifier, export.identifier);
        assert_eq!(decoded.threshold, export.threshold);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let export = ShareExport::from_share(&shares[0], "correct").unwrap();
        let result = export.to_share("wrong", "imported");

        assert!(result.is_err());
    }

    #[test]
    fn test_animated_frames_roundtrip() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let export = ShareExport::from_share(&shares[0], "pass").unwrap();

        let frames = export.to_animated_frames(100).unwrap();
        assert!(frames.len() > 1);

        let reconstructed = ShareExport::from_animated_frames(&frames).unwrap();
        assert_eq!(reconstructed.identifier, export.identifier);
        assert_eq!(reconstructed.threshold, export.threshold);
        assert_eq!(reconstructed.group_pubkey, export.group_pubkey);
    }

    #[test]
    fn test_animated_frames_single() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let export = ShareExport::from_share(&shares[0], "pass").unwrap();

        let frames = export.to_animated_frames(10000).unwrap();
        assert_eq!(frames.len(), 1);

        let reconstructed = ShareExport::from_animated_frames(&frames).unwrap();
        assert_eq!(reconstructed.identifier, export.identifier);
    }

    #[test]
    fn test_frost_message_roundtrip() {
        let session_id = [42u8; 32];
        let commitment_data = vec![1, 2, 3, 4, 5];

        let msg = FrostMessage::commitment(&session_id, 1, &commitment_data);
        assert_eq!(msg.msg_type, FrostMessageType::Round1Commitment);
        assert_eq!(msg.identifier, 1);

        let json = msg.to_json().unwrap();
        let parsed = FrostMessage::from_json(&json).unwrap();

        assert_eq!(parsed.msg_type, FrostMessageType::Round1Commitment);
        assert_eq!(parsed.identifier, 1);
        assert_eq!(parsed.payload_bytes().unwrap(), commitment_data);
        assert_eq!(parsed.session_id_bytes().unwrap(), session_id);
    }

    #[test]
    fn test_frost_message_signature_share() {
        let session_id = [99u8; 32];
        let share_data = vec![10, 20, 30];

        let msg = FrostMessage::signature_share(&session_id, 2, &share_data);
        assert_eq!(msg.msg_type, FrostMessageType::Round2Share);
        assert_eq!(msg.identifier, 2);

        let json = msg.to_json().unwrap();
        assert!(json.contains("round2_share"));
    }
}
