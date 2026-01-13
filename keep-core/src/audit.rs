#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, SecretKey};
use crate::error::{KeepError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventType {
    KeyGenerate,
    KeyImport,
    KeyExport,
    KeyDelete,
    Sign,
    SignFailed,
    FrostGenerate,
    FrostSplit,
    FrostSign,
    FrostSignFailed,
    FrostSessionStart,
    FrostSessionComplete,
    FrostSessionFailed,
    FrostShareImport,
    FrostShareExport,
    FrostShareDelete,
    AuthFailed,
    VaultUnlock,
    VaultLock,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGenerate => write!(f, "key_generate"),
            Self::KeyImport => write!(f, "key_import"),
            Self::KeyExport => write!(f, "key_export"),
            Self::KeyDelete => write!(f, "key_delete"),
            Self::Sign => write!(f, "sign"),
            Self::SignFailed => write!(f, "sign_failed"),
            Self::FrostGenerate => write!(f, "frost_generate"),
            Self::FrostSplit => write!(f, "frost_split"),
            Self::FrostSign => write!(f, "frost_sign"),
            Self::FrostSignFailed => write!(f, "frost_sign_failed"),
            Self::FrostSessionStart => write!(f, "frost_session_start"),
            Self::FrostSessionComplete => write!(f, "frost_session_complete"),
            Self::FrostSessionFailed => write!(f, "frost_session_failed"),
            Self::FrostShareImport => write!(f, "frost_share_import"),
            Self::FrostShareExport => write!(f, "frost_share_export"),
            Self::FrostShareDelete => write!(f, "frost_share_delete"),
            Self::AuthFailed => write!(f, "auth_failed"),
            Self::VaultUnlock => write!(f, "vault_unlock"),
            Self::VaultLock => write!(f, "vault_lock"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: i64,
    pub event_type: AuditEventType,
    pub pubkey: Option<String>,
    pub key_type: Option<String>,
    pub message_hash: Option<String>,
    pub group_pubkey: Option<String>,
    pub participants: Option<Vec<u16>>,
    pub threshold: Option<u16>,
    pub success: bool,
    pub reason: Option<String>,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

impl AuditEntry {
    pub fn new(event_type: AuditEventType, prev_hash: [u8; 32]) -> Self {
        Self {
            timestamp: chrono::Utc::now().timestamp(),
            event_type,
            pubkey: None,
            key_type: None,
            message_hash: None,
            group_pubkey: None,
            participants: None,
            threshold: None,
            success: true,
            reason: None,
            prev_hash,
            hash: [0u8; 32],
        }
    }

    pub fn with_pubkey(mut self, pubkey: &[u8; 32]) -> Self {
        self.pubkey = Some(hex::encode(pubkey));
        self
    }

    pub fn with_key_type(mut self, key_type: &str) -> Self {
        self.key_type = Some(key_type.to_string());
        self
    }

    pub fn with_message_hash(mut self, message: &[u8]) -> Self {
        self.message_hash = Some(hex::encode(crypto::blake2b_256(message)));
        self
    }

    pub fn with_group(mut self, group_pubkey: &[u8; 32]) -> Self {
        self.group_pubkey = Some(hex::encode(group_pubkey));
        self
    }

    pub fn with_participants(mut self, participants: Vec<u16>) -> Self {
        self.participants = Some(participants);
        self
    }

    pub fn with_threshold(mut self, threshold: u16) -> Self {
        self.threshold = Some(threshold);
        self
    }

    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    pub fn with_reason(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_string());
        self
    }

    pub fn finalize(mut self) -> Self {
        self.hash = self.compute_hash();
        self
    }

    fn compute_hash(&self) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&(self.event_type as u8).to_le_bytes());
        if let Some(ref pk) = self.pubkey {
            data.extend_from_slice(pk.as_bytes());
        }
        if let Some(ref kt) = self.key_type {
            data.extend_from_slice(kt.as_bytes());
        }
        if let Some(ref mh) = self.message_hash {
            data.extend_from_slice(mh.as_bytes());
        }
        if let Some(ref gp) = self.group_pubkey {
            data.extend_from_slice(gp.as_bytes());
        }
        if let Some(ref p) = self.participants {
            for id in p {
                data.extend_from_slice(&id.to_le_bytes());
            }
        }
        if let Some(t) = self.threshold {
            data.extend_from_slice(&t.to_le_bytes());
        }
        data.push(self.success as u8);
        if let Some(ref r) = self.reason {
            data.extend_from_slice(r.as_bytes());
        }
        data.extend_from_slice(&self.prev_hash);
        crypto::blake2b_256(&data)
    }

    pub fn verify(&self, prev_hash: &[u8; 32]) -> bool {
        if self.prev_hash != *prev_hash {
            return false;
        }
        self.hash == self.compute_hash()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub max_entries: Option<usize>,
    pub max_age_days: Option<u32>,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_entries: Some(10000),
            max_age_days: Some(365),
        }
    }
}

pub struct AuditLog {
    path: PathBuf,
    last_hash: [u8; 32],
    retention: RetentionPolicy,
}

impl AuditLog {
    pub fn open(path: &Path, data_key: &SecretKey) -> Result<Self> {
        let audit_path = path.join("audit.log");
        let last_hash = if audit_path.exists() {
            Self::read_last_hash(&audit_path, data_key)?
        } else {
            [0u8; 32]
        };

        Ok(Self {
            path: audit_path,
            last_hash,
            retention: RetentionPolicy::default(),
        })
    }

    pub fn set_retention(&mut self, policy: RetentionPolicy) {
        self.retention = policy;
    }

    pub fn log(&mut self, entry: AuditEntry, data_key: &SecretKey) -> Result<()> {
        let mut entry = entry;
        entry.prev_hash = self.last_hash;
        entry.hash = entry.compute_hash();

        let serialized = serde_json::to_vec(&entry)
            .map_err(|e| KeepError::Other(format!("Failed to serialize audit entry: {}", e)))?;

        let encrypted = crypto::encrypt(&serialized, data_key)?;
        let line = format!("{}\n", STANDARD.encode(encrypted.to_bytes()));

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;

        self.last_hash = entry.hash;
        Ok(())
    }

    pub fn read_all(&self, data_key: &SecretKey) -> Result<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            if let Ok(entry) = Self::decrypt_line(&line, data_key) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    pub fn verify_chain(&self, data_key: &SecretKey) -> Result<bool> {
        let entries = self.read_all(data_key)?;
        let mut prev_hash = [0u8; 32];

        for entry in entries {
            if !entry.verify(&prev_hash) {
                return Ok(false);
            }
            prev_hash = entry.hash;
        }

        Ok(true)
    }

    pub fn apply_retention(&mut self, data_key: &SecretKey) -> Result<usize> {
        let entries = self.read_all(data_key)?;
        let original_count = entries.len();
        let now = chrono::Utc::now().timestamp();
        let max_age_secs = self.retention.max_age_days.map(|d| i64::from(d) * 86400);

        let mut filtered: Vec<_> = entries
            .into_iter()
            .filter(|e| max_age_secs.map_or(true, |max| now - e.timestamp <= max))
            .collect();

        if let Some(max) = self.retention.max_entries {
            if filtered.len() > max {
                filtered = filtered.split_off(filtered.len() - max);
            }
        }

        let removed = original_count - filtered.len();
        if removed > 0 {
            self.rewrite(&filtered, data_key)?;
        }

        Ok(removed)
    }

    pub fn export(&self, data_key: &SecretKey) -> Result<String> {
        let entries = self.read_all(data_key)?;
        serde_json::to_string_pretty(&entries)
            .map_err(|e| KeepError::Other(format!("Failed to export audit log: {}", e)))
    }

    fn read_last_hash(path: &Path, data_key: &SecretKey) -> Result<[u8; 32]> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut last_hash = [0u8; 32];

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            if let Ok(entry) = Self::decrypt_line(&line, data_key) {
                last_hash = entry.hash;
            }
        }

        Ok(last_hash)
    }

    fn decrypt_line(line: &str, data_key: &SecretKey) -> Result<AuditEntry> {
        let bytes = STANDARD
            .decode(line)
            .map_err(|e| KeepError::Other(format!("Failed to decode audit line: {}", e)))?;

        let encrypted = crypto::EncryptedData::from_bytes(&bytes)?;
        let decrypted = crypto::decrypt(&encrypted, data_key)?;
        let decrypted_bytes = decrypted.as_slice()?;

        serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| KeepError::Other(format!("Failed to parse audit entry: {e}")))
    }

    fn rewrite(&mut self, entries: &[AuditEntry], data_key: &SecretKey) -> Result<()> {
        let temp_path = self.path.with_extension("log.tmp");
        let mut file = File::create(&temp_path)?;
        let mut prev_hash = [0u8; 32];

        for entry in entries {
            let mut entry = entry.clone();
            entry.prev_hash = prev_hash;
            entry.hash = entry.compute_hash();

            let serialized = serde_json::to_vec(&entry)
                .map_err(|e| KeepError::Other(format!("Failed to serialize: {}", e)))?;

            let encrypted = crypto::encrypt(&serialized, data_key)?;
            let line = format!("{}\n", STANDARD.encode(encrypted.to_bytes()));
            file.write_all(line.as_bytes())?;
            prev_hash = entry.hash;
        }

        std::fs::rename(&temp_path, &self.path)?;
        self.last_hash = prev_hash;
        Ok(())
    }

    pub fn last_hash(&self) -> [u8; 32] {
        self.last_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_key() -> SecretKey {
        SecretKey::generate().unwrap()
    }

    #[test]
    fn test_audit_entry_hash_chain() {
        let genesis = [0u8; 32];
        let entry1 = AuditEntry::new(AuditEventType::KeyGenerate, genesis)
            .with_pubkey(&[1u8; 32])
            .with_key_type("nostr")
            .finalize();

        assert!(entry1.verify(&genesis));

        let entry2 = AuditEntry::new(AuditEventType::Sign, entry1.hash)
            .with_pubkey(&[1u8; 32])
            .with_message_hash(b"test message")
            .finalize();

        assert!(entry2.verify(&entry1.hash));
        assert!(!entry2.verify(&genesis));
    }

    #[test]
    fn test_audit_log_persistence() {
        let dir = tempdir().unwrap();
        let key = test_key();

        {
            let mut log = AuditLog::open(dir.path(), &key).unwrap();
            let entry = AuditEntry::new(AuditEventType::KeyGenerate, log.last_hash())
                .with_pubkey(&[1u8; 32]);
            log.log(entry, &key).unwrap();
        }

        {
            let log = AuditLog::open(dir.path(), &key).unwrap();
            let entries = log.read_all(&key).unwrap();
            assert_eq!(entries.len(), 1);
            assert!(matches!(entries[0].event_type, AuditEventType::KeyGenerate));
        }
    }

    #[test]
    fn test_audit_chain_verification() {
        let dir = tempdir().unwrap();
        let key = test_key();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();

        for i in 0..5 {
            let entry =
                AuditEntry::new(AuditEventType::Sign, log.last_hash()).with_pubkey(&[i as u8; 32]);
            log.log(entry, &key).unwrap();
        }

        assert!(log.verify_chain(&key).unwrap());
    }

    #[test]
    fn test_retention_policy() {
        let dir = tempdir().unwrap();
        let key = test_key();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        log.set_retention(RetentionPolicy {
            max_entries: Some(3),
            max_age_days: None,
        });

        for i in 0..5 {
            let entry =
                AuditEntry::new(AuditEventType::Sign, log.last_hash()).with_pubkey(&[i as u8; 32]);
            log.log(entry, &key).unwrap();
        }

        let removed = log.apply_retention(&key).unwrap();
        assert_eq!(removed, 2);

        let entries = log.read_all(&key).unwrap();
        assert_eq!(entries.len(), 3);
    }
}
