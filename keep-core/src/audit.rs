// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tamper-evident audit logging with hash chain integrity.
//!
//! This module provides encrypted audit logging with cryptographic integrity guarantees.
//! Each entry links to the previous via a hash chain, making tampering detectable.
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::crypto::{self, SecretKey};
use crate::error::{Result, StorageError};

/// Type of audit event being logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuditEventType {
    /// A new key was generated.
    KeyGenerate = 0,
    /// A key was imported.
    KeyImport = 1,
    /// A key was exported.
    KeyExport = 2,
    /// A key was deleted.
    KeyDelete = 3,
    /// A signing operation succeeded.
    Sign = 4,
    /// A signing operation failed.
    SignFailed = 5,
    /// A new FROST key was generated.
    FrostGenerate = 6,
    /// An existing key was split into FROST shares.
    FrostSplit = 7,
    /// A FROST signing operation succeeded.
    FrostSign = 8,
    /// A FROST signing operation failed.
    FrostSignFailed = 9,
    /// A FROST signing session was started.
    FrostSessionStart = 10,
    /// A FROST signing session completed successfully.
    FrostSessionComplete = 11,
    /// A FROST signing session failed.
    FrostSessionFailed = 12,
    /// A FROST share was imported.
    FrostShareImport = 13,
    /// A FROST share was exported.
    FrostShareExport = 14,
    /// A FROST share was deleted.
    FrostShareDelete = 15,
    /// Authentication failed.
    AuthFailed = 16,
    /// The vault was unlocked.
    VaultUnlock = 17,
    /// The vault was locked.
    VaultLock = 18,
    /// FROST shares were refreshed.
    FrostShareRefresh = 19,
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
            Self::FrostShareRefresh => write!(f, "frost_share_refresh"),
        }
    }
}

/// A single audit log entry with hash chain linkage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unix timestamp when the event occurred.
    pub timestamp: i64,
    /// Type of event.
    pub event_type: AuditEventType,
    /// Public key involved, if applicable.
    pub pubkey: Option<String>,
    /// Key type (e.g., "nostr"), if applicable.
    pub key_type: Option<String>,
    /// Hash of the message being signed, if applicable.
    pub message_hash: Option<String>,
    /// FROST group public key, if applicable.
    pub group_pubkey: Option<String>,
    /// FROST participant identifiers, if applicable.
    pub participants: Option<Vec<u16>>,
    /// FROST threshold, if applicable.
    pub threshold: Option<u16>,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Reason for failure, if applicable.
    pub reason: Option<String>,
    /// Hash of the previous entry in the chain.
    pub prev_hash: [u8; 32],
    /// Hash of this entry.
    pub hash: [u8; 32],
}

impl AuditEntry {
    /// Create a new audit entry with the given event type and previous hash.
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

    /// Set the public key for this entry.
    pub fn with_pubkey(mut self, pubkey: &[u8; 32]) -> Self {
        self.pubkey = Some(hex::encode(pubkey));
        self
    }

    /// Set the key type for this entry.
    pub fn with_key_type(mut self, key_type: &str) -> Self {
        self.key_type = Some(key_type.to_string());
        self
    }

    /// Set the message hash for this entry.
    pub fn with_message_hash(mut self, message: &[u8]) -> Self {
        self.message_hash = Some(hex::encode(crypto::blake2b_256(message)));
        self
    }

    /// Set the FROST group public key for this entry.
    pub fn with_group(mut self, group_pubkey: &[u8; 32]) -> Self {
        self.group_pubkey = Some(hex::encode(group_pubkey));
        self
    }

    /// Set the FROST participant identifiers for this entry.
    pub fn with_participants(mut self, participants: Vec<u16>) -> Self {
        self.participants = Some(participants);
        self
    }

    /// Set the FROST threshold for this entry.
    pub fn with_threshold(mut self, threshold: u16) -> Self {
        self.threshold = Some(threshold);
        self
    }

    /// Set whether the operation succeeded.
    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    /// Set the failure reason for this entry.
    pub fn with_reason(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_string());
        self
    }

    /// Compute and set the hash for this entry.
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

    /// Verify this entry's hash chain linkage.
    pub fn verify(&self, prev_hash: &[u8; 32]) -> bool {
        let prev_hash_match = self.prev_hash.ct_eq(prev_hash);
        let hash_match = self.hash.ct_eq(&self.compute_hash());
        (prev_hash_match & hash_match).into()
    }
}

/// Policy for automatic audit log retention.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Maximum number of entries to keep.
    pub max_entries: Option<usize>,
    /// Maximum age of entries in days.
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

/// Encrypted audit log with hash chain integrity.
pub struct AuditLog {
    path: PathBuf,
    last_hash: [u8; 32],
    retention: RetentionPolicy,
}

impl AuditLog {
    /// Open or create an audit log at the given path.
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

    /// Set the retention policy for this log.
    pub fn set_retention(&mut self, policy: RetentionPolicy) {
        self.retention = policy;
    }

    /// Log an audit entry.
    pub fn log(&mut self, entry: AuditEntry, data_key: &SecretKey) -> Result<()> {
        let mut entry = entry;
        entry.prev_hash = self.last_hash;
        entry.hash = entry.compute_hash();

        let serialized = serde_json::to_vec(&entry)
            .map_err(|e| StorageError::serialization(format!("audit entry: {e}")))?;

        let encrypted = crypto::encrypt(&serialized, data_key)?;
        let line = format!("{}\n", STANDARD.encode(encrypted.to_bytes()));

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.sync_all()?;

        self.last_hash = entry.hash;
        Ok(())
    }

    /// Read all entries from the log.
    pub fn read_all(&self, data_key: &SecretKey) -> Result<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        Self::read_entries(&self.path, data_key)
    }

    /// Verify the integrity of the hash chain.
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

    /// Apply the retention policy and return the number of entries removed.
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

    /// Export the log as JSON.
    pub fn export(&self, data_key: &SecretKey) -> Result<String> {
        let entries = self.read_all(data_key)?;
        serde_json::to_string_pretty(&entries)
            .map_err(|e| StorageError::serialization(format!("export audit log: {e}")).into())
    }

    fn read_last_hash(path: &Path, data_key: &SecretKey) -> Result<[u8; 32]> {
        let entries = Self::read_entries(path, data_key)?;
        Ok(entries.last().map_or([0u8; 32], |e| e.hash))
    }

    fn read_entries(path: &Path, data_key: &SecretKey) -> Result<Vec<AuditEntry>> {
        const MAX_ENTRIES: usize = 100_000;

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for (line_num, line) in reader.lines().enumerate() {
            if entries.len() >= MAX_ENTRIES {
                return Err(StorageError::io(format!(
                    "audit log exceeds maximum of {MAX_ENTRIES} entries"
                ))
                .into());
            }
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let entry = Self::decrypt_line(&line, data_key).map_err(|e| {
                StorageError::corrupted(format!("audit log at line {}: {}", line_num + 1, e))
            })?;
            entries.push(entry);
        }

        Ok(entries)
    }

    fn decrypt_line(line: &str, data_key: &SecretKey) -> Result<AuditEntry> {
        let bytes = STANDARD
            .decode(line)
            .map_err(|e| StorageError::invalid_format(format!("audit line: {e}")))?;

        let encrypted = crypto::EncryptedData::from_bytes(&bytes)?;
        let decrypted = crypto::decrypt(&encrypted, data_key)?;

        serde_json::from_slice(&decrypted.as_slice()?)
            .map_err(|e| StorageError::invalid_format(format!("audit entry: {e}")).into())
    }

    fn rewrite(&mut self, entries: &[AuditEntry], data_key: &SecretKey) -> Result<()> {
        let temp_path = self.path.with_extension("log.tmp");
        let backup_path = self.path.with_extension("log.bak");

        let final_hash = match self.write_entries_to_temp(&temp_path, entries, data_key) {
            Ok(hash) => hash,
            Err(e) => {
                let _ = std::fs::remove_file(&temp_path);
                return Err(e);
            }
        };

        if self.path.exists() {
            if let Err(e) = std::fs::rename(&self.path, &backup_path) {
                let _ = std::fs::remove_file(&temp_path);
                return Err(StorageError::io(format!("backup existing audit log: {e}")).into());
            }
        }

        if let Err(e) = std::fs::rename(&temp_path, &self.path) {
            if backup_path.exists() {
                let _ = std::fs::rename(&backup_path, &self.path);
            }
            let _ = std::fs::remove_file(&temp_path);
            return Err(StorageError::io(format!("replace audit log: {e}")).into());
        }

        let _ = std::fs::remove_file(&backup_path);
        self.last_hash = final_hash;
        Ok(())
    }

    fn write_entries_to_temp(
        &self,
        temp_path: &Path,
        entries: &[AuditEntry],
        data_key: &SecretKey,
    ) -> Result<[u8; 32]> {
        let mut file = File::create(temp_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }

        let mut prev_hash = [0u8; 32];
        for entry in entries {
            let mut entry = entry.clone();
            entry.prev_hash = prev_hash;
            entry.hash = entry.compute_hash();

            let serialized = serde_json::to_vec(&entry)
                .map_err(|e| StorageError::serialization(e.to_string()))?;

            let encrypted = crypto::encrypt(&serialized, data_key)?;
            let line = format!("{}\n", STANDARD.encode(encrypted.to_bytes()));
            file.write_all(line.as_bytes())?;
            prev_hash = entry.hash;
        }

        file.sync_all()?;
        Ok(prev_hash)
    }

    /// Get the hash of the last entry in the chain.
    pub fn last_hash(&self) -> [u8; 32] {
        self.last_hash
    }

    /// Re-encrypt the entire audit log with a new data key.
    pub fn reencrypt(&mut self, old_key: &SecretKey, new_key: &SecretKey) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }
        let entries = Self::read_entries(&self.path, old_key)?;
        if entries.is_empty() {
            return Ok(());
        }
        self.rewrite(&entries, new_key)
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
