// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tamper-evident audit logging with hash chain integrity.
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::crypto::{self, SecretKey};
use crate::error::{Result, StorageError};

/// Type of audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuditEventType {
    /// Key generated.
    KeyGenerate = 0,
    /// Key imported.
    KeyImport = 1,
    /// Key exported.
    KeyExport = 2,
    /// Key deleted.
    KeyDelete = 3,
    /// Signing succeeded.
    Sign = 4,
    /// Signing failed.
    SignFailed = 5,
    /// FROST key generated.
    FrostGenerate = 6,
    /// Key split into FROST shares.
    FrostSplit = 7,
    /// FROST signing succeeded.
    FrostSign = 8,
    /// FROST signing failed.
    FrostSignFailed = 9,
    /// FROST session started.
    FrostSessionStart = 10,
    /// FROST session completed.
    FrostSessionComplete = 11,
    /// FROST session failed.
    FrostSessionFailed = 12,
    /// FROST share imported.
    FrostShareImport = 13,
    /// FROST share exported.
    FrostShareExport = 14,
    /// FROST share deleted.
    FrostShareDelete = 15,
    /// Authentication failed.
    AuthFailed = 16,
    /// Vault unlocked.
    VaultUnlock = 17,
    /// Vault locked.
    VaultLock = 18,
    /// FROST shares refreshed.
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
    /// Unix timestamp.
    pub timestamp: i64,
    /// Event type.
    pub event_type: AuditEventType,
    /// Public key involved.
    pub pubkey: Option<String>,
    /// Key type (e.g. "nostr").
    pub key_type: Option<String>,
    /// Hash of the signed message.
    pub message_hash: Option<String>,
    /// FROST group public key.
    pub group_pubkey: Option<String>,
    /// FROST participant identifiers.
    pub participants: Option<Vec<u16>>,
    /// FROST threshold.
    pub threshold: Option<u16>,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Failure reason.
    pub reason: Option<String>,
    /// Previous entry hash.
    pub prev_hash: [u8; 32],
    /// This entry's hash.
    pub hash: [u8; 32],
}

impl AuditEntry {
    /// Create a new entry with the given event type and previous hash.
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

    /// Set the public key.
    pub fn with_pubkey(mut self, pubkey: &[u8; 32]) -> Self {
        self.pubkey = Some(hex::encode(pubkey));
        self
    }

    /// Set the key type.
    pub fn with_key_type(mut self, key_type: &str) -> Self {
        self.key_type = Some(key_type.to_string());
        self
    }

    /// Set the message hash.
    pub fn with_message_hash(mut self, message: &[u8]) -> Self {
        self.message_hash = Some(hex::encode(crypto::blake2b_256(message)));
        self
    }

    /// Set the FROST group public key.
    pub fn with_group(mut self, group_pubkey: &[u8; 32]) -> Self {
        self.group_pubkey = Some(hex::encode(group_pubkey));
        self
    }

    /// Set the FROST participant identifiers.
    pub fn with_participants(mut self, participants: Vec<u16>) -> Self {
        self.participants = Some(participants);
        self
    }

    /// Set the FROST threshold.
    pub fn with_threshold(mut self, threshold: u16) -> Self {
        self.threshold = Some(threshold);
        self
    }

    /// Set whether the operation succeeded.
    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    /// Set the failure reason.
    pub fn with_reason(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_string());
        self
    }

    /// Compute and set this entry's hash.
    pub fn finalize(mut self) -> Self {
        self.hash = self.compute_hash();
        self
    }

    fn compute_hash(&self) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&(self.event_type as u8).to_le_bytes());
        Self::hash_optional_str(&mut data, self.pubkey.as_deref());
        Self::hash_optional_str(&mut data, self.key_type.as_deref());
        Self::hash_optional_str(&mut data, self.message_hash.as_deref());
        Self::hash_optional_str(&mut data, self.group_pubkey.as_deref());
        if let Some(ref p) = self.participants {
            data.push(1);
            let len = u32::try_from(p.len()).expect("participants too long for hash");
            data.extend_from_slice(&len.to_le_bytes());
            for id in p {
                data.extend_from_slice(&id.to_le_bytes());
            }
        } else {
            data.push(0);
        }
        if let Some(t) = self.threshold {
            data.push(1);
            data.extend_from_slice(&t.to_le_bytes());
        } else {
            data.push(0);
        }
        data.push(self.success as u8);
        Self::hash_optional_str(&mut data, self.reason.as_deref());
        data.extend_from_slice(&self.prev_hash);
        crypto::blake2b_256(&data)
    }

    fn hash_optional_str(data: &mut Vec<u8>, value: Option<&str>) {
        match value {
            Some(s) => {
                data.push(1);
                let len = u32::try_from(s.len()).expect("string too long for hash");
                data.extend_from_slice(&len.to_le_bytes());
                data.extend_from_slice(s.as_bytes());
            }
            None => data.push(0),
        }
    }

    /// Verify this entry's hash chain linkage.
    pub fn verify(&self, prev_hash: &[u8; 32]) -> bool {
        let prev_hash_match = self.prev_hash.ct_eq(prev_hash);
        let hash_match = self.hash.ct_eq(&self.compute_hash());
        (prev_hash_match & hash_match).into()
    }
}

/// Automatic retention policy.
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

    /// Set the retention policy.
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

        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts.open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.sync_all()?;

        self.last_hash = entry.hash;
        Ok(())
    }

    /// Read all entries.
    pub fn read_all(&self, data_key: &SecretKey) -> Result<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        Self::read_entries(&self.path, data_key)
    }

    /// Verify the hash chain integrity.
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

    /// Apply the retention policy, returning the number of entries removed.
    pub fn apply_retention(&mut self, data_key: &SecretKey) -> Result<usize> {
        let entries = self.read_all(data_key)?;
        let original_count = entries.len();
        let now = chrono::Utc::now().timestamp();
        let max_age_secs = self.retention.max_age_days.map(|d| i64::from(d) * 86400);

        let mut filtered: Vec<_> = entries
            .into_iter()
            .filter(|e| max_age_secs.map_or(true, |max| now.saturating_sub(e.timestamp) <= max))
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
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts.open(temp_path)?;

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

    /// Get the last entry's hash.
    pub fn last_hash(&self) -> [u8; 32] {
        self.last_hash
    }

    /// Re-encrypt the entire log with a new data key.
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

/// NIP-46 signing request type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SigningRequestType {
    /// Client connection.
    Connect = 0,
    /// Public key retrieval.
    GetPublicKey = 1,
    /// Event signing.
    SignEvent = 2,
    /// NIP-04 encryption.
    Nip04Encrypt = 3,
    /// NIP-04 decryption.
    Nip04Decrypt = 4,
    /// NIP-44 encryption.
    Nip44Encrypt = 5,
    /// NIP-44 decryption.
    Nip44Decrypt = 6,
    /// Client disconnection.
    Disconnect = 7,
}

impl std::fmt::Display for SigningRequestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect => write!(f, "connect"),
            Self::GetPublicKey => write!(f, "get_public_key"),
            Self::SignEvent => write!(f, "sign_event"),
            Self::Nip04Encrypt => write!(f, "nip04_encrypt"),
            Self::Nip04Decrypt => write!(f, "nip04_decrypt"),
            Self::Nip44Encrypt => write!(f, "nip44_encrypt"),
            Self::Nip44Decrypt => write!(f, "nip44_decrypt"),
            Self::Disconnect => write!(f, "disconnect"),
        }
    }
}

/// Decision made on a signing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SigningDecision {
    /// Approved.
    Approved = 0,
    /// Denied.
    Denied = 1,
}

impl std::fmt::Display for SigningDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approved => write!(f, "approved"),
            Self::Denied => write!(f, "denied"),
        }
    }
}

/// A single signing audit log entry with hash chain linkage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningAuditEntry {
    /// Unix timestamp.
    pub timestamp: i64,
    /// Request type.
    pub request_type: SigningRequestType,
    /// Decision (approved/denied).
    pub decision: SigningDecision,
    /// Whether decided by policy (true) or user (false).
    pub was_automatic: bool,
    /// Hex public key of the requesting app.
    pub caller: String,
    /// Human-readable caller name.
    pub caller_name: Option<String>,
    /// Nostr event kind.
    pub event_kind: Option<u32>,
    /// Reason for the decision.
    pub reason: Option<String>,
    /// Previous entry hash.
    pub prev_hash: [u8; 32],
    /// This entry's hash.
    pub hash: [u8; 32],
}

impl SigningAuditEntry {
    /// Create a new signing audit entry.
    pub fn new(
        request_type: SigningRequestType,
        decision: SigningDecision,
        was_automatic: bool,
        caller: String,
        prev_hash: [u8; 32],
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().timestamp(),
            request_type,
            decision,
            was_automatic,
            caller,
            caller_name: None,
            event_kind: None,
            reason: None,
            prev_hash,
            hash: [0u8; 32],
        }
    }

    /// Set the caller name.
    pub fn with_caller_name(mut self, name: impl Into<String>) -> Self {
        self.caller_name = Some(name.into());
        self
    }

    /// Set the event kind.
    pub fn with_event_kind(mut self, kind: u32) -> Self {
        self.event_kind = Some(kind);
        self
    }

    /// Set the reason.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Compute and set this entry's hash.
    pub fn finalize(mut self) -> Self {
        self.hash = self.compute_hash();
        self
    }

    fn compute_hash(&self) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.push(self.request_type as u8);
        data.push(self.decision as u8);
        data.push(self.was_automatic as u8);
        let caller_len = u32::try_from(self.caller.len()).expect("caller too long for hash");
        data.extend_from_slice(&caller_len.to_le_bytes());
        data.extend_from_slice(self.caller.as_bytes());
        Self::hash_optional_str(&mut data, self.caller_name.as_deref());
        if let Some(kind) = self.event_kind {
            data.push(1);
            data.extend_from_slice(&kind.to_le_bytes());
        } else {
            data.push(0);
        }
        Self::hash_optional_str(&mut data, self.reason.as_deref());
        data.extend_from_slice(&self.prev_hash);
        crypto::blake2b_256(&data)
    }

    fn hash_optional_str(data: &mut Vec<u8>, value: Option<&str>) {
        match value {
            Some(s) => {
                data.push(1);
                let len = u32::try_from(s.len()).expect("string too long for hash");
                data.extend_from_slice(&len.to_le_bytes());
                data.extend_from_slice(s.as_bytes());
            }
            None => data.push(0),
        }
    }

    /// Verify this entry's hash chain linkage.
    pub fn verify(&self, prev_hash: &[u8; 32]) -> bool {
        let prev_hash_match = self.prev_hash.ct_eq(prev_hash);
        let hash_match = self.hash.ct_eq(&self.compute_hash());
        (prev_hash_match & hash_match).into()
    }
}

/// Encrypted signing audit log with hash chain integrity.
pub struct SigningAuditLog {
    path: PathBuf,
    last_hash: [u8; 32],
    retention: RetentionPolicy,
}

impl SigningAuditLog {
    /// Open or create a signing audit log at the given path.
    pub fn open(path: &Path, data_key: &SecretKey) -> Result<Self> {
        let audit_path = path.join("signing_audit.log");
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

    /// Set the retention policy.
    pub fn set_retention(&mut self, policy: RetentionPolicy) {
        self.retention = policy;
    }

    /// Apply the retention policy, returning the number of entries removed.
    pub fn apply_retention(&mut self, data_key: &SecretKey) -> Result<usize> {
        let entries = self.read_all(data_key)?;
        let original_count = entries.len();
        let now = chrono::Utc::now().timestamp();
        let max_age_secs = self.retention.max_age_days.map(|d| i64::from(d) * 86400);

        let mut filtered: Vec<_> = entries
            .into_iter()
            .filter(|e| {
                max_age_secs.map_or(true, |max| now.saturating_sub(e.timestamp) <= max)
            })
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

    /// Log a signing audit entry.
    pub fn log(&mut self, entry: SigningAuditEntry, data_key: &SecretKey) -> Result<()> {
        let mut entry = entry;
        entry.prev_hash = self.last_hash;
        entry.hash = entry.compute_hash();

        let serialized = serde_json::to_vec(&entry)
            .map_err(|e| StorageError::serialization(format!("signing audit entry: {e}")))?;

        let encrypted = crypto::encrypt(&serialized, data_key)?;
        let line = format!("{}\n", STANDARD.encode(encrypted.to_bytes()));

        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts.open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.sync_all()?;

        self.last_hash = entry.hash;
        Ok(())
    }

    /// Read all entries.
    pub fn read_all(&self, data_key: &SecretKey) -> Result<Vec<SigningAuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        Self::read_entries(&self.path, data_key)
    }

    /// Read a page of entries (newest first), optionally filtered by caller.
    pub fn read_page(
        &self,
        data_key: &SecretKey,
        offset: usize,
        limit: usize,
        caller_filter: Option<&str>,
    ) -> Result<Vec<SigningAuditEntry>> {
        let all = self.read_all(data_key)?;
        let entries = all
            .into_iter()
            .rev()
            .filter(|e| caller_filter.map_or(true, |c| e.caller == c))
            .skip(offset)
            .take(limit)
            .collect();
        Ok(entries)
    }

    /// Read a page and return metadata (distinct callers, total count) in a single pass.
    pub fn read_page_with_metadata(
        &self,
        data_key: &SecretKey,
        offset: usize,
        limit: usize,
        caller_filter: Option<&str>,
    ) -> Result<(Vec<SigningAuditEntry>, Vec<String>, usize)> {
        let all = self.read_all(data_key)?;
        let count = all.len();

        let mut seen = std::collections::HashSet::new();
        let mut callers = Vec::new();
        for entry in all.iter().rev() {
            if seen.insert(entry.caller.clone()) {
                callers.push(entry.caller.clone());
            }
        }

        let entries = all
            .into_iter()
            .rev()
            .filter(|e| caller_filter.map_or(true, |c| e.caller == c))
            .skip(offset)
            .take(limit)
            .collect();

        Ok((entries, callers, count))
    }

    /// Get distinct callers, most recently active first.
    pub fn distinct_callers(&self, data_key: &SecretKey) -> Result<Vec<String>> {
        let entries = self.read_all(data_key)?;
        let mut seen = std::collections::HashSet::new();
        let mut callers = Vec::new();
        for entry in entries.iter().rev() {
            if seen.insert(entry.caller.clone()) {
                callers.push(entry.caller.clone());
            }
        }
        Ok(callers)
    }

    /// Get the total number of entries.
    pub fn count(&self, data_key: &SecretKey) -> Result<usize> {
        Ok(self.read_all(data_key)?.len())
    }

    /// Verify the hash chain integrity and return the entry count.
    pub fn verify_chain(&self, data_key: &SecretKey) -> Result<(bool, usize)> {
        let entries = self.read_all(data_key)?;
        let count = entries.len();
        let mut prev_hash = [0u8; 32];

        for entry in entries {
            if !entry.verify(&prev_hash) {
                return Ok((false, count));
            }
            prev_hash = entry.hash;
        }

        Ok((true, count))
    }

    /// Get the last entry's hash.
    pub fn last_hash(&self) -> [u8; 32] {
        self.last_hash
    }

    /// Re-encrypt the entire log with a new data key.
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

    fn read_last_hash(path: &Path, data_key: &SecretKey) -> Result<[u8; 32]> {
        let entries = Self::read_entries(path, data_key)?;
        Ok(entries.last().map_or([0u8; 32], |e| e.hash))
    }

    fn read_entries(path: &Path, data_key: &SecretKey) -> Result<Vec<SigningAuditEntry>> {
        const MAX_ENTRIES: usize = 100_000;

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for (line_num, line) in reader.lines().enumerate() {
            if entries.len() >= MAX_ENTRIES {
                return Err(StorageError::io(format!(
                    "signing audit log exceeds maximum of {MAX_ENTRIES} entries"
                ))
                .into());
            }
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let entry = Self::decrypt_line(&line, data_key).map_err(|e| {
                StorageError::corrupted(format!(
                    "signing audit log at line {}: {}",
                    line_num + 1,
                    e
                ))
            })?;
            entries.push(entry);
        }

        Ok(entries)
    }

    fn decrypt_line(line: &str, data_key: &SecretKey) -> Result<SigningAuditEntry> {
        let bytes = STANDARD
            .decode(line)
            .map_err(|e| StorageError::invalid_format(format!("signing audit line: {e}")))?;

        let encrypted = crypto::EncryptedData::from_bytes(&bytes)?;
        let decrypted = crypto::decrypt(&encrypted, data_key)?;

        serde_json::from_slice(&decrypted.as_slice()?)
            .map_err(|e| StorageError::invalid_format(format!("signing audit entry: {e}")).into())
    }

    fn rewrite(&mut self, entries: &[SigningAuditEntry], data_key: &SecretKey) -> Result<()> {
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
                return Err(StorageError::io(format!("backup signing audit log: {e}")).into());
            }
        }

        if let Err(e) = std::fs::rename(&temp_path, &self.path) {
            if backup_path.exists() {
                let _ = std::fs::rename(&backup_path, &self.path);
            }
            let _ = std::fs::remove_file(&temp_path);
            return Err(StorageError::io(format!("replace signing audit log: {e}")).into());
        }

        let _ = std::fs::remove_file(&backup_path);
        self.last_hash = final_hash;
        Ok(())
    }

    fn write_entries_to_temp(
        &self,
        temp_path: &Path,
        entries: &[SigningAuditEntry],
        data_key: &SecretKey,
    ) -> Result<[u8; 32]> {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts.open(temp_path)?;

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

    #[test]
    fn test_signing_audit_hash_chain() {
        let genesis = [0u8; 32];
        let entry1 = SigningAuditEntry::new(
            SigningRequestType::SignEvent,
            SigningDecision::Approved,
            false,
            "abc123".into(),
            genesis,
        )
        .with_event_kind(1)
        .finalize();

        assert!(entry1.verify(&genesis));

        let entry2 = SigningAuditEntry::new(
            SigningRequestType::SignEvent,
            SigningDecision::Denied,
            true,
            "def456".into(),
            entry1.hash,
        )
        .with_event_kind(30023)
        .with_reason("rate limited")
        .finalize();

        assert!(entry2.verify(&entry1.hash));
        assert!(!entry2.verify(&genesis));
    }

    #[test]
    fn test_signing_audit_log_persistence() {
        let dir = tempdir().unwrap();
        let key = test_key();

        {
            let mut log = SigningAuditLog::open(dir.path(), &key).unwrap();
            let entry = SigningAuditEntry::new(
                SigningRequestType::Connect,
                SigningDecision::Approved,
                false,
                "app1".into(),
                log.last_hash(),
            )
            .with_caller_name("Test App");
            log.log(entry, &key).unwrap();
        }

        {
            let log = SigningAuditLog::open(dir.path(), &key).unwrap();
            let entries = log.read_all(&key).unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].request_type, SigningRequestType::Connect);
            assert_eq!(entries[0].caller_name, Some("Test App".into()));
        }
    }

    #[test]
    fn test_signing_audit_chain_verification() {
        let dir = tempdir().unwrap();
        let key = test_key();
        let mut log = SigningAuditLog::open(dir.path(), &key).unwrap();

        for i in 0..5 {
            let entry = SigningAuditEntry::new(
                SigningRequestType::SignEvent,
                SigningDecision::Approved,
                i % 2 == 0,
                format!("app{i}"),
                log.last_hash(),
            )
            .with_event_kind(1);
            log.log(entry, &key).unwrap();
        }

        assert!(log.verify_chain(&key).unwrap().0);
    }

    #[test]
    fn test_signing_audit_pagination() {
        let dir = tempdir().unwrap();
        let key = test_key();
        let mut log = SigningAuditLog::open(dir.path(), &key).unwrap();

        for i in 0..10 {
            let caller = if i % 3 == 0 { "app_a" } else { "app_b" };
            let entry = SigningAuditEntry::new(
                SigningRequestType::SignEvent,
                SigningDecision::Approved,
                false,
                caller.into(),
                log.last_hash(),
            );
            log.log(entry, &key).unwrap();
        }

        let page = log.read_page(&key, 0, 3, None).unwrap();
        assert_eq!(page.len(), 3);

        let page = log.read_page(&key, 3, 3, None).unwrap();
        assert_eq!(page.len(), 3);

        let filtered = log.read_page(&key, 0, 100, Some("app_a")).unwrap();
        assert_eq!(filtered.len(), 4);
    }

    #[test]
    fn test_signing_audit_distinct_callers() {
        let dir = tempdir().unwrap();
        let key = test_key();
        let mut log = SigningAuditLog::open(dir.path(), &key).unwrap();

        for caller in &["app_a", "app_b", "app_a", "app_c"] {
            let entry = SigningAuditEntry::new(
                SigningRequestType::SignEvent,
                SigningDecision::Approved,
                false,
                caller.to_string(),
                log.last_hash(),
            );
            log.log(entry, &key).unwrap();
        }

        let callers = log.distinct_callers(&key).unwrap();
        assert_eq!(callers.len(), 3);
    }
}
