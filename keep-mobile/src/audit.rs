// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::KeepMobileError;
use keep_core::crypto::blake2b_256;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

const MAX_AUDIT_ENTRIES: usize = 10_000;
const MAX_PUBKEY_LENGTH: usize = 256;
const MAX_DETAILS_LENGTH: usize = 4096;

fn truncate_str(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        return s;
    }
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventType {
    Sign,
    SignFailed,
    FrostSign,
    FrostSignFailed,
    ShareImport,
    ShareExport,
    ShareDelete,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sign => write!(f, "sign"),
            Self::SignFailed => write!(f, "sign_failed"),
            Self::FrostSign => write!(f, "frost_sign"),
            Self::FrostSignFailed => write!(f, "frost_sign_failed"),
            Self::ShareImport => write!(f, "share_import"),
            Self::ShareExport => write!(f, "share_export"),
            Self::ShareDelete => write!(f, "share_delete"),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: i64,
    pub event_type: AuditEventType,
    pub pubkey: Option<String>,
    pub success: bool,
    pub details: Option<String>,
    pub prev_hash: Vec<u8>,
    pub hash: Vec<u8>,
}

impl AuditEntry {
    pub fn new(event_type: AuditEventType, prev_hash: [u8; 32]) -> Self {
        Self {
            timestamp: chrono::Utc::now().timestamp(),
            event_type,
            pubkey: None,
            success: true,
            details: None,
            prev_hash: prev_hash.to_vec(),
            hash: vec![0u8; 32],
        }
    }

    pub fn with_pubkey(mut self, pubkey: &str) -> Self {
        self.pubkey = Some(truncate_str(pubkey, MAX_PUBKEY_LENGTH).to_string());
        self
    }

    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(truncate_str(details, MAX_DETAILS_LENGTH).to_string());
        self
    }

    pub fn finalize(mut self) -> Self {
        self.hash = self.compute_hash().to_vec();
        self
    }

    fn compute_hash(&self) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&(self.event_type as u8).to_le_bytes());
        if let Some(ref pk) = self.pubkey {
            data.extend_from_slice(pk.as_bytes());
        }
        data.push(self.success as u8);
        if let Some(ref d) = self.details {
            data.extend_from_slice(d.as_bytes());
        }
        data.extend_from_slice(&self.prev_hash);
        blake2b_256(&data)
    }

    fn verify(&self, prev_hash: &[u8]) -> bool {
        if prev_hash.len() != 32 || self.prev_hash.len() != 32 || self.hash.len() != 32 {
            return false;
        }
        let prev_hash_match = self.prev_hash.ct_eq(prev_hash);
        let computed = self.compute_hash();
        let hash_match = self.hash.ct_eq(&computed);
        (prev_hash_match & hash_match).into()
    }
}

#[uniffi::export(with_foreign)]
pub trait AuditStorage: Send + Sync {
    fn store_entry(&self, entry_json: String) -> Result<(), KeepMobileError>;
    fn load_entries(&self, limit: Option<u32>) -> Result<Vec<String>, KeepMobileError>;
    /// Privileged operation: callers must ensure proper authorization before invoking.
    fn clear_entries(&self) -> Result<(), KeepMobileError>;
}

#[derive(uniffi::Object)]
pub struct AuditLog {
    storage: std::sync::Arc<dyn AuditStorage>,
    last_hash: std::sync::Mutex<[u8; 32]>,
}

#[uniffi::export]
impl AuditLog {
    #[uniffi::constructor]
    pub fn new(storage: std::sync::Arc<dyn AuditStorage>) -> Result<Self, KeepMobileError> {
        let entries = storage.load_entries(None)?;

        if entries.len() > MAX_AUDIT_ENTRIES {
            return Err(KeepMobileError::StorageError {
                msg: format!("Audit log exceeds maximum of {} entries", MAX_AUDIT_ENTRIES),
            });
        }

        let last_hash = if let Some(last_json) = entries.last() {
            let entry: AuditEntry =
                serde_json::from_str(last_json).map_err(|e| KeepMobileError::Serialization {
                    msg: format!("Invalid audit entry: {}", e),
                })?;
            entry
                .hash
                .as_slice()
                .try_into()
                .map_err(|_| KeepMobileError::Serialization {
                    msg: "Invalid hash length".into(),
                })?
        } else {
            [0u8; 32]
        };

        Ok(Self {
            storage,
            last_hash: std::sync::Mutex::new(last_hash),
        })
    }

    pub fn log_event(
        &self,
        event_type: AuditEventType,
        pubkey: Option<String>,
        success: bool,
        details: Option<String>,
    ) -> Result<(), KeepMobileError> {
        let entry_count = self.storage.load_entries(None)?.len();
        if entry_count >= MAX_AUDIT_ENTRIES {
            return Err(KeepMobileError::StorageError {
                msg: format!(
                    "Audit log full: {} entries (max {})",
                    entry_count, MAX_AUDIT_ENTRIES
                ),
            });
        }

        let mut last_hash = self
            .last_hash
            .lock()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "Lock poisoned".into(),
            })?;

        let mut entry = AuditEntry::new(event_type, *last_hash);
        if let Some(pk) = pubkey {
            entry = entry.with_pubkey(&pk);
        }
        entry = entry.with_success(success);
        if let Some(d) = details {
            entry = entry.with_details(&d);
        }
        entry = entry.finalize();

        let entry_json = serde_json::to_string(&entry)
            .map_err(|e| KeepMobileError::Serialization { msg: e.to_string() })?;

        let new_hash: [u8; 32] =
            entry
                .hash
                .as_slice()
                .try_into()
                .map_err(|_| KeepMobileError::Serialization {
                    msg: "Invalid hash length".into(),
                })?;

        self.storage.store_entry(entry_json)?;
        *last_hash = new_hash;

        Ok(())
    }

    pub fn get_entries(&self, limit: Option<u32>) -> Result<Vec<AuditEntry>, KeepMobileError> {
        let entry_jsons = self.storage.load_entries(limit)?;

        if entry_jsons.len() > MAX_AUDIT_ENTRIES {
            return Err(KeepMobileError::StorageError {
                msg: format!("Audit log exceeds maximum of {} entries", MAX_AUDIT_ENTRIES),
            });
        }

        let mut entries = Vec::with_capacity(entry_jsons.len());
        for json in entry_jsons {
            let entry: AuditEntry =
                serde_json::from_str(&json).map_err(|e| KeepMobileError::Serialization {
                    msg: format!("Invalid audit entry: {}", e),
                })?;
            entries.push(entry);
        }
        Ok(entries)
    }

    pub fn export_json(&self) -> Result<String, KeepMobileError> {
        let entries = self.get_entries(None)?;
        serde_json::to_string_pretty(&entries).map_err(|e| KeepMobileError::Serialization {
            msg: format!("Export failed: {}", e),
        })
    }

    pub fn verify_chain(&self) -> Result<bool, KeepMobileError> {
        let entries = self.get_entries(None)?;
        let mut prev_hash = [0u8; 32];

        for entry in entries {
            if !entry.verify(&prev_hash) {
                return Ok(false);
            }
            prev_hash =
                entry
                    .hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| KeepMobileError::Serialization {
                        msg: "Invalid hash length".into(),
                    })?;
        }

        Ok(true)
    }

    pub fn entry_count(&self) -> Result<u32, KeepMobileError> {
        let entries = self.storage.load_entries(None)?;
        let count = entries.len().min(MAX_AUDIT_ENTRIES);
        Ok(count as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct MockStorage {
        entries: Mutex<Vec<String>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                entries: Mutex::new(Vec::new()),
            }
        }
    }

    impl AuditStorage for MockStorage {
        fn store_entry(&self, entry_json: String) -> Result<(), KeepMobileError> {
            self.entries.lock().unwrap().push(entry_json);
            Ok(())
        }

        fn load_entries(&self, limit: Option<u32>) -> Result<Vec<String>, KeepMobileError> {
            let entries = self.entries.lock().unwrap();
            match limit {
                Some(n) => Ok(entries
                    .iter()
                    .rev()
                    .take(n as usize)
                    .rev()
                    .cloned()
                    .collect()),
                None => Ok(entries.clone()),
            }
        }

        fn clear_entries(&self) -> Result<(), KeepMobileError> {
            self.entries.lock().unwrap().clear();
            Ok(())
        }
    }

    #[test]
    fn test_audit_entry_hash() {
        let entry = AuditEntry::new(AuditEventType::Sign, [0u8; 32])
            .with_pubkey("abc123")
            .with_success(true)
            .finalize();

        assert_eq!(entry.hash.len(), 32);
        assert_ne!(entry.hash, vec![0u8; 32]);
    }

    #[test]
    fn test_audit_chain_verification() {
        let storage = Arc::new(MockStorage::new());
        let log = AuditLog::new(storage).unwrap();

        log.log_event(AuditEventType::ShareImport, Some("pk1".into()), true, None)
            .unwrap();
        log.log_event(AuditEventType::FrostSign, Some("pk1".into()), true, None)
            .unwrap();
        log.log_event(
            AuditEventType::FrostSign,
            Some("pk1".into()),
            false,
            Some("timeout".into()),
        )
        .unwrap();

        assert!(log.verify_chain().unwrap());
        assert_eq!(log.entry_count().unwrap(), 3);
    }

    #[test]
    fn test_export_json() {
        let storage = Arc::new(MockStorage::new());
        let log = AuditLog::new(storage).unwrap();

        log.log_event(AuditEventType::Sign, Some("pk1".into()), true, None)
            .unwrap();

        let json = log.export_json().unwrap();
        assert!(json.contains("Sign"), "JSON: {}", json);
        assert!(json.contains("pk1"), "JSON: {}", json);
    }

    #[test]
    fn test_chain_detects_tampering() {
        let mock = Arc::new(MockStorage::new());
        let storage: Arc<dyn AuditStorage> = Arc::clone(&mock) as Arc<dyn AuditStorage>;
        let log = AuditLog::new(storage).unwrap();

        log.log_event(AuditEventType::Sign, Some("pk1".into()), true, None)
            .unwrap();
        log.log_event(AuditEventType::FrostSign, Some("pk1".into()), true, None)
            .unwrap();

        {
            let mut entries = mock.entries.lock().unwrap();
            if let Some(first) = entries.first_mut() {
                let mut entry: AuditEntry = serde_json::from_str(first).unwrap();
                entry.success = false;
                *first = serde_json::to_string(&entry).unwrap();
            }
        }

        let storage2: Arc<dyn AuditStorage> = mock;
        let log2 = AuditLog::new(storage2).unwrap();
        assert!(!log2.verify_chain().unwrap());
    }
}
