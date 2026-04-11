// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

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

fn require_hash_32(hash: &[u8], field: &str) -> Result<(), KeepMobileError> {
    if hash.len() != 32 {
        return Err(KeepMobileError::InvalidInput {
            msg: format!("{field} length {} != 32", hash.len()),
        });
    }
    Ok(())
}

fn hash_optional_str(data: &mut Vec<u8>, opt: &Option<String>) {
    match opt {
        Some(s) => {
            data.push(1);
            data.extend_from_slice(&(s.len() as u32).to_le_bytes());
            data.extend_from_slice(s.as_bytes());
        }
        None => data.push(0),
    }
}

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventType {
    Sign = 0,
    SignFailed = 1,
    FrostSign = 2,
    FrostSignFailed = 3,
    ShareImport = 4,
    ShareExport = 5,
    ShareDelete = 6,
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
        data.push(self.event_type as u8);
        hash_optional_str(&mut data, &self.pubkey);
        data.push(self.success as u8);
        hash_optional_str(&mut data, &self.details);
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

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
struct AuditEntryExport {
    timestamp: i64,
    event_type: AuditEventType,
    pubkey: Option<String>,
    success: bool,
    details: Option<String>,
    prev_hash: String,
    hash: String,
}

impl TryFrom<AuditEntry> for AuditEntryExport {
    type Error = KeepMobileError;

    fn try_from(e: AuditEntry) -> Result<Self, Self::Error> {
        require_hash_32(&e.prev_hash, "prev_hash")?;
        require_hash_32(&e.hash, "hash")?;
        Ok(Self {
            timestamp: e.timestamp,
            event_type: e.event_type,
            pubkey: e.pubkey,
            success: e.success,
            details: e.details,
            prev_hash: hex::encode(e.prev_hash),
            hash: hex::encode(e.hash),
        })
    }
}

#[uniffi::export(with_foreign)]
pub trait AuditStorage: Send + Sync {
    fn store_entry(&self, entry_json: String) -> Result<(), KeepMobileError>;
    fn load_entries(&self, limit: Option<u32>) -> Result<Vec<String>, KeepMobileError>;
    fn load_last_entry(&self) -> Result<Option<String>, KeepMobileError>;
    fn entry_count(&self) -> Result<u32, KeepMobileError>;
    fn clear_entries(&self, confirm: String) -> Result<(), KeepMobileError>;
}

#[derive(uniffi::Object)]
pub struct AuditLog {
    storage: std::sync::Arc<dyn AuditStorage>,
    last_hash: std::sync::Mutex<[u8; 32]>,
}

impl AuditLog {
    fn load_all_checked(&self) -> Result<Vec<AuditEntry>, KeepMobileError> {
        const _: () = assert!(MAX_AUDIT_ENTRIES < u32::MAX as usize);
        let entry_jsons = self
            .storage
            .load_entries(Some(MAX_AUDIT_ENTRIES as u32 + 1))?;
        if entry_jsons.len() > MAX_AUDIT_ENTRIES {
            return Err(KeepMobileError::StorageError {
                msg: format!("Audit log exceeds maximum of {MAX_AUDIT_ENTRIES} entries"),
            });
        }
        let mut entries = Vec::with_capacity(entry_jsons.len());
        for json in entry_jsons {
            let entry: AuditEntry =
                serde_json::from_str(&json).map_err(|e| KeepMobileError::Serialization {
                    msg: format!("Invalid audit entry: {e}"),
                })?;
            entries.push(entry);
        }
        Ok(entries)
    }
}

#[uniffi::export]
impl AuditLog {
    #[uniffi::constructor]
    pub fn new(storage: std::sync::Arc<dyn AuditStorage>) -> Result<Self, KeepMobileError> {
        let last_hash = if let Some(last_json) = storage.load_last_entry()? {
            let entry: AuditEntry =
                serde_json::from_str(&last_json).map_err(|e| KeepMobileError::Serialization {
                    msg: format!("Invalid audit entry: {e}"),
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
        let mut last_hash = self
            .last_hash
            .lock()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "Lock poisoned".into(),
            })?;

        let entry_count = self.storage.entry_count()? as usize;
        if entry_count >= MAX_AUDIT_ENTRIES {
            return Err(KeepMobileError::StorageError {
                msg: format!("Audit log full: {entry_count} entries (max {MAX_AUDIT_ENTRIES})"),
            });
        }

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
        const _: () = assert!(MAX_AUDIT_ENTRIES < u32::MAX as usize);
        let capped = Some(
            limit
                .unwrap_or(MAX_AUDIT_ENTRIES as u32 + 1)
                .min(MAX_AUDIT_ENTRIES as u32 + 1),
        );
        let entry_jsons = self.storage.load_entries(capped)?;
        let mut entries = Vec::with_capacity(entry_jsons.len());
        for json in entry_jsons {
            let entry: AuditEntry =
                serde_json::from_str(&json).map_err(|e| KeepMobileError::Serialization {
                    msg: format!("Invalid audit entry: {e}"),
                })?;
            entries.push(entry);
        }
        Ok(entries)
    }

    pub fn export_json(&self) -> Result<String, KeepMobileError> {
        let entries = self.load_all_checked()?;
        let exports: Vec<AuditEntryExport> = entries
            .into_iter()
            .map(AuditEntryExport::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        serde_json::to_string_pretty(&exports).map_err(|e| KeepMobileError::Serialization {
            msg: format!("Export failed: {e}"),
        })
    }

    pub fn verify_chain(&self) -> Result<bool, KeepMobileError> {
        let entries = self.load_all_checked()?;
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
        self.storage.entry_count()
    }

    pub fn clear_entries(&self, confirm: String) -> Result<(), KeepMobileError> {
        let mut last_hash = self
            .last_hash
            .lock()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "Lock poisoned".into(),
            })?;
        self.storage.clear_entries(confirm)?;
        *last_hash = [0u8; 32];
        Ok(())
    }
}

const MAX_CALLER_LENGTH: usize = 256;
const MAX_REASON_LENGTH: usize = 4096;

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningRequestType {
    Connect = 0,
    GetPublicKey = 1,
    SignEvent = 2,
    Nip04Encrypt = 3,
    Nip04Decrypt = 4,
    Nip44Encrypt = 5,
    Nip44Decrypt = 6,
    Disconnect = 7,
    KillSwitch = 8,
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
            Self::KillSwitch => write!(f, "kill_switch"),
        }
    }
}

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningDecision {
    Approved = 0,
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

#[derive(uniffi::Record, Clone, Debug, Serialize, Deserialize)]
pub struct SigningAuditEntry {
    pub timestamp: i64,
    pub request_type: SigningRequestType,
    pub decision: SigningDecision,
    pub was_automatic: bool,
    pub caller: String,
    pub caller_name: Option<String>,
    pub event_kind: Option<u32>,
    pub reason: Option<String>,
    pub prev_hash: Vec<u8>,
    pub hash: Vec<u8>,
}

impl SigningAuditEntry {
    fn new(
        request_type: SigningRequestType,
        decision: SigningDecision,
        was_automatic: bool,
        caller: &str,
        prev_hash: [u8; 32],
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().timestamp(),
            request_type,
            decision,
            was_automatic,
            caller: truncate_str(caller, MAX_CALLER_LENGTH).to_string(),
            caller_name: None,
            event_kind: None,
            reason: None,
            prev_hash: prev_hash.to_vec(),
            hash: vec![0u8; 32],
        }
    }

    fn with_caller_name(mut self, name: &str) -> Self {
        self.caller_name = Some(truncate_str(name, MAX_CALLER_LENGTH).to_string());
        self
    }

    fn with_event_kind(mut self, kind: u32) -> Self {
        self.event_kind = Some(kind);
        self
    }

    fn with_reason(mut self, reason: &str) -> Self {
        self.reason = Some(truncate_str(reason, MAX_REASON_LENGTH).to_string());
        self
    }

    fn finalize(mut self) -> Self {
        self.hash = self.compute_hash().to_vec();
        self
    }

    fn compute_hash(&self) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.push(self.request_type as u8);
        data.push(self.decision as u8);
        data.push(self.was_automatic as u8);
        data.extend_from_slice(&(self.caller.len() as u32).to_le_bytes());
        data.extend_from_slice(self.caller.as_bytes());
        hash_optional_str(&mut data, &self.caller_name);
        match self.event_kind {
            Some(kind) => {
                data.push(1);
                data.extend_from_slice(&kind.to_le_bytes());
            }
            None => data.push(0),
        }
        hash_optional_str(&mut data, &self.reason);
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

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
struct SigningAuditEntryExport {
    timestamp: i64,
    request_type: SigningRequestType,
    decision: SigningDecision,
    was_automatic: bool,
    caller: String,
    caller_name: Option<String>,
    event_kind: Option<u32>,
    reason: Option<String>,
    prev_hash: String,
    hash: String,
}

impl TryFrom<SigningAuditEntry> for SigningAuditEntryExport {
    type Error = KeepMobileError;

    fn try_from(e: SigningAuditEntry) -> Result<Self, Self::Error> {
        require_hash_32(&e.prev_hash, "prev_hash")?;
        require_hash_32(&e.hash, "hash")?;
        Ok(Self {
            timestamp: e.timestamp,
            request_type: e.request_type,
            decision: e.decision,
            was_automatic: e.was_automatic,
            caller: e.caller,
            caller_name: e.caller_name,
            event_kind: e.event_kind,
            reason: e.reason,
            prev_hash: hex::encode(e.prev_hash),
            hash: hex::encode(e.hash),
        })
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct ChainStatus {
    pub verified: bool,
    pub entry_count: u32,
}

#[uniffi::export(with_foreign)]
pub trait SigningAuditStorage: Send + Sync {
    fn store_entry(&self, entry_json: String) -> Result<(), KeepMobileError>;
    fn load_entries(&self, limit: Option<u32>) -> Result<Vec<String>, KeepMobileError>;
    fn load_entries_page(
        &self,
        offset: u32,
        limit: u32,
        caller_filter: Option<String>,
    ) -> Result<Vec<String>, KeepMobileError>;
    fn distinct_callers(&self) -> Result<Vec<String>, KeepMobileError>;
    fn load_last_entry(&self) -> Result<Option<String>, KeepMobileError>;
    fn entry_count(&self) -> Result<u32, KeepMobileError>;
    fn clear_entries(&self, confirm: String) -> Result<(), KeepMobileError>;
}

#[derive(uniffi::Object)]
pub struct SigningAuditLog {
    storage: std::sync::Arc<dyn SigningAuditStorage>,
    last_hash: std::sync::Mutex<[u8; 32]>,
}

impl SigningAuditLog {
    fn load_all_checked(&self) -> Result<Vec<SigningAuditEntry>, KeepMobileError> {
        const _: () = assert!(MAX_AUDIT_ENTRIES < u32::MAX as usize);
        let entry_jsons = self
            .storage
            .load_entries(Some(MAX_AUDIT_ENTRIES as u32 + 1))?;
        if entry_jsons.len() > MAX_AUDIT_ENTRIES {
            return Err(KeepMobileError::StorageError {
                msg: format!(
                    "Signing audit log exceeds maximum of {MAX_AUDIT_ENTRIES} entries"
                ),
            });
        }
        let mut entries = Vec::with_capacity(entry_jsons.len());
        for json in entry_jsons {
            let entry: SigningAuditEntry =
                serde_json::from_str(&json).map_err(|e| KeepMobileError::Serialization {
                    msg: format!("Invalid signing audit entry: {e}"),
                })?;
            entries.push(entry);
        }
        Ok(entries)
    }
}

#[uniffi::export]
impl SigningAuditLog {
    #[uniffi::constructor]
    pub fn new(storage: std::sync::Arc<dyn SigningAuditStorage>) -> Result<Self, KeepMobileError> {
        let last_hash = if let Some(last_json) = storage.load_last_entry()? {
            let entry: SigningAuditEntry =
                serde_json::from_str(&last_json).map_err(|e| KeepMobileError::Serialization {
                    msg: format!("Invalid signing audit entry: {e}"),
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

    #[allow(clippy::too_many_arguments)]
    pub fn log_event(
        &self,
        request_type: SigningRequestType,
        decision: SigningDecision,
        was_automatic: bool,
        caller: String,
        caller_name: Option<String>,
        event_kind: Option<u32>,
        reason: Option<String>,
    ) -> Result<(), KeepMobileError> {
        let mut last_hash = self
            .last_hash
            .lock()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "Lock poisoned".into(),
            })?;

        let entry_count = self.storage.entry_count()? as usize;
        if entry_count >= MAX_AUDIT_ENTRIES {
            return Err(KeepMobileError::StorageError {
                msg: format!(
                    "Signing audit log full: {entry_count} entries (max {MAX_AUDIT_ENTRIES})"
                ),
            });
        }

        let mut entry =
            SigningAuditEntry::new(request_type, decision, was_automatic, &caller, *last_hash);
        if let Some(name) = caller_name {
            entry = entry.with_caller_name(&name);
        }
        if let Some(kind) = event_kind {
            entry = entry.with_event_kind(kind);
        }
        if let Some(r) = reason {
            entry = entry.with_reason(&r);
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

    pub fn get_entries(
        &self,
        offset: u32,
        limit: u32,
        caller_filter: Option<String>,
    ) -> Result<Vec<SigningAuditEntry>, KeepMobileError> {
        let entry_jsons = self
            .storage
            .load_entries_page(offset, limit, caller_filter)?;

        let mut entries = Vec::with_capacity(entry_jsons.len());
        for json in entry_jsons {
            let entry: SigningAuditEntry =
                serde_json::from_str(&json).map_err(|e| KeepMobileError::Serialization {
                    msg: format!("Invalid signing audit entry: {e}"),
                })?;
            entries.push(entry);
        }
        Ok(entries)
    }

    pub fn get_distinct_callers(&self) -> Result<Vec<String>, KeepMobileError> {
        self.storage.distinct_callers()
    }

    pub fn verify_chain(&self) -> Result<ChainStatus, KeepMobileError> {
        let entries = self.load_all_checked()?;
        let count = entries.len() as u32;

        let mut prev_hash = [0u8; 32];
        for entry in entries {
            if !entry.verify(&prev_hash) {
                return Ok(ChainStatus {
                    verified: false,
                    entry_count: count,
                });
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

        Ok(ChainStatus {
            verified: true,
            entry_count: count,
        })
    }

    pub fn export_json(&self) -> Result<String, KeepMobileError> {
        let entries = self.load_all_checked()?;
        let exports: Vec<SigningAuditEntryExport> = entries
            .into_iter()
            .map(SigningAuditEntryExport::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        serde_json::to_string_pretty(&exports).map_err(|e| KeepMobileError::Serialization {
            msg: format!("Export failed: {e}"),
        })
    }

    pub fn get_entry_count(&self) -> Result<u32, KeepMobileError> {
        self.storage.entry_count()
    }

    pub fn clear_entries(&self, confirm: String) -> Result<(), KeepMobileError> {
        let mut last_hash = self
            .last_hash
            .lock()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "Lock poisoned".into(),
            })?;
        self.storage.clear_entries(confirm)?;
        *last_hash = [0u8; 32];
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn assert_lowercase_hex(s: &str) {
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

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

        fn load_last_entry(&self) -> Result<Option<String>, KeepMobileError> {
            Ok(self.entries.lock().unwrap().last().cloned())
        }

        fn entry_count(&self) -> Result<u32, KeepMobileError> {
            Ok(self.entries.lock().unwrap().len() as u32)
        }

        fn clear_entries(&self, confirm: String) -> Result<(), KeepMobileError> {
            if confirm != "CLEAR_ALL_ENTRIES" {
                return Err(KeepMobileError::StorageError {
                    msg: "Confirmation string must be 'CLEAR_ALL_ENTRIES'".into(),
                });
            }
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

        let json = log.export_json().unwrap();
        let entries: Vec<AuditEntryExport> = serde_json::from_str(&json).unwrap();
        assert!(entries.is_empty());

        log.log_event(AuditEventType::Sign, Some("pk1".into()), true, None)
            .unwrap();

        let json = log.export_json().unwrap();
        let entries: Vec<AuditEntryExport> = serde_json::from_str(&json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, AuditEventType::Sign);
        assert_eq!(entries[0].pubkey.as_deref(), Some("pk1"));
        assert!(entries[0].success);
        assert_lowercase_hex(&entries[0].hash);
        assert_lowercase_hex(&entries[0].prev_hash);
    }

    #[test]
    fn test_export_json_chain_linkage() {
        let storage = Arc::new(MockStorage::new());
        let log = AuditLog::new(storage).unwrap();

        log.log_event(AuditEventType::Sign, Some("pk1".into()), true, None)
            .unwrap();
        log.log_event(AuditEventType::FrostSign, Some("pk2".into()), true, None)
            .unwrap();
        log.log_event(
            AuditEventType::ShareExport,
            Some("pk1".into()),
            true,
            Some("exported".into()),
        )
        .unwrap();

        let json = log.export_json().unwrap();
        let entries: Vec<AuditEntryExport> = serde_json::from_str(&json).unwrap();
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].prev_hash, "0".repeat(64));
        for i in 1..entries.len() {
            assert_eq!(
                entries[i].prev_hash, entries[i - 1].hash,
                "entry {i} prev_hash should equal entry {} hash",
                i - 1
            );
        }
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

    struct MockSigningStorage {
        entries: Mutex<Vec<String>>,
    }

    impl MockSigningStorage {
        fn new() -> Self {
            Self {
                entries: Mutex::new(Vec::new()),
            }
        }
    }

    impl SigningAuditStorage for MockSigningStorage {
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

        fn load_entries_page(
            &self,
            offset: u32,
            limit: u32,
            caller_filter: Option<String>,
        ) -> Result<Vec<String>, KeepMobileError> {
            let entries = self.entries.lock().unwrap();
            let filtered: Vec<_> = entries
                .iter()
                .rev()
                .filter(|json| {
                    caller_filter.as_ref().is_none_or(|filter| {
                        serde_json::from_str::<SigningAuditEntry>(json)
                            .map(|e| e.caller == *filter)
                            .unwrap_or(false)
                    })
                })
                .skip(offset as usize)
                .take(limit as usize)
                .cloned()
                .collect();
            Ok(filtered)
        }

        fn distinct_callers(&self) -> Result<Vec<String>, KeepMobileError> {
            let entries = self.entries.lock().unwrap();
            let mut seen = std::collections::HashSet::new();
            let mut callers = Vec::new();
            for json in entries.iter().rev() {
                if let Ok(entry) = serde_json::from_str::<SigningAuditEntry>(json) {
                    if seen.insert(entry.caller.clone()) {
                        callers.push(entry.caller);
                    }
                }
            }
            Ok(callers)
        }

        fn load_last_entry(&self) -> Result<Option<String>, KeepMobileError> {
            Ok(self.entries.lock().unwrap().last().cloned())
        }

        fn entry_count(&self) -> Result<u32, KeepMobileError> {
            Ok(self.entries.lock().unwrap().len() as u32)
        }

        fn clear_entries(&self, confirm: String) -> Result<(), KeepMobileError> {
            if confirm != "CLEAR_ALL_ENTRIES" {
                return Err(KeepMobileError::StorageError {
                    msg: "Confirmation string must be 'CLEAR_ALL_ENTRIES'".into(),
                });
            }
            self.entries.lock().unwrap().clear();
            Ok(())
        }
    }

    #[test]
    fn test_signing_audit_chain_verification() {
        let storage = Arc::new(MockSigningStorage::new());
        let log = SigningAuditLog::new(storage).unwrap();

        log.log_event(
            SigningRequestType::SignEvent,
            SigningDecision::Approved,
            false,
            "app1".into(),
            Some("Test App".into()),
            Some(1),
            None,
        )
        .unwrap();
        log.log_event(
            SigningRequestType::Nip44Encrypt,
            SigningDecision::Denied,
            true,
            "app2".into(),
            None,
            None,
            Some("rate limited".into()),
        )
        .unwrap();

        let status = log.verify_chain().unwrap();
        assert!(status.verified);
        assert_eq!(status.entry_count, 2);
    }

    #[test]
    fn test_signing_audit_pagination() {
        let storage = Arc::new(MockSigningStorage::new());
        let log = SigningAuditLog::new(storage).unwrap();

        for i in 0..10 {
            let caller = if i % 3 == 0 { "app_a" } else { "app_b" };
            log.log_event(
                SigningRequestType::SignEvent,
                SigningDecision::Approved,
                false,
                caller.into(),
                None,
                Some(1),
                None,
            )
            .unwrap();
        }

        let page = log.get_entries(0, 3, None).unwrap();
        assert_eq!(page.len(), 3);

        let filtered = log.get_entries(0, 100, Some("app_a".into())).unwrap();
        assert_eq!(filtered.len(), 4);
    }

    #[test]
    fn test_signing_audit_distinct_callers() {
        let storage = Arc::new(MockSigningStorage::new());
        let log = SigningAuditLog::new(storage).unwrap();

        for caller in &["app_a", "app_b", "app_a", "app_c"] {
            log.log_event(
                SigningRequestType::Connect,
                SigningDecision::Approved,
                false,
                caller.to_string(),
                None,
                None,
                None,
            )
            .unwrap();
        }

        let callers = log.get_distinct_callers().unwrap();
        assert_eq!(callers.len(), 3);
    }

    #[test]
    fn test_signing_audit_export_json() {
        let storage = Arc::new(MockSigningStorage::new());
        let log = SigningAuditLog::new(storage).unwrap();

        let json = log.export_json().unwrap();
        let entries: Vec<SigningAuditEntryExport> = serde_json::from_str(&json).unwrap();
        assert!(entries.is_empty());

        log.log_event(
            SigningRequestType::SignEvent,
            SigningDecision::Approved,
            false,
            "app1".into(),
            Some("Test App".into()),
            Some(1),
            None,
        )
        .unwrap();

        let json = log.export_json().unwrap();
        let entries: Vec<SigningAuditEntryExport> = serde_json::from_str(&json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].request_type, SigningRequestType::SignEvent);
        assert_eq!(entries[0].decision, SigningDecision::Approved);
        assert_eq!(entries[0].caller, "app1");
        assert_eq!(entries[0].caller_name.as_deref(), Some("Test App"));
        assert_eq!(entries[0].event_kind, Some(1));
        assert_lowercase_hex(&entries[0].hash);
        assert_lowercase_hex(&entries[0].prev_hash);
    }

    #[test]
    fn test_signing_export_json_chain_linkage() {
        let storage = Arc::new(MockSigningStorage::new());
        let log = SigningAuditLog::new(storage).unwrap();

        for i in 0..3 {
            log.log_event(
                SigningRequestType::SignEvent,
                SigningDecision::Approved,
                false,
                format!("app{i}"),
                Some(format!("App {i}")),
                Some(1),
                None,
            )
            .unwrap();
        }

        let json = log.export_json().unwrap();
        let entries: Vec<SigningAuditEntryExport> = serde_json::from_str(&json).unwrap();
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].prev_hash, "0".repeat(64));
        for i in 1..entries.len() {
            assert_eq!(
                entries[i].prev_hash, entries[i - 1].hash,
                "entry {i} prev_hash should equal entry {} hash",
                i - 1
            );
        }
    }

    #[test]
    fn test_signing_audit_tamper_detection() {
        let mock = Arc::new(MockSigningStorage::new());
        let storage: Arc<dyn SigningAuditStorage> =
            Arc::clone(&mock) as Arc<dyn SigningAuditStorage>;
        let log = SigningAuditLog::new(storage).unwrap();

        log.log_event(
            SigningRequestType::SignEvent,
            SigningDecision::Approved,
            false,
            "app1".into(),
            None,
            Some(1),
            None,
        )
        .unwrap();
        log.log_event(
            SigningRequestType::SignEvent,
            SigningDecision::Denied,
            true,
            "app1".into(),
            None,
            Some(1),
            None,
        )
        .unwrap();

        {
            let mut entries = mock.entries.lock().unwrap();
            if let Some(first) = entries.first_mut() {
                let mut entry: SigningAuditEntry = serde_json::from_str(first).unwrap();
                entry.was_automatic = true;
                *first = serde_json::to_string(&entry).unwrap();
            }
        }

        let storage2: Arc<dyn SigningAuditStorage> = mock;
        let log2 = SigningAuditLog::new(storage2).unwrap();
        let status = log2.verify_chain().unwrap();
        assert!(!status.verified);
    }
}
