// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use chrono::{DateTime, Utc};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AuditAction {
    Connect,
    Disconnect,
    GetPublicKey,
    SignEvent,
    Nip04Encrypt,
    Nip04Decrypt,
    Nip44Encrypt,
    Nip44Decrypt,
    PermissionDenied,
    UserRejected,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect => write!(f, "connect"),
            Self::Disconnect => write!(f, "disconnect"),
            Self::GetPublicKey => write!(f, "get_public_key"),
            Self::SignEvent => write!(f, "sign_event"),
            Self::Nip04Encrypt => write!(f, "nip04_encrypt"),
            Self::Nip04Decrypt => write!(f, "nip04_decrypt"),
            Self::Nip44Encrypt => write!(f, "nip44_encrypt"),
            Self::Nip44Decrypt => write!(f, "nip44_decrypt"),
            Self::PermissionDenied => write!(f, "permission_denied"),
            Self::UserRejected => write!(f, "user_rejected"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub action: AuditAction,
    pub app_pubkey: String,
    pub app_name: Option<String>,
    pub event_kind: Option<u16>,
    pub event_id: Option<String>,
    pub success: bool,
    pub reason: Option<String>,
}

impl AuditEntry {
    pub fn new(action: AuditAction, app_pubkey: PublicKey) -> Self {
        Self {
            timestamp: Utc::now(),
            action,
            app_pubkey: app_pubkey.to_hex(),
            app_name: None,
            event_kind: None,
            event_id: None,
            success: true,
            reason: None,
        }
    }

    pub fn with_app_name(mut self, name: impl Into<String>) -> Self {
        self.app_name = Some(name.into());
        self
    }

    pub fn with_event_kind(mut self, kind: Kind) -> Self {
        self.event_kind = Some(kind.as_u16());
        self
    }

    pub fn with_event_id(mut self, id: EventId) -> Self {
        self.event_id = Some(id.to_hex());
        self
    }

    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

#[allow(clippy::type_complexity)]
pub struct AuditLog {
    entries: VecDeque<AuditEntry>,
    max_entries: usize,
    file: Option<File>,
    on_entry: Option<Box<dyn Fn(&AuditEntry) + Send + Sync>>,
}

impl AuditLog {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_entries),
            max_entries,
            file: None,
            on_entry: None,
        }
    }

    #[allow(dead_code)]
    pub fn open_file(&mut self, path: &Path) -> std::io::Result<()> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        self.file = Some(file);
        Ok(())
    }

    #[allow(dead_code)]
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: Fn(&AuditEntry) + Send + Sync + 'static,
    {
        self.on_entry = Some(Box::new(callback));
    }

    pub fn log(&mut self, entry: AuditEntry) {
        if let Some(ref mut file) = self.file {
            let result = serde_json::to_string(&entry)
                .map_err(|e| ("Failed to serialize audit log entry", e.to_string()))
                .and_then(|json| {
                    writeln!(file, "{}", json)
                        .map_err(|e| ("Failed to write audit log entry to file", e.to_string()))
                });

            if let Err((msg, e)) = result {
                warn!(error = %e, action = %entry.action, "{}", msg);
            }
        }

        if let Some(ref callback) = self.on_entry {
            callback(&entry);
        }

        self.entries.push_back(entry);

        while self.entries.len() > self.max_entries {
            self.entries.pop_front();
        }
    }

    #[allow(dead_code)]
    pub fn recent(&self, count: usize) -> impl Iterator<Item = &AuditEntry> {
        self.entries.iter().rev().take(count)
    }

    #[allow(dead_code)]
    pub fn by_app<'a>(&'a self, pubkey: &'a str) -> impl Iterator<Item = &'a AuditEntry> {
        self.entries.iter().filter(move |e| e.app_pubkey == pubkey)
    }
}

impl std::fmt::Display for AuditEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = if self.success { "✓" } else { "✗" };
        let app = self.app_name.as_deref().unwrap_or(&self.app_pubkey[..8]);

        write!(
            f,
            "[{}] {} {} {}",
            self.timestamp.format("%H:%M:%S"),
            status,
            app,
            self.action
        )?;

        if let Some(kind) = self.event_kind {
            write!(f, " kind:{}", kind)?;
        }

        if let Some(ref reason) = self.reason {
            write!(f, " ({})", reason)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> PublicKey {
        Keys::generate().public_key()
    }

    #[test]
    fn test_audit_entry_builder() {
        let pubkey = test_pubkey();
        let entry = AuditEntry::new(AuditAction::Connect, pubkey)
            .with_app_name("TestApp")
            .with_success(true);

        assert!(entry.success);
        assert_eq!(entry.app_name, Some("TestApp".into()));
        assert_eq!(entry.app_pubkey, pubkey.to_hex());
    }

    #[test]
    fn test_audit_entry_with_event() {
        let pubkey = test_pubkey();
        let entry = AuditEntry::new(AuditAction::SignEvent, pubkey)
            .with_event_kind(Kind::TextNote)
            .with_success(false)
            .with_reason("Permission denied");

        assert!(!entry.success);
        assert_eq!(entry.event_kind, Some(1));
        assert_eq!(entry.reason, Some("Permission denied".into()));
    }

    #[test]
    fn test_audit_log_capacity() {
        let mut log = AuditLog::new(3);
        let pubkey = test_pubkey();

        for _ in 0..5 {
            log.log(AuditEntry::new(AuditAction::Connect, pubkey));
        }

        assert_eq!(log.entries.len(), 3);
    }

    #[test]
    fn test_audit_log_recent() {
        let mut log = AuditLog::new(10);
        let pubkey = test_pubkey();

        log.log(AuditEntry::new(AuditAction::Connect, pubkey));
        log.log(AuditEntry::new(AuditAction::GetPublicKey, pubkey));
        log.log(AuditEntry::new(AuditAction::SignEvent, pubkey));

        let recent: Vec<_> = log.recent(2).collect();
        assert_eq!(recent.len(), 2);
        assert!(matches!(recent[0].action, AuditAction::SignEvent));
        assert!(matches!(recent[1].action, AuditAction::GetPublicKey));
    }

    #[test]
    fn test_audit_log_by_app() {
        let mut log = AuditLog::new(10);
        let pubkey1 = test_pubkey();
        let pubkey2 = test_pubkey();

        log.log(AuditEntry::new(AuditAction::Connect, pubkey1));
        log.log(AuditEntry::new(AuditAction::Connect, pubkey2));
        log.log(AuditEntry::new(AuditAction::SignEvent, pubkey1));

        let pubkey1_hex = pubkey1.to_hex();
        let entries: Vec<_> = log.by_app(&pubkey1_hex).collect();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_audit_action_display() {
        assert_eq!(format!("{}", AuditAction::Connect), "connect");
        assert_eq!(format!("{}", AuditAction::SignEvent), "sign_event");
        assert_eq!(
            format!("{}", AuditAction::PermissionDenied),
            "permission_denied"
        );
    }
}
