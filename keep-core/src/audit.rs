// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

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
use crate::error::{KeepError, Result, StorageError};

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

fn hash_migration(data: &mut Vec<u8>, migration: Option<AuditMigration>) {
    match migration {
        Some(m) => {
            data.push(1);
            data.extend_from_slice(&m.old_head);
            data.extend_from_slice(&m.old_count.to_le_bytes());
            data.push(u8::from(m.old_chain_valid));
            data.extend_from_slice(&m.seq.to_le_bytes());
        }
        None => data.push(0),
    }
}

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
    /// Rate limiter tripped on a failed unlock attempt. Recorded at unlock
    /// time on the NEXT successful unlock, since the data key needed to
    /// encrypt audit entries is not available while the vault is locked.
    RateLimitTripped = 20,
    /// Vault password rotated successfully.
    PasswordRotate = 21,
    /// Vault password rotation attempted but rejected (wrong old password,
    /// invalid new password, or mid-rotation failure). Recorded only when
    /// the vault was unlocked at attempt time; failed attempts on a locked
    /// vault cannot be persisted because the audit log needs the data key.
    PasswordRotateFailed = 22,
    /// Data encryption key rotated successfully.
    DataKeyRotate = 23,
    /// Data-key rotation attempted but rejected (wrong password or mid-
    /// rotation failure). Same locked-vault caveat as `PasswordRotateFailed`.
    DataKeyRotateFailed = 24,
    /// Arbitrary secret (password, API token, note) created or overwritten.
    SecretCreate = 25,
    /// Arbitrary secret deleted.
    SecretDelete = 26,
    /// Threshold-sealed secret value revealed via an OPRF quorum unseal. The most
    /// sensitive read in the store (it hands out the plaintext), audited like
    /// `KeyExport`.
    SecretReveal = 27,
    /// Agent gateway credential issued.
    AgentCredentialIssue = 28,
    /// Agent gateway credential revoked.
    AgentCredentialRevoke = 29,
    /// Agent gateway credential deleted.
    AgentCredentialDelete = 30,
    /// One agent credential, or every one, frozen.
    AgentFreeze = 31,
    /// One agent credential, or every one, unfrozen.
    AgentUnfreeze = 32,
    /// An agent gateway request refused, or held for an approval.
    AgentRefused = 33,
    /// An agent gateway request served something other than a signature (a
    /// public key, an address, its own grant), recorded before it is returned.
    AgentServed = 34,
    /// The log was moved to sequence numbers. Carries the old log's head,
    /// entry count and whether its chain checked out, in [`AuditEntry::migration`].
    AuditLogMigrated = 35,
    /// Retention removed old entries. Carries where the kept chain now
    /// starts, in [`AuditEntry::retention`].
    AuditRetention = 36,
    /// An agent request was sent to the approvers: its credential, op,
    /// reason and request hash.
    AgentApprovalRequested = 37,
    /// A request sent to the approvers ended: approved, denied, expired or
    /// canceled, with the deciding device's keys and the decision's
    /// signature when a device decided.
    AgentApprovalDecided = 38,
    /// A freeze or unfreeze from an approver device, with the device's
    /// transport key, the key that signed, the counter, the epoch and the
    /// signature.
    AgentApproverFreeze = 39,
    /// An approver device was registered: its label and both of its keys.
    AgentApproverAdded = 40,
    /// An approver device was removed: its label and both of its keys.
    AgentApproverRemoved = 41,
    /// The owner acknowledged the audit warnings the vault reported (a log
    /// set aside, a log found not continuing the record, the record lost),
    /// naming each.
    AuditAcknowledged = 42,
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
            Self::RateLimitTripped => write!(f, "rate_limit_tripped"),
            Self::PasswordRotate => write!(f, "password_rotate"),
            Self::PasswordRotateFailed => write!(f, "password_rotate_failed"),
            Self::DataKeyRotate => write!(f, "data_key_rotate"),
            Self::DataKeyRotateFailed => write!(f, "data_key_rotate_failed"),
            Self::SecretCreate => write!(f, "secret_create"),
            Self::SecretDelete => write!(f, "secret_delete"),
            Self::SecretReveal => write!(f, "secret_reveal"),
            Self::AgentCredentialIssue => write!(f, "agent_credential_issue"),
            Self::AgentCredentialRevoke => write!(f, "agent_credential_revoke"),
            Self::AgentCredentialDelete => write!(f, "agent_credential_delete"),
            Self::AgentFreeze => write!(f, "agent_freeze"),
            Self::AgentUnfreeze => write!(f, "agent_unfreeze"),
            Self::AgentRefused => write!(f, "agent_refused"),
            Self::AgentServed => write!(f, "agent_served"),
            Self::AuditLogMigrated => write!(f, "audit_log_migrated"),
            Self::AuditRetention => write!(f, "audit_retention"),
            Self::AgentApprovalRequested => write!(f, "agent_approval_requested"),
            Self::AgentApprovalDecided => write!(f, "agent_approval_decided"),
            Self::AgentApproverFreeze => write!(f, "agent_approver_freeze"),
            Self::AgentApproverAdded => write!(f, "agent_approver_added"),
            Self::AgentApproverRemoved => write!(f, "agent_approver_removed"),
            Self::AuditAcknowledged => write!(f, "audit_acknowledged"),
        }
    }
}

/// The entry format written now. Format 1 entries came before sequence
/// numbers; a log of them is migrated when it is opened.
pub const AUDIT_FORMAT: u8 = 2;

fn format_1() -> u8 {
    1
}

/// What [`AuditEventType::AuditLogMigrated`] records about the log it
/// replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditMigration {
    /// The hash of the old log's last readable entry; zero when it had none.
    pub old_head: [u8; 32],
    /// How many entries of the old log could be read.
    pub old_count: u64,
    /// Whether the old log read to its end and its chain checked out.
    pub old_chain_valid: bool,
    /// The migration entry's own sequence number. The entries before it in
    /// the same log came from the old log.
    pub seq: u64,
}

/// What [`AuditEventType::AuditRetention`] records: where the kept chain
/// starts, so a log cut at the front by anything else does not verify, and
/// the latest migration the log recorded before it, so removing the
/// migration entry never removes what it said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionMark {
    /// The sequence number of the first kept entry.
    pub first_seq: u64,
    /// The hash the first kept entry links to.
    pub first_link: [u8; 32],
    /// How many entries were removed.
    pub removed: u64,
    /// The migration recorded before this entry that counts (see
    /// [`AuditVerification::migration`]), carried forward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration: Option<AuditMigration>,
}

/// A single audit log entry with hash chain linkage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// The entry's format: 1 before sequence numbers, [`AUDIT_FORMAT`] since.
    #[serde(default = "format_1")]
    pub format: u8,
    /// One more than the entry before, counted from the first entry the log
    /// ever had, so it never goes down, not even when retention removes
    /// entries. Zero in format 1 entries.
    #[serde(default)]
    pub seq: u64,
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
    /// Set only on [`AuditEventType::AuditLogMigrated`], by the log itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration: Option<AuditMigration>,
    /// Set only on [`AuditEventType::AuditRetention`], by the log itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<RetentionMark>,
    /// Previous entry hash.
    pub prev_hash: [u8; 32],
    /// This entry's hash.
    pub hash: [u8; 32],
}

impl AuditEntry {
    /// Create a new entry with the given event type and previous hash.
    pub fn new(event_type: AuditEventType, prev_hash: [u8; 32]) -> Self {
        Self {
            format: AUDIT_FORMAT,
            seq: 0,
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
            migration: None,
            retention: None,
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

    /// The entry's hash. Format 1 hashes what it always did; every later
    /// format also covers the format, the sequence number and the chain
    /// records, behind a tag no format 1 preimage starts with.
    fn compute_hash(&self) -> [u8; 32] {
        let mut data = Vec::new();
        if self.format != 1 {
            data.extend_from_slice(AUDIT_HASH_TAG);
            data.push(self.format);
            data.extend_from_slice(&self.seq.to_le_bytes());
            hash_migration(&mut data, self.migration);
            match self.retention {
                Some(r) => {
                    data.push(1);
                    data.extend_from_slice(&r.first_seq.to_le_bytes());
                    data.extend_from_slice(&r.first_link);
                    data.extend_from_slice(&r.removed.to_le_bytes());
                    hash_migration(&mut data, r.migration);
                }
                None => data.push(0),
            }
        }
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&(self.event_type as u8).to_le_bytes());
        hash_optional_str(&mut data, self.pubkey.as_deref());
        hash_optional_str(&mut data, self.key_type.as_deref());
        hash_optional_str(&mut data, self.message_hash.as_deref());
        hash_optional_str(&mut data, self.group_pubkey.as_deref());
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
        hash_optional_str(&mut data, self.reason.as_deref());
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

/// The most entries the audit log is read back with; a longer log is refused.
pub const MAX_AUDIT_ENTRIES: usize = 100_000;

/// Starts the hashed data of every entry after format 1, so the two
/// formats hash different data. Verification also checks each entry's
/// format, so neither can stand in for the other.
const AUDIT_HASH_TAG: &[u8] = b"keep/audit/v2";

/// Encrypted audit log with hash chain integrity.
///
/// Every entry carries a sequence number inside its hash, one more than the
/// entry before, counted from the first entry the log ever had. Rewrites
/// (retention and a data key change) keep every remaining entry's hash and
/// sequence number; retention appends an [`AuditEventType::AuditRetention`]
/// entry naming where the kept chain starts. So the last entry's sequence
/// number and hash never go back while the log is intact, which is what an
/// outside observer anchors.
///
/// A log written before sequence numbers (format 1) is migrated the first
/// time it is opened; see [`AuditLog::open`].
pub struct AuditLog {
    path: PathBuf,
    last_hash: [u8; 32],
    /// The last entry's sequence number; zero for an empty log.
    seq: u64,
    /// The latest time keep set on an entry it wrote this session or found
    /// last in the log (a trip's time is not one), in Unix seconds.
    own_time: i64,
    entries: usize,
    /// Where to cut a partial line a failed write left, before the next append.
    torn: Option<u64>,
    /// The file as this log last left it. Anything else before a write
    /// means the file was changed, replaced or removed while the log was
    /// open.
    on_disk: OnDisk,
    read_cap: usize,
    retention: RetentionPolicy,
    /// A migration found the old log failed its chain check, and the old
    /// log is still kept beside this one.
    failed_migration_kept: bool,
    /// The migration this open ran, if any.
    migrated: Option<OpenedMigration>,
}

/// A migration [`AuditLog::open`] ran: a format 1 log moved to sequence
/// numbers, or a log holding lines this keep cannot read set aside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedMigration {
    /// Every line was read and the old chain checked out.
    pub chain_valid: bool,
    /// The name the old log was kept under beside the log.
    pub kept: String,
    /// Not one line of the old log decrypted under the data key.
    pub unreadable: bool,
    /// The old log was one written before sequence numbers.
    pub from_format1: bool,
    /// The time of the old log's last readable entry, in Unix seconds;
    /// zero when it had none.
    pub old_last_timestamp: i64,
}

/// What [`AuditLog::verify`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditVerification {
    /// Every entry is in the current format, carries the next sequence
    /// number, links to the entry before and hashes to its stored hash, and
    /// the first entry is the log's first or where the latest retention
    /// entry says the kept chain starts.
    pub valid: bool,
    /// The migration the log records, in its own entry or carried forward by
    /// a retention entry after that one was removed: the latest that failed
    /// its check if any did, otherwise the latest.
    pub migration: Option<AuditMigration>,
    /// The first entry's sequence number; zero for an empty log.
    pub first_seq: u64,
}

impl AuditVerification {
    /// Whether the log still holds entries from before a migration whose old
    /// chain failed its check, which therefore cannot be trusted.
    pub fn holds_untrusted_entries(&self) -> bool {
        self.migration
            .is_some_and(|m| !m.old_chain_valid && self.first_seq < m.seq)
    }
}

/// The name of the old log a migration keeps.
const MIGRATED_LOG: &str = "audit.log.v1";

/// Present beside the log when a migration found the old chain failed its
/// check: the cheap signal for the warning on open, so opening never reads
/// the whole log. [`AuditLog::verify`] reads the record from the chain itself.
const FAILED_MIGRATION_MARKER: &str = "audit.log.v1.failed";

/// The name an unreadable signing audit log is kept under.
const UNREADABLE_SIGNING_LOG: &str = "signing_audit.log.unreadable";

impl AuditLog {
    /// Open or create an audit log at the given path.
    ///
    /// A log written before sequence numbers is migrated here, once: its
    /// chain is checked with the old rules, it is written again with
    /// sequence numbers and new hashes, an
    /// [`AuditEventType::AuditLogMigrated`] entry records the old head, the
    /// old entry count and whether the old chain checked out, and the old
    /// file is kept as `audit.log.v1`. A fault in the old log never stops the
    /// vault from opening: the migration records it, and while the old file
    /// is kept, every open logs it as an error and
    /// [`AuditLog::failed_migration_kept`] reports it.
    pub fn open(path: &Path, data_key: &SecretKey) -> Result<Self> {
        let mut log = Self {
            path: path.join("audit.log"),
            last_hash: [0u8; 32],
            seq: 0,
            own_time: 0,
            entries: 0,
            torn: None,
            on_disk: OnDisk::default(),
            read_cap: MAX_AUDIT_ENTRIES,
            retention: RetentionPolicy::default(),
            failed_migration_kept: false,
            migrated: None,
        };
        log.recover_interrupted_rewrite(data_key)?;
        if present(&log.path) {
            let tail = scan_tail(&log.path)?;
            let last = tail
                .last
                .as_ref()
                .map(|line| Self::decrypt_bytes(line_text(line), data_key));
            // A final line without its newline is an append a crash cut
            // short. It is dropped only after a line that reads, so a log
            // that is set aside is kept byte for byte, torn end and all.
            let drop_torn = || match tail.complete {
                Some(complete) => truncate(&log.path, complete),
                None => Ok(()),
            };
            match last {
                None => {
                    drop_torn()?;
                    log.on_disk = tail.on_disk();
                }
                // A newer keep's entry is a line this keep cannot read: the
                // log is set aside as a damaged one is, never refused.
                Some(Ok(last)) if last.format != 1 && last.format <= AUDIT_FORMAT => {
                    drop_torn()?;
                    log.last_hash = last.hash;
                    log.seq = last.seq;
                    log.note_time(&last);
                    log.entries = tail.count;
                    log.on_disk = tail.on_disk();
                }
                Some(Ok(last)) if last.format == 1 => {
                    drop_torn()?;
                    log.migrate(data_key)?;
                }
                // The last entry cannot be read, or does not parse. The log
                // is migrated with the fault recorded and the old file kept
                // beside it byte for byte, whatever its format, so a damaged
                // log, or one holding an entry a newer keep wrote or a line
                // copied in from another file, never locks the vault.
                Some(_) => log.migrate(data_key)?,
            }
        }
        let kept = log.failed_migration_kept_path();
        log.failed_migration_kept = kept.is_some();
        if let Some(kept) = kept {
            tracing::error!(
                kept = %kept.display(),
                "the audit log was moved to sequence numbers or set aside, and the old log FAILED its chain check or could not be read: entries from before that cannot be trusted; keep the old log file named here for investigation and run `keep audit verify`"
            );
        }
        Ok(log)
    }

    /// The number of entries in the log.
    pub fn entry_count(&self) -> usize {
        self.entries
    }

    /// The latest time keep set on an entry this log wrote or found last.
    pub fn own_time(&self) -> i64 {
        self.own_time
    }

    fn note_time(&mut self, entry: &AuditEntry) {
        if entry.event_type != AuditEventType::RateLimitTripped {
            self.own_time = self.own_time.max(entry.timestamp);
        }
    }

    /// The time of the last entry whose time keep set itself (any but a
    /// rate-limit trip, whose time comes from a forgeable file), in Unix
    /// seconds; zero when there is none. Reads the whole log, so it is for
    /// the rare unlock that finds the record missing.
    pub fn last_own_timestamp(&self, data_key: &SecretKey) -> Result<i64> {
        if self.seq == 0 {
            return Ok(0);
        }
        let file = match open_regular(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let batch = crypto::BatchDecryptor::new(data_key)?;
        let mut reader = BufReader::new(file);
        let (mut line, mut latest) = (Vec::new(), 0);
        while reader.read_until(b'\n', &mut line)? > 0 {
            if let Ok(entry) = Self::decrypt_batch(line_text(&line), &batch) {
                if entry.event_type != AuditEventType::RateLimitTripped {
                    latest = entry.timestamp;
                }
            }
            line.clear();
        }
        Ok(latest)
    }

    /// The last entry's sequence number, which counts every entry the log
    /// ever had; zero for an empty log.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Whether a migration found the old log failed its chain check while
    /// the old log is still kept beside this one. Callers should warn: the
    /// entries from before the migration cannot be trusted.
    pub fn failed_migration_kept(&self) -> bool {
        self.failed_migration_kept
    }

    /// The name of the kept old log the marker beside the log names, while
    /// both exist: what an earlier migration that failed its check left.
    pub fn failed_migration_marked(&self) -> Option<String> {
        self.failed_migration_kept_path()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
    }

    /// The migration this open ran, if any.
    pub fn migrated_on_open(&self) -> Option<&OpenedMigration> {
        self.migrated.as_ref()
    }

    /// Remove the marker a migration that failed its check left beside the
    /// log, once the owner acknowledged the failure.
    pub fn clear_failed_migration_marker(&mut self) -> Result<()> {
        match std::fs::remove_file(self.marker_path()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        sync_parent(&self.marker_path());
        self.failed_migration_kept = false;
        Ok(())
    }

    /// The hash of the entry with sequence number `seq`, if the log still
    /// holds it: `None` when it is past the log's end, before the first
    /// entry retention kept, or the line there cannot be read or carries
    /// another sequence number. Reads only the first line and that one.
    pub fn entry_hash_at(&self, seq: u64, data_key: &SecretKey) -> Option<[u8; 32]> {
        if seq == 0 || seq > self.seq {
            return None;
        }
        let mut reader = BufReader::new(open_regular(&self.path).ok()?);
        let mut line = Vec::new();
        let mut next = |reader: &mut BufReader<File>| -> Option<Vec<u8>> {
            loop {
                line.clear();
                if reader.read_until(b'\n', &mut line).ok()? == 0 {
                    return None;
                }
                let text = line_text(&line);
                if !text.is_empty() {
                    return Some(text.to_vec());
                }
            }
        };
        let first = Self::decrypt_bytes(&next(&mut reader)?, data_key).ok()?;
        let mut skip = seq.checked_sub(first.seq)?;
        let mut entry = first;
        while skip > 0 {
            let text = next(&mut reader)?;
            skip -= 1;
            if skip == 0 {
                entry = Self::decrypt_bytes(&text, data_key).ok()?;
            }
        }
        (entry.seq == seq).then_some(entry.hash)
    }

    /// Whether any readable entry of `event_type` carries `note` in its
    /// reason. Lines that cannot be read are passed over.
    pub fn any_entry_noting(
        &self,
        event_types: &[AuditEventType],
        note: &str,
        data_key: &SecretKey,
    ) -> bool {
        let Ok(file) = open_regular(&self.path) else {
            return false;
        };
        let Ok(batch) = crypto::BatchDecryptor::new(data_key) else {
            return false;
        };
        let mut reader = BufReader::new(file);
        let mut line = Vec::new();
        while reader.read_until(b'\n', &mut line).is_ok_and(|n| n > 0) {
            let noted = Self::decrypt_batch(line_text(&line), &batch).is_ok_and(|e| {
                event_types.contains(&e.event_type)
                    && e.reason.as_deref().is_some_and(|r| r.contains(note))
            });
            if noted {
                return true;
            }
            line.clear();
        }
        false
    }

    /// Whether a file named `name` (one a migration kept) is still beside
    /// the log.
    pub fn kept_log_present(&self, name: &str) -> bool {
        self.migrated_paths()
            .iter()
            .any(|p| p.file_name().is_some_and(|n| n == name))
    }

    /// Lower how many entries reads and checks go to, for tests of long
    /// logs.
    #[cfg(test)]
    pub(crate) fn set_read_cap_for_tests(&mut self, cap: usize) {
        self.read_cap = cap;
    }

    /// Set the retention policy.
    pub fn set_retention(&mut self, policy: RetentionPolicy) {
        self.retention = policy;
    }

    /// Log an audit entry. The log sets its format, sequence number and
    /// chain link, and drops the records only the log itself writes; the
    /// event types only the log writes are refused.
    pub fn log(&mut self, mut entry: AuditEntry, data_key: &SecretKey) -> Result<()> {
        if matches!(
            entry.event_type,
            AuditEventType::AuditLogMigrated | AuditEventType::AuditRetention
        ) {
            return Err(KeepError::InvalidInput(format!(
                "{} entries are written only by the audit log itself",
                entry.event_type
            )));
        }
        entry.migration = None;
        entry.retention = None;
        self.append(entry, data_key)
    }

    fn append(&mut self, mut entry: AuditEntry, data_key: &SecretKey) -> Result<()> {
        entry.format = AUDIT_FORMAT;
        entry.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| StorageError::invalid_format("audit log sequence overflow"))?;
        entry.prev_hash = self.last_hash;
        entry.hash = entry.compute_hash();

        let line = Self::encrypt_line(&entry, data_key)?;

        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        opts.mode(0o600);
        if let Some(len) = self.torn {
            truncate(&self.path, len)?;
            self.torn = None;
        }
        // Appending to a file someone else cut, replaced or removed would
        // carry this log's place onto it, hiding what was there.
        self.check_on_disk()?;
        let mut file = open_regular_with(&mut opts, &self.path)?;
        let len = file.metadata()?.len();
        // A partial line left by a failed write would make the log unreadable.
        if let Err(e) = write_line(&mut file, line.as_bytes()).and_then(|()| file.sync_all()) {
            self.torn = truncate(&self.path, len).err().map(|_| len);
            return Err(e.into());
        }

        self.last_hash = entry.hash;
        self.seq = entry.seq;
        self.note_time(&entry);
        self.entries += 1;
        let end = len + line.len() as u64;
        self.on_disk = OnDisk {
            len: end,
            last: Some((end, line.into_bytes())),
        };
        Ok(())
    }

    /// Refuse unless `entries`, read from the file, end where this log last
    /// left it. Behind [`AuditLog::check_on_disk`] this holds already; it is
    /// checked again on what was actually read before it is rewritten.
    fn check_tail(&self, entries: &[AuditEntry]) -> Result<()> {
        let tail = entries.last().map_or((0, [0u8; 32]), |e| (e.seq, e.hash));
        if tail == (self.seq, self.last_hash) {
            return Ok(());
        }
        Err(StorageError::corrupted(format!(
            "the audit log on disk ends at entry {}, not at entry {} where this vault left it",
            tail.0, self.seq
        ))
        .into())
    }

    /// Refuse unless the file is as this log last left it: the same length,
    /// and this log's last line still where it wrote it. Padding a cut file
    /// back to its length with blank lines does not pass.
    fn check_on_disk(&self) -> Result<()> {
        let now = file_len(&self.path)?;
        let at_end = match &self.on_disk.last {
            None => true,
            Some((end, line)) => {
                let mut found = vec![0u8; line.len()];
                open_regular(&self.path)
                    .and_then(|mut f| {
                        std::io::Seek::seek(
                            &mut f,
                            std::io::SeekFrom::Start(end.saturating_sub(line.len() as u64)),
                        )?;
                        std::io::Read::read_exact(&mut f, &mut found)
                    })
                    .is_ok_and(|()| found == *line)
            }
        };
        if now == self.on_disk.len && at_end {
            return Ok(());
        }
        Err(StorageError::corrupted(format!(
            "the audit log changed on disk while the vault was open ({now} bytes where this vault \
             left {}); nothing more is written to it until the vault is unlocked again",
            self.on_disk.len
        ))
        .into())
    }

    /// Check the whole chain without holding the log, as
    /// [`AuditLog::verify`] does, counting a line that cannot be read as a
    /// break rather than failing. A log longer than [`MAX_AUDIT_ENTRIES`]
    /// entries is checked from its start that far, since the chain's first
    /// entry is where its rules start, and reported too long rather than
    /// broken.
    pub fn check_chain(&self, data_key: &SecretKey) -> Result<ChainCheck> {
        let mut chain = ChainVerifier::default();
        let file = match open_regular(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(chain.finish()),
            Err(e) => return Err(e.into()),
        };
        let batch = crypto::BatchDecryptor::new(data_key)?;
        let mut reader = BufReader::new(file);
        let (mut line, mut number, mut entries) = (Vec::new(), 0u64, 0usize);
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            number += 1;
            let text = line_text(&line);
            if text.is_empty() {
                continue;
            }
            entries += 1;
            if entries > self.read_cap {
                chain.too_long = true;
                break;
            }
            match Self::decrypt_batch(text, &batch) {
                Ok(entry) => chain.push(&entry),
                Err(_) => chain.unreadable(number),
            }
        }
        Ok(chain.finish())
    }

    /// Read all entries.
    pub fn read_all(&self, data_key: &SecretKey) -> Result<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        Self::read_entries(&self.path, data_key, self.read_cap)
    }

    /// Verify the hash chain integrity. False while the log still holds
    /// entries from before a migration whose old chain failed its check.
    pub fn verify_chain(&self, data_key: &SecretKey) -> Result<bool> {
        let report = self.verify(data_key)?;
        Ok(report.valid && !report.holds_untrusted_entries())
    }

    /// Verify the hash chain, and report the migration the log records.
    pub fn verify(&self, data_key: &SecretKey) -> Result<AuditVerification> {
        Ok(verify_entries(&self.read_all(data_key)?))
    }

    /// Apply the retention policy, returning the number of entries removed.
    /// It reads past the cap on reads, so a log too long to list can be pruned.
    ///
    /// Only the oldest entries are removed, so the kept ones still form one
    /// chain, and an [`AuditEventType::AuditRetention`] entry naming where
    /// that chain now starts, and carrying the latest migration record, is
    /// appended in the same rewrite. An entry too old to keep that follows a
    /// newer one is kept until everything before it is removed. The
    /// retention entry counts toward `max_entries`. A log whose chain fails
    /// its check is never pruned, so pruning cannot hide a cut or splice.
    pub fn apply_retention(&mut self, data_key: &SecretKey) -> Result<usize> {
        self.apply_retention_noting(data_key, None, |_, _| Ok(()))
    }

    /// [`AuditLog::apply_retention`], with `note` added to the retention
    /// entry's reason, and `before_rewrite` given the sequence number and
    /// hash the log will end at, before the log is replaced; the log is not
    /// pruned if it fails. Only the log this process left is pruned: one
    /// changed on disk is refused.
    pub fn apply_retention_noting(
        &mut self,
        data_key: &SecretKey,
        note: Option<&str>,
        before_rewrite: impl FnOnce(u64, [u8; 32]) -> Result<()>,
    ) -> Result<usize> {
        if !self.path.exists() && self.seq == 0 {
            return Ok(0);
        }
        self.check_on_disk()?;
        let mut entries = Self::read_entries(&self.path, data_key, usize::MAX)?;
        self.check_tail(&entries)?;
        let Some(last) = entries.last() else {
            return Ok(0);
        };
        if !verify_entries(&entries).valid {
            return Err(StorageError::corrupted(
                "the audit log fails its chain check, so it is not pruned; run `keep audit verify`",
            )
            .into());
        }
        let (last_seq, last_hash) = (last.seq, last.hash);
        let now = chrono::Utc::now().timestamp();
        let max_age_secs = self.retention.max_age_days.map(|d| i64::from(d) * 86400);

        let mut cut = entries
            .iter()
            .take_while(|e| max_age_secs.is_some_and(|max| now.saturating_sub(e.timestamp) > max))
            .count();
        if let Some(max) = self.retention.max_entries {
            if entries.len() > max {
                cut = cut.max(entries.len() - max.saturating_sub(1));
            }
        }
        if cut == 0 {
            return Ok(0);
        }

        let migration = latest_migration(&entries);
        let mut kept = entries.split_off(cut);
        let (first_seq, first_link) = match kept.first() {
            Some(first) => (first.seq, first.prev_hash),
            None => (last_seq.saturating_add(1), last_hash),
        };
        let reason = match note {
            Some(note) => format!("retention removed {cut} entries; {note}"),
            None => format!("retention removed {cut} entries"),
        };
        let mut mark =
            AuditEntry::new(AuditEventType::AuditRetention, last_hash).with_reason(&reason);
        mark.seq = last_seq
            .checked_add(1)
            .ok_or_else(|| StorageError::invalid_format("audit log sequence overflow"))?;
        mark.retention = Some(RetentionMark {
            first_seq,
            first_link,
            removed: cut as u64,
            migration,
        });
        mark.hash = mark.compute_hash();
        before_rewrite(mark.seq, mark.hash)?;
        kept.push(mark);

        self.rewrite(&kept, data_key)?;
        Ok(cut)
    }

    /// Export the log as JSON.
    pub fn export(&self, data_key: &SecretKey) -> Result<String> {
        let entries = self.read_all(data_key)?;
        serde_json::to_string_pretty(&entries)
            .map_err(|e| StorageError::serialization(format!("export audit log: {e}")).into())
    }

    /// Finish a rewrite a crash interrupted in an older release, which
    /// replaced the log in two renames: the log moved to `audit.log.bak`,
    /// then the new one from `audit.log.tmp`. With no log left, the new one
    /// is taken when its last entry reads under the current key (it was
    /// complete before the first rename), and the backup otherwise. Nothing
    /// is done without the backup, the signature of that crash.
    fn recover_interrupted_rewrite(&self, data_key: &SecretKey) -> Result<()> {
        if self.path.exists() {
            return Ok(());
        }
        let temp = self.path.with_extension("log.tmp");
        let backup = self.path.with_extension("log.bak");
        if !is_regular_file(&backup) {
            return Ok(());
        }
        let from = if is_regular_file(&temp)
            && scan_tail(&temp).is_ok_and(|tail| {
                tail.last
                    .is_some_and(|line| Self::decrypt_bytes(line_text(&line), data_key).is_ok())
            }) {
            temp
        } else {
            backup
        };
        std::fs::rename(&from, &self.path)?;
        sync_parent(&self.path);
        Ok(())
    }

    fn read_entries(path: &Path, data_key: &SecretKey, cap: usize) -> Result<Vec<AuditEntry>> {
        let file = open_regular(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        let batch = crypto::BatchDecryptor::new(data_key)?;

        for (line_num, line) in reader.lines().enumerate() {
            if entries.len() >= cap {
                return Err(StorageError::io(format!(
                    "audit log exceeds maximum of {cap} entries"
                ))
                .into());
            }
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let entry = Self::decrypt_batch(line.as_bytes(), &batch).map_err(|e| {
                StorageError::corrupted(format!("audit log at line {}: {}", line_num + 1, e))
            })?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Every entry that can be read, how many were read before the first
    /// line that cannot be, if there is one, and how many lines decrypted.
    /// A line that does not decrypt, that decrypts but does not parse (an
    /// entry type a newer keep added, or a line copied in from the signing
    /// log), or that is in a format newer than this keep's, cannot be read.
    /// Only a failure to read the file is an error.
    fn read_readable(
        path: &Path,
        data_key: &SecretKey,
    ) -> Result<(Vec<AuditEntry>, Option<usize>, usize)> {
        let mut reader = BufReader::new(open_regular(path)?);
        let (mut entries, mut before_gap, mut decrypted) = (Vec::new(), None, 0);
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                return Ok((entries, before_gap, decrypted));
            }
            let text = line_text(&line);
            if text.is_empty() {
                continue;
            }
            let plaintext = std::str::from_utf8(text)
                .ok()
                .and_then(|text| Self::decrypt_raw(text, data_key).ok());
            decrypted += usize::from(plaintext.is_some());
            match plaintext
                .and_then(|p| serde_json::from_slice::<AuditEntry>(&p).ok())
                .filter(|e| e.format <= AUDIT_FORMAT)
            {
                Some(entry) => entries.push(entry),
                None => {
                    before_gap.get_or_insert(entries.len());
                }
            }
        }
    }

    /// [`AuditLog::decrypt_bytes`] with the key taken out once for many lines.
    fn decrypt_batch(line: &[u8], batch: &crypto::BatchDecryptor) -> Result<AuditEntry> {
        let bytes = STANDARD
            .decode(line)
            .map_err(|e| StorageError::invalid_format(format!("audit line: {e}")))?;
        let plaintext = batch.decrypt(&crypto::EncryptedData::from_bytes(&bytes)?)?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| StorageError::invalid_format(format!("audit entry: {e}")).into())
    }

    fn decrypt_bytes(line: &[u8], data_key: &SecretKey) -> Result<AuditEntry> {
        let text = std::str::from_utf8(line)
            .map_err(|e| StorageError::invalid_format(format!("audit line: {e}")))?;
        Self::decrypt_line(text, data_key)
    }

    fn decrypt_line(line: &str, data_key: &SecretKey) -> Result<AuditEntry> {
        let plaintext = Self::decrypt_raw(line, data_key)?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| StorageError::invalid_format(format!("audit entry: {e}")).into())
    }

    fn decrypt_raw(line: &str, data_key: &SecretKey) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let bytes = STANDARD
            .decode(line)
            .map_err(|e| StorageError::invalid_format(format!("audit line: {e}")))?;

        let encrypted = crypto::EncryptedData::from_bytes(&bytes)?;
        crypto::decrypt(&encrypted, data_key)?.as_slice()
    }

    fn encrypt_line(entry: &AuditEntry, data_key: &SecretKey) -> Result<String> {
        let serialized = serde_json::to_vec(entry)
            .map_err(|e| StorageError::serialization(format!("audit entry: {e}")))?;
        let encrypted = crypto::encrypt(&serialized, data_key)?;
        Ok(format!("{}\n", STANDARD.encode(encrypted.to_bytes())))
    }

    /// Move a format 1 log to sequence numbers. See [`AuditLog::open`].
    ///
    /// Every readable entry of an old log is carried over; a line that cannot
    /// be read is left out. A log that already holds later-format entries
    /// keeps only those before its first unreadable line. The old chain
    /// counts as checked out only if every line could be read and each entry
    /// links to the one before and hashes to its stored hash; entries already
    /// in a later format at the start (a migrated log an older keep then
    /// appended to) must also pass [`AuditLog::verify`]'s rules. An earlier
    /// failed migration they record stays the one reported (see
    /// [`AuditVerification::migration`]). A log nothing in can be read (one
    /// left under a data key that no longer exists) is set aside the same
    /// way, with the failure recorded, rather than locking the vault.
    ///
    /// The new log is written beside the old one and renamed over it last, so
    /// a crash at any point leaves either the old log, which is migrated
    /// again on the next open, or the new one. The old file is kept under
    /// the first name no earlier migration used, and never replaces a file.
    fn migrate(&mut self, data_key: &SecretKey) -> Result<()> {
        let (mut old, gap, decrypted) = Self::read_readable(&self.path, data_key)?;
        let complete = gap.is_none();
        let from_format1 = old.iter().any(|e| e.format == 1);
        let old_last_timestamp = old
            .iter()
            .rev()
            .find(|e| e.event_type != AuditEventType::RateLimitTripped)
            .map_or(0, |e| e.timestamp);
        // A log that already holds entries in a later format and has a line
        // that cannot be read keeps only what came before the damage, so no
        // entry whose sequence number was already seen is renumbered; the
        // rest stays in the kept copy.
        if let Some(gap) = gap.filter(|_| old.iter().any(|e| e.format != 1)) {
            old.truncate(gap);
        }
        // Entries already in a later format at the start (a migrated log an
        // older keep then appended to) are kept exactly as they are, so their
        // sequence numbers and hashes never change; only what follows is
        // renumbered, continuing from them.
        let kept = old.iter().take_while(|e| e.format != 1).count();
        let mut chain_valid = complete && verify_entries(&old[..kept]).valid;
        let mut prev_hash = old[..kept].last().map_or([0u8; 32], |e| e.hash);
        for entry in &old[kept..] {
            chain_valid &= entry.format == 1;
            chain_valid &= entry.verify(&prev_hash);
            prev_hash = entry.hash;
        }
        let (old_head, old_count) = (prev_hash, old.len() as u64);

        let rest = old.split_off(kept);
        let mut entries = old;
        entries.reserve(rest.len() + 1);
        let (mut prev_hash, mut seq) = entries.last().map_or(([0u8; 32], 0), |e| (e.hash, e.seq));
        for mut entry in rest {
            seq = seq
                .checked_add(1)
                .ok_or_else(|| StorageError::invalid_format("audit log sequence overflow"))?;
            entry.format = AUDIT_FORMAT;
            entry.seq = seq;
            entry.prev_hash = prev_hash;
            entry.hash = entry.compute_hash();
            prev_hash = entry.hash;
            entries.push(entry);
        }
        let migration = AuditMigration {
            old_head,
            old_count,
            old_chain_valid: chain_valid,
            seq: seq
                .checked_add(1)
                .ok_or_else(|| StorageError::invalid_format("audit log sequence overflow"))?,
        };
        let reason = if chain_valid {
            format!(
                "moved {} entries to sequence numbers; the old chain checked out",
                migration.old_count
            )
        } else {
            format!(
                "moved {} readable entries to sequence numbers; the old chain FAILED its check, so entries before this one cannot be trusted",
                migration.old_count
            )
        };
        let mut note = AuditEntry::new(AuditEventType::AuditLogMigrated, prev_hash)
            .with_success(chain_valid)
            .with_reason(&reason);
        note.seq = migration.seq;
        note.migration = Some(migration);
        note.hash = note.compute_hash();
        entries.push(note);

        let temp_path = self.path.with_extension("log.tmp");
        self.write_entries_to_temp(&temp_path, &entries, data_key)?;
        let kept = keep_copy(
            &self.path,
            self.path.parent().unwrap_or(Path::new(".")),
            MIGRATED_LOG,
        );
        let mut kept_name = String::new();
        let marked = kept.and_then(|kept| {
            kept_name = kept
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if chain_valid {
                return Ok(());
            }
            write_marker(&self.marker_path(), kept_name.as_bytes()).map_err(Into::into)
        });
        if let Err(e) = marked {
            let _ = std::fs::remove_file(&temp_path);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&temp_path, &self.path) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(StorageError::io(format!("replace audit log: {e}")).into());
        }
        sync_parent(&self.path);
        self.set_tail(&entries);
        self.migrated = Some(OpenedMigration {
            chain_valid,
            kept: kept_name,
            unreadable: decrypted == 0 && !complete,
            from_format1,
            old_last_timestamp,
        });
        Ok(())
    }

    fn marker_path(&self) -> PathBuf {
        self.path.with_file_name(FAILED_MIGRATION_MARKER)
    }

    /// The old logs migrations kept, oldest first: `audit.log.v1`, then
    /// `audit.log.v1.2` and so on.
    fn migrated_paths(&self) -> Vec<PathBuf> {
        kept_paths(self.path.parent().unwrap_or(Path::new(".")), MIGRATED_LOG)
    }

    /// The kept old log a failed migration names in the marker, while both
    /// the marker and that file exist.
    fn failed_migration_kept_path(&self) -> Option<PathBuf> {
        let marker = self.marker_path();
        if !is_regular_file(&marker) {
            return None;
        }
        let mut name = String::new();
        std::io::Read::read_to_string(
            &mut std::io::Read::take(open_regular(&marker).ok()?, 255),
            &mut name,
        )
        .ok()?;
        let name = name.trim();
        let path = self
            .migrated_paths()
            .into_iter()
            .find(|p| p.file_name().is_some_and(|n| n == name))?;
        Some(path)
    }

    fn rewrite(&mut self, entries: &[AuditEntry], data_key: &SecretKey) -> Result<()> {
        let temp_path = self.path.with_extension("log.tmp");
        self.write_entries_to_temp(&temp_path, entries, data_key)?;
        // One rename replaces the log, so a crash leaves the old log or the
        // new one, never neither.
        if let Err(e) = std::fs::rename(&temp_path, &self.path) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(StorageError::io(format!("replace audit log: {e}")).into());
        }
        sync_parent(&self.path);
        self.set_tail(entries);
        Ok(())
    }

    fn set_tail(&mut self, entries: &[AuditEntry]) {
        let (last_hash, seq) = entries.last().map_or(([0u8; 32], 0), |e| (e.hash, e.seq));
        self.last_hash = last_hash;
        self.seq = seq;
        if let Some(last) = entries.last() {
            self.note_time(last);
        }
        self.entries = entries.len();
        self.torn = None;
        self.on_disk = OnDisk::read(&self.path).unwrap_or(OnDisk {
            len: u64::MAX,
            last: None,
        });
    }

    /// Write `entries` exactly as they are, hashes and sequence numbers
    /// included, to a new file at `temp_path`, replacing any left there.
    fn write_entries_to_temp(
        &self,
        temp_path: &Path,
        entries: &[AuditEntry],
        data_key: &SecretKey,
    ) -> Result<()> {
        let written = (|| -> Result<()> {
            let mut file = create_fresh(temp_path)?;
            for entry in entries {
                file.write_all(Self::encrypt_line(entry, data_key)?.as_bytes())?;
            }
            file.sync_all()?;
            Ok(())
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(temp_path);
        }
        written
    }

    /// Get the last entry's hash.
    pub fn last_hash(&self) -> [u8; 32] {
        self.last_hash
    }

    /// Re-encrypt the entire log with a new data key, keeping every entry's
    /// hash and sequence number. The old logs migrations kept are
    /// re-encrypted separately, by [`AuditLog::reencrypt_kept_logs`].
    pub fn reencrypt(&mut self, old_key: &SecretKey, new_key: &SecretKey) -> Result<()> {
        if !self.path.exists() && self.seq == 0 {
            return Ok(());
        }
        self.check_on_disk()?;
        // Past the read cap too, so rotating a long log cannot strand it under
        // the old key after the new one is committed.
        let entries = Self::read_entries(&self.path, old_key, usize::MAX)?;
        // Another log put in its place is not re-encrypted as this one, but
        // left to be set aside.
        self.check_tail(&entries)?;
        if entries.is_empty() {
            return Ok(());
        }
        self.rewrite(&entries, new_key)
    }

    /// Re-encrypt the old logs migrations kept with a new data key, line for
    /// line the same plaintext, without checking or re-chaining anything. A
    /// line that does not decrypt under `old_key` is kept as it is.
    /// Every kept log is tried, and the failures are reported together.
    pub fn reencrypt_kept_logs(&self, old_key: &SecretKey, new_key: &SecretKey) -> Result<()> {
        let failed: Vec<String> = self
            .migrated_paths()
            .into_iter()
            .filter_map(|path| {
                reencrypt_as_is(&path, old_key, new_key)
                    .err()
                    .map(|e| format!("{}: {e}", path.display()))
            })
            .collect();
        if failed.is_empty() {
            Ok(())
        } else {
            Err(
                StorageError::io(format!("re-encrypt kept audit logs: {}", failed.join("; ")))
                    .into(),
            )
        }
    }

    /// Log entries restored from a backup, in order, into this chain. Each
    /// keeps its event type and records, but a migration record's `seq` is
    /// moved so the restored log holds untrusted entries exactly when the
    /// backup's log did: when it did, to where the migration entry now is
    /// (or to 0 for a record carried past an entry the backup no longer
    /// held); when it did not, to 0.
    ///
    /// When the backup's entries fail their chain check (under the rules of
    /// their format), an [`AuditEventType::AuditLogMigrated`] entry recording
    /// the failure follows them, so the restored log reports them untrusted
    /// as a failed migration would.
    pub(crate) fn restore_entries(
        &mut self,
        entries: &[AuditEntry],
        data_key: &SecretKey,
    ) -> Result<()> {
        let report = verify_entries(entries);
        let untrusted = report.holds_untrusted_entries();
        let chain_valid = if entries.iter().all(|e| e.format == 1) {
            let mut prev_hash = [0u8; 32];
            entries.iter().all(|e| {
                let ok = e.verify(&prev_hash);
                prev_hash = e.hash;
                ok
            })
        } else {
            report.valid
        };
        let mut moved = std::collections::HashMap::new();
        for entry in entries {
            let mut entry = entry.clone();
            if let Some(m) = entry.migration.as_mut() {
                let new_seq = if untrusted { self.seq + 1 } else { 0 };
                moved.insert(m.seq, new_seq);
                m.seq = new_seq;
            }
            if let Some(m) = entry.retention.as_mut().and_then(|r| r.migration.as_mut()) {
                m.seq = moved.get(&m.seq).copied().unwrap_or(0);
            }
            self.append(entry, data_key)?;
        }
        if chain_valid {
            return Ok(());
        }
        let migration = AuditMigration {
            old_head: entries.last().map_or([0u8; 32], |e| e.hash),
            old_count: entries.len() as u64,
            old_chain_valid: false,
            seq: self
                .seq
                .checked_add(1)
                .ok_or_else(|| StorageError::invalid_format("audit log sequence overflow"))?,
        };
        let mut note = AuditEntry::new(AuditEventType::AuditLogMigrated, [0u8; 32])
            .with_success(false)
            .with_reason(&format!(
                "restored {} entries from a backup whose audit chain FAILED its check, so entries before this one cannot be trusted",
                entries.len()
            ));
        note.migration = Some(migration);
        self.append(note, data_key)
    }
}

/// The files [`keep_copy`] kept in `dir` under `base`, oldest first: `base`,
/// then `base.2` and so on.
fn kept_paths(dir: &Path, base: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let first = dir.join(base);
    if is_regular_file(&first) {
        paths.push(first);
    }
    let mut numbered: Vec<(u32, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let n = name.strip_prefix(base)?.strip_prefix('.')?;
            if n.is_empty()
                || !n.bytes().all(|b| b.is_ascii_digit())
                || !is_regular_file(&entry.path())
            {
                return None;
            }
            Some((n.parse().ok()?, entry.path()))
        })
        .collect();
    numbered.sort();
    paths.extend(numbered.into_iter().map(|(_, p)| p));
    paths
}

/// The migration record that counts among `entries`, in its own entry or
/// carried by a retention entry: the latest one that failed its check if any
/// did, so a later clean migration never hides an earlier failure, and the
/// latest one otherwise.
fn latest_migration(entries: &[AuditEntry]) -> Option<AuditMigration> {
    let (mut latest, mut failed) = (None, None);
    for m in entries.iter().filter_map(|e| {
        e.migration
            .or_else(|| e.retention.and_then(|r| r.migration))
    }) {
        if !m.old_chain_valid {
            failed = Some(m);
        }
        latest = Some(m);
    }
    failed.or(latest)
}

/// The verification rules of [`AuditLog::verify`], over entries already read.
fn verify_entries(entries: &[AuditEntry]) -> AuditVerification {
    let mut chain = ChainVerifier::default();
    for entry in entries {
        chain.push(entry);
    }
    AuditVerification {
        valid: chain.finish().valid,
        migration: latest_migration(entries),
        first_seq: entries.first().map_or(0, |e| e.seq),
    }
}

/// The chain rules of [`AuditLog::verify`], applied one entry at a time, so
/// a log can be checked without holding it: every entry in the current
/// format, carrying the next sequence number, linking to the entry before
/// and hashing to its stored hash, the records only their own entries carry,
/// and a first entry that is the log's first or where the latest retention
/// entry says the kept chain starts. Each entry or line that breaks a rule is
/// counted and fingerprinted, so the same breaks can be told from new ones.
#[derive(Default)]
struct ChainVerifier {
    /// The first entry's sequence number and link.
    first: Option<(u64, [u8; 32])>,
    /// The last entry's hash and the sequence number the next must carry.
    prev: Option<([u8; 32], Option<u64>)>,
    /// The latest retention record.
    mark: Option<RetentionMark>,
    /// What broke the rules, in order: each breaking entry's sequence number
    /// and hash, or the line number of a line that could not be read.
    breaks: Vec<u8>,
    failures: u64,
    first_failure: Option<u64>,
    too_long: bool,
    latest_time: i64,
}

/// What [`ChainVerifier`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainCheck {
    /// Nothing broke the rules.
    pub valid: bool,
    /// How many entries or lines broke them.
    pub failures: u64,
    /// The sequence number (or, for a line that could not be read, the line
    /// number) of the first break.
    pub first_failure: Option<u64>,
    /// A fingerprint of every break, which only the same breaks reproduce.
    pub breaks: [u8; 32],
    /// The log holds more than [`MAX_AUDIT_ENTRIES`] entries, and was
    /// checked only that far.
    pub too_long: bool,
    /// The latest time keep set on an entry it checked (a trip's time is
    /// not one), in Unix seconds; zero when there is none.
    pub latest_time: i64,
}

impl ChainVerifier {
    fn push(&mut self, entry: &AuditEntry) {
        let (prev_hash, seq) = match self.prev {
            Some(prev) => prev,
            None => {
                self.first = Some((entry.seq, entry.prev_hash));
                (entry.prev_hash, Some(entry.seq))
            }
        };
        let valid = entry.format == AUDIT_FORMAT
            && Some(entry.seq) == seq
            && entry.verify(&prev_hash)
            && (entry.migration.is_none() || entry.event_type == AuditEventType::AuditLogMigrated)
            && (entry.retention.is_none() || entry.event_type == AuditEventType::AuditRetention);
        if !valid {
            self.broke(b'e', entry.seq, &entry.hash);
        }
        if entry.retention.is_some() {
            self.mark = entry.retention;
        }
        if entry.event_type != AuditEventType::RateLimitTripped {
            self.latest_time = self.latest_time.max(entry.timestamp);
        }
        self.prev = Some((entry.hash, entry.seq.checked_add(1)));
    }

    /// A line `number` (counted from 1) that could not be read as an entry.
    fn unreadable(&mut self, number: u64) {
        self.broke(b'l', number, &[0; 32]);
    }

    fn broke(&mut self, kind: u8, at: u64, hash: &[u8; 32]) {
        self.failures += 1;
        self.first_failure.get_or_insert(at);
        self.breaks.push(kind);
        self.breaks.extend_from_slice(&at.to_le_bytes());
        self.breaks.extend_from_slice(hash);
    }

    fn finish(mut self) -> ChainCheck {
        if let Some((first_seq, first_link)) = self.first {
            let starts = if first_seq == 1 {
                first_link == [0u8; 32]
            } else {
                self.mark
                    .is_some_and(|m| m.first_seq == first_seq && m.first_link == first_link)
            };
            if !starts {
                self.broke(b's', first_seq, &first_link);
            }
        }
        ChainCheck {
            valid: self.failures == 0,
            failures: self.failures,
            first_failure: self.first_failure,
            breaks: crypto::blake2b_256(&self.breaks),
            too_long: self.too_long,
            latest_time: self.latest_time,
        }
    }
}

/// A log file as a log last left it: its length, and its last line with
/// the offset that line ends at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct OnDisk {
    len: u64,
    last: Option<(u64, Vec<u8>)>,
}

impl OnDisk {
    fn read(path: &Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        Ok(scan_tail(path)?.on_disk())
    }
}

/// What [`scan_tail`] found.
struct Tail {
    /// The last complete line that is not blank, with its newline.
    last: Option<Vec<u8>>,
    /// Where that line ends.
    last_end: u64,
    /// How many complete lines are not blank.
    count: usize,
    /// The length of the complete lines, when a final line has no newline.
    complete: Option<u64>,
    /// The length of the complete lines.
    end: u64,
}

impl Tail {
    /// The file as it is once a torn final line, if any, is dropped.
    fn on_disk(&self) -> OnDisk {
        OnDisk {
            len: self.end,
            last: self.last.clone().map(|line| (self.last_end, line)),
        }
    }
}

/// Scan `path` for its last complete line that is not blank, without
/// changing it.
fn scan_tail(path: &Path) -> std::io::Result<Tail> {
    let mut reader = BufReader::new(open_regular(path)?);
    let (mut line, mut last) = (Vec::new(), Vec::new());
    let (mut count, mut at, mut last_end) = (0, 0u64, 0u64);
    let complete = loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            break None;
        }
        if line.last() != Some(&b'\n') {
            break Some(at);
        }
        at += n as u64;
        if !line_text(&line).is_empty() {
            count += 1;
            last_end = at;
            std::mem::swap(&mut last, &mut line);
        }
    };
    Ok(Tail {
        last: (!last.is_empty()).then_some(last),
        last_end,
        count,
        complete,
        end: at,
    })
}

/// The length of the file at `path`; zero when there is none.
fn file_len(path: &Path) -> std::io::Result<u64> {
    match std::fs::metadata(path) {
        Ok(m) => Ok(m.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

/// Whether `path` is a regular file, without following a symlink.
fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

/// Whether anything is at `path`, a dangling symlink included.
fn present(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Open the audit file at `path` for reading, only if it is a regular file.
fn open_regular(path: &Path) -> std::io::Result<File> {
    open_regular_with(OpenOptions::new().read(true), path)
}

/// Open `path` with `opts` only if it is a regular file: never through a
/// symlink, and without blocking on a FIFO. A log replaced by a symlink to
/// `/dev/zero` or by a FIFO would otherwise fill memory or hang every unlock,
/// and a symlink would carry a cut or an append to the file it names.
fn open_regular_with(opts: &mut OpenOptions, path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY);
    let not_regular = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} is not a regular file (a symlink, a FIFO or a device); keep reads and writes only a regular file there, so move it out of the vault directory",
                path.display()
            ),
        )
    };
    let file = opts.open(path).map_err(|e| {
        if e.kind() != std::io::ErrorKind::NotFound
            && std::fs::symlink_metadata(path).is_ok_and(|m| !m.is_file())
        {
            not_regular()
        } else {
            e
        }
    })?;
    if !file.metadata()?.is_file() {
        return Err(not_regular());
    }
    Ok(file)
}

/// Write one log line. In tests, `PARTIAL_WRITE` stops it halfway with an
/// error, as a full disk would.
fn write_line(file: &mut File, line: &[u8]) -> std::io::Result<()> {
    #[cfg(test)]
    if test_support::PARTIAL_WRITE.with(std::cell::Cell::get) {
        file.write_all(&line[..line.len() / 2])?;
        return Err(std::io::Error::other("write cut short for the test"));
    }
    file.write_all(line)
}

/// A new file at `path` with mode 0600, after removing anything left there,
/// so a stale file's permissions are never inherited.
fn create_fresh(path: &Path) -> std::io::Result<File> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    opts.open(path)
}

/// Write the failed-migration marker, naming the kept old log, through a
/// temporary file so a crash never leaves it half written.
fn write_marker(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let temp = temp_beside(path);
    let written = (|| {
        let mut file = create_fresh(&temp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written?;
    sync_parent(path);
    Ok(())
}

/// Keep a durable copy of `from` in `dir` under the first name of `base`,
/// `base.2`, ... that does not exist, and return
/// it. The copy is made under a temporary name and hard-linked into place,
/// which never replaces a file. Where hard links are not supported (FAT,
/// some network and FUSE file systems), it is copied straight into a name
/// created new, which never replaces a file either; a failed copy is removed,
/// but a crash can leave a partial copy under that name, beside the intact log.
fn keep_copy(from: &Path, dir: &Path, base: &str) -> Result<PathBuf> {
    let name = |n: u32| {
        if n == 1 {
            dir.join(base)
        } else {
            dir.join(format!("{base}.{n}"))
        }
    };
    let temp = dir.join(format!("{base}.tmp"));
    let copied = (|| -> std::io::Result<PathBuf> {
        let mut out = create_fresh(&temp)?;
        std::io::copy(&mut open_regular(from)?, &mut out)?;
        out.sync_all()?;
        let mut n = 1u32;
        loop {
            match hard_link(&temp, &name(n)) {
                Ok(()) => return Ok(name(n)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => n += 1,
                Err(_) => break,
            }
        }
        let mut n = 1u32;
        loop {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            opts.mode(0o600);
            match opts.open(name(n)) {
                Ok(mut out) => {
                    let copied = open_regular(&temp)
                        .and_then(|mut from| std::io::copy(&mut from, &mut out))
                        .and_then(|_| out.sync_all());
                    #[cfg(test)]
                    let copied = match test_support::FAIL_COPY.with(std::cell::Cell::get) {
                        true => Err(std::io::ErrorKind::Other.into()),
                        false => copied,
                    };
                    if let Err(e) = copied {
                        let _ = std::fs::remove_file(name(n));
                        return Err(e);
                    }
                    return Ok(name(n));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => n += 1,
                Err(e) => return Err(e),
            }
        }
    })();
    let _ = std::fs::remove_file(&temp);
    let kept = copied.map_err(|e| StorageError::io(format!("keep the old audit log: {e}")))?;
    sync_parent(&kept);
    Ok(kept)
}

fn hard_link(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if test_support::NO_HARD_LINKS.with(std::cell::Cell::get) {
        return Err(std::io::ErrorKind::Unsupported.into());
    }
    std::fs::hard_link(from, to)
}

/// Re-encrypt every line of a kept old log under `new_key`, byte for byte
/// the same plaintext, without checking or re-chaining anything. A line that
/// does not decrypt under `old_key` is kept as it is.
fn reencrypt_as_is(path: &Path, old_key: &SecretKey, new_key: &SecretKey) -> Result<()> {
    let mut reader = BufReader::new(open_regular(path)?);
    let temp = temp_beside(path);
    let written = (|| -> Result<()> {
        let mut out = create_fresh(&temp)?;
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            let text = line_text(&line);
            let plaintext = std::str::from_utf8(text)
                .ok()
                .filter(|t| !t.is_empty())
                .and_then(|t| AuditLog::decrypt_raw(t, old_key).ok());
            match plaintext {
                Some(plaintext) => {
                    let encrypted = crypto::encrypt(&plaintext, new_key)?;
                    out.write_all(STANDARD.encode(encrypted.to_bytes()).as_bytes())?;
                    out.write_all(&line[text.len()..])?;
                }
                None => out.write_all(&line)?,
            }
        }
        out.sync_all()?;
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written?;
    sync_parent(path);
    Ok(())
}

fn temp_beside(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".tmp");
    PathBuf::from(name)
}

/// Make a rename in `path`'s directory durable. Best effort: not every
/// platform can sync a directory.
fn sync_parent(path: &Path) {
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        if let Ok(dir) = File::open(dir) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Cut `path` back to `len` bytes, durably; never grows it. A separate write
/// handle, since an append-only handle cannot truncate on every platform.
fn truncate(path: &Path, len: u64) -> std::io::Result<()> {
    #[cfg(test)]
    if test_support::FAIL_TRUNCATE.with(std::cell::Cell::get) {
        return Err(std::io::Error::other("truncate refused for the test"));
    }
    let file = open_regular_with(OpenOptions::new().write(true), path)?;
    if file.metadata()?.len() > len {
        file.set_len(len)?;
        file.sync_all()?;
    }
    Ok(())
}

/// A line without its `\n` or `\r\n` ending, as `BufRead::lines` yields it.
fn line_text(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
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
    /// Kill switch toggled.
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
        hash_optional_str(&mut data, self.caller_name.as_deref());
        if let Some(kind) = self.event_kind {
            data.push(1);
            data.extend_from_slice(&kind.to_le_bytes());
        } else {
            data.push(0);
        }
        hash_optional_str(&mut data, self.reason.as_deref());
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

/// Encrypted signing audit log with hash chain integrity.
pub struct SigningAuditLog {
    path: PathBuf,
    last_hash: [u8; 32],
    retention: RetentionPolicy,
    /// The name this open kept an unreadable log under, if it did.
    set_aside: Option<String>,
    /// The length to cut the log back to before the next append, when a
    /// failed append left part of a line that could not be cut off then.
    torn: Option<u64>,
}

impl SigningAuditLog {
    /// Open or create a signing audit log at the given path, decrypting only
    /// its last line. A final line cut short by a crash is dropped. A log
    /// whose last line cannot be read under `data_key` (one left under a
    /// data key that no longer exists, an entry a newer keep wrote, or a line
    /// copied in from the audit log) is kept beside it byte for byte as
    /// `signing_audit.log.unreadable` and a new one started, with an error
    /// logged, rather than locking the vault.
    pub fn open(path: &Path, data_key: &SecretKey) -> Result<Self> {
        let audit_path = path.join("signing_audit.log");
        let mut set_aside = None;
        let last_hash = if present(&audit_path) {
            let tail = scan_tail(&audit_path)?;
            let last = tail.last.as_ref().map_or(Ok([0u8; 32]), |line| {
                std::str::from_utf8(line_text(line))
                    .map_err(|e| {
                        StorageError::invalid_format(format!("signing audit line: {e}")).into()
                    })
                    .and_then(|text| Self::decrypt_line(text, data_key))
                    .map(|entry| entry.hash)
            });
            // A torn final line is dropped only after a line that reads, so
            // a log that is set aside is kept byte for byte.
            if last.is_ok() {
                if let Some(complete) = tail.complete {
                    truncate(&audit_path, complete)?;
                }
            }
            match last {
                Ok(hash) => hash,
                Err(e) => {
                    let kept = keep_copy(&audit_path, path, UNREADABLE_SIGNING_LOG)?;
                    std::fs::remove_file(&audit_path)?;
                    sync_parent(&audit_path);
                    tracing::error!(
                        error = %e,
                        kept = %kept.display(),
                        "the signing audit log's last line cannot be read under the vault's key; it was kept under the name here and a new one started"
                    );
                    set_aside = kept.file_name().map(|n| n.to_string_lossy().into_owned());
                    [0u8; 32]
                }
            }
        } else {
            [0u8; 32]
        };

        Ok(Self {
            path: audit_path,
            last_hash,
            retention: RetentionPolicy::default(),
            set_aside,
            torn: None,
        })
    }

    /// The name this open kept an unreadable log under, if it did.
    pub fn set_aside_on_open(&self) -> Option<&str> {
        self.set_aside.as_deref()
    }

    /// Whether a file named `name` (one [`SigningAuditLog::open`] kept) is
    /// still beside the log.
    pub fn kept_log_present(&self, name: &str) -> bool {
        kept_paths(
            self.path.parent().unwrap_or(Path::new(".")),
            UNREADABLE_SIGNING_LOG,
        )
        .iter()
        .any(|p| p.file_name().is_some_and(|n| n == name))
    }

    /// Set the retention policy.
    pub fn set_retention(&mut self, policy: RetentionPolicy) {
        self.retention = policy;
    }

    /// Cut off the partial line a failed append left, if one is pending, so
    /// the log reads back whole.
    fn cut_torn(&mut self) -> Result<()> {
        if let Some(len) = self.torn {
            truncate(&self.path, len)?;
            self.torn = None;
        }
        Ok(())
    }

    /// Apply the retention policy, returning the number of entries removed.
    pub fn apply_retention(&mut self, data_key: &SecretKey) -> Result<usize> {
        self.cut_torn()?;
        let entries = self.read_all(data_key)?;
        let original_count = entries.len();
        let now = chrono::Utc::now().timestamp();
        let max_age_secs = self.retention.max_age_days.map(|d| i64::from(d) * 86400);

        let mut filtered: Vec<_> = entries
            .into_iter()
            .filter(|e| max_age_secs.is_none_or(|max| now.saturating_sub(e.timestamp) <= max))
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
    pub fn log(&mut self, mut entry: SigningAuditEntry, data_key: &SecretKey) -> Result<()> {
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
        self.cut_torn()?;
        let mut file = open_regular_with(&mut opts, &self.path)?;
        let len = file.metadata()?.len();
        // A partial line left by a failed write would join the next entry
        // into one line that cannot be read.
        if let Err(e) = write_line(&mut file, line.as_bytes()).and_then(|()| file.sync_all()) {
            self.torn = truncate(&self.path, len).err().map(|_| len);
            return Err(e.into());
        }

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
            .filter(|e| caller_filter.is_none_or(|c| e.caller == c))
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
            .filter(|e| caller_filter.is_none_or(|c| e.caller == c))
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
        self.cut_torn()?;
        let entries = Self::read_entries(&self.path, old_key)?;
        if entries.is_empty() {
            return Ok(());
        }
        self.rewrite(&entries, new_key)
    }

    /// Re-encrypt the unreadable logs [`SigningAuditLog::open`] kept with a
    /// new data key, line for line the same plaintext; a line that does not
    /// decrypt under `old_key` is kept as it is.
    /// Every kept log is tried, and the failures are reported together.
    pub fn reencrypt_kept_logs(&self, old_key: &SecretKey, new_key: &SecretKey) -> Result<()> {
        let dir = self.path.parent().unwrap_or(Path::new("."));
        let failed: Vec<String> = kept_paths(dir, UNREADABLE_SIGNING_LOG)
            .into_iter()
            .filter_map(|path| {
                reencrypt_as_is(&path, old_key, new_key)
                    .err()
                    .map(|e| format!("{}: {e}", path.display()))
            })
            .collect();
        if failed.is_empty() {
            Ok(())
        } else {
            Err(StorageError::io(format!(
                "re-encrypt kept signing audit logs: {}",
                failed.join("; ")
            ))
            .into())
        }
    }

    fn read_entries(path: &Path, data_key: &SecretKey) -> Result<Vec<SigningAuditEntry>> {
        const MAX_ENTRIES: usize = 100_000;

        let file = open_regular(path)?;
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
        self.torn = None;
        Ok(())
    }

    fn write_entries_to_temp(
        &self,
        temp_path: &Path,
        entries: &[SigningAuditEntry],
        data_key: &SecretKey,
    ) -> Result<[u8; 32]> {
        let mut file = create_fresh(temp_path)?;

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
pub(crate) mod test_support {
    use super::*;

    std::thread_local! {
        /// Makes this thread's migrations behave as on a file system without
        /// hard links.
        pub(crate) static NO_HARD_LINKS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        /// Makes this thread's copies into a kept log's name fail.
        pub(crate) static FAIL_COPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        /// Makes this thread's log appends write half a line and fail.
        pub(crate) static PARTIAL_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        /// Makes this thread's cuts of a log back to a length fail.
        pub(crate) static FAIL_TRUNCATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Append `count` entries to the log in `dir`, chained from its last
    /// entry, without a sync per line, for tests of long logs.
    pub(crate) fn write_long_log(dir: &Path, key: &SecretKey, count: usize) {
        let log = AuditLog::open(dir, key).unwrap();
        let (mut seq, mut prev) = (log.seq(), log.last_hash());
        let mut out = std::io::BufWriter::new(
            OpenOptions::new()
                .append(true)
                .open(dir.join("audit.log"))
                .unwrap(),
        );
        for _ in 0..count {
            let mut entry = AuditEntry::new(AuditEventType::Sign, prev);
            entry.format = AUDIT_FORMAT;
            seq += 1;
            entry.seq = seq;
            entry.hash = entry.compute_hash();
            prev = entry.hash;
            out.write_all(AuditLog::encrypt_line(&entry, key).unwrap().as_bytes())
                .unwrap();
        }
        out.flush().unwrap();
    }

    /// Write `entries` to `dir/audit.log` exactly as the release before
    /// sequence numbers did: format 1 hashes, chained from zero, and JSON
    /// without the fields that came later.
    pub(crate) fn write_format1_log(dir: &Path, key: &SecretKey, entries: Vec<AuditEntry>) {
        let mut out = String::new();
        let mut prev_hash = [0u8; 32];
        for mut entry in entries {
            entry.format = 1;
            entry.seq = 0;
            entry.migration = None;
            entry.retention = None;
            entry.prev_hash = prev_hash;
            entry.hash = entry.compute_hash();
            prev_hash = entry.hash;
            out.push_str(&format1_line(&entry, key));
        }
        std::fs::write(dir.join("audit.log"), out).unwrap();
    }

    /// One line of a format 1 log, as the release before sequence numbers
    /// wrote it.
    pub(crate) fn format1_line(entry: &AuditEntry, key: &SecretKey) -> String {
        let mut value = serde_json::to_value(entry).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("format");
        object.remove("seq");
        let encrypted = crypto::encrypt(&serde_json::to_vec(&value).unwrap(), key).unwrap();
        format!("{}\n", STANDARD.encode(encrypted.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_key() -> SecretKey {
        SecretKey::generate().unwrap()
    }

    /// Opening reads only the last entry, so a log longer than it can be read
    /// back with still opens and its chain continues from the last entry.
    #[test]
    fn a_log_past_the_read_cap_still_opens_and_chains() {
        let dir = tempdir().unwrap();
        let key = test_key();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        log.log(AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]), &key)
            .unwrap();
        let last = log.last_hash();
        let path = dir.path().join("audit.log");
        let line = std::fs::read(&path).unwrap();
        std::fs::write(&path, line.repeat(MAX_AUDIT_ENTRIES + 1)).unwrap();
        // Reading back that many entries is too slow for a debug test; the cap
        // on reads is covered with a small cap below.

        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!(log.entry_count(), MAX_AUDIT_ENTRIES + 1);
        assert_eq!(log.last_hash(), last);
        log.log(AuditEntry::new(AuditEventType::VaultLock, [0; 32]), &key)
            .unwrap();
        assert_eq!(log.entry_count(), MAX_AUDIT_ENTRIES + 2);
        let reopened = AuditLog::open(dir.path(), &key).unwrap();
        assert_ne!(reopened.last_hash(), last);
        assert_eq!(reopened.last_hash(), log.last_hash());
    }

    /// Listing stops at the read cap, but retention and re-encryption read the
    /// whole log, so a log too long to list can still be pruned and rotated.
    #[test]
    fn a_log_past_the_read_cap_can_be_pruned_and_reencrypted() {
        let dir = tempdir().unwrap();
        let key = test_key();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        for _ in 0..5 {
            log.log(AuditEntry::new(AuditEventType::Sign, [0; 32]), &key)
                .unwrap();
        }
        log.read_cap = 3;
        let err = log.read_all(&key).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum of 3"), "{err}");

        let new_key = test_key();
        log.reencrypt(&key, &new_key).unwrap();
        log.set_retention(RetentionPolicy {
            max_entries: Some(2),
            max_age_days: None,
        });
        // Two kept, counting the retention entry.
        assert_eq!(log.apply_retention(&new_key).unwrap(), 4);
        assert_eq!(log.read_all(&new_key).unwrap().len(), 2);
        assert!(log.verify_chain(&new_key).unwrap());
    }

    /// A partial line a failed write could not cut off is cut before the next
    /// append, so the next entry is not glued onto it.
    #[test]
    fn a_partial_line_is_cut_before_the_next_append() {
        let dir = tempdir().unwrap();
        let key = test_key();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        log.log(AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]), &key)
            .unwrap();
        let path = dir.path().join("audit.log");
        let len = std::fs::metadata(&path).unwrap().len();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"partial").unwrap();
        log.torn = Some(len);

        log.log(AuditEntry::new(AuditEventType::VaultLock, [0; 32]), &key)
            .unwrap();
        assert_eq!(log.torn, None);
        assert_eq!(log.read_all(&key).unwrap().len(), 2);
        assert!(log.verify_chain(&key).unwrap());
    }

    /// A rewrite replaces the file, so a cut pending against the old file is
    /// dropped rather than applied to the new one.
    #[test]
    fn a_rewrite_drops_a_pending_cut() {
        let dir = tempdir().unwrap();
        let key = test_key();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        for _ in 0..3 {
            log.log(AuditEntry::new(AuditEventType::Sign, [0; 32]), &key)
                .unwrap();
        }
        let len = std::fs::metadata(dir.path().join("audit.log"))
            .unwrap()
            .len();
        log.torn = Some(len - 1);
        log.reencrypt(&key, &key).unwrap();
        assert_eq!(log.torn, None);
        log.log(AuditEntry::new(AuditEventType::Sign, [0; 32]), &key)
            .unwrap();
        assert_eq!(log.read_all(&key).unwrap().len(), 4);
        assert!(log.verify_chain(&key).unwrap());
    }

    /// A log whose lines end in `\r\n` opens and counts like `read_all` reads it.
    #[test]
    fn crlf_line_endings_open() {
        let dir = tempdir().unwrap();
        let key = test_key();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        log.log(AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]), &key)
            .unwrap();
        let last = log.last_hash();
        let path = dir.path().join("audit.log");
        let crlf = String::from_utf8(std::fs::read(&path).unwrap())
            .unwrap()
            .replace('\n', "\r\n");
        std::fs::write(&path, format!("{crlf}\r\n")).unwrap();

        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!(log.entry_count(), 1);
        assert_eq!(log.last_hash(), last);
        assert_eq!(log.read_all(&key).unwrap().len(), 1);
    }

    /// An append a crash cut short (no trailing newline) is dropped on open, so
    /// the log still opens, reads back and chains.
    #[test]
    fn a_torn_final_line_is_dropped_on_open() {
        let dir = tempdir().unwrap();
        let key = test_key();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        log.log(AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]), &key)
            .unwrap();
        log.log(AuditEntry::new(AuditEventType::VaultLock, [0; 32]), &key)
            .unwrap();
        let path = dir.path().join("audit.log");
        let whole = std::fs::read(&path).unwrap();
        let mut torn = whole.clone();
        torn.extend_from_slice(&whole[..20]);
        std::fs::write(&path, torn).unwrap();

        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), whole);
        assert_eq!(log.entry_count(), 2);
        log.log(AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]), &key)
            .unwrap();
        assert_eq!(log.read_all(&key).unwrap().len(), 3);
        assert!(log.verify_chain(&key).unwrap());
    }

    /// Run `f` with the test write and cut faults set as given, clearing
    /// them after.
    fn with_faults<T>(partial_write: bool, fail_truncate: bool, f: impl FnOnce() -> T) -> T {
        use super::test_support::{FAIL_TRUNCATE, PARTIAL_WRITE};
        PARTIAL_WRITE.with(|c| c.set(partial_write));
        FAIL_TRUNCATE.with(|c| c.set(fail_truncate));
        let out = f();
        PARTIAL_WRITE.with(|c| c.set(false));
        FAIL_TRUNCATE.with(|c| c.set(false));
        out
    }

    fn signing_entry(n: u8) -> SigningAuditEntry {
        SigningAuditEntry::new(
            SigningRequestType::SignEvent,
            SigningDecision::Approved,
            false,
            "caller".into(),
            [0; 32],
        )
        .with_caller_name(format!("app {n}"))
    }

    /// A signing append that fails partway leaves no partial line: it is
    /// cut off at once, or before the next append when the cut fails too,
    /// so the next entry starts its own line and the log reads back whole.
    #[test]
    fn a_failed_signing_append_leaves_no_partial_line() {
        for fail_truncate in [false, true] {
            let dir = tempdir().unwrap();
            let key = test_key();
            let path = dir.path().join("signing_audit.log");
            let mut log = SigningAuditLog::open(dir.path(), &key).unwrap();
            log.log(signing_entry(1), &key).unwrap();
            let before = std::fs::read(&path).unwrap();

            let failed = with_faults(true, fail_truncate, || log.log(signing_entry(2), &key));
            assert!(failed.is_err());
            let after = std::fs::read(&path).unwrap();
            assert_eq!(
                after == before,
                !fail_truncate,
                "fail_truncate {fail_truncate}"
            );

            log.log(signing_entry(3), &key).unwrap();
            let entries = log.read_all(&key).unwrap();
            let names: Vec<_> = entries.iter().map(|e| e.caller_name.clone()).collect();
            assert_eq!(names, [Some("app 1".into()), Some("app 3".into())]);
            assert_eq!(log.verify_chain(&key).unwrap(), (true, 2));
        }
    }

    /// A partial line a failed append could not cut is cut before key
    /// rotation or retention reads the signing log, so neither finds it
    /// unreadable and the entries before it survive.
    #[test]
    fn a_left_over_signing_cut_is_made_before_rotation_and_retention() {
        for rotate in [true, false] {
            let dir = tempdir().unwrap();
            let key = test_key();
            let mut log = SigningAuditLog::open(dir.path(), &key).unwrap();
            log.log(signing_entry(1), &key).unwrap();
            log.log(signing_entry(2), &key).unwrap();
            let failed = with_faults(true, true, || log.log(signing_entry(3), &key));
            assert!(failed.is_err());
            let read_key = if rotate {
                let new_key = SecretKey::generate().unwrap();
                log.reencrypt(&key, &new_key).unwrap();
                new_key
            } else {
                log.set_retention(RetentionPolicy {
                    max_entries: Some(1),
                    max_age_days: None,
                });
                assert_eq!(log.apply_retention(&key).unwrap(), 1);
                key
            };
            let names: Vec<_> = log
                .read_all(&read_key)
                .unwrap()
                .into_iter()
                .map(|e| e.caller_name)
                .collect();
            let expected: Vec<Option<String>> = if rotate {
                vec![Some("app 1".into()), Some("app 2".into())]
            } else {
                vec![Some("app 2".into())]
            };
            assert_eq!(names, expected, "rotate {rotate}");
        }
    }

    /// The same holds for the audit log.
    #[test]
    fn a_failed_audit_append_leaves_no_partial_line() {
        for fail_truncate in [false, true] {
            let dir = tempdir().unwrap();
            let key = test_key();
            let mut log = AuditLog::open(dir.path(), &key).unwrap();
            log.log(AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]), &key)
                .unwrap();
            let failed = with_faults(true, fail_truncate, || {
                log.log(AuditEntry::new(AuditEventType::VaultLock, [0; 32]), &key)
            });
            assert!(failed.is_err());
            log.log(AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]), &key)
                .unwrap();
            assert_eq!(log.read_all(&key).unwrap().len(), 2);
            assert!(log.verify_chain(&key).unwrap());
        }
    }

    /// A symlink in a log's place is refused with an error naming it, and
    /// the file it points at is neither cut nor written, though a torn end
    /// would be cut from a log and an entry appended to it.
    #[cfg(unix)]
    #[test]
    fn a_symlink_in_a_logs_place_is_refused_and_not_followed() {
        let key = test_key();
        let dir = tempdir().unwrap();
        let source = tempdir().unwrap();
        let mut log = AuditLog::open(source.path(), &key).unwrap();
        log.log(AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]), &key)
            .unwrap();
        let mut signing = SigningAuditLog::open(source.path(), &key).unwrap();
        signing.log(signing_entry(1), &key).unwrap();

        for name in ["audit.log", "signing_audit.log"] {
            let mut torn = std::fs::read(source.path().join(name)).unwrap();
            torn.extend_from_slice(b"half a line");
            let target = dir.path().join(format!("{name}.elsewhere"));
            std::fs::write(&target, &torn).unwrap();
            std::os::unix::fs::symlink(&target, dir.path().join(name)).unwrap();
        }
        let err = AuditLog::open(dir.path(), &key).err().unwrap().to_string();
        assert!(err.contains("audit.log is not a regular file"), "{err}");
        std::fs::remove_file(dir.path().join("audit.log")).unwrap();
        let err = SigningAuditLog::open(dir.path(), &key)
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("signing_audit.log is not a regular file"),
            "{err}"
        );

        for name in ["audit.log", "signing_audit.log"] {
            let mut torn = std::fs::read(source.path().join(name)).unwrap();
            torn.extend_from_slice(b"half a line");
            let target = dir.path().join(format!("{name}.elsewhere"));
            assert_eq!(std::fs::read(&target).unwrap(), torn, "{name}");
        }
    }

    /// A symlink left where no log is yet is refused, not taken for no log.
    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_in_a_logs_place_is_refused() {
        let key = test_key();
        for name in ["audit.log", "signing_audit.log"] {
            let dir = tempdir().unwrap();
            let target = dir.path().join("nowhere");
            std::os::unix::fs::symlink(&target, dir.path().join(name)).unwrap();
            let opened = match name {
                "audit.log" => AuditLog::open(dir.path(), &key).map(drop),
                _ => SigningAuditLog::open(dir.path(), &key).map(drop),
            };
            assert!(opened.is_err(), "{name}");
            assert!(!target.exists(), "{name}");
        }
    }

    /// A log swapped for a symlink to a copy of itself while the vault is
    /// open is refused at the next append, and the copy is left as it was.
    #[cfg(unix)]
    #[test]
    fn a_log_swapped_for_a_symlink_while_open_is_not_appended_through() {
        let key = test_key();
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        log.log(AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]), &key)
            .unwrap();
        let copy = dir.path().join("copy");
        std::fs::copy(&path, &copy).unwrap();
        let before = std::fs::read(&copy).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&copy, &path).unwrap();

        let appended = log.log(AuditEntry::new(AuditEventType::VaultLock, [0; 32]), &key);
        assert!(appended.is_err());
        assert_eq!(std::fs::read(&copy).unwrap(), before);
    }

    /// Replace the file at `path` with a symlink to a copy of it, returning
    /// the copy's path and contents.
    #[cfg(unix)]
    fn swap_for_symlink_to_copy(path: &Path) -> (PathBuf, Vec<u8>) {
        let copy = path.with_extension("copy");
        std::fs::copy(path, &copy).unwrap();
        std::fs::remove_file(path).unwrap();
        std::os::unix::fs::symlink(&copy, path).unwrap();
        let before = std::fs::read(&copy).unwrap();
        (copy, before)
    }

    /// A log swapped for a symlink while the vault is open is not read
    /// through by any read, so a symlink to `/dev/zero` cannot fill memory.
    #[cfg(unix)]
    #[test]
    fn no_read_follows_a_log_swapped_for_a_symlink() {
        let key = test_key();
        let dir = tempdir().unwrap();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        log.log(
            AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]).with_reason("noted"),
            &key,
        )
        .unwrap();
        let mut signing = SigningAuditLog::open(dir.path(), &key).unwrap();
        signing.log(signing_entry(1), &key).unwrap();
        swap_for_symlink_to_copy(&dir.path().join("audit.log"));
        swap_for_symlink_to_copy(&dir.path().join("signing_audit.log"));

        assert!(log.read_all(&key).is_err());
        assert!(log.check_chain(&key).is_err());
        assert!(log.last_own_timestamp(&key).is_err());
        assert_eq!(log.entry_hash_at(1, &key), None);
        assert!(!log.any_entry_noting(&[AuditEventType::VaultUnlock], "noted", &key));
        assert!(signing.read_all(&key).is_err());
    }

    /// The cut a failed append left for the next one is not made through a
    /// symlink put in the log's place, nor is the append, for either log.
    #[cfg(unix)]
    #[test]
    fn a_left_over_cut_is_not_made_through_a_symlink() {
        let key = test_key();
        for torn in [false, true] {
            let dir = tempdir().unwrap();
            let mut log = AuditLog::open(dir.path(), &key).unwrap();
            log.log(AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]), &key)
                .unwrap();
            let mut signing = SigningAuditLog::open(dir.path(), &key).unwrap();
            signing.log(signing_entry(1), &key).unwrap();
            if torn {
                let failed = with_faults(true, true, || {
                    log.log(AuditEntry::new(AuditEventType::VaultLock, [0; 32]), &key)
                });
                assert!(failed.is_err());
                let failed = with_faults(true, true, || signing.log(signing_entry(2), &key));
                assert!(failed.is_err());
            }
            let (copy, before) = swap_for_symlink_to_copy(&dir.path().join("audit.log"));
            let (signing_copy, signing_before) =
                swap_for_symlink_to_copy(&dir.path().join("signing_audit.log"));

            let appended = log.log(AuditEntry::new(AuditEventType::VaultLock, [0; 32]), &key);
            assert!(appended.is_err(), "torn {torn}");
            assert_eq!(std::fs::read(&copy).unwrap(), before, "torn {torn}");
            assert!(signing.log(signing_entry(3), &key).is_err(), "torn {torn}");
            assert_eq!(
                std::fs::read(&signing_copy).unwrap(),
                signing_before,
                "torn {torn}"
            );
        }
    }

    /// The first append to a log that has no entries yet, which has no last
    /// line to check, does not write through a symlink put in its place.
    #[cfg(unix)]
    #[test]
    fn a_first_append_is_not_made_through_a_symlink() {
        let key = test_key();
        let dir = tempdir().unwrap();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("audit.log")).unwrap();
        let appended = log.log(AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]), &key);
        assert!(appended.is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"");
    }

    /// Retention rewrites the signing log through a fresh temporary file, so
    /// a symlink left at the temporary name is replaced, and the file it
    /// points at is neither cut nor written.
    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_signing_logs_temporary_name_is_not_written_through() {
        let key = test_key();
        let dir = tempdir().unwrap();
        let mut log = SigningAuditLog::open(dir.path(), &key).unwrap();
        for n in 0..3 {
            log.log(signing_entry(n), &key).unwrap();
        }
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, b"not keep's").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("signing_audit.log.tmp")).unwrap();
        log.set_retention(RetentionPolicy {
            max_entries: Some(1),
            max_age_days: None,
        });
        assert_eq!(log.apply_retention(&key).unwrap(), 2);
        assert_eq!(std::fs::read(&target).unwrap(), b"not keep's");
        assert_eq!(log.read_all(&key).unwrap().len(), 1);
    }

    /// A FIFO in a log's place is refused at once rather than hanging the
    /// open waiting for a writer.
    #[cfg(unix)]
    #[test]
    fn a_fifo_in_a_logs_place_is_refused_without_blocking() {
        for name in ["audit.log", "signing_audit.log"] {
            let dir = tempdir().unwrap();
            let fifo = dir.path().join(name);
            let made = std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap();
            assert!(made.success());
            let (tx, rx) = std::sync::mpsc::channel();
            let at = dir.path().to_path_buf();
            let owned = name.to_string();
            std::thread::spawn(move || {
                let key = test_key();
                let opened = match owned.as_str() {
                    "audit.log" => AuditLog::open(&at, &key).map(drop),
                    _ => SigningAuditLog::open(&at, &key).map(drop),
                };
                let _ = tx.send(opened.err().map(|e| e.to_string()));
            });
            let err = rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap_or_else(|_| panic!("opening a FIFO at {name} hung"))
                .unwrap_or_else(|| panic!("a FIFO at {name} was taken for a log"));
            assert!(err.contains("is not a regular file"), "{err}");
        }
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

        // Three kept, counting the retention entry, so a second run with
        // nothing new removes nothing.
        let removed = log.apply_retention(&key).unwrap();
        assert_eq!(removed, 3);

        let entries = log.read_all(&key).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].event_type, AuditEventType::AuditRetention);
        assert_eq!(log.apply_retention(&key).unwrap(), 0);
        assert!(log.verify_chain(&key).unwrap());
    }

    #[test]
    fn verify_chain_returns_true_when_log_absent() {
        // A vault that has never recorded an entry has no audit.log on disk.
        // `verify_chain` must not error or return false in that case, or every
        // freshly-created vault would look "tampered" to `keep audit verify`.
        let dir = tempdir().unwrap();
        let key = test_key();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert!(log.verify_chain(&key).unwrap());
        assert!(log.read_all(&key).unwrap().is_empty());
    }

    #[test]
    fn verify_chain_detects_ciphertext_tamper() {
        // The audit log's primary integrity guarantee: a byte flip in a
        // persisted entry must NOT pass verify_chain. The line-level
        // ciphertext check is what `keep audit verify` relies on to detect
        // post-hoc edits of the audit log.
        let dir = tempdir().unwrap();
        let key = test_key();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();

        for i in 0..3 {
            let entry =
                AuditEntry::new(AuditEventType::Sign, log.last_hash()).with_pubkey(&[i as u8; 32]);
            log.log(entry, &key).unwrap();
        }
        assert!(log.verify_chain(&key).unwrap());

        // Flip a byte in the middle of the first persisted entry.
        let audit_path = dir.path().join("audit.log");
        let mut content = std::fs::read(&audit_path).unwrap();
        let first_newline = content.iter().position(|b| *b == b'\n').unwrap();
        // Pick a base64 alphabet character inside the first line so the byte
        // remains decode-valid but the underlying ciphertext is altered.
        let target = first_newline / 2;
        content[target] = if content[target] == b'A' { b'B' } else { b'A' };
        std::fs::write(&audit_path, &content).unwrap();

        // The tampered line must NOT verify cleanly. Either Ok(false) for a
        // hash-chain mismatch, or Err(Corrupted/InvalidFormat) for a failed
        // decrypt: both are acceptable failure modes that `keep audit verify`
        // surfaces to the operator as a tamper warning.
        match log.verify_chain(&key) {
            Ok(false) => {}
            Err(_) => {}
            Ok(true) => panic!("verify_chain accepted a tampered entry as valid"),
        }
    }

    #[test]
    fn apply_retention_by_age_drops_old_entries() {
        // The age-based retention path is what `keep audit retention --max-days`
        // exercises; nothing tested it end-to-end before.
        let dir = tempdir().unwrap();
        let key = test_key();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();

        let now = chrono::Utc::now().timestamp();
        let old_ts = now - 60 * 86400; // 60 days ago.
        let recent_ts = now - 86400; // 1 day ago.

        let mut old_entry = AuditEntry::new(AuditEventType::Sign, log.last_hash());
        old_entry.timestamp = old_ts;
        log.log(old_entry, &key).unwrap();

        let mut recent_entry = AuditEntry::new(AuditEventType::Sign, log.last_hash());
        recent_entry.timestamp = recent_ts;
        log.log(recent_entry, &key).unwrap();

        log.set_retention(RetentionPolicy {
            max_entries: None,
            max_age_days: Some(30),
        });
        let removed = log.apply_retention(&key).unwrap();
        assert_eq!(removed, 1, "the 60-day-old entry must be pruned");

        let remaining = log.read_all(&key).unwrap();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].timestamp, recent_ts);
        assert_eq!(remaining[1].event_type, AuditEventType::AuditRetention);
        assert!(
            log.verify_chain(&key).unwrap(),
            "retention rewrite must preserve a valid hash chain"
        );
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

#[cfg(test)]
mod sequence_tests {
    use super::test_support::{format1_line, write_format1_log};
    use super::*;
    use tempfile::tempdir;

    /// The fixture's key, head and entries, from the release before sequence
    /// numbers (`tests/fixtures/audit-format1.log`).
    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/audit-format1.log");
    const FIXTURE_KEY: [u8; 32] = [7u8; 32];
    const FIXTURE_HEAD: &str = "2aed8b64adf6b4cfd761024f6538ca41932cab836759aec4784ae1c3ae46a882";

    fn key() -> SecretKey {
        SecretKey::generate().unwrap()
    }

    fn sign(n: u8) -> AuditEntry {
        AuditEntry::new(AuditEventType::Sign, [0; 32]).with_pubkey(&[n; 32])
    }

    fn logged(dir: &Path, key: &SecretKey, n: u8) -> AuditLog {
        let mut log = AuditLog::open(dir, key).unwrap();
        for i in 0..n {
            log.log(sign(i), key).unwrap();
        }
        log
    }

    fn assert_migrated(entries: &[AuditEntry]) {
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.format, AUDIT_FORMAT);
            assert_eq!(e.seq, i as u64 + 1);
        }
    }

    /// A log the release before sequence numbers wrote migrates on open:
    /// every entry kept with its contents, sequence numbers from 1, a
    /// migration entry binding the old head and count, the old file kept
    /// byte for byte, and a chain that verifies.
    #[test]
    fn a_release_log_migrates() {
        let dir = tempdir().unwrap();
        let key = SecretKey::new(FIXTURE_KEY).unwrap();
        std::fs::write(dir.path().join("audit.log"), FIXTURE).unwrap();
        let old = AuditLog::read_entries(&dir.path().join("audit.log"), &key, usize::MAX).unwrap();
        assert!(old.iter().all(|e| e.format == 1 && e.seq == 0));

        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!(log.entry_count(), 7);
        assert_eq!(log.seq(), 7);
        assert!(!log.failed_migration_kept());
        assert_eq!(
            std::fs::read(dir.path().join(MIGRATED_LOG)).unwrap(),
            FIXTURE
        );

        let entries = log.read_all(&key).unwrap();
        assert_migrated(&entries);
        for (new, old) in entries.iter().zip(&old) {
            assert_eq!(new.timestamp, old.timestamp);
            assert_eq!(new.event_type, old.event_type);
            assert_eq!(new.pubkey, old.pubkey);
            assert_eq!(new.key_type, old.key_type);
            assert_eq!(new.message_hash, old.message_hash);
            assert_eq!(new.group_pubkey, old.group_pubkey);
            assert_eq!(new.participants, old.participants);
            assert_eq!(new.threshold, old.threshold);
            assert_eq!(new.success, old.success);
            assert_eq!(new.reason, old.reason);
        }
        let note = &entries[6];
        assert_eq!(note.event_type, AuditEventType::AuditLogMigrated);
        assert!(note.success);
        let migration = AuditMigration {
            old_head: hex::decode(FIXTURE_HEAD).unwrap().try_into().unwrap(),
            old_count: 6,
            old_chain_valid: true,
            seq: 7,
        };
        assert_eq!(note.migration, Some(migration));
        assert_eq!(
            log.verify(&key).unwrap(),
            AuditVerification {
                valid: true,
                migration: Some(migration),
                first_seq: 1,
            }
        );

        // Opened again, nothing migrates again.
        let head = log.last_hash();
        let reopened = AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!(reopened.last_hash(), head);
        assert_eq!(reopened.seq(), 7);
        assert!(!dir.path().join(format!("{MIGRATED_LOG}.2")).exists());
    }

    /// A migrated log keeps counting: appends continue the sequence.
    #[test]
    fn appends_continue_the_sequence_after_migration() {
        let dir = tempdir().unwrap();
        let key = key();
        write_format1_log(dir.path(), &key, vec![sign(1), sign(2)]);
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        log.log(sign(3), &key).unwrap();
        assert_eq!(log.seq(), 4);
        let entries = log.read_all(&key).unwrap();
        assert_migrated(&entries);
        assert!(log.verify_chain(&key).unwrap());
    }

    /// An old log whose chain does not check out still migrates and the vault
    /// still opens, with the failure recorded, reported on every open while
    /// the old file is kept, and no longer once it is removed.
    #[test]
    fn a_tampered_old_log_migrates_with_the_failure_recorded() {
        let dir = tempdir().unwrap();
        let key = key();
        write_format1_log(dir.path(), &key, vec![sign(1), sign(2), sign(3)]);
        // Rewrite the middle entry's reason under its old hash.
        let path = dir.path().join("audit.log");
        let mut entries = AuditLog::read_entries(&path, &key, usize::MAX).unwrap();
        entries[1].reason = Some("edited".into());
        let lines: String = entries.iter().map(|e| format1_line(e, &key)).collect();
        std::fs::write(&path, lines).unwrap();
        let old_head = entries[2].hash;

        let log = AuditLog::open(dir.path(), &key).unwrap();
        let failed = AuditMigration {
            old_head,
            old_count: 3,
            old_chain_valid: false,
            seq: 4,
        };
        assert!(log.failed_migration_kept());
        assert_eq!(log.verify(&key).unwrap().migration, Some(failed));
        let report = log.verify(&key).unwrap();
        assert!(report.valid);
        assert_eq!(report.migration, Some(failed));
        let note = log.read_all(&key).unwrap().pop().unwrap();
        assert!(!note.success);

        let reopened = AuditLog::open(dir.path(), &key).unwrap();
        assert!(reopened.failed_migration_kept());
        std::fs::remove_file(dir.path().join(MIGRATED_LOG)).unwrap();
        let reopened = AuditLog::open(dir.path(), &key).unwrap();
        assert!(!reopened.failed_migration_kept());
        // The record stays in the chain.
        assert_eq!(reopened.verify(&key).unwrap().migration, Some(failed));
    }

    /// An old log with a line that cannot be read keeps every entry that can
    /// be read, records the fault, and the warning is still found on the
    /// next open.
    #[test]
    fn a_partly_unreadable_old_log_migrates_what_it_can() {
        let dir = tempdir().unwrap();
        let key = key();
        write_format1_log(dir.path(), &key, vec![sign(1), sign(2), sign(3), sign(4)]);
        let path = dir.path().join("audit.log");
        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        let readable = AuditLog::read_entries(&path, &key, usize::MAX).unwrap();
        lines[2] = "bm90IGFuIGVudHJ5".into();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let log = AuditLog::open(dir.path(), &key).unwrap();
        let failed = AuditMigration {
            old_head: readable[3].hash,
            old_count: 3,
            old_chain_valid: false,
            seq: 4,
        };
        assert!(log.failed_migration_kept());
        let report = log.verify(&key).unwrap();
        assert_eq!(report.migration, Some(failed));
        assert!(report.valid);
        assert!(!log.verify_chain(&key).unwrap());
        let carried: Vec<_> = log.read_all(&key).unwrap()[..3]
            .iter()
            .map(|e| e.pubkey.clone())
            .collect();
        let expected: Vec<_> = [0, 1, 3]
            .iter()
            .map(|&i| readable[i].pubkey.clone())
            .collect();
        assert_eq!(carried, expected);
        assert_eq!(log.entry_count(), 4);
        let reopened = AuditLog::open(dir.path(), &key).unwrap();
        assert!(reopened.failed_migration_kept());
    }

    /// A log whose last line cannot be read still opens, in either format:
    /// it migrates with the fault recorded, a current-format log keeping its
    /// entries and sequence numbers up to the damage.
    #[test]
    fn an_unreadable_last_line_never_stops_a_log_opening() {
        let dir = tempdir().unwrap();
        let key = key();
        write_format1_log(dir.path(), &key, vec![sign(1), sign(2)]);
        let path = dir.path().join("audit.log");
        let mut old = std::fs::read_to_string(&path).unwrap();
        old.push_str("bm90IGFuIGVudHJ5\n");
        std::fs::write(&path, &old).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert!(log.failed_migration_kept());
        assert_eq!(
            log.verify(&key).unwrap().migration.map(|m| m.old_count),
            Some(2)
        );

        let dir = tempdir().unwrap();
        logged(dir.path(), &key, 2);
        let path = dir.path().join("audit.log");
        let mut new = std::fs::read_to_string(&path).unwrap();
        new.push_str("bm90IGFuIGVudHJ5\n");
        std::fs::write(&path, &new).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert!(log.failed_migration_kept());
        assert_eq!(log.seq(), 3);
        let m = log.verify(&key).unwrap().migration.unwrap();
        assert_eq!((m.old_count, m.old_chain_valid, m.seq), (2, false, 3));
        assert_eq!(
            std::fs::read_to_string(dir.path().join(MIGRATED_LOG)).unwrap(),
            new
        );
    }

    /// A crash after the old log was copied but before the new one replaced
    /// it leaves the old log in place; the next open migrates it again and
    /// keeps a second copy rather than overwriting the first.
    #[test]
    fn a_crash_before_the_rename_migrates_again() {
        let dir = tempdir().unwrap();
        let key = key();
        write_format1_log(dir.path(), &key, vec![sign(1), sign(2)]);
        let old = std::fs::read(dir.path().join("audit.log")).unwrap();
        std::fs::write(dir.path().join(MIGRATED_LOG), &old).unwrap();
        std::fs::write(dir.path().join("audit.log.tmp"), b"half a new log").unwrap();

        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!(log.seq(), 3);
        assert!(log.verify_chain(&key).unwrap());
        assert_eq!(std::fs::read(dir.path().join(MIGRATED_LOG)).unwrap(), old);
        assert_eq!(
            std::fs::read(dir.path().join(format!("{MIGRATED_LOG}.2"))).unwrap(),
            old
        );
        assert!(!dir.path().join("audit.log.tmp").exists());
    }

    /// A data key change re-encrypts the kept old log too, line for line the
    /// same plaintext, and leaves a line that never decrypted as it was.
    #[test]
    fn reencrypting_keeps_the_old_log_readable() {
        let dir = tempdir().unwrap();
        let key = key();
        write_format1_log(dir.path(), &key, vec![sign(1), sign(2)]);
        let path = dir.path().join("audit.log");
        let mut old = std::fs::read_to_string(&path).unwrap();
        old.push_str("bm90IGFuIGVudHJ5\n");
        std::fs::write(&path, &old).unwrap();
        let before: Vec<Vec<u8>> = old
            .lines()
            .take(2)
            .map(|l| AuditLog::decrypt_raw(l, &key).unwrap().to_vec())
            .collect();

        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        let new_key = super::super::crypto::SecretKey::generate().unwrap();
        log.reencrypt(&key, &new_key).unwrap();
        log.reencrypt_kept_logs(&key, &new_key).unwrap();

        let kept = std::fs::read_to_string(dir.path().join(MIGRATED_LOG)).unwrap();
        let lines: Vec<&str> = kept.lines().collect();
        assert_eq!(lines.len(), 3);
        for (line, plain) in lines.iter().zip(&before) {
            assert!(AuditLog::decrypt_raw(line, &key).is_err());
            assert_eq!(&*AuditLog::decrypt_raw(line, &new_key).unwrap(), plain);
        }
        assert_eq!(lines[2], "bm90IGFuIGVudHJ5");
        assert!(log.verify(&new_key).unwrap().valid);
        let reopened = AuditLog::open(dir.path(), &new_key).unwrap();
        assert!(reopened.failed_migration_kept());
        assert_eq!(
            reopened
                .verify(&new_key)
                .unwrap()
                .migration
                .map(|m| m.old_count),
            Some(2)
        );
    }

    /// Re-encryption and retention keep every remaining entry's hash and
    /// sequence number, so the head never changes under a rewrite.
    #[test]
    fn rewrites_keep_hashes_and_sequence_numbers() {
        let dir = tempdir().unwrap();
        let key = key();
        let mut log = logged(dir.path(), &key, 5);
        let before = log.read_all(&key).unwrap();
        let new_key = super::super::crypto::SecretKey::generate().unwrap();
        log.reencrypt(&key, &new_key).unwrap();
        let after = log.read_all(&new_key).unwrap();
        let hashes = |v: &[AuditEntry]| v.iter().map(|e| (e.seq, e.hash)).collect::<Vec<_>>();
        assert_eq!(hashes(&after), hashes(&before));
        assert_eq!(log.last_hash(), before[4].hash);

        log.set_retention(RetentionPolicy {
            max_entries: Some(3),
            max_age_days: None,
        });
        assert_eq!(log.apply_retention(&new_key).unwrap(), 3);
        let kept = log.read_all(&new_key).unwrap();
        assert_eq!(hashes(&kept[..2]), hashes(&before[3..]));
        assert_eq!(
            kept[2].retention,
            Some(RetentionMark {
                first_seq: 4,
                first_link: before[2].hash,
                removed: 3,
                migration: None,
            })
        );
        assert_eq!(log.seq(), 6);
        assert!(log.verify_chain(&new_key).unwrap());
        log.log(sign(9), &new_key).unwrap();
        assert_eq!(log.seq(), 7);
        assert!(log.verify_chain(&new_key).unwrap());

        // Retention that removes everything keeps only its own entry.
        log.set_retention(RetentionPolicy {
            max_entries: Some(0),
            max_age_days: None,
        });
        log.apply_retention(&new_key).unwrap();
        let kept = log.read_all(&new_key).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].seq, 8);
        assert!(log.verify_chain(&new_key).unwrap());
    }

    /// The records only the log writes cannot come in through `log`.
    #[test]
    fn log_drops_chain_records_and_sets_the_sequence() {
        let dir = tempdir().unwrap();
        let key = key();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        let mut entry = sign(1);
        entry.format = 1;
        entry.seq = 99;
        entry.migration = Some(AuditMigration {
            old_head: [1; 32],
            old_count: 1,
            old_chain_valid: true,
            seq: 1,
        });
        entry.retention = Some(RetentionMark {
            first_seq: 5,
            first_link: [2; 32],
            removed: 4,
            migration: None,
        });
        log.log(entry, &key).unwrap();
        let e = &log.read_all(&key).unwrap()[0];
        assert_eq!((e.format, e.seq), (AUDIT_FORMAT, 1));
        assert_eq!((e.migration, e.retention), (None, None));
        assert!(log.verify_chain(&key).unwrap());
    }

    fn chain(n: u8) -> Vec<AuditEntry> {
        let dir = tempdir().unwrap();
        let key = key();
        logged(dir.path(), &key, n).read_all(&key).unwrap()
    }

    fn rehash(entries: &mut [AuditEntry], from: usize) {
        for i in from..entries.len() {
            if i > 0 {
                entries[i].prev_hash = entries[i - 1].hash;
            }
            entries[i].hash = entries[i].compute_hash();
        }
    }

    /// Each rule of verification, broken on its own, fails it.
    #[test]
    fn verification_fails_on_each_broken_rule() {
        let good = chain(4);
        assert!(verify_entries(&good).valid);

        // An entry in the old format, rehashed so only the format is wrong.
        let mut v = good.clone();
        v[2].format = 1;
        rehash(&mut v, 2);
        assert!(!verify_entries(&v).valid);

        // A gap in the sequence numbers.
        let mut v = good.clone();
        v[2].seq = 4;
        v[3].seq = 5;
        rehash(&mut v, 2);
        assert!(!verify_entries(&v).valid);

        // A broken link.
        let mut v = good.clone();
        v[2].prev_hash = [9; 32];
        v[2].hash = v[2].compute_hash();
        assert!(!verify_entries(&v).valid);

        // A stored hash that does not match.
        let mut v = good.clone();
        v[1].hash = [9; 32];
        v[2].prev_hash = v[1].hash;
        rehash(&mut v, 2);
        assert!(!verify_entries(&v).valid);

        // A first entry that claims to be first but links somewhere.
        let mut v = good.clone();
        v[0].prev_hash = [9; 32];
        rehash(&mut v, 0);
        assert!(!verify_entries(&v).valid);

        // A log cut at the front with no retention entry.
        assert!(!verify_entries(&good[1..]).valid);

        // A migration record on another kind of entry.
        let mut v = good.clone();
        v[1].migration = Some(AuditMigration {
            old_head: [0; 32],
            old_count: 0,
            old_chain_valid: true,
            seq: 0,
        });
        rehash(&mut v, 1);
        assert!(!verify_entries(&v).valid);

        // A retention record on another kind of entry.
        let mut v = good.clone();
        v[1].retention = Some(RetentionMark {
            first_seq: 1,
            first_link: [0; 32],
            removed: 0,
            migration: None,
        });
        rehash(&mut v, 1);
        assert!(!verify_entries(&v).valid);
    }

    /// Retention's entry vouches only for where it cut: cutting more at the
    /// front afterwards, or a mark naming another start, fails.
    #[test]
    fn verification_checks_where_retention_cut() {
        let dir = tempdir().unwrap();
        let key = key();
        let mut log = logged(dir.path(), &key, 6);
        log.set_retention(RetentionPolicy {
            max_entries: Some(4),
            max_age_days: None,
        });
        log.apply_retention(&key).unwrap();
        let kept = log.read_all(&key).unwrap();
        assert!(verify_entries(&kept).valid);
        assert!(!verify_entries(&kept[1..]).valid);

        let mut v = kept.clone();
        let last = v.len() - 1;
        let mut mark = v[last].retention.unwrap();
        mark.first_link = [9; 32];
        v[last].retention = Some(mark);
        rehash(&mut v, last);
        assert!(!verify_entries(&v).valid);

        let mut v = kept;
        mark.first_link = v[0].prev_hash;
        mark.first_seq += 1;
        v[last].retention = Some(mark);
        rehash(&mut v, last);
        assert!(!verify_entries(&v).valid);
    }

    /// The hash covers the format, the sequence number and both chain
    /// records, so none can be changed without changing the hash.
    #[test]
    fn the_hash_covers_the_new_fields() {
        let base = sign(1);
        let hash = base.compute_hash();
        let mut e = base.clone();
        e.seq = 1;
        assert_ne!(e.compute_hash(), hash);
        let mut e = base.clone();
        e.format = 3;
        assert_ne!(e.compute_hash(), hash);
        let migration = AuditMigration {
            old_head: [0; 32],
            old_count: 0,
            old_chain_valid: false,
            seq: 0,
        };
        let mut e = base.clone();
        e.migration = Some(migration);
        let with = e.compute_hash();
        assert_ne!(with, hash);
        e.migration = Some(AuditMigration {
            old_chain_valid: true,
            ..migration
        });
        assert_ne!(e.compute_hash(), with);
        e.migration = Some(AuditMigration {
            old_count: 1,
            ..migration
        });
        assert_ne!(e.compute_hash(), with);
        e.migration = Some(AuditMigration {
            old_head: [1; 32],
            ..migration
        });
        assert_ne!(e.compute_hash(), with);
        e.migration = Some(AuditMigration {
            seq: 1,
            ..migration
        });
        assert_ne!(e.compute_hash(), with);
        let mark = RetentionMark {
            first_seq: 0,
            first_link: [0; 32],
            removed: 0,
            migration: None,
        };
        let mut e = base.clone();
        e.retention = Some(mark);
        let with = e.compute_hash();
        assert_ne!(with, hash);
        for changed in [
            RetentionMark {
                first_seq: 1,
                ..mark
            },
            RetentionMark {
                first_link: [1; 32],
                ..mark
            },
            RetentionMark { removed: 1, ..mark },
            RetentionMark {
                migration: Some(migration),
                ..mark
            },
        ] {
            e.retention = Some(changed);
            assert_ne!(e.compute_hash(), with);
        }
        // Format 1 hashes what it always did.
        let mut e = base;
        e.format = 1;
        e.seq = 5;
        let old = e.compute_hash();
        e.seq = 6;
        assert_eq!(e.compute_hash(), old);
    }

    /// Retention by age removes only the oldest run of entries: an old
    /// timestamp after a recent one stays, so the kept entries are one chain.
    #[test]
    fn retention_by_age_removes_only_a_leading_run() {
        let dir = tempdir().unwrap();
        let key = key();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        let now = chrono::Utc::now().timestamp();
        for age_days in [60, 1, 60, 1] {
            let mut e = sign(0);
            e.timestamp = now - age_days * 86400;
            log.log(e, &key).unwrap();
        }
        log.set_retention(RetentionPolicy {
            max_entries: None,
            max_age_days: Some(30),
        });
        assert_eq!(log.apply_retention(&key).unwrap(), 1);
        let kept = log.read_all(&key).unwrap();
        assert_eq!(kept.iter().map(|e| e.seq).collect::<Vec<_>>(), [2, 3, 4, 5]);
        assert!(log.verify_chain(&key).unwrap());
    }

    /// After a second retention run the log holds two retention entries; the
    /// chain starts where the latest one says, not the earlier one.
    #[test]
    fn the_latest_retention_entry_names_the_start() {
        let dir = tempdir().unwrap();
        let key = key();
        let mut log = logged(dir.path(), &key, 6);
        log.set_retention(RetentionPolicy {
            max_entries: Some(5),
            max_age_days: None,
        });
        assert_eq!(log.apply_retention(&key).unwrap(), 2);
        log.log(sign(7), &key).unwrap();
        log.log(sign(8), &key).unwrap();
        assert_eq!(log.apply_retention(&key).unwrap(), 3);
        let kept = log.read_all(&key).unwrap();
        let marks: Vec<_> = kept.iter().filter_map(|e| e.retention).collect();
        assert_eq!(marks.len(), 2);
        assert_eq!(marks[0].first_seq, 3);
        assert_eq!(marks[1].first_seq, kept[0].seq);
        assert!(log.verify_chain(&key).unwrap());
    }

    fn tampered_format1_log(dir: &Path, key: &SecretKey, n: u8) {
        write_format1_log(dir, key, (0..n).map(sign).collect());
        let path = dir.join("audit.log");
        let mut entries = AuditLog::read_entries(&path, key, usize::MAX).unwrap();
        entries[1].reason = Some("edited".into());
        let lines: String = entries.iter().map(|e| format1_line(e, key)).collect();
        std::fs::write(&path, lines).unwrap();
    }

    /// Retention that removes the migration entry carries its record
    /// forward, so a failed migration is still reported and still warned
    /// about while the old log is kept.
    #[test]
    fn retention_keeps_a_failed_migration_reported() {
        let dir = tempdir().unwrap();
        let key = key();
        tampered_format1_log(dir.path(), &key, 3);
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        let failed = log.verify(&key).unwrap().migration.unwrap();
        assert!(!failed.old_chain_valid);
        for i in 0..5 {
            log.log(sign(i), &key).unwrap();
        }
        log.set_retention(RetentionPolicy {
            max_entries: Some(3),
            max_age_days: None,
        });
        log.apply_retention(&key).unwrap();
        // A second run keeps carrying it.
        log.log(sign(9), &key).unwrap();
        log.log(sign(9), &key).unwrap();
        log.apply_retention(&key).unwrap();
        let entries = log.read_all(&key).unwrap();
        assert!(entries
            .iter()
            .all(|e| e.event_type != AuditEventType::AuditLogMigrated));
        let report = log.verify(&key).unwrap();
        assert!(report.valid);
        assert_eq!(report.migration, Some(failed));
        assert!(!report.holds_untrusted_entries());
        assert!(AuditLog::open(dir.path(), &key)
            .unwrap()
            .failed_migration_kept());
    }

    /// The report says whether entries from before a failed migration are
    /// still in the log.
    #[test]
    fn untrusted_entries_are_reported_until_removed() {
        let dir = tempdir().unwrap();
        let key = key();
        tampered_format1_log(dir.path(), &key, 3);
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        assert!(log.verify(&key).unwrap().holds_untrusted_entries());
        log.set_retention(RetentionPolicy {
            max_entries: Some(3),
            max_age_days: None,
        });
        log.apply_retention(&key).unwrap();
        // The first kept entry is the third old one.
        assert!(log.verify(&key).unwrap().holds_untrusted_entries());
        log.set_retention(RetentionPolicy {
            max_entries: Some(2),
            max_age_days: None,
        });
        log.apply_retention(&key).unwrap();
        assert!(!log.verify(&key).unwrap().holds_untrusted_entries());
    }

    /// A first line that is not even text does not stop an old log from
    /// opening.
    #[test]
    fn non_text_lines_never_stop_an_old_log_opening() {
        let dir = tempdir().unwrap();
        let key = key();
        write_format1_log(dir.path(), &key, vec![sign(1), sign(2)]);
        let path = dir.path().join("audit.log");
        let mut bytes = b"\xff\xfe not text\n".to_vec();
        bytes.extend(std::fs::read(&path).unwrap());
        bytes.extend_from_slice(b"\xff\n");
        std::fs::write(&path, bytes).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert!(log.failed_migration_kept());
        assert_eq!(
            log.verify(&key).unwrap().migration.map(|m| m.old_count),
            Some(2)
        );
    }

    /// A migrated log whose first and last lines cannot be read keeps
    /// nothing before the damage, so it starts again from a record of the
    /// failure, with the whole old log kept beside it; the sequence going
    /// back is what an outside record of it is there to notice.
    #[test]
    fn a_migrated_log_damaged_at_its_start_is_set_aside() {
        let dir = tempdir().unwrap();
        let key = key();
        logged(dir.path(), &key, 4);
        let path = dir.path().join("audit.log");
        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        lines[0] = "bm90IGFuIGVudHJ5".into();
        lines[3] = "bm90IGFuIGVudHJ5".into();
        let text = lines.join("\n") + "\n";
        std::fs::write(&path, &text).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert!(log.failed_migration_kept());
        assert_eq!(log.seq(), 1);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(MIGRATED_LOG)).unwrap(),
            text
        );
    }

    /// A log whose first migration failed, which an older keep then
    /// appended to, is migrated again: the second migration checks out, but
    /// the earlier failure stays the one reported, so it is never cleared.
    #[test]
    fn a_failed_migration_stays_reported_when_migrated_again() {
        let dir = tempdir().unwrap();
        let key = key();
        tampered_format1_log(dir.path(), &key, 3);
        let log = AuditLog::open(dir.path(), &key).unwrap();
        let first = log.verify(&key).unwrap().migration.unwrap();
        // An older keep appends a format 1 entry chained onto the new head.
        let mut old = sign(5);
        old.format = 1;
        old.prev_hash = log.last_hash();
        old.hash = old.compute_hash();
        let mut text = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        text.push_str(&format1_line(&old, &key));
        std::fs::write(dir.path().join("audit.log"), text).unwrap();

        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert!(log.failed_migration_kept());
        let report = log.verify(&key).unwrap();
        assert!(report.valid);
        assert_eq!(report.migration, Some(first));
        assert!(report.holds_untrusted_entries());
        let entries = log.read_all(&key).unwrap();
        assert!(entries.last().unwrap().migration.unwrap().old_chain_valid);
        assert!(dir.path().join(format!("{MIGRATED_LOG}.2")).exists());

        // Once retention has removed the untrusted entries, an older keep's
        // append migrates again without marking the trusted entries since.
        let mut log = log;
        log.set_retention(RetentionPolicy {
            max_entries: Some(2),
            max_age_days: None,
        });
        log.apply_retention(&key).unwrap();
        assert!(log.verify_chain(&key).unwrap());
        let mut old = sign(6);
        old.format = 1;
        old.prev_hash = log.last_hash();
        old.hash = old.compute_hash();
        let mut text = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        text.push_str(&format1_line(&old, &key));
        std::fs::write(dir.path().join("audit.log"), text).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        let report = log.verify(&key).unwrap();
        assert!(log.verify_chain(&key).unwrap());
        assert_eq!(report.migration, Some(first));
    }

    /// A kept old log is never overwritten, whatever names are free.
    #[test]
    fn kept_old_logs_are_never_overwritten() {
        let dir = tempdir().unwrap();
        let key = key();
        std::fs::write(dir.path().join(format!("{MIGRATED_LOG}.2")), b"earlier").unwrap();
        std::fs::write(dir.path().join(format!("{MIGRATED_LOG}.tmp")), b"stale").unwrap();
        write_format1_log(dir.path(), &key, vec![sign(1)]);
        let old = std::fs::read(dir.path().join("audit.log")).unwrap();
        AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!(std::fs::read(dir.path().join(MIGRATED_LOG)).unwrap(), old);
        assert_eq!(
            std::fs::read(dir.path().join(format!("{MIGRATED_LOG}.2"))).unwrap(),
            b"earlier"
        );
        assert!(!dir.path().join(format!("{MIGRATED_LOG}.tmp")).exists());

        std::fs::remove_file(dir.path().join(MIGRATED_LOG)).unwrap();
        write_format1_log(dir.path(), &key, vec![sign(2)]);
        let again = std::fs::read(dir.path().join("audit.log")).unwrap();
        AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!(std::fs::read(dir.path().join(MIGRATED_LOG)).unwrap(), again);
        assert_eq!(
            std::fs::read(dir.path().join(format!("{MIGRATED_LOG}.2"))).unwrap(),
            b"earlier"
        );
    }

    /// Files the log writes are 0600 even when a stale file with looser
    /// permissions was left under the same temporary name.
    #[cfg(unix)]
    #[test]
    fn written_files_are_private_despite_stale_temporaries() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let key = key();
        for stale in ["audit.log.tmp", "audit.log.v1.tmp"] {
            let path = dir.path().join(stale);
            std::fs::write(&path, b"stale").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        tampered_format1_log(dir.path(), &key, 3);
        std::fs::set_permissions(
            dir.path().join("audit.log"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        let new_key = super::super::crypto::SecretKey::generate().unwrap();
        std::fs::write(dir.path().join("audit.log.v1.tmp"), b"stale").unwrap();
        std::fs::set_permissions(
            dir.path().join("audit.log.v1.tmp"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        log.reencrypt_kept_logs(&key, &new_key).unwrap();
        log.reencrypt(&key, &new_key).unwrap();
        for name in ["audit.log", MIGRATED_LOG, FAILED_MIGRATION_MARKER] {
            let mode = std::fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
    }

    /// The event types only the log writes are refused through `log`, but a
    /// restore keeps them and their records.
    #[test]
    fn only_the_log_writes_its_own_event_types() {
        let dir = tempdir().unwrap();
        let key = key();
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        for event in [
            AuditEventType::AuditLogMigrated,
            AuditEventType::AuditRetention,
        ] {
            assert!(log.log(AuditEntry::new(event, [0; 32]), &key).is_err());
        }
        assert_eq!(log.seq(), 0);
        let mut note = AuditEntry::new(AuditEventType::AuditLogMigrated, [0; 32]);
        let failed = AuditMigration {
            old_head: [3; 32],
            old_count: 3,
            old_chain_valid: false,
            seq: 9,
        };
        note.migration = Some(failed);
        note.seq = 1;
        note.hash = note.compute_hash();
        log.restore_entries(&[note], &key).unwrap();
        let report = log.verify(&key).unwrap();
        assert!(report.valid);
        // The record moves to where its entry now is.
        assert_eq!(report.migration, Some(AuditMigration { seq: 1, ..failed }));
    }

    /// A crash an older release left between its two renames (only the
    /// backup left) is recovered on open.
    #[test]
    fn a_log_left_only_as_its_backup_is_recovered() {
        let dir = tempdir().unwrap();
        let key = key();
        let head = logged(dir.path(), &key, 3).last_hash();
        std::fs::rename(
            dir.path().join("audit.log"),
            dir.path().join("audit.log.bak"),
        )
        .unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!((log.seq(), log.last_hash()), (3, head));
        assert!(!dir.path().join("audit.log.bak").exists());
    }

    /// A log holding entries in the current format, then format 1 entries,
    /// then a line that cannot be read, keeps all of them before the damage
    /// and records the failure.
    #[test]
    fn a_log_with_current_entries_and_a_bad_end_opens() {
        let dir = tempdir().unwrap();
        let key = key();
        let log = logged(dir.path(), &key, 3);
        let mut old = sign(8);
        old.format = 1;
        old.prev_hash = log.last_hash();
        old.hash = old.compute_hash();
        let mut text = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        text.push_str(&format1_line(&old, &key));
        text.push_str("bm90IGFuIGVudHJ5\n");
        std::fs::write(dir.path().join("audit.log"), text).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert!(log.failed_migration_kept());
        assert_eq!(log.seq(), 5);
        let m = log.verify(&key).unwrap().migration.unwrap();
        assert_eq!((m.old_count, m.old_chain_valid), (4, false));
    }

    /// A log holding current-format entries that is damaged before its end
    /// keeps only the entries before the damage, unchanged, so no sequence
    /// number already seen is renumbered; the rest stays in the kept copy.
    #[test]
    fn a_damaged_log_with_current_entries_keeps_what_precedes_the_damage() {
        let dir = tempdir().unwrap();
        let key = key();
        let log = logged(dir.path(), &key, 4);
        let mut old = sign(8);
        old.format = 1;
        old.prev_hash = log.last_hash();
        old.hash = old.compute_hash();
        let path = dir.path().join("audit.log");
        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        lines[1] = "bm90IGFuIGVudHJ5".into();
        let first = AuditLog::read_entries(&path, &key, usize::MAX).unwrap();
        let mut text = lines.join("\n") + "\n";
        text.push_str(&format1_line(&old, &key));
        std::fs::write(&path, &text).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert!(log.failed_migration_kept());
        let entries = log.read_all(&key).unwrap();
        assert_eq!(
            (entries[0].seq, entries[0].hash),
            (first[0].seq, first[0].hash)
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].event_type, AuditEventType::AuditLogMigrated);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(MIGRATED_LOG)).unwrap(),
            text
        );
    }

    /// A backup whose log starts at a failed migration entry (retention cut
    /// exactly the untrusted entries) restores into a log that already has
    /// entries of its own without claiming to hold untrusted ones; a backup
    /// that still holds them restores claiming so.
    #[test]
    fn restore_keeps_the_untrusted_answer() {
        let source_dir = tempdir().unwrap();
        let key = key();
        tampered_format1_log(source_dir.path(), &key, 3);
        let mut source = AuditLog::open(source_dir.path(), &key).unwrap();
        source.log(sign(7), &key).unwrap();
        let all = source.read_all(&key).unwrap();
        let at = all.iter().position(|e| e.migration.is_some()).unwrap();
        source.set_retention(RetentionPolicy {
            max_entries: Some(all.len() - at + 1),
            max_age_days: None,
        });
        assert_eq!(source.apply_retention(&key).unwrap(), at);
        let pruned = source.read_all(&key).unwrap();
        assert_eq!(pruned[0].seq, all[at].seq);

        for (entries, untrusted) in [(&all[..], true), (&pruned[..], false)] {
            assert_eq!(verify_entries(entries).holds_untrusted_entries(), untrusted);
            let dir = tempdir().unwrap();
            let mut log = logged(dir.path(), &key, 2);
            log.restore_entries(entries, &key).unwrap();
            let report = log.verify(&key).unwrap();
            assert!(report.valid);
            assert_eq!(report.holds_untrusted_entries(), untrusted);
            assert_eq!(report.migration.map(|m| m.old_chain_valid), Some(false));
        }
    }

    /// A log nothing in can be read under the current key (one a crash or
    /// an older keep's data key change left under a key that no longer
    /// exists) never locks the vault: it is kept beside a new log that
    /// starts with a record of the failure, in either format.
    #[test]
    fn an_unreadable_log_is_set_aside_with_the_failure_recorded() {
        let old_key = key();
        let new_key = key();
        for format1 in [true, false] {
            let dir = tempdir().unwrap();
            if format1 {
                write_format1_log(dir.path(), &old_key, vec![sign(1), sign(2)]);
            } else {
                logged(dir.path(), &old_key, 3);
            }
            let old = std::fs::read(dir.path().join("audit.log")).unwrap();
            let log = AuditLog::open(dir.path(), &new_key).unwrap();
            assert!(log.failed_migration_kept());
            assert_eq!(log.seq(), 1);
            assert_eq!(std::fs::read(dir.path().join(MIGRATED_LOG)).unwrap(), old);
            let report = log.verify(&new_key).unwrap();
            assert!(report.valid);
            let m = report.migration.unwrap();
            assert_eq!(
                (m.old_count, m.old_chain_valid, m.old_head),
                (0, false, [0; 32])
            );
        }
    }

    /// Without hard links the old log is copied straight into a new name,
    /// which still never replaces a kept file.
    #[test]
    fn migration_works_without_hard_links() {
        test_support::NO_HARD_LINKS.with(|c| c.set(true));
        let dir = tempdir().unwrap();
        let key = key();
        std::fs::write(dir.path().join(MIGRATED_LOG), b"earlier").unwrap();
        write_format1_log(dir.path(), &key, vec![sign(1), sign(2)]);
        let old = std::fs::read(dir.path().join("audit.log")).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        test_support::NO_HARD_LINKS.with(|c| c.set(false));
        assert_eq!(log.seq(), 3);
        assert_eq!(
            std::fs::read(dir.path().join(MIGRATED_LOG)).unwrap(),
            b"earlier"
        );
        assert_eq!(
            std::fs::read(dir.path().join(format!("{MIGRATED_LOG}.2"))).unwrap(),
            old
        );
        assert!(!dir.path().join(format!("{MIGRATED_LOG}.tmp")).exists());
    }

    /// When an older keep appended to a migrated, pruned log, the entries
    /// already in the current format keep their hashes and sequence numbers
    /// and the rest continue from them, so the sequence never goes back. An
    /// intact chain migrates again without a false alarm.
    #[test]
    fn migrating_again_never_sends_the_sequence_back() {
        let dir = tempdir().unwrap();
        let key = key();
        let mut log = logged(dir.path(), &key, 6);
        log.set_retention(RetentionPolicy {
            max_entries: Some(3),
            max_age_days: None,
        });
        log.apply_retention(&key).unwrap();
        let before = log.read_all(&key).unwrap();
        let (head, seq) = (log.last_hash(), log.seq());
        let mut old = sign(8);
        old.format = 1;
        old.prev_hash = head;
        old.hash = old.compute_hash();
        let mut text = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        text.push_str(&format1_line(&old, &key));
        std::fs::write(dir.path().join("audit.log"), text).unwrap();

        let log = AuditLog::open(dir.path(), &key).unwrap();
        let after = log.read_all(&key).unwrap();
        let ids = |v: &[AuditEntry]| v.iter().map(|e| (e.seq, e.hash)).collect::<Vec<_>>();
        assert_eq!(ids(&after[..before.len()]), ids(&before));
        assert_eq!(after[before.len()].seq, seq + 1);
        assert_eq!(log.seq(), seq + 2);
        assert!(log.verify_chain(&key).unwrap());
        assert!(log.verify(&key).unwrap().migration.unwrap().old_chain_valid);
        assert!(!log.failed_migration_kept());
        assert!(!dir.path().join(FAILED_MIGRATION_MARKER).exists());

        // The same append onto a broken chain is not taken as intact.
        let dir = tempdir().unwrap();
        let log = logged(dir.path(), &key, 4);
        let mut old = sign(8);
        old.format = 1;
        old.prev_hash = [7; 32];
        old.hash = old.compute_hash();
        let mut text = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        text.push_str(&format1_line(&old, &key));
        std::fs::write(dir.path().join("audit.log"), text).unwrap();
        drop(log);
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert!(log.failed_migration_kept());
        assert!(!log.verify_chain(&key).unwrap());

        // So is an intact append onto current-format entries that were
        // spliced before it.
        let dir = tempdir().unwrap();
        let log = logged(dir.path(), &key, 4);
        let mut old = sign(8);
        old.format = 1;
        old.prev_hash = log.last_hash();
        old.hash = old.compute_hash();
        drop(log);
        let path = dir.path().join("audit.log");
        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        lines.remove(1);
        let mut text = lines.join("\n") + "\n";
        text.push_str(&format1_line(&old, &key));
        std::fs::write(&path, text).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert!(log.failed_migration_kept());
        assert!(!log.verify(&key).unwrap().migration.unwrap().old_chain_valid);
    }

    /// A rewrite an older release left between its two renames is finished
    /// from the new file when it is complete under the current key, from the
    /// backup otherwise.
    #[test]
    fn an_interrupted_rewrite_prefers_the_complete_new_file() {
        let dir = tempdir().unwrap();
        let key = key();
        let mut log = logged(dir.path(), &key, 2);
        let old_bytes = std::fs::read(dir.path().join("audit.log")).unwrap();
        log.log(sign(3), &key).unwrap();
        let head = log.last_hash();
        std::fs::rename(
            dir.path().join("audit.log"),
            dir.path().join("audit.log.tmp"),
        )
        .unwrap();
        std::fs::write(dir.path().join("audit.log.bak"), &old_bytes).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!((log.seq(), log.last_hash()), (3, head));

        // A new file under another key loses to the backup.
        let dir = tempdir().unwrap();
        let head = logged(dir.path(), &key, 2).last_hash();
        std::fs::rename(
            dir.path().join("audit.log"),
            dir.path().join("audit.log.bak"),
        )
        .unwrap();
        let other = super::super::crypto::SecretKey::generate().unwrap();
        let tmp_dir = tempdir().unwrap();
        logged(tmp_dir.path(), &other, 4);
        std::fs::copy(
            tmp_dir.path().join("audit.log"),
            dir.path().join("audit.log.tmp"),
        )
        .unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!((log.seq(), log.last_hash()), (2, head));
    }

    /// Without the backup a crash in an older release would have left, a
    /// stale temporary file is never promoted to the log.
    #[test]
    fn a_stale_temp_alone_is_never_promoted() {
        let dir = tempdir().unwrap();
        let key = key();
        logged(dir.path(), &key, 2);
        std::fs::rename(
            dir.path().join("audit.log"),
            dir.path().join("audit.log.tmp"),
        )
        .unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!(log.seq(), 0);
        assert!(dir.path().join("audit.log.tmp").exists());
    }

    /// One kept log that cannot be re-encrypted does not stop the others.
    #[cfg(unix)]
    #[test]
    fn every_kept_log_is_tried() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let key = key();
        write_format1_log(dir.path(), &key, vec![sign(1)]);
        let log = AuditLog::open(dir.path(), &key).unwrap();
        let unreadable = dir.path().join(format!("{MIGRATED_LOG}.2"));
        std::fs::write(&unreadable, b"x\n").unwrap();
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
        if File::open(&unreadable).is_ok() {
            return; // Running as root, which reads any file.
        }
        std::fs::copy(
            dir.path().join(MIGRATED_LOG),
            dir.path().join(format!("{MIGRATED_LOG}.3")),
        )
        .unwrap();
        let new_key = super::super::crypto::SecretKey::generate().unwrap();
        assert!(log.reencrypt_kept_logs(&key, &new_key).is_err());
        for name in [MIGRATED_LOG.to_string(), format!("{MIGRATED_LOG}.3")] {
            let text = std::fs::read_to_string(dir.path().join(name)).unwrap();
            assert!(AuditLog::decrypt_raw(text.trim_end(), &new_key).is_ok());
        }
    }

    /// The warning follows the kept file the failed migration named, not
    /// any kept file.
    #[test]
    fn the_warning_follows_the_file_the_failed_migration_kept() {
        let dir = tempdir().unwrap();
        let key = key();
        std::fs::write(
            dir.path().join(MIGRATED_LOG),
            b"from a migration that passed",
        )
        .unwrap();
        tampered_format1_log(dir.path(), &key, 3);
        assert!(AuditLog::open(dir.path(), &key)
            .unwrap()
            .failed_migration_kept());
        assert_eq!(
            std::fs::read_to_string(dir.path().join(FAILED_MIGRATION_MARKER)).unwrap(),
            format!("{MIGRATED_LOG}.2")
        );
        std::fs::remove_file(dir.path().join(format!("{MIGRATED_LOG}.2"))).unwrap();
        assert!(!AuditLog::open(dir.path(), &key)
            .unwrap()
            .failed_migration_kept());
    }

    /// The migration's check of the old chain catches each kind of fault:
    /// a broken link, a wrong hash and an entry missing from the middle.
    #[test]
    fn the_old_chain_check_catches_each_fault() {
        let cases: [fn(&mut Vec<AuditEntry>); 3] = [
            |v| v[1].prev_hash = [9; 32],
            |v| v[1].hash = [9; 32],
            |v| {
                v.remove(1);
            },
        ];
        for break_it in cases {
            let dir = tempdir().unwrap();
            let key = key();
            write_format1_log(dir.path(), &key, vec![sign(1), sign(2), sign(3)]);
            let path = dir.path().join("audit.log");
            let mut entries = AuditLog::read_entries(&path, &key, usize::MAX).unwrap();
            break_it(&mut entries);
            let lines: String = entries.iter().map(|e| format1_line(e, &key)).collect();
            std::fs::write(&path, lines).unwrap();
            let log = AuditLog::open(dir.path(), &key).unwrap();
            assert!(log.failed_migration_kept());
        }
    }

    /// Retention never prunes a chain that fails its check, so a cut or
    /// splice in the range it would remove stays visible.
    #[test]
    fn retention_refuses_a_broken_chain() {
        let dir = tempdir().unwrap();
        let key = key();
        let mut log = logged(dir.path(), &key, 6);
        let path = dir.path().join("audit.log");
        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        lines.remove(3);
        let text = lines.join("\n") + "\n";
        std::fs::write(&path, &text).unwrap();
        assert!(!log.verify_chain(&key).unwrap());
        log.set_retention(RetentionPolicy {
            max_entries: Some(3),
            max_age_days: None,
        });
        assert!(log.apply_retention(&key).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        assert!(!log.verify_chain(&key).unwrap());
    }

    /// Pruning tells its caller where the log will end before replacing it,
    /// and leaves the log as it was when the caller fails.
    #[test]
    fn retention_reports_the_new_end_before_rewriting() {
        let dir = tempdir().unwrap();
        let key = key();
        let mut log = logged(dir.path(), &key, 4);
        log.set_retention(RetentionPolicy {
            max_entries: Some(2),
            max_age_days: None,
        });
        let path = dir.path().join("audit.log");
        let before = std::fs::read(&path).unwrap();
        assert!(log
            .apply_retention_noting(&key, None, |_, _| Err(KeepError::Other("no".into())))
            .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let mut told = None;
        log.apply_retention_noting(&key, None, |seq, hash| {
            told = Some((seq, hash));
            Ok(())
        })
        .unwrap();
        assert_eq!(told, Some((log.seq(), log.last_hash())));
    }

    /// A log whose newest entry is in a format newer than this keep writes
    /// is set aside byte for byte rather than refusing to open or having
    /// older entries appended after it.
    #[test]
    fn a_log_from_a_newer_keep_is_set_aside() {
        let dir = tempdir().unwrap();
        let key = key();
        let log = logged(dir.path(), &key, 2);
        let mut next = sign(9);
        next.format = AUDIT_FORMAT + 1;
        next.seq = 3;
        next.prev_hash = log.last_hash();
        next.hash = next.compute_hash();
        let path = dir.path().join("audit.log");
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str(&AuditLog::encrypt_line(&next, &key).unwrap());
        std::fs::write(&path, &text).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join(MIGRATED_LOG)).unwrap(),
            text
        );
        assert!(!log.migrated_on_open().unwrap().chain_valid);
        let entries = log.read_all(&key).unwrap();
        assert!(entries.iter().all(|e| e.format == AUDIT_FORMAT));
        assert!(verify_entries(&entries).valid);
    }

    /// The marker, the kept logs and an interrupted rewrite's files are used
    /// only when they are regular files, never through a symlink.
    #[cfg(unix)]
    #[test]
    fn symlinks_beside_the_log_are_never_followed() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let key = key();
        tampered_format1_log(dir.path(), &key, 3);
        assert!(AuditLog::open(dir.path(), &key)
            .unwrap()
            .failed_migration_kept());
        let marker = dir.path().join(FAILED_MIGRATION_MARKER);
        let name = std::fs::read(&marker).unwrap();
        let elsewhere = tempdir().unwrap();
        let target = elsewhere.path().join("marker");
        std::fs::write(&target, &name).unwrap();
        std::fs::remove_file(&marker).unwrap();
        symlink(&target, &marker).unwrap();
        assert!(!AuditLog::open(dir.path(), &key)
            .unwrap()
            .failed_migration_kept());

        let outside = elsewhere.path().join("outside");
        std::fs::write(&outside, b"not a kept log\n").unwrap();
        symlink(&outside, dir.path().join(format!("{MIGRATED_LOG}.9"))).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert!(!log
            .migrated_paths()
            .iter()
            .any(|p| p.ends_with(format!("{MIGRATED_LOG}.9"))));
        log.reencrypt_kept_logs(&key, &SecretKey::generate().unwrap())
            .unwrap();
        assert_eq!(std::fs::read(&outside).unwrap(), b"not a kept log\n");

        // An interrupted rewrite's backup or new file behind a symlink is
        // left alone, and the file it points at is never cut.
        let dir = tempdir().unwrap();
        let victim = elsewhere.path().join("victim");
        std::fs::write(&victim, b"line\npartial").unwrap();
        symlink(&victim, dir.path().join("audit.log.bak")).unwrap();
        symlink(&victim, dir.path().join("audit.log.tmp")).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!(log.seq(), 0);
        assert_eq!(std::fs::read(&victim).unwrap(), b"line\npartial");

        let dir = tempdir().unwrap();
        let head = logged(dir.path(), &key, 2).last_hash();
        std::fs::rename(
            dir.path().join("audit.log"),
            dir.path().join("audit.log.bak"),
        )
        .unwrap();
        symlink(&victim, dir.path().join("audit.log.tmp")).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert_eq!((log.seq(), log.last_hash()), (2, head));
        assert_eq!(std::fs::read(&victim).unwrap(), b"line\npartial");
    }

    /// Without hard links, a copy into a kept log's name that fails is
    /// removed, so a retry never piles up partial copies.
    #[test]
    fn a_failed_fallback_copy_is_removed() {
        let dir = tempdir().unwrap();
        let key = key();
        write_format1_log(dir.path(), &key, vec![sign(1)]);
        test_support::NO_HARD_LINKS.with(|c| c.set(true));
        test_support::FAIL_COPY.with(|c| c.set(true));
        let opened = AuditLog::open(dir.path(), &key);
        test_support::NO_HARD_LINKS.with(|c| c.set(false));
        test_support::FAIL_COPY.with(|c| c.set(false));
        assert!(opened.is_err());
        assert!(!dir.path().join(MIGRATED_LOG).exists());
        assert!(AuditLog::open(dir.path(), &key).is_ok());
        assert!(dir.path().join(MIGRATED_LOG).exists());
    }

    /// A current-format entry after an old-format one cannot come from any
    /// keep, so a re-migration that finds one fails its check.
    #[test]
    fn interleaved_formats_fail_the_check() {
        let dir = tempdir().unwrap();
        let key = key();
        let log = logged(dir.path(), &key, 2);
        let mut old = sign(5);
        old.format = 1;
        old.prev_hash = log.last_hash();
        old.hash = old.compute_hash();
        let mut new = sign(6);
        new.seq = 3;
        new.prev_hash = old.hash;
        new.hash = new.compute_hash();
        let mut last = sign(7);
        last.format = 1;
        last.prev_hash = new.hash;
        last.hash = last.compute_hash();
        drop(log);
        let path = dir.path().join("audit.log");
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str(&format1_line(&old, &key));
        text.push_str(&AuditLog::encrypt_line(&new, &key).unwrap());
        text.push_str(&format1_line(&last, &key));
        std::fs::write(&path, text).unwrap();
        let log = AuditLog::open(dir.path(), &key).unwrap();
        assert!(log.failed_migration_kept());
        assert!(!log.verify(&key).unwrap().migration.unwrap().old_chain_valid);
    }

    /// A backup whose entries fail their chain check restores with a record
    /// of the failure after them, in either format, so restoring cannot turn
    /// a broken chain into one that verifies; an intact one restores clean.
    #[test]
    fn restoring_a_broken_chain_records_it() {
        let key = key();
        let src = tempdir().unwrap();
        let good = logged(src.path(), &key, 4).read_all(&key).unwrap();
        let mut spliced = good.clone();
        spliced.remove(2);
        let format1: Vec<AuditEntry> = {
            let dir = tempdir().unwrap();
            write_format1_log(dir.path(), &key, (0..4).map(sign).collect());
            AuditLog::read_entries(&dir.path().join("audit.log"), &key, usize::MAX).unwrap()
        };
        let mut format1_spliced = format1.clone();
        format1_spliced.remove(1);

        for (entries, intact) in [
            (&good, true),
            (&spliced, false),
            (&format1, true),
            (&format1_spliced, false),
        ] {
            let dir = tempdir().unwrap();
            let mut log = AuditLog::open(dir.path(), &key).unwrap();
            log.restore_entries(entries, &key).unwrap();
            let report = log.verify(&key).unwrap();
            assert!(report.valid);
            assert_eq!(log.verify_chain(&key).unwrap(), intact);
            assert_eq!(report.holds_untrusted_entries(), !intact);
            if !intact {
                let m = report.migration.unwrap();
                assert_eq!(m.old_count, entries.len() as u64);
                assert_eq!(m.old_head, entries.last().unwrap().hash);
                assert_eq!(m.seq, log.seq());
            }
        }
    }

    /// A signing audit log that cannot be read under the vault's key is kept
    /// beside a new one rather than locking the vault.
    #[test]
    fn an_unreadable_signing_log_is_set_aside() {
        let dir = tempdir().unwrap();
        let old_key = key();
        let mut log = SigningAuditLog::open(dir.path(), &old_key).unwrap();
        log.log(
            SigningAuditEntry::new(
                SigningRequestType::SignEvent,
                SigningDecision::Approved,
                false,
                "caller".into(),
                log.last_hash(),
            )
            .finalize(),
            &old_key,
        )
        .unwrap();
        let path = dir.path().join("signing_audit.log");
        let old = std::fs::read(&path).unwrap();
        let new_key = key();
        let log = SigningAuditLog::open(dir.path(), &new_key).unwrap();
        assert_eq!(log.last_hash(), [0; 32]);
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(dir.path().join(UNREADABLE_SIGNING_LOG)).unwrap(),
            old
        );
    }

    /// Encrypt `json` as one log line under `key`, as a keep that knows more
    /// entry types than this one would write it.
    fn foreign_line(json: &str, key: &SecretKey) -> String {
        let encrypted = crypto::encrypt(json.as_bytes(), key).unwrap();
        format!("{}\n", STANDARD.encode(encrypted.to_bytes()))
    }

    /// A line that decrypts but does not parse (an entry type a newer keep
    /// added, a line copied in from the signing log) or that is in a newer
    /// format never stops the log opening: the log is set aside byte for
    /// byte, the readable entries before the line carry on with the failure
    /// recorded, and nothing after it is renumbered.
    #[test]
    fn an_entry_this_keep_cannot_read_sets_the_log_aside_rather_than_refusing() {
        let key = key();
        let entry = serde_json::to_value(sign(9)).unwrap();
        let mut newer = entry.clone();
        newer["event_type"] = "SomethingNewer".into();
        let mut format3 = serde_json::to_value({
            let mut e = sign(9);
            e.format = 3;
            e
        })
        .unwrap();
        format3["seq"] = 3.into();
        let signing = foreign_line(
            &serde_json::to_string(
                &SigningAuditEntry::new(
                    SigningRequestType::SignEvent,
                    SigningDecision::Approved,
                    false,
                    "caller".into(),
                    [0; 32],
                )
                .finalize(),
            )
            .unwrap(),
            &key,
        );
        for line in [
            foreign_line(&newer.to_string(), &key),
            foreign_line(&format3.to_string(), &key),
            signing,
        ] {
            for format1 in [true, false] {
                let dir = tempdir().unwrap();
                if format1 {
                    write_format1_log(dir.path(), &key, vec![sign(1), sign(2)]);
                } else {
                    logged(dir.path(), &key, 2);
                }
                let path = dir.path().join("audit.log");
                let mut text = std::fs::read_to_string(&path).unwrap();
                if format1 {
                    text.insert_str(0, &line);
                } else {
                    text.push_str(&line);
                }
                std::fs::write(&path, &text).unwrap();
                let log = AuditLog::open(dir.path(), &key).unwrap();
                assert_eq!(
                    std::fs::read_to_string(dir.path().join(MIGRATED_LOG)).unwrap(),
                    text,
                    "kept byte for byte"
                );
                let migrated = log.migrated_on_open().unwrap();
                assert!(!migrated.chain_valid);
                assert!(!migrated.unreadable);
                assert!(log.failed_migration_kept());
                let entries = log.read_all(&key).unwrap();
                assert!(verify_entries(&entries).valid);
                // Both readable entries carry on; the migration follows.
                assert_eq!(entries.len(), 3);
                assert_eq!(log.seq(), 3);
            }
        }
    }

    /// A signing log whose last line a crash cut short drops that line and
    /// is not set aside; one ending in an entry this keep cannot parse is
    /// set aside byte for byte rather than refusing to open.
    #[test]
    fn the_signing_log_is_set_aside_for_a_last_line_it_cannot_read() {
        let dir = tempdir().unwrap();
        let key = key();
        let mut log = SigningAuditLog::open(dir.path(), &key).unwrap();
        log.log(
            SigningAuditEntry::new(
                SigningRequestType::SignEvent,
                SigningDecision::Approved,
                false,
                "caller".into(),
                log.last_hash(),
            )
            .finalize(),
            &key,
        )
        .unwrap();
        let head = log.last_hash();
        let path = dir.path().join("signing_audit.log");
        let whole = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("{whole}{}", &whole[..20])).unwrap();
        let log = SigningAuditLog::open(dir.path(), &key).unwrap();
        assert_eq!(log.last_hash(), head);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), whole);

        // Opening reads only the last line, so damage before it is left for
        // a full read to find.
        std::fs::write(&path, format!("bm90IGFuIGVudHJ5\n{whole}")).unwrap();
        assert_eq!(
            SigningAuditLog::open(dir.path(), &key).unwrap().last_hash(),
            head
        );
        assert!(!dir.path().join(UNREADABLE_SIGNING_LOG).exists());

        let newer = foreign_line(r#"{"unknown":"entry"}"#, &key);
        let text = format!("{whole}{newer}");
        std::fs::write(&path, &text).unwrap();
        let log = SigningAuditLog::open(dir.path(), &key).unwrap();
        assert_eq!(log.last_hash(), [0; 32]);
        assert_eq!(log.set_aside_on_open(), Some(UNREADABLE_SIGNING_LOG));
        assert!(log.kept_log_present(UNREADABLE_SIGNING_LOG));
        assert!(!path.exists());
        assert_eq!(
            std::fs::read_to_string(dir.path().join(UNREADABLE_SIGNING_LOG)).unwrap(),
            text
        );
    }
}
