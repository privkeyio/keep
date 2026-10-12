// SPDX-FileCopyrightText: (C) 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![deny(unsafe_code)]

//! Sovereign key management for Nostr and Bitcoin.
//!
//! This crate provides encrypted key storage with the following features:
//!
//! - **Encrypted storage** using Redb with XChaCha20-Poly1305
//! - **Key derivation** using Argon2id with configurable parameters
//! - **Nostr keypair management** with nsec/npub support
//! - **FROST threshold signatures** for distributed key management
//! - **Hidden volumes** for plausible deniability
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use keep_core::Keep;
//!
//! // Create a new Keep
//! let mut keep = Keep::create(Path::new("/tmp/my-keep"), "password")?;
//!
//! // Generate a new key
//! let pubkey = keep.generate_key("my-key")?;
//!
//! // Lock when done
//! keep.lock();
//! # Ok::<(), keep_core::error::KeepError>(())
//! ```

#![deny(missing_docs)]

/// Credentials for AI agents served by the agent gateway.
pub mod agent;
/// Tamper-evident audit logging with hash chain integrity.
pub mod audit;
pub mod audit_record;
/// Pluggable storage backends.
pub mod backend;
/// Portable encrypted vault backup and restore.
pub mod backup;
/// Cryptographic primitives for encryption, key derivation, and hashing.
pub mod crypto;
/// Shared text-level helpers for output descriptor strings.
pub mod descriptor;
/// Display formatting helpers for truncation and timestamps.
pub mod display;
/// Multi-source entropy mixing for defense-in-depth randomness.
pub mod entropy;
/// Error types and result aliases.
pub mod error;
/// FROST threshold signature implementation.
pub mod frost;
/// BIP-32 unhardened child-key primitives for FROST group keys (#487).
pub mod frost_bip32;
/// Hidden volume storage for plausible deniability.
pub mod hidden;
/// In-memory keyring for unlocked keys.
pub mod keyring;
/// Key types and Nostr keypair operations.
pub mod keys;
pub mod migration;

/// BIP-39 mnemonic generation and validation.
pub mod mnemonic;
/// NIP-06 key derivation from mnemonic seed phrase.
pub mod nip06;
/// Threshold-OPRF unlock primitive (frost-gate v2). Opt-in via the `oprf` feature.
#[cfg(feature = "oprf")]
pub mod oprf;
pub(crate) mod rate_limit;
/// Relay configuration for FROST shares.
pub mod relay;
mod rotation;
pub use rotation::fsync_dir;
/// Arbitrary-secret records (passwords, API tokens, notes) stored in the vault.
pub mod secret;
/// Persistent encrypted storage backend.
pub mod storage;
/// Ephemeral time-limited secret vault.
pub mod vault;
/// Wallet descriptor types for FROST group spending policies.
pub mod wallet;

use std::path::{Path, PathBuf};

use tracing::debug;
use zeroize::Zeroizing;

use crate::audit::{
    AuditEntry, AuditEventType, AuditLog, AuditVerification, RetentionPolicy, SigningAuditEntry,
    SigningAuditLog,
};
use crate::crypto::{Argon2Params, SecretKey};
use crate::error::{KeepError, Result};
use crate::frost::{ShareExport, SharePackage, StoredShare, ThresholdConfig, TrustedDealer};
use crate::keyring::Keyring;
use crate::keys::{KeyRecord, KeyType, NostrKeypair};
pub use crate::relay::{KfpV1PeerPolicyEntry, PeerPolicyEntry, RelayConfig, GLOBAL_RELAY_KEY};
pub use crate::storage::ProxyConfig;
use crate::storage::Storage;
pub use crate::storage::{ReplicatedApply, StatePublisher};
pub use crate::wallet::{DeviceRegistration, WalletDescriptor};

/// Vault secret-store name for a group's per-group DKG signing subkey (§3). The
/// reserved prefix namespaces these off the user's own secret entries so a
/// lookup by group name can never collide with a hand-created secret.
fn frost_group_subkey_name(group_name: &str) -> String {
    format!("frost-group-subkey:{group_name}")
}

/// Entries kept free for the owner's own events once agent signatures stop.
pub const AGENT_AUDIT_HEADROOM: usize = 10_000;

/// The most bytes of an owner event's reason the audit log keeps.
pub const MAX_OWNER_AUDIT_TEXT: usize = 1_024;

/// What an audit entry adds when the freeze epoch could not be read and a
/// new one was seeded.
fn seeded_note(moved: Option<storage::EpochMoved>) -> String {
    match moved {
        Some(moved) if moved.seeded => format!(
            "; the agent freeze epoch could not be read, so a new one was started at {}",
            moved.epoch
        ),
        _ => String::new(),
    }
}

/// The main Keep type for encrypted key management.
pub struct Keep {
    storage: Storage,
    keyring: Keyring,
    audit: Option<AuditLog>,
    signing_audit: Option<SigningAuditLog>,
    /// What `keep.db` holds about the audit log, read at unlock.
    audit_record: Option<audit_record::AuditRecord>,
}

impl Keep {
    /// Install the keep-state replication sink on the underlying storage (keep-web wires this to a
    /// publisher that ships each vault-state change to the state relay). See [`StatePublisher`].
    pub fn set_state_publisher(&self, publisher: std::sync::Arc<dyn StatePublisher>) {
        self.storage.set_state_publisher(publisher);
    }

    /// Apply a record replicated from a peer into storage (the standby consumer side). Delegates to
    /// [`Storage::apply_replicated_record`]; never echoes back to the relay.
    pub fn apply_replicated_record(
        &self,
        table: &str,
        record_id: &str,
        encrypted: &[u8],
        created_at: u64,
        now: u64,
    ) -> Result<ReplicatedApply> {
        self.storage
            .apply_replicated_record(table, record_id, encrypted, created_at, now)
    }

    /// Apply a replicated delete (tombstone) from a peer. `now` is local wall-clock, used to reject an
    /// implausibly future-dated event (see [`Storage::apply_replicated_delete`]).
    pub fn apply_replicated_delete(
        &self,
        table: &str,
        record_id: &str,
        created_at: u64,
        now: u64,
    ) -> Result<ReplicatedApply> {
        self.storage
            .apply_replicated_delete(table, record_id, created_at, now)
    }

    /// The persisted rollback high-water-mark for one replicated record's d-tag (`None` if never
    /// applied), for seeding the publisher's per-d-tag floor. See [`Storage::state_version`].
    pub fn state_version(&self, table: &str, record_id: &str) -> Result<Option<u64>> {
        self.storage.state_version(table, record_id)
    }

    /// Snapshot all replicable records for the keep-state publisher to replay at startup, so records
    /// written before the replication hook was installed still reach a fresh standby. See
    /// [`Storage::snapshot_replicable_records`].
    pub fn snapshot_replicable_records(&self) -> Result<Vec<(&'static str, String, Vec<u8>)>> {
        self.storage.snapshot_replicable_records()
    }

    /// Every undelivered delete-tombstone as `(table, record_id)`, for the
    /// keep-state publisher to seed as pending deletes at startup so a revoked
    /// record removed but never published still reaches standbys. See
    /// [`Storage::pending_tombstones`].
    pub fn pending_tombstones(&self) -> Result<Vec<(String, String)>> {
        self.storage.pending_tombstones()
    }

    /// Clear a delete-tombstone once its delete has been accepted by a relay.
    /// See [`Storage::clear_pending_tombstone`].
    pub fn clear_pending_tombstone(&self, table: &str, record_id: &str) -> Result<()> {
        self.storage.clear_pending_tombstone(table, record_id)
    }

    /// Create a new Keep with the given password.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use keep_core::Keep;
    ///
    /// let keep = Keep::create(Path::new("/tmp/my-keep"), "password")?;
    /// assert!(keep.is_unlocked());
    /// # Ok::<(), keep_core::error::KeepError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`KeepError::AlreadyExists`] if a Keep already exists at the path.
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        Self::create_with_params(path, password, Argon2Params::DEFAULT)
    }

    /// Create a new Keep with custom Argon2 parameters.
    pub fn create_with_params(path: &Path, password: &str, params: Argon2Params) -> Result<Self> {
        let storage = Storage::create(path, password, params)?;
        Self::started(storage)
    }

    /// Like [`Self::create_with_params`] but seeds a shared record-encryption key, so every node in a
    /// cluster shares one vault key (keep-state replication) and a standby decrypts what the active
    /// shipped. Each node still wraps the key under its own password+salt.
    pub fn create_with_shared_data_key(
        path: &Path,
        password: &str,
        params: Argon2Params,
        data_key: Zeroizing<[u8; crypto::KEY_SIZE]>,
    ) -> Result<Self> {
        let storage = Storage::create_with_shared_data_key(path, password, params, data_key)?;
        Self::started(storage)
    }

    /// A Keep for a vault just created: its audit record and agent freeze
    /// epoch start here, so either missing later means deleted.
    fn started(storage: Storage) -> Result<Self> {
        let mut keep = Self {
            storage,
            keyring: Keyring::new(),
            audit: None,
            signing_audit: None,
            audit_record: None,
        };
        keep.save_audit_record_with(audit_record::AuditRecord::default(), Some(0))?;
        keep.audit_record = None;
        Ok(keep)
    }

    /// Open an existing Keep.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use keep_core::Keep;
    ///
    /// let mut keep = Keep::open(Path::new("~/.keep"))?;
    /// keep.unlock("password")?;
    /// # Ok::<(), keep_core::error::KeepError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`KeepError::NotFound`] if no Keep exists at the path.
    pub fn open(path: &Path) -> Result<Self> {
        let storage = Storage::open(path)?;
        Ok(Self {
            storage,
            keyring: Keyring::new(),
            audit: None,
            signing_audit: None,
            audit_record: None,
        })
    }

    /// Unlock with the given password.
    ///
    /// # Errors
    ///
    /// Returns [`KeepError::InvalidPassword`] if the password is incorrect.
    /// Returns [`KeepError::RateLimited`] after too many failed attempts.
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        self.storage.unlock(password)?;

        let data_key = self.get_data_key()?;
        self.audit = Some(AuditLog::open(self.storage.path(), &data_key)?);
        self.signing_audit = Some(SigningAuditLog::open(self.storage.path(), &data_key)?);
        let reseeded = self.check_audit_record()?;

        // Flush any rate-limit trip events queued by prior failed unlocks
        // before recording this success, so the audit chain reflects the
        // chronological order: lock-out events first, then the successful
        // unlock that observed and cleared them. The drain consumes the trip
        // file before the audit writes, so emission is best-effort: a failed
        // audit write loses that event at-most-once with no retry.
        let trips = self.storage.drain_pending_trips();
        for trip in trips {
            let trip_ts = trip.audit_time();
            let reason = format!(
                "rate limit threshold reached after {} failed attempts",
                trip.failed_attempts
            );
            self.audit_event(AuditEventType::RateLimitTripped, |mut e| {
                e.timestamp = trip_ts;
                e.with_success(false).with_reason(&reason)
            });
        }

        let reason = match reseeded {
            Some(epoch) => format!(
                "{}; the agent freeze epoch was missing and was started again at {epoch}",
                audit_record::RECORD_NOTE
            ),
            None => audit_record::RECORD_NOTE.to_string(),
        };
        self.audit_event(AuditEventType::VaultUnlock, |e| e.with_reason(&reason));
        debug!("loading keys to keyring");
        self.load_keys_to_keyring()
    }

    /// Verify a password without changing the unlock state.
    pub fn verify_password(&self, password: &str) -> Result<()> {
        self.storage.verify_password(password)
    }

    /// Read-only pre-flight check of whether `password` is this vault's password,
    /// WITHOUT touching the rate limiter, audit log, keyring, or unlock state.
    /// `Ok(true)` = matches, `Ok(false)` = wrong password, `Err` = could not check.
    /// Unlike [`Self::verify_password`] it does not record a rate-limit attempt and
    /// is not blocked by an active backoff, so a pre-flight check cannot self-inflict
    /// a lockout nor be silently skipped. Because it does not rate-limit, use it only
    /// on local, operator-driven paths (e.g. the duress-provision anti-brick guard),
    /// never as a remote or automated unlock oracle.
    pub fn password_matches(&self, password: &str) -> Result<bool> {
        self.storage.password_matches(password)
    }

    /// Lock and clear all keys from memory.
    pub fn lock(&mut self) {
        self.audit_event(AuditEventType::VaultLock, |e| e);
        self.keyring.clear();
        self.audit = None;
        self.signing_audit = None;
        self.audit_record = None;
        self.storage.lock();
    }

    /// Compare the audit log just opened with what `keep.db` recorded, check
    /// its whole chain, note what the owner must be told, and record where
    /// the log is now. The vault opens whatever the record says: a record
    /// that is missing while the log or the vault shows one was kept, or
    /// that cannot be decrypted or parsed, is itself noted and started
    /// again, so detection resumes. Only a failure to read the database or
    /// the log fails the unlock.
    /// Returns the epoch started when the agent freeze epoch was found
    /// deleted.
    fn check_audit_record(&mut self) -> Result<Option<u64>> {
        let data_key = self.get_data_key()?;
        let (Some(audit), Some(signing)) = (self.audit.as_ref(), self.signing_audit.as_ref())
        else {
            return Ok(None);
        };
        let (seq, head) = (audit.seq(), audit.last_hash());
        let now = chrono::Utc::now().timestamp();
        let rotation = self.storage.rotation_in_progress();
        let migrated = audit.migrated_on_open().cloned();
        let mut first_open = false;
        self.storage.set_seed_floor(audit.own_time());
        let mut record = match self.load_audit_record()? {
            Some(Ok(record)) => record,
            Some(Err(e)) => {
                tracing::error!(error = %e, "the record of the audit log cannot be read; starting it again");
                audit_record::AuditRecord {
                    lost: Some(audit_record::RecordLost {
                        missing: false,
                        found_at: now,
                    }),
                    ..Default::default()
                }
            }
            None => {
                // A keep that keeps the record notes it in the log and writes
                // the freeze epoch at create and every unlock; and the log
                // records everything created. A record missing while the log
                // notes it, the epoch is there, or something was created
                // after the log's last entry, was deleted. Otherwise this is
                // the vault's first open by a keep that keeps the record (an
                // older release's or main's vault), which writes the first.
                let noted = audit.any_entry_noting(
                    &[AuditEventType::VaultUnlock, AuditEventType::AuditRetention],
                    audit_record::RECORD_NOTE,
                    &data_key,
                );
                // A migration on this open added its own entry; what counts
                // is the last entry the old log had.
                // Trip entries carry a time from a file anyone can forge,
                // so the last time keep set itself counts.
                let logged_until = match migrated.as_ref() {
                    Some(m) => m.old_last_timestamp,
                    None => audit.last_own_timestamp(&data_key)?,
                };
                let lost = noted
                    || self.storage.agent_freeze_epoch_row()?
                    || self.storage.latest_created_at()? > logged_until;
                first_open = !lost;
                audit_record::AuditRecord {
                    lost: lost.then_some(audit_record::RecordLost {
                        missing: true,
                        found_at: now,
                    }),
                    ..Default::default()
                }
            }
        };
        let mut quiet = false;
        match migrated.as_ref().filter(|m| !m.chain_valid) {
            Some(m) => {
                record.note_set_aside(audit_record::SetAside {
                    kept: m.kept.clone(),
                    unreadable: m.unreadable,
                    recorded_seq: record.seq,
                    recorded_head: record.head,
                    rotation: rotation && m.unreadable,
                });
                // A log nothing of which decrypts was set aside whole, which
                // the note above says plainly; it is not also a rollback.
                quiet = m.unreadable;
            }
            // A set-aside the record has not seen: one from before the
            // record, or one a crash kept from it. Noted and reported until
            // acknowledged; the marker is a file anyone with the vault folder
            // can write, so the log is still compared with the record.
            None => {
                if let Some(kept) = audit.failed_migration_marked() {
                    if !record.set_asides.iter().any(|s| s.kept == kept) {
                        record.note_set_aside(audit_record::SetAside {
                            kept,
                            unreadable: false,
                            recorded_seq: record.seq,
                            recorded_head: record.head,
                            rotation: false,
                        });
                    }
                }
            }
        }
        if let Some(kept) = signing.set_aside_on_open() {
            record.note_signing_set_aside(kept);
        }
        if quiet {
            record.seq = seq;
            record.head = head;
        } else {
            let holds = |(at, hash): (u64, [u8; 32])| {
                (seq, head) == (at, hash) || audit.entry_hash_at(at, &data_key) == Some(hash)
            };
            // A pruning that replaced the log before the record followed it
            // left the log at the entry it noted beforehand.
            let continues = seq <= record.seq
                || record.seq == 0
                || holds((record.seq, record.head))
                || record.retention_pending.is_some_and(holds);
            record.observe(seq, head, continues, now);
        }
        record.retention_pending = None;
        let chain = audit.check_chain(&data_key)?;
        record.too_long = chain.too_long;
        if chain.valid || record.chain_acknowledged == Some(chain.breaks) {
            record.chain_broken = None;
        } else {
            let found_at = record.chain_broken.map_or(now, |b| b.found_at);
            record.chain_broken = Some(audit_record::ChainBroken {
                found_at,
                failures: chain.failures,
                first_failure: chain.first_failure.unwrap_or(0),
                breaks: chain.breaks,
            });
        }
        // The judgment above read whether the epoch's row is there; only now
        // is a missing one written, in the same write as the record, so a
        // stop between them cannot leave either without the other.
        let epoch = self.storage.missing_agent_freeze_epoch()?;
        // Outside a vault's first open the row was written when the vault
        // was created and at every unlock since, so a missing one was
        // deleted: told to the owner until acknowledged, and noted in the
        // unlock's own entry.
        let reseeded = epoch.filter(|_| !first_open);
        if let Some(epoch) = reseeded {
            record.epoch_reseeded = Some(audit_record::EpochReseeded {
                epoch,
                found_at: now,
            });
        }
        if let Err(e) = self.save_audit_record_with(record, epoch) {
            tracing::error!(error = %e, "the record of the audit log could not be written");
        }
        if rotation {
            if let Err(e) = self.storage.set_rotation_in_progress(false) {
                tracing::error!(error = %e, "the note of an interrupted rotation could not be cleared");
            }
        }
        for warning in self.audit_warnings() {
            tracing::error!("{warning}");
        }
        Ok(reseeded)
    }

    /// The record of the audit log: `None` when there is none, and an inner
    /// error when it cannot be decrypted, is under another key or does not
    /// parse. The outer error is a failure to read the database.
    fn load_audit_record(&self) -> Result<Option<Result<audit_record::AuditRecord>>> {
        let Some(stored) = self.storage.config_row(audit_record::AUDIT_RECORD_KEY)? else {
            return Ok(None);
        };
        Ok(Some(
            self.storage
                .open_config_bound(audit_record::AUDIT_RECORD_KEY, &stored)
                .and_then(|bytes| {
                    serde_json::from_slice(&bytes)
                        .map_err(|e| KeepError::Other(format!("audit record: {e}")))
                }),
        ))
    }

    /// Keep `record` as the record, in memory at once and in `keep.db`.
    fn save_audit_record(&mut self, record: audit_record::AuditRecord) -> Result<()> {
        self.save_audit_record_with(record, None)
    }

    /// [`Self::save_audit_record`], writing the agent freeze epoch `epoch`
    /// in the same write when given.
    fn save_audit_record_with(
        &mut self,
        record: audit_record::AuditRecord,
        epoch: Option<u64>,
    ) -> Result<()> {
        let stored = serde_json::to_vec(&record)
            .map_err(|e| KeepError::Other(e.to_string()))
            .and_then(|bytes| self.storage.set_audit_record(&bytes, epoch));
        self.audit_record = Some(record);
        stored
    }

    /// Move the record to where the audit log is now, after an entry was
    /// appended. The append is durable before this runs, so the record never
    /// runs ahead of the log; a failure to write it is logged, and the next
    /// unlock finds the log past the record, which continues it. The log in
    /// memory only moves forward, so a log behind the record here is noted,
    /// never moved to silently.
    fn note_audit_place(&mut self) {
        if let Some(audit) = self.audit.as_ref() {
            self.storage.set_seed_floor(audit.own_time());
        }
        let (Some(audit), Some(record)) = (self.audit.as_ref(), self.audit_record.as_ref()) else {
            return;
        };
        if (record.seq, record.head) == (audit.seq(), audit.last_hash())
            && record.retention_pending.is_none()
        {
            return;
        }
        let mut record = record.clone();
        record.observe(
            audit.seq(),
            audit.last_hash(),
            true,
            chrono::Utc::now().timestamp(),
        );
        record.retention_pending = None;
        if let Err(e) = self.save_audit_record(record) {
            tracing::error!(error = %e, "the audit log's place could not be recorded");
        }
    }

    /// Write the first record for a log this process just wrote whole (a
    /// restored backup's), so a later unlock compares against it.
    pub(crate) fn record_audit_place(&mut self, seq: u64, head: [u8; 32]) -> Result<()> {
        self.save_audit_record(audit_record::AuditRecord {
            seq,
            head,
            ..Default::default()
        })
    }

    /// The audit log's last sequence number and last entry hash: what an
    /// anchor carries.
    pub fn audit_anchor(&self) -> Result<(u64, [u8; 32])> {
        let audit = self.audit.as_ref().ok_or(KeepError::Locked)?;
        Ok((audit.seq(), audit.last_hash()))
    }

    /// What the owner must be told about the audit logs, on every unlock
    /// until acknowledged with [`Self::audit_acknowledge`]: logs set aside
    /// or migrations that failed their check (whether or not the kept file
    /// is still there), a log found not continuing the record, the record
    /// found missing or unreadable, signing logs set aside, and a broken
    /// chain.
    pub fn audit_warnings(&self) -> Vec<audit_record::AuditWarning> {
        use audit_record::AuditWarning;
        let mut warnings = Vec::new();
        let Some(record) = self.audit_record.as_ref() else {
            return warnings;
        };
        for set_aside in &record.set_asides {
            let present = self
                .audit
                .as_ref()
                .is_some_and(|a| a.kept_log_present(&set_aside.kept));
            warnings.push(AuditWarning::FailedMigration {
                set_aside: set_aside.clone(),
                missing: !present,
            });
        }
        if let Some(rollback) = record.rollback {
            warnings.push(AuditWarning::RolledBack(rollback));
        }
        if let Some(lost) = record.lost {
            warnings.push(AuditWarning::RecordLost(lost));
        }
        for kept in &record.signing_set_asides {
            let present = self
                .signing_audit
                .as_ref()
                .is_some_and(|s| s.kept_log_present(kept));
            warnings.push(AuditWarning::SigningLogSetAside {
                kept: kept.clone(),
                missing: !present,
            });
        }
        if record.more_set_asides > 0 {
            warnings.push(AuditWarning::MoreSetAside(record.more_set_asides));
        }
        if let Some(broken) = record.chain_broken {
            warnings.push(AuditWarning::ChainBroken(broken));
        }
        if let Some(reseeded) = record.epoch_reseeded {
            warnings.push(AuditWarning::EpochReseeded(reseeded));
        }
        if record.too_long {
            warnings.push(AuditWarning::TooLong);
        }
        warnings
    }

    /// The log found not continuing what the vault recorded, until
    /// acknowledged.
    #[cfg(test)]
    fn audit_rollback(&self) -> Option<audit_record::AuditRollback> {
        self.audit_record.as_ref().and_then(|r| r.rollback)
    }

    /// Acknowledge the warnings [`Self::audit_warnings`] reports, once
    /// investigated, given exactly as they were shown (`shown`): if they
    /// changed since, nothing is acknowledged, so nothing is acknowledged
    /// unseen. The audit log gets an entry naming each, so the evidence
    /// stays in the chain, and the warnings stop; a broken chain is
    /// acknowledged as the unlock found it, so a break made since is still
    /// reported. Returns what was acknowledged; nothing is written when
    /// nothing is pending.
    pub fn audit_acknowledge(
        &mut self,
        shown: &[audit_record::AuditWarning],
    ) -> Result<Vec<audit_record::AuditWarning>> {
        let mut record = self.audit_record.clone().ok_or(KeepError::Locked)?;
        let warnings = self.audit_warnings();
        if warnings != shown {
            return Err(KeepError::invalid_input(
                "the audit warnings changed since they were shown; review them again",
            ));
        }
        if !record.pending() {
            return Ok(Vec::new());
        }
        let reason = format!(
            "acknowledged: {}",
            warnings
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
        self.audit_event_required(AuditEventType::AuditAcknowledged, |e| {
            e.with_reason(&reason)
        })?;
        let audit = self.audit.as_mut().ok_or(KeepError::Locked)?;
        if !record.set_asides.is_empty() || record.more_set_asides > 0 {
            audit.clear_failed_migration_marker()?;
        }
        if let Some(broken) = record.chain_broken {
            record.chain_acknowledged = Some(broken.breaks);
        }
        record.clear_pending();
        record.seq = audit.seq();
        record.head = audit.last_hash();
        self.save_audit_record(record)?;
        Ok(warnings)
    }

    /// Returns true if unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.storage.is_unlocked()
    }

    /// The vault's Argon2id parameters (from the header, readable before unlock).
    /// Non-secret; used to reproduce an unlock's KDF cost without unlocking.
    pub fn argon2_params(&self) -> crate::crypto::Argon2Params {
        self.storage.argon2_params()
    }

    /// Generate a new Nostr keypair and store it.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::path::Path;
    /// # use keep_core::Keep;
    /// # let mut keep = Keep::create(Path::new("/tmp/k"), "pw")?;
    /// let pubkey = keep.generate_key("my-nostr-key")?;
    /// println!("Created key: {}", hex::encode(pubkey));
    /// # Ok::<(), keep_core::error::KeepError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`KeepError::Locked`] if the Keep is not unlocked.
    pub fn generate_key(&mut self, name: &str) -> Result<[u8; 32]> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let keypair = NostrKeypair::generate()?;
        let pubkey = *keypair.public_bytes();

        let data_key = self.get_data_key()?;
        let encrypted = crypto::encrypt(keypair.secret_bytes(), &data_key)?;

        let record = KeyRecord::new(
            pubkey,
            KeyType::Nostr,
            name.to_string(),
            encrypted.to_bytes(),
        );

        self.storage.store_key(&record)?;

        self.keyring.load_key(
            pubkey,
            *keypair.secret_bytes(),
            KeyType::Nostr,
            name.to_string(),
        )?;

        self.audit_event(AuditEventType::KeyGenerate, |e| {
            e.with_pubkey(&pubkey).with_key_type("nostr")
        });

        Ok(pubkey)
    }

    /// Import an nsec and store it.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::path::Path;
    /// # use keep_core::Keep;
    /// # let mut keep = Keep::create(Path::new("/tmp/k"), "pw")?;
    /// let nsec = "nsec1...";
    /// let pubkey = keep.import_nsec(nsec, "imported-key")?;
    /// # Ok::<(), keep_core::error::KeepError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`KeepError::Locked`] if the Keep is not unlocked.
    /// Returns [`KeepError::InvalidNsec`] if the nsec format is invalid.
    /// Returns [`KeepError::KeyAlreadyExists`] if the key is already stored.
    pub fn import_nsec(&mut self, nsec: &str, name: &str) -> Result<[u8; 32]> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let name = name.trim();
        if name.is_empty() {
            return Err(KeepError::InvalidInput("name cannot be empty".into()));
        }
        if name.chars().count() > 64 {
            return Err(KeepError::InvalidInput(
                "name must be 64 characters or fewer".into(),
            ));
        }

        let keypair = NostrKeypair::from_nsec(nsec)?;
        let pubkey = *keypair.public_bytes();

        if self.keyring.get(&pubkey).is_some() {
            return Err(KeepError::KeyAlreadyExists(keypair.to_npub()));
        }

        let data_key = self.get_data_key()?;
        let encrypted = crypto::encrypt(keypair.secret_bytes(), &data_key)?;

        let record = KeyRecord::new(
            pubkey,
            KeyType::Nostr,
            name.to_string(),
            encrypted.to_bytes(),
        );

        self.storage.store_key(&record)?;

        self.keyring.load_key(
            pubkey,
            *keypair.secret_bytes(),
            KeyType::Nostr,
            name.to_string(),
        )?;

        self.audit_event(AuditEventType::KeyImport, |e| {
            e.with_pubkey(&pubkey).with_key_type("nostr")
        });

        Ok(pubkey)
    }

    /// Import a Nostr key from raw secret bytes.
    pub fn import_secret_bytes(&mut self, secret: &mut [u8; 32], name: &str) -> Result<[u8; 32]> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let name = name.trim();
        if name.is_empty() {
            return Err(KeepError::InvalidInput("name cannot be empty".into()));
        }
        if name.chars().count() > 64 {
            return Err(KeepError::InvalidInput(
                "name must be 64 characters or fewer".into(),
            ));
        }

        let keypair = NostrKeypair::from_secret_bytes(secret)?;
        let pubkey = *keypair.public_bytes();

        if self.keyring.get(&pubkey).is_some() {
            return Err(KeepError::KeyAlreadyExists(keypair.to_npub()));
        }

        let data_key = self.get_data_key()?;
        let encrypted = crypto::encrypt(keypair.secret_bytes(), &data_key)?;

        let record = KeyRecord::new(
            pubkey,
            KeyType::Nostr,
            name.to_string(),
            encrypted.to_bytes(),
        );

        self.storage.store_key(&record)?;

        self.keyring.load_key(
            pubkey,
            *keypair.secret_bytes(),
            KeyType::Nostr,
            name.to_string(),
        )?;

        self.audit_event(AuditEventType::KeyImport, |e| {
            e.with_pubkey(&pubkey).with_key_type("nostr")
        });

        Ok(pubkey)
    }

    /// The primary key slot, if set.
    pub fn get_primary_key(&self) -> Option<&keyring::KeySlot> {
        self.keyring.get_primary()
    }

    /// List all stored key records.
    pub fn list_keys(&self) -> Result<Vec<KeyRecord>> {
        self.storage.list_keys()
    }

    /// Store (insert or overwrite by id) an arbitrary-secret record (password,
    /// API token, note). The whole record, including its plaintext value and
    /// title, is encrypted under the vault data key at rest. See
    /// [`storage::Storage::store_secret`]. Records a `SecretCreate` audit event
    /// (tagged with the non-sensitive random id, never the name or value) so
    /// secret mutations leave a forensic trail like every other sensitive op.
    pub fn store_secret(&mut self, record: &crate::secret::SecretRecord) -> Result<()> {
        self.storage.store_secret(record)?;
        self.audit_event(AuditEventType::SecretCreate, |e| e.with_pubkey(&record.id));
        Ok(())
    }

    /// Load a secret record by its 32-byte id.
    pub fn load_secret(&self, id: &[u8; 32]) -> Result<crate::secret::SecretRecord> {
        self.storage.load_secret(id)
    }

    /// The plaintext value of a plain (not threshold-sealed) secret. The
    /// `SecretReveal` audit event is written first and nothing is returned if it
    /// cannot be, so no value leaves the vault unrecorded.
    pub fn reveal_secret(&mut self, id: &[u8; 32]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if self.storage.load_secret_seal(id)?.is_some() {
            return Err(KeepError::invalid_input(
                "secret is threshold-sealed; reveal it with its quorum",
            ));
        }
        let record = self.storage.load_secret(id)?;
        self.audit_event_required(AuditEventType::SecretReveal, |e| e.with_pubkey(id))?;
        Ok(zeroize::Zeroizing::new(record.value.clone()))
    }

    /// Records a signature an agent obtained with `pubkey`'s key over `message`,
    /// with `context` naming what was signed. Fails when the entry cannot be
    /// written, so a caller can withhold a signature that would go unrecorded.
    ///
    /// Agent entries stop [`AGENT_AUDIT_HEADROOM`] short of the most entries the
    /// log is read back with, so an agent cannot make the log unreadable.
    pub fn record_agent_signature(
        &mut self,
        pubkey: &[u8; 32],
        message: &[u8],
        context: &str,
    ) -> Result<()> {
        self.check_agent_audit_room()?;
        let context = crate::agent::audit_text(context);
        self.audit_event_required(AuditEventType::Sign, |e| {
            e.with_pubkey(pubkey)
                .with_message_hash(message)
                .with_reason(&context)
        })
    }

    /// Issue an agent gateway credential bound to `uid`, valid from Unix time
    /// `now` for `ttl_secs`, with the gateway's serialized `grant`. `now` comes
    /// from the same clock later passed to [`Self::authenticate_agent`]. Returns
    /// the credential with its token, which is never stored and must be handed
    /// to the agent now. Nothing is issued unless the `AgentCredentialIssue`
    /// entry, which records a hash of the grant, is written.
    pub fn issue_agent_credential(
        &mut self,
        name: &str,
        uid: u32,
        grant: Vec<u8>,
        now: u64,
        ttl_secs: u64,
    ) -> Result<(crate::agent::AgentCredential, Zeroizing<String>)> {
        let id = crate::entropy::try_random_bytes()?;
        self.issue_agent_credential_with_id(id, name, uid, grant, now, ttl_secs)
    }

    /// [`Self::issue_agent_credential`] with the id chosen beforehand, as an
    /// approver approved it. An id already in use is refused.
    pub fn issue_agent_credential_with_id(
        &mut self,
        id: [u8; 16],
        name: &str,
        uid: u32,
        grant: Vec<u8>,
        now: u64,
        ttl_secs: u64,
    ) -> Result<(crate::agent::AgentCredential, Zeroizing<String>)> {
        if self.storage.load_agent_credential(&id)?.is_some() {
            return Err(KeepError::invalid_input(
                "an agent credential with that id already exists",
            ));
        }
        let (credential, token) =
            crate::agent::AgentCredential::issue_with_id(id, name, uid, grant, now, ttl_secs)?;
        self.storage.insert_agent_credential(&credential)?;
        let reason = format!(
            "agent {} uid {} expires {} grant {}",
            credential.id_hex(),
            credential.uid,
            credential.expires_at,
            hex::encode(crate::crypto::blake2b_256(&credential.grant))
        );
        if let Err(e) = self.audit_event_required(AuditEventType::AgentCredentialIssue, |e| {
            e.with_reason(&reason)
        }) {
            // Nobody holds the token, but an unaudited credential must not stay
            // live: delete it, or failing that revoke it.
            if let Err(delete) = self
                .storage
                .delete_agent_credential(&credential.id, None, &[])
            {
                let mut revoked = credential.clone();
                revoked.revoked = true;
                let revoke = self.storage.update_agent_credential(&revoked);
                tracing::warn!(id = %credential.id_hex(), %delete, ?revoke, "unaudited agent credential could not be deleted");
            }
            return Err(e);
        }
        Ok((credential, token))
    }

    /// Every agent credential, revoked and expired ones included.
    pub fn agent_credentials(&self) -> Result<Vec<crate::agent::AgentCredential>> {
        self.storage.list_agent_credentials()
    }

    /// The id of every stored agent credential, read without decrypting any,
    /// so a row that cannot be read can still be found and deleted.
    pub fn agent_credential_ids(&self) -> Result<Vec<[u8; 16]>> {
        self.storage.agent_credential_ids()
    }

    /// The agent credential with `id`, if any, decoding only that row.
    pub fn load_agent_credential(
        &self,
        id: &[u8; 16],
    ) -> Result<Option<crate::agent::AgentCredential>> {
        self.storage.load_agent_credential(id)
    }

    fn agent_credential(&self, id: &[u8; 16]) -> Result<crate::agent::AgentCredential> {
        self.storage
            .load_agent_credential(id)?
            .ok_or_else(|| KeepError::NotFound(hex::encode(id)))
    }

    /// Revoke an agent credential for good. Revoking is never held back by the
    /// audit log; its `AgentCredentialRevoke` entry is best effort.
    pub fn revoke_agent_credential(&mut self, id: &[u8; 16]) -> Result<()> {
        let mut credential = self.agent_credential(id)?;
        credential.revoked = true;
        self.storage.update_agent_credential(&credential)?;
        self.audit_event(AuditEventType::AgentCredentialRevoke, |e| {
            e.with_reason(&format!("agent {}", hex::encode(id)))
        });
        Ok(())
    }

    /// Delete an agent credential and its ledger, freeing its slot. Deleting
    /// a frozen one moves the freeze epoch, as every clear of a freeze does.
    pub fn delete_agent_credential(&mut self, id: &[u8; 16]) -> Result<()> {
        self.delete_agent_credential_with(id, None, &[]).map(|_| ())
    }

    /// [`Self::delete_agent_credential`], storing the agent ledgers
    /// `ledgers` in the same write when the credential was frozen, refused
    /// when `expect_epoch` is given and is not the current epoch. Returns
    /// the new epoch when it moved.
    pub fn delete_agent_credential_with(
        &mut self,
        id: &[u8; 16],
        expect_epoch: Option<u64>,
        ledgers: &[(&[u8], &[u8])],
    ) -> Result<Option<u64>> {
        let moved = self
            .storage
            .delete_agent_credential(id, expect_epoch, ledgers)?;
        let reason = format!("agent {}{}", hex::encode(id), seeded_note(moved));
        self.audit_event(AuditEventType::AgentCredentialDelete, |e| {
            e.with_reason(&reason)
        });
        Ok(moved.map(|m| m.epoch))
    }

    /// Freeze or unfreeze one agent credential. Freezing is never held back by
    /// the audit log; unfreezing is refused unless its entry is written.
    /// Either moves the freeze epoch (see [`Self::set_agent_frozen`]).
    pub fn set_agent_credential_frozen(&mut self, id: &[u8; 16], frozen: bool) -> Result<()> {
        self.set_agent_frozen(Some(id), frozen, None, &[])
            .map(|_| ())
    }

    /// Freeze or unfreeze every agent credential at once, on the same terms as
    /// [`Self::set_agent_credential_frozen`].
    pub fn set_agent_freeze(&mut self, frozen: bool) -> Result<()> {
        self.set_agent_frozen(None, frozen, None, &[]).map(|_| ())
    }

    /// The agent freeze epoch: one more on every freeze and unfreeze, from
    /// any source, so an unfreeze approved for an earlier state cannot undo
    /// a later freeze. An `Err` means it could not be read.
    pub fn agent_freeze_epoch(&self) -> Result<u64> {
        self.storage.get_agent_freeze_epoch()
    }

    /// Freeze or unfreeze (`frozen`) agent credential `credential`, or every
    /// agent when it is `None`, and store the agent ledgers `ledgers`, in one
    /// durable write that also moves the freeze epoch on by one. Refused when
    /// `expect_epoch` is given and is not the current epoch. Freezing is
    /// never held back by the audit log; unfreezing is refused unless its
    /// entry is written first. Returns the new epoch.
    pub fn set_agent_frozen(
        &mut self,
        credential: Option<&[u8; 16]>,
        frozen: bool,
        expect_epoch: Option<u64>,
        ledgers: &[(&[u8], &[u8])],
    ) -> Result<u64> {
        let reason = match credential {
            Some(id) => {
                // Refuse an unknown credential before any entry is written.
                self.agent_credential(id)?;
                format!("agent {}", hex::encode(id))
            }
            None => "every agent".to_string(),
        };
        if frozen {
            // A freeze goes ahead even when the epoch cannot be read, with a
            // new one seeded and the entry saying so.
            let moved = self
                .storage
                .set_agent_frozen(credential, true, expect_epoch, ledgers)?;
            let reason = format!("{reason}{}", seeded_note(Some(moved)));
            self.audit_event(AuditEventType::AgentFreeze, |e| e.with_reason(&reason));
            Ok(moved.epoch)
        } else {
            let epoch = self.storage.get_agent_freeze_epoch()?;
            if expect_epoch.is_some_and(|expected| expected != epoch) {
                return Err(KeepError::invalid_input(format!(
                    "the agent freeze epoch moved to {epoch}: something froze or unfroze since"
                )));
            }
            self.audit_event_required(AuditEventType::AgentUnfreeze, |e| e.with_reason(&reason))?;
            self.storage
                .set_agent_frozen(credential, false, Some(epoch), ledgers)
                .map(|moved| moved.epoch)
        }
    }

    /// Freeze again `credential`, or every agent when it is `None`, which is
    /// frozen already: move the freeze epoch on by one and store the agent
    /// ledgers `ledgers`, in one durable write, so an unfreeze approved for
    /// the state before can no longer apply. Nothing changes but the epoch,
    /// so no entry is written unless the epoch had to be seeded. Refused
    /// when the scope is not frozen. Returns the new epoch.
    pub fn refreeze_agent(
        &mut self,
        credential: Option<&[u8; 16]>,
        ledgers: &[(&[u8], &[u8])],
    ) -> Result<u64> {
        let frozen = match credential {
            Some(id) => self.agent_credential(id)?.frozen,
            None => self.storage.get_agent_freeze()?,
        };
        if !frozen {
            return Err(KeepError::invalid_input("not frozen: freeze it instead"));
        }
        let moved = self
            .storage
            .set_agent_frozen(credential, true, None, ledgers)?;
        if moved.seeded {
            let reason = match credential {
                Some(id) => format!("agent {} again", hex::encode(id)),
                None => "every agent again".to_string(),
            };
            let reason = format!("{reason}{}", seeded_note(Some(moved)));
            self.audit_event(AuditEventType::AgentFreeze, |e| e.with_reason(&reason));
        }
        Ok(moved.epoch)
    }

    /// Overwrite the vault-wide agent freeze with bytes that do not decrypt,
    /// for tests of what must fail closed when it cannot be read.
    #[cfg(feature = "testing")]
    pub fn corrupt_agent_freeze_for_testing(&self) -> Result<()> {
        self.storage.put_raw(
            crate::backend::CONFIG_TABLE,
            crate::storage::AGENT_FREEZE,
            b"not ciphertext",
        )
    }

    /// Overwrite the agent freeze epoch with bytes that do not decrypt, for
    /// tests of what must go ahead without it.
    #[cfg(feature = "testing")]
    pub fn corrupt_agent_freeze_epoch_for_testing(&self) -> Result<()> {
        self.storage.put_raw(
            crate::backend::CONFIG_TABLE,
            b"agent_freeze_epoch",
            b"not ciphertext",
        )
    }

    /// Store credential `from`'s row again under id `to`, where it does not
    /// load, for tests of what must not stop on an unreadable credential.
    #[cfg(feature = "testing")]
    pub fn misplace_agent_credential_for_testing(
        &self,
        from: &[u8; 16],
        to: &[u8; 16],
    ) -> Result<()> {
        let table = crate::backend::AGENT_CREDENTIALS_TABLE;
        let row = self
            .storage
            .list_raw(table)?
            .into_iter()
            .find(|(id, _)| id.as_slice() == from)
            .ok_or_else(|| KeepError::NotFound(hex::encode(from)))?
            .1;
        self.storage.put_raw(table, to, &row)
    }

    /// Whether every agent credential is frozen. An `Err` means the flag could
    /// not be read; the gateway then refuses to serve.
    pub fn agent_freeze(&self) -> Result<bool> {
        self.storage.get_agent_freeze()
    }

    /// Check a token presented by `peer_uid` at Unix time `now`.
    ///
    /// Returns the credential if the token is well formed, matches exactly one
    /// credential, and that credential is live, unfrozen (itself and
    /// vault-wide) and bound to `peer_uid`; otherwise the reason it was
    /// refused. The caller records the reason but answers the agent with one
    /// uniform refusal. Every stored credential is compared, so the time taken
    /// does not depend on which one matches, and an unreadable vault-wide
    /// freeze counts as frozen.
    ///
    /// `now` comes from the caller so the gateway can use a clock that only
    /// advances with elapsed time; a clock reading before the credential was
    /// issued is refused. The result is a snapshot: the gateway authenticates
    /// every request, so a revocation takes effect on the next one. Each call
    /// decrypts every credential: at most 64 rows of at most 64 KiB of grant.
    pub fn authenticate_agent(
        &self,
        token: &str,
        peer_uid: u32,
        now: u64,
    ) -> Result<std::result::Result<crate::agent::AgentCredential, crate::agent::AgentRefused>>
    {
        use crate::agent::{AgentRefusal, AgentRefused};
        let unknown = AgentRefused {
            reason: AgentRefusal::Unknown,
            credential: None,
        };
        let Some(hash) = crate::agent::hash_presented_token(token) else {
            return Ok(Err(unknown));
        };
        // Read whatever the token matches, so an unknown token costs the same
        // reads as a real one and how long a refusal takes tells nothing.
        let all_frozen = self.storage.get_agent_freeze().unwrap_or(true);
        let mut found = None;
        let mut matched = 0usize;
        for credential in self.storage.list_agent_credentials()? {
            if credential.matches_hash(&hash) {
                matched += 1;
                found = Some(credential);
            }
        }
        // A copied row is already refused when listed; refusing a second match
        // here is defense in depth.
        let credential = match (matched, found) {
            (1, Some(credential)) => credential,
            _ => return Ok(Err(unknown)),
        };
        match credential.check_usable(peer_uid, now, all_frozen) {
            Ok(()) => Ok(Ok(credential)),
            Err(reason) => Ok(Err(AgentRefused {
                reason,
                credential: Some(credential.id),
            })),
        }
    }

    /// The serialized agent ledger stored under `key`, if any.
    pub fn load_agent_ledger(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.storage.load_agent_ledger(key)
    }

    /// Read the ledgers under `keys`, let `update` replace them, and store the
    /// replacements in one durable transaction. Taking `&mut self` keeps any
    /// other update from interleaving, so a budget check and the spend it
    /// records cannot race.
    pub fn update_agent_ledgers<F>(&mut self, keys: &[&[u8]], update: F) -> Result<()>
    where
        F: FnOnce(&[Option<Zeroizing<Vec<u8>>>]) -> Result<Vec<Vec<u8>>>,
    {
        self.storage.update_agent_ledgers(keys, update)
    }

    /// Records a request by the agent credential `id` that was refused or held
    /// for an approval. `label` is the gateway's own fixed text (see
    /// [`crate::agent::valid_audit_label`]); `detail`, which may hold text the
    /// agent sent, is capped, escaped and quoted so it cannot pose as anything
    /// else. Fails when the entry cannot be written, and stops
    /// [`AGENT_AUDIT_HEADROOM`] short of the most entries the log is read back
    /// with, like [`Self::record_agent_signature`].
    pub fn record_agent_refusal(
        &mut self,
        id: &[u8; 16],
        label: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        self.record_agent_entry(AuditEventType::AgentRefused, id, label, detail)
    }

    /// Records what the agent credential `id` was served, other than a
    /// signature, before it is returned, on the same terms as
    /// [`Self::record_agent_refusal`]. Fails when the entry cannot be written,
    /// so the caller can withhold the answer.
    pub fn record_agent_served(
        &mut self,
        id: &[u8; 16],
        label: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        self.record_agent_entry(AuditEventType::AgentServed, id, label, detail)
    }

    fn record_agent_entry(
        &mut self,
        event: AuditEventType,
        id: &[u8; 16],
        label: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        if !crate::agent::valid_audit_label(label) {
            return Err(KeepError::invalid_input(format!(
                "an agent audit label is 1 to {} printable ASCII characters",
                crate::agent::MAX_AUDIT_LABEL
            )));
        }
        self.check_agent_audit_room()?;
        let mut reason = format!("agent {} {label}", hex::encode(id));
        if let Some(detail) = detail {
            reason.push_str(&format!(" \"{}\"", crate::agent::audit_text(detail)));
        }
        let success = event != AuditEventType::AgentRefused;
        self.audit_event_required(event, |e| e.with_reason(&reason).with_success(success))
    }

    /// Records something the owner did through the agent gateway or an
    /// approver device: a management change sent to the approvers, an
    /// approval decided, a freeze from a device, a device added or removed. Charged to no agent's budget, so agents cannot use up
    /// the room the owner needs; it may use the headroom agents leave, and
    /// stops only where the log could no longer be read back. Fails when the
    /// entry cannot be written.
    pub fn record_owner_event(&mut self, event: AuditEventType, reason: &str) -> Result<()> {
        if !matches!(
            event,
            AuditEventType::AgentApprovalRequested
                | AuditEventType::AgentApprovalDecided
                | AuditEventType::AgentApproverFreeze
                | AuditEventType::AgentApproverAdded
                | AuditEventType::AgentApproverRemoved
        ) {
            return Err(KeepError::invalid_input(format!(
                "{event} is not an owner event"
            )));
        }
        let count = self.audit.as_ref().map_or(0, AuditLog::entry_count);
        if count >= crate::audit::MAX_AUDIT_ENTRIES - 1 {
            return Err(KeepError::AuditWriteFailed(format!(
                "audit log is full ({count} entries): export the log with `keep audit export`, \
                 then prune it with `keep audit retention --max-entries 10000 --apply`"
            )));
        }
        // The gateway builds these from fixed text, keys, signatures and a
        // checked label; escaped all the same, and capped well above them.
        let reason = crate::agent::cap_text(reason, MAX_OWNER_AUDIT_TEXT)
            .escape_debug()
            .to_string();
        self.audit_event_required(event, |e| e.with_reason(&reason))
    }

    /// Records an agent request sent to the approvers, on the same terms as
    /// [`Self::record_agent_refusal`]: charged to the agent, and refused once
    /// agents have used their share of the log.
    pub fn record_agent_approval_requested(
        &mut self,
        id: &[u8; 16],
        label: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        self.record_agent_entry(AuditEventType::AgentApprovalRequested, id, label, detail)
    }

    /// Records how an agent request sent to the approvers ended without an
    /// approval (it expired, or the agent withdrew it), on the same terms as
    /// [`Self::record_agent_refusal`]: charged to the agent.
    pub fn record_agent_approval_decided(
        &mut self,
        id: &[u8; 16],
        label: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        self.record_agent_entry(AuditEventType::AgentApprovalDecided, id, label, detail)
    }

    fn check_agent_audit_room(&self) -> Result<()> {
        let count = self.audit.as_ref().map_or(0, AuditLog::entry_count);
        if count >= crate::audit::MAX_AUDIT_ENTRIES - AGENT_AUDIT_HEADROOM {
            return Err(KeepError::AuditWriteFailed(format!(
                "audit log is full ({count} entries): stop the agent, export the log with \
                 `keep audit export`, then prune it with \
                 `keep audit retention --max-entries 10000 --apply`"
            )));
        }
        Ok(())
    }

    /// List all stored secret records.
    pub fn list_secrets(&self) -> Result<Vec<crate::secret::SecretRecord>> {
        self.storage.list_secrets()
    }

    /// Delete a secret record by its 32-byte id. Records a `SecretDelete` audit
    /// event tagged with the id.
    pub fn delete_secret(&mut self, id: &[u8; 32]) -> Result<()> {
        self.storage.delete_secret(id)?;
        self.audit_event(AuditEventType::SecretDelete, |e| e.with_pubkey(id));
        Ok(())
    }

    /// Restore a secret WITHOUT emitting an audit event, for the backup-restore
    /// path only. Restore re-establishes the source vault's audit log verbatim
    /// (see `VaultBackup::audit_entries`), so re-auditing each restored row would
    /// double-count. Mirrors `restore_key_record`.
    pub fn restore_secret(&self, record: &crate::secret::SecretRecord) -> Result<()> {
        self.storage.store_secret(record)
    }

    /// Store a secret whose value can only be revealed with a t-of-n OPRF quorum.
    ///
    /// Takes a caller-minted `record` (via [`crate::secret::SecretRecord::new`])
    /// carrying the plaintext in `record.value`. The caller must mint the record
    /// FIRST so it knows the id, then derive `oprf_key` from the quorum for that id
    /// (`oprf_id = hex(record.id)`, `epoch`) BEFORE calling this: the seal records
    /// `oprf_id`, and a reveal re-derives the key for the same id, so a key derived
    /// for any other id would seal a value no quorum could ever reopen.
    ///
    /// `oprf_key` is the quorum-derived key ([`crate::oprf::derive_luks_key`]
    /// output); `epoch` its OPRF rotation counter. The value is sealed under a fresh
    /// per-secret DEK wrapped by `oprf_key`, so a single device that never assembles
    /// the quorum cannot decrypt it even with the vault unlocked. The record's
    /// name/kind stay readable with the vault data key. Returns the stored record
    /// (its `value` now the DEK-ciphertext). Records a `SecretCreate` audit event.
    pub fn store_sealed_secret(
        &mut self,
        mut record: crate::secret::SecretRecord,
        oprf_key: &crate::crypto::SecretKey,
        epoch: u32,
    ) -> Result<crate::secret::SecretRecord> {
        let oprf_id = hex::encode(record.id);
        // Take the plaintext out of the record and seal it; `record.value` becomes
        // the DEK-ciphertext. The lifted plaintext is zeroized when this scope ends.
        let plaintext = zeroize::Zeroizing::new(std::mem::take(&mut record.value));
        let (value_ciphertext, seal) =
            crate::secret::seal_value(&plaintext, oprf_key, oprf_id, epoch)?;
        record.value = value_ciphertext;
        self.storage.store_sealed_secret(&record, &seal)?;
        self.audit_event(AuditEventType::SecretCreate, |e| e.with_pubkey(&record.id));
        Ok(record)
    }

    /// Load the threshold seal for a secret id, or `None` if the secret is an
    /// ordinary plaintext-value secret. The seal carries the OPRF params
    /// (`oprf_id`, `epoch`) the quorum needs to re-derive the unwrapping key.
    pub fn load_secret_seal(&self, id: &[u8; 32]) -> Result<Option<crate::secret::ThresholdSeal>> {
        self.storage.load_secret_seal(id)
    }

    /// Reveal a threshold-sealed secret's plaintext value given the OPRF-quorum
    /// -derived key. Errors if the secret is not sealed, or if `oprf_key` is wrong
    /// (a single-device caller that never assembled the quorum cannot derive it).
    ///
    /// Records a `SecretReveal` audit event (tagged with the id) only on a
    /// successful unseal: revealing a quorum-gated plaintext is the most sensitive
    /// read in the store, audited like `KeyExport`. A wrong-key attempt leaves no
    /// entry (it never yields the value).
    pub fn reveal_sealed_secret(
        &mut self,
        id: &[u8; 32],
        oprf_key: &crate::crypto::SecretKey,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let record = self.storage.load_secret(id)?;
        let seal = self
            .storage
            .load_secret_seal(id)?
            .ok_or_else(|| KeepError::invalid_input("secret is not threshold-sealed"))?;
        let plaintext = crate::secret::unseal_value(&record.value, &seal, oprf_key)?;
        self.audit_event_required(AuditEventType::SecretReveal, |e| e.with_pubkey(id))?;
        Ok(plaintext)
    }

    /// Restore a threshold-sealed secret (record + seal) WITHOUT emitting an audit
    /// event, for the backup-restore path only. Mirrors [`Self::restore_secret`].
    pub fn restore_sealed_secret(
        &self,
        record: &crate::secret::SecretRecord,
        seal: &crate::secret::ThresholdSeal,
    ) -> Result<()> {
        self.storage.store_sealed_secret(record, seal)
    }

    /// Export a stored nsec key as NIP-49 ncryptsec.
    pub fn export_ncryptsec(&mut self, pubkey: &[u8; 32], password: &str) -> Result<String> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let slot = self
            .keyring
            .get(pubkey)
            .ok_or_else(|| KeepError::KeyNotFound(hex::encode(pubkey)))?;

        if slot.key_type != KeyType::Nostr {
            return Err(KeepError::InvalidInput("not a Nostr key".into()));
        }

        let result = keys::nip49::encrypt(slot.expose_secret(), password, None)?;
        self.audit_event(AuditEventType::KeyExport, |e| e.with_pubkey(pubkey));
        Ok(result)
    }

    /// Delete a key.
    pub fn delete_key(&mut self, pubkey: &[u8; 32]) -> Result<()> {
        let id = crypto::blake2b_256(pubkey);
        self.storage.delete_key(&id)?;
        self.keyring.remove(pubkey)?;
        self.audit_event(AuditEventType::KeyDelete, |e| e.with_pubkey(pubkey));
        Ok(())
    }

    /// The keyring.
    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    /// Decrypted audit log entries for this vault, in chronological order.
    /// Returns an empty vec if the audit log file does not exist yet.
    ///
    /// # Errors
    /// Returns [`KeepError::Locked`] if the vault is not unlocked.
    pub fn read_audit_entries(&self) -> Result<Vec<AuditEntry>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let data_key = self.get_data_key()?;
        match &self.audit {
            Some(audit) => audit.read_all(&data_key),
            None => AuditLog::open(self.storage.path(), &data_key)?.read_all(&data_key),
        }
    }

    /// Mutable access to the keyring.
    pub fn keyring_mut(&mut self) -> &mut Keyring {
        &mut self.keyring
    }

    /// Generate a new FROST key with the given threshold and total shares.
    pub fn frost_generate(
        &mut self,
        threshold: u16,
        total_shares: u16,
        name: &str,
    ) -> Result<Vec<SharePackage>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let config = ThresholdConfig::new(threshold, total_shares)?;
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate(name)?;

        let data_key = self.get_data_key()?;
        for share in &shares {
            let stored = StoredShare::encrypt(share, &data_key)?;
            self.storage.store_share(&stored)?;
        }

        let group_pubkey = *shares[0].group_pubkey();
        let participants: Vec<u16> = (1..=total_shares).collect();
        self.audit_event(AuditEventType::FrostGenerate, |e| {
            e.with_group(&group_pubkey)
                .with_threshold(threshold)
                .with_participants(participants)
        });

        Ok(shares)
    }

    /// Split an existing key into FROST shares.
    pub fn frost_split(
        &mut self,
        key_name: &str,
        threshold: u16,
        total_shares: u16,
    ) -> Result<Vec<SharePackage>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let slot = self
            .keyring
            .get_by_name(key_name)
            .ok_or_else(|| KeepError::KeyNotFound(key_name.to_string()))?;

        let secret = Zeroizing::new(*slot.expose_secret());

        let config = ThresholdConfig::new(threshold, total_shares)?;
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.split_existing(&secret, key_name)?;

        let data_key = self.get_data_key()?;
        for share in &shares {
            let stored = StoredShare::encrypt(share, &data_key)?;
            self.storage.store_share(&stored)?;
        }

        let group_pubkey = *shares[0].group_pubkey();
        let participants: Vec<u16> = (1..=total_shares).collect();
        self.audit_event(AuditEventType::FrostSplit, |e| {
            e.with_group(&group_pubkey)
                .with_threshold(threshold)
                .with_participants(participants)
        });

        Ok(shares)
    }

    /// List all stored FROST shares.
    pub fn frost_list_shares(&self) -> Result<Vec<StoredShare>> {
        self.storage.list_shares()
    }

    fn find_stored_share(
        &self,
        group_pubkey: &[u8; 32],
        identifier: u16,
        ciphersuite: Option<crate::frost::Ciphersuite>,
    ) -> Result<StoredShare> {
        let shares = self.storage.list_shares()?;
        shares
            .into_iter()
            .find(|s| {
                s.metadata.group_pubkey == *group_pubkey
                    && s.metadata.identifier == identifier
                    && ciphersuite.is_none_or(|cs| s.ciphersuite == cs)
            })
            .ok_or_else(|| KeepError::KeyNotFound(format!("No share {identifier} for group")))
    }

    /// Export a FROST share encrypted with a passphrase.
    pub fn frost_export_share(
        &mut self,
        group_pubkey: &[u8; 32],
        identifier: u16,
        passphrase: &str,
    ) -> Result<ShareExport> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let mut stored = self.find_stored_share(group_pubkey, identifier, None)?;
        let data_key = self.get_data_key()?;
        let share = stored.decrypt(&data_key)?;

        self.audit_event(AuditEventType::FrostShareExport, |e| {
            e.with_group(group_pubkey)
                .with_participants(vec![identifier])
        });

        let export =
            ShareExport::from_share_with_ciphersuite(&share, stored.ciphersuite, passphrase)?;

        // Exporting is the backup action: record it so the UI/clients can stop
        // nagging "not backed up". Best-effort; a storage error here must not
        // fail the export the caller already holds.
        if !stored.metadata.did_backup {
            stored.metadata.mark_backed_up();
            if let Err(e) = self.storage.store_share(&stored) {
                tracing::warn!(error = %e, "failed to persist did_backup after export");
            }
        }

        Ok(export)
    }

    /// Import a FROST share from an encrypted export.
    pub fn frost_import_share(
        &mut self,
        export: &ShareExport,
        passphrase: &str,
        name: &str,
    ) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let name = name.trim();
        if name.is_empty() {
            return Err(KeepError::InvalidInput("name cannot be empty".into()));
        }
        if name.chars().count() > 64 {
            return Err(KeepError::InvalidInput(
                "name must be 64 characters or fewer".into(),
            ));
        }

        let share = export.to_share(passphrase, name)?;
        let data_key = self.get_data_key()?;
        let stored = StoredShare::encrypt_with_ciphersuite(&share, export.ciphersuite, &data_key)?;
        self.storage.store_share(&stored)?;

        let group = hex::decode(&export.group_pubkey)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .unwrap_or_else(|| crypto::blake2b_256(export.group_pubkey.as_bytes()));
        self.audit_event(AuditEventType::FrostShareImport, |e| {
            e.with_group(&group)
                .with_participants(vec![export.identifier])
        });

        Ok(())
    }

    /// Generate (if absent) and persist this device's per-group DKG signing
    /// subkey (§3), keyed by `group_name` in the vault secret store, and return
    /// its x-only public key for the coordinator's kind-31101 roster. The subkey
    /// — never the identity nsec — is what the roster pins and what signs this
    /// party's DKG events, so the announcement never publishes a targeting map of
    /// identities. Idempotent: a second call for the same group returns the
    /// already-enrolled subkey rather than minting a divergent one, so a retried
    /// enrollment cannot desync the pubkey a coordinator may already have pinned.
    pub fn frost_group_subkey_ensure(&mut self, group_name: &str) -> Result<[u8; 32]> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        if let Some(mut secret) = self.frost_group_subkey_secret(group_name)? {
            let keypair = NostrKeypair::from_secret_bytes(&mut secret)?;
            return Ok(*keypair.public_bytes());
        }
        let keypair = NostrKeypair::generate()?;
        let pubkey = *keypair.public_bytes();
        let record = crate::secret::SecretRecord::new(
            frost_group_subkey_name(group_name),
            crate::secret::SecretKind::Generic,
            keypair.secret_bytes().to_vec(),
        )?;
        self.store_secret(&record)?;
        // Deliberately no read-back here. `SecretRecord::new` mints a random
        // row id, so a racing enroller writes a *second* row under the same
        // name rather than overwriting this one. A read-back would resolve which
        // row later reads resolve to (`list_secrets` is a deterministic
        // key-ordered scan), but it would not remove the duplicate row and would
        // not close the window against a writer arriving after it, while costing
        // a full decrypt of every secret in the vault on every enrollment.
        //
        // Closing this properly needs a store-if-absent primitive or a
        // name-derived deterministic record id. `&mut self` plus redb's
        // exclusive database lock make a concurrent writer hard to reach today,
        // so this is tracked rather than papered over.
        Ok(pubkey)
    }

    /// Load this device's per-group DKG signing subkey secret (§3), if one was
    /// enrolled via [`Keep::frost_group_subkey_ensure`]. `Ok(None)` when the
    /// group has no subkey yet (the caller must enroll one before running DKG).
    pub fn frost_group_subkey_secret(&self, group_name: &str) -> Result<Option<[u8; 32]>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let wanted = frost_group_subkey_name(group_name);
        for record in self.list_secrets()? {
            if record.name == wanted {
                let secret: [u8; 32] = record.value.as_slice().try_into().map_err(|_| {
                    KeepError::CryptoErr(crate::error::CryptoError::invalid_key(
                        "stored per-group subkey is not 32 bytes".to_string(),
                    ))
                })?;
                return Ok(Some(secret));
            }
        }
        Ok(None)
    }

    /// Persist a share produced by [`frost::dkg::SoftwareDkgSession::finalize`]
    /// (#454). Wraps the finalized `KeyPackage` + `PublicKeyPackage` into a
    /// [`SharePackage`] with fresh metadata, encrypts under the vault's data
    /// key, stores it, and writes a `FrostShareImport` audit entry.
    ///
    /// `group_subkey_secret` is this device's per-group signing subkey (§3), kept
    /// with the share so recovery can prove membership (C1); pass `None` only for
    /// legacy shares that authenticated on the identity key.
    pub fn frost_store_dkg_share(
        &mut self,
        result: &crate::frost::dkg::SoftwareDkgResult,
        threshold: u16,
        total_shares: u16,
        name: &str,
        group_subkey_secret: Option<[u8; 32]>,
    ) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let name = name.trim();
        if name.is_empty() {
            return Err(KeepError::InvalidInput("name cannot be empty".into()));
        }
        if name.chars().count() > 64 {
            return Err(KeepError::InvalidInput(
                "name must be 64 characters or fewer".into(),
            ));
        }

        let mut metadata = crate::frost::ShareMetadata::new(
            result.our_index,
            threshold,
            total_shares,
            result.group_pubkey,
            name.to_string(),
        );
        if let Some(subkey_secret) = group_subkey_secret {
            metadata = metadata.with_group_subkey_secret(subkey_secret);
        }
        let share = crate::frost::SharePackage::new(
            metadata,
            &result.key_package,
            &result.public_key_package,
        )?;

        let data_key = self.get_data_key()?;
        let stored = StoredShare::encrypt(&share, &data_key)?;
        self.storage.store_share(&stored)?;

        self.audit_event(AuditEventType::FrostShareImport, |e| {
            e.with_group(&result.group_pubkey)
                .with_threshold(threshold)
                .with_participants(vec![result.our_index])
        });

        Ok(())
    }

    /// Refresh all FROST shares for a group, invalidating old shares.
    pub fn frost_refresh(&mut self, group_pubkey: &[u8; 32]) -> Result<Vec<frost::ShareMetadata>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let data_key = self.get_data_key()?;
        let all_shares = self.storage.list_shares()?;
        let group_shares: Vec<_> = all_shares
            .into_iter()
            .filter(|s| {
                s.metadata.group_pubkey == *group_pubkey
                    && s.ciphersuite == crate::frost::Ciphersuite::Secp256k1Tr
            })
            .collect();

        if group_shares.is_empty() {
            return Err(KeepError::KeyNotFound("No shares for group".into()));
        }

        let threshold = group_shares[0].metadata.threshold;
        let total = group_shares[0].metadata.total_shares;

        let share_count: u16 = group_shares
            .len()
            .try_into()
            .map_err(|_| KeepError::Frost("Too many shares".into()))?;
        if share_count != total {
            return Err(KeepError::Frost(format!(
                "refresh requires the full set of {total} shares; only {share_count} available. \
                 A partial refresh would orphan the absent shares (#586)."
            )));
        }

        let decrypted: Vec<SharePackage> = group_shares
            .iter()
            .map(|s| s.decrypt(&data_key))
            .collect::<Result<_>>()?;

        let (refreshed, _) = frost::refresh_shares(&decrypted)?;

        let encrypted_shares: Vec<StoredShare> = refreshed
            .iter()
            .map(|share| StoredShare::encrypt(share, &data_key))
            .collect::<Result<_>>()?;

        self.storage.store_shares_atomic(&encrypted_shares)?;

        let metadata: Vec<_> = refreshed.iter().map(|s| s.metadata.clone()).collect();
        let participants: Vec<u16> = metadata.iter().map(|m| m.identifier).collect();
        self.audit_event(AuditEventType::FrostShareRefresh, |e| {
            e.with_group(group_pubkey)
                .with_threshold(threshold)
                .with_participants(participants)
        });

        Ok(metadata)
    }

    /// Store the full verifying-share set for a share that was imported
    /// without it, once [`frost::complete_verifying_shares`] accepts the set.
    /// A share that already holds a complete set is left unchanged.
    pub fn frost_store_verifying_shares(
        &mut self,
        group_pubkey: &[u8; 32],
        identifier: u16,
        verifying_shares: &std::collections::BTreeMap<u16, [u8; 33]>,
    ) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let data_key = self.get_data_key()?;
        let stored = self.find_stored_share(
            group_pubkey,
            identifier,
            Some(crate::frost::Ciphersuite::Secp256k1Tr),
        )?;
        let share = stored.decrypt(&data_key)?;
        let Some(package) = frost::completed_pubkey_package(&share, verifying_shares)? else {
            return Ok(());
        };
        let updated = SharePackage::new(share.metadata.clone(), &share.key_package()?, &package)?;
        self.storage
            .store_share(&StoredShare::encrypt(&updated, &data_key)?)
    }

    /// Delete a FROST share.
    pub fn frost_delete_share(&mut self, group_pubkey: &[u8; 32], identifier: u16) -> Result<()> {
        self.storage.delete_share(group_pubkey, identifier)?;
        self.audit_event(AuditEventType::FrostShareDelete, |e| {
            e.with_group(group_pubkey)
                .with_participants(vec![identifier])
        });
        Ok(())
    }

    /// Rename a stored FROST share (updates its display name only).
    pub fn frost_rename_share(
        &mut self,
        group_pubkey: &[u8; 32],
        identifier: u16,
        name: &str,
    ) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let name = name.trim();
        if name.is_empty() {
            return Err(KeepError::InvalidInput(
                "share name must not be empty".into(),
            ));
        }
        if name.chars().count() > 64 {
            return Err(KeepError::InvalidInput(
                "share name must not exceed 64 characters".into(),
            ));
        }
        let mut stored = self.find_stored_share(group_pubkey, identifier, None)?;
        stored.metadata.name = name.to_string();
        self.storage.store_share(&stored)?;
        Ok(())
    }

    /// Get the hex-encoded group pubkey of the active share, if set.
    pub fn get_active_share_key(&self) -> Option<String> {
        std::fs::read_to_string(self.active_share_path())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| is_valid_hex_pubkey(s))
    }

    /// Set the active share by hex-encoded group pubkey. Pass `None` to clear.
    pub fn set_active_share_key(&self, key: Option<&str>) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let path = self.active_share_path();
        match key {
            Some(k) => {
                if !is_valid_hex_pubkey(k) {
                    return Err(KeepError::InvalidInput(
                        "Group pubkey must be 64 hex characters".into(),
                    ));
                }
                let normalized = k.to_ascii_lowercase();
                write_restricted(&path, normalized.as_bytes())?;
            }
            None => {
                if let Err(e) = std::fs::remove_file(&path) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        return Err(e.into());
                    }
                }
            }
        }
        Ok(())
    }

    fn active_share_path(&self) -> PathBuf {
        self.storage.path.join("active_share")
    }

    /// Store a finalized wallet descriptor, associated with a FROST group.
    pub fn store_wallet_descriptor(&self, descriptor: &WalletDescriptor) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.store_descriptor(descriptor)
    }

    /// Get the wallet descriptor for a FROST group.
    pub fn get_wallet_descriptor(
        &self,
        group_pubkey: &[u8; 32],
    ) -> Result<Option<WalletDescriptor>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.get_descriptor(group_pubkey)
    }

    /// List the latest-version wallet descriptor for every group. Older
    /// descriptor versions are not returned; use
    /// [`list_all_wallet_descriptor_versions`] when every row is required
    /// (backup, rotation re-encryption verification, etc.).
    ///
    /// [`list_all_wallet_descriptor_versions`]: Self::list_all_wallet_descriptor_versions
    pub fn list_wallet_descriptors(&self) -> Result<Vec<WalletDescriptor>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.list_descriptors()
    }

    /// List every persisted wallet descriptor row across all groups and
    /// versions. Used by backup and rotation paths that must round-trip every
    /// stored record.
    pub fn list_all_wallet_descriptor_versions(&self) -> Result<Vec<WalletDescriptor>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.list_all_descriptor_versions()
    }

    /// List every stored wallet descriptor version for one group, oldest first.
    pub fn list_wallet_descriptor_versions(
        &self,
        group_pubkey: &[u8; 32],
    ) -> Result<Vec<WalletDescriptor>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.list_descriptors_for_group(group_pubkey)
    }

    /// Delete a wallet descriptor.
    pub fn delete_wallet_descriptor(&self, group_pubkey: &[u8; 32]) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.delete_descriptor(group_pubkey)
    }

    /// Atomically insert or update a device registration on the descriptor for
    /// the given FROST group. Performs the load-modify-store under the
    /// storage's descriptor write lock so concurrent callers cannot drop each
    /// other's updates.
    pub fn upsert_device_registration(
        &self,
        group_pubkey: &[u8; 32],
        registration: DeviceRegistration,
    ) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage
            .upsert_device_registration(group_pubkey, registration)
    }

    /// Store a key health status record.
    pub fn store_health_status(&self, status: &wallet::KeyHealthStatus) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.store_health_status(status)
    }

    /// Get a key health status record.
    pub fn get_health_status(
        &self,
        group_pubkey: &[u8; 32],
        share_index: u16,
    ) -> Result<Option<wallet::KeyHealthStatus>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.get_health_status(group_pubkey, share_index)
    }

    /// List all key health status records.
    pub fn list_health_statuses(&self) -> Result<Vec<wallet::KeyHealthStatus>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.list_health_statuses()
    }

    /// List health statuses that are stale (not checked within the threshold).
    pub fn list_stale_health_statuses(&self, now: u64) -> Result<Vec<wallet::KeyHealthStatus>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let all = self.storage.list_health_statuses()?;
        Ok(all.into_iter().filter(|s| s.is_stale(now)).collect())
    }

    /// Store relay configuration for a FROST share.
    pub fn store_relay_config(&self, config: &RelayConfig) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let normalized_config = config.clone().normalize()?;
        self.storage.store_relay_config(&normalized_config)
    }

    /// Get relay configuration for a FROST share.
    pub fn get_relay_config(&self, group_pubkey: &[u8; 32]) -> Result<Option<RelayConfig>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.get_relay_config(group_pubkey)
    }

    /// Get relay configuration for a FROST share, returning defaults if none stored.
    pub fn get_relay_config_or_default(&self, group_pubkey: &[u8; 32]) -> Result<RelayConfig> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        Ok(self
            .storage
            .get_relay_config(group_pubkey)?
            .unwrap_or_else(|| RelayConfig::with_defaults(*group_pubkey)))
    }

    /// List all stored relay configurations.
    pub fn list_relay_configs(&self) -> Result<Vec<RelayConfig>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.list_relay_configs()
    }

    /// Delete relay configuration for a FROST share.
    pub fn delete_relay_config(&self, group_pubkey: &[u8; 32]) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.delete_relay_config(group_pubkey)
    }

    /// Get the kill switch state from the vault.
    pub fn get_kill_switch(&self) -> Result<bool> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.get_kill_switch()
    }

    /// Set the kill switch state in the vault.
    pub fn set_kill_switch(&self, active: bool) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.set_kill_switch(active)
    }

    /// Get the proxy configuration.
    pub fn get_proxy_config(&self) -> Result<ProxyConfig> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.get_proxy_config()
    }

    /// Set the proxy configuration.
    pub fn set_proxy_config(&self, config: &ProxyConfig) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.set_proxy_config(config)
    }

    /// Get a FROST share by group public key.
    pub fn frost_get_share(&self, group_pubkey: &[u8; 32]) -> Result<frost::SharePackage> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let data_key = self.get_data_key()?;
        let shares = self.storage.list_shares()?;
        let stored = shares
            .iter()
            .find(|s| {
                s.metadata.group_pubkey == *group_pubkey
                    && s.ciphersuite == crate::frost::Ciphersuite::Secp256k1Tr
            })
            .ok_or_else(|| KeepError::KeyNotFound("No shares for group".into()))?;

        stored.decrypt(&data_key)
    }

    /// Get a FROST share by group public key and identifier index.
    pub fn frost_get_share_by_index(
        &self,
        group_pubkey: &[u8; 32],
        identifier: u16,
    ) -> Result<frost::SharePackage> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let stored = self.find_stored_share(group_pubkey, identifier, None)?;
        let data_key = self.get_data_key()?;
        stored.decrypt(&data_key)
    }

    /// Sign using local FROST shares. Requires threshold shares locally.
    pub fn frost_sign(&mut self, group_pubkey: &[u8; 32], message: &[u8]) -> Result<[u8; 64]> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let (threshold, decrypted_shares) = self.local_threshold_shares(group_pubkey, message)?;

        match frost::sign_with_local_shares(&decrypted_shares, message) {
            Ok(sig) => {
                self.audit_event(AuditEventType::FrostSign, |e| {
                    e.with_group(group_pubkey)
                        .with_message_hash(message)
                        .with_threshold(threshold)
                });
                Ok(sig)
            }
            Err(e) => {
                self.audit_event(AuditEventType::FrostSignFailed, |e| {
                    e.with_group(group_pubkey)
                        .with_message_hash(message)
                        .with_success(false)
                });
                Err(e)
            }
        }
    }

    /// Decrypt `threshold` of this vault's secp256k1 shares of `group_pubkey`,
    /// recording a refusal (against `audit_hash`) when too few are held.
    fn local_threshold_shares(
        &mut self,
        group_pubkey: &[u8; 32],
        audit_hash: &[u8],
    ) -> Result<(u16, Vec<frost::SharePackage>)> {
        let data_key = self.get_data_key()?;
        let shares = self.storage.list_shares()?;
        let ours: Vec<_> = shares
            .iter()
            .filter(|s| {
                s.metadata.group_pubkey == *group_pubkey
                    && s.ciphersuite == crate::frost::Ciphersuite::Secp256k1Tr
            })
            .collect();
        let threshold = ours
            .first()
            .ok_or_else(|| KeepError::KeyNotFound("No shares for group".into()))?
            .metadata
            .threshold;
        if ours.len() < threshold as usize {
            self.audit_event(AuditEventType::FrostSignFailed, |e| {
                e.with_group(group_pubkey)
                    .with_message_hash(audit_hash)
                    .with_success(false)
                    .with_reason("Insufficient shares")
            });
            return Err(KeepError::Frost(format!(
                "Need {} shares to sign, only {} available",
                threshold,
                ours.len()
            )));
        }
        let decrypted = ours
            .iter()
            .take(threshold as usize)
            .map(|stored| stored.decrypt(&data_key))
            .collect::<Result<Vec<_>>>()?;
        Ok((threshold, decrypted))
    }

    /// Sign key-path spends of the group's taproot outputs with local shares, one
    /// per request. Every signature is checked against the output key of its
    /// scriptPubKey, and all are made before any is returned or recorded: the
    /// audit log gets one entry per spend (its sighash and context) only once all
    /// have succeeded, or the failure. Requires threshold shares locally.
    pub fn frost_sign_key_path_spends(
        &mut self,
        group_pubkey: &[u8; 32],
        spends: &[frost::taproot::KeyPathSpendRequest],
    ) -> Result<Vec<[u8; 64]>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let first = spends
            .first()
            .ok_or_else(|| KeepError::InvalidInput("nothing to sign".into()))?;
        let (threshold, decrypted) = self.local_threshold_shares(group_pubkey, &first.sighash)?;

        let mut signatures = Vec::with_capacity(spends.len());
        for spend in spends {
            match frost::taproot::sign_key_path_spend_with_local_shares(
                &decrypted,
                &spend.sighash,
                &spend.path,
                spend.tweak,
                &spend.script_pubkey,
            ) {
                Ok(sig) => signatures.push(sig),
                Err(e) => {
                    self.audit_event(AuditEventType::FrostSignFailed, |ev| {
                        ev.with_group(group_pubkey)
                            .with_message_hash(&spend.sighash)
                            .with_success(false)
                            .with_reason(&spend.context)
                    });
                    return Err(e);
                }
            }
        }
        // These signatures move funds, so they are released only once recorded.
        for spend in spends {
            self.audit_event_required(AuditEventType::FrostSign, |e| {
                e.with_group(group_pubkey)
                    .with_message_hash(&spend.sighash)
                    .with_threshold(threshold)
                    .with_reason(&spend.context)
            })?;
        }
        Ok(signatures)
    }

    /// Generate a FROST-Ed25519 threshold key and store its shares.
    ///
    /// Shares are tagged with [`Ciphersuite::Ed25519`], which is bound into the
    /// at-rest AEAD AAD so they cannot be confused with secp256k1 shares.
    #[cfg(feature = "ed25519")]
    pub fn frost_generate_ed25519(
        &mut self,
        threshold: u16,
        total_shares: u16,
        name: &str,
    ) -> Result<Vec<SharePackage>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let config = ThresholdConfig::new(threshold, total_shares)?;
        let dealer = crate::frost::ed25519::TrustedDealer::new(config);
        let (shares, _) = dealer.generate(name)?;

        let data_key = self.get_data_key()?;
        for share in &shares {
            let stored = StoredShare::encrypt_with_ciphersuite(
                share,
                crate::frost::Ciphersuite::Ed25519,
                &data_key,
            )?;
            self.storage.store_share(&stored)?;
        }

        let group_pubkey = *shares[0].group_pubkey();
        let participants: Vec<u16> = shares.iter().map(|s| s.metadata.identifier).collect();
        self.audit_event(AuditEventType::FrostGenerate, |e| {
            e.with_group(&group_pubkey)
                .with_threshold(threshold)
                .with_participants(participants)
        });

        Ok(shares)
    }

    /// Sign a message with a threshold of local FROST-Ed25519 shares.
    ///
    /// Returns a detached 64-byte Ed25519 signature over the raw message
    /// (RFC 8032), verifiable by [`Keep::frost_verify_ed25519`] and by any
    /// standard Ed25519 verifier against the group public key.
    #[cfg(feature = "ed25519")]
    pub fn frost_sign_ed25519(
        &mut self,
        group_pubkey: &[u8; 32],
        message: &[u8],
    ) -> Result<[u8; 64]> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let decrypted_shares = match self.frost_ed25519_decrypt_threshold_shares(group_pubkey) {
            Ok(shares) => shares,
            Err(e) => {
                self.audit_event(AuditEventType::FrostSignFailed, |ev| {
                    ev.with_group(group_pubkey)
                        .with_message_hash(message)
                        .with_success(false)
                        .with_reason("Insufficient shares")
                });
                return Err(e);
            }
        };
        let threshold = decrypted_shares[0].metadata.threshold;

        match crate::frost::ed25519::sign_with_local_shares(&decrypted_shares, message) {
            Ok(sig) => {
                self.audit_event(AuditEventType::FrostSign, |e| {
                    e.with_group(group_pubkey)
                        .with_message_hash(message)
                        .with_threshold(threshold)
                });
                Ok(sig)
            }
            Err(e) => {
                self.audit_event(AuditEventType::FrostSignFailed, |e| {
                    e.with_group(group_pubkey)
                        .with_message_hash(message)
                        .with_success(false)
                });
                Err(e)
            }
        }
    }

    /// Decrypt the threshold set of local Ed25519 shares for a group.
    ///
    /// Returns exactly `threshold` decrypted shares or a `KeyNotFound`/`Frost`
    /// error. Does not emit audit events; callers own audit semantics.
    #[cfg(feature = "ed25519")]
    fn frost_ed25519_decrypt_threshold_shares(
        &self,
        group_pubkey: &[u8; 32],
    ) -> Result<Vec<SharePackage>> {
        let data_key = self.get_data_key()?;
        let shares = self.storage.list_shares()?;
        let our_shares: Vec<_> = shares
            .iter()
            .filter(|s| {
                s.metadata.group_pubkey == *group_pubkey
                    && s.ciphersuite == crate::frost::Ciphersuite::Ed25519
            })
            .collect();

        if our_shares.is_empty() {
            return Err(KeepError::KeyNotFound("No Ed25519 shares for group".into()));
        }

        let threshold = our_shares[0].metadata.threshold;
        if our_shares.len() < threshold as usize {
            return Err(KeepError::Frost(format!(
                "Need {} shares to sign, only {} available",
                threshold,
                our_shares.len()
            )));
        }

        let mut decrypted_shares = Vec::with_capacity(threshold as usize);
        for stored in our_shares.iter().take(threshold as usize) {
            decrypted_shares.push(stored.decrypt(&data_key)?);
        }
        Ok(decrypted_shares)
    }

    /// Verify a detached Ed25519 signature against a group public key.
    #[cfg(feature = "ed25519")]
    pub fn frost_verify_ed25519(
        group_pubkey: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<()> {
        crate::frost::ed25519::verify(group_pubkey, message, signature)
    }

    /// Sign `message` and produce a minisign-compatible detached signature.
    ///
    /// Runs two FROST-Ed25519 threshold signing sessions: one over the
    /// BLAKE2b-512 prehash of the message (the `"ED"` file signature) and one
    /// over `file_signature || trusted_comment` (the global signature). The
    /// result verifies with the standard `minisign -V` tool against the
    /// exported group public key.
    #[cfg(feature = "ed25519")]
    pub fn frost_sign_ed25519_minisign(
        &mut self,
        group_pubkey: &[u8; 32],
        message: &[u8],
        untrusted_comment: String,
        trusted_comment: String,
    ) -> Result<crate::frost::ed25519::minisign::MinisignSignature> {
        use crate::frost::ed25519::minisign;

        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        minisign::validate_comment("untrusted", &untrusted_comment)?;
        minisign::validate_comment("trusted", &trusted_comment)?;

        let decrypted_shares = match self.frost_ed25519_decrypt_threshold_shares(group_pubkey) {
            Ok(shares) => shares,
            Err(e) => {
                self.audit_event(AuditEventType::FrostSignFailed, |ev| {
                    ev.with_group(group_pubkey)
                        .with_message_hash(message)
                        .with_success(false)
                        .with_reason("Insufficient shares")
                });
                return Err(e);
            }
        };
        let threshold = decrypted_shares[0].metadata.threshold;

        // Two independent threshold sessions over the same decrypted share set:
        // fresh nonces per session keep each signature secure.
        let prehash = minisign::prehash(message);
        let sign_both = (|| {
            let signature =
                crate::frost::ed25519::sign_with_local_shares(&decrypted_shares, &prehash)?;
            let global_bytes = minisign::global_signed_bytes(&signature, &trusted_comment);
            let global_signature =
                crate::frost::ed25519::sign_with_local_shares(&decrypted_shares, &global_bytes)?;
            Ok::<_, KeepError>((signature, global_signature))
        })();

        let (signature, global_signature) = match sign_both {
            Ok(pair) => {
                self.audit_event(AuditEventType::FrostSign, |e| {
                    e.with_group(group_pubkey)
                        .with_message_hash(message)
                        .with_threshold(threshold)
                });
                pair
            }
            Err(e) => {
                self.audit_event(AuditEventType::FrostSignFailed, |ev| {
                    ev.with_group(group_pubkey)
                        .with_message_hash(message)
                        .with_success(false)
                });
                return Err(e);
            }
        };

        Ok(minisign::MinisignSignature {
            sig_alg: minisign::ALG_PREHASHED,
            key_id: minisign::key_id(group_pubkey),
            signature,
            global_signature,
            untrusted_comment,
            trusted_comment,
        })
    }

    /// Verify a minisign-compatible detached signature against a group public
    /// key, checking both the file signature and the global signature using
    /// minisign's semantics (key-id match, prehash for `"ED"`, RFC 8032 strict
    /// cofactorless verification via frost-ed25519).
    #[cfg(feature = "ed25519")]
    pub fn frost_verify_ed25519_minisign(
        group_pubkey: &[u8; 32],
        message: &[u8],
        sig: &crate::frost::ed25519::minisign::MinisignSignature,
    ) -> Result<()> {
        use crate::frost::ed25519::minisign;

        if sig.key_id != minisign::key_id(group_pubkey) {
            return Err(KeepError::InvalidInput(
                "signature key id does not match group public key".into(),
            ));
        }

        let signed_message = match sig.sig_alg {
            minisign::ALG_PREHASHED => minisign::prehash(message).to_vec(),
            minisign::ALG_LEGACY => message.to_vec(),
            _ => {
                return Err(KeepError::InvalidInput(
                    "unknown signature algorithm".into(),
                ))
            }
        };

        crate::frost::ed25519::verify(group_pubkey, &signed_message, &sig.signature)?;

        let global_bytes = minisign::global_signed_bytes(&sig.signature, &sig.trusted_comment);
        crate::frost::ed25519::verify(group_pubkey, &global_bytes, &sig.global_signature)
    }

    fn load_keys_to_keyring(&mut self) -> Result<()> {
        let data_key = self.get_data_key()?;
        let records = self.storage.list_keys()?;

        for record in records {
            let encrypted = crypto::EncryptedData::from_bytes(&record.encrypted_secret)?;
            let secret_bytes = crypto::decrypt(&encrypted, &data_key)?;

            let mut secret = Zeroizing::new([0u8; 32]);
            let decrypted = secret_bytes.as_slice()?;
            secret.copy_from_slice(&decrypted);

            self.keyring
                .load_key(record.pubkey, *secret, record.key_type, record.name)?;
        }

        Ok(())
    }

    fn get_data_key(&self) -> Result<SecretKey> {
        self.storage.data_key().cloned().ok_or(KeepError::Locked)
    }

    /// Rotate the vault password.
    ///
    /// Re-encrypts the data encryption key with a new password-derived key.
    /// The data encryption key itself is unchanged, so stored secrets remain intact.
    ///
    /// Closes #579 (every post-storage-rotation failure path now emits a
    /// failure audit entry before propagating) and #580 (the success path
    /// uses `audit_event_required`, so a silent audit-write failure is
    /// surfaced as `KeepError::AuditWriteFailed`).
    pub fn rotate_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        let result = self.rotate_password_inner(old_password, new_password);
        match &result {
            Ok(()) => self.audit_event_required(AuditEventType::PasswordRotate, |e| e),
            Err(e) => {
                // Failed attempts are observable only when the vault was
                // unlocked before the call (audit log needs the data key).
                let reason = e.to_string();
                self.audit_event(AuditEventType::PasswordRotateFailed, |entry| {
                    entry.with_success(false).with_reason(&reason)
                });
                result
            }
        }
    }

    fn rotate_password_inner(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        self.storage.rotate_password(old_password, new_password)?;
        self.keyring.clear();
        self.load_keys_to_keyring()?;
        Ok(())
    }

    /// Rotate the data encryption key.
    ///
    /// Generates a new data encryption key and re-encrypts all stored keys and shares.
    ///
    /// Closes #579 (a failure before the storage commit audits
    /// DataKeyRotateFailed) and #580 (success path uses `audit_event_required`).
    pub fn rotate_data_key(&mut self, password: &str) -> Result<()> {
        // A locked vault has no data key, so the failure entry cannot be
        // encrypted/recorded here; `audit_event` no-ops in that case.
        let old_data_key = self.get_data_key()?;

        // Pre-commit phase. `storage.rotate_data_key` rolls back internally on
        // failure, so the on-disk data key is unchanged and the audit chains
        // still match `old_data_key` == the current data key. The failure entry
        // therefore encrypts under the key matching the on-disk chain (#579).
        // Noted under the old key, the rotation carries the note to the new
        // one, so a log a crash leaves under the old key is put down to it.
        self.storage.set_rotation_in_progress(true)?;
        if let Err(e) = self.storage.rotate_data_key(password) {
            if let Err(e) = self.storage.set_rotation_in_progress(false) {
                tracing::error!(error = %e, "the note of a rotation under way could not be cleared");
            }
            let reason = e.to_string();
            self.audit_event(AuditEventType::DataKeyRotateFailed, |entry| {
                entry.with_success(false).with_reason(&reason)
            });
            return Err(e);
        }

        // Post-commit phase. Storage has durably committed the new data key, so
        // the rotation has already succeeded on disk; the audit chains are still
        // under `old_data_key` until re-encrypted below. A failure here must NOT
        // emit a DataKeyRotateFailed entry: it would be encrypted under the new
        // key and appended to a chain still under the old key (corrupting it,
        // since `reencrypt` is atomic and leaves the file under the old key on
        // failure), and it would misreport a rotation that already committed.
        let new_data_key = self.get_data_key()?;
        // Each log is re-encrypted whatever happened to the other. One that
        // fails is still wholly under the old key, which no longer exists, so
        // it is opened again under the new key, which sets it aside beside a
        // new log with the failure recorded rather than locking the vault on
        // the next unlock.
        if let Some(Err(e)) = self
            .audit
            .as_mut()
            .map(|audit| audit.reencrypt(&old_data_key, &new_data_key))
        {
            tracing::error!(error = %e, "could not re-encrypt the audit log; setting it aside");
            self.audit = None;
            self.audit = Some(AuditLog::open(self.storage.path(), &new_data_key)?);
            // Recorded at once, so a crash before the rest of the rotation
            // finds the set-aside noted rather than a log behind the record.
            self.rebaseline_audit_record();
        }
        if let Some(Err(e)) = self
            .signing_audit
            .as_mut()
            .map(|log| log.reencrypt(&old_data_key, &new_data_key))
        {
            tracing::error!(error = %e, "could not re-encrypt the signing audit log; setting it aside");
            self.signing_audit = None;
            self.signing_audit = Some(SigningAuditLog::open(self.storage.path(), &new_data_key)?);
        }
        // The old audit logs a migration kept come last, and a failure there
        // does not stop the rotation: both live logs are already under the
        // new key, and the success entry below must still be written.
        if let Some(ref audit) = self.audit {
            if let Err(e) = audit.reencrypt_kept_logs(&old_data_key, &new_data_key) {
                tracing::error!(
                    error = %e,
                    "could not re-encrypt the old audit log a migration kept; it may no longer be readable"
                );
            }
        }
        if let Some(ref signing_audit) = self.signing_audit {
            if let Err(e) = signing_audit.reencrypt_kept_logs(&old_data_key, &new_data_key) {
                tracing::error!(
                    error = %e,
                    "could not re-encrypt a signing audit log that was set aside; it may no longer be readable"
                );
            }
        }

        // A log set aside above starts again from its migration entry: the
        // record notes the set-aside and moves to the new log, before the
        // next entry would find it behind.
        self.rebaseline_audit_record();
        // Both chains are now under `new_data_key`, so record the success entry
        // before reloading the keyring (#580 fails closed). The rotation has
        // already committed; the keyring is in-memory and rebuilt on the next
        // unlock, so a reload failure must not leave the rotation unrecorded.
        self.audit_event_required(AuditEventType::DataKeyRotate, |e| e)?;
        if let Err(e) = self.storage.set_rotation_in_progress(false) {
            tracing::error!(error = %e, "the note of a rotation under way could not be cleared");
        }

        self.keyring.clear();
        self.load_keys_to_keyring()
    }

    /// Move the record to the log as it is now, after this process itself
    /// re-encrypted the logs. A log set aside on the way (one that could not
    /// be re-encrypted, or another log found in its place) is noted for the
    /// owner; a log found behind the record without being set aside is
    /// noted as a rollback, never moved to silently.
    fn rebaseline_audit_record(&mut self) {
        let (Some(audit), Some(signing)) = (self.audit.as_ref(), self.signing_audit.as_ref())
        else {
            return;
        };
        let (seq, head) = (audit.seq(), audit.last_hash());
        let mut record = self.audit_record.clone().unwrap_or_default();
        let set_aside = audit
            .migrated_on_open()
            .filter(|m| !m.chain_valid)
            .map(|m| audit_record::SetAside {
                kept: m.kept.clone(),
                unreadable: m.unreadable,
                recorded_seq: record.seq,
                recorded_head: record.head,
                rotation: self.storage.rotation_in_progress(),
            });
        if let Some(kept) = signing.set_aside_on_open() {
            record.note_signing_set_aside(kept);
        }
        if let Some(set_aside) = set_aside {
            if !record.set_asides.iter().any(|s| s.kept == set_aside.kept) {
                record.note_set_aside(set_aside);
                record.seq = seq;
                record.head = head;
            }
        } else {
            record.observe(seq, head, true, chrono::Utc::now().timestamp());
        }
        if let Err(e) = self.save_audit_record(record) {
            tracing::error!(error = %e, "the record of the audit log could not be written");
        }
    }

    /// Returns the data encryption key used to encrypt stored secrets.
    ///
    /// # Errors
    /// Returns [`KeepError::Locked`] if [`unlock()`](Self::unlock) has not been called.
    ///
    /// Exposed for FROST/FrostSigner integration to decrypt stored shares.
    pub fn data_key(&self) -> Result<SecretKey> {
        self.get_data_key()
    }

    /// Store a pre-encrypted key record directly (for backup restore).
    pub(crate) fn restore_key_record(&self, record: &KeyRecord) -> Result<()> {
        self.get_data_key()?;
        self.storage.store_key(record)
    }

    /// Store a pre-encrypted share directly (for backup restore).
    pub(crate) fn restore_stored_share(&self, share: &StoredShare) -> Result<()> {
        self.get_data_key()?;
        self.storage.store_share(share)
    }

    fn audit_event<F>(&mut self, event_type: AuditEventType, builder: F)
    where
        F: FnOnce(AuditEntry) -> AuditEntry,
    {
        let data_key = match self.get_data_key() {
            Ok(k) => k,
            Err(_) => return,
        };
        if let Some(ref mut audit) = self.audit {
            let entry = builder(AuditEntry::new(event_type, audit.last_hash()));
            match audit.log(entry, &data_key) {
                Ok(()) => self.note_audit_place(),
                Err(e) => {
                    tracing::warn!("Failed to write audit log entry for {}: {}", event_type, e);
                }
            }
        }
    }

    /// Audit-write that propagates failure to the caller. Used for
    /// security-critical events where a silent best-effort log (#580) is
    /// unacceptable: a successful return MUST mean the audit entry was
    /// persisted. Fails closed when the vault is locked or the audit log is
    /// unavailable.
    fn audit_event_required<F>(&mut self, event_type: AuditEventType, builder: F) -> Result<()>
    where
        F: FnOnce(AuditEntry) -> AuditEntry,
    {
        let data_key = self.get_data_key()?;
        let audit = self.audit.as_mut().ok_or_else(|| {
            KeepError::AuditWriteFailed(format!(
                "audit log not initialized; cannot record required event {event_type}"
            ))
        })?;
        let entry = builder(AuditEntry::new(event_type, audit.last_hash()));
        audit
            .log(entry, &data_key)
            .map_err(|e| KeepError::AuditWriteFailed(format!("{event_type}: {e}")))?;
        self.note_audit_place();
        Ok(())
    }

    /// Read all audit log entries.
    pub fn audit_read_all(&self) -> Result<Vec<AuditEntry>> {
        let (audit, data_key) = self.audit_with_key()?;
        audit.read_all(&data_key)
    }

    /// Verify the integrity of the audit log chain.
    pub fn audit_verify_chain(&self) -> Result<bool> {
        let (audit, data_key) = self.audit_with_key()?;
        audit.verify_chain(&data_key)
    }

    /// Verify the audit log chain, and report the migration it records.
    pub fn audit_verify(&self) -> Result<AuditVerification> {
        let (audit, data_key) = self.audit_with_key()?;
        audit.verify(&data_key)
    }

    /// Export the audit log as JSON.
    pub fn audit_export(&self) -> Result<String> {
        let (audit, data_key) = self.audit_with_key()?;
        audit.export(&data_key)
    }

    fn audit_with_key(&self) -> Result<(&AuditLog, SecretKey)> {
        let audit = self.audit.as_ref().ok_or(KeepError::Locked)?;
        let data_key = self.get_data_key()?;
        Ok((audit, data_key))
    }

    /// Set the retention policy for the audit log.
    pub fn audit_set_retention(&mut self, policy: RetentionPolicy) {
        if let Some(ref mut audit) = self.audit {
            audit.set_retention(policy);
        }
    }

    /// Apply the retention policy and return the number of entries removed.
    pub fn audit_apply_retention(&mut self) -> Result<usize> {
        let data_key = self.get_data_key()?;
        let mut record = self.audit_record.clone();
        let storage = &self.storage;
        let audit = self.audit.as_mut().ok_or(KeepError::Locked)?;
        // The record notes where the log will end before the log is
        // replaced, so a stop before it follows finds the log continuing it.
        let removed = audit.apply_retention_noting(
            &data_key,
            Some(audit_record::RECORD_NOTE),
            |seq, hash| match record.as_mut() {
                Some(record) => {
                    record.retention_pending = Some((seq, hash));
                    let bytes =
                        serde_json::to_vec(record).map_err(|e| KeepError::Other(e.to_string()))?;
                    storage.set_config_bound(audit_record::AUDIT_RECORD_KEY, &bytes)
                }
                None => Ok(()),
            },
        )?;
        if record.is_some() {
            self.audit_record = record;
        }
        self.note_audit_place();
        Ok(removed)
    }

    /// Log a signing audit entry.
    pub fn signing_audit_log(&mut self, entry: SigningAuditEntry) -> Result<()> {
        let data_key = self.get_data_key()?;
        let log = self.signing_audit.as_mut().ok_or(KeepError::Locked)?;
        log.log(entry, &data_key)
    }

    /// Get the last hash of the signing audit chain.
    pub fn signing_audit_last_hash(&self) -> Result<[u8; 32]> {
        let log = self.signing_audit.as_ref().ok_or(KeepError::Locked)?;
        Ok(log.last_hash())
    }

    /// Read a page of signing audit entries with metadata in a single decryption pass.
    pub fn signing_audit_read_page_with_metadata(
        &self,
        offset: usize,
        limit: usize,
        caller_filter: Option<&str>,
    ) -> Result<(Vec<SigningAuditEntry>, Vec<String>, usize)> {
        let (log, data_key) = self.signing_audit_with_key()?;
        log.read_page_with_metadata(&data_key, offset, limit, caller_filter)
    }

    /// Verify the integrity of the signing audit chain and return the entry count.
    pub fn signing_audit_verify_chain(&self) -> Result<(bool, usize)> {
        let (log, data_key) = self.signing_audit_with_key()?;
        log.verify_chain(&data_key)
    }

    fn signing_audit_with_key(&self) -> Result<(&SigningAuditLog, SecretKey)> {
        let log = self.signing_audit.as_ref().ok_or(KeepError::Locked)?;
        let data_key = self.get_data_key()?;
        Ok((log, data_key))
    }
}

fn is_valid_hex_pubkey(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn write_restricted(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(data)
}

/// Returns the default path to the Keep directory (~/.keep).
/// Override with the `KEEP_HOME` environment variable.
pub fn default_keep_path() -> Result<PathBuf> {
    match std::env::var("KEEP_HOME") {
        Ok(val) if !val.trim().is_empty() => {
            let path = PathBuf::from(&val);
            if path.is_absolute() {
                Ok(path)
            } else {
                Err(KeepError::InvalidInput(
                    "KEEP_HOME must be an absolute path".into(),
                ))
            }
        }
        _ => dirs::home_dir()
            .map(|p| p.join(".keep"))
            .ok_or(KeepError::HomeNotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_keep(path: &Path) -> Keep {
        Storage::create(path, "testpass", crypto::Argon2Params::TESTING).unwrap();
        let mut keep = Keep::open(path).unwrap();
        keep.unlock("testpass").unwrap();
        keep
    }

    fn audited(keep: &Keep, event: AuditEventType, id: &[u8; 32]) -> bool {
        keep.audit_read_all()
            .unwrap()
            .iter()
            .any(|e| e.event_type == event && e.pubkey.as_deref() == Some(&hex::encode(id)))
    }

    fn agent_entries(keep: &Keep, event: AuditEventType) -> Vec<String> {
        keep.audit_read_all()
            .unwrap()
            .into_iter()
            .filter(|e| e.event_type == event)
            .filter_map(|e| e.reason)
            .collect()
    }

    fn unix_now() -> u64 {
        u64::try_from(chrono::Utc::now().timestamp()).unwrap()
    }

    fn refusal(keep: &Keep, token: &str, uid: u32, now: u64) -> crate::agent::AgentRefusal {
        keep.authenticate_agent(token, uid, now)
            .unwrap()
            .unwrap_err()
            .reason
    }

    fn accepted(keep: &Keep, token: &str, uid: u32, now: u64) -> crate::agent::AgentCredential {
        keep.authenticate_agent(token, uid, now).unwrap().unwrap()
    }

    /// An issued token authenticates only from its own uid, only while live,
    /// and never once revoked; the lifecycle is audited with the credential id
    /// and a hash of the grant, never the owner's label.
    #[test]
    fn an_agent_credential_authenticates_until_revoked() {
        use crate::agent::AgentRefusal;
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        let (credential, token) = keep
            .issue_agent_credential("claude", 1000, b"grant".to_vec(), unix_now(), 3600)
            .unwrap();
        let id = credential.id_hex();
        let now = unix_now();
        assert_eq!(accepted(&keep, &token, 1000, now), credential);
        assert_eq!(refusal(&keep, &token, 1001, now), AgentRefusal::WrongUid);
        assert_eq!(
            refusal(&keep, &token, 1000, credential.expires_at),
            AgentRefusal::Expired
        );
        assert_eq!(refusal(&keep, &token, 1000, 0), AgentRefusal::ClockBehind);
        assert_eq!(
            refusal(&keep, &token[1..], 1000, now),
            AgentRefusal::Unknown
        );
        let (_, other) = keep
            .issue_agent_credential("other", 1000, Vec::new(), now, 3600)
            .unwrap();
        assert_ne!(accepted(&keep, &other, 1000, now).id, credential.id);
        let issued = agent_entries(&keep, AuditEventType::AgentCredentialIssue);
        let grant_hash = hex::encode(crate::crypto::blake2b_256(b"grant"));
        assert!(
            issued[0].contains(&format!("agent {id} uid 1000 expires")),
            "{issued:?}"
        );
        assert!(issued[0].contains(&grant_hash), "{issued:?}");
        assert!(!issued[0].contains("claude"), "{issued:?}");

        assert_eq!(
            keep.authenticate_agent(&token[1..], 1000, now)
                .unwrap()
                .unwrap_err()
                .credential,
            None
        );
        keep.revoke_agent_credential(&credential.id).unwrap();
        assert_eq!(refusal(&keep, &token, 1000, now), AgentRefusal::Revoked);
        assert_eq!(
            keep.authenticate_agent(&token, 1000, now)
                .unwrap()
                .unwrap_err()
                .credential,
            Some(credential.id)
        );
        assert!(agent_entries(&keep, AuditEventType::AgentCredentialRevoke)[0].contains(&id));

        keep.lock();
        keep.unlock("testpass").unwrap();
        assert_eq!(
            refusal(&keep, &token, 1000, now),
            AgentRefusal::Revoked,
            "revocation persists"
        );
        accepted(&keep, &other, 1000, now);
    }

    /// A frozen credential, or every credential under the vault-wide freeze, is
    /// refused until unfrozen.
    #[test]
    fn frozen_agent_credentials_are_refused() {
        use crate::agent::AgentRefusal;
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        let (credential, token) = keep
            .issue_agent_credential("claude", 1000, Vec::new(), unix_now(), 3600)
            .unwrap();
        let now = unix_now();
        keep.set_agent_credential_frozen(&credential.id, true)
            .unwrap();
        assert_eq!(refusal(&keep, &token, 1000, now), AgentRefusal::Frozen);
        keep.set_agent_credential_frozen(&credential.id, false)
            .unwrap();
        accepted(&keep, &token, 1000, now);
        keep.set_agent_freeze(true).unwrap();
        assert_eq!(refusal(&keep, &token, 1000, now), AgentRefusal::Frozen);
        keep.set_agent_freeze(false).unwrap();
        accepted(&keep, &token, 1000, now);
        assert_eq!(agent_entries(&keep, AuditEventType::AgentFreeze).len(), 2);
        assert_eq!(agent_entries(&keep, AuditEventType::AgentUnfreeze).len(), 2);
    }

    /// A vault-wide freeze flag that cannot be read counts as frozen.
    #[test]
    fn an_unreadable_agent_freeze_refuses_every_credential() {
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        let (_, token) = keep
            .issue_agent_credential("claude", 1000, Vec::new(), unix_now(), 3600)
            .unwrap();
        accepted(&keep, &token, 1000, unix_now());
        keep.storage
            .put_raw(
                crate::backend::CONFIG_TABLE,
                crate::storage::AGENT_FREEZE,
                b"not ciphertext",
            )
            .unwrap();
        assert_eq!(
            refusal(&keep, &token, 1000, unix_now()),
            crate::agent::AgentRefusal::Frozen
        );
    }

    /// A credential row copied under another key is refused, not taken for a
    /// second credential, and a revoked credential is never reinstated.
    #[test]
    fn copied_or_reinstated_agent_credentials_are_refused() {
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        let (credential, token) = keep
            .issue_agent_credential("claude", 1000, Vec::new(), unix_now(), 3600)
            .unwrap();
        let mut reinstated = credential.clone();
        keep.revoke_agent_credential(&credential.id).unwrap();
        reinstated.revoked = false;
        assert!(matches!(
            keep.storage.insert_agent_credential(&reinstated),
            Err(KeepError::AlreadyExists(_))
        ));
        let mut extended = credential.clone();
        extended.revoked = true;
        extended.expires_at += 1;
        assert!(keep.storage.update_agent_credential(&extended).is_err());
        let err = keep
            .storage
            .update_agent_credential(&reinstated)
            .unwrap_err();
        assert!(err.to_string().contains("cannot be reinstated"), "{err}");

        let table = crate::backend::AGENT_CREDENTIALS_TABLE;
        let stored = keep
            .storage
            .list_raw(table)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .1;
        keep.storage.put_raw(table, &[0xff; 16], &stored).unwrap();
        assert!(keep.agent_credentials().is_err());
        let ids = keep.agent_credential_ids().unwrap();
        assert!(ids.contains(&[0xff; 16]) && ids.contains(&credential.id));
        assert!(keep.authenticate_agent(&token, 1000, unix_now()).is_err());
    }

    /// Freezing again what is frozen moves the epoch with no entry, and is
    /// refused for what is not frozen.
    #[test]
    fn a_refreeze_moves_the_epoch_without_an_entry() {
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        let (credential, _) = keep
            .issue_agent_credential("claude", 1000, Vec::new(), unix_now(), 3600)
            .unwrap();
        assert!(keep.refreeze_agent(None, &[]).is_err());
        assert!(keep.refreeze_agent(Some(&credential.id), &[]).is_err());
        let e0 = keep.agent_freeze_epoch().unwrap();
        keep.set_agent_credential_frozen(&credential.id, true)
            .unwrap();
        keep.set_agent_freeze(true).unwrap();
        let entries = keep.audit_read_all().unwrap().len();
        assert_eq!(
            keep.refreeze_agent(Some(&credential.id), &[]).unwrap(),
            e0 + 3
        );
        assert_eq!(
            keep.refreeze_agent(None, &[(b"ledger", b"x")]).unwrap(),
            e0 + 4
        );
        assert_eq!(keep.audit_read_all().unwrap().len(), entries);
        assert_eq!(
            keep.load_agent_ledger(b"ledger")
                .unwrap()
                .unwrap()
                .as_slice(),
            b"x"
        );
        assert!(keep.agent_freeze().unwrap());
    }

    /// Without a writable audit log, nothing is issued and nothing is
    /// unfrozen, while revoking and freezing still take effect.
    #[test]
    fn agent_credential_changes_that_loosen_need_the_audit_log() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        let (credential, token) = keep
            .issue_agent_credential("claude", 1000, Vec::new(), unix_now(), 3600)
            .unwrap();
        let (second, second_token) = keep
            .issue_agent_credential("second", 1000, Vec::new(), unix_now(), 3600)
            .unwrap();
        keep.set_agent_credential_frozen(&second.id, true).unwrap();
        let audit = path.join("audit.log");
        std::fs::remove_file(&audit).unwrap();
        std::fs::create_dir(&audit).unwrap();

        let err = keep
            .issue_agent_credential("unaudited", 1000, Vec::new(), unix_now(), 3600)
            .unwrap_err();
        assert!(matches!(err, KeepError::AuditWriteFailed(_)), "{err}");
        assert_eq!(keep.agent_credentials().unwrap().len(), 2, "nothing issued");

        assert!(keep.set_agent_credential_frozen(&second.id, false).is_err());
        refusal(&keep, &second_token, 1000, unix_now());
        assert!(keep.set_agent_freeze(true).is_ok());
        assert!(keep.set_agent_freeze(false).is_err());
        keep.revoke_agent_credential(&credential.id).unwrap();
        refusal(&keep, &token, 1000, unix_now());
    }

    /// A vault holds a bounded number of credentials, which can still be
    /// revoked and frozen when full; deleting one frees its slot and drops its
    /// ledger with it.
    #[test]
    fn agent_credentials_are_capped_and_deletable() {
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        let mut ids = Vec::new();
        for i in 0..crate::agent::MAX_AGENT_CREDENTIALS {
            let (c, _) = keep
                .issue_agent_credential(&format!("a{i}"), 1000, Vec::new(), unix_now(), 3600)
                .unwrap();
            ids.push(c.id);
        }
        let err = keep
            .issue_agent_credential("one too many", 1000, Vec::new(), unix_now(), 3600)
            .unwrap_err();
        assert!(err.to_string().contains("at most"), "{err}");
        keep.revoke_agent_credential(&ids[1]).unwrap();
        keep.set_agent_credential_frozen(&ids[2], true).unwrap();

        keep.update_agent_ledgers(&[&ids[0], b"wallet"], |_| {
            Ok(vec![b"ledger".to_vec(), b"w".to_vec()])
        })
        .unwrap();
        keep.delete_agent_credential(&ids[0]).unwrap();
        assert!(
            agent_entries(&keep, AuditEventType::AgentCredentialDelete)[0]
                .contains(&hex::encode(ids[0]))
        );
        assert!(keep.load_agent_ledger(&ids[0]).unwrap().is_none());
        assert_eq!(
            keep.load_agent_ledger(b"wallet")
                .unwrap()
                .unwrap()
                .as_slice(),
            b"w"
        );
        assert!(keep
            .issue_agent_credential("fits again", 1000, Vec::new(), unix_now(), 3600)
            .is_ok());
        assert!(matches!(
            keep.delete_agent_credential(&ids[0]),
            Err(KeepError::NotFound(_))
        ));

        // A ledger written after its credential was deleted can still be removed.
        keep.update_agent_ledgers(&[&ids[0]], |_| Ok(vec![b"orphan".to_vec()]))
            .unwrap();
        keep.delete_agent_credential(&ids[0]).unwrap();
        assert!(keep.load_agent_ledger(&ids[0]).unwrap().is_none());
    }

    /// A ledger update sees the current ledgers and writes all of its
    /// replacements, or none of them when it fails.
    #[test]
    fn agent_ledger_updates_are_all_or_nothing() {
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        let keys: [&[u8]; 2] = [b"credential", b"wallet"];
        keep.update_agent_ledgers(&keys, |current| {
            assert!(current.iter().all(Option::is_none));
            Ok(vec![b"1".to_vec(), b"10".to_vec()])
        })
        .unwrap();
        let err = keep
            .update_agent_ledgers(&keys, |current| {
                assert_eq!(current[0].as_deref().map(Vec::as_slice), Some(&b"1"[..]));
                Err(KeepError::invalid_input("over budget"))
            })
            .unwrap_err();
        assert!(err.to_string().contains("over budget"));
        assert!(keep
            .update_agent_ledgers(&keys, |_| Ok(vec![b"only one".to_vec()]))
            .is_err());
        let err = keep
            .update_agent_ledgers(&[b"credential", b"credential"], |_| {
                Ok(vec![b"2".to_vec(), b"3".to_vec()])
            })
            .unwrap_err();
        assert!(err.to_string().contains("each ledger once"), "{err}");
        assert_eq!(
            keep.load_agent_ledger(b"credential")
                .unwrap()
                .unwrap()
                .as_slice(),
            b"1"
        );
        assert_eq!(
            keep.load_agent_ledger(b"wallet")
                .unwrap()
                .unwrap()
                .as_slice(),
            b"10"
        );
    }

    /// Revealing a plain secret's value leaves a `SecretReveal` entry, like a
    /// sealed reveal; a sealed secret is refused here (it needs its quorum).
    #[test]
    fn revealing_a_plain_secret_is_audited() {
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        let record = crate::secret::SecretRecord::new(
            "api".into(),
            crate::secret::SecretKind::ApiToken,
            b"tok".to_vec(),
        )
        .unwrap();
        keep.store_secret(&record).unwrap();
        assert!(!audited(&keep, AuditEventType::SecretReveal, &record.id));
        assert_eq!(keep.reveal_secret(&record.id).unwrap().as_slice(), b"tok");
        assert!(audited(&keep, AuditEventType::SecretReveal, &record.id));

        keep.lock();
        assert!(
            keep.reveal_secret(&record.id).is_err(),
            "nothing is revealed from a locked vault"
        );
    }

    /// No value is revealed when its `SecretReveal` entry cannot be written,
    /// plain or sealed.
    #[test]
    fn a_reveal_that_cannot_be_recorded_returns_nothing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        let plain = crate::secret::SecretRecord::new(
            "p".into(),
            crate::secret::SecretKind::Generic,
            b"v".to_vec(),
        )
        .unwrap();
        keep.store_secret(&plain).unwrap();
        let sealed = crate::secret::SecretRecord::new(
            "s".into(),
            crate::secret::SecretKind::Generic,
            b"v".to_vec(),
        )
        .unwrap();
        let oprf_key = crate::crypto::SecretKey::from_slice(&[9u8; 32]).unwrap();
        let sealed = keep.store_sealed_secret(sealed, &oprf_key, 0).unwrap();
        assert_eq!(
            &*keep.reveal_sealed_secret(&sealed.id, &oprf_key).unwrap(),
            b"v"
        );

        let audit = path.join("audit.log");
        std::fs::remove_file(&audit).unwrap();
        std::fs::create_dir(&audit).unwrap();
        let err = keep.reveal_secret(&plain.id).unwrap_err();
        assert!(matches!(err, KeepError::AuditWriteFailed(_)), "{err}");
        let err = keep
            .reveal_sealed_secret(&sealed.id, &oprf_key)
            .unwrap_err();
        assert!(matches!(err, KeepError::AuditWriteFailed(_)), "{err}");
    }

    /// Agent signatures stop short of the log's read cap, leaving room for the
    /// owner's entries, so an agent cannot make the log unreadable.
    #[test]
    fn agent_signatures_stop_before_the_audit_log_fills() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        let audit = path.join("audit.log");
        let lines = |p: &Path| {
            std::fs::read(p).map_or(0, |b| {
                b.split(|&c| c == b'\n').filter(|l| !l.is_empty()).count()
            })
        };
        keep.lock();
        let before = lines(&audit);
        keep.unlock("testpass").unwrap();
        let per_unlock = lines(&audit) - before;
        keep.lock();

        let ceiling = crate::audit::MAX_AUDIT_ENTRIES - AGENT_AUDIT_HEADROOM;
        let filler = ceiling - 1 - lines(&audit) - per_unlock;
        let mut long = b"x\n".repeat(filler);
        long.extend_from_slice(&std::fs::read(&audit).unwrap());
        std::fs::write(&audit, long).unwrap();
        keep.unlock("testpass").unwrap();

        keep.record_agent_signature(&[1; 32], b"m", "last").unwrap();
        let err = keep
            .record_agent_signature(&[1; 32], b"m", "over")
            .unwrap_err();
        assert!(err.to_string().contains("audit log is full"), "{err}");
        let err = keep
            .record_agent_refusal(&[2; 16], "over", None)
            .unwrap_err();
        assert!(err.to_string().contains("audit log is full"), "{err}");
        let err = keep
            .record_agent_served(&[2; 16], "over", None)
            .unwrap_err();
        assert!(err.to_string().contains("audit log is full"), "{err}");
        assert_eq!(
            lines(&audit),
            ceiling,
            "the refused signature, refusal and served entry wrote nothing"
        );
        keep.audit_event_required(AuditEventType::VaultLock, |e| e)
            .unwrap();
    }

    /// A refused agent request is recorded as a failure with its credential,
    /// the gateway's label and the agent's text capped, escaped and quoted; a
    /// refusal that cannot be recorded fails.
    #[test]
    fn agent_refusals_are_recorded_fail_closed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        let id = hex::encode([7u8; 16]);
        keep.record_agent_refusal(&[7; 16], "deny", Some("kind 4\nOK agent_unfreeze"))
            .unwrap();
        keep.record_agent_refusal(&[7; 16], "deny x3", None)
            .unwrap();
        keep.record_agent_refusal(&[7; 16], "deny", Some(&"a".repeat(1 << 16)))
            .unwrap();
        let refused: Vec<_> = keep
            .audit_read_all()
            .unwrap()
            .into_iter()
            .filter(|e| e.event_type == AuditEventType::AgentRefused)
            .collect();
        assert!(refused.iter().all(|e| !e.success));
        let reasons: Vec<_> = refused.iter().filter_map(|e| e.reason.clone()).collect();
        assert_eq!(
            reasons[0],
            format!("agent {id} deny \"kind 4\\nOK agent_unfreeze\"")
        );
        assert_eq!(reasons[1], format!("agent {id} deny x3"));
        assert!(
            reasons[2].len() < crate::agent::MAX_AUDIT_TEXT + 64,
            "{}",
            reasons[2].len()
        );
        for label in ["", "a\nb", &"a".repeat(65)] {
            assert!(
                keep.record_agent_refusal(&[7; 16], label, None).is_err(),
                "{label:?}"
            );
        }

        let audit = path.join("audit.log");
        std::fs::remove_file(&audit).unwrap();
        std::fs::create_dir(&audit).unwrap();
        assert!(matches!(
            keep.record_agent_refusal(&[7; 16], "again", None),
            Err(KeepError::AuditWriteFailed(_))
        ));
    }

    /// What an agent was served is recorded as a success, on the same terms as
    /// a refusal: a gateway label, the agent's text escaped, fail closed.
    #[test]
    fn agent_served_entries_are_recorded_fail_closed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        let id = hex::encode([7u8; 16]);
        keep.record_agent_served(&[7; 16], "get_nostr_pubkey", Some("a\"b\n"))
            .unwrap();
        let served: Vec<_> = keep
            .audit_read_all()
            .unwrap()
            .into_iter()
            .filter(|e| e.event_type == AuditEventType::AgentServed)
            .collect();
        assert_eq!(served.len(), 1);
        assert!(served[0].success);
        assert_eq!(
            served[0].reason.as_deref(),
            Some(format!("agent {id} get_nostr_pubkey \"a\\\"b\\n\"").as_str())
        );
        for label in ["", "a\nb", &"a".repeat(crate::agent::MAX_AUDIT_LABEL + 1)] {
            assert!(
                keep.record_agent_served(&[7; 16], label, None).is_err(),
                "{label:?}"
            );
        }
        assert!(keep
            .record_agent_served(&[7; 16], &"a".repeat(crate::agent::MAX_AUDIT_LABEL), None)
            .is_ok());

        let audit = path.join("audit.log");
        std::fs::remove_file(&audit).unwrap();
        std::fs::create_dir(&audit).unwrap();
        assert!(matches!(
            keep.record_agent_served(&[7; 16], "again", None),
            Err(KeepError::AuditWriteFailed(_))
        ));
    }

    /// The vault-wide agent freeze reads back as set, and reads as unfrozen
    /// when never set.
    #[test]
    fn the_agent_freeze_reads_back() {
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        assert!(!keep.agent_freeze().unwrap());
        keep.set_agent_freeze(true).unwrap();
        assert!(keep.agent_freeze().unwrap());
        keep.set_agent_freeze(false).unwrap();
        assert!(!keep.agent_freeze().unwrap());
        keep.lock();
        assert!(keep.agent_freeze().is_err(), "a locked vault cannot say");
    }

    /// An agent signature's context is capped and escaped like a refusal's.
    #[test]
    fn agent_signature_context_is_capped_and_escaped() {
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        keep.record_agent_signature(&[1; 32], b"m", &format!("x\ny{}", "z".repeat(1 << 16)))
            .unwrap();
        let reason = agent_entries(&keep, AuditEventType::Sign).remove(0);
        assert!(reason.starts_with("x\\ny"), "{reason:.20}");
        assert!(reason.len() <= crate::agent::MAX_AUDIT_TEXT + 2);
    }

    #[test]
    fn a_sealed_secret_is_not_revealed_without_its_quorum() {
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        let record = crate::secret::SecretRecord::new(
            "s".into(),
            crate::secret::SecretKind::Generic,
            b"v".to_vec(),
        )
        .unwrap();
        let oprf_key = crate::crypto::SecretKey::from_slice(&[9u8; 32]).unwrap();
        let stored = keep.store_sealed_secret(record, &oprf_key, 0).unwrap();
        let err = keep.reveal_secret(&stored.id).unwrap_err();
        assert!(err.to_string().contains("threshold-sealed"), "{err}");
        assert!(!audited(&keep, AuditEventType::SecretReveal, &stored.id));
    }

    /// A value too large to load back is refused when stored, not lost.
    #[test]
    fn a_secret_too_large_to_load_is_refused() {
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        let limit = crate::storage::MAX_RECORD_SIZE as usize;
        let big = crate::secret::SecretRecord::new(
            "big".into(),
            crate::secret::SecretKind::Generic,
            vec![7u8; limit],
        )
        .unwrap();
        let err = keep.store_secret(&big).unwrap_err();
        assert!(err.to_string().contains("secret too large"), "{err}");
        assert!(keep.load_secret(&big.id).is_err(), "nothing was stored");

        let fits = crate::secret::SecretRecord::new(
            "fits".into(),
            crate::secret::SecretKind::Generic,
            vec![7u8; limit - 1024],
        )
        .unwrap();
        keep.store_secret(&fits).unwrap();
        assert_eq!(
            keep.load_secret(&fits.id).unwrap().value.len(),
            limit - 1024
        );
    }

    #[test]
    fn active_share_key_set_get_roundtrip_and_clear() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let keep = test_keep(&path);

        assert_eq!(keep.get_active_share_key(), None, "absent by default");

        // Set an uppercase pubkey -> stored normalized to lowercase.
        let key = "AB".repeat(32);
        keep.set_active_share_key(Some(&key)).unwrap();
        assert_eq!(keep.get_active_share_key(), Some(key.to_ascii_lowercase()));

        // Clear, then clearing again (absent file) is not an error.
        keep.set_active_share_key(None).unwrap();
        assert_eq!(keep.get_active_share_key(), None);
        keep.set_active_share_key(None).unwrap();
    }

    #[test]
    fn active_share_key_rejects_invalid_and_requires_unlock() {
        let dir = tempdir().unwrap();
        let keep = test_keep(&dir.path().join("keep"));

        assert!(matches!(
            keep.set_active_share_key(Some("nothex")),
            Err(KeepError::InvalidInput(_))
        ));
        assert!(
            matches!(
                keep.set_active_share_key(Some(&"ab".repeat(31))),
                Err(KeepError::InvalidInput(_))
            ),
            "62 hex chars is not a valid 32-byte pubkey"
        );

        let mut locked = test_keep(&dir.path().join("keep2"));
        locked.lock();
        assert!(matches!(
            locked.set_active_share_key(Some(&"ab".repeat(32))),
            Err(KeepError::Locked)
        ));
    }

    #[test]
    fn active_share_key_get_ignores_garbage_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let keep = test_keep(&path);
        // A file whose content is not a valid hex pubkey is filtered out by get.
        std::fs::write(path.join("active_share"), b"not-a-valid-pubkey").unwrap();
        assert_eq!(keep.get_active_share_key(), None);
    }

    #[test]
    fn descriptor_snapshot_survives_lock() {
        // cmd_wallet_spend (keep-1ij5) snapshots the descriptor set while unlocked, then
        // locks the vault before the coordination wait so the master key is not resident.
        // The snapshot is owned, non-secret metadata, so it must stay usable after lock.
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        let group_pubkey = [0x11u8; 32];
        let descriptor = WalletDescriptor {
            group_pubkey,
            external_descriptor: format!("tr({})/0/*)", hex::encode(group_pubkey)),
            internal_descriptor: format!("tr({})/1/*)", hex::encode(group_pubkey)),
            network: "signet".into(),
            created_at: 1_700_000_000,
            device_registrations: Vec::new(),
            policy_hash: [0x22; 32],
            version: crate::wallet::INITIAL_DESCRIPTOR_VERSION,
            previous_descriptor_hash: None,
            policy: None,
        };
        keep.store_wallet_descriptor(&descriptor).unwrap();

        // Snapshot while unlocked (as the spend path does), then lock.
        let snapshot = keep.list_all_wallet_descriptor_versions().unwrap();
        assert!(snapshot.iter().any(|d| d.group_pubkey == group_pubkey));

        keep.lock();
        assert!(!keep.is_unlocked());
        // A live read now requires unlock, but the pre-lock snapshot the coordination
        // wait relies on is unaffected.
        assert!(keep.list_all_wallet_descriptor_versions().is_err());
        assert!(snapshot.iter().any(|d| d.group_pubkey == group_pubkey));
    }

    #[test]
    fn rate_limit_trip_emits_audit_entry_on_next_unlock() {
        // The rate limiter trips after MAX_ATTEMPTS (5) failed unlocks. The
        // trip event must surface as a `RateLimitTripped` audit entry the
        // next time the operator successfully unlocks (#495).
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        Storage::create(&path, "right-password", crypto::Argon2Params::TESTING).unwrap();

        // Five failed attempts trips the limiter.
        for _ in 0..5 {
            let mut keep = Keep::open(&path).unwrap();
            let _ = keep.unlock("wrong-password");
        }

        // The sixth attempt would hit the back-off; wait it out by clearing
        // the active rate-limit counter (the trip event lives in a separate
        // file that record_success deliberately does NOT touch).
        crate::rate_limit::record_success(&path);

        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("right-password").unwrap();

        let entries = keep.audit_read_all().unwrap();
        let trips: Vec<_> = entries
            .iter()
            .filter(|e| matches!(e.event_type, AuditEventType::RateLimitTripped))
            .collect();
        assert_eq!(trips.len(), 1, "expected one trip entry, got {trips:#?}");
        assert!(!trips[0].success, "trip entry must record success=false");
        assert!(
            trips[0]
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("rate limit")),
            "trip entry must carry a descriptive reason, got {:?}",
            trips[0].reason
        );

        // Chronological order: RateLimitTripped precedes the VaultUnlock it
        // was discovered by, so the audit chain reflects the actual sequence
        // of lockout then recovery.
        let trip_idx = entries
            .iter()
            .position(|e| matches!(e.event_type, AuditEventType::RateLimitTripped))
            .unwrap();
        let unlock_idx = entries
            .iter()
            .rposition(|e| matches!(e.event_type, AuditEventType::VaultUnlock))
            .unwrap();
        assert!(trip_idx < unlock_idx);

        // Subsequent unlocks don't re-emit the same trip.
        keep.lock();
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("right-password").unwrap();
        let entries = keep.audit_read_all().unwrap();
        let trip_count = entries
            .iter()
            .filter(|e| matches!(e.event_type, AuditEventType::RateLimitTripped))
            .count();
        assert_eq!(
            trip_count, 1,
            "trip entry must not duplicate on later unlocks"
        );
    }

    #[test]
    fn test_keep_create_and_unlock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        {
            let keep = Keep::create(&path, "password").unwrap();
            assert!(keep.is_unlocked());
        }

        {
            let mut keep = Keep::open(&path).unwrap();
            assert!(!keep.is_unlocked());
            keep.unlock("password").unwrap();
            assert!(keep.is_unlocked());
        }
    }

    #[test]
    fn test_keep_generate_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        let mut keep = test_keep(&path);
        let pubkey = keep.generate_key("test").unwrap();

        assert_eq!(keep.keyring().len(), 1);
        assert!(keep.keyring().get(&pubkey).is_some());
        assert!(keep.keyring().get_by_name("test").is_some());
    }

    #[test]
    fn test_keep_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        let mut keep = test_keep(&path);
        keep.generate_key("test").unwrap();
        assert!(keep.is_unlocked());

        keep.lock();
        assert!(!keep.is_unlocked());
        assert_eq!(keep.keyring().len(), 0);
    }

    #[test]
    fn test_keep_primary_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        let mut keep = test_keep(&path);
        assert!(keep.get_primary_key().is_none());

        keep.generate_key("first").unwrap();
        let primary = keep.get_primary_key().unwrap();
        assert_eq!(primary.name, "first");
    }

    #[test]
    fn test_frost_generate_and_sign() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        let mut keep = test_keep(&path);

        let shares = keep.frost_generate(2, 3, "frost-test").unwrap();
        assert_eq!(shares.len(), 3);

        let group_pubkey = *shares[0].group_pubkey();

        let message = b"test message to sign with FROST";
        let signature = keep.frost_sign(&group_pubkey, message).unwrap();

        assert_eq!(signature.len(), 64);

        let stored_shares = keep.frost_list_shares().unwrap();
        assert_eq!(stored_shares.len(), 3);
    }

    /// Local key-path spends: each signature verifies under its output key, and the
    /// audit log records each spend with its context only once all are signed; a
    /// spend that fails records the failure and nothing for the ones before it.
    #[test]
    fn local_key_path_spends_are_signed_then_audited() {
        use crate::frost::taproot::{self, KeyPathSpendRequest, TaprootTweak};
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        let shares = keep.frost_generate(2, 3, "spend-test").unwrap();
        let group = *shares[0].group_pubkey();
        let request = |path: Vec<u32>, sighash: [u8; 32], context: &str| {
            let internal = taproot::internal_key(&group, &path).unwrap();
            KeyPathSpendRequest {
                sighash,
                path,
                tweak: TaprootTweak::default(),
                script_pubkey: TaprootTweak::default().script_pubkey(&internal).unwrap(),
                context: context.into(),
            }
        };
        let spends = [
            request(vec![0, 1], [1; 32], "txid aa input 0"),
            request(vec![1, 2], [2; 32], "txid aa input 1"),
        ];
        let sigs = keep.frost_sign_key_path_spends(&group, &spends).unwrap();
        for (spend, sig) in spends.iter().zip(&sigs) {
            taproot::verify_key_path_signature(sig, &spend.sighash, &spend.script_pubkey).unwrap();
        }
        let signed: Vec<_> = keep
            .audit_read_all()
            .unwrap()
            .into_iter()
            .filter(|e| e.event_type == AuditEventType::FrostSign)
            .filter_map(|e| e.reason)
            .collect();
        assert_eq!(signed, vec!["txid aa input 0", "txid aa input 1"]);

        let mut bad = request(vec![0, 3], [3; 32], "txid bb input 1");
        bad.script_pubkey = request(vec![0, 4], [3; 32], "").script_pubkey;
        let before = keep.audit_read_all().unwrap().len();
        assert!(keep
            .frost_sign_key_path_spends(
                &group,
                &[request(vec![0, 5], [4; 32], "txid bb input 0"), bad]
            )
            .is_err());
        let after: Vec<_> = keep
            .audit_read_all()
            .unwrap()
            .into_iter()
            .skip(before)
            .collect();
        assert_eq!(after.len(), 1, "only the failure is recorded");
        assert_eq!(after[0].event_type, AuditEventType::FrostSignFailed);
        assert_eq!(after[0].reason.as_deref(), Some("txid bb input 1"));
    }

    #[test]
    fn test_frost_split_preserves_npub() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        let mut keep = test_keep(&path);

        let pubkey = keep.generate_key("to-split").unwrap();

        let shares = keep.frost_split("to-split", 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        let frost_pubkey = *shares[0].group_pubkey();
        assert_eq!(frost_pubkey, pubkey);

        let message = b"sign with split key";
        let signature = keep.frost_sign(&frost_pubkey, message).unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_frost_ed25519_generate_sign_verify() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        let shares = keep.frost_generate_ed25519(2, 3, "release").unwrap();
        assert_eq!(shares.len(), 3);
        let group_pubkey = *shares[0].group_pubkey();

        let message = b"release artifact v1.0";
        let signature = keep.frost_sign_ed25519(&group_pubkey, message).unwrap();
        assert_eq!(signature.len(), 64);

        Keep::frost_verify_ed25519(&group_pubkey, message, &signature).unwrap();
        assert!(Keep::frost_verify_ed25519(&group_pubkey, b"tampered", &signature).is_err());

        // Shares persisted across reopen carry the Ed25519 ciphersuite tag and
        // still sign after the versioned-blob round-trip through storage.
        drop(keep);
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        let sig2 = keep.frost_sign_ed25519(&group_pubkey, message).unwrap();
        Keep::frost_verify_ed25519(&group_pubkey, message, &sig2).unwrap();
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_frost_ed25519_export_import_sign() {
        let src_dir = tempdir().unwrap();
        let src_path = src_dir.path().join("keep");
        let mut src = test_keep(&src_path);

        let shares = src.frost_generate_ed25519(2, 3, "release").unwrap();
        let group_pubkey = *shares[0].group_pubkey();

        let exports: Vec<_> = shares
            .iter()
            .take(2)
            .map(|s| {
                let export = src
                    .frost_export_share(&group_pubkey, s.metadata.identifier, "transfer-pass")
                    .unwrap();
                assert_eq!(export.ciphersuite, crate::frost::Ciphersuite::Ed25519);
                export
            })
            .collect();

        let dst_dir = tempdir().unwrap();
        let dst_path = dst_dir.path().join("keep");
        let mut dst = test_keep(&dst_path);

        for (i, export) in exports.iter().enumerate() {
            dst.frost_import_share(export, "transfer-pass", &format!("imported-{i}"))
                .unwrap();
        }

        let message = b"exported then imported";
        let sig = dst.frost_sign_ed25519(&group_pubkey, message).unwrap();
        Keep::frost_verify_ed25519(&group_pubkey, message, &sig).unwrap();
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_frost_ed25519_data_key_rotation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        let shares = keep.frost_generate_ed25519(2, 3, "release").unwrap();
        let group_pubkey = *shares[0].group_pubkey();

        // Rotation re-encrypts the inner key package under the ciphersuite AAD
        // and verifies it; an Ed25519 vault must rotate without failing.
        keep.rotate_data_key("testpass").unwrap();

        let message = b"after rotation";
        let sig = keep.frost_sign_ed25519(&group_pubkey, message).unwrap();
        Keep::frost_verify_ed25519(&group_pubkey, message, &sig).unwrap();
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_frost_ed25519_minisign_round_trip() {
        use crate::frost::ed25519::minisign::MinisignSignature;

        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        let shares = keep.frost_generate_ed25519(2, 3, "release").unwrap();
        let group_pubkey = *shares[0].group_pubkey();

        let message = b"release artifact v2.0";
        let sig = keep
            .frost_sign_ed25519_minisign(
                &group_pubkey,
                message,
                "untrusted".into(),
                "trusted:abc".into(),
            )
            .unwrap();

        // Full struct verifies (file + global signatures).
        Keep::frost_verify_ed25519_minisign(&group_pubkey, message, &sig).unwrap();

        // Survives encode/parse round-trip.
        let encoded = sig.encode().unwrap();
        let parsed = MinisignSignature::parse(&encoded).unwrap();
        Keep::frost_verify_ed25519_minisign(&group_pubkey, message, &parsed).unwrap();

        // Tampered message rejected.
        assert!(Keep::frost_verify_ed25519_minisign(&group_pubkey, b"tampered", &parsed).is_err());

        // Tampered trusted comment breaks the global signature.
        let mut bad = MinisignSignature::parse(&encoded).unwrap();
        bad.trusted_comment = "trusted:evil".into();
        assert!(Keep::frost_verify_ed25519_minisign(&group_pubkey, message, &bad).is_err());

        // Wrong group public key fails the key-id check.
        let wrong = [0u8; 32];
        assert!(Keep::frost_verify_ed25519_minisign(&wrong, message, &parsed).is_err());
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_frost_ed25519_minisign_external_binary() {
        use crate::frost::ed25519::minisign::MinisignPublicKey;
        use std::process::Command;

        // Prefer the C minisign binary; fall back to rsign2 (rsign), which is
        // byte-format compatible with minisign. Skip if neither is installed.
        let verifier = if Command::new("minisign").arg("-v").output().is_ok() {
            "minisign"
        } else if Command::new("rsign").arg("--help").output().is_ok() {
            "rsign"
        } else {
            eprintln!("no minisign/rsign binary installed; skipping external cross-check");
            return;
        };

        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        let shares = keep.frost_generate_ed25519(2, 3, "release").unwrap();
        let group_pubkey = *shares[0].group_pubkey();

        let data_path = dir.path().join("artifact.bin");
        std::fs::write(&data_path, b"external minisign cross-check payload").unwrap();
        let message = std::fs::read(&data_path).unwrap();

        let sig = keep
            .frost_sign_ed25519_minisign(
                &group_pubkey,
                &message,
                "keep test".into(),
                "timestamp:0\tfile:artifact.bin".into(),
            )
            .unwrap();
        let sig_path = dir.path().join("artifact.bin.minisig");
        std::fs::write(&sig_path, sig.encode().unwrap()).unwrap();

        let pk = MinisignPublicKey::from_group_pubkey(&group_pubkey, "keep test".into());
        let pk_path = dir.path().join("keep.pub");
        std::fs::write(&pk_path, pk.encode().unwrap()).unwrap();

        let output = match verifier {
            "minisign" => Command::new("minisign")
                .arg("-V")
                .arg("-p")
                .arg(&pk_path)
                .arg("-m")
                .arg(&data_path)
                .output()
                .expect("run minisign -V"),
            _ => Command::new("rsign")
                .arg("verify")
                .arg("-p")
                .arg(&pk_path)
                .arg("-x")
                .arg(&sig_path)
                .arg(&data_path)
                .output()
                .expect("run rsign verify"),
        };
        assert!(
            output.status.success(),
            "external verify ({verifier}) failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn test_frost_insufficient_shares_fails() {
        use crate::frost::{SigningSession, ThresholdConfig, TrustedDealer};

        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let message = b"test".to_vec();
        let kp0 = shares[0].key_package().unwrap();

        let mut session = SigningSession::new(message, 2).unwrap();
        session.generate_commitment(&kp0).unwrap();

        assert_eq!(session.commitments_needed(), 1);
        assert!(!session.is_complete());
    }

    #[test]
    fn test_keep_rotate_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        {
            let mut keep = test_keep(&path);
            keep.generate_key("rotatetest").unwrap();
        }

        {
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("testpass").unwrap();
            keep.rotate_password("testpass", "newpass1").unwrap();
        }

        {
            let mut keep = Keep::open(&path).unwrap();
            assert!(keep.unlock("testpass").is_err());
        }

        {
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("newpass1").unwrap();
            assert!(keep.keyring().get_by_name("rotatetest").is_some());
        }
    }

    #[test]
    fn test_is_valid_hex_pubkey() {
        let valid = "a".repeat(64);
        assert!(is_valid_hex_pubkey(&valid));

        let mixed_hex = "0123456789abcdef".repeat(4);
        assert!(is_valid_hex_pubkey(&mixed_hex));

        // is_ascii_hexdigit accepts A-F; set_active_share_key normalizes
        // to lowercase before persisting.
        let upper = "A".repeat(64);
        assert!(is_valid_hex_pubkey(&upper));

        assert!(!is_valid_hex_pubkey(&"a".repeat(63)));
        assert!(!is_valid_hex_pubkey(&"a".repeat(65)));
        assert!(!is_valid_hex_pubkey(""));
        assert!(!is_valid_hex_pubkey(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ));
    }

    #[test]
    fn test_keep_rotate_data_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        let pubkey;
        {
            let mut keep = test_keep(&path);
            pubkey = keep.generate_key("dektest").unwrap();
        }

        {
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("testpass").unwrap();
            keep.rotate_data_key("testpass").unwrap();
            assert!(keep.keyring().get(&pubkey).is_some());
        }

        {
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("testpass").unwrap();
            let slot = keep.keyring().get(&pubkey).unwrap();
            assert_eq!(slot.name, "dektest");
        }
    }

    // === #566: audit-log entries for rotation security operations ===

    /// `Keep::rotate_password` MUST emit a `PasswordRotate` audit entry on
    /// success. Without this, security-sensitive password rotations leave no
    /// observable trace for the operator or for post-incident review.
    #[test]
    fn rotate_password_emits_success_audit_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        {
            let mut keep = test_keep(&path);
            keep.generate_key("audited").unwrap();
            keep.rotate_password("testpass", "newpass1").unwrap();
            let entries = keep.audit_read_all().unwrap();
            assert!(
                entries
                    .iter()
                    .any(|e| e.event_type == AuditEventType::PasswordRotate),
                "PasswordRotate entry missing from audit log: {:?}",
                entries.iter().map(|e| e.event_type).collect::<Vec<_>>()
            );
        }
        // Re-open with the NEW password to confirm the audit log survived the
        // header rotation and still chain-verifies.
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("newpass1").unwrap();
        keep.audit_verify_chain().unwrap();
        let entries = keep.audit_read_all().unwrap();
        assert!(entries
            .iter()
            .any(|e| e.event_type == AuditEventType::PasswordRotate));
    }

    /// `Keep::rotate_password` MUST emit a `PasswordRotateFailed` audit entry
    /// when the call is rejected, so failed attacker attempts are observable.
    /// Failed attempts on an already-locked vault cannot be recorded (data
    /// key unavailable); this test exercises the unlocked path and uses an
    /// invalid new password as the failure trigger because Storage's
    /// `rotate_password` short-circuits the wrong-old-password check when
    /// the vault is already unlocked (which is the path that admits audit
    /// writes), while `validate_new_password` is enforced unconditionally.
    #[test]
    fn rotate_password_emits_failure_audit_entry_when_unlocked() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.generate_key("audited").unwrap();

        let pre = keep.audit_read_all().unwrap().len();

        // Empty new password: validate_new_password rejects.
        assert!(keep.rotate_password("testpass", "").is_err());
        let after_empty = keep.audit_read_all().unwrap();
        assert!(
            after_empty.len() > pre,
            "audit log should grow on empty-new-password rejection"
        );
        let failure = after_empty
            .iter()
            .find(|e| e.event_type == AuditEventType::PasswordRotateFailed)
            .expect("PasswordRotateFailed entry missing after empty-new-password rejection");
        assert!(
            !failure.success,
            "PasswordRotateFailed entry must be marked success=false"
        );
        assert!(
            failure.reason.is_some(),
            "PasswordRotateFailed entry must record a failure reason"
        );

        // Too-short new password: same rejection.
        let pre2 = keep.audit_read_all().unwrap().len();
        assert!(keep.rotate_password("testpass", "a").is_err());
        let entries = keep.audit_read_all().unwrap();
        assert!(
            entries.len() > pre2,
            "audit log should grow on too-short-new-password rejection"
        );
        // The original password still unlocks: failure paths don't corrupt
        // the header. Drop the first handle before reopening so the vault
        // file lock is released.
        drop(keep);
        let mut reopened = Keep::open(&path).unwrap();
        reopened.unlock("testpass").unwrap();
    }

    /// An old-format vault log migrates on unlock, the signing audit log is
    /// left exactly as it was, and a data key change keeps the kept old log
    /// readable under the new key.
    #[test]
    fn unlock_migrates_the_vault_log_and_rotation_keeps_the_old_one() {
        use crate::audit::test_support::write_format1_log;

        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let data_key = {
            let mut keep = test_keep(&path);
            keep.signing_audit_log(
                SigningAuditEntry::new(
                    crate::audit::SigningRequestType::SignEvent,
                    crate::audit::SigningDecision::Approved,
                    false,
                    "caller".into(),
                    keep.signing_audit_last_hash().unwrap(),
                )
                .finalize(),
            )
            .unwrap();
            keep.data_key().unwrap()
        };
        write_format1_log(
            &path,
            &data_key,
            vec![
                AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]),
                AuditEntry::new(AuditEventType::VaultLock, [0; 32]),
            ],
        );
        let signing = std::fs::read(path.join("signing_audit.log")).unwrap();
        let old = std::fs::read(path.join("audit.log")).unwrap();

        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert_eq!(
            std::fs::read(path.join("signing_audit.log")).unwrap(),
            signing
        );
        assert_eq!(std::fs::read(path.join("audit.log.v1")).unwrap(), old);
        assert!(set_aside(&keep).is_none());
        let report = keep.audit_verify().unwrap();
        assert!(report.valid);
        assert_eq!(report.migration.map(|m| m.old_count), Some(2));
        let entries = keep.audit_read_all().unwrap();
        assert_eq!(entries[2].event_type, AuditEventType::AuditLogMigrated);
        assert_eq!(
            entries.last().unwrap().event_type,
            AuditEventType::VaultUnlock
        );
        assert!(entries.iter().zip(1u64..).all(|(e, seq)| e.seq == seq));

        keep.rotate_data_key("testpass").unwrap();
        let new_key = keep.data_key().unwrap();
        let kept = std::fs::read_to_string(path.join("audit.log.v1")).unwrap();
        assert_eq!(kept.lines().count(), 2);
        for line in kept.lines() {
            let bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, line).unwrap();
            let encrypted = crypto::EncryptedData::from_bytes(&bytes).unwrap();
            assert!(crypto::decrypt(&encrypted, &data_key).is_err());
            assert!(crypto::decrypt(&encrypted, &new_key).is_ok());
        }
        assert!(keep.audit_verify_chain().unwrap());
    }

    /// A kept old log that cannot be re-encrypted does not stop a data key
    /// rotation: both live logs move to the new key and the rotation is
    /// recorded.
    /// A live log that cannot be re-encrypted (a damaged line the vault
    /// opened past, or entries an older keep cannot read) is set aside under
    /// the new key rather than left under the old one, so the rotation
    /// completes and the next unlock still opens the vault.
    #[test]
    fn rotation_sets_aside_a_log_it_cannot_reencrypt() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        // Enough entries that the new log starts well behind them.
        for name in ["a", "b", "c", "d"] {
            keep.generate_key(name).unwrap();
        }
        for _ in 0..2 {
            keep.signing_audit_log(
                SigningAuditEntry::new(
                    crate::audit::SigningRequestType::SignEvent,
                    crate::audit::SigningDecision::Approved,
                    false,
                    "caller".into(),
                    keep.signing_audit_last_hash().unwrap(),
                )
                .finalize(),
            )
            .unwrap();
        }
        let damage = |name: &str| {
            let file = path.join(name);
            let text = std::fs::read_to_string(&file).unwrap();
            assert!(!text.is_empty(), "{name}");
            std::fs::write(&file, format!("bm90IGFuIGVudHJ5\n{text}")).unwrap();
        };
        damage("audit.log");
        damage("signing_audit.log");

        let old_key = keep.data_key().unwrap();
        keep.rotate_data_key("testpass").unwrap();
        let new_key = keep.data_key().unwrap();
        assert!(set_aside(&keep).is_some_and(|s| s.unreadable && s.rotation));
        assert!(!keep.storage.rotation_in_progress());
        assert!(keep.audit_warnings().iter().any(|w| matches!(
            w,
            audit_record::AuditWarning::SigningLogSetAside { missing: false, .. }
        )));
        // The set-aside copies hold their readable lines under the new key,
        // and the damaged line as it was.
        for kept in ["audit.log.v1", "signing_audit.log.unreadable"] {
            let text = std::fs::read_to_string(path.join(kept)).unwrap();
            let mut lines = text.lines();
            assert_eq!(lines.next(), Some("bm90IGFuIGVudHJ5"), "{kept}");
            let mut rest = 0;
            for line in lines {
                let bytes =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, line)
                        .unwrap();
                let encrypted = crypto::EncryptedData::from_bytes(&bytes).unwrap();
                assert!(crypto::decrypt(&encrypted, &old_key).is_err(), "{kept}");
                assert!(crypto::decrypt(&encrypted, &new_key).is_ok(), "{kept}");
                rest += 1;
            }
            assert!(rest >= 1, "{kept}");
        }
        assert!(keep
            .audit_read_all()
            .unwrap()
            .iter()
            .any(|e| e.event_type == AuditEventType::DataKeyRotate));
        // The record follows the new log at once, so a stop before the next
        // entry shows no rollback either.
        let record = keep.load_audit_record().unwrap().unwrap().unwrap();
        let audit = keep.audit.as_ref().unwrap();
        assert_eq!((record.seq, record.head), (audit.seq(), audit.last_hash()));
        drop(keep);

        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(keep.audit_verify().unwrap().valid);
        assert!(keep.signing_audit_verify_chain().unwrap().0);
        // The log set aside by this vault's own rotation is no rollback.
        assert!(!keep
            .audit_warnings()
            .iter()
            .any(|w| matches!(w, audit_record::AuditWarning::RolledBack(_))));
    }

    fn acknowledge(keep: &mut Keep) -> Vec<audit_record::AuditWarning> {
        let shown = keep.audit_warnings();
        keep.audit_acknowledge(&shown).unwrap()
    }

    fn rolled_back(keep: &Keep) -> Option<audit_record::AuditRollback> {
        keep.audit_rollback()
    }

    fn set_aside(keep: &Keep) -> Option<audit_record::SetAside> {
        keep.audit_warnings().into_iter().find_map(|w| match w {
            audit_record::AuditWarning::FailedMigration { set_aside, .. } => Some(set_aside),
            _ => None,
        })
    }

    fn record_lost(keep: &Keep) -> Option<audit_record::RecordLost> {
        keep.audit_warnings().into_iter().find_map(|w| match w {
            audit_record::AuditWarning::RecordLost(lost) => Some(lost),
            _ => None,
        })
    }

    /// An earlier copy of the log put back is noticed on the next unlock,
    /// which still opens the vault, and stays reported until the owner
    /// acknowledges it; the acknowledgement keeps the evidence in the chain.
    #[test]
    fn a_log_put_back_behind_the_record_is_reported_until_acknowledged() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.generate_key("one").unwrap();
        keep.lock();
        let earlier = std::fs::read(path.join("audit.log")).unwrap();
        keep.unlock("testpass").unwrap();
        keep.generate_key("two").unwrap();
        let (seq, head) = keep.audit_anchor().unwrap();
        assert!(rolled_back(&keep).is_none());
        keep.lock();

        std::fs::write(path.join("audit.log"), &earlier).unwrap();
        keep.unlock("testpass").unwrap();
        let rollback = rolled_back(&keep).expect("the earlier log is noticed");
        assert!(rollback.recorded_seq > seq, "the lock entry counts too");
        assert!(rollback.found_seq < seq);
        assert_ne!(rollback.recorded_head, head);
        assert!(
            keep.audit_verify_chain().unwrap(),
            "the copy itself is intact"
        );
        // Still reported after another unlock, even as the log moves on.
        keep.lock();
        keep.unlock("testpass").unwrap();
        assert_eq!(rolled_back(&keep), Some(rollback));

        assert_eq!(acknowledge(&mut keep).len(), 1);
        assert!(rolled_back(&keep).is_none());
        let last = keep.audit_read_all().unwrap().pop().unwrap();
        assert_eq!(last.event_type, AuditEventType::AuditAcknowledged);
        assert!(last
            .reason
            .unwrap()
            .contains(&format!("found at entry {}", rollback.found_seq)));
        keep.lock();
        keep.unlock("testpass").unwrap();
        assert!(keep.audit_warnings().is_empty());
    }

    /// The same count with another head is a rollback too: a log replaced
    /// by a different one of the same length.
    #[test]
    fn a_log_of_the_same_length_with_another_head_is_noticed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.lock();
        let earlier = std::fs::read(path.join("audit.log")).unwrap();
        keep.unlock("testpass").unwrap();
        keep.lock();
        // Two entries since (unlock and lock): put back the earlier log with
        // two other entries of its own, a different chain of the same length.
        let other = dir.path().join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::write(other.join("audit.log"), &earlier).unwrap();
        let data_key = {
            keep.unlock("testpass").unwrap();
            let key = keep.data_key().unwrap();
            keep.lock();
            key
        };
        let mut log = AuditLog::open(&other, &data_key).unwrap();
        for _ in 0..4 {
            log.log(
                AuditEntry::new(AuditEventType::SecretCreate, log.last_hash()),
                &data_key,
            )
            .unwrap();
        }
        std::fs::copy(other.join("audit.log"), path.join("audit.log")).unwrap();
        keep.unlock("testpass").unwrap();
        let rollback = rolled_back(&keep).expect("another chain of the same length");
        assert_eq!(rollback.recorded_seq, rollback.found_seq);
        assert_ne!(rollback.recorded_head, rollback.found_head);
    }

    /// The old log a migration kept, copied back over the log, migrates
    /// again from its start and resets the sequence numbers: noticed.
    #[test]
    fn the_kept_old_log_copied_back_is_noticed() {
        use crate::audit::test_support::write_format1_log;

        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        // A vault from before sequence numbers, never unlocked by a keep
        // that keeps the record: migrated on this unlock, nothing to compare.
        let data_key = {
            let storage =
                Storage::create(&path, "testpass", crypto::Argon2Params::TESTING).unwrap();
            storage.data_key().unwrap().clone()
        };
        write_format1_log(
            &path,
            &data_key,
            vec![
                AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]),
                AuditEntry::new(AuditEventType::VaultLock, [0; 32]),
            ],
        );
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(path.join("audit.log.v1").exists());
        assert!(keep.audit_warnings().is_empty());
        keep.generate_key("k").unwrap();
        keep.lock();

        std::fs::copy(path.join("audit.log.v1"), path.join("audit.log")).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(path.join("audit.log.v1.2").exists(), "migrated again");
        let rollback = rolled_back(&keep).expect("the seq reset is noticed");
        assert!(rollback.found_seq < rollback.recorded_seq);
        assert!(keep.audit_verify().unwrap().valid);
    }

    /// The warning about a migration that failed its check comes from
    /// `keep.db` and stays until the owner acknowledges it: deleting the
    /// marker file beside the log does not silence it, nor does deleting the
    /// kept old log, which is then reported missing.
    #[test]
    fn a_failed_migration_stays_reported_until_acknowledged() {
        use crate::audit::test_support::write_format1_log;

        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let data_key = {
            let storage =
                Storage::create(&path, "testpass", crypto::Argon2Params::TESTING).unwrap();
            storage.data_key().unwrap().clone()
        };
        let mut forged = AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]);
        forged.reason = Some("x".into());
        write_format1_log(&path, &data_key, vec![forged.clone(), forged]);
        // Break the old chain: swap in a line whose hash does not link.
        let text = std::fs::read_to_string(path.join("audit.log")).unwrap();
        let first = text.lines().next().unwrap().to_string();
        std::fs::write(path.join("audit.log"), format!("{text}{first}\n")).unwrap();

        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        let failed = |keep: &Keep| {
            keep.audit_warnings().into_iter().find_map(|w| match w {
                audit_record::AuditWarning::FailedMigration { set_aside, missing } => {
                    Some((set_aside.kept, missing))
                }
                _ => None,
            })
        };
        assert_eq!(failed(&keep), Some(("audit.log.v1".into(), false)));
        // As a vault migrated before the record was kept: the failure only in
        // the marker, which is copied into the record on the next unlock.
        let mut record = keep.load_audit_record().unwrap().unwrap().unwrap();
        record.set_asides.clear();
        keep.save_audit_record(record).unwrap();
        keep.lock();
        keep.unlock("testpass").unwrap();
        keep.lock();
        std::fs::remove_file(path.join("audit.log.v1.failed")).unwrap();
        keep.unlock("testpass").unwrap();
        assert_eq!(failed(&keep), Some(("audit.log.v1".into(), false)));
        keep.lock();
        std::fs::remove_file(path.join("audit.log.v1")).unwrap();
        keep.unlock("testpass").unwrap();
        assert_eq!(failed(&keep), Some(("audit.log.v1".into(), true)));
        assert!(keep.audit_warnings()[0]
            .to_string()
            .contains("the kept log audit.log.v1 is missing"));

        let acknowledged = acknowledge(&mut keep);
        assert_eq!(acknowledged.len(), 1);
        let last = keep.audit_read_all().unwrap().pop().unwrap();
        assert_eq!(last.event_type, AuditEventType::AuditAcknowledged);
        assert!(last.reason.unwrap().contains("audit.log.v1 is missing"));
        assert!(keep.audit_warnings().is_empty());
        keep.lock();
        keep.unlock("testpass").unwrap();
        assert!(keep.audit_warnings().is_empty());
        assert!(acknowledge(&mut keep).is_empty());
    }

    /// Acknowledging a failed migration while its marker and kept file are
    /// still there removes the marker, so the next unlock does not raise the
    /// warning again from it; the kept file stays for investigation.
    #[test]
    fn acknowledging_a_failed_migration_removes_its_marker() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.lock();
        std::fs::write(path.join("audit.log"), "bm90IGFuIGVudHJ5\n").unwrap();
        keep.unlock("testpass").unwrap();
        assert!(path.join("audit.log.v1.failed").exists());
        assert!(set_aside(&keep).is_some());
        acknowledge(&mut keep);
        assert!(!path.join("audit.log.v1.failed").exists());
        assert!(path.join("audit.log.v1").exists());
        keep.lock();
        keep.unlock("testpass").unwrap();
        assert!(
            keep.audit_warnings().is_empty(),
            "{:?}",
            keep.audit_warnings()
        );
    }

    /// The latest session's entries cut off the log, by a process that never
    /// locked (the CLI, the desktop app, keep-web, a crashed gateway), are
    /// noticed: the record follows every entry, not only unlock and lock.
    #[test]
    fn the_latest_session_cut_off_is_noticed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.generate_key("one").unwrap();
        keep.lock();
        let before = std::fs::read(path.join("audit.log")).unwrap();
        keep.unlock("testpass").unwrap();
        keep.generate_key("two").unwrap();
        drop(keep);

        std::fs::write(path.join("audit.log"), &before).unwrap();
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        let rollback = rolled_back(&keep).expect("the cut session is noticed");
        assert!(rollback.found_seq < rollback.recorded_seq);
    }

    /// Each rollback while one is pending is counted, with the lowest count
    /// kept, so a harmless first one cannot hide a later truncation; the
    /// acknowledgement names them all.
    #[test]
    fn every_rollback_while_one_is_pending_is_kept() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.lock();
        let first = std::fs::read(path.join("audit.log")).unwrap();
        for name in ["a", "b"] {
            keep.unlock("testpass").unwrap();
            keep.generate_key(name).unwrap();
            keep.lock();
        }
        let second = std::fs::read(path.join("audit.log")).unwrap();
        keep.unlock("testpass").unwrap();
        keep.generate_key("c").unwrap();
        keep.lock();
        // A small step back first, then a cut all the way to the start.
        std::fs::write(path.join("audit.log"), &second).unwrap();
        keep.unlock("testpass").unwrap();
        let noted = rolled_back(&keep).unwrap();
        keep.lock();
        std::fs::write(path.join("audit.log"), &first).unwrap();
        keep.unlock("testpass").unwrap();
        let both = rolled_back(&keep).unwrap();
        assert_eq!(
            (both.found_seq, both.found_at),
            (noted.found_seq, noted.found_at)
        );
        assert_eq!(both.count, 2);
        assert!(both.lowest_found_seq < noted.found_seq);
        acknowledge(&mut keep);
        let last = keep.audit_read_all().unwrap().pop().unwrap();
        assert!(last
            .reason
            .unwrap()
            .contains(&format!("as low as entry {}", both.lowest_found_seq)));
    }

    /// A longer log that does not hold the recorded entry (another vault's
    /// log under a shared data key, or any other history swapped in) is
    /// noticed, though its count is past the record.
    #[test]
    fn a_longer_log_that_does_not_continue_the_record_is_noticed() {
        let dir = tempdir().unwrap();
        let shared = Zeroizing::new([7u8; crypto::KEY_SIZE]);
        let open = |name: &str| {
            let path = dir.path().join(name);
            Keep::create_with_shared_data_key(
                &path,
                "testpass",
                crypto::Argon2Params::TESTING,
                shared.clone(),
            )
            .unwrap();
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("testpass").unwrap();
            (path, keep)
        };
        let (path, mut keep) = open("a");
        keep.lock();
        let (other, mut node) = open("b");
        for name in ["x", "y", "z"] {
            node.generate_key(name).unwrap();
        }
        node.lock();
        let longer = std::fs::read(other.join("audit.log")).unwrap();
        std::fs::write(path.join("audit.log"), longer).unwrap();
        keep.unlock("testpass").unwrap();
        let rollback = rolled_back(&keep).expect("the other node's log is noticed");
        assert!(rollback.found_seq > rollback.recorded_seq);
    }

    /// A record deleted from `keep.db` while the log shows one was kept, or
    /// one that cannot be read (damaged, or another row's value moved under
    /// its key), is reported until acknowledged, and is started again so a
    /// later rollback is still noticed.
    #[test]
    fn a_lost_record_is_reported_and_detection_resumes() {
        for damage in ["delete", "garbage", "moved"] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("keep");
            let mut keep = test_keep(&path);
            keep.generate_key("one").unwrap();
            keep.lock();
            let before = std::fs::read(path.join("audit.log")).unwrap();
            keep.unlock("testpass").unwrap();
            keep.generate_key("two").unwrap();
            match damage {
                "delete" => {
                    assert!(keep
                        .storage
                        .remove_config_for_tests(audit_record::AUDIT_RECORD_KEY)
                        .unwrap());
                }
                "garbage" => keep
                    .storage
                    .set_config_bytes(audit_record::AUDIT_RECORD_KEY, b"\x00not a record")
                    .unwrap(),
                _ => {
                    let record = serde_json::to_vec(&keep.audit_record).unwrap();
                    keep.storage
                        .set_config_bound(b"agent_freeze_epoch", &record)
                        .unwrap();
                    let moved = keep
                        .storage
                        .get_config_bytes(b"agent_freeze_epoch")
                        .unwrap();
                    keep.storage
                        .set_config_bytes(audit_record::AUDIT_RECORD_KEY, &moved.unwrap())
                        .unwrap();
                }
            }
            drop(keep);
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("testpass").unwrap();
            let lost = record_lost(&keep).unwrap_or_else(|| panic!("{damage}"));
            assert_eq!(lost.missing, damage == "delete", "{damage}");
            keep.lock();
            keep.unlock("testpass").unwrap();
            assert!(record_lost(&keep).is_some(), "{damage}: until acknowledged");
            assert!(rolled_back(&keep).is_none(), "{damage}");
            keep.lock();
            std::fs::write(path.join("audit.log"), &before).unwrap();
            keep.unlock("testpass").unwrap();
            assert!(rolled_back(&keep).is_some(), "{damage}: detection resumes");
            acknowledge(&mut keep);
            assert!(keep.audit_warnings().is_empty(), "{damage}");
        }
    }

    /// A vault's first record is no deleted one: a log written before any
    /// record (a vault an older keep made) is baselined without a warning.
    #[test]
    fn a_first_record_raises_nothing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        // As an older keep left it: entries, no record, and no note.
        let data_key = {
            let storage =
                Storage::create(&path, "testpass", crypto::Argon2Params::TESTING).unwrap();
            storage.data_key().unwrap().clone()
        };
        let mut log = AuditLog::open(&path, &data_key).unwrap();
        for event in [AuditEventType::VaultUnlock, AuditEventType::VaultLock] {
            log.log(AuditEntry::new(event, log.last_hash()), &data_key)
                .unwrap();
        }
        drop(log);
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(
            keep.audit_warnings().is_empty(),
            "{:?}",
            keep.audit_warnings()
        );
        assert!(keep.audit_record.as_ref().is_some_and(|r| r.seq > 0));
    }

    /// A line copied in from the signing log, which decrypts under the same
    /// key, never locks the vault: the log is set aside byte for byte and the
    /// owner told until acknowledged.
    #[test]
    fn a_line_copied_from_the_signing_log_sets_the_log_aside() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.signing_audit_log(
            SigningAuditEntry::new(
                crate::audit::SigningRequestType::SignEvent,
                crate::audit::SigningDecision::Approved,
                false,
                "caller".into(),
                keep.signing_audit_last_hash().unwrap(),
            )
            .finalize(),
        )
        .unwrap();
        keep.lock();
        let signing = std::fs::read_to_string(path.join("signing_audit.log")).unwrap();
        let mut log = std::fs::read_to_string(path.join("audit.log")).unwrap();
        log.push_str(signing.lines().last().unwrap());
        log.push('\n');
        std::fs::write(path.join("audit.log"), &log).unwrap();
        keep.unlock("testpass").unwrap();
        assert_eq!(
            std::fs::read_to_string(path.join("audit.log.v1")).unwrap(),
            log
        );
        let set = set_aside(&keep).expect("set aside, and told");
        assert!(!set.unreadable);
        assert!(keep.audit_verify().unwrap().valid);
        keep.lock();
        keep.unlock("testpass").unwrap();
        assert!(set_aside(&keep).is_some());

        // The same for the signing log: a line from the audit log there is
        // set aside at unlock, and the owner told until acknowledged.
        keep.lock();
        let audit = std::fs::read_to_string(path.join("audit.log")).unwrap();
        let mut signing = std::fs::read_to_string(path.join("signing_audit.log")).unwrap();
        signing.push_str(audit.lines().last().unwrap());
        signing.push('\n');
        std::fs::write(path.join("signing_audit.log"), &signing).unwrap();
        keep.unlock("testpass").unwrap();
        let kept = keep.audit_warnings().into_iter().find_map(|w| match w {
            audit_record::AuditWarning::SigningLogSetAside { kept, missing } => {
                assert!(!missing);
                Some(kept)
            }
            _ => None,
        });
        assert_eq!(
            std::fs::read_to_string(path.join(kept.expect("told"))).unwrap(),
            signing
        );
    }

    /// Retention that keeps none of the unlock entries still leaves a note
    /// that a record was kept, in its own entry, so a deleted record is
    /// still noticed.
    #[test]
    fn a_deleted_record_is_noticed_after_retention() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.generate_key("one").unwrap();
        keep.audit_set_retention(RetentionPolicy {
            max_entries: Some(1),
            max_age_days: None,
        });
        assert!(keep.audit_apply_retention().unwrap() > 0);
        let entries = keep.audit_read_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(keep
            .storage
            .remove_config_for_tests(audit_record::AUDIT_RECORD_KEY)
            .unwrap());
        drop(keep);
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(record_lost(&keep).is_some_and(|l| l.missing));
    }

    /// A crash after a data key rotation committed but before the log was
    /// re-encrypted leaves a log nothing of which decrypts, with the
    /// rotation's note still there: the next unlock says so plainly, in one
    /// warning, not also as a rollback, and clears the note. Without the
    /// note, the same log is reported as replaced or damaged, never put down
    /// to a rotation.
    #[test]
    fn a_log_left_under_a_rotated_key_is_reported_plainly() {
        for interrupted in [true, false] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("keep");
            let mut keep = test_keep(&path);
            keep.generate_key("one").unwrap();
            let old_log = std::fs::read(path.join("audit.log")).unwrap();
            keep.rotate_data_key("testpass").unwrap();
            assert!(!keep.storage.rotation_in_progress());
            if interrupted {
                keep.storage.set_rotation_in_progress(true).unwrap();
            }
            let (seq, head) = keep.audit_anchor().unwrap();
            drop(keep);
            std::fs::write(path.join("audit.log"), old_log).unwrap();
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("testpass").unwrap();
            let warnings = keep.audit_warnings();
            assert_eq!(warnings.len(), 1, "{warnings:?}");
            let set = set_aside(&keep).unwrap();
            assert!(set.unreadable);
            assert_eq!((set.recorded_seq, set.recorded_head), (seq, head));
            assert_eq!(set.rotation, interrupted);
            let text = warnings[0].to_string();
            assert_eq!(text.contains("rotate-data-key"), interrupted, "{text}");
            assert_eq!(
                text.contains("no data key change was under way"),
                !interrupted,
                "{text}"
            );
            assert!(!keep.storage.rotation_in_progress());
        }
    }

    /// A log swapped in while the vault is open is never taken for its own:
    /// a rotation sets it aside rather than re-encrypting it and moving the
    /// record to it, and an append refuses to carry the log's place onto it.
    #[test]
    fn a_log_swapped_in_while_open_is_not_taken_for_the_vaults() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.lock();
        let earlier = std::fs::read(path.join("audit.log")).unwrap();
        keep.unlock("testpass").unwrap();
        keep.generate_key("one").unwrap();
        std::fs::write(path.join("audit.log"), &earlier).unwrap();
        keep.rotate_data_key("testpass").unwrap();
        assert!(set_aside(&keep).is_some(), "set aside, not re-encrypted");
        keep.lock();
        keep.unlock("testpass").unwrap();
        assert!(set_aside(&keep).is_some());

        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.lock();
        let earlier = std::fs::read(path.join("audit.log")).unwrap();
        keep.unlock("testpass").unwrap();
        keep.generate_key("one").unwrap();
        std::fs::write(path.join("audit.log"), &earlier).unwrap();
        keep.generate_key("two").unwrap();
        assert_eq!(std::fs::read(path.join("audit.log")).unwrap(), earlier);
        drop(keep);
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(rolled_back(&keep).is_some());
    }

    /// Owner events may use the room agents leave, and only owner event
    /// types are taken.
    #[test]
    fn owner_events_are_recorded_past_the_agents_share() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        assert!(keep
            .record_owner_event(AuditEventType::Sign, "not an owner event")
            .is_err());
        keep.record_owner_event(AuditEventType::AgentApproverAdded, "label \"x\"\u{202e}")
            .unwrap();
        let last = keep.audit_read_all().unwrap().pop().unwrap();
        assert_eq!(last.event_type, AuditEventType::AgentApproverAdded);
        assert!(!last.reason.unwrap().contains('\u{202e}'));
        let audit = path.join("audit.log");
        keep.lock();
        let ceiling = crate::audit::MAX_AUDIT_ENTRIES - AGENT_AUDIT_HEADROOM;
        let mut long = b"x\n".repeat(ceiling);
        long.extend_from_slice(&std::fs::read(&audit).unwrap());
        std::fs::write(&audit, long).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(keep
            .record_agent_approval_requested(&[1; 16], "sign", None)
            .is_err());
        keep.record_owner_event(AuditEventType::AgentApprovalDecided, "denied")
            .unwrap();
        // Owner events stop one short of where the log could not be read back.
        let lines = |audit: &std::path::Path| {
            std::fs::read(audit)
                .unwrap()
                .split(|b| *b == b'\n')
                .filter(|l| !l.is_empty())
                .count()
        };
        keep.lock();
        let before = lines(&audit);
        keep.unlock("testpass").unwrap();
        let added = keep.audit.as_ref().unwrap().entry_count() - before;
        keep.lock();
        let mut full = b"x\n".repeat(crate::audit::MAX_AUDIT_ENTRIES - 1 - added - lines(&audit));
        full.extend_from_slice(&std::fs::read(&audit).unwrap());
        std::fs::write(&audit, full).unwrap();
        keep.unlock("testpass").unwrap();
        assert_eq!(
            keep.audit.as_ref().unwrap().entry_count(),
            crate::audit::MAX_AUDIT_ENTRIES - 1
        );
        assert!(keep
            .record_owner_event(AuditEventType::AgentApprovalDecided, "denied")
            .is_err());
    }

    #[test]
    fn rotation_survives_a_kept_log_it_cannot_reencrypt() {
        use crate::audit::test_support::write_format1_log;

        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let data_key = test_keep(&path).data_key().unwrap();
        write_format1_log(
            &path,
            &data_key,
            vec![AuditEntry::new(AuditEventType::VaultUnlock, [0; 32])],
        );
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        // A kept log that cannot be read fails its re-encryption.
        let unreadable = path.join("audit.log.v1.7");
        std::fs::write(&unreadable, b"x\n").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(
            &unreadable,
            std::os::unix::fs::PermissionsExt::from_mode(0o000),
        )
        .unwrap();
        if std::fs::File::open(&unreadable).is_ok() {
            return; // Root, or no permissions to drop: nothing would fail.
        }
        keep.rotate_data_key("testpass").unwrap();
        assert!(keep.audit_verify_chain().unwrap());
        assert!(keep
            .audit_read_all()
            .unwrap()
            .iter()
            .any(|e| e.event_type == AuditEventType::DataKeyRotate));
        assert!(keep.signing_audit_verify_chain().unwrap().0);
    }

    /// `Keep::rotate_data_key` MUST emit a `DataKeyRotate` audit entry on
    /// success. The entry's payload is encrypted under the NEW data key (the
    /// log gets re-encrypted as part of rotation); this test confirms the
    /// entry is readable after rotation and the chain still verifies.
    #[test]
    fn rotate_data_key_emits_success_audit_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        {
            let mut keep = test_keep(&path);
            keep.generate_key("dek-audit").unwrap();
            keep.rotate_data_key("testpass").unwrap();
            let entries = keep.audit_read_all().unwrap();
            assert!(
                entries
                    .iter()
                    .any(|e| e.event_type == AuditEventType::DataKeyRotate),
                "DataKeyRotate entry missing from audit log: {:?}",
                entries.iter().map(|e| e.event_type).collect::<Vec<_>>()
            );
            // The audit log was re-encrypted under the new data key during
            // rotation; the chain over both pre- and post-rotation entries
            // must remain valid.
            keep.audit_verify_chain().unwrap();
        }
        // Confirm persistence: re-open and the entry is still there.
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        let entries = keep.audit_read_all().unwrap();
        assert!(entries
            .iter()
            .any(|e| e.event_type == AuditEventType::DataKeyRotate));
    }

    // === #581 / #579 / #580: rotation hardening ===

    /// `Keep::rotate_password` MUST reject a wrong `old_password` even when the
    /// vault is already unlocked (#581). Without this, anyone with access to
    /// an unlocked Keep could re-wrap the data key without proving knowledge
    /// of the prior credential.
    #[test]
    fn rotate_password_rejects_wrong_old_password_when_already_unlocked() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        // Vault is unlocked. The rotation should still refuse without the
        // correct old password.
        let err = keep
            .rotate_password("NOT_THE_OLD_PASSWORD", "newpass1")
            .expect_err("wrong old password must be refused even when unlocked");
        let _ = err; // shape varies, pin only on error path

        // The original password still unlocks: failure paths do not corrupt
        // the header.
        drop(keep);
        let mut reopened = Keep::open(&path).unwrap();
        reopened.unlock("testpass").unwrap();
    }

    /// Same gap on `rotate_data_key`: wrong password rejected even when
    /// already unlocked (#581).
    #[test]
    fn rotate_data_key_rejects_wrong_password_when_already_unlocked() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        let err = keep
            .rotate_data_key("WRONG_PASSWORD")
            .expect_err("wrong password must be refused even when unlocked");
        let _ = err;

        drop(keep);
        let mut reopened = Keep::open(&path).unwrap();
        reopened.unlock("testpass").unwrap();
    }

    /// `Keep::rotate_password` MUST emit a `PasswordRotateFailed` audit entry
    /// when the wrong-old-password gate (#581) fires on an unlocked vault.
    /// Without this, an attacker's failed rotation attempts on a hijacked
    /// unlocked Keep would be unobservable.
    #[test]
    fn rotate_password_wrong_old_password_emits_failure_audit_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        let pre = keep.audit_read_all().unwrap().len();
        assert!(keep
            .rotate_password("WRONG_OLD_PASSWORD", "newpass1")
            .is_err());
        let entries = keep.audit_read_all().unwrap();
        assert!(
            entries.len() > pre,
            "audit log must grow on a rejected rotation"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.event_type == AuditEventType::PasswordRotateFailed),
            "PasswordRotateFailed entry missing after wrong-old-password rejection"
        );
    }

    #[test]
    fn test_default_keep_path_from_env() {
        let abs_path = if cfg!(windows) {
            "C:\\tmp\\my-keep"
        } else {
            "/tmp/my-keep"
        };
        temp_env::with_var("KEEP_HOME", Some(abs_path), || {
            let p = default_keep_path().unwrap();
            assert_eq!(p, PathBuf::from(abs_path));
        });
    }

    #[test]
    fn test_default_keep_path_relative_env_rejected() {
        temp_env::with_var("KEEP_HOME", Some("relative/path"), || {
            let result = default_keep_path();
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_default_keep_path_empty_env_falls_back() {
        temp_env::with_var("KEEP_HOME", Some(""), || {
            let p = default_keep_path().unwrap();
            let expected = dirs::home_dir().unwrap().join(".keep");
            assert_eq!(p, expected);
        });
    }

    #[test]
    fn test_default_keep_path_blank_env_falls_back() {
        temp_env::with_var("KEEP_HOME", Some("   "), || {
            let p = default_keep_path().unwrap();
            let expected = dirs::home_dir().unwrap().join(".keep");
            assert_eq!(p, expected);
        });
    }

    /// Run a software DKG group in-process, persist every finalized share via
    /// `frost_store_dkg_share`, and confirm the shares reload with intact
    /// metadata and can be exported. Covers the finalize -> SharePackage ->
    /// encrypt -> store -> reload bridge that the DKG unit tests do not touch.
    #[test]
    fn test_frost_store_dkg_share_roundtrip() {
        use crate::frost::dkg::{SoftwareDkgSession, SoftwareRound1Wire, SoftwareRound2Wire};

        let (threshold, participants): (u16, u16) = (2, 3);

        let mut sessions: Vec<SoftwareDkgSession> = (1..=participants)
            .map(|idx| SoftwareDkgSession::init(threshold, participants, idx).unwrap())
            .collect();

        let round1_wires: Vec<SoftwareRound1Wire> =
            sessions.iter_mut().map(|s| s.round1().unwrap()).collect();
        for (i, session) in sessions.iter_mut().enumerate() {
            for (j, wire) in round1_wires.iter().enumerate() {
                if i != j {
                    session.round1_peer(wire).unwrap();
                }
            }
        }

        let mut per_session_round2: Vec<Vec<(u16, SoftwareRound2Wire)>> =
            sessions.iter_mut().map(|s| s.round2().unwrap()).collect();
        for (sender_i, wires) in per_session_round2.drain(..).enumerate() {
            for (recipient_index, wire) in wires {
                let recipient_i = (recipient_index - 1) as usize;
                assert_ne!(recipient_i, sender_i);
                sessions[recipient_i].receive_share(&wire).unwrap();
            }
        }

        let results: Vec<_> = sessions.iter_mut().map(|s| s.finalize().unwrap()).collect();
        let group_pubkey = results[0].group_pubkey;

        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        for r in &results {
            keep.frost_store_dkg_share(r, threshold, participants, "dkg-group", None)
                .unwrap();
        }

        let shares = keep.frost_list_shares().unwrap();
        assert_eq!(shares.len(), participants as usize);
        for share in &shares {
            assert_eq!(share.metadata.group_pubkey, group_pubkey);
            assert_eq!(share.metadata.threshold, threshold);
            assert_eq!(share.metadata.total_shares, participants);
            assert_eq!(share.metadata.name, "dkg-group");
        }
        let indices: std::collections::BTreeSet<u16> =
            shares.iter().map(|s| s.metadata.identifier).collect();
        assert_eq!(indices, (1..=participants).collect());

        // A stored share decrypts and exports under a passphrase.
        let export = keep
            .frost_export_share(&group_pubkey, results[0].our_index, "export-pass")
            .unwrap();
        drop(export);

        // A locked vault refuses to store.
        keep.lock();
        assert!(matches!(
            keep.frost_store_dkg_share(&results[0], threshold, participants, "dkg-group", None),
            Err(KeepError::Locked)
        ));
    }

    #[test]
    fn frost_group_subkey_is_enrolled_idempotently_and_retrievable() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        // No subkey until enrolled.
        assert_eq!(keep.frost_group_subkey_secret("alpha").unwrap(), None);

        // Enrolling mints a subkey whose secret is retrievable and whose pubkey
        // is derivable from it.
        let pubkey = keep.frost_group_subkey_ensure("alpha").unwrap();
        let mut secret = keep.frost_group_subkey_secret("alpha").unwrap().unwrap();
        let derived = crate::keys::NostrKeypair::from_secret_bytes(&mut secret).unwrap();
        assert_eq!(*derived.public_bytes(), pubkey);

        // Idempotent: a second enroll returns the same subkey, not a new one.
        assert_eq!(keep.frost_group_subkey_ensure("alpha").unwrap(), pubkey);

        // Distinct groups get distinct subkeys.
        let other = keep.frost_group_subkey_ensure("beta").unwrap();
        assert_ne!(other, pubkey);

        // A locked vault refuses both operations.
        keep.lock();
        assert!(matches!(
            keep.frost_group_subkey_ensure("alpha"),
            Err(KeepError::Locked)
        ));
        assert!(matches!(
            keep.frost_group_subkey_secret("alpha"),
            Err(KeepError::Locked)
        ));
    }

    #[test]
    fn frost_store_dkg_share_retains_group_subkey_secret() {
        let (threshold, participants) = (2u16, 2u16);
        let mut sessions: Vec<_> = (1..=participants)
            .map(|i| frost::dkg::SoftwareDkgSession::init(threshold, participants, i).unwrap())
            .collect();

        let round1_wires: Vec<_> = sessions.iter_mut().map(|s| s.round1().unwrap()).collect();
        for (i, session) in sessions.iter_mut().enumerate() {
            for (j, wire) in round1_wires.iter().enumerate() {
                if i != j {
                    session.round1_peer(wire).unwrap();
                }
            }
        }
        let mut per_session_round2: Vec<Vec<(u16, frost::dkg::SoftwareRound2Wire)>> =
            sessions.iter_mut().map(|s| s.round2().unwrap()).collect();
        for wires in per_session_round2.drain(..) {
            for (recipient_index, wire) in wires {
                sessions[(recipient_index - 1) as usize]
                    .receive_share(&wire)
                    .unwrap();
            }
        }
        let result = sessions[0].finalize().unwrap();

        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        let subkey = [9u8; 32];
        keep.frost_store_dkg_share(
            &result,
            threshold,
            participants,
            "retain-group",
            Some(subkey),
        )
        .unwrap();

        let shares = keep.frost_list_shares().unwrap();
        let stored = shares
            .iter()
            .find(|s| s.metadata.name == "retain-group")
            .unwrap();
        assert_eq!(stored.metadata.group_subkey_secret, Some(subkey));
    }

    #[test]
    fn learned_verifying_shares_complete_an_imported_share() {
        let src_dir = tempdir().unwrap();
        let mut src = test_keep(&src_dir.path().join("keep"));
        let shares = src.frost_generate(3, 5, "learned").unwrap();
        let group_pubkey = *shares[0].group_pubkey();
        let full = shares[0].pubkey_package().unwrap();
        let set = frost::verifying_share_map(&full, 5).unwrap();

        let mut export = src
            .frost_export_share(&group_pubkey, 1, "transfer-pass")
            .unwrap();
        export.encrypted_pubkey_package = None;
        export.pubkey_nonce = None;
        export.encrypted_verifying_shares = None;
        export.verifying_shares_nonce = None;

        let dst_dir = tempdir().unwrap();
        let mut dst = test_keep(&dst_dir.path().join("keep"));
        dst.frost_import_share(&export, "transfer-pass", "imported")
            .unwrap();
        let single = dst.frost_get_share_by_index(&group_pubkey, 1).unwrap();
        assert_eq!(single.pubkey_package().unwrap().verifying_shares().len(), 1);

        let mut forged = set.clone();
        forged.insert(4, set[&5]);
        assert!(dst
            .frost_store_verifying_shares(&group_pubkey, 1, &forged)
            .is_err());
        assert_eq!(
            dst.frost_get_share_by_index(&group_pubkey, 1)
                .unwrap()
                .pubkey_package()
                .unwrap()
                .verifying_shares()
                .len(),
            1
        );

        dst.frost_store_verifying_shares(&group_pubkey, 1, &set)
            .unwrap();
        let completed = dst.frost_get_share_by_index(&group_pubkey, 1).unwrap();
        assert_eq!(
            completed.pubkey_package().unwrap().verifying_shares(),
            full.verifying_shares()
        );
        assert_eq!(completed.key_package_bytes(), single.key_package_bytes());
    }

    #[test]
    fn deleting_a_frozen_agent_credential_moves_the_freeze_epoch() {
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        let (plain, _) = keep
            .issue_agent_credential("plain", 1000, Vec::new(), unix_now(), 3600)
            .unwrap();
        let (frozen, _) = keep
            .issue_agent_credential("frozen", 1000, Vec::new(), unix_now(), 3600)
            .unwrap();
        let e0 = keep.agent_freeze_epoch().unwrap();
        keep.delete_agent_credential(&plain.id).unwrap();
        assert_eq!(keep.agent_freeze_epoch().unwrap(), e0);
        keep.set_agent_credential_frozen(&frozen.id, true).unwrap();
        assert_eq!(keep.agent_freeze_epoch().unwrap(), e0 + 1);
        assert!(keep
            .delete_agent_credential_with(&frozen.id, Some(e0), &[])
            .is_err());
        assert!(keep.load_agent_credential(&frozen.id).unwrap().is_some());
        let ledger: (&[u8], &[u8]) = (b"noted", b"value");
        assert_eq!(
            keep.delete_agent_credential_with(&frozen.id, Some(e0 + 1), &[ledger])
                .unwrap(),
            Some(e0 + 2)
        );
        assert_eq!(keep.agent_freeze_epoch().unwrap(), e0 + 2);
        assert_eq!(
            keep.load_agent_ledger(b"noted")
                .unwrap()
                .as_deref()
                .map(|v| &v[..]),
            Some(&b"value"[..])
        );
    }

    fn chain_broken(keep: &Keep) -> Option<audit_record::ChainBroken> {
        keep.audit_warnings().into_iter().find_map(|w| match w {
            audit_record::AuditWarning::ChainBroken(b) => Some(b),
            _ => None,
        })
    }

    /// Lines removed from the middle of the log, keeping its last, are
    /// caught by the chain check at unlock, though the end still matches the
    /// record; once acknowledged, only a new break is reported.
    #[test]
    fn lines_removed_before_the_last_are_noticed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        for name in ["a", "b", "c"] {
            keep.generate_key(name).unwrap();
        }
        drop(keep);
        let cut = |path: &std::path::Path, from_end: std::ops::Range<usize>| {
            let text = std::fs::read_to_string(path.join("audit.log")).unwrap();
            let mut lines: Vec<&str> = text.lines().collect();
            let n = lines.len();
            lines.drain(n - from_end.end..n - from_end.start);
            std::fs::write(path.join("audit.log"), lines.join("\n") + "\n").unwrap();
        };
        // Remove lines N-2 and N-1, keeping N.
        cut(&path, 1..3);
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(rolled_back(&keep).is_none(), "the end still matches");
        let broken = chain_broken(&keep).expect("the cut is noticed");
        assert!(broken.failures >= 1);
        keep.lock();
        keep.unlock("testpass").unwrap();
        assert!(chain_broken(&keep).is_some(), "until acknowledged");
        acknowledge(&mut keep);
        keep.lock();
        keep.unlock("testpass").unwrap();
        assert!(
            chain_broken(&keep).is_none(),
            "the same breaks, acknowledged"
        );
        drop(keep);
        cut(&path, 3..4);
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(chain_broken(&keep).is_some(), "a new break is reported");
    }

    /// Another vault's entry put into a longer log at the same position, a
    /// splice under a shared data key, breaks the chain and is noticed.
    #[test]
    fn an_entry_spliced_in_from_another_log_is_noticed() {
        let dir = tempdir().unwrap();
        let shared = Zeroizing::new([7u8; crypto::KEY_SIZE]);
        let open = |name: &str| {
            let path = dir.path().join(name);
            Keep::create_with_shared_data_key(
                &path,
                "testpass",
                crypto::Argon2Params::TESTING,
                shared.clone(),
            )
            .unwrap();
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("testpass").unwrap();
            (path, keep)
        };
        let (a, mut ka) = open("a");
        let (b, mut kb) = open("b");
        for name in ["x", "y", "z"] {
            ka.generate_key(name).unwrap();
            kb.generate_key(name).unwrap();
        }
        kb.generate_key("w").unwrap();
        drop(ka);
        drop(kb);
        let a_text = std::fs::read_to_string(a.join("audit.log")).unwrap();
        let b_text = std::fs::read_to_string(b.join("audit.log")).unwrap();
        let mut b_lines: Vec<&str> = b_text.lines().collect();
        b_lines[2] = a_text.lines().nth(2).unwrap();
        std::fs::write(b.join("audit.log"), b_lines.join("\n") + "\n").unwrap();
        let mut kb = Keep::open(&b).unwrap();
        kb.unlock("testpass").unwrap();
        assert!(chain_broken(&kb).is_some());
    }

    /// A log cut while the vault is open and padded back to its length with
    /// blank lines is not appended to: the last line this vault wrote is no
    /// longer where it left it.
    #[test]
    fn a_cut_log_padded_to_its_length_is_not_appended_to() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.generate_key("a").unwrap();
        keep.generate_key("b").unwrap();
        let text = std::fs::read_to_string(path.join("audit.log")).unwrap();
        let last = text.lines().last().unwrap().len() + 1;
        let mut padded = text[..text.len() - last].to_string();
        padded.push_str(&"\n".repeat(last));
        assert_eq!(padded.len(), text.len());
        std::fs::write(path.join("audit.log"), &padded).unwrap();
        keep.generate_key("c").unwrap();
        assert_eq!(
            std::fs::read_to_string(path.join("audit.log")).unwrap(),
            padded
        );
        assert!(keep.audit_apply_retention().is_err());
    }

    /// Pruning refuses a log swapped in while the vault is open, rather than
    /// taking it for its own.
    #[test]
    fn retention_refuses_a_log_swapped_in_while_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.lock();
        let earlier = std::fs::read(path.join("audit.log")).unwrap();
        keep.unlock("testpass").unwrap();
        keep.generate_key("a").unwrap();
        keep.audit_set_retention(RetentionPolicy {
            max_entries: Some(1),
            max_age_days: None,
        });
        // As long as the length matches, only the tail check is left.
        let now = std::fs::read(path.join("audit.log")).unwrap();
        let mut swapped = earlier.clone();
        swapped.resize(now.len(), b'\n');
        std::fs::write(path.join("audit.log"), &swapped).unwrap();
        assert!(keep.audit_apply_retention().is_err());
        assert_eq!(std::fs::read(path.join("audit.log")).unwrap(), swapped);

        // Nor one that only grew blank lines past where this vault left it.
        std::fs::write(path.join("audit.log"), &now).unwrap();
        let mut grown = now.clone();
        grown.extend_from_slice(b"\n\n");
        std::fs::write(path.join("audit.log"), &grown).unwrap();
        assert!(keep.audit_apply_retention().is_err());
        assert_eq!(std::fs::read(path.join("audit.log")).unwrap(), grown);
    }

    /// Deleting the record and the log together, from a vault holding a
    /// key, is noticed; a vault an older release left (a format 1 log, no
    /// record) upgrades quietly, its migration writing the first record; a
    /// vault created and given a key before its first unlock is quiet too.
    #[test]
    fn a_record_deleted_with_its_log_is_noticed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.generate_key("a").unwrap();
        assert!(keep
            .storage
            .remove_config_for_tests(audit_record::AUDIT_RECORD_KEY)
            .unwrap());
        drop(keep);
        std::fs::remove_file(path.join("audit.log")).unwrap();
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(record_lost(&keep).is_some_and(|l| l.missing));

        // An older release's vault: a key, a format 1 log, no record.
        use crate::audit::test_support::write_format1_log;
        let path = dir.path().join("released");
        let data_key = {
            let mut keep =
                Keep::create_with_params(&path, "testpass", crypto::Argon2Params::TESTING).unwrap();
            keep.generate_key("a").unwrap();
            for row in [audit_record::AUDIT_RECORD_KEY, b"agent_freeze_epoch"] {
                assert!(keep.storage.remove_config_for_tests(row).unwrap());
            }
            keep.data_key().unwrap()
        };
        write_format1_log(
            &path,
            &data_key,
            vec![
                AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]),
                AuditEntry::new(AuditEventType::KeyGenerate, [0; 32]),
            ],
        );
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(
            keep.audit_warnings().is_empty(),
            "{:?}",
            keep.audit_warnings()
        );
        assert!(keep.load_audit_record().unwrap().is_some());

        let path = dir.path().join("fresh");
        let mut keep =
            Keep::create_with_params(&path, "testpass", crypto::Argon2Params::TESTING).unwrap();
        keep.generate_key("a").unwrap();
        drop(keep);
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(
            keep.audit_warnings().is_empty(),
            "{:?}",
            keep.audit_warnings()
        );
    }

    /// A freeze goes ahead when the freeze epoch cannot be read, with a new
    /// epoch above any an unfreeze held back from before could carry, and
    /// says so; an unfreeze needs a readable epoch. A deleted epoch is not
    /// read as 0 once agents exist, and deleting a frozen credential, even
    /// one whose row cannot be read, goes ahead the same way.
    #[test]
    fn a_freeze_goes_ahead_when_the_epoch_cannot_be_read() {
        let floor = unix_now() << 24;
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        assert!(keep.agent_freeze_epoch().is_ok());
        let (one, _) = keep
            .issue_agent_credential("one", 1000, Vec::new(), unix_now(), 3600)
            .unwrap();
        keep.storage
            .put_raw(
                crate::backend::CONFIG_TABLE,
                b"agent_freeze_epoch",
                b"not an epoch",
            )
            .unwrap();
        assert!(keep.agent_freeze_epoch().is_err());
        assert!(keep.set_agent_credential_frozen(&one.id, false).is_err());
        let seeded = keep
            .set_agent_frozen(Some(&one.id), true, Some(3), &[])
            .unwrap();
        assert!(seeded >= floor, "{seeded} < {floor}");
        assert_eq!(keep.agent_freeze_epoch().unwrap(), seeded);
        let last = keep.audit_read_all().unwrap().pop().unwrap();
        assert_eq!(last.event_type, AuditEventType::AgentFreeze);
        assert!(last.reason.unwrap().contains("could not be read"));
        assert_eq!(
            keep.set_agent_frozen(Some(&one.id), false, Some(seeded), &[])
                .unwrap(),
            seeded + 1
        );

        // A deleted epoch is not 0 once agents exist.
        assert!(keep
            .storage
            .remove_config_for_tests(b"agent_freeze_epoch")
            .unwrap());
        assert!(keep.agent_freeze_epoch().is_err());
        keep.set_agent_credential_frozen(&one.id, true).unwrap();
        assert!(keep.agent_freeze_epoch().unwrap() >= floor);

        // Deleting a frozen credential with the epoch unreadable.
        keep.storage
            .put_raw(crate::backend::CONFIG_TABLE, b"agent_freeze_epoch", b"x")
            .unwrap();
        let moved = keep
            .delete_agent_credential_with(&one.id, None, &[])
            .unwrap();
        assert!(moved.is_some_and(|e| e >= floor));
    }

    /// A credential row that cannot be read (here, stored under another id)
    /// is still deleted, and taken for frozen, so the epoch moves.
    #[test]
    fn a_credential_row_that_cannot_be_read_is_deleted_as_frozen() {
        let dir = tempdir().unwrap();
        let mut keep = test_keep(&dir.path().join("keep"));
        let (one, _) = keep
            .issue_agent_credential("one", 1000, Vec::new(), unix_now(), 3600)
            .unwrap();
        let row = keep
            .storage
            .raw_row_for_tests(crate::backend::AGENT_CREDENTIALS_TABLE, &one.id)
            .unwrap();
        let other = [9u8; 16];
        keep.storage
            .put_raw(crate::backend::AGENT_CREDENTIALS_TABLE, &other, &row)
            .unwrap();
        assert!(keep.storage.load_agent_credential(&other).is_err());
        let epoch = keep.agent_freeze_epoch().unwrap();
        let twice: [(&[u8], &[u8]); 2] = [(b"x", b"1"), (b"x", b"2")];
        assert!(keep
            .delete_agent_credential_with(&other, Some(epoch), &twice)
            .is_err());
        assert_eq!(
            keep.delete_agent_credential_with(&other, Some(epoch), &[])
                .unwrap(),
            Some(epoch + 1)
        );
        assert!(keep
            .storage
            .raw_row_for_tests(crate::backend::AGENT_CREDENTIALS_TABLE, &other)
            .is_none());
    }

    /// A set-aside found only from its marker (one a crash kept from the
    /// record, or a marker planted beside an older kept log) is noted, and
    /// the log is still compared with the record: a log behind it is a
    /// rollback too.
    #[test]
    fn a_set_aside_found_from_its_marker_is_still_compared() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        for name in ["a", "b", "c"] {
            keep.generate_key(name).unwrap();
        }
        let data_key = keep.data_key().unwrap();
        drop(keep);
        let mut text = std::fs::read_to_string(path.join("audit.log")).unwrap();
        text.push_str("bm90IGFuIGVudHJ5\n");
        let mut lines: Vec<&str> = text.lines().collect();
        lines.drain(1..lines.len() - 1);
        std::fs::write(path.join("audit.log"), lines.join("\n") + "\n").unwrap();
        // The set-aside, as a crashed process or someone with the folder
        // ran it, without the record.
        drop(AuditLog::open(&path, &data_key).unwrap());
        assert!(path.join("audit.log.v1.failed").exists());
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(rolled_back(&keep).is_some(), "{:?}", keep.audit_warnings());
        let set = set_aside(&keep).unwrap();
        assert!(set.recorded_seq > 0);
        assert!(keep.audit_warnings()[0]
            .to_string()
            .contains(&format!("at entry {}", set.recorded_seq)));
    }

    /// A second set-aside before the owner acknowledges the first is noted
    /// beside it, not in its place.
    #[test]
    fn every_set_aside_while_one_is_pending_is_kept() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        for _ in 0..2 {
            keep.lock();
            std::fs::write(path.join("audit.log"), "bm90IGFuIGVudHJ5\n").unwrap();
            keep.unlock("testpass").unwrap();
        }
        let kept: Vec<String> = keep
            .audit_warnings()
            .into_iter()
            .filter_map(|w| match w {
                audit_record::AuditWarning::FailedMigration { set_aside, .. } => {
                    Some(set_aside.kept)
                }
                _ => None,
            })
            .collect();
        assert_eq!(kept, ["audit.log.v1", "audit.log.v1.2"]);
    }

    /// A pruning that replaced the log before the record followed it, with
    /// the recorded entry among those removed, is no rollback: the record
    /// noted where the log would end beforehand.
    #[test]
    fn a_pruning_the_record_did_not_follow_is_not_a_rollback() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.generate_key("a").unwrap();
        keep.audit_set_retention(RetentionPolicy {
            max_entries: Some(1),
            max_age_days: None,
        });
        // As audit_apply_retention does, stopped before the record follows.
        let data_key = keep.data_key().unwrap();
        let mut record = keep.audit_record.clone().unwrap();
        let storage = &keep.storage;
        keep.audit
            .as_mut()
            .unwrap()
            .apply_retention_noting(&data_key, Some(audit_record::RECORD_NOTE), |seq, hash| {
                record.retention_pending = Some((seq, hash));
                storage.set_config_bound(
                    audit_record::AUDIT_RECORD_KEY,
                    &serde_json::to_vec(&record).unwrap(),
                )
            })
            .unwrap();
        drop(keep);
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(
            keep.audit_warnings().is_empty(),
            "{:?}",
            keep.audit_warnings()
        );
    }

    /// A log whose last line is damaged and has no newline is set aside
    /// byte for byte, torn end and all; so is a signing log.
    #[test]
    fn a_log_set_aside_keeps_its_torn_end() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.signing_audit_log(
            SigningAuditEntry::new(
                crate::audit::SigningRequestType::SignEvent,
                crate::audit::SigningDecision::Approved,
                false,
                "caller".into(),
                keep.signing_audit_last_hash().unwrap(),
            )
            .finalize(),
        )
        .unwrap();
        keep.lock();
        let mut damaged = Vec::new();
        for name in ["audit.log", "signing_audit.log"] {
            let mut text = std::fs::read_to_string(path.join(name)).unwrap();
            text.push_str("bm90IGFuIGVudHJ5\ntorn");
            std::fs::write(path.join(name), &text).unwrap();
            damaged.push(text);
        }
        keep.unlock("testpass").unwrap();
        assert_eq!(
            std::fs::read_to_string(path.join("audit.log.v1")).unwrap(),
            damaged[0]
        );
        assert_eq!(
            std::fs::read_to_string(path.join("signing_audit.log.unreadable")).unwrap(),
            damaged[1]
        );
    }

    /// A storage backend that fails to read the audit record while `fail`
    /// is set, as a failing disk would.
    struct FlakyBackend {
        inner: crate::backend::MemoryBackend,
        fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl crate::backend::StorageBackend for FlakyBackend {
        fn get(&self, table: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst)
                && key == audit_record::AUDIT_RECORD_KEY
            {
                return Err(KeepError::Other("read failed".into()));
            }
            self.inner.get(table, key)
        }
        fn put(&self, table: &str, key: &[u8], value: &[u8]) -> Result<()> {
            self.inner.put(table, key, value)
        }
        fn delete(&self, table: &str, key: &[u8]) -> Result<bool> {
            self.inner.delete(table, key)
        }
        fn list(&self, table: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
            self.inner.list(table)
        }
        fn create_table(&self, table: &str) -> Result<()> {
            self.inner.create_table(table)
        }
    }

    /// A failure to read the record fails the check rather than starting the
    /// record again, which would hide what it noted.
    #[test]
    fn a_record_that_cannot_be_read_from_disk_is_not_started_again() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let fail = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let storage = Storage::create_with_backend(
            &path,
            "testpass",
            crypto::Argon2Params::TESTING,
            Box::new(FlakyBackend {
                inner: crate::backend::MemoryBackend::new(),
                fail: fail.clone(),
            }),
        )
        .unwrap();
        let mut keep = Keep::started(storage).unwrap();
        let data_key = keep.data_key().unwrap();
        keep.audit = Some(AuditLog::open(&path, &data_key).unwrap());
        keep.signing_audit = Some(SigningAuditLog::open(&path, &data_key).unwrap());
        let mut noted = audit_record::AuditRecord {
            seq: 5,
            head: [5; 32],
            ..Default::default()
        };
        noted.lost = Some(audit_record::RecordLost {
            missing: true,
            found_at: 1,
        });
        keep.save_audit_record(noted.clone()).unwrap();
        fail.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(keep.check_audit_record().is_err());
        fail.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(keep.load_audit_record().unwrap().unwrap().unwrap(), noted);
    }

    /// How long an unlock takes on a log of MAX_AUDIT_ENTRIES entries, chain
    /// check included. Run with `--ignored --nocapture` in release.
    #[test]
    #[ignore]
    fn unlock_time_at_the_entry_cap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let keep = test_keep(&path);
        let data_key = keep.data_key().unwrap();
        drop(keep);
        crate::audit::test_support::write_long_log(
            &path,
            &data_key,
            crate::audit::MAX_AUDIT_ENTRIES - 10,
        );
        let mut keep = Keep::open(&path).unwrap();
        let started = std::time::Instant::now();
        keep.unlock("testpass").unwrap();
        println!(
            "unlock with {} entries: {:?}",
            keep.audit.as_ref().unwrap().entry_count(),
            started.elapsed()
        );
        assert!(chain_broken(&keep).is_none());
    }

    /// The kept format 1 log moved back over the log with the record
    /// deleted migrates again from its start: noticed from the freeze
    /// epoch's row when nothing was created since, and with that row
    /// deleted too, from a key created after the old log's last entry.
    #[test]
    fn the_old_log_moved_back_with_the_record_deleted_is_noticed() {
        use crate::audit::test_support::write_format1_log;

        for epoch_too in [false, true] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("keep");
            let data_key = {
                let storage =
                    Storage::create(&path, "testpass", crypto::Argon2Params::TESTING).unwrap();
                storage.data_key().unwrap().clone()
            };
            let mut old = AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]);
            old.timestamp -= 3600;
            write_format1_log(&path, &data_key, vec![old]);
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("testpass").unwrap();
            assert!(
                keep.audit_warnings().is_empty(),
                "{:?}",
                keep.audit_warnings()
            );
            if epoch_too {
                keep.generate_key("since").unwrap();
            }
            assert!(keep
                .storage
                .remove_config_for_tests(audit_record::AUDIT_RECORD_KEY)
                .unwrap());
            if epoch_too {
                assert!(keep
                    .storage
                    .remove_config_for_tests(b"agent_freeze_epoch")
                    .unwrap());
            }
            drop(keep);
            std::fs::rename(path.join("audit.log.v1"), path.join("audit.log")).unwrap();
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("testpass").unwrap();
            assert!(
                record_lost(&keep).is_some_and(|l| l.missing),
                "epoch row deleted too: {epoch_too}"
            );
        }
    }

    /// A vault from a keep before the record and the epoch, with agent
    /// credentials (as main left it), opens quietly the first time, with a
    /// seeded epoch that reads, so anchors and pairing work at once.
    #[test]
    fn a_vault_from_before_the_record_with_agents_opens_quietly() {
        let floor = unix_now() << 24;
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.issue_agent_credential("one", 1000, Vec::new(), unix_now(), 3600)
            .unwrap();
        let data_key = keep.data_key().unwrap();
        // A credential row that cannot be read is passed over, not fatal.
        let (other, _) = keep
            .issue_agent_credential("two", 1000, Vec::new(), unix_now(), 3600)
            .unwrap();
        let row = keep
            .storage
            .raw_row_for_tests(crate::backend::AGENT_CREDENTIALS_TABLE, &other.id)
            .unwrap();
        keep.storage
            .put_raw(crate::backend::AGENT_CREDENTIALS_TABLE, &[9; 16], &row)
            .unwrap();
        for row in [audit_record::AUDIT_RECORD_KEY, b"agent_freeze_epoch"] {
            assert!(keep.storage.remove_config_for_tests(row).unwrap());
        }
        drop(keep);
        // Its log, without the notes this keep writes.
        std::fs::remove_file(path.join("audit.log")).unwrap();
        let mut log = AuditLog::open(&path, &data_key).unwrap();
        for event in [
            AuditEventType::VaultUnlock,
            AuditEventType::AgentCredentialIssue,
        ] {
            log.log(AuditEntry::new(event, log.last_hash()), &data_key)
                .unwrap();
        }
        drop(log);
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(
            keep.audit_warnings().is_empty(),
            "{:?}",
            keep.audit_warnings()
        );
        assert!(keep.agent_freeze_epoch().unwrap() >= floor);
        keep.lock();
        keep.unlock("testpass").unwrap();
        assert!(keep.audit_warnings().is_empty());
    }

    /// Acknowledging takes the warnings as shown, refusing others, and
    /// covers the chain's breaks as the unlock found them: a break made
    /// while the vault is open is still reported at the next unlock.
    #[test]
    fn acknowledging_covers_only_what_was_shown() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        for name in ["a", "b", "c", "d", "e", "f"] {
            keep.generate_key(name).unwrap();
        }
        drop(keep);
        let edit = |change: &dyn Fn(&mut Vec<String>)| {
            let text = std::fs::read_to_string(path.join("audit.log")).unwrap();
            let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
            change(&mut lines);
            std::fs::write(path.join("audit.log"), lines.join("\n") + "\n").unwrap();
        };
        edit(&|lines| {
            let n = lines.len();
            lines.remove(n - 2);
        });
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(chain_broken(&keep).is_some());
        assert!(keep.audit_acknowledge(&[]).is_err(), "not what is shown");
        let shown = keep.audit_warnings();
        // While the banner is up, two entries of the same length further
        // back swap places: the file keeps its length and last line.
        edit(&|lines| {
            let (i, j) = (2..lines.len() - 2)
                .flat_map(|i| (i + 1..lines.len() - 2).map(move |j| (i, j)))
                .find(|&(i, j)| lines[i].len() == lines[j].len())
                .expect("two entries of the same length");
            lines.swap(i, j);
        });
        keep.audit_acknowledge(&shown).unwrap();
        drop(keep);
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(chain_broken(&keep).is_some(), "the later break is new");
    }

    /// A log longer than an unlock checks is reported as too long, with
    /// its own warning, never as broken, and acknowledging does not hide it.
    #[test]
    fn a_log_too_long_to_check_is_not_reported_broken() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        for name in ["a", "b", "c"] {
            keep.generate_key(name).unwrap();
        }
        keep.audit.as_mut().unwrap().set_read_cap_for_tests(3);
        keep.check_audit_record().unwrap();
        let warnings = keep.audit_warnings();
        assert_eq!(
            warnings,
            [audit_record::AuditWarning::TooLong],
            "{warnings:?}"
        );
        assert!(warnings[0].to_string().contains("keep audit retention"));
        assert!(acknowledge(&mut keep).is_empty());
        assert_eq!(keep.audit_warnings(), [audit_record::AuditWarning::TooLong]);
    }

    /// A rate-limit trip forged with a time far in the future is entered at
    /// most at the current time; and a log cut back to end at such a trip,
    /// with the record and the epoch rows deleted, is still noticed, since
    /// a trip's time is never what the creation-time test compares with.
    #[test]
    fn a_forged_trip_time_does_not_hide_a_deleted_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let keep =
            Keep::create_with_params(&path, "testpass", crypto::Argon2Params::TESTING).unwrap();
        keep.storage.forge_trip_for_tests(u64::MAX);
        drop(keep);
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        let entries = keep.audit_read_all().unwrap();
        assert_eq!(entries[0].event_type, AuditEventType::RateLimitTripped);
        assert!(entries[0].timestamp <= chrono::Utc::now().timestamp());
        keep.generate_key("since").unwrap();
        for row in [audit_record::AUDIT_RECORD_KEY, b"agent_freeze_epoch"] {
            assert!(keep.storage.remove_config_for_tests(row).unwrap());
        }
        drop(keep);
        let text = std::fs::read_to_string(path.join("audit.log")).unwrap();
        let first = text.lines().next().unwrap();
        std::fs::write(path.join("audit.log"), format!("{first}\n")).unwrap();
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(record_lost(&keep).is_some_and(|l| l.missing));
    }

    /// A log (of either format) that already holds a trip dated in the
    /// future, from before trip times were capped, does not pass for one
    /// that recorded everything created: the creation-time test passes
    /// over trips.
    #[test]
    fn a_trip_dated_in_the_future_is_not_the_logs_end() {
        use crate::audit::test_support::write_format1_log;

        for format1 in [false, true] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("keep");
            let data_key = {
                let mut keep =
                    Keep::create_with_params(&path, "testpass", crypto::Argon2Params::TESTING)
                        .unwrap();
                keep.generate_key("a").unwrap();
                for row in [audit_record::AUDIT_RECORD_KEY, b"agent_freeze_epoch"] {
                    assert!(keep.storage.remove_config_for_tests(row).unwrap());
                }
                keep.data_key().unwrap()
            };
            let mut early = AuditEntry::new(AuditEventType::VaultUnlock, [0; 32]);
            early.timestamp -= 3600;
            let mut trip = AuditEntry::new(AuditEventType::RateLimitTripped, [0; 32]);
            trip.timestamp = i64::MAX;
            if format1 {
                write_format1_log(&path, &data_key, vec![early, trip]);
            } else {
                let mut log = AuditLog::open(&path, &data_key).unwrap();
                for mut entry in [early, trip] {
                    entry.prev_hash = log.last_hash();
                    log.log(entry, &data_key).unwrap();
                }
            }
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("testpass").unwrap();
            assert!(
                record_lost(&keep).is_some_and(|l| l.missing),
                "format 1: {format1}"
            );
        }
    }

    /// A missing freeze epoch is started again at unlock, seeded whether
    /// or not agent rows remain (never 0, which an unfreeze held back from
    /// when the epoch was 0 would match, as wiping the agents and the epoch
    /// together would otherwise allow), noted in the unlock's entry and
    /// reported until acknowledged, without taking the record for a deleted
    /// one. Only creating a vault starts the epoch at 0.
    #[test]
    fn a_missing_epoch_is_seeded_and_reported_at_unlock() {
        let floor = unix_now() << 24;
        for wipe_agents in [false, true] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("keep");
            let mut keep =
                Keep::create_with_params(&path, "testpass", crypto::Argon2Params::TESTING).unwrap();
            drop(keep);
            keep = Keep::open(&path).unwrap();
            keep.unlock("testpass").unwrap();
            assert_eq!(keep.agent_freeze_epoch().unwrap(), 0, "created at 0");
            assert!(keep.audit_warnings().is_empty());
            let (one, _) = keep
                .issue_agent_credential("one", 1000, Vec::new(), unix_now(), 3600)
                .unwrap();
            if wipe_agents {
                keep.delete_agent_credential(&one.id).unwrap();
            }
            assert!(keep
                .storage
                .remove_config_for_tests(b"agent_freeze_epoch")
                .unwrap());
            keep.lock();
            keep.unlock("testpass").unwrap();
            let epoch = keep.agent_freeze_epoch().unwrap();
            assert!(epoch >= floor, "wiped agents: {wipe_agents}");
            assert_eq!(
                keep.audit_warnings(),
                [audit_record::AuditWarning::EpochReseeded(
                    audit_record::EpochReseeded {
                        epoch,
                        found_at: keep
                            .audit_record
                            .as_ref()
                            .unwrap()
                            .epoch_reseeded
                            .unwrap()
                            .found_at,
                    }
                )]
            );
            let unlock = keep.audit_read_all().unwrap().pop().unwrap();
            assert_eq!(unlock.event_type, AuditEventType::VaultUnlock);
            assert!(unlock
                .reason
                .unwrap()
                .contains(&format!("started again at {epoch}")));
            acknowledge(&mut keep);
            keep.lock();
            keep.unlock("testpass").unwrap();
            assert!(keep.audit_warnings().is_empty());
            assert_eq!(keep.agent_freeze_epoch().unwrap(), epoch);
        }
    }

    /// A seeded epoch is never below the latest time the audit log
    /// recorded (a wall clock stepped back), and two in the same second
    /// differ in their random low bits.
    #[test]
    fn seeded_epochs_follow_the_log_and_differ() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let keep = test_keep(&path);
        let data_key = keep.data_key().unwrap();
        drop(keep);
        let ahead = unix_now() as i64 + 100_000;
        let mut log = AuditLog::open(&path, &data_key).unwrap();
        let mut entry = AuditEntry::new(AuditEventType::KeyGenerate, log.last_hash());
        entry.timestamp = ahead;
        log.log(entry, &data_key).unwrap();
        drop(log);
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(keep
            .storage
            .remove_config_for_tests(b"agent_freeze_epoch")
            .unwrap());
        keep.lock();
        keep.unlock("testpass").unwrap();
        let epoch = keep.agent_freeze_epoch().unwrap();
        assert!(epoch >= (ahead as u64) << 24, "{epoch}");
        let (a, b) = (
            keep.storage.missing_or_seeded_for_tests(),
            keep.storage.missing_or_seeded_for_tests(),
        );
        assert_eq!(a >> 24, b >> 24);
        assert_ne!(a, b, "random low bits");
        assert!(a & ((1 << 24) - 1) < 1 << 23);
    }

    /// A wallet descriptor counts by its creation time.
    #[test]
    fn a_wallet_descriptor_counts_by_its_creation_time() {
        let dir = tempdir().unwrap();
        let keep = test_keep(&dir.path().join("keep"));
        keep.storage
            .store_descriptor(&WalletDescriptor {
                group_pubkey: [9u8; 32],
                external_descriptor: "tr(xpub.../0/*)".into(),
                internal_descriptor: "tr(xpub.../1/*)".into(),
                network: "bitcoin".into(),
                created_at: 2_000,
                device_registrations: Vec::new(),
                policy_hash: [0u8; 32],
                version: 1,
                previous_descriptor_hash: None,
                policy: None,
            })
            .unwrap();
        assert_eq!(keep.storage.latest_created_at().unwrap(), 2_000);
    }

    /// A secret updated after it was created counts by its update time.
    #[test]
    fn a_secret_counts_by_its_update_time() {
        let dir = tempdir().unwrap();
        let keep = test_keep(&dir.path().join("keep"));
        let mut secret = crate::secret::SecretRecord::new(
            "s".into(),
            crate::secret::SecretKind::Password,
            b"v".to_vec(),
        )
        .unwrap();
        secret.created_at = 1;
        secret.updated_at = 1_000;
        keep.storage.store_secret(&secret).unwrap();
        assert_eq!(keep.storage.latest_created_at().unwrap(), 1_000);
    }
}
