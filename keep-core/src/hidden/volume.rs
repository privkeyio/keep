// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Hidden volume implementation for plausible deniability.
//!
//! # Architecture
//!
//! The hidden volume system provides two encrypted storage areas within a single vault file:
//!
//! - **Outer volume**: Standard encrypted storage, unlocked with the primary password
//! - **Hidden volume**: Secondary encrypted storage, cryptographically indistinguishable from random data
//!
//! # File Layout
//!
//! ```text
//! ┌─────────────────────┐  0
//! │   Outer Header      │  512 bytes - salt, encrypted data key, argon2 params
//! ├─────────────────────┤  512
//! │   Hidden Header     │  512 bytes - fully encrypted (looks random)
//! ├─────────────────────┤  1024 (DATA_START_OFFSET)
//! │   Outer Data Area   │  Variable size - redb database for outer volume
//! ├─────────────────────┤
//! │   Hidden Data Area  │  Variable size - encrypted length + encrypted records + random padding
//! └─────────────────────┘
//! ```
//!
//! # Security Properties
//!
//! - Hidden header KDF salt is derived from password (not stored)
//! - Hidden data length is encrypted (no plaintext size prefix)
//! - Hidden header is encrypted and indistinguishable from random bytes
//! - Wrong password for hidden volume produces same error as "no hidden volume"
//! - Both volumes use independent Argon2id key derivation
//! - Unlock attempts both decryptions to prevent timing attacks
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rand::Rng;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::crypto::{self, Argon2Params, EncryptedData, SecretKey};
use crate::error::{KeepError, Result, StorageError};
use crate::keys::KeyRecord;
use crate::rate_limit;
use crate::relay::{self, RelayConfig};

use bincode::Options;

use super::header::{
    HiddenHeader, OuterHeader, DATA_START_OFFSET, HEADER_SIZE, HIDDEN_HEADER_OFFSET,
};

const KEYS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("keys");
const RELAY_CONFIGS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("relay_configs");

const MAX_RECORD_SIZE: u64 = 1024 * 1024;

const MIN_HIDDEN_SIZE: u64 = (crypto::NONCE_SIZE + 8 + crypto::TAG_SIZE) as u64;

fn derive_hidden_salt(outer_salt: &[u8; 32], password: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(19 + 32 + password.len());
    input.extend_from_slice(b"keep-hidden-salt-v1");
    input.extend_from_slice(outer_salt);
    input.extend_from_slice(password.as_bytes());
    crypto::blake2b_256(&input)
}

fn write_random_padding(file: &mut File, size: u64) -> std::io::Result<()> {
    let mut buffer = [0u8; 4096];
    let mut written = 0u64;
    while written < size {
        let to_write = ((size - written) as usize).min(buffer.len());
        rand::rng().fill_bytes(&mut buffer[..to_write]);
        file.write_all(&buffer[..to_write])?;
        written += to_write as u64;
    }
    Ok(())
}

/// Type of encrypted volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeType {
    /// The primary outer volume.
    Outer,
    /// The hidden plausible-deniability volume.
    Hidden,
}

/// Encrypted storage with optional hidden volume.
pub struct HiddenStorage {
    path: PathBuf,
    outer_header: OuterHeader,
    hidden_header: Option<HiddenHeader>,
    outer_key: Option<SecretKey>,
    hidden_key: Option<SecretKey>,
    active_volume: Option<VolumeType>,
    outer_db: Option<Database>,
    /// Audit log attached on outer unlock so the `keep audit list/verify/...`
    /// surface works on hidden-init vaults and `drain_pending_trips` can
    /// flush rate-limit trip events queued by failed unlocks (#520).
    /// Outer-volume scope only, paralleling the #507 relay-config decision.
    outer_audit: Option<crate::audit::AuditLog>,
}

impl HiddenStorage {
    /// Create a new hidden storage vault.
    ///
    /// `hidden_ratio` is the fraction of space for the hidden volume (0.0-1.0).
    pub fn create(
        path: &Path,
        outer_password: &str,
        hidden_password: Option<&str>,
        total_size: u64,
        hidden_ratio: f32,
        params: Argon2Params,
    ) -> Result<Self> {
        if path.exists() {
            return Err(KeepError::AlreadyExists(path.display().to_string()));
        }

        if !(0.0..=1.0).contains(&hidden_ratio) {
            return Err(KeepError::InvalidInput(format!(
                "hidden_ratio must be between 0.0 and 1.0, got {hidden_ratio}"
            )));
        }

        let hidden_size = if hidden_password.is_some() {
            ((total_size as f64) * (hidden_ratio as f64)) as u64
        } else {
            0
        };

        if hidden_password.is_some() && hidden_size < MIN_HIDDEN_SIZE {
            return Err(KeepError::InvalidInput(format!(
                "hidden volume size {hidden_size} too small, need at least {MIN_HIDDEN_SIZE} bytes"
            )));
        }

        let required_min = DATA_START_OFFSET
            .checked_add(hidden_size)
            .ok_or_else(|| KeepError::InvalidInput("volume size overflow".into()))?;

        if total_size < required_min {
            return Err(KeepError::InvalidInput(format!(
                "total size {total_size} too small, need at least {required_min} bytes (header: {DATA_START_OFFSET}, hidden: {hidden_size})"
            )));
        }

        let outer_size = total_size - DATA_START_OFFSET - hidden_size;

        let mut outer_header = OuterHeader::new(params, outer_size, total_size);

        let outer_data_key = SecretKey::generate()?;
        let outer_master_key =
            crypto::derive_key(outer_password.as_bytes(), &outer_header.salt, params)?;
        let outer_header_key = crypto::derive_subkey(&outer_master_key, b"keep-outer-header")?;

        let outer_key_bytes = outer_data_key.decrypt()?;
        let encrypted_outer = crypto::encrypt(&*outer_key_bytes, &outer_header_key)?;
        outer_header.nonce.copy_from_slice(&encrypted_outer.nonce);
        outer_header
            .encrypted_data_key
            .copy_from_slice(&encrypted_outer.ciphertext);

        let (hidden_header, hidden_data_key, encrypted_hidden_header) =
            if let Some(hp) = hidden_password {
                let hidden_offset = DATA_START_OFFSET + outer_size;
                let mut hh = HiddenHeader::new(hidden_offset, hidden_size);

                let hidden_data_key = SecretKey::generate()?;
                let kdf_salt = derive_hidden_salt(&outer_header.salt, hp);
                let hidden_master_key = crypto::derive_key(hp.as_bytes(), &kdf_salt, params)?;

                let hidden_header_key =
                    crypto::derive_subkey(&hidden_master_key, b"keep-hidden-header")?;
                let hidden_key_bytes = hidden_data_key.decrypt()?;
                let encrypted_hidden = crypto::encrypt(&*hidden_key_bytes, &hidden_header_key)?;
                hh.nonce.copy_from_slice(&encrypted_hidden.nonce);
                hh.encrypted_data_key
                    .copy_from_slice(&encrypted_hidden.ciphertext);
                hh.checksum = hh.compute_checksum();

                let hidden_header_enc_key =
                    crypto::derive_subkey(&hidden_master_key, b"keep-hidden-header-enc")?;
                let encrypted_hh = crypto::encrypt(&hh.to_bytes_compact(), &hidden_header_enc_key)?;

                (Some(hh), Some(hidden_data_key), Some(encrypted_hh))
            } else {
                (None, None, None)
            };

        fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        }
        let vault_path = path.join("keep.vault");
        let mut file = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&vault_path)?
            }
            #[cfg(not(unix))]
            {
                File::create(&vault_path)?
            }
        };

        file.write_all(&outer_header.to_bytes())?;

        let mut hidden_area: [u8; HEADER_SIZE] = crypto::try_random_bytes()?;
        if let Some(encrypted_hh) = encrypted_hidden_header {
            hidden_area[..24].copy_from_slice(&encrypted_hh.nonce);
            hidden_area[24..24 + encrypted_hh.ciphertext.len()]
                .copy_from_slice(&encrypted_hh.ciphertext);
        }
        file.write_all(&hidden_area)?;

        write_random_padding(&mut file, total_size - DATA_START_OFFSET)?;
        file.sync_all()?;
        drop(file);

        let db_path = path.join("keep.db");
        let db = Database::create(&db_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600));
        }

        let wtxn = db.begin_write()?;
        let _ = wtxn.open_table(KEYS_TABLE)?;
        let _ = wtxn.open_table(RELAY_CONFIGS_TABLE)?;
        wtxn.commit()?;

        Ok(Self {
            path: path.to_path_buf(),
            outer_header,
            hidden_header,
            outer_key: Some(outer_data_key),
            hidden_key: hidden_data_key,
            active_volume: Some(VolumeType::Outer),
            outer_db: Some(db),
            outer_audit: None,
        })
    }

    /// Open an existing hidden storage vault.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(KeepError::NotFound(path.display().to_string()));
        }

        let vault_path = path.join("keep.vault");
        let mut file = File::open(&vault_path)?;

        let mut header_bytes = [0u8; HEADER_SIZE];
        file.read_exact(&mut header_bytes)?;
        let outer_header = OuterHeader::from_bytes(&header_bytes)?;

        Ok(Self {
            path: path.to_path_buf(),
            outer_header,
            hidden_header: None,
            outer_key: None,
            hidden_key: None,
            active_volume: None,
            outer_db: None,
            outer_audit: None,
        })
    }

    fn try_unlock_outer(&mut self, password: &str) -> Result<()> {
        if self.outer_key.is_some() {
            return Ok(());
        }

        let master_key = crypto::derive_key(
            password.as_bytes(),
            &self.outer_header.salt,
            self.outer_header.argon2_params(),
        )?;

        let header_key = crypto::derive_subkey(&master_key, b"keep-outer-header")?;

        let encrypted = EncryptedData {
            nonce: self.outer_header.nonce,
            ciphertext: self.outer_header.encrypted_data_key.to_vec(),
        };

        let decrypted = crypto::decrypt(&encrypted, &header_key)?;
        let decrypted_slice = decrypted.as_slice()?;
        self.outer_key = Some(SecretKey::from_slice(&decrypted_slice)?);

        let db_path = self.path.join("keep.db");
        let db = match crate::backend::open_database_with_retry(&db_path) {
            Ok(db) => db,
            // Hidden vaults don't auto-upgrade the redb file format here; the
            // outer-volume schema is owned by `RedbBackend::open`. Surface the
            // upgrade requirement as a generic database error rather than
            // silently half-migrating a hidden-init vault.
            Err(crate::backend::OpenWithRetryError::UpgradeRequired(v)) => {
                return Err(StorageError::database(format!(
                    "hidden-vault outer redb requires file format upgrade from v{v}; not yet supported"
                ))
                .into());
            }
            Err(crate::backend::OpenWithRetryError::Other(e)) => {
                return Err(crate::backend::map_open_failure(&db_path, e));
            }
        };

        self.outer_db = Some(db);
        self.active_volume = Some(VolumeType::Outer);

        Ok(())
    }

    /// Unlock the outer volume.
    pub fn unlock_outer(&mut self, password: &str) -> Result<()> {
        if self.outer_key.is_some() {
            return Ok(());
        }

        let hmac_key = rate_limit::derive_hmac_key(&self.outer_header.salt);
        if let Err(remaining) = rate_limit::check_rate_limit(&self.path, &hmac_key) {
            return Err(KeepError::RateLimited(remaining.as_secs().max(1)));
        }

        match self.try_unlock_outer(password) {
            Ok(()) => {
                rate_limit::record_success(&self.path);
                // #520: open the audit log under the outer data key and flush
                // any queued rate-limit trip events. Mirrors `Keep::unlock` so
                // hidden-init vaults get the same `RateLimitTripped` audit
                // surfacing that regular vaults do.
                self.attach_outer_audit(&hmac_key)?;
                Ok(())
            }
            Err(e) => {
                if matches!(e, KeepError::InvalidPassword | KeepError::DecryptionFailed) {
                    rate_limit::record_failure(&self.path, &hmac_key);
                }
                Err(e)
            }
        }
    }

    /// Open the outer-volume audit log and drain pending trip events. Called
    /// from `unlock_outer` and the `unlock()` dispatcher after the data key is
    /// in hand. Errors on the audit log are non-fatal to the unlock itself; we
    /// log and continue so a corrupted audit log can't make the whole vault
    /// inaccessible. Idempotent: a no-op once the log is already attached.
    fn attach_outer_audit(&mut self, hmac_key: &[u8; 32]) -> Result<()> {
        use crate::audit::{AuditEntry, AuditEventType};

        if self.outer_audit.is_some() {
            return Ok(());
        }

        let data_key = self.outer_key.as_ref().ok_or(KeepError::Locked)?;
        let mut audit = match crate::audit::AuditLog::open(&self.path, data_key) {
            Ok(log) => log,
            Err(e) => {
                tracing::warn!(error = %e, "could not open audit log on hidden vault outer unlock; trips will not flush this cycle");
                return Ok(());
            }
        };

        let trips = rate_limit::drain_pending_trips(&self.path, hmac_key);
        for trip in trips {
            let trip_ts = i64::try_from(trip.timestamp).unwrap_or(i64::MAX);
            let reason = format!(
                "rate limit threshold reached after {} failed attempts",
                trip.failed_attempts
            );
            let mut entry = AuditEntry::new(AuditEventType::RateLimitTripped, audit.last_hash())
                .with_success(false)
                .with_reason(&reason);
            entry.timestamp = trip_ts;
            if let Err(e) = audit.log(entry, data_key) {
                tracing::warn!(error = %e, "failed to flush RateLimitTripped audit entry on hidden vault");
            }
        }

        // Emit VaultUnlock to mirror `Keep::unlock`.
        let unlock_entry = AuditEntry::new(AuditEventType::VaultUnlock, audit.last_hash());
        if let Err(e) = audit.log(unlock_entry, data_key) {
            tracing::warn!(error = %e, "failed to log VaultUnlock audit entry on hidden vault");
        }

        self.outer_audit = Some(audit);
        Ok(())
    }

    fn try_unlock_hidden(&mut self, password: &str) -> Result<()> {
        if self.hidden_key.is_some() {
            return Ok(());
        }

        let vault_path = self.path.join("keep.vault");
        let mut file = File::open(&vault_path)?;
        file.seek(SeekFrom::Start(HIDDEN_HEADER_OFFSET))?;

        let mut hidden_area = [0u8; HEADER_SIZE];
        file.read_exact(&mut hidden_area)?;

        let kdf_salt = derive_hidden_salt(&self.outer_header.salt, password);
        let master_key = crypto::derive_key(
            password.as_bytes(),
            &kdf_salt,
            self.outer_header.argon2_params(),
        )?;
        let header_enc_key = crypto::derive_subkey(&master_key, b"keep-hidden-header-enc")?;

        const ENCRYPTED_HEADER_SIZE: usize = HiddenHeader::COMPACT_SIZE + crypto::TAG_SIZE;
        let encrypted = EncryptedData {
            nonce: hidden_area[..24].try_into().expect("slice is 24 bytes"),
            ciphertext: hidden_area[24..24 + ENCRYPTED_HEADER_SIZE].to_vec(),
        };

        let decrypted =
            crypto::decrypt(&encrypted, &header_enc_key).map_err(|_| KeepError::InvalidPassword)?;

        let decrypted_bytes = decrypted.as_slice()?;
        let hidden_header = HiddenHeader::from_bytes_compact(&decrypted_bytes)?;

        if !hidden_header.verify_checksum() {
            return Err(KeepError::InvalidPassword);
        }

        let data_key_enc = crypto::derive_subkey(&master_key, b"keep-hidden-header")?;
        let data_encrypted = EncryptedData {
            nonce: hidden_header.nonce,
            ciphertext: hidden_header.encrypted_data_key.to_vec(),
        };

        let data_key_bytes = crypto::decrypt(&data_encrypted, &data_key_enc)?;
        let data_key_slice = data_key_bytes.as_slice()?;
        self.hidden_key = Some(SecretKey::from_slice(&data_key_slice)?);
        self.hidden_header = Some(hidden_header);
        self.active_volume = Some(VolumeType::Hidden);

        Ok(())
    }

    /// Unlock the hidden volume.
    pub fn unlock_hidden(&mut self, password: &str) -> Result<()> {
        if self.hidden_key.is_some() {
            return Ok(());
        }

        let hmac_key = rate_limit::derive_hmac_key(&self.outer_header.salt);
        if let Err(remaining) = rate_limit::check_rate_limit(&self.path, &hmac_key) {
            return Err(KeepError::RateLimited(remaining.as_secs().max(1)));
        }

        match self.try_unlock_hidden(password) {
            Ok(()) => {
                rate_limit::record_success(&self.path);
                Ok(())
            }
            Err(e) => {
                if matches!(e, KeepError::InvalidPassword | KeepError::DecryptionFailed) {
                    rate_limit::record_failure(&self.path, &hmac_key);
                }
                Err(e)
            }
        }
    }

    /// Unlock whichever volume the password matches.
    /// Returns the type that was unlocked.
    pub fn unlock(&mut self, password: &str) -> Result<VolumeType> {
        let hmac_key = rate_limit::derive_hmac_key(&self.outer_header.salt);
        if let Err(remaining) = rate_limit::check_rate_limit(&self.path, &hmac_key) {
            return Err(KeepError::RateLimited(remaining.as_secs().max(1)));
        }

        let outer_result = self.try_unlock_outer(password);
        let hidden_result = self.try_unlock_hidden(password);

        match (outer_result, hidden_result) {
            (Ok(()), _) => {
                self.active_volume = Some(VolumeType::Outer);
                rate_limit::record_success(&self.path);
                // #520: the auto-detect path must flush trips and attach the
                // outer audit log too, otherwise `audit_*` accessors see an
                // unlocked vault with `outer_audit == None`. Mirror `unlock_outer`.
                self.attach_outer_audit(&hmac_key)?;
                Ok(VolumeType::Outer)
            }
            (Err(_), Ok(())) => {
                self.active_volume = Some(VolumeType::Hidden);
                rate_limit::record_success(&self.path);
                Ok(VolumeType::Hidden)
            }
            (Err(outer_err), Err(hidden_err)) => {
                let is_auth_error = |e: &KeepError| {
                    matches!(e, KeepError::InvalidPassword | KeepError::DecryptionFailed)
                };

                if !is_auth_error(&outer_err) {
                    return Err(outer_err);
                }
                if !is_auth_error(&hidden_err) {
                    return Err(hidden_err);
                }

                rate_limit::record_failure(&self.path, &hmac_key);
                Err(KeepError::InvalidPassword)
            }
        }
    }

    /// Lock and zeroize all keys.
    pub fn lock(&mut self) {
        self.outer_key = None;
        self.hidden_key = None;
        self.hidden_header = None;
        self.active_volume = None;
        self.outer_db = None;
        self.outer_audit = None;
    }

    /// Returns true if any volume is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.active_volume.is_some()
    }

    /// The data encryption key for the active volume.
    pub fn data_key(&self) -> Option<&SecretKey> {
        match self.active_volume {
            Some(VolumeType::Hidden) => self.hidden_key.as_ref(),
            Some(VolumeType::Outer) => self.outer_key.as_ref(),
            None => None,
        }
    }

    /// The active volume type, if unlocked.
    pub fn active_volume(&self) -> Option<VolumeType> {
        self.active_volume
    }

    /// Returns true if the hidden volume is unlocked.
    pub fn is_hidden_unlocked(&self) -> bool {
        self.hidden_key.is_some()
    }

    /// Store a key record in the active volume.
    pub fn store_key(&self, record: &KeyRecord) -> Result<()> {
        match self.active_volume {
            Some(VolumeType::Outer) => self.store_key_outer(record),
            Some(VolumeType::Hidden) => self.store_key_hidden(record),
            None => Err(KeepError::Locked),
        }
    }

    fn store_key_outer(&self, record: &KeyRecord) -> Result<()> {
        let data_key = self.outer_key.as_ref().ok_or(KeepError::Locked)?;
        let db = self.outer_db.as_ref().ok_or(KeepError::Locked)?;

        let serialized = bincode::options()
            .with_fixint_encoding()
            .serialize(record)?;

        let encrypted = crypto::encrypt(&serialized, data_key)?;
        let encrypted_bytes = encrypted.to_bytes();

        let wtxn = db.begin_write()?;
        {
            let mut table = wtxn.open_table(KEYS_TABLE)?;
            table.insert(record.id.as_slice(), encrypted_bytes.as_slice())?;
        }
        wtxn.commit()?;

        Ok(())
    }

    fn store_key_hidden(&self, record: &KeyRecord) -> Result<()> {
        let data_key = self.hidden_key.as_ref().ok_or(KeepError::Locked)?;
        let hidden_header = self.hidden_header.as_ref().ok_or(KeepError::Locked)?;

        let mut records = self.load_hidden_records()?;
        records.retain(|r| r.id != record.id);
        records.push(record.clone());

        self.write_hidden_records(&records, data_key, hidden_header)
    }

    fn load_hidden_records(&self) -> Result<Vec<KeyRecord>> {
        let data_key = self.hidden_key.as_ref().ok_or(KeepError::Locked)?;
        let hidden_header = self.hidden_header.as_ref().ok_or(KeepError::Locked)?;

        let vault_path = self.path.join("keep.vault");
        let mut file = File::open(&vault_path)?;
        file.seek(SeekFrom::Start(hidden_header.hidden_data_offset))?;

        const ENCRYPTED_LENGTH_SIZE: usize = crypto::NONCE_SIZE + 8 + crypto::TAG_SIZE;
        let mut length_blob = [0u8; ENCRYPTED_LENGTH_SIZE];
        if file.read_exact(&mut length_blob).is_err() {
            return Ok(Vec::new());
        }

        let data_size = (|| -> Option<u64> {
            let encrypted_length = EncryptedData::from_bytes(&length_blob).ok()?;
            let decrypted_length = crypto::decrypt(&encrypted_length, data_key).ok()?;
            let length_bytes = decrypted_length.as_slice().ok()?;
            let arr: [u8; 8] = length_bytes.as_slice().try_into().ok()?;
            Some(u64::from_le_bytes(arr))
        })();

        let Some(data_size) = data_size else {
            return Ok(Vec::new());
        };

        let max_data_size = hidden_header
            .hidden_data_size
            .saturating_sub(ENCRYPTED_LENGTH_SIZE as u64);
        if data_size == 0 || data_size > max_data_size {
            return Ok(Vec::new());
        }

        let mut encrypted_data = vec![0u8; data_size as usize];
        file.read_exact(&mut encrypted_data)?;

        let records = (|| -> Option<Vec<KeyRecord>> {
            let encrypted = EncryptedData::from_bytes(&encrypted_data).ok()?;
            let decrypted = crypto::decrypt(&encrypted, data_key).ok()?;
            let decrypted_bytes = decrypted.as_slice().ok()?;
            bincode::options()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(MAX_RECORD_SIZE)
                .deserialize(&decrypted_bytes)
                .ok()
        })();

        Ok(records.unwrap_or_default())
    }

    fn write_hidden_records(
        &self,
        records: &[KeyRecord],
        data_key: &SecretKey,
        hidden_header: &HiddenHeader,
    ) -> Result<()> {
        let serialized = bincode::options()
            .with_fixint_encoding()
            .serialize(records)?;
        let encrypted = crypto::encrypt(&serialized, data_key)?;
        let encrypted_bytes = encrypted.to_bytes();

        let length_bytes = (encrypted_bytes.len() as u64).to_le_bytes();
        let encrypted_length = crypto::encrypt(&length_bytes, data_key)?;
        let encrypted_length_bytes = encrypted_length.to_bytes();

        let total_size = encrypted_length_bytes.len() + encrypted_bytes.len();
        if total_size as u64 > hidden_header.hidden_data_size {
            return Err(StorageError::hidden_volume_full().into());
        }

        let vault_path = self.path.join("keep.vault");
        let mut file = OpenOptions::new().write(true).open(&vault_path)?;
        file.seek(SeekFrom::Start(hidden_header.hidden_data_offset))?;

        file.write_all(&encrypted_length_bytes)?;
        file.write_all(&encrypted_bytes)?;

        let remaining = hidden_header.hidden_data_size - total_size as u64;
        write_random_padding(&mut file, remaining)?;

        file.sync_all()?;
        Ok(())
    }

    /// List all keys in the active volume.
    pub fn list_keys(&self) -> Result<Vec<KeyRecord>> {
        match self.active_volume {
            Some(VolumeType::Outer) => self.list_keys_outer(),
            Some(VolumeType::Hidden) => self.load_hidden_records(),
            None => Err(KeepError::Locked),
        }
    }

    fn list_keys_outer(&self) -> Result<Vec<KeyRecord>> {
        let data_key = self.outer_key.as_ref().ok_or(KeepError::Locked)?;
        let db = self.outer_db.as_ref().ok_or(KeepError::Locked)?;

        let rtxn = db.begin_read()?;
        let table = rtxn.open_table(KEYS_TABLE)?;

        let mut records = Vec::new();

        for result in table.iter()? {
            let (_, encrypted_bytes) = result?;
            let encrypted = EncryptedData::from_bytes(encrypted_bytes.value())?;
            let decrypted = crypto::decrypt(&encrypted, data_key)?;

            let decrypted_bytes = decrypted.as_slice()?;
            let record: KeyRecord = bincode::options()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(MAX_RECORD_SIZE)
                .deserialize(&decrypted_bytes)?;

            records.push(record);
        }

        Ok(records)
    }

    /// Delete a key from the active volume.
    pub fn delete_key(&self, id: &[u8; 32]) -> Result<()> {
        match self.active_volume {
            Some(VolumeType::Outer) => self.delete_key_outer(id),
            Some(VolumeType::Hidden) => self.delete_key_hidden(id),
            None => Err(KeepError::Locked),
        }
    }

    fn delete_key_outer(&self, id: &[u8; 32]) -> Result<()> {
        let db = self.outer_db.as_ref().ok_or(KeepError::Locked)?;

        let wtxn = db.begin_write()?;
        let existed;
        {
            let mut table = wtxn.open_table(KEYS_TABLE)?;
            existed = table.remove(id.as_slice())?.is_some();
        }
        wtxn.commit()?;

        if !existed {
            return Err(KeepError::KeyNotFound(hex::encode(id)));
        }

        Ok(())
    }

    fn delete_key_hidden(&self, id: &[u8; 32]) -> Result<()> {
        let data_key = self.hidden_key.as_ref().ok_or(KeepError::Locked)?;
        let hidden_header = self.hidden_header.as_ref().ok_or(KeepError::Locked)?;

        let mut records = self.load_hidden_records()?;
        let original_len = records.len();
        records.retain(|r| &r.id != id);

        if records.len() == original_len {
            return Err(KeepError::KeyNotFound(hex::encode(id)));
        }

        self.write_hidden_records(&records, data_key, hidden_header)
    }

    /// Persist a relay configuration on the outer volume.
    ///
    /// Only the outer volume is currently supported; hidden-volume relay-config
    /// storage is a documented follow-up so the headless NIP-46 bunker on the
    /// outer side can load pre-grants without leaking the existence of a
    /// hidden volume into the relay layer.
    pub fn store_relay_config(&self, config: &RelayConfig) -> Result<()> {
        match self.active_volume {
            Some(VolumeType::Outer) => {}
            Some(VolumeType::Hidden) => {
                return Err(KeepError::NotImplemented(
                    "relay config storage on the hidden volume is not yet implemented".into(),
                ));
            }
            None => return Err(KeepError::Locked),
        }
        let (data_key, db) = self.outer_relay_handles()?;

        let normalized = config.clone().normalize()?;
        let encrypted_bytes = relay::encode_relay_config(&normalized, data_key)?;

        let wtxn = db.begin_write()?;
        {
            let mut table = wtxn.open_table(RELAY_CONFIGS_TABLE)?;
            table.insert(
                normalized.group_pubkey.as_slice(),
                encrypted_bytes.as_slice(),
            )?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Load a relay configuration from the outer volume.
    ///
    /// Hidden volume callers get `Ok(None)` so a hidden-vault headless bunker
    /// degrades cleanly to the interactive-approval path until hidden-volume
    /// relay-config storage is implemented.
    pub fn get_relay_config(&self, group_pubkey: &[u8; 32]) -> Result<Option<RelayConfig>> {
        match self.active_volume {
            Some(VolumeType::Outer) => {}
            Some(VolumeType::Hidden) => return Ok(None),
            None => return Err(KeepError::Locked),
        }
        let (data_key, db) = self.outer_relay_handles()?;

        let rtxn = db.begin_read()?;
        let table = match rtxn.open_table(RELAY_CONFIGS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let Some(entry) = table.get(group_pubkey.as_slice())? else {
            return Ok(None);
        };
        Ok(Some(relay::decode_relay_config(entry.value(), data_key)?))
    }

    /// Load a relay configuration or return a fresh default for `group_pubkey`.
    pub fn get_relay_config_or_default(&self, group_pubkey: &[u8; 32]) -> Result<RelayConfig> {
        Ok(self
            .get_relay_config(group_pubkey)?
            .unwrap_or_else(|| RelayConfig::with_defaults(*group_pubkey)))
    }

    fn outer_relay_handles(&self) -> Result<(&SecretKey, &Database)> {
        let data_key = self.outer_key.as_ref().ok_or(KeepError::Locked)?;
        let db = self.outer_db.as_ref().ok_or(KeepError::Locked)?;
        Ok((data_key, db))
    }

    /// The vault directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read every audit entry stored under the outer data key. Hidden-vault
    /// scope is deliberately limited to the outer volume (#520, paralleling
    /// the #507 relay-config decision); a hidden-active session has no
    /// audit log of its own and returns `Ok(vec![])` rather than reading
    /// the outer log's contents.
    pub fn audit_read_all(&self) -> Result<Vec<crate::audit::AuditEntry>> {
        match self.active_volume {
            Some(VolumeType::Outer) => {}
            Some(VolumeType::Hidden) => return Ok(Vec::new()),
            None => return Err(KeepError::Locked),
        }
        let (data_key, audit) = self.outer_audit_handles()?;
        audit.read_all(data_key)
    }

    /// Export the outer-volume audit log as JSON. Hidden-active sessions
    /// return an empty array rather than the outer log's contents, matching
    /// the deniability boundary `audit_read_all` enforces.
    pub fn audit_export(&self) -> Result<String> {
        match self.active_volume {
            Some(VolumeType::Outer) => {}
            Some(VolumeType::Hidden) => return Ok("[]".to_string()),
            None => return Err(KeepError::Locked),
        }
        let (data_key, audit) = self.outer_audit_handles()?;
        audit.export(data_key)
    }

    /// Verify the outer-volume audit log's hash chain. Hidden-active sessions
    /// have no log of their own and return `Ok(true)` (vacuously valid).
    pub fn audit_verify_chain(&self) -> Result<bool> {
        match self.active_volume {
            Some(VolumeType::Outer) => {}
            Some(VolumeType::Hidden) => return Ok(true),
            None => return Err(KeepError::Locked),
        }
        let (data_key, audit) = self.outer_audit_handles()?;
        audit.verify_chain(data_key)
    }

    /// Resolve the outer data key and audit log for an outer-active session.
    /// A `None` `outer_audit` despite an unlocked outer volume means
    /// `attach_outer_audit` failed to open the on-disk audit log earlier and
    /// logged the underlying error. Surface a descriptive error rather than
    /// the misleading `Locked` so callers can distinguish "not unlocked yet"
    /// from "unlocked but audit log unavailable" (see PR #540 review).
    fn outer_audit_handles(&self) -> Result<(&SecretKey, &crate::audit::AuditLog)> {
        let data_key = self.outer_key.as_ref().ok_or(KeepError::Locked)?;
        let audit = self.outer_audit.as_ref().ok_or_else(|| {
            KeepError::Other(
                "outer-volume audit log is unavailable; check earlier logs for the underlying open failure (the unlock succeeded but `attach_outer_audit` did not attach an audit log)".into(),
            )
        })?;
        Ok((data_key, audit))
    }

    /// Set the retention policy on the outer-volume audit log. No-op when
    /// the active volume is hidden.
    pub fn audit_set_retention(&mut self, policy: crate::audit::RetentionPolicy) {
        if !matches!(self.active_volume, Some(VolumeType::Outer)) {
            return;
        }
        if let Some(audit) = self.outer_audit.as_mut() {
            audit.set_retention(policy);
        }
    }

    /// Apply the retention policy on the outer-volume audit log. Errors on
    /// hidden-active sessions since no audit log exists there.
    pub fn audit_apply_retention(&mut self) -> Result<usize> {
        match self.active_volume {
            Some(VolumeType::Outer) => {}
            Some(VolumeType::Hidden) => {
                return Err(KeepError::Other(
                    "audit retention is not yet supported on the hidden volume".into(),
                ));
            }
            None => return Err(KeepError::Locked),
        }
        let data_key = self.outer_key.as_ref().ok_or(KeepError::Locked)?;
        let audit = self.outer_audit.as_mut().ok_or_else(|| {
            KeepError::Other(
                "outer-volume audit log is unavailable; check earlier logs for the underlying open failure (the unlock succeeded but `attach_outer_audit` did not attach an audit log)".into(),
            )
        })?;
        audit.apply_retention(data_key)
    }
}

impl Drop for HiddenStorage {
    fn drop(&mut self) {
        self.lock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyType;
    use tempfile::tempdir;

    #[test]
    fn test_create_and_unlock_outer() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-hidden");

        {
            let storage = HiddenStorage::create(
                &path,
                "outer_password",
                Some("hidden_password"),
                10 * 1024 * 1024,
                0.2,
                Argon2Params::TESTING,
            )
            .unwrap();

            assert!(storage.active_volume() == Some(VolumeType::Outer));
        }

        {
            let mut storage = HiddenStorage::open(&path).unwrap();
            assert!(storage.active_volume().is_none());

            storage.unlock_outer("outer_password").unwrap();
            assert!(storage.active_volume() == Some(VolumeType::Outer));
        }
    }

    #[test]
    fn test_unlock_hidden() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-hidden2");

        HiddenStorage::create(
            &path,
            "outer",
            Some("hidden"),
            10 * 1024 * 1024,
            0.2,
            Argon2Params::TESTING,
        )
        .unwrap();

        let mut storage = HiddenStorage::open(&path).unwrap();

        storage.unlock_hidden("hidden").unwrap();
        assert!(storage.active_volume() == Some(VolumeType::Hidden));
        assert!(storage.is_hidden_unlocked());
    }

    #[test]
    fn test_smart_unlock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-hidden3");

        HiddenStorage::create(
            &path,
            "outer",
            Some("hidden"),
            10 * 1024 * 1024,
            0.2,
            Argon2Params::TESTING,
        )
        .unwrap();

        {
            let mut storage = HiddenStorage::open(&path).unwrap();
            let volume = storage.unlock("outer").unwrap();
            assert_eq!(volume, VolumeType::Outer);
        }

        {
            let mut storage = HiddenStorage::open(&path).unwrap();
            let volume = storage.unlock("hidden").unwrap();
            assert_eq!(volume, VolumeType::Hidden);
        }
    }

    #[test]
    fn test_wrong_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-hidden4");

        HiddenStorage::create(
            &path,
            "correct",
            None,
            10 * 1024 * 1024,
            0.0,
            Argon2Params::TESTING,
        )
        .unwrap();

        let mut storage = HiddenStorage::open(&path).unwrap();
        let result = storage.unlock("wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_outer_volume_key_operations() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-hidden5");

        let storage = HiddenStorage::create(
            &path,
            "password",
            None,
            10 * 1024 * 1024,
            0.0,
            Argon2Params::TESTING,
        )
        .unwrap();

        let record = KeyRecord::new(
            crypto::random_bytes(),
            KeyType::Nostr,
            "test key".into(),
            vec![1, 2, 3, 4],
        );

        storage.store_key(&record).unwrap();

        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, record.name);

        storage.delete_key(&record.id).unwrap();
        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_hidden_volume_key_operations() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-hidden6");

        HiddenStorage::create(
            &path,
            "outer",
            Some("hidden"),
            10 * 1024 * 1024,
            0.2,
            Argon2Params::TESTING,
        )
        .unwrap();

        let mut storage = HiddenStorage::open(&path).unwrap();
        storage.unlock_hidden("hidden").unwrap();

        let record = KeyRecord::new(
            crypto::random_bytes(),
            KeyType::Nostr,
            "hidden key".into(),
            vec![5, 6, 7, 8],
        );

        storage.store_key(&record).unwrap();

        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "hidden key");

        storage.delete_key(&record.id).unwrap();
        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_volume_isolation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-hidden7");

        {
            let storage = HiddenStorage::create(
                &path,
                "outer",
                Some("hidden"),
                10 * 1024 * 1024,
                0.2,
                Argon2Params::TESTING,
            )
            .unwrap();

            let outer_key = KeyRecord::new(
                crypto::random_bytes(),
                KeyType::Nostr,
                "outer key".into(),
                vec![1, 2, 3],
            );
            storage.store_key(&outer_key).unwrap();
        }

        {
            let mut storage = HiddenStorage::open(&path).unwrap();
            storage.unlock_hidden("hidden").unwrap();

            let hidden_key = KeyRecord::new(
                crypto::random_bytes(),
                KeyType::Nostr,
                "hidden key".into(),
                vec![4, 5, 6],
            );
            storage.store_key(&hidden_key).unwrap();

            let hidden_keys = storage.list_keys().unwrap();
            assert_eq!(hidden_keys.len(), 1);
            assert_eq!(hidden_keys[0].name, "hidden key");
        }

        {
            let mut storage = HiddenStorage::open(&path).unwrap();
            storage.unlock_outer("outer").unwrap();

            let outer_keys = storage.list_keys().unwrap();
            assert_eq!(outer_keys.len(), 1);
            assert_eq!(outer_keys[0].name, "outer key");
        }
    }

    #[test]
    fn test_sequential_key_operations() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-sequential");

        let storage = HiddenStorage::create(
            &path,
            "password",
            None,
            10 * 1024 * 1024,
            0.0,
            Argon2Params::TESTING,
        )
        .unwrap();

        for i in 0..4 {
            let record = KeyRecord::new(
                crypto::random_bytes(),
                KeyType::Nostr,
                format!("key-{i}"),
                vec![i as u8],
            );
            storage.store_key(&record).unwrap();
        }

        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 4);

        drop(storage);

        let mut storage = HiddenStorage::open(&path).unwrap();
        storage.unlock_outer("password").unwrap();
        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 4);
    }

    #[test]
    fn test_volume_isolation_sequential() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-isolation-sequential");

        {
            let storage = HiddenStorage::create(
                &path,
                "outer",
                Some("hidden"),
                10 * 1024 * 1024,
                0.2,
                Argon2Params::TESTING,
            )
            .unwrap();

            for i in 0..3 {
                let record = KeyRecord::new(
                    crypto::random_bytes(),
                    KeyType::Nostr,
                    format!("outer-{i}"),
                    vec![i as u8],
                );
                storage.store_key(&record).unwrap();
            }
        }

        {
            let mut storage = HiddenStorage::open(&path).unwrap();
            storage.unlock_hidden("hidden").unwrap();

            for i in 0..2 {
                let record = KeyRecord::new(
                    crypto::random_bytes(),
                    KeyType::Nostr,
                    format!("hidden-{i}"),
                    vec![100 + i as u8],
                );
                storage.store_key(&record).unwrap();
            }
        }

        {
            let mut storage = HiddenStorage::open(&path).unwrap();
            storage.unlock_outer("outer").unwrap();
            let keys = storage.list_keys().unwrap();
            assert_eq!(keys.len(), 3);
            assert!(keys.iter().all(|k| k.name.starts_with("outer-")));
        }

        {
            let mut storage = HiddenStorage::open(&path).unwrap();
            storage.unlock_hidden("hidden").unwrap();
            let keys = storage.list_keys().unwrap();
            assert_eq!(keys.len(), 2);
            assert!(keys.iter().all(|k| k.name.starts_with("hidden-")));
        }
    }

    #[test]
    fn test_rate_limiting_outer() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-rate-outer");

        HiddenStorage::create(
            &path,
            "outer",
            Some("hidden"),
            10 * 1024 * 1024,
            0.2,
            Argon2Params::TESTING,
        )
        .unwrap();

        // First 5 attempts - new storage each time to test persistence
        for _ in 0..5 {
            let mut storage = HiddenStorage::open(&path).unwrap();
            let result = storage.unlock_outer("wrong");
            assert!(result.is_err());
            assert!(!matches!(result, Err(KeepError::RateLimited(_))));
        }

        // Attempts 6-8 on same instance for tight timing.
        // After 5 failures, delay=1s. After 6, delay=2s. After 7, delay=4s.
        // Three rapid attempts ensures we hit rate limiting even on very
        // slow CI runners where individual Argon2 calls take >1s.
        let mut storage = HiddenStorage::open(&path).unwrap();
        let _ = storage.unlock_outer("wrong");
        let _ = storage.unlock_outer("wrong");
        let result = storage.unlock_outer("wrong");
        assert!(matches!(result, Err(KeepError::RateLimited(_))));
    }

    #[test]
    fn test_rate_limiting_hidden() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-rate-hidden");

        HiddenStorage::create(
            &path,
            "outer",
            Some("hidden"),
            10 * 1024 * 1024,
            0.2,
            Argon2Params::TESTING,
        )
        .unwrap();

        // First 5 attempts - new storage each time to test persistence
        for _ in 0..5 {
            let mut storage = HiddenStorage::open(&path).unwrap();
            let result = storage.unlock_hidden("wrong");
            assert!(result.is_err());
            assert!(!matches!(result, Err(KeepError::RateLimited(_))));
        }

        // Attempts 6-8 on same instance for tight timing.
        // After 5 failures, delay=1s. After 6, delay=2s. After 7, delay=4s.
        // Three rapid attempts ensures we hit rate limiting even on very
        // slow CI runners where individual Argon2 calls take >1s.
        let mut storage = HiddenStorage::open(&path).unwrap();
        let _ = storage.unlock_hidden("wrong");
        let _ = storage.unlock_hidden("wrong");
        let result = storage.unlock_hidden("wrong");
        assert!(matches!(result, Err(KeepError::RateLimited(_))));
    }

    #[test]
    fn test_rate_limiting_combined_unlock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-rate-combined");

        HiddenStorage::create(
            &path,
            "outer",
            Some("hidden"),
            10 * 1024 * 1024,
            0.2,
            Argon2Params::TESTING,
        )
        .unwrap();

        // First 5 attempts - new storage each time to test persistence
        for _ in 0..5 {
            let mut storage = HiddenStorage::open(&path).unwrap();
            let result = storage.unlock("wrong");
            assert!(result.is_err());
            assert!(!matches!(result, Err(KeepError::RateLimited(_))));
        }

        // Attempts 6-8 on same instance for tight timing.
        // After 5 failures, delay=1s. After 6, delay=2s. After 7, delay=4s.
        // Three rapid attempts ensures we hit rate limiting even on very
        // slow CI runners where individual Argon2 calls take >1s.
        let mut storage = HiddenStorage::open(&path).unwrap();
        let _ = storage.unlock("wrong");
        let _ = storage.unlock("wrong");
        let result = storage.unlock("wrong");
        assert!(matches!(result, Err(KeepError::RateLimited(_))));
    }

    #[test]
    fn relay_config_round_trip_outer() {
        use crate::relay::{
            RelayConfig, StoredBunkerPermission, StoredPermissionDuration, GLOBAL_RELAY_KEY,
        };

        let dir = tempdir().unwrap();
        let path = dir.path().join("test-relay-cfg-outer");

        HiddenStorage::create(
            &path,
            "outer",
            Some("hidden"),
            10 * 1024 * 1024,
            0.2,
            Argon2Params::TESTING,
        )
        .unwrap();

        let mut storage = HiddenStorage::open(&path).unwrap();
        storage.unlock_outer("outer").unwrap();

        // Default until first write.
        let initial = storage
            .get_relay_config_or_default(&GLOBAL_RELAY_KEY)
            .unwrap();
        assert!(initial.bunker_permissions.is_empty());

        let mut cfg = RelayConfig::with_defaults(GLOBAL_RELAY_KEY);
        cfg.bunker_permissions.push(StoredBunkerPermission {
            pubkey_hex: "a".repeat(64),
            name: "client".to_string(),
            permissions: 0b1111,
            auto_approve_kinds: vec![1, 7],
            duration: StoredPermissionDuration::Forever,
            connected_at: 100,
            timed_kind_grants: Vec::new(),
        });
        cfg.auto_approve_kinds = vec![22242];

        storage.store_relay_config(&cfg).unwrap();

        let loaded = storage
            .get_relay_config(&GLOBAL_RELAY_KEY)
            .unwrap()
            .expect("stored config should round-trip");
        assert_eq!(loaded.bunker_permissions.len(), 1);
        assert_eq!(loaded.bunker_permissions[0].name, "client");
        assert_eq!(loaded.auto_approve_kinds, vec![22242]);
    }

    #[test]
    fn relay_config_returns_none_on_hidden_volume() {
        use crate::relay::GLOBAL_RELAY_KEY;

        let dir = tempdir().unwrap();
        let path = dir.path().join("test-relay-cfg-hidden");

        HiddenStorage::create(
            &path,
            "outer",
            Some("hidden"),
            10 * 1024 * 1024,
            0.2,
            Argon2Params::TESTING,
        )
        .unwrap();

        let mut storage = HiddenStorage::open(&path).unwrap();
        storage.unlock_hidden("hidden").unwrap();

        // Hidden-active reads return Ok(None) so headless callers can degrade
        // cleanly until hidden-volume scope is implemented.
        let result = storage.get_relay_config(&GLOBAL_RELAY_KEY).unwrap();
        assert!(result.is_none());

        // Writes from a hidden-active session are explicitly refused so they
        // never silently land in outer storage and leak hidden-volume activity.
        let cfg = crate::relay::RelayConfig::with_defaults(GLOBAL_RELAY_KEY);
        assert!(storage.store_relay_config(&cfg).is_err());
    }

    #[test]
    fn relay_config_round_trip_persists_across_open() {
        use crate::relay::{RelayConfig, GLOBAL_RELAY_KEY};

        let dir = tempdir().unwrap();
        let path = dir.path().join("test-relay-cfg-reopen");

        HiddenStorage::create(
            &path,
            "outer",
            None,
            10 * 1024 * 1024,
            0.0,
            Argon2Params::TESTING,
        )
        .unwrap();

        {
            let mut storage = HiddenStorage::open(&path).unwrap();
            storage.unlock_outer("outer").unwrap();
            let mut cfg = RelayConfig::with_defaults(GLOBAL_RELAY_KEY);
            cfg.auto_approve_kinds = vec![1, 2, 3];
            storage.store_relay_config(&cfg).unwrap();
        }
        {
            let mut storage = HiddenStorage::open(&path).unwrap();
            storage.unlock_outer("outer").unwrap();
            let loaded = storage
                .get_relay_config(&GLOBAL_RELAY_KEY)
                .unwrap()
                .unwrap();
            assert_eq!(loaded.auto_approve_kinds, vec![1, 2, 3]);
        }
    }

    /// Pin that hidden-vault outer unlock surfaces the #422 lock-holder hint
    /// when the outer redb is already held (mirrors
    /// `backend::tests::second_open_surfaces_lock_holder_hint` for the
    /// HiddenStorage code path, which has its own retry+map_open_failure
    /// chain).
    #[test]
    fn hidden_outer_unlock_surfaces_lock_holder_hint() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-locked-hidden");

        HiddenStorage::create(
            &path,
            "outer",
            None,
            10 * 1024 * 1024,
            0.0,
            Argon2Params::TESTING,
        )
        .unwrap();

        let mut first = HiddenStorage::open(&path).unwrap();
        first.unlock_outer("outer").unwrap();

        let mut second = HiddenStorage::open(&path).unwrap();
        let err = match second.unlock_outer("outer") {
            Err(e) => e,
            Ok(_) => panic!("second outer unlock while first is held must fail"),
        };
        let msg = err.to_string();
        assert!(
            matches!(err, KeepError::Database(_)),
            "expected Database from map_open_failure, got {err:?}"
        );
        assert!(
            msg.contains("already opened by another process"),
            "got {msg}"
        );
        assert!(msg.contains("#422"), "got {msg}");
    }

    /// #520 end-to-end on the hidden-vault outer path: trip the rate limiter
    /// with failed unlocks, then successfully unlock and observe the
    /// `RateLimitTripped` entry in the outer audit log. Mirrors the
    /// `rate_limit_trip_emits_audit_entry_on_next_unlock` test that proves
    /// this works on regular vaults.
    #[test]
    fn hidden_outer_unlock_flushes_rate_limit_trips_to_audit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault-trip-audit");

        HiddenStorage::create(
            &path,
            "outer-password",
            None,
            10 * 1024 * 1024,
            0.0,
            Argon2Params::TESTING,
        )
        .unwrap();

        // Five failed attempts trip the limiter.
        for _ in 0..5 {
            let mut storage = HiddenStorage::open(&path).unwrap();
            let _ = storage.unlock_outer("wrong-password");
        }

        // Clear the rate-limit counter so the next attempt isn't gated by the
        // active back-off. The trip queue lives in a separate file the rate
        // limiter deliberately does NOT clear on success.
        crate::rate_limit::record_success(&path);

        let mut storage = HiddenStorage::open(&path).unwrap();
        storage.unlock_outer("outer-password").unwrap();

        let entries = storage.audit_read_all().unwrap();
        let trips: Vec<_> = entries
            .iter()
            .filter(|e| matches!(e.event_type, crate::audit::AuditEventType::RateLimitTripped))
            .collect();
        assert_eq!(
            trips.len(),
            1,
            "exactly one trip entry must surface after hidden-outer unlock; got {trips:#?}"
        );
        assert!(!trips[0].success, "trip entry must record success=false");
        assert!(
            trips[0]
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("rate limit")),
            "trip entry must carry a descriptive reason"
        );

        let trip_idx = entries
            .iter()
            .position(|e| matches!(e.event_type, crate::audit::AuditEventType::RateLimitTripped))
            .unwrap();
        let unlock_idx = entries
            .iter()
            .rposition(|e| matches!(e.event_type, crate::audit::AuditEventType::VaultUnlock))
            .unwrap();
        assert!(
            trip_idx < unlock_idx,
            "trip must precede the unlock it was observed by"
        );

        assert!(storage.audit_verify_chain().unwrap());
    }

    /// A hidden-active session must NOT surface the outer audit log's
    /// contents. Pin so a future refactor doesn't accidentally leak outer
    /// activity through the hidden-active read paths.
    #[test]
    fn hidden_active_audit_returns_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault-hidden-audit-empty");

        HiddenStorage::create(
            &path,
            "outer",
            Some("hidden"),
            10 * 1024 * 1024,
            0.2,
            Argon2Params::TESTING,
        )
        .unwrap();

        let mut storage = HiddenStorage::open(&path).unwrap();
        storage.unlock_hidden("hidden").unwrap();

        assert!(storage.audit_read_all().unwrap().is_empty());
        assert!(storage.audit_verify_chain().unwrap());
        assert!(storage.audit_apply_retention().is_err());
        // Export must also surface the same deniability boundary — the outer
        // log's JSON must not appear under a hidden-active session.
        assert_eq!(storage.audit_export().unwrap(), "[]");
    }

    /// `audit_export` on the outer-volume path must serialise the outer log
    /// as JSON. Pin so `keep audit export` against a hidden-init vault stops
    /// erroring (the explicit gap left open by PR #538 / closed here).
    #[test]
    fn hidden_outer_audit_export_returns_valid_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault-outer-audit-export");

        HiddenStorage::create(
            &path,
            "outer",
            None,
            10 * 1024 * 1024,
            0.0,
            Argon2Params::TESTING,
        )
        .unwrap();

        let mut storage = HiddenStorage::open(&path).unwrap();
        storage.unlock_outer("outer").unwrap();

        let json = storage.audit_export().unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("audit_export output must be valid JSON");
        let arr = parsed.as_array().expect("export root must be a JSON array");

        // `AuditEventType` derives `Serialize` without a tag attribute, so a
        // `VaultUnlock` entry serializes as `{"event_type":"VaultUnlock", ...}`.
        // Pin the actual invariant — unlock emitted at least one such entry —
        // instead of a loose `!arr.is_empty()` check which would also pass on
        // a stray `RateLimitTripped` from an earlier session.
        let has_unlock = arr.iter().any(|entry| {
            entry
                .get("event_type")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s == "VaultUnlock")
        });
        assert!(
            has_unlock,
            "expected exported audit to contain a VaultUnlock entry; got {arr:#?}"
        );
    }

    /// Deniability boundary must hold even when the outer log is populated.
    /// Unlocking outer first fills `outer_key`/`outer_audit`; switching to the
    /// hidden volume must still yield "[]" from `audit_export`. Pins that the
    /// hidden-active guard, not a `None` outer key, enforces the boundary.
    #[test]
    fn hidden_active_audit_export_empty_with_populated_outer() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault-outer-populated-then-hidden");

        HiddenStorage::create(
            &path,
            "outer",
            Some("hidden"),
            10 * 1024 * 1024,
            0.2,
            Argon2Params::TESTING,
        )
        .unwrap();

        let mut storage = HiddenStorage::open(&path).unwrap();
        storage.unlock_outer("outer").unwrap();
        // Outer export is non-empty here (VaultUnlock entry present).
        let outer_json = storage.audit_export().unwrap();
        let outer_parsed: serde_json::Value = serde_json::from_str(&outer_json).unwrap();
        assert!(!outer_parsed.as_array().unwrap().is_empty());

        storage.unlock_hidden("hidden").unwrap();
        assert_eq!(storage.active_volume(), Some(VolumeType::Hidden));
        assert_eq!(storage.audit_export().unwrap(), "[]");
    }

    /// #520 on the auto-detect `unlock()` path: tripping the limiter then
    /// unlocking via the dispatcher (not `unlock_outer`) must still flush the
    /// `RateLimitTripped` entry and attach the outer audit log. Pins the fix
    /// for the dispatcher arm that previously skipped `attach_outer_audit`.
    #[test]
    fn hidden_dispatch_unlock_flushes_rate_limit_trips_to_audit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault-dispatch-trip-audit");

        HiddenStorage::create(
            &path,
            "outer-password",
            None,
            10 * 1024 * 1024,
            0.0,
            Argon2Params::TESTING,
        )
        .unwrap();

        for _ in 0..5 {
            let mut storage = HiddenStorage::open(&path).unwrap();
            let _ = storage.unlock_outer("wrong-password");
        }

        crate::rate_limit::record_success(&path);

        let mut storage = HiddenStorage::open(&path).unwrap();
        assert_eq!(storage.unlock("outer-password").unwrap(), VolumeType::Outer);

        let entries = storage.audit_read_all().unwrap();
        let trips: Vec<_> = entries
            .iter()
            .filter(|e| matches!(e.event_type, crate::audit::AuditEventType::RateLimitTripped))
            .collect();
        assert_eq!(
            trips.len(),
            1,
            "dispatcher unlock must flush exactly one trip entry; got {trips:#?}"
        );
        assert!(storage.audit_verify_chain().unwrap());
    }
}
