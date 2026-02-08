// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

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

use rand::RngCore;
use redb::{Database, ReadableTable, TableDefinition};

use crate::crypto::{self, Argon2Params, EncryptedData, SecretKey};
use crate::error::{KeepError, Result, StorageError};
use crate::keys::KeyRecord;
use crate::rate_limit;

use bincode::Options;

use super::header::{
    HiddenHeader, OuterHeader, DATA_START_OFFSET, HEADER_SIZE, HIDDEN_HEADER_OFFSET,
};

const KEYS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("keys");

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
        let vault_path = path.join("keep.vault");
        let mut file = File::create(&vault_path)?;

        file.write_all(&outer_header.to_bytes())?;

        let mut hidden_area: [u8; HEADER_SIZE] = crypto::random_bytes();
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

        let wtxn = db.begin_write()?;
        let _ = wtxn.open_table(KEYS_TABLE)?;
        wtxn.commit()?;

        Ok(Self {
            path: path.to_path_buf(),
            outer_header,
            hidden_header,
            outer_key: Some(outer_data_key),
            hidden_key: hidden_data_key,
            active_volume: Some(VolumeType::Outer),
            outer_db: Some(db),
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
        let db = Database::open(&db_path)?;

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
            let arr: [u8; 8] = length_bytes.try_into().ok()?;
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

    /// The vault directory path.
    pub fn path(&self) -> &Path {
        &self.path
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

        // Attempts 6 and 7 on same instance for tight timing.
        // After 5 failures, delay=1s. After 6, delay=2s. Two attempts
        // ensures we hit rate limiting even if the first attempt's
        // 1-second window expired on slow CI.
        let mut storage = HiddenStorage::open(&path).unwrap();
        let result = storage.unlock_outer("wrong");
        assert!(result.is_err()); // May or may not be rate limited (1s window)

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

        // Attempts 6 and 7 on same instance for tight timing.
        // After 5 failures, delay=1s. After 6, delay=2s. Two attempts
        // ensures we hit rate limiting even if the first attempt's
        // 1-second window expired on slow CI.
        let mut storage = HiddenStorage::open(&path).unwrap();
        let result = storage.unlock_hidden("wrong");
        assert!(result.is_err()); // May or may not be rate limited (1s window)

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

        // Attempts 6 and 7 on same instance for tight timing.
        // After 5 failures, delay=1s. After 6, delay=2s. Two attempts
        // ensures we hit rate limiting even if the first attempt's
        // 1-second window expired on slow CI.
        let mut storage = HiddenStorage::open(&path).unwrap();
        let result = storage.unlock("wrong");
        assert!(result.is_err()); // May or may not be rate limited (1s window)

        let result = storage.unlock("wrong");
        assert!(matches!(result, Err(KeepError::RateLimited(_))));
    }
}
