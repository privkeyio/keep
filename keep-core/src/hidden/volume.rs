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
//! │   Outer Header      │  256 bytes - salt, encrypted data key, argon2 params
//! ├─────────────────────┤  256
//! │   Hidden Header     │  256 bytes - encrypted with separate KDF salt (looks random)
//! ├─────────────────────┤  512 (DATA_START_OFFSET)
//! │   Outer Data Area   │  Variable size - redb database for outer volume
//! ├─────────────────────┤
//! │   Hidden Data Area  │  Variable size - serialized records for hidden volume
//! └─────────────────────┘
//! ```
//!
//! # Security Properties
//!
//! - Hidden header is encrypted and indistinguishable from random bytes
//! - Wrong password for hidden volume produces same error as "no hidden volume"
//! - Both volumes use independent Argon2id key derivation
//! - Unlock attempts both decryptions to prevent timing attacks

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;
use redb::{Database, ReadableTable, TableDefinition};

use crate::crypto::{self, Argon2Params, EncryptedData, SecretKey};
use crate::error::{KeepError, Result};
use crate::keys::KeyRecord;
use crate::rate_limit;

use bincode::Options;

use super::header::{
    HiddenHeader, OuterHeader, DATA_START_OFFSET, HEADER_SIZE, HIDDEN_HEADER_OFFSET,
};

const KEYS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("keys");

const MAX_RECORD_SIZE: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeType {
    Outer,
    Hidden,
}

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
    pub fn create(
        path: &Path,
        outer_password: &str,
        hidden_password: Option<&str>,
        total_size: u64,
        hidden_ratio: f32,
    ) -> Result<Self> {
        if path.exists() {
            return Err(KeepError::AlreadyExists(path.display().to_string()));
        }

        if !(0.0..=1.0).contains(&hidden_ratio) {
            return Err(KeepError::Other(format!(
                "hidden_ratio must be between 0.0 and 1.0, got {}",
                hidden_ratio
            )));
        }

        let hidden_size = if hidden_password.is_some() {
            ((total_size as f64) * (hidden_ratio as f64)) as u64
        } else {
            0
        };

        let required_min = DATA_START_OFFSET
            .checked_add(hidden_size)
            .ok_or_else(|| KeepError::Other("Volume size overflow".into()))?;

        if total_size < required_min {
            return Err(KeepError::Other(format!(
                "Total size {} too small, need at least {} bytes (header: {}, hidden: {})",
                total_size, required_min, DATA_START_OFFSET, hidden_size
            )));
        }

        let outer_size = total_size - DATA_START_OFFSET - hidden_size;

        let mut outer_header = OuterHeader::new(Argon2Params::DEFAULT, outer_size, total_size);

        let outer_data_key = SecretKey::generate()?;
        let outer_master_key = crypto::derive_key(
            outer_password.as_bytes(),
            &outer_header.salt,
            Argon2Params::DEFAULT,
        )?;
        let outer_header_key = crypto::derive_subkey(&outer_master_key, b"keep-outer-header")?;

        let outer_key_bytes = outer_data_key.decrypt()?;
        let encrypted_outer = crypto::encrypt(&*outer_key_bytes, &outer_header_key)?;
        outer_header.nonce.copy_from_slice(&encrypted_outer.nonce);
        outer_header
            .encrypted_data_key
            .copy_from_slice(&encrypted_outer.ciphertext);

        let (hidden_header, hidden_data_key, hidden_kdf_salt) = if let Some(hp) = hidden_password {
            let hidden_offset = DATA_START_OFFSET + outer_size;
            let mut hh = HiddenHeader::new(hidden_offset, hidden_size);

            let hidden_data_key = SecretKey::generate()?;

            let kdf_salt: [u8; 32] = crypto::random_bytes();

            let hidden_master_key =
                crypto::derive_key(hp.as_bytes(), &kdf_salt, Argon2Params::DEFAULT)?;
            let hidden_header_key =
                crypto::derive_subkey(&hidden_master_key, b"keep-hidden-header")?;

            let hidden_key_bytes = hidden_data_key.decrypt()?;
            let encrypted_hidden = crypto::encrypt(&*hidden_key_bytes, &hidden_header_key)?;
            hh.nonce.copy_from_slice(&encrypted_hidden.nonce);
            hh.encrypted_data_key
                .copy_from_slice(&encrypted_hidden.ciphertext);

            hh.checksum = hh.compute_checksum();

            (Some(hh), Some(hidden_data_key), Some(kdf_salt))
        } else {
            (None, None, None)
        };

        fs::create_dir_all(path)?;
        let vault_path = path.join("keep.vault");
        let mut file = File::create(&vault_path)?;

        file.write_all(&outer_header.to_bytes())?;

        if let Some(ref hh) = hidden_header {
            let kdf_salt = hidden_kdf_salt.unwrap();

            let hidden_master_key = crypto::derive_key(
                hidden_password.unwrap().as_bytes(),
                &kdf_salt,
                Argon2Params::DEFAULT,
            )?;
            let hidden_header_enc_key =
                crypto::derive_subkey(&hidden_master_key, b"keep-hidden-header-enc")?;

            let encrypted_hh = crypto::encrypt(&hh.to_bytes_compact(), &hidden_header_enc_key)?;

            let mut hidden_area: [u8; HEADER_SIZE] = crypto::random_bytes();
            hidden_area[..32].copy_from_slice(&kdf_salt);
            hidden_area[32..56].copy_from_slice(&encrypted_hh.nonce);
            hidden_area[56..56 + encrypted_hh.ciphertext.len()]
                .copy_from_slice(&encrypted_hh.ciphertext);
            file.write_all(&hidden_area)?;
        } else {
            let random_bytes: [u8; HEADER_SIZE] = crypto::random_bytes();
            file.write_all(&random_bytes)?;
        }

        let remaining = total_size - DATA_START_OFFSET;
        let mut written = 0u64;
        let mut buffer = [0u8; 4096];

        while written < remaining {
            let to_write = ((remaining - written) as usize).min(buffer.len());
            rand::rng().fill_bytes(&mut buffer[..to_write]);
            file.write_all(&buffer[..to_write])?;
            written += to_write as u64;
        }

        file.sync_all()?;
        drop(file);

        let db_path = path.join("keep.db");
        let db = Database::create(&db_path)?;

        {
            let wtxn = db.begin_write()?;
            {
                let _ = wtxn.open_table(KEYS_TABLE)?;
            }
            wtxn.commit()?;
        }

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

        let mut kdf_salt = [0u8; 32];
        kdf_salt.copy_from_slice(&hidden_area[..32]);

        let master_key = crypto::derive_key(password.as_bytes(), &kdf_salt, Argon2Params::DEFAULT)?;

        let header_enc_key = crypto::derive_subkey(&master_key, b"keep-hidden-header-enc")?;

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&hidden_area[32..56]);

        const ENCRYPTED_HEADER_SIZE: usize = HiddenHeader::COMPACT_SIZE + crypto::TAG_SIZE;

        let encrypted = EncryptedData {
            nonce,
            ciphertext: hidden_area[56..56 + ENCRYPTED_HEADER_SIZE].to_vec(),
        };

        let decrypted = match crypto::decrypt(&encrypted, &header_enc_key) {
            Ok(d) => d,
            Err(_) => return Err(KeepError::InvalidPassword),
        };

        let decrypted_bytes = decrypted.as_slice()?;
        let hidden_header = HiddenHeader::from_bytes_compact(&decrypted_bytes)?;

        if !hidden_header.verify_checksum() {
            return Err(KeepError::InvalidPassword);
        }

        let data_key_enc = crypto::derive_subkey(&master_key, b"keep-hidden-header")?;

        let mut data_nonce = [0u8; 24];
        data_nonce.copy_from_slice(&hidden_header.nonce);

        let data_encrypted = EncryptedData {
            nonce: data_nonce,
            ciphertext: hidden_header.encrypted_data_key.to_vec(),
        };

        let data_key_bytes = crypto::decrypt(&data_encrypted, &data_key_enc)?;
        let data_key_slice = data_key_bytes.as_slice()?;
        self.hidden_key = Some(SecretKey::from_slice(&data_key_slice)?);
        self.hidden_header = Some(hidden_header);
        self.active_volume = Some(VolumeType::Hidden);

        Ok(())
    }

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

    pub fn lock(&mut self) {
        self.outer_key = None;
        self.hidden_key = None;
        self.hidden_header = None;
        self.active_volume = None;
        self.outer_db = None;
    }

    pub fn is_unlocked(&self) -> bool {
        self.active_volume.is_some()
    }

    pub fn data_key(&self) -> Option<&SecretKey> {
        match self.active_volume {
            Some(VolumeType::Hidden) => self.hidden_key.as_ref(),
            Some(VolumeType::Outer) => self.outer_key.as_ref(),
            None => None,
        }
    }

    pub fn active_volume(&self) -> Option<VolumeType> {
        self.active_volume
    }

    pub fn is_hidden_unlocked(&self) -> bool {
        self.hidden_key.is_some()
    }

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

        let mut size_bytes = [0u8; 8];
        if file.read_exact(&mut size_bytes).is_err() {
            return Ok(Vec::new());
        }

        let data_size = u64::from_le_bytes(size_bytes);
        if data_size == 0 || data_size > hidden_header.hidden_data_size {
            return Ok(Vec::new());
        }

        let mut encrypted_data = vec![0u8; data_size as usize];
        file.read_exact(&mut encrypted_data)?;

        let encrypted = match EncryptedData::from_bytes(&encrypted_data) {
            Ok(e) => e,
            Err(_) => return Ok(Vec::new()),
        };

        let decrypted = match crypto::decrypt(&encrypted, data_key) {
            Ok(d) => d,
            Err(_) => return Ok(Vec::new()),
        };

        let decrypted_bytes = match decrypted.as_slice() {
            Ok(d) => d,
            Err(_) => return Ok(Vec::new()),
        };
        let records: Vec<KeyRecord> = match bincode::options()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_RECORD_SIZE)
            .deserialize(&decrypted_bytes)
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to deserialize hidden records (possible data corruption or wrong password)"
                );
                Vec::new()
            }
        };
        Ok(records)
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

        if (encrypted_bytes.len() + 8) as u64 > hidden_header.hidden_data_size {
            return Err(KeepError::Other("Hidden volume full".into()));
        }

        let vault_path = self.path.join("keep.vault");
        let mut file = OpenOptions::new().write(true).open(&vault_path)?;
        file.seek(SeekFrom::Start(hidden_header.hidden_data_offset))?;

        file.write_all(&(encrypted_bytes.len() as u64).to_le_bytes())?;
        file.write_all(&encrypted_bytes)?;

        let remaining = hidden_header.hidden_data_size - encrypted_bytes.len() as u64 - 8;
        let mut buffer = [0u8; 4096];
        let mut written = 0u64;
        while written < remaining {
            let to_write = ((remaining - written) as usize).min(buffer.len());
            rand::rng().fill_bytes(&mut buffer[..to_write]);
            file.write_all(&buffer[..to_write])?;
            written += to_write as u64;
        }

        file.sync_all()?;
        Ok(())
    }

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

        HiddenStorage::create(&path, "outer", Some("hidden"), 10 * 1024 * 1024, 0.2).unwrap();

        let mut storage = HiddenStorage::open(&path).unwrap();

        storage.unlock_hidden("hidden").unwrap();
        assert!(storage.active_volume() == Some(VolumeType::Hidden));
        assert!(storage.is_hidden_unlocked());
    }

    #[test]
    fn test_smart_unlock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-hidden3");

        HiddenStorage::create(&path, "outer", Some("hidden"), 10 * 1024 * 1024, 0.2).unwrap();

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

        HiddenStorage::create(&path, "correct", None, 10 * 1024 * 1024, 0.0).unwrap();

        let mut storage = HiddenStorage::open(&path).unwrap();
        let result = storage.unlock("wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_outer_volume_key_operations() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-hidden5");

        let storage =
            HiddenStorage::create(&path, "password", None, 10 * 1024 * 1024, 0.0).unwrap();

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

        HiddenStorage::create(&path, "outer", Some("hidden"), 10 * 1024 * 1024, 0.2).unwrap();

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
            let storage =
                HiddenStorage::create(&path, "outer", Some("hidden"), 10 * 1024 * 1024, 0.2)
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

        let storage =
            HiddenStorage::create(&path, "password", None, 10 * 1024 * 1024, 0.0).unwrap();

        for i in 0..4 {
            let record = KeyRecord::new(
                crypto::random_bytes(),
                KeyType::Nostr,
                format!("key-{}", i),
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
            let storage =
                HiddenStorage::create(&path, "outer", Some("hidden"), 10 * 1024 * 1024, 0.2)
                    .unwrap();

            for i in 0..3 {
                let record = KeyRecord::new(
                    crypto::random_bytes(),
                    KeyType::Nostr,
                    format!("outer-{}", i),
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
                    format!("hidden-{}", i),
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

        HiddenStorage::create(&path, "outer", Some("hidden"), 10 * 1024 * 1024, 0.2).unwrap();

        for _ in 0..5 {
            let mut storage = HiddenStorage::open(&path).unwrap();
            let result = storage.unlock_outer("wrong");
            assert!(result.is_err());
            assert!(!matches!(result, Err(KeepError::RateLimited(_))));
        }

        let mut storage = HiddenStorage::open(&path).unwrap();
        let result = storage.unlock_outer("wrong");
        assert!(matches!(result, Err(KeepError::RateLimited(_))));
    }

    #[test]
    fn test_rate_limiting_hidden() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-rate-hidden");

        HiddenStorage::create(&path, "outer", Some("hidden"), 10 * 1024 * 1024, 0.2).unwrap();

        for _ in 0..5 {
            let mut storage = HiddenStorage::open(&path).unwrap();
            let result = storage.unlock_hidden("wrong");
            assert!(matches!(result, Err(KeepError::InvalidPassword)));
        }

        let mut storage = HiddenStorage::open(&path).unwrap();
        let result = storage.unlock_hidden("wrong");
        assert!(matches!(result, Err(KeepError::RateLimited(_))));
    }

    #[test]
    fn test_rate_limiting_combined_unlock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-rate-combined");

        HiddenStorage::create(&path, "outer", Some("hidden"), 10 * 1024 * 1024, 0.2).unwrap();

        for _ in 0..5 {
            let mut storage = HiddenStorage::open(&path).unwrap();
            let result = storage.unlock("wrong");
            assert!(matches!(result, Err(KeepError::InvalidPassword)));
        }

        let mut storage = HiddenStorage::open(&path).unwrap();
        let result = storage.unlock("wrong");
        assert!(matches!(result, Err(KeepError::RateLimited(_))));
    }
}
