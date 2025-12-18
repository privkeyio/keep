use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use heed::types::*;
use heed::{Database, Env, EnvOpenOptions};
use rand::RngCore;

use crate::crypto::{self, Argon2Params, EncryptedData, SecretKey};
use crate::error::{KeepError, Result};
use crate::keys::KeyRecord;

use super::header::{
    HiddenHeader, OuterHeader, DATA_START_OFFSET, HEADER_SIZE, HIDDEN_HEADER_OFFSET,
};

const MIN_LMDB_SIZE: usize = 100 * 1024 * 1024;

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
    outer_env: Option<Env>,
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

        let hidden_size = if hidden_password.is_some() {
            ((total_size as f64) * (hidden_ratio as f64)) as u64
        } else {
            0
        };
        let outer_size = total_size - DATA_START_OFFSET - hidden_size;

        let mut outer_header = OuterHeader::new(Argon2Params::DEFAULT, outer_size, total_size);

        let outer_data_key = SecretKey::generate();
        let outer_master_key = crypto::derive_key(
            outer_password.as_bytes(),
            &outer_header.salt,
            Argon2Params::DEFAULT,
        )?;
        let outer_header_key = crypto::derive_subkey(&outer_master_key, b"keep-outer-header");

        let encrypted_outer = crypto::encrypt(outer_data_key.as_bytes(), &outer_header_key)?;
        outer_header.nonce.copy_from_slice(&encrypted_outer.nonce);
        outer_header
            .encrypted_data_key
            .copy_from_slice(&encrypted_outer.ciphertext);

        let (hidden_header, hidden_data_key) = if let Some(hp) = hidden_password {
            let hidden_offset = DATA_START_OFFSET + outer_size;
            let mut hh = HiddenHeader::new(hidden_offset, hidden_size);

            let hidden_data_key = SecretKey::generate();

            let hidden_salt = crypto::blake2b_256(hp.as_bytes());
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&hidden_salt);

            let hidden_master_key =
                crypto::derive_key(hp.as_bytes(), &salt, Argon2Params::DEFAULT)?;
            let hidden_header_key = crypto::derive_subkey(&hidden_master_key, b"keep-hidden-header");

            let encrypted_hidden = crypto::encrypt(hidden_data_key.as_bytes(), &hidden_header_key)?;
            hh.nonce.copy_from_slice(&encrypted_hidden.nonce);
            hh.encrypted_data_key
                .copy_from_slice(&encrypted_hidden.ciphertext);

            hh.checksum = hh.compute_checksum();

            (Some(hh), Some(hidden_data_key))
        } else {
            (None, None)
        };

        fs::create_dir_all(path)?;
        let vault_path = path.join("keep.vault");
        let mut file = File::create(&vault_path)?;

        file.write_all(&outer_header.to_bytes())?;

        if let Some(ref hh) = hidden_header {
            let hidden_salt = crypto::blake2b_256(hidden_password.unwrap().as_bytes());
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&hidden_salt);

            let hidden_master_key = crypto::derive_key(
                hidden_password.unwrap().as_bytes(),
                &salt,
                Argon2Params::DEFAULT,
            )?;
            let hidden_header_enc_key =
                crypto::derive_subkey(&hidden_master_key, b"keep-hidden-header-enc");

            let encrypted_hh = crypto::encrypt(&hh.to_bytes_compact(), &hidden_header_enc_key)?;

            let mut hidden_area: [u8; HEADER_SIZE] = crypto::random_bytes();
            hidden_area[..24].copy_from_slice(&encrypted_hh.nonce);
            hidden_area[24..24 + encrypted_hh.ciphertext.len()]
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
            rand::thread_rng().fill_bytes(&mut buffer[..to_write]);
            file.write_all(&buffer[..to_write])?;
            written += to_write as u64;
        }

        file.sync_all()?;
        drop(file);

        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(MIN_LMDB_SIZE)
                .max_dbs(10)
                .open(path)?
        };

        let mut wtxn = env.write_txn()?;
        let _: Database<Bytes, Bytes> = env.create_database(&mut wtxn, Some("keys"))?;
        let _: Database<Str, Bytes> = env.create_database(&mut wtxn, Some("meta"))?;
        wtxn.commit()?;

        Ok(Self {
            path: path.to_path_buf(),
            outer_header,
            hidden_header,
            outer_key: Some(outer_data_key),
            hidden_key: hidden_data_key,
            active_volume: Some(VolumeType::Outer),
            outer_env: Some(env),
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
            outer_env: None,
        })
    }

    pub fn unlock_outer(&mut self, password: &str) -> Result<()> {
        if self.outer_key.is_some() {
            return Ok(());
        }

        let master_key = crypto::derive_key(
            password.as_bytes(),
            &self.outer_header.salt,
            self.outer_header.argon2_params(),
        )?;

        let header_key = crypto::derive_subkey(&master_key, b"keep-outer-header");

        let encrypted = EncryptedData {
            nonce: self.outer_header.nonce,
            ciphertext: self.outer_header.encrypted_data_key.to_vec(),
        };

        let decrypted = crypto::decrypt(&encrypted, &header_key)?;
        self.outer_key = Some(SecretKey::from_slice(&decrypted)?);

        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(MIN_LMDB_SIZE)
                .max_dbs(10)
                .open(&self.path)?
        };
        self.outer_env = Some(env);
        self.active_volume = Some(VolumeType::Outer);

        Ok(())
    }

    pub fn unlock_hidden(&mut self, password: &str) -> Result<()> {
        if self.hidden_key.is_some() {
            return Ok(());
        }

        let vault_path = self.path.join("keep.vault");
        let mut file = File::open(&vault_path)?;
        file.seek(SeekFrom::Start(HIDDEN_HEADER_OFFSET))?;

        let mut hidden_area = [0u8; HEADER_SIZE];
        file.read_exact(&mut hidden_area)?;

        let hidden_salt = crypto::blake2b_256(password.as_bytes());
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&hidden_salt);

        let master_key = crypto::derive_key(password.as_bytes(), &salt, Argon2Params::DEFAULT)?;

        let header_enc_key = crypto::derive_subkey(&master_key, b"keep-hidden-header-enc");

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&hidden_area[..24]);

        const ENCRYPTED_HEADER_SIZE: usize = HiddenHeader::COMPACT_SIZE + 16;

        let encrypted = EncryptedData {
            nonce,
            ciphertext: hidden_area[24..24 + ENCRYPTED_HEADER_SIZE].to_vec(),
        };

        let decrypted = match crypto::decrypt(&encrypted, &header_enc_key) {
            Ok(d) => d,
            Err(_) => return Err(KeepError::InvalidPassword),
        };

        let hidden_header = HiddenHeader::from_bytes_compact(&decrypted);

        if !hidden_header.verify_checksum() {
            return Err(KeepError::InvalidPassword);
        }

        let data_key_enc = crypto::derive_subkey(&master_key, b"keep-hidden-header");

        let mut data_nonce = [0u8; 24];
        data_nonce.copy_from_slice(&hidden_header.nonce);

        let data_encrypted = EncryptedData {
            nonce: data_nonce,
            ciphertext: hidden_header.encrypted_data_key.to_vec(),
        };

        let data_key_bytes = crypto::decrypt(&data_encrypted, &data_key_enc)?;
        self.hidden_key = Some(SecretKey::from_slice(&data_key_bytes)?);
        self.hidden_header = Some(hidden_header);
        self.active_volume = Some(VolumeType::Hidden);

        Ok(())
    }

    pub fn unlock(&mut self, password: &str) -> Result<VolumeType> {
        if self.unlock_outer(password).is_ok() {
            return Ok(VolumeType::Outer);
        }

        if self.unlock_hidden(password).is_ok() {
            return Ok(VolumeType::Hidden);
        }

        Err(KeepError::InvalidPassword)
    }

    pub fn lock(&mut self) {
        self.outer_key = None;
        self.hidden_key = None;
        self.hidden_header = None;
        self.active_volume = None;
        self.outer_env = None;
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
        let env = self.outer_env.as_ref().ok_or(KeepError::Locked)?;

        let serialized = bincode::serialize(record)
            .map_err(|e| KeepError::Other(format!("Serialization error: {}", e)))?;

        let encrypted = crypto::encrypt(&serialized, data_key)?;
        let encrypted_bytes = encrypted.to_bytes();

        let mut wtxn = env.write_txn()?;
        let keys_db: Database<Bytes, Bytes> = env.create_database(&mut wtxn, Some("keys"))?;
        keys_db.put(&mut wtxn, &record.id, &encrypted_bytes)?;
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

        let records: Vec<KeyRecord> = bincode::deserialize(&decrypted).unwrap_or_default();
        Ok(records)
    }

    fn write_hidden_records(
        &self,
        records: &[KeyRecord],
        data_key: &SecretKey,
        hidden_header: &HiddenHeader,
    ) -> Result<()> {
        let serialized = bincode::serialize(records)
            .map_err(|e| KeepError::Other(format!("Serialization error: {}", e)))?;

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
            rand::thread_rng().fill_bytes(&mut buffer[..to_write]);
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
        let env = self.outer_env.as_ref().ok_or(KeepError::Locked)?;

        let rtxn = env.read_txn()?;
        let keys_db: Database<Bytes, Bytes> = env
            .open_database(&rtxn, Some("keys"))?
            .ok_or(KeepError::Other("Keys database not found".into()))?;

        let mut records = Vec::new();

        for result in keys_db.iter(&rtxn)? {
            let (_, encrypted_bytes) = result?;
            let encrypted = EncryptedData::from_bytes(encrypted_bytes)?;
            let decrypted = crypto::decrypt(&encrypted, data_key)?;

            let record: KeyRecord = bincode::deserialize(&decrypted)
                .map_err(|e| KeepError::Other(format!("Deserialization error: {}", e)))?;

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
        let env = self.outer_env.as_ref().ok_or(KeepError::Locked)?;

        let mut wtxn = env.write_txn()?;
        let keys_db: Database<Bytes, Bytes> = env.create_database(&mut wtxn, Some("keys"))?;
        let existed = keys_db.delete(&mut wtxn, id)?;
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
}
