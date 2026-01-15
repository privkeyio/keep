//! Persistent encrypted storage backend.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use redb::{Database, ReadableTable, TableDefinition};
use tracing::{debug, trace};

use crate::crypto::{self, Argon2Params, EncryptedData, SecretKey, SALT_SIZE};
use crate::error::{KeepError, Result};
use crate::frost::StoredShare;
use crate::keys::KeyRecord;
use crate::rate_limit;

use bincode::Options;

const KEYS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("keys");
const SHARES_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("shares");

const MAX_RECORD_SIZE: u64 = 1024 * 1024;

const HEADER_MAGIC: &[u8; 8] = b"KEEPVALT";
const HEADER_VERSION: u16 = 1;
const HEADER_SIZE: usize = 256;

/// Storage file header containing encryption metadata.
#[repr(C)]
#[derive(Clone)]
struct Header {
    magic: [u8; 8],
    version: u16,
    flags: u16,
    salt: [u8; SALT_SIZE],
    nonce: [u8; 24],
    encrypted_data_key: [u8; 48],
    argon2_memory_kib: u32,
    argon2_iterations: u32,
    argon2_parallelism: u32,
    _padding: [u8; 140],
}

impl Header {
    fn new(params: Argon2Params) -> Self {
        Self {
            magic: *HEADER_MAGIC,
            version: HEADER_VERSION,
            flags: 0,
            salt: crypto::random_bytes(),
            nonce: crypto::random_bytes(),
            encrypted_data_key: [0; 48],
            argon2_memory_kib: params.memory_kib,
            argon2_iterations: params.iterations,
            argon2_parallelism: params.parallelism,
            _padding: [0; 140],
        }
    }

    fn argon2_params(&self) -> Argon2Params {
        Argon2Params {
            memory_kib: self.argon2_memory_kib,
            iterations: self.argon2_iterations,
            parallelism: self.argon2_parallelism,
        }
    }

    fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0..8].copy_from_slice(&self.magic);
        bytes[8..10].copy_from_slice(&self.version.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.flags.to_le_bytes());
        bytes[12..44].copy_from_slice(&self.salt);
        bytes[44..68].copy_from_slice(&self.nonce);
        bytes[68..116].copy_from_slice(&self.encrypted_data_key);
        bytes[116..120].copy_from_slice(&self.argon2_memory_kib.to_le_bytes());
        bytes[120..124].copy_from_slice(&self.argon2_iterations.to_le_bytes());
        bytes[124..128].copy_from_slice(&self.argon2_parallelism.to_le_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8; HEADER_SIZE]) -> Result<Self> {
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);

        if magic != *HEADER_MAGIC {
            return Err(KeepError::Other("Invalid keep file".into()));
        }

        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version > HEADER_VERSION {
            return Err(KeepError::Other("Unsupported version".into()));
        }

        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&bytes[12..44]);

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&bytes[44..68]);

        let mut encrypted_data_key = [0u8; 48];
        encrypted_data_key.copy_from_slice(&bytes[68..116]);

        Ok(Self {
            magic,
            version,
            flags: u16::from_le_bytes([bytes[10], bytes[11]]),
            salt,
            nonce,
            encrypted_data_key,
            argon2_memory_kib: u32::from_le_bytes([bytes[116], bytes[117], bytes[118], bytes[119]]),
            argon2_iterations: u32::from_le_bytes([bytes[120], bytes[121], bytes[122], bytes[123]]),
            argon2_parallelism: u32::from_le_bytes([
                bytes[124], bytes[125], bytes[126], bytes[127],
            ]),
            _padding: [0; 140],
        })
    }
}

/// Encrypted persistent storage for keys and FROST shares.
pub struct Storage {
    path: PathBuf,
    header: Header,
    data_key: Option<SecretKey>,
    db: Option<Database>,
}

impl Storage {
    /// Create new storage with the given password.
    pub fn create(path: &Path, password: &str, params: Argon2Params) -> Result<Self> {
        if path.exists() {
            return Err(KeepError::AlreadyExists(path.display().to_string()));
        }

        fs::create_dir_all(path)?;

        let mut header = Header::new(params);

        let data_key = SecretKey::generate()?;

        let master_key = crypto::derive_key(password.as_bytes(), &header.salt, params)?;

        let header_key = crypto::derive_subkey(&master_key, b"keep-header-key")?;

        let data_key_bytes = data_key.decrypt()?;
        let encrypted = crypto::encrypt(&*data_key_bytes, &header_key)?;
        header.nonce.copy_from_slice(&encrypted.nonce);
        header
            .encrypted_data_key
            .copy_from_slice(&encrypted.ciphertext);

        let header_path = path.join("keep.hdr");
        fs::write(&header_path, header.to_bytes())?;

        let db_path = path.join("keep.db");
        let db = Database::create(&db_path)?;

        {
            let wtxn = db.begin_write()?;
            {
                let _ = wtxn.open_table(KEYS_TABLE)?;
                let _ = wtxn.open_table(SHARES_TABLE)?;
            }
            wtxn.commit()?;
        }

        Ok(Self {
            path: path.to_path_buf(),
            header,
            data_key: Some(data_key),
            db: Some(db),
        })
    }

    /// Open existing storage.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(KeepError::NotFound(path.display().to_string()));
        }

        let header_path = path.join("keep.hdr");
        let header_bytes = fs::read(&header_path)?;

        if header_bytes.len() != HEADER_SIZE {
            return Err(KeepError::Other("Invalid header size".into()));
        }

        let mut bytes = [0u8; HEADER_SIZE];
        bytes.copy_from_slice(&header_bytes);
        let header = Header::from_bytes(&bytes)?;

        Ok(Self {
            path: path.to_path_buf(),
            header,
            data_key: None,
            db: None,
        })
    }

    /// Unlock with the given password.
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        if self.data_key.is_some() {
            return Ok(());
        }

        let hmac_key = rate_limit::derive_hmac_key(&self.header.salt);
        if let Err(remaining) = rate_limit::check_rate_limit(&self.path, &hmac_key) {
            return Err(KeepError::RateLimited(remaining.as_secs().max(1)));
        }

        debug!("deriving master key");
        let master_key = crypto::derive_key(
            password.as_bytes(),
            &self.header.salt,
            self.header.argon2_params(),
        )?;

        let header_key = crypto::derive_subkey(&master_key, b"keep-header-key")?;

        let encrypted = EncryptedData {
            nonce: self.header.nonce,
            ciphertext: self.header.encrypted_data_key.to_vec(),
        };

        debug!("decrypting data key");
        let decrypted = match crypto::decrypt(&encrypted, &header_key) {
            Ok(d) => d,
            Err(e) => {
                if matches!(e, KeepError::DecryptionFailed) {
                    rate_limit::record_failure(&self.path, &hmac_key);
                }
                return Err(e);
            }
        };
        let decrypted_bytes = decrypted.as_slice()?;
        self.data_key = Some(SecretKey::from_slice(&decrypted_bytes)?);

        debug!(path = ?self.path, "opening database");
        let db_path = self.path.join("keep.db");
        let db = Database::open(&db_path)?;

        self.db = Some(db);
        rate_limit::record_success(&self.path);
        debug!("storage unlocked");

        Ok(())
    }

    /// Lock and clear keys from memory.
    pub fn lock(&mut self) {
        self.data_key = None;
        self.db = None;
    }

    /// Returns true if unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.data_key.is_some()
    }

    /// The data encryption key, if unlocked.
    pub fn data_key(&self) -> Option<&SecretKey> {
        self.data_key.as_ref()
    }

    /// Store a key record.
    pub fn store_key(&self, record: &KeyRecord) -> Result<()> {
        debug!(name = %record.name, "storing key");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let db = self.db.as_ref().ok_or(KeepError::Locked)?;

        let serialized = bincode::serialize(record)?;

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

    /// Load a key record.
    pub fn load_key(&self, id: &[u8; 32]) -> Result<KeyRecord> {
        trace!(id = %hex::encode(id), "loading key");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let db = self.db.as_ref().ok_or(KeepError::Locked)?;

        let rtxn = db.begin_read()?;
        let table = rtxn.open_table(KEYS_TABLE)?;

        let encrypted_bytes = table
            .get(id.as_slice())?
            .ok_or_else(|| KeepError::KeyNotFound(hex::encode(id)))?;

        let encrypted = EncryptedData::from_bytes(encrypted_bytes.value())?;
        let decrypted = crypto::decrypt(&encrypted, data_key)?;

        let decrypted_bytes = decrypted.as_slice()?;
        Ok(bincode::options()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_RECORD_SIZE)
            .deserialize(&decrypted_bytes)?)
    }

    /// List all stored key records.
    pub fn list_keys(&self) -> Result<Vec<KeyRecord>> {
        trace!("listing keys");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let db = self.db.as_ref().ok_or(KeepError::Locked)?;

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

    /// Delete a key record.
    pub fn delete_key(&self, id: &[u8; 32]) -> Result<()> {
        debug!(id = %hex::encode(id), "deleting key");
        let db = self.db.as_ref().ok_or(KeepError::Locked)?;

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

    /// The storage directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Store a FROST share.
    pub fn store_share(&self, share: &StoredShare) -> Result<()> {
        debug!(name = %share.metadata.name, "storing FROST share");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let db = self.db.as_ref().ok_or(KeepError::Locked)?;

        let serialized = bincode::serialize(share)?;

        let encrypted = crypto::encrypt(&serialized, data_key)?;
        let encrypted_bytes = encrypted.to_bytes();

        let id = share_id(&share.metadata.group_pubkey, share.metadata.identifier);

        let wtxn = db.begin_write()?;
        {
            let mut table = wtxn.open_table(SHARES_TABLE)?;
            table.insert(id.as_slice(), encrypted_bytes.as_slice())?;
        }
        wtxn.commit()?;

        Ok(())
    }

    /// List all stored FROST shares.
    pub fn list_shares(&self) -> Result<Vec<StoredShare>> {
        trace!("listing FROST shares");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let db = self.db.as_ref().ok_or(KeepError::Locked)?;

        let rtxn = db.begin_read()?;
        let table = rtxn.open_table(SHARES_TABLE)?;

        let mut shares = Vec::new();

        for result in table.iter()? {
            let (_, encrypted_bytes) = result?;
            let encrypted = EncryptedData::from_bytes(encrypted_bytes.value())?;
            let decrypted = crypto::decrypt(&encrypted, data_key)?;

            let decrypted_bytes = decrypted.as_slice()?;
            let share: StoredShare = bincode::options()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(MAX_RECORD_SIZE)
                .deserialize(&decrypted_bytes)?;

            shares.push(share);
        }

        Ok(shares)
    }

    /// Delete a FROST share.
    pub fn delete_share(&self, group_pubkey: &[u8; 32], identifier: u16) -> Result<()> {
        debug!(id = identifier, "deleting FROST share");
        let db = self.db.as_ref().ok_or(KeepError::Locked)?;

        let id = share_id(group_pubkey, identifier);

        let wtxn = db.begin_write()?;
        let existed;
        {
            let mut table = wtxn.open_table(SHARES_TABLE)?;
            existed = table.remove(id.as_slice())?.is_some();
        }
        wtxn.commit()?;

        if !existed {
            return Err(KeepError::KeyNotFound(format!(
                "share {} not found",
                identifier
            )));
        }

        Ok(())
    }
}

fn share_id(group_pubkey: &[u8; 32], identifier: u16) -> [u8; 32] {
    let mut data = [0u8; 34];
    data[..32].copy_from_slice(group_pubkey);
    data[32..34].copy_from_slice(&identifier.to_le_bytes());
    crypto::blake2b_256(&data)
}

impl Drop for Storage {
    fn drop(&mut self) {
        self.lock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_storage_create_and_unlock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-keep");

        {
            let storage = Storage::create(&path, "password", Argon2Params::TESTING).unwrap();
            assert!(storage.is_unlocked());
        }

        {
            let mut storage = Storage::open(&path).unwrap();
            assert!(!storage.is_unlocked());

            storage.unlock("password").unwrap();
            assert!(storage.is_unlocked());
        }
    }

    #[test]
    fn test_storage_wrong_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-keep");

        Storage::create(&path, "correct", Argon2Params::TESTING).unwrap();

        let mut storage = Storage::open(&path).unwrap();
        let result = storage.unlock("wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_storage_key_operations() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-keep");

        let storage = Storage::create(&path, "password", Argon2Params::TESTING).unwrap();

        let record = KeyRecord::new(
            crypto::random_bytes(),
            crate::keys::KeyType::Nostr,
            "test key".into(),
            vec![1, 2, 3, 4],
        );

        storage.store_key(&record).unwrap();

        let loaded = storage.load_key(&record.id).unwrap();
        assert_eq!(loaded.name, record.name);
        assert_eq!(loaded.pubkey, record.pubkey);

        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 1);

        storage.delete_key(&record.id).unwrap();
        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_storage_rate_limiting() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-rate-limit");

        Storage::create(&path, "correct", Argon2Params::TESTING).unwrap();

        for _ in 0..5 {
            let mut storage = Storage::open(&path).unwrap();
            let result = storage.unlock("wrong");
            assert!(matches!(result, Err(KeepError::DecryptionFailed)));
        }

        let mut storage = Storage::open(&path).unwrap();
        let result = storage.unlock("wrong");
        assert!(matches!(result, Err(KeepError::RateLimited(_))));
    }

    #[test]
    fn test_storage_rate_limit_resets_on_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-rate-limit-reset");

        Storage::create(&path, "correct", Argon2Params::TESTING).unwrap();

        for _ in 0..4 {
            let mut storage = Storage::open(&path).unwrap();
            let _ = storage.unlock("wrong");
        }

        {
            let mut storage = Storage::open(&path).unwrap();
            storage.unlock("correct").unwrap();
        }

        for _ in 0..4 {
            let mut storage = Storage::open(&path).unwrap();
            let result = storage.unlock("wrong");
            assert!(matches!(result, Err(KeepError::DecryptionFailed)));
        }
    }
}
