// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Persistent encrypted storage backend.
use std::fs;
use std::path::{Path, PathBuf};

use tracing::{debug, trace};

use crate::backend::{
    RedbBackend, StorageBackend, DESCRIPTORS_TABLE, KEYS_TABLE, RELAY_CONFIGS_TABLE, SHARES_TABLE,
};
use crate::crypto::{self, Argon2Params, EncryptedData, SecretKey, SALT_SIZE};
use crate::error::{KeepError, Result, StorageError};
use crate::frost::StoredShare;
use crate::keys::KeyRecord;
use crate::rate_limit;
use crate::relay::RelayConfig;
use crate::wallet::WalletDescriptor;

use bincode::Options;

const MAX_RECORD_SIZE: u64 = 1024 * 1024;

pub(crate) fn bincode_options() -> impl Options {
    bincode::options()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_RECORD_SIZE)
}

const HEADER_MAGIC: &[u8; 8] = b"KEEPVALT";
const HEADER_VERSION: u16 = 1;
const HEADER_SIZE: usize = 256;

struct Argon2Bounds {
    min: u32,
    max: u32,
}

const ARGON2_MEMORY_KIB: Argon2Bounds = Argon2Bounds {
    min: 1024,
    max: 4_194_304,
};
const ARGON2_ITERATIONS: Argon2Bounds = Argon2Bounds { min: 1, max: 20 };
const ARGON2_PARALLELISM: Argon2Bounds = Argon2Bounds { min: 1, max: 64 };

fn validate_argon2_param(value: u32, bounds: &Argon2Bounds, name: &str) -> Result<()> {
    if value < bounds.min || value > bounds.max {
        return Err(KeepError::InvalidInput(format!(
            "argon2 {} parameter: {} (must be {}-{})",
            name, value, bounds.min, bounds.max
        )));
    }
    Ok(())
}

/// Storage file header containing encryption metadata.
#[repr(C)]
#[derive(Clone)]
pub(crate) struct Header {
    pub(crate) magic: [u8; 8],
    pub(crate) version: u16,
    pub(crate) flags: u16,
    pub(crate) salt: [u8; SALT_SIZE],
    pub(crate) nonce: [u8; 24],
    pub(crate) encrypted_data_key: [u8; 48],
    pub(crate) argon2_memory_kib: u32,
    pub(crate) argon2_iterations: u32,
    pub(crate) argon2_parallelism: u32,
    pub(crate) _padding: [u8; 140],
}

impl Header {
    pub(crate) fn new(params: Argon2Params) -> Self {
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

    pub(crate) fn argon2_params(&self) -> Argon2Params {
        Argon2Params {
            memory_kib: self.argon2_memory_kib,
            iterations: self.argon2_iterations,
            parallelism: self.argon2_parallelism,
        }
    }

    pub(crate) fn to_bytes(&self) -> [u8; HEADER_SIZE] {
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

    pub(crate) fn from_bytes(bytes: &[u8; HEADER_SIZE]) -> Result<Self> {
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);

        if magic != *HEADER_MAGIC {
            return Err(StorageError::invalid_format("invalid keep file magic").into());
        }

        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version > HEADER_VERSION {
            return Err(StorageError::invalid_format("unsupported version").into());
        }

        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&bytes[12..44]);

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&bytes[44..68]);

        let mut encrypted_data_key = [0u8; 48];
        encrypted_data_key.copy_from_slice(&bytes[68..116]);

        let argon2_memory_kib =
            u32::from_le_bytes([bytes[116], bytes[117], bytes[118], bytes[119]]);
        let argon2_iterations =
            u32::from_le_bytes([bytes[120], bytes[121], bytes[122], bytes[123]]);
        let argon2_parallelism =
            u32::from_le_bytes([bytes[124], bytes[125], bytes[126], bytes[127]]);

        validate_argon2_param(argon2_memory_kib, &ARGON2_MEMORY_KIB, "memory")?;
        validate_argon2_param(argon2_iterations, &ARGON2_ITERATIONS, "iterations")?;
        validate_argon2_param(argon2_parallelism, &ARGON2_PARALLELISM, "parallelism")?;

        Ok(Self {
            magic,
            version,
            flags: u16::from_le_bytes([bytes[10], bytes[11]]),
            salt,
            nonce,
            encrypted_data_key,
            argon2_memory_kib,
            argon2_iterations,
            argon2_parallelism,
            _padding: [0; 140],
        })
    }
}

/// Encrypted persistent storage for keys and FROST shares.
pub struct Storage {
    pub(crate) path: PathBuf,
    pub(crate) header: Header,
    pub(crate) data_key: Option<SecretKey>,
    pub(crate) backend: Option<Box<dyn StorageBackend>>,
}

fn create_storage_dir(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(KeepError::AlreadyExists(path.display().to_string()));
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

impl Storage {
    /// Create new storage with the given password.
    pub fn create(path: &Path, password: &str, params: Argon2Params) -> Result<Self> {
        create_storage_dir(path)?;
        let backend = RedbBackend::create(&path.join("keep.db"))?;
        Self::create_inner(path, password, params, Box::new(backend))
    }

    /// Create new storage with a custom backend.
    pub fn create_with_backend(
        path: &Path,
        password: &str,
        params: Argon2Params,
        backend: Box<dyn StorageBackend>,
    ) -> Result<Self> {
        create_storage_dir(path)?;
        Self::create_inner(path, password, params, backend)
    }

    fn create_inner(
        path: &Path,
        password: &str,
        params: Argon2Params,
        backend: Box<dyn StorageBackend>,
    ) -> Result<Self> {
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

        fs::write(path.join("keep.hdr"), header.to_bytes())?;

        backend.create_table(KEYS_TABLE)?;
        backend.create_table(SHARES_TABLE)?;
        backend.create_table(DESCRIPTORS_TABLE)?;
        backend.create_table(RELAY_CONFIGS_TABLE)?;

        Ok(Self {
            path: path.to_path_buf(),
            header,
            data_key: Some(data_key),
            backend: Some(backend),
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
            return Err(StorageError::invalid_format("invalid header size").into());
        }

        let mut bytes = [0u8; HEADER_SIZE];
        bytes.copy_from_slice(&header_bytes);
        let header = Header::from_bytes(&bytes)?;

        Ok(Self {
            path: path.to_path_buf(),
            header,
            data_key: None,
            backend: None,
        })
    }

    /// Unlock with the given password.
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        if self.data_key.is_some() {
            return Ok(());
        }

        self.unlock_inner(password)?;

        let backend = RedbBackend::open(&self.path.join("keep.db"))?;
        self.backend = Some(Box::new(backend));
        Ok(())
    }

    /// Unlock with the given password using a custom backend.
    pub fn unlock_with_backend(
        &mut self,
        password: &str,
        backend: Box<dyn StorageBackend>,
    ) -> Result<()> {
        if self.data_key.is_some() {
            return Ok(());
        }

        self.unlock_inner(password)?;
        self.backend = Some(backend);
        Ok(())
    }

    fn unlock_inner(&mut self, password: &str) -> Result<()> {
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

        rate_limit::record_success(&self.path);
        debug!("storage unlocked");
        Ok(())
    }

    /// Lock and clear keys from memory.
    pub fn lock(&mut self) {
        self.data_key = None;
        self.backend = None;
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
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let serialized = bincode::serialize(record)?;
        let encrypted = crypto::encrypt(&serialized, data_key)?;
        let encrypted_bytes = encrypted.to_bytes();

        backend.put(KEYS_TABLE, &record.id, &encrypted_bytes)?;
        Ok(())
    }

    /// Load a key record.
    pub fn load_key(&self, id: &[u8; 32]) -> Result<KeyRecord> {
        trace!(id = %hex::encode(id), "loading key");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let encrypted_bytes = backend
            .get(KEYS_TABLE, id)?
            .ok_or_else(|| KeepError::KeyNotFound(hex::encode(id)))?;

        let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
        let decrypted = crypto::decrypt(&encrypted, data_key)?;

        let decrypted_bytes = decrypted.as_slice()?;
        Ok(bincode_options().deserialize(&decrypted_bytes)?)
    }

    /// List all stored key records.
    pub fn list_keys(&self) -> Result<Vec<KeyRecord>> {
        trace!("listing keys");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let entries = backend.list(KEYS_TABLE)?;
        let mut records = Vec::new();

        for (_, encrypted_bytes) in entries {
            let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
            let decrypted = crypto::decrypt(&encrypted, data_key)?;
            let decrypted_bytes = decrypted.as_slice()?;
            records.push(bincode_options().deserialize(&decrypted_bytes)?);
        }

        Ok(records)
    }

    /// Delete a key record.
    pub fn delete_key(&self, id: &[u8; 32]) -> Result<()> {
        debug!(id = %hex::encode(id), "deleting key");
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;
        if backend.delete(KEYS_TABLE, id)? {
            Ok(())
        } else {
            Err(KeepError::KeyNotFound(hex::encode(id)))
        }
    }

    /// The storage directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the current schema version.
    pub fn schema_version(&self) -> Result<u32> {
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;
        backend.schema_version()
    }

    /// Check if migrations are needed.
    pub fn needs_migration(&self) -> Result<bool> {
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;
        backend.needs_migration()
    }

    /// Run pending migrations.
    pub fn run_migrations(&self) -> Result<crate::migration::MigrationResult> {
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;
        backend.run_migrations()
    }

    /// Store a FROST share.
    pub fn store_share(&self, share: &StoredShare) -> Result<()> {
        debug!(name = %share.metadata.name, "storing FROST share");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let serialized = bincode::serialize(share)?;
        let encrypted = crypto::encrypt(&serialized, data_key)?;
        let encrypted_bytes = encrypted.to_bytes();

        let id = share_id(&share.metadata.group_pubkey, share.metadata.identifier);
        backend.put(SHARES_TABLE, &id, &encrypted_bytes)?;

        Ok(())
    }

    /// Store multiple FROST shares atomically.
    pub fn store_shares_atomic(&self, shares: &[StoredShare]) -> Result<()> {
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let mut entries_data: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(shares.len());
        for share in shares {
            let serialized = bincode::serialize(share)?;
            let encrypted = crypto::encrypt(&serialized, data_key)?;
            let id = share_id(&share.metadata.group_pubkey, share.metadata.identifier);
            entries_data.push((id.to_vec(), encrypted.to_bytes()));
        }

        let entries_refs: Vec<(&[u8], &[u8])> = entries_data
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();

        backend.put_batch(SHARES_TABLE, &entries_refs)
    }

    /// List all stored FROST shares.
    pub fn list_shares(&self) -> Result<Vec<StoredShare>> {
        trace!("listing FROST shares");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let entries = backend.list(SHARES_TABLE)?;
        let mut shares = Vec::new();

        for (_, encrypted_bytes) in entries {
            let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
            let decrypted = crypto::decrypt(&encrypted, data_key)?;
            let decrypted_bytes = decrypted.as_slice()?;
            shares.push(bincode_options().deserialize(&decrypted_bytes)?);
        }

        Ok(shares)
    }

    /// Delete a FROST share.
    pub fn delete_share(&self, group_pubkey: &[u8; 32], identifier: u16) -> Result<()> {
        debug!(id = identifier, "deleting FROST share");
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;
        let id = share_id(group_pubkey, identifier);
        if backend.delete(SHARES_TABLE, &id)? {
            Ok(())
        } else {
            Err(KeepError::KeyNotFound(format!(
                "share {identifier} not found"
            )))
        }
    }

    /// Store a wallet descriptor.
    pub fn store_descriptor(&self, descriptor: &WalletDescriptor) -> Result<()> {
        debug!(group = %hex::encode(descriptor.group_pubkey), "storing wallet descriptor");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let serialized = serde_json::to_vec(descriptor)
            .map_err(|e| KeepError::Other(format!("json serialization failed: {e}")))?;
        let encrypted = crypto::encrypt(&serialized, data_key)?;
        let encrypted_bytes = encrypted.to_bytes();

        backend.put(
            DESCRIPTORS_TABLE,
            &descriptor.group_pubkey,
            &encrypted_bytes,
        )?;
        Ok(())
    }

    /// Get a wallet descriptor by group public key.
    pub fn get_descriptor(&self, group_pubkey: &[u8; 32]) -> Result<Option<WalletDescriptor>> {
        trace!(group = %hex::encode(group_pubkey), "loading wallet descriptor");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let Some(encrypted_bytes) = backend.get(DESCRIPTORS_TABLE, group_pubkey)? else {
            return Ok(None);
        };

        let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
        let decrypted = crypto::decrypt(&encrypted, data_key)?;
        let decrypted_bytes = decrypted.as_slice()?;
        let descriptor: WalletDescriptor = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| KeepError::Other(format!("json deserialization failed: {e}")))?;
        Ok(Some(descriptor))
    }

    /// List all stored wallet descriptors.
    pub fn list_descriptors(&self) -> Result<Vec<WalletDescriptor>> {
        trace!("listing wallet descriptors");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let entries = backend.list(DESCRIPTORS_TABLE)?;
        let mut descriptors = Vec::new();

        for (_, encrypted_bytes) in entries {
            let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
            let decrypted = crypto::decrypt(&encrypted, data_key)?;
            let decrypted_bytes = decrypted.as_slice()?;
            let descriptor: WalletDescriptor = serde_json::from_slice(&decrypted_bytes)
                .map_err(|e| KeepError::Other(format!("json deserialization failed: {e}")))?;
            descriptors.push(descriptor);
        }

        Ok(descriptors)
    }

    /// Delete a wallet descriptor.
    pub fn delete_descriptor(&self, group_pubkey: &[u8; 32]) -> Result<()> {
        debug!(group = %hex::encode(group_pubkey), "deleting wallet descriptor");
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;
        if backend.delete(DESCRIPTORS_TABLE, group_pubkey)? {
            Ok(())
        } else {
            Err(KeepError::KeyNotFound(format!(
                "wallet descriptor for group {} not found",
                hex::encode(group_pubkey)
            )))
        }
    }

    /// Store a relay configuration.
    pub fn store_relay_config(&self, config: &RelayConfig) -> Result<()> {
        debug!(group = %hex::encode(config.group_pubkey), "storing relay config");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let serialized = serde_json::to_vec(config)
            .map_err(|e| KeepError::Other(format!("json serialization failed: {e}")))?;
        let encrypted = crypto::encrypt(&serialized, data_key)?;
        let encrypted_bytes = encrypted.to_bytes();

        backend.put(RELAY_CONFIGS_TABLE, &config.group_pubkey, &encrypted_bytes)?;
        Ok(())
    }

    /// Get a relay configuration by group public key.
    pub fn get_relay_config(&self, group_pubkey: &[u8; 32]) -> Result<Option<RelayConfig>> {
        trace!(group = %hex::encode(group_pubkey), "loading relay config");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let Some(encrypted_bytes) = backend.get(RELAY_CONFIGS_TABLE, group_pubkey)? else {
            return Ok(None);
        };

        let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
        let decrypted = crypto::decrypt(&encrypted, data_key)?;
        let decrypted_bytes = decrypted.as_slice()?;
        let config: RelayConfig = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| KeepError::Other(format!("json deserialization failed: {e}")))?;
        Ok(Some(config))
    }

    /// List all stored relay configurations.
    pub fn list_relay_configs(&self) -> Result<Vec<RelayConfig>> {
        trace!("listing relay configs");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let entries = backend.list(RELAY_CONFIGS_TABLE)?;
        let mut configs = Vec::new();

        for (_, encrypted_bytes) in entries {
            let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
            let decrypted = crypto::decrypt(&encrypted, data_key)?;
            let decrypted_bytes = decrypted.as_slice()?;
            let config: RelayConfig = serde_json::from_slice(&decrypted_bytes)
                .map_err(|e| KeepError::Other(format!("json deserialization failed: {e}")))?;
            configs.push(config);
        }

        Ok(configs)
    }

    /// Delete a relay configuration.
    pub fn delete_relay_config(&self, group_pubkey: &[u8; 32]) -> Result<()> {
        debug!(group = %hex::encode(group_pubkey), "deleting relay config");
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;
        if backend.delete(RELAY_CONFIGS_TABLE, group_pubkey)? {
            Ok(())
        } else {
            Err(KeepError::KeyNotFound(format!(
                "relay config for group {} not found",
                hex::encode(group_pubkey)
            )))
        }
    }
}

pub(crate) fn share_id(group_pubkey: &[u8; 32], identifier: u16) -> [u8; 32] {
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

    #[test]
    fn test_storage_with_memory_backend() {
        use crate::backend::MemoryBackend;

        let dir = tempdir().unwrap();
        let path = dir.path().join("test-mem-backend");

        let backend = Box::new(MemoryBackend::new());
        let storage =
            Storage::create_with_backend(&path, "password", Argon2Params::TESTING, backend)
                .unwrap();
        assert!(storage.is_unlocked());

        let record = KeyRecord::new(
            crypto::random_bytes(),
            crate::keys::KeyType::Nostr,
            "mem test key".into(),
            vec![1, 2, 3, 4],
        );

        storage.store_key(&record).unwrap();
        let loaded = storage.load_key(&record.id).unwrap();
        assert_eq!(loaded.name, record.name);

        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn test_header_rejects_malicious_argon2_params() {
        let valid_header = Header::new(Argon2Params::TESTING);
        let valid_bytes = valid_header.to_bytes();

        Header::from_bytes(&valid_bytes).expect("valid header should parse");

        let mut bad_memory_high = valid_bytes;
        bad_memory_high[116..120].copy_from_slice(&u32::MAX.to_le_bytes());
        match Header::from_bytes(&bad_memory_high) {
            Err(e) => assert!(e.to_string().contains("memory")),
            Ok(_) => panic!("expected error for extreme memory"),
        }

        let mut bad_memory_low = valid_bytes;
        bad_memory_low[116..120].copy_from_slice(&0u32.to_le_bytes());
        assert!(Header::from_bytes(&bad_memory_low).is_err());

        let mut bad_iterations_high = valid_bytes;
        bad_iterations_high[120..124].copy_from_slice(&u32::MAX.to_le_bytes());
        match Header::from_bytes(&bad_iterations_high) {
            Err(e) => assert!(e.to_string().contains("iterations")),
            Ok(_) => panic!("expected error for extreme iterations"),
        }

        let mut bad_iterations_low = valid_bytes;
        bad_iterations_low[120..124].copy_from_slice(&0u32.to_le_bytes());
        assert!(Header::from_bytes(&bad_iterations_low).is_err());

        let mut bad_parallelism_high = valid_bytes;
        bad_parallelism_high[124..128].copy_from_slice(&u32::MAX.to_le_bytes());
        match Header::from_bytes(&bad_parallelism_high) {
            Err(e) => assert!(e.to_string().contains("parallelism")),
            Ok(_) => panic!("expected error for extreme parallelism"),
        }

        let mut bad_parallelism_low = valid_bytes;
        bad_parallelism_low[124..128].copy_from_slice(&0u32.to_le_bytes());
        assert!(Header::from_bytes(&bad_parallelism_low).is_err());
    }
}
