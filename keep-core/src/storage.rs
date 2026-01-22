// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Persistent encrypted storage backend.

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;

use subtle::ConstantTimeEq;
use tracing::{debug, trace, warn};

use crate::backend::{RedbBackend, StorageBackend, KEYS_TABLE, SHARES_TABLE};
use crate::crypto::{self, Argon2Params, EncryptedData, SecretKey, SALT_SIZE};
use crate::error::{KeepError, Result, StorageError};
use crate::frost::StoredShare;
use crate::keys::KeyRecord;
use crate::rate_limit;

use bincode::Options;

const MAX_RECORD_SIZE: u64 = 1024 * 1024;

fn bincode_options() -> impl Options {
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
    path: PathBuf,
    header: Header,
    data_key: Option<SecretKey>,
    backend: Option<Box<dyn StorageBackend>>,
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
                "share {} not found",
                identifier
            )))
        }
    }
}

fn share_id(group_pubkey: &[u8; 32], identifier: u16) -> [u8; 32] {
    let mut data = [0u8; 34];
    data[..32].copy_from_slice(group_pubkey);
    data[32..34].copy_from_slice(&identifier.to_le_bytes());
    crypto::blake2b_256(&data)
}

fn secure_delete(path: &Path) -> std::io::Result<()> {
    if let Ok(metadata) = fs::metadata(path) {
        if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
            const CHUNK: usize = 8 * 1024;
            let zeros = [0u8; CHUNK];
            let mut remaining = metadata.len();
            file.seek(SeekFrom::Start(0))?;
            while remaining > 0 {
                let to_write = std::cmp::min(CHUNK as u64, remaining) as usize;
                file.write_all(&zeros[..to_write])?;
                remaining -= to_write as u64;
            }
            file.sync_all()?;
        }
    }
    fs::remove_file(path)
}

#[cfg(not(windows))]
fn fsync_dir(path: &Path) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "path has no parent directory")
    })?;
    let dir = File::open(parent)?;
    dir.sync_all()
}

#[cfg(windows)]
fn fsync_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn copy_with_retry(from: &Path, to: &Path) -> std::io::Result<u64> {
    const MAX_RETRIES: u32 = 10;
    const RETRY_DELAY_MS: u64 = 50;

    let mut last_err = None;
    for _ in 0..MAX_RETRIES {
        match fs::copy(from, to) {
            Ok(n) => return Ok(n),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    last_err = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS));
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "file copy failed after retries",
        )
    }))
}

fn acquire_rotation_lock(path: &Path) -> Result<File> {
    let lock_path = path.join(".rotation.lock");
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    lock_file.lock_exclusive()?;
    Ok(lock_file)
}

fn cleanup_rotation_lock(_path: &Path) {
    // No-op: we intentionally leave the lock file in place to avoid a race
    // condition between drop(lock) and remove_file that could allow concurrent
    // rotations. The file lock held by the lock object is sufficient.
}

fn write_header_atomically(path: &Path, header: &Header) -> Result<()> {
    let header_path = path.join("keep.hdr");
    let tmp_path = path.join("keep.hdr.tmp");
    let mut tmp_file = File::create(&tmp_path)?;
    tmp_file.write_all(&header.to_bytes())?;
    tmp_file.sync_all()?;
    drop(tmp_file);
    fs::rename(&tmp_path, &header_path)?;
    fsync_dir(&header_path)?;
    Ok(())
}

impl Storage {
    /// Rotate the vault password.
    ///
    /// Re-encrypts the data encryption key with a new password-derived key.
    /// Creates a backup of the header before rotation and restores it on failure.
    pub fn rotate_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        let lock = acquire_rotation_lock(&self.path)?;

        if !self.is_unlocked() {
            self.unlock(old_password)?;
        }

        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let data_key_bytes = data_key.decrypt()?;
        let old_header = self.header.clone();
        let header_path = self.path.join("keep.hdr");
        let backup_path = self.path.join("keep.hdr.backup");

        copy_with_retry(&header_path, &backup_path)?;

        let new_header = self.create_header_with_key(new_password, data_key)?;
        write_header_atomically(&self.path, &new_header)?;
        self.header = new_header.clone();

        if let Err(e) = self.verify_header_decryption(&new_header, new_password, &*data_key_bytes) {
            self.header = old_header;
            if let Err(restore_err) = copy_with_retry(&backup_path, &header_path) {
                warn!(error = %restore_err, "failed to restore backup during rollback - vault may be corrupted");
                let _ = secure_delete(&backup_path);
                drop(lock);
                return Err(KeepError::RotationFailed(format!(
                    "verification failed and backup restoration failed: {} (restore error: {})",
                    e, restore_err
                )));
            }
            let _ = secure_delete(&backup_path);
            drop(lock);
            return Err(KeepError::RotationFailed(format!(
                "verification failed: {}",
                e
            )));
        }

        let _ = secure_delete(&backup_path);
        drop(lock);
        cleanup_rotation_lock(&self.path);
        Ok(())
    }

    fn verify_header_decryption(
        &self,
        header: &Header,
        password: &str,
        expected_data_key: &[u8],
    ) -> Result<()> {
        let master_key =
            crypto::derive_key(password.as_bytes(), &header.salt, header.argon2_params())?;
        let header_key = crypto::derive_subkey(&master_key, b"keep-header-key")?;
        let encrypted = EncryptedData {
            nonce: header.nonce,
            ciphertext: header.encrypted_data_key.to_vec(),
        };
        let decrypted = crypto::decrypt(&encrypted, &header_key)?;
        let decrypted_bytes = decrypted.as_slice()?;
        if !bool::from(decrypted_bytes.ct_eq(expected_data_key)) {
            return Err(KeepError::DecryptionFailed);
        }
        Ok(())
    }

    fn create_header_with_key(&self, password: &str, data_key: &SecretKey) -> Result<Header> {
        let mut header = Header::new(self.header.argon2_params());
        let master_key =
            crypto::derive_key(password.as_bytes(), &header.salt, header.argon2_params())?;
        let header_key = crypto::derive_subkey(&master_key, b"keep-header-key")?;
        let data_key_bytes = data_key.decrypt()?;
        let encrypted = crypto::encrypt(&*data_key_bytes, &header_key)?;
        header.nonce.copy_from_slice(&encrypted.nonce);
        header
            .encrypted_data_key
            .copy_from_slice(&encrypted.ciphertext);
        Ok(header)
    }

    /// Rotate the data encryption key.
    ///
    /// Generates a new data encryption key and re-encrypts all stored keys and shares.
    /// Creates backups of the header and database before rotation and restores them on failure.
    pub fn rotate_data_key(&mut self, password: &str) -> Result<()> {
        let lock = acquire_rotation_lock(&self.path)?;

        if !self.is_unlocked() {
            self.unlock(password)?;
        }

        let old_data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?.clone();
        let old_header = self.header.clone();
        let header_path = self.path.join("keep.hdr");
        let backup_path = self.path.join("keep.hdr.backup");
        let db_path = self.path.join("keep.db");
        let db_backup_path = self.path.join("keep.db.backup");

        let keys = self.list_keys()?;
        let shares = self.list_shares()?;

        let decrypted_keys = self.decrypt_all_keys(&keys, &old_data_key)?;
        let decrypted_shares = self.decrypt_all_shares(&shares, &old_data_key)?;

        self.backend = None;

        if let Err(e) = copy_with_retry(&header_path, &backup_path) {
            self.backend = RedbBackend::open(&db_path)
                .ok()
                .map(|b| Box::new(b) as Box<dyn StorageBackend>);
            return Err(KeepError::Io(e));
        }
        if let Err(e) = copy_with_retry(&db_path, &db_backup_path) {
            self.backend = RedbBackend::open(&db_path)
                .ok()
                .map(|b| Box::new(b) as Box<dyn StorageBackend>);
            return Err(KeepError::Io(e));
        }

        self.backend = Some(Box::new(match RedbBackend::open(&db_path) {
            Ok(backend) => backend,
            Err(e) => {
                self.backend = RedbBackend::open(&db_path)
                    .ok()
                    .map(|b| Box::new(b) as Box<dyn StorageBackend>);
                return Err(e);
            }
        }));

        let result = (|| -> Result<()> {
            let new_data_key = SecretKey::generate()?;
            self.reencrypt_database(&decrypted_keys, &decrypted_shares, &new_data_key)?;

            let new_header = self.encrypt_data_key_in_header(password, &new_data_key)?;
            write_header_atomically(&self.path, &new_header)?;

            self.header = new_header;
            self.data_key = Some(new_data_key);

            self.verify_rotation_integrity(&decrypted_keys, &decrypted_shares)?;

            Ok(())
        })();

        if let Err(e) = result {
            self.backend = None;
            self.header = old_header;
            self.data_key = Some(old_data_key.clone());
            let header_err = copy_with_retry(&backup_path, &header_path).err();
            let db_err = copy_with_retry(&db_backup_path, &db_path).err();
            self.backend = RedbBackend::open(&db_path)
                .ok()
                .map(|b| Box::new(b) as Box<dyn StorageBackend>);
            if let Some(ref err) = header_err {
                warn!(error = %err, "failed to restore header backup during rollback - vault may be corrupted");
            }
            if let Some(ref err) = db_err {
                warn!(error = %err, "failed to restore database backup during rollback - vault may be corrupted");
            }
            if let Err(err) = secure_delete(&backup_path) {
                warn!(path = %backup_path.display(), error = %err, "failed to securely delete backup file after rotation failure");
            }
            if let Err(err) = secure_delete(&db_backup_path) {
                warn!(path = %db_backup_path.display(), error = %err, "failed to securely delete database backup after rotation failure");
            }
            drop(lock);
            if header_err.is_some() || db_err.is_some() {
                return Err(KeepError::RotationFailed(format!(
                    "rotation failed and backup restoration failed: {} (header: {:?}, db: {:?})",
                    e, header_err, db_err
                )));
            }
            return Err(e);
        }

        let _ = secure_delete(&backup_path);
        let _ = secure_delete(&db_backup_path);
        drop(lock);
        cleanup_rotation_lock(&self.path);
        Ok(())
    }

    fn decrypt_all_keys(
        &self,
        keys: &[KeyRecord],
        data_key: &SecretKey,
    ) -> Result<Vec<(KeyRecord, Vec<u8>)>> {
        keys.iter()
            .map(|record| {
                let encrypted = EncryptedData::from_bytes(&record.encrypted_secret)?;
                let secret = crypto::decrypt(&encrypted, data_key)?;
                Ok((record.clone(), secret.as_slice()?.to_vec()))
            })
            .collect()
    }

    fn decrypt_all_shares(
        &self,
        shares: &[StoredShare],
        data_key: &SecretKey,
    ) -> Result<Vec<(StoredShare, Vec<u8>)>> {
        shares
            .iter()
            .map(|stored| {
                let encrypted = EncryptedData::from_bytes(&stored.encrypted_key_package)?;
                let key_package_bytes = crypto::decrypt(&encrypted, data_key)?;
                Ok((stored.clone(), key_package_bytes.as_slice()?.to_vec()))
            })
            .collect()
    }

    fn reencrypt_database(
        &self,
        keys: &[(KeyRecord, Vec<u8>)],
        shares: &[(StoredShare, Vec<u8>)],
        new_data_key: &SecretKey,
    ) -> Result<()> {
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        for (record, secret_bytes) in keys {
            let new_encrypted = crypto::encrypt(secret_bytes, new_data_key)?;
            let mut new_record = record.clone();
            new_record.encrypted_secret = new_encrypted.to_bytes();
            let serialized = bincode::serialize(&new_record)?;
            let record_encrypted = crypto::encrypt(&serialized, new_data_key)?;
            backend.put(KEYS_TABLE, &new_record.id, &record_encrypted.to_bytes())?;
        }

        for (stored, key_package_bytes) in shares {
            let new_encrypted = crypto::encrypt(key_package_bytes, new_data_key)?;
            let new_stored = StoredShare {
                metadata: stored.metadata.clone(),
                encrypted_key_package: new_encrypted.to_bytes(),
                pubkey_package: stored.pubkey_package.clone(),
            };
            let serialized = bincode::serialize(&new_stored)?;
            let record_encrypted = crypto::encrypt(&serialized, new_data_key)?;
            let id = share_id(&stored.metadata.group_pubkey, stored.metadata.identifier);
            backend.put(SHARES_TABLE, &id, &record_encrypted.to_bytes())?;
        }

        Ok(())
    }

    fn verify_rotation_integrity(
        &self,
        original_keys: &[(KeyRecord, Vec<u8>)],
        original_shares: &[(StoredShare, Vec<u8>)],
    ) -> Result<()> {
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let stored_keys = backend.list(KEYS_TABLE)?;
        if stored_keys.len() != original_keys.len() {
            return Err(KeepError::RotationFailed(format!(
                "key count mismatch: expected {}, found {}",
                original_keys.len(),
                stored_keys.len()
            )));
        }

        for (original_record, original_secret) in original_keys {
            let encrypted_bytes =
                backend
                    .get(KEYS_TABLE, &original_record.id)?
                    .ok_or_else(|| {
                        KeepError::RotationFailed(format!(
                            "key {} missing after rotation",
                            hex::encode(original_record.id)
                        ))
                    })?;
            let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
            let decrypted = crypto::decrypt(&encrypted, data_key)?;
            let decrypted_bytes = decrypted.as_slice()?;
            let record: KeyRecord = bincode_options().deserialize(&decrypted_bytes)?;
            let inner_encrypted = EncryptedData::from_bytes(&record.encrypted_secret)?;
            let inner_decrypted = crypto::decrypt(&inner_encrypted, data_key)?;
            let inner_bytes = inner_decrypted.as_slice()?;
            if !bool::from(inner_bytes.ct_eq(original_secret.as_slice())) {
                return Err(KeepError::RotationFailed(format!(
                    "key {} content mismatch after rotation",
                    hex::encode(original_record.id)
                )));
            }
        }

        let stored_shares = backend.list(SHARES_TABLE)?;
        if stored_shares.len() != original_shares.len() {
            return Err(KeepError::RotationFailed(format!(
                "share count mismatch: expected {}, found {}",
                original_shares.len(),
                stored_shares.len()
            )));
        }

        for (original_stored, original_key_package) in original_shares {
            let id = share_id(
                &original_stored.metadata.group_pubkey,
                original_stored.metadata.identifier,
            );
            let encrypted_bytes = backend.get(SHARES_TABLE, &id)?.ok_or_else(|| {
                KeepError::RotationFailed(format!(
                    "share {} missing after rotation",
                    original_stored.metadata.identifier
                ))
            })?;
            let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
            let decrypted = crypto::decrypt(&encrypted, data_key)?;
            let decrypted_bytes = decrypted.as_slice()?;
            let stored: StoredShare = bincode_options().deserialize(&decrypted_bytes)?;
            let inner_encrypted = EncryptedData::from_bytes(&stored.encrypted_key_package)?;
            let inner_decrypted = crypto::decrypt(&inner_encrypted, data_key)?;
            let inner_bytes = inner_decrypted.as_slice()?;
            if !bool::from(inner_bytes.ct_eq(original_key_package.as_slice())) {
                return Err(KeepError::RotationFailed(format!(
                    "share {} content mismatch after rotation",
                    original_stored.metadata.identifier
                )));
            }
        }

        Ok(())
    }

    fn encrypt_data_key_in_header(&self, password: &str, data_key: &SecretKey) -> Result<Header> {
        let master_key = crypto::derive_key(
            password.as_bytes(),
            &self.header.salt,
            self.header.argon2_params(),
        )?;
        let header_key = crypto::derive_subkey(&master_key, b"keep-header-key")?;
        let data_key_bytes = data_key.decrypt()?;
        let encrypted = crypto::encrypt(&*data_key_bytes, &header_key)?;

        let mut new_header = self.header.clone();
        new_header.nonce.copy_from_slice(&encrypted.nonce);
        new_header
            .encrypted_data_key
            .copy_from_slice(&encrypted.ciphertext);
        Ok(new_header)
    }
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
    fn test_rotate_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-rotate-pw");

        {
            let storage = Storage::create(&path, "oldpass", Argon2Params::TESTING).unwrap();
            let pubkey: [u8; 32] = crypto::random_bytes();
            let secret: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8];
            let encrypted = crypto::encrypt(&secret, storage.data_key().unwrap()).unwrap();
            let record = KeyRecord::new(
                pubkey,
                crate::keys::KeyType::Nostr,
                "test".into(),
                encrypted.to_bytes(),
            );
            storage.store_key(&record).unwrap();
        }

        {
            let mut storage = Storage::open(&path).unwrap();
            storage.rotate_password("oldpass", "newpass").unwrap();
        }

        {
            let mut storage = Storage::open(&path).unwrap();
            assert!(storage.unlock("oldpass").is_err());
        }

        {
            let mut storage = Storage::open(&path).unwrap();
            storage.unlock("newpass").unwrap();
            let keys = storage.list_keys().unwrap();
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0].name, "test");
        }
    }

    #[test]
    fn test_rotate_data_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-rotate-dek");

        {
            let storage = Storage::create(&path, "password", Argon2Params::TESTING).unwrap();
            let pubkey: [u8; 32] = crypto::random_bytes();
            let secret: Vec<u8> = vec![9, 10, 11, 12];
            let encrypted = crypto::encrypt(&secret, storage.data_key().unwrap()).unwrap();
            let record = KeyRecord::new(
                pubkey,
                crate::keys::KeyType::Nostr,
                "dek-test".into(),
                encrypted.to_bytes(),
            );
            storage.store_key(&record).unwrap();
        }

        {
            let mut storage = Storage::open(&path).unwrap();
            storage.rotate_data_key("password").unwrap();
            let keys = storage.list_keys().unwrap();
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0].name, "dek-test");
        }
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
