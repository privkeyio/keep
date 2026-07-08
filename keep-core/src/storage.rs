// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Persistent encrypted storage backend.
use std::fs;
use std::path::{Path, PathBuf};

use tracing::{debug, trace, warn};

use crate::backend::{
    RedbBackend, StorageBackend, CONFIG_TABLE, DESCRIPTORS_TABLE, HEALTH_STATUS_TABLE, KEYS_TABLE,
    RELAY_CONFIGS_TABLE, SHARES_TABLE, STATE_VERSIONS_TABLE,
};
use crate::crypto::{self, Argon2Params, EncryptedData, SecretKey, SALT_SIZE};
use crate::error::{KeepError, Result, StorageError};
use crate::frost::StoredShare;
use crate::keys::KeyRecord;
use crate::rate_limit;
use crate::relay::{self, RelayConfig};
use crate::wallet::{KeyHealthStatus, WalletDescriptor};

use bincode::Options;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// SOCKS5 proxy configuration stored in the vault.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Whether the proxy is enabled.
    pub enabled: bool,
    /// The proxy port (host is always 127.0.0.1).
    pub port: u16,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 9050,
        }
    }
}

const MAX_RECORD_SIZE: u64 = 1024 * 1024;
const MIN_PASSWORD_LEN: usize = 8;
const MAX_PASSWORD_LEN: usize = 4096;

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

fn validate_password_max_len(password: &str) -> Result<()> {
    if password.len() > MAX_PASSWORD_LEN {
        return Err(KeepError::InvalidInput(
            "password too long (max 4096 bytes)".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_new_password(password: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(KeepError::InvalidInput(format!(
            "password too short (min {MIN_PASSWORD_LEN} bytes)"
        )));
    }
    validate_password_max_len(password)
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
    pub(crate) fn new(params: Argon2Params) -> Result<Self> {
        Ok(Self {
            magic: *HEADER_MAGIC,
            version: HEADER_VERSION,
            flags: 0,
            salt: crypto::try_random_bytes()?,
            nonce: crypto::try_random_bytes()?,
            encrypted_data_key: [0; 48],
            argon2_memory_kib: params.memory_kib,
            argon2_iterations: params.iterations,
            argon2_parallelism: params.parallelism,
            _padding: [0; 140],
        })
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

/// Sink for vault-state changes so a node can replicate its redb records to a standby (the
/// keep-state-over-wisp design). keep-web installs an implementation that publishes each change as a
/// Nostr event; keep-core only signals table/record/bytes and never touches the network. `on_record`
/// carries the record's already-encrypted redb bytes -- the exact bytes stored -- so a peer that
/// shares the vault key stores them verbatim. Called from inside the write path, so an implementation
/// MUST NOT block: enqueue and return.
pub trait StatePublisher: Send + Sync {
    /// A record was written: `table` is one of keys/descriptors/relay_configs, `record_id` is its
    /// hex redb key, and `encrypted` is the vault-encrypted bytes as stored.
    fn on_record(&self, table: &str, record_id: &str, encrypted: &[u8]);
    /// A record (`table`, hex `record_id`) was deleted.
    fn on_delete(&self, table: &str, record_id: &str);
}

/// Encrypted persistent storage for keys and FROST shares.
pub struct Storage {
    pub(crate) path: PathBuf,
    pub(crate) header: Header,
    pub(crate) data_key: Option<SecretKey>,
    pub(crate) backend: Option<Box<dyn StorageBackend>>,
    /// Serializes read-modify-write sequences on wallet descriptors so that
    /// e.g. two concurrent `upsert_device_registration` calls cannot drop
    /// one another's updates.
    pub(crate) descriptor_lock: std::sync::Mutex<()>,
    /// Optional replication sink; see [`StatePublisher`]. `RwLock` so keep-web can install it after
    /// construction (via [`Storage::set_state_publisher`]) while storage methods take `&self`.
    pub(crate) state_publisher: std::sync::RwLock<Option<std::sync::Arc<dyn StatePublisher>>>,
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

/// Write a vault data file with 0o600 perms on Unix. Defense-in-depth: even
/// if the containing 0o700 directory is ever loosened (umask, restore-from-tar,
/// rsync to a less-strict filesystem), the file itself stays owner-readable.
fn write_vault_file_secure(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        std::io::Write::write_all(&mut file, data)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    fs::write(path, data)?;
    Ok(())
}

/// Apply 0o600 perms to an existing file (best-effort). Used to bring
/// pre-existing redb-created files in line with the rest of the vault.
#[cfg(unix)]
fn chmod_secure(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

impl Storage {
    /// Install the replication sink (keep-web). A later call replaces the previous sink.
    pub fn set_state_publisher(&self, publisher: std::sync::Arc<dyn StatePublisher>) {
        if let Ok(mut slot) = self.state_publisher.write() {
            *slot = Some(publisher);
        }
    }

    fn notify_record(&self, table: &str, record_id: &str, encrypted: &[u8]) {
        if let Ok(slot) = self.state_publisher.read() {
            if let Some(p) = slot.as_ref() {
                p.on_record(table, record_id, encrypted);
            }
        }
    }

    fn notify_delete(&self, table: &str, record_id: &str) {
        if let Ok(slot) = self.state_publisher.read() {
            if let Some(p) = slot.as_ref() {
                p.on_delete(table, record_id);
            }
        }
    }

    /// Apply a record replicated from a peer (the keep-state consumer / standby side). Stores the
    /// already-vault-encrypted `encrypted` bytes verbatim under `table`, keyed by hex `record_id` --
    /// the standby shares the vault key, so it later decrypts them like its own. Never notifies the
    /// publisher, so a consumed record is not echoed back to the relay. Rejects any table but the three
    /// replicated ones, so a hostile or buggy peer cannot write `shares` or node-local state.
    /// `created_at` is the replicated event's signed timestamp; the record is applied only if it is
    /// strictly newer than the highest already applied for this d-tag (rollback/replay guard). Returns
    /// `true` if applied, `false` if ignored as stale.
    pub fn apply_replicated_record(
        &self,
        table: &str,
        record_id: &str,
        encrypted: &[u8],
        created_at: u64,
    ) -> Result<bool> {
        let (table_name, key) = Self::replicated_key(table, record_id)?;
        if !self.accept_state_version(table, record_id, created_at)? {
            return Ok(false);
        }
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;
        backend.put(table_name, &key, encrypted)?;
        Ok(true)
    }

    /// Apply a replicated delete (tombstone) from a peer. Never notifies the publisher. Same rollback
    /// guard as `apply_replicated_record`; returns `true` if applied, `false` if ignored as stale.
    pub fn apply_replicated_delete(
        &self,
        table: &str,
        record_id: &str,
        created_at: u64,
    ) -> Result<bool> {
        let (table_name, key) = Self::replicated_key(table, record_id)?;
        if !self.accept_state_version(table, record_id, created_at)? {
            return Ok(false);
        }
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;
        backend.delete(table_name, &key)?;
        Ok(true)
    }

    /// keep-state rollback guard. Returns `true` (and records the new high-water-mark) if `created_at`
    /// is strictly newer than the highest previously applied for this record's d-tag; `false` if it is
    /// stale or a replay and must be ignored. `created_at` lives in the SIGNED event, so a malicious
    /// relay cannot forge a newer one, and persisting the mark keeps the guard across restarts.
    fn accept_state_version(&self, table: &str, record_id: &str, created_at: u64) -> Result<bool> {
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;
        // Lazily ensure the table exists so a vault created before this guard migrates transparently.
        backend.create_table(STATE_VERSIONS_TABLE)?;
        let vkey = format!("{table}:{record_id}").into_bytes();
        if let Some(prev) = backend.get(STATE_VERSIONS_TABLE, &vkey)? {
            let prev_ts = u64::from_be_bytes(prev.as_slice().try_into().map_err(|_| {
                KeepError::Other("corrupt keep-state version high-water-mark".to_string())
            })?);
            if created_at <= prev_ts {
                return Ok(false);
            }
        }
        backend.put(STATE_VERSIONS_TABLE, &vkey, &created_at.to_be_bytes())?;
        Ok(true)
    }

    /// Resolve a replicated `(table, record_id)` to its backend table and raw key: maps the logical
    /// table name and hex-decodes the id. Descriptor keys are fixed 36-byte `group||version`, and the
    /// listing/lookup path fails closed on any other length, so a malformed descriptor key would poison
    /// `list_descriptors` for the whole vault -- reject it here at the trust boundary.
    fn replicated_key(table: &str, record_id: &str) -> Result<(&'static str, Vec<u8>)> {
        let table_name = Self::replicated_table(table)?;
        let key = hex::decode(record_id)
            .map_err(|e| KeepError::Other(format!("replicated record id not hex: {e}")))?;
        if table_name == DESCRIPTORS_TABLE && key.len() != 36 {
            return Err(KeepError::Other(format!(
                "replicated descriptor key has length {} (expected 36)",
                key.len()
            )));
        }
        Ok((table_name, key))
    }

    /// Map a replicated logical table name (as it appears in the event `d`-tag) to its backend table.
    fn replicated_table(table: &str) -> Result<&'static str> {
        match table {
            "keys" => Ok(KEYS_TABLE),
            "descriptors" => Ok(DESCRIPTORS_TABLE),
            "relay_configs" => Ok(RELAY_CONFIGS_TABLE),
            other => Err(KeepError::Other(format!("table {other} is not replicable"))),
        }
    }
    /// Create new storage with the given password.
    pub fn create(path: &Path, password: &str, params: Argon2Params) -> Result<Self> {
        create_storage_dir(path)?;
        let db_path = path.join("keep.db");
        let backend = RedbBackend::create(&db_path)?;
        #[cfg(unix)]
        let _ = chmod_secure(&db_path);
        Self::create_inner(path, password, params, Box::new(backend), None)
    }

    /// Create new storage whose data key is the caller-provided `data_key` rather than a fresh random
    /// one, so every node in a cluster shares one vault key (keep-state replication).
    pub fn create_with_shared_data_key(
        path: &Path,
        password: &str,
        params: Argon2Params,
        data_key: [u8; crypto::KEY_SIZE],
    ) -> Result<Self> {
        create_storage_dir(path)?;
        let db_path = path.join("keep.db");
        let backend = RedbBackend::create(&db_path)?;
        #[cfg(unix)]
        let _ = chmod_secure(&db_path);
        Self::create_inner(path, password, params, Box::new(backend), Some(data_key))
    }

    /// Create new storage with a custom backend.
    pub fn create_with_backend(
        path: &Path,
        password: &str,
        params: Argon2Params,
        backend: Box<dyn StorageBackend>,
    ) -> Result<Self> {
        create_storage_dir(path)?;
        Self::create_inner(path, password, params, backend, None)
    }

    fn create_inner(
        path: &Path,
        password: &str,
        params: Argon2Params,
        backend: Box<dyn StorageBackend>,
        shared_data_key: Option<[u8; crypto::KEY_SIZE]>,
    ) -> Result<Self> {
        validate_new_password(password)?;

        let mut header = Header::new(params)?;
        // The data key encrypts every record and is normally random per vault. A cluster can instead
        // seed the SAME data key on every node (keep-state replication), so a standby decrypts records
        // the active shipped: each node still wraps it under its OWN password+salt in its own header.
        let data_key = match shared_data_key {
            Some(k) => SecretKey::new(k)?,
            None => SecretKey::generate()?,
        };
        let master_key = crypto::derive_key(password.as_bytes(), &header.salt, params)?;
        let header_key = crypto::derive_subkey(&master_key, b"keep-header-key")?;

        let data_key_bytes = data_key.decrypt()?;
        let encrypted = crypto::encrypt(&*data_key_bytes, &header_key)?;
        header.nonce.copy_from_slice(&encrypted.nonce);
        header
            .encrypted_data_key
            .copy_from_slice(&encrypted.ciphertext);

        write_vault_file_secure(&path.join("keep.hdr"), &header.to_bytes())?;

        backend.create_table(KEYS_TABLE)?;
        backend.create_table(SHARES_TABLE)?;
        backend.create_table(DESCRIPTORS_TABLE)?;
        backend.create_table(RELAY_CONFIGS_TABLE)?;
        backend.create_table(CONFIG_TABLE)?;
        backend.create_table(HEALTH_STATUS_TABLE)?;
        backend.create_table(STATE_VERSIONS_TABLE)?;

        Ok(Self {
            path: path.to_path_buf(),
            header,
            data_key: Some(data_key),
            backend: Some(backend),
            descriptor_lock: std::sync::Mutex::new(()),
            state_publisher: std::sync::RwLock::new(None),
        })
    }

    /// Open existing storage.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(KeepError::NotFound(path.display().to_string()));
        }

        // Reconcile any leftover rotation artifacts (`.hdr.tmp`, `.hdr.backup`,
        // `.db.backup`) before reading the header. Handles the mid-rotation
        // kill gap surfaced by #565's tests: without this, a crash inside
        // `reencrypt_database` for `rotate_data_key` leaves `keep.db` with
        // rows partially rewritten under the new DEK while `keep.hdr` still
        // pins the old DEK, and every list post-open fails. See #662.
        crate::rotation::recover_rotation_artifacts(path);

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
            descriptor_lock: std::sync::Mutex::new(()),
            state_publisher: std::sync::RwLock::new(None),
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

    /// Verify a password without changing the unlock state.
    pub fn verify_password(&self, password: &str) -> Result<()> {
        validate_password_max_len(password)?;

        let hmac_key = rate_limit::derive_hmac_key(&self.header.salt);
        if let Err(remaining) = rate_limit::check_rate_limit(&self.path, &hmac_key) {
            return Err(KeepError::RateLimited(remaining.as_secs().max(1)));
        }

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
        match crypto::decrypt(&encrypted, &header_key) {
            Ok(_) => {
                rate_limit::record_success(&self.path);
                Ok(())
            }
            Err(e) => {
                if matches!(e, KeepError::DecryptionFailed) {
                    rate_limit::record_failure(&self.path, &hmac_key);
                }
                Err(e)
            }
        }
    }

    fn unlock_inner(&mut self, password: &str) -> Result<()> {
        validate_password_max_len(password)?;

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

    /// Drain rate-limit trip events queued by failed unlock attempts on this
    /// vault. The caller is expected to be holding an open audit log so the
    /// trips can be flushed as `RateLimitTripped` entries.
    pub(crate) fn drain_pending_trips(&self) -> Vec<crate::rate_limit::PendingTrip> {
        let hmac_key = crate::rate_limit::derive_hmac_key(&self.header.salt);
        crate::rate_limit::drain_pending_trips(&self.path, &hmac_key)
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
        self.notify_record("keys", &hex::encode(record.id), &encrypted_bytes);
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
            self.notify_delete("keys", &hex::encode(id));
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

        let serialized = serialize_stored_share(share)?;
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
            let serialized = serialize_stored_share(share)?;
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
            shares.push(deserialize_stored_share(&decrypted_bytes)?);
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

    /// Store a wallet descriptor. The storage key is
    /// `group_pubkey || version_be(version)` so multiple versions for the
    /// same group can coexist; replacing an existing version is a no-op
    /// upsert against the same key.
    pub fn store_descriptor(&self, descriptor: &WalletDescriptor) -> Result<()> {
        debug!(
            group = %hex::encode(descriptor.group_pubkey),
            version = descriptor.version,
            "storing wallet descriptor"
        );
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let serialized = Zeroizing::new(
            serde_json::to_vec(descriptor)
                .map_err(|e| KeepError::Other(format!("json serialization failed: {e}")))?,
        );
        let encrypted = crypto::encrypt(&serialized, data_key)?;
        let encrypted_bytes = encrypted.to_bytes();

        let key = descriptor_storage_key(&descriptor.group_pubkey, descriptor.version);
        backend.put(DESCRIPTORS_TABLE, &key, &encrypted_bytes)?;
        self.notify_record("descriptors", &hex::encode(key), &encrypted_bytes);
        Ok(())
    }

    /// Get the latest-version wallet descriptor for a group public key.
    /// Returns `None` if no descriptor is stored for the group.
    ///
    /// Only one row is decrypted (the highest-versioned one) regardless of
    /// how many versions exist for the group. The latest version is
    /// determined by the trailing 4 big-endian bytes of the key, so the
    /// payload only needs to be touched once we know which row to read.
    pub fn get_descriptor(&self, group_pubkey: &[u8; 32]) -> Result<Option<WalletDescriptor>> {
        trace!(group = %hex::encode(group_pubkey), "loading latest wallet descriptor");
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let keys = backend.list_keys_with_prefix(DESCRIPTORS_TABLE, group_pubkey.as_slice())?;
        let mut latest_version: Option<u32> = None;
        for k in &keys {
            let version = require_versioned_descriptor_key(k)?;
            if latest_version.is_none_or(|cur| version > cur) {
                latest_version = Some(version);
            }
        }
        match latest_version {
            Some(v) => self.get_descriptor_version(group_pubkey, v),
            None => Ok(None),
        }
    }

    /// Get a specific version of the wallet descriptor for a group.
    pub fn get_descriptor_version(
        &self,
        group_pubkey: &[u8; 32],
        version: u32,
    ) -> Result<Option<WalletDescriptor>> {
        trace!(
            group = %hex::encode(group_pubkey),
            version,
            "loading wallet descriptor version"
        );
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let key = descriptor_storage_key(group_pubkey, version);
        let Some(encrypted_bytes) = backend.get(DESCRIPTORS_TABLE, &key)? else {
            return Ok(None);
        };

        let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
        let decrypted = crypto::decrypt(&encrypted, data_key)?;
        let decrypted_bytes = decrypted.as_slice()?;
        let descriptor: WalletDescriptor = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| KeepError::Other(format!("json deserialization failed: {e}")))?;
        Ok(Some(descriptor))
    }

    /// List the latest-version wallet descriptor for every group. Older
    /// versions are not returned; use [`list_all_descriptor_versions`] when
    /// every row is required (e.g. backup, rotation).
    ///
    /// [`list_all_descriptor_versions`]: Self::list_all_descriptor_versions
    pub fn list_descriptors(&self) -> Result<Vec<WalletDescriptor>> {
        trace!("listing latest wallet descriptors (one per group)");
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let keys = backend.list_keys_with_prefix(DESCRIPTORS_TABLE, &[])?;
        // Pick the highest-versioned key per group from the trailing 4 BE
        // bytes of each row key, then decrypt only those rows.
        let mut latest: std::collections::HashMap<[u8; 32], u32> = std::collections::HashMap::new();
        for key in &keys {
            // Mirror `get_descriptor`: fail closed on unexpected key lengths
            // rather than silently hiding a group whose row survived an
            // incomplete v4->v5 migration.
            let version = require_versioned_descriptor_key(key)?;
            let mut group = [0u8; 32];
            group.copy_from_slice(&key[..32]);
            latest
                .entry(group)
                .and_modify(|cur| {
                    if version > *cur {
                        *cur = version;
                    }
                })
                .or_insert(version);
        }
        let mut descriptors = Vec::with_capacity(latest.len());
        for (group, version) in latest {
            if let Some(desc) = self.get_descriptor_version(&group, version)? {
                descriptors.push(desc);
            }
        }
        Ok(descriptors)
    }

    /// List every stored wallet descriptor row across all groups and
    /// versions. Decrypts every row; prefer [`list_descriptors`] when only the
    /// latest version per group is needed.
    ///
    /// [`list_descriptors`]: Self::list_descriptors
    pub fn list_all_descriptor_versions(&self) -> Result<Vec<WalletDescriptor>> {
        trace!("listing all wallet descriptor versions");
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

    /// List all stored descriptor versions for a single group public key,
    /// sorted ascending by version. Decrypts only rows whose key prefix
    /// matches the group, avoiding a full-table scan.
    pub fn list_descriptors_for_group(
        &self,
        group_pubkey: &[u8; 32],
    ) -> Result<Vec<WalletDescriptor>> {
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let keys = backend.list_keys_with_prefix(DESCRIPTORS_TABLE, group_pubkey.as_slice())?;
        let mut versions: Vec<u32> = keys
            .iter()
            .filter_map(|k| parse_versioned_descriptor_key(k, group_pubkey, "list"))
            .collect();
        versions.sort_unstable();

        let mut out = Vec::with_capacity(versions.len());
        for v in versions {
            if let Some(d) = self.get_descriptor_version(group_pubkey, v)? {
                out.push(d);
            }
        }
        Ok(out)
    }

    /// Atomically insert or update a device registration on the latest
    /// descriptor for the given group. Serialized under `descriptor_lock` so
    /// concurrent callers cannot lose each other's updates across the
    /// read-modify-write.
    ///
    /// Only the latest version row is mutated: registrations on superseded
    /// descriptor versions are not reachable through this path. This matches
    /// the protocol's "latest descriptor is authoritative" invariant. No
    /// other path iterates `list_descriptors` and re-stores entries, so older
    /// versions remain frozen at the registrations they captured at the time
    /// of the corresponding descriptor finalization.
    pub fn upsert_device_registration(
        &self,
        group_pubkey: &[u8; 32],
        registration: crate::wallet::DeviceRegistration,
    ) -> Result<()> {
        let _guard = self
            .descriptor_lock
            .lock()
            .map_err(|_| StorageError::database("descriptor lock poisoned"))?;
        let mut descriptor = self.get_descriptor(group_pubkey)?.ok_or_else(|| {
            KeepError::KeyNotFound(format!(
                "wallet descriptor for group {} not found",
                hex::encode(group_pubkey)
            ))
        })?;
        descriptor.upsert_device_registration(registration);
        self.store_descriptor(&descriptor)
    }

    /// Delete every stored version of the wallet descriptor for a group.
    /// All version rows are removed via the backend's `delete_batch`; on
    /// backends that implement it atomically (redb does) a crash mid-delete
    /// cannot leave a partial set behind.
    pub fn delete_descriptor(&self, group_pubkey: &[u8; 32]) -> Result<()> {
        debug!(group = %hex::encode(group_pubkey), "deleting wallet descriptor (all versions)");
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let keys = backend.list_keys_with_prefix(DESCRIPTORS_TABLE, group_pubkey.as_slice())?;
        // Delete every row under the group prefix regardless of key length:
        // skipping a stray legacy 32-byte row here would leave it behind
        // forever and make subsequent reads inconsistent. The v4->v5
        // migration is expected to have rewritten such rows, so the only way
        // we observe one is partial migration; the safest action is to drop
        // it along with the versioned rows.
        if keys.is_empty() {
            return Err(KeepError::KeyNotFound(format!(
                "wallet descriptor for group {} not found",
                hex::encode(group_pubkey)
            )));
        }

        let refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        backend.delete_batch(DESCRIPTORS_TABLE, &refs)?;
        for k in &keys {
            self.notify_delete("descriptors", &hex::encode(k));
        }
        Ok(())
    }

    /// Delete a single version of a wallet descriptor for a group.
    pub fn delete_descriptor_version(&self, group_pubkey: &[u8; 32], version: u32) -> Result<()> {
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;
        let key = descriptor_storage_key(group_pubkey, version);
        if backend.delete(DESCRIPTORS_TABLE, &key)? {
            self.notify_delete("descriptors", &hex::encode(key));
            Ok(())
        } else {
            Err(KeepError::KeyNotFound(format!(
                "wallet descriptor for group {} version {} not found",
                hex::encode(group_pubkey),
                version
            )))
        }
    }

    /// Store a relay configuration.
    pub fn store_relay_config(&self, config: &RelayConfig) -> Result<()> {
        debug!(group = %hex::encode(config.group_pubkey), "storing relay config");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let normalized = config.clone().normalize()?;
        let encrypted_bytes = relay::encode_relay_config(&normalized, data_key)?;
        backend.put(
            RELAY_CONFIGS_TABLE,
            &normalized.group_pubkey,
            &encrypted_bytes,
        )?;
        self.notify_record(
            "relay_configs",
            &hex::encode(normalized.group_pubkey),
            &encrypted_bytes,
        );
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

        Ok(Some(relay::decode_relay_config(
            &encrypted_bytes,
            data_key,
        )?))
    }

    /// List all stored relay configurations.
    pub fn list_relay_configs(&self) -> Result<Vec<RelayConfig>> {
        trace!("listing relay configs");
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let entries = backend.list(RELAY_CONFIGS_TABLE)?;
        let mut configs = Vec::new();

        for (_, encrypted_bytes) in entries {
            configs.push(relay::decode_relay_config(&encrypted_bytes, data_key)?);
        }

        Ok(configs)
    }

    /// Delete a relay configuration.
    pub fn delete_relay_config(&self, group_pubkey: &[u8; 32]) -> Result<()> {
        debug!(group = %hex::encode(group_pubkey), "deleting relay config");
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;
        if backend.delete(RELAY_CONFIGS_TABLE, group_pubkey)? {
            self.notify_delete("relay_configs", &hex::encode(group_pubkey));
            Ok(())
        } else {
            Err(KeepError::KeyNotFound(format!(
                "relay config for group {} not found",
                hex::encode(group_pubkey)
            )))
        }
    }

    /// Get the kill switch state from the vault.
    pub fn get_kill_switch(&self) -> Result<bool> {
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let Some(encrypted_bytes) = backend.get(CONFIG_TABLE, b"kill_switch")? else {
            return Ok(false);
        };

        let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
        let decrypted = crypto::decrypt(&encrypted, data_key)?;
        let bytes = decrypted.as_slice()?;
        Ok(bytes.first().copied() == Some(1))
    }

    /// Set the kill switch state in the vault.
    pub fn set_kill_switch(&self, active: bool) -> Result<()> {
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let value = if active { [1u8] } else { [0u8] };
        let encrypted = crypto::encrypt(&value, data_key)?;
        let encrypted_bytes = encrypted.to_bytes();

        backend.put(CONFIG_TABLE, b"kill_switch", &encrypted_bytes)?;
        Ok(())
    }

    /// Get the proxy configuration from the vault.
    pub fn get_proxy_config(&self) -> Result<ProxyConfig> {
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let Some(encrypted_bytes) = backend.get(CONFIG_TABLE, b"proxy_config")? else {
            return Ok(ProxyConfig::default());
        };

        let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
        let decrypted = crypto::decrypt(&encrypted, data_key)?;
        let decrypted_bytes = decrypted.as_slice()?;
        serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| KeepError::Other(format!("json deserialization failed: {e}")))
    }

    /// Set the proxy configuration in the vault.
    pub fn set_proxy_config(&self, config: &ProxyConfig) -> Result<()> {
        if config.port == 0 {
            return Err(KeepError::InvalidInput(
                "proxy port must be non-zero".into(),
            ));
        }
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let serialized = serde_json::to_vec(config)
            .map_err(|e| KeepError::Other(format!("json serialization failed: {e}")))?;
        let encrypted = crypto::encrypt(&serialized, data_key)?;
        let encrypted_bytes = encrypted.to_bytes();

        backend.put(CONFIG_TABLE, b"proxy_config", &encrypted_bytes)?;
        Ok(())
    }

    /// Store a key health status record.
    pub fn store_health_status(&self, status: &KeyHealthStatus) -> Result<()> {
        debug!(
            group = %hex::encode(status.group_pubkey),
            share = status.share_index,
            responsive = status.responsive,
            "storing health status"
        );
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let key = health_status_key(&status.group_pubkey, status.share_index);
        let serialized = serde_json::to_vec(status)
            .map_err(|e| KeepError::Other(format!("json serialization failed: {e}")))?;
        let encrypted = crypto::encrypt(&serialized, data_key)?;
        backend.put(HEALTH_STATUS_TABLE, key.as_bytes(), &encrypted.to_bytes())?;
        Ok(())
    }

    /// Get a key health status record.
    pub fn get_health_status(
        &self,
        group_pubkey: &[u8; 32],
        share_index: u16,
    ) -> Result<Option<KeyHealthStatus>> {
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let key = health_status_key(group_pubkey, share_index);
        let Some(encrypted_bytes) = backend.get(HEALTH_STATUS_TABLE, key.as_bytes())? else {
            return Ok(None);
        };

        let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
        let decrypted = crypto::decrypt(&encrypted, data_key)?;
        let decrypted_bytes = decrypted.as_slice()?;
        let status: KeyHealthStatus = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| KeepError::Other(format!("json deserialization failed: {e}")))?;
        Ok(Some(status))
    }

    /// List all key health status records.
    pub fn list_health_statuses(&self) -> Result<Vec<KeyHealthStatus>> {
        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;

        let entries = backend.list(HEALTH_STATUS_TABLE)?;
        let mut statuses = Vec::new();

        for (_, encrypted_bytes) in entries {
            let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
            let decrypted = crypto::decrypt(&encrypted, data_key)?;
            let decrypted_bytes = decrypted.as_slice()?;
            let status: KeyHealthStatus = serde_json::from_slice(&decrypted_bytes)
                .map_err(|e| KeepError::Other(format!("json deserialization failed: {e}")))?;
            statuses.push(status);
        }

        Ok(statuses)
    }

    /// Delete a key health status record.
    pub fn delete_health_status(&self, group_pubkey: &[u8; 32], share_index: u16) -> Result<()> {
        let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;
        let key = health_status_key(group_pubkey, share_index);
        if backend.delete(HEALTH_STATUS_TABLE, key.as_bytes())? {
            Ok(())
        } else {
            Err(KeepError::KeyNotFound(format!(
                "health status for share {share_index} not found"
            )))
        }
    }
}

fn health_status_key(group_pubkey: &[u8; 32], share_index: u16) -> String {
    format!("{}:{}", hex::encode(group_pubkey), share_index)
}

/// Compose the storage key for a wallet descriptor row:
/// `group_pubkey (32) || version_be (4)`.
pub(crate) fn descriptor_storage_key(group_pubkey: &[u8; 32], version: u32) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[..32].copy_from_slice(group_pubkey);
    key[32..36].copy_from_slice(&version.to_be_bytes());
    key
}

/// Extract the version from the trailing 4 big-endian bytes of a descriptor
/// row key. Caller must have verified `key.len() == 36`.
fn descriptor_key_version(key: &[u8]) -> u32 {
    let mut v_bytes = [0u8; 4];
    v_bytes.copy_from_slice(&key[32..36]);
    u32::from_be_bytes(v_bytes)
}

/// Strictly parse a descriptor row key, returning its version. Fails closed on
/// any non-36-byte key: post-migration every row is `group||version_be`, so an
/// unexpected length means the v4->v5 migration did not complete and the caller
/// must not silently miss data.
fn require_versioned_descriptor_key(key: &[u8]) -> Result<u32> {
    if key.len() != 36 {
        return Err(KeepError::Other(format!(
            "wallet_descriptors row has unexpected key length {} (expected 36); migration to v5 incomplete",
            key.len()
        )));
    }
    Ok(descriptor_key_version(key))
}

/// Parse a descriptor row key produced by [`descriptor_storage_key`] and
/// return its version. Returns `None` for any legacy 32-byte row that
/// matches the group prefix; the v4->v5 migration was expected to rewrite
/// those, so a remaining row is logged as a warning rather than silently
/// dropped. `op` tags the call site (e.g. `"lookup"`, `"delete"`) so log
/// readers can tell which scan surfaced the leftover.
fn parse_versioned_descriptor_key(
    key: &[u8],
    group_pubkey: &[u8; 32],
    op: &'static str,
) -> Option<u32> {
    if key.len() != 36 {
        warn!(
            group = %hex::encode(group_pubkey),
            key_len = key.len(),
            op,
            "skipping non-versioned descriptor row under group prefix (expected migration to v5)"
        );
        return None;
    }
    Some(descriptor_key_version(key))
}

/// Self-describing version prefix on the persisted `StoredShare` blob.
///
/// bincode is not self-describing, so a `#[serde(default)]` field appended to
/// `StoredShare` cannot be filled in from an older blob that lacks it. Rather
/// than guess the layout by trying multiple deserializations, new writes carry
/// an explicit `magic || version` prefix that unambiguously identifies the
/// layout. Blobs without the prefix are pre-versioning data (v0), which is
/// always secp256k1.
const SHARE_FORMAT_MAGIC: &[u8; 4] = b"KSH1";
const SHARE_FORMAT_V1: u8 = 1;

/// Serialize a `StoredShare` with the explicit version prefix.
pub(crate) fn serialize_stored_share(share: &StoredShare) -> Result<Vec<u8>> {
    let body = bincode_options().serialize(share)?;
    let mut out = Vec::with_capacity(SHARE_FORMAT_MAGIC.len() + 1 + body.len());
    out.extend_from_slice(SHARE_FORMAT_MAGIC);
    out.push(SHARE_FORMAT_V1);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Deserialize a `StoredShare`, dispatching on the explicit version prefix.
///
/// A blob carrying the `KSH1` magic is parsed strictly as the current
/// `StoredShare` layout (ciphersuite tag included). A blob without the magic is
/// pre-versioning data: it is parsed as the legacy three-field layout and the
/// tag defaults to `Secp256k1Tr`. This is parse-don't-guess: the prefix names
/// the layout instead of inferring it from a failed deserialization. The
/// ciphersuite tag stays bound in the AEAD AAD, so a misclassification (e.g. an
/// adversarially prefixed legacy blob) still fails closed at the MAC rather
/// than yielding a wrong key.
pub(crate) fn deserialize_stored_share(bytes: &[u8]) -> Result<StoredShare> {
    if let Some([SHARE_FORMAT_V1, body @ ..]) = bytes.strip_prefix(SHARE_FORMAT_MAGIC.as_slice()) {
        return Ok(bincode_options().deserialize::<StoredShare>(body)?);
    }

    #[derive(serde::Deserialize)]
    struct LegacyStoredShare {
        metadata: crate::frost::ShareMetadata,
        encrypted_key_package: Vec<u8>,
        pubkey_package: Vec<u8>,
    }

    let legacy: LegacyStoredShare = bincode_options().deserialize(bytes)?;
    Ok(StoredShare {
        metadata: legacy.metadata,
        encrypted_key_package: legacy.encrypted_key_package,
        pubkey_package: legacy.pubkey_package,
        ciphersuite: crate::frost::Ciphersuite::Secp256k1Tr,
    })
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
    fn test_legacy_stored_share_blob_loads_as_secp256k1() {
        use bincode::Options;

        #[derive(serde::Serialize)]
        struct LegacyStoredShare {
            metadata: crate::frost::ShareMetadata,
            encrypted_key_package: Vec<u8>,
            pubkey_package: Vec<u8>,
        }

        let legacy = LegacyStoredShare {
            metadata: crate::frost::ShareMetadata::new(1, 2, 3, [3u8; 32], "old".into()),
            encrypted_key_package: vec![1u8; 64],
            pubkey_package: vec![2u8; 33],
        };

        let opts = || {
            bincode::options()
                .with_fixint_encoding()
                .allow_trailing_bytes()
        };

        // A blob written by the old default-options path and the configured path.
        for blob in [
            bincode::serialize(&legacy).unwrap(),
            opts().serialize(&legacy).unwrap(),
        ] {
            let loaded = deserialize_stored_share(&blob).unwrap();
            assert_eq!(loaded.ciphersuite, crate::frost::Ciphersuite::Secp256k1Tr);
            assert_eq!(loaded.metadata.identifier, 1);
            assert_eq!(loaded.encrypted_key_package, vec![1u8; 64]);
            assert_eq!(loaded.pubkey_package, vec![2u8; 33]);
        }
    }

    #[test]
    fn test_new_stored_share_blob_roundtrips() {
        let share = StoredShare {
            metadata: crate::frost::ShareMetadata::new(2, 2, 3, [4u8; 32], "new".into()),
            encrypted_key_package: vec![7u8; 50],
            pubkey_package: vec![8u8; 33],
            ciphersuite: crate::frost::Ciphersuite::Ed25519,
        };

        let blob = serialize_stored_share(&share).unwrap();
        assert!(blob.starts_with(SHARE_FORMAT_MAGIC));
        assert_eq!(blob[SHARE_FORMAT_MAGIC.len()], SHARE_FORMAT_V1);

        let loaded = deserialize_stored_share(&blob).unwrap();
        assert_eq!(loaded.ciphersuite, crate::frost::Ciphersuite::Ed25519);
        assert_eq!(loaded.metadata.identifier, 2);
        assert_eq!(loaded.encrypted_key_package, vec![7u8; 50]);
    }

    #[test]
    fn test_versioned_blob_does_not_parse_as_legacy() {
        // A v1-prefixed Ed25519 blob must never be silently read through the
        // legacy (always-secp256k1) path. The magic dispatches it strictly to
        // the current layout, preserving its real ciphersuite tag.
        let share = StoredShare {
            metadata: crate::frost::ShareMetadata::new(5, 2, 3, [6u8; 32], "v1".into()),
            encrypted_key_package: vec![1u8; 40],
            pubkey_package: vec![2u8; 32],
            ciphersuite: crate::frost::Ciphersuite::Ed25519,
        };
        let blob = serialize_stored_share(&share).unwrap();
        let loaded = deserialize_stored_share(&blob).unwrap();
        assert_eq!(loaded.ciphersuite, crate::frost::Ciphersuite::Ed25519);
    }

    #[test]
    fn test_legacy_blob_cannot_be_misread_as_ed25519() {
        // A legacy (unprefixed) blob is always loaded as secp256k1; there is no
        // input shape that makes the legacy path yield a different ciphersuite.
        use bincode::Options;

        #[derive(serde::Serialize)]
        struct LegacyStoredShare {
            metadata: crate::frost::ShareMetadata,
            encrypted_key_package: Vec<u8>,
            pubkey_package: Vec<u8>,
        }

        let legacy = LegacyStoredShare {
            metadata: crate::frost::ShareMetadata::new(9, 2, 3, [1u8; 32], "legacy".into()),
            encrypted_key_package: vec![3u8; 48],
            pubkey_package: vec![4u8; 33],
        };
        let blob = bincode::options()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .serialize(&legacy)
            .unwrap();

        let loaded = deserialize_stored_share(&blob).unwrap();
        assert_eq!(loaded.ciphersuite, crate::frost::Ciphersuite::Secp256k1Tr);
    }

    #[test]
    fn test_stored_share_envelope_byte_identity_preserved() {
        // The version prefix lives on the plaintext StoredShare serialization,
        // independent of the AEAD envelope. A secp256k1 share's encrypted_key_package
        // (empty AAD) is byte-identical to what plain crypto::encrypt produces.
        let key = crypto::SecretKey::generate().unwrap();
        let pkg = crate::frost::SharePackage::from_bytes(
            crate::frost::ShareMetadata::new(1, 2, 3, [7u8; 32], "x".into()),
            vec![1, 2, 3, 4],
            vec![9, 9, 9],
        );
        let stored = StoredShare::encrypt(&pkg, &key).unwrap();
        let restored = stored.decrypt(&key).unwrap();
        assert_eq!(restored.key_package_bytes(), pkg.key_package_bytes());
        assert_eq!(stored.ciphersuite, crate::frost::Ciphersuite::Secp256k1Tr);
    }

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

        Storage::create(&path, "correctpass", Argon2Params::TESTING).unwrap();

        let mut storage = Storage::open(&path).unwrap();
        let result = storage.unlock("wrongpass");
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

        Storage::create(&path, "correctpass", Argon2Params::TESTING).unwrap();

        for _ in 0..5 {
            let mut storage = Storage::open(&path).unwrap();
            let result = storage.unlock("wrongpass");
            assert!(matches!(result, Err(KeepError::DecryptionFailed)));
        }

        // Bump failure count higher so the delay (4s) won't expire during test
        // execution. Without this, the 1s delay at exactly 5 failures can expire
        // on slow CI (Windows) between record_failure and check_rate_limit.
        {
            let storage = Storage::open(&path).unwrap();
            let hmac_key = rate_limit::derive_hmac_key(&storage.header.salt);
            for _ in 0..2 {
                rate_limit::record_failure(&path, &hmac_key);
            }
        }

        let mut storage = Storage::open(&path).unwrap();
        let result = storage.unlock("wrongpass");
        assert!(matches!(result, Err(KeepError::RateLimited(_))));
    }

    #[test]
    fn test_storage_rate_limit_resets_on_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-rate-limit-reset");

        Storage::create(&path, "correctpass", Argon2Params::TESTING).unwrap();

        for _ in 0..4 {
            let mut storage = Storage::open(&path).unwrap();
            let _ = storage.unlock("wrongpass");
        }

        {
            let mut storage = Storage::open(&path).unwrap();
            storage.unlock("correctpass").unwrap();
        }

        for _ in 0..4 {
            let mut storage = Storage::open(&path).unwrap();
            let result = storage.unlock("wrongpass");
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

    #[derive(Default)]
    struct RecordingPublisher {
        records: std::sync::Mutex<Vec<(String, String)>>,
        deletes: std::sync::Mutex<Vec<(String, String)>>,
        last_bytes: std::sync::Mutex<Vec<u8>>,
    }
    impl StatePublisher for RecordingPublisher {
        fn on_record(&self, table: &str, record_id: &str, encrypted: &[u8]) {
            self.records
                .lock()
                .unwrap()
                .push((table.into(), record_id.into()));
            *self.last_bytes.lock().unwrap() = encrypted.to_vec();
        }
        fn on_delete(&self, table: &str, record_id: &str) {
            self.deletes
                .lock()
                .unwrap()
                .push((table.into(), record_id.into()));
        }
    }

    #[test]
    fn apply_replicated_record_round_trips_and_rejects_nonreplicable_tables() {
        use crate::backend::MemoryBackend;

        let dir = tempdir().unwrap();
        let path = dir.path().join("test-apply");
        let backend = Box::new(MemoryBackend::new());
        let storage =
            Storage::create_with_backend(&path, "password", Argon2Params::TESTING, backend)
                .unwrap();

        let publisher = std::sync::Arc::new(RecordingPublisher::default());
        storage.set_state_publisher(publisher.clone());

        let record = KeyRecord::new(
            crypto::random_bytes(),
            crate::keys::KeyType::Nostr,
            "replicated".into(),
            vec![7, 7, 7],
        );
        // Store, capture the exact bytes the publisher shipped, then delete so the vault no longer has
        // the record locally.
        storage.store_key(&record).unwrap();
        let encrypted = publisher.last_bytes.lock().unwrap().clone();
        storage.delete_key(&record.id).unwrap();
        assert!(storage.load_key(&record.id).is_err());

        // Applying the replicated bytes reconstructs a loadable record (same vault key decrypts them).
        storage
            .apply_replicated_record("keys", &hex::encode(record.id), &encrypted, 1)
            .unwrap();
        assert_eq!(storage.load_key(&record.id).unwrap().name, "replicated");

        // A non-replicable table (shares / node-local / unknown) is refused, so a peer cannot write it.
        assert!(storage
            .apply_replicated_record("shares", &hex::encode(record.id), &encrypted, 1)
            .is_err());
        assert!(storage
            .apply_replicated_record("bogus", &hex::encode(record.id), &encrypted, 1)
            .is_err());

        // A descriptor key of the wrong length is refused: the listing/lookup path fails closed on any
        // non-36-byte descriptor row, so accepting one would poison list_descriptors for the vault.
        assert!(storage
            .apply_replicated_record("descriptors", &hex::encode([0u8; 20]), &encrypted, 1)
            .is_err());
        assert!(storage
            .apply_replicated_delete("descriptors", &hex::encode([0u8; 20]), 1)
            .is_err());
        // A correctly-sized 36-byte descriptor key is accepted.
        assert!(storage
            .apply_replicated_record("descriptors", &hex::encode([0u8; 36]), &encrypted, 1)
            .is_ok());

        // A replicated delete removes it, and never echoes to the publisher: the only recorded delete
        // is the earlier real delete_key, not this apply.
        let deletes_before = publisher.deletes.lock().unwrap().len();
        storage
            .apply_replicated_delete("keys", &hex::encode(record.id), 2)
            .unwrap();
        assert!(storage.load_key(&record.id).is_err());
        assert_eq!(publisher.deletes.lock().unwrap().len(), deletes_before);
    }

    #[test]
    fn replicated_apply_rejects_stale_created_at() {
        // The rollback guard: an event not strictly newer than the highest applied for its d-tag is
        // ignored, so an untrusted relay cannot replay a stale record/delete to roll a standby back.
        // created_at is the SIGNED event timestamp and cannot be forged to look newer.
        let dir = tempdir().unwrap();
        let storage =
            Storage::create(&dir.path().join("v"), "passwordX", Argon2Params::TESTING).unwrap();

        let publisher = std::sync::Arc::new(RecordingPublisher::default());
        storage.set_state_publisher(publisher.clone());
        let mk = |name: &str| {
            KeyRecord::new(
                [9u8; 32],
                crate::keys::KeyType::Nostr,
                name.into(),
                vec![1, 2, 3],
            )
        };
        storage.store_key(&mk("v1")).unwrap();
        let enc_v1 = publisher.last_bytes.lock().unwrap().clone();
        storage.store_key(&mk("v2")).unwrap();
        let enc_v2 = publisher.last_bytes.lock().unwrap().clone();
        let id = hex::encode([9u8; 32]);

        // Apply v2 at created_at=100.
        assert!(storage
            .apply_replicated_record("keys", &id, &enc_v2, 100)
            .unwrap());
        assert_eq!(storage.load_key(&[9u8; 32]).unwrap().name, "v2");

        // An older replay is rejected and does NOT roll the record back to v1.
        assert!(!storage
            .apply_replicated_record("keys", &id, &enc_v1, 50)
            .unwrap());
        assert_eq!(storage.load_key(&[9u8; 32]).unwrap().name, "v2");
        // The SAME created_at is also rejected (idempotent, no rollback).
        assert!(!storage
            .apply_replicated_record("keys", &id, &enc_v1, 100)
            .unwrap());
        assert_eq!(storage.load_key(&[9u8; 32]).unwrap().name, "v2");

        // A strictly-newer delete IS applied, and a stale record cannot resurrect the deleted row.
        assert!(storage.apply_replicated_delete("keys", &id, 200).unwrap());
        assert!(storage.load_key(&[9u8; 32]).is_err());
        assert!(!storage
            .apply_replicated_record("keys", &id, &enc_v1, 150)
            .unwrap());
        assert!(storage.load_key(&[9u8; 32]).is_err());
    }

    #[test]
    fn shared_data_key_cross_decrypts_across_vaults() {
        // Two independent vaults with DIFFERENT passwords but the SAME seeded data key: a record
        // encrypted by one must decrypt in the other. This is the cluster invariant keep-state
        // replication relies on (the standby reads what the active shipped).
        let shared: [u8; 32] = crypto::random_bytes();
        let dir = tempdir().unwrap();

        let a = Storage::create_with_shared_data_key(
            &dir.path().join("a"),
            "passwordA",
            Argon2Params::TESTING,
            shared,
        )
        .unwrap();
        let b = Storage::create_with_shared_data_key(
            &dir.path().join("b"),
            "differentB",
            Argon2Params::TESTING,
            shared,
        )
        .unwrap();

        let publisher = std::sync::Arc::new(RecordingPublisher::default());
        a.set_state_publisher(publisher.clone());

        let record = KeyRecord::new(
            crypto::random_bytes(),
            crate::keys::KeyType::Nostr,
            "shared".into(),
            vec![1, 2, 3],
        );
        a.store_key(&record).unwrap();
        let encrypted = publisher.last_bytes.lock().unwrap().clone();

        b.apply_replicated_record("keys", &hex::encode(record.id), &encrypted, 1)
            .unwrap();
        assert_eq!(b.load_key(&record.id).unwrap().name, "shared");

        // Sanity: WITHOUT the shared key, a third vault cannot decrypt the same bytes.
        let c = Storage::create(&dir.path().join("c"), "passwordC", Argon2Params::TESTING).unwrap();
        c.apply_replicated_record("keys", &hex::encode(record.id), &encrypted, 1)
            .unwrap();
        assert!(c.load_key(&record.id).is_err());
    }

    #[test]
    fn state_publisher_fires_on_key_writes() {
        use crate::backend::MemoryBackend;

        let dir = tempdir().unwrap();
        let path = dir.path().join("test-publish");
        let backend = Box::new(MemoryBackend::new());
        let storage =
            Storage::create_with_backend(&path, "password", Argon2Params::TESTING, backend)
                .unwrap();

        let publisher = std::sync::Arc::new(RecordingPublisher::default());
        storage.set_state_publisher(publisher.clone());

        let record = KeyRecord::new(
            crypto::random_bytes(),
            crate::keys::KeyType::Nostr,
            "k".into(),
            vec![1, 2, 3],
        );
        storage.store_key(&record).unwrap();
        storage.delete_key(&record.id).unwrap();

        // The write hook fires with the record's table + hex id; the encrypted-bytes payload is the
        // same bytes stored (asserted non-empty). Shares are intentionally NOT hooked (per-node, per
        // the qmc design), which is enforced by construction: store_share carries no notify call.
        let records = publisher.records.lock().unwrap();
        let deletes = publisher.deletes.lock().unwrap();
        assert_eq!(*records, vec![("keys".to_string(), hex::encode(record.id))]);
        assert_eq!(*deletes, vec![("keys".to_string(), hex::encode(record.id))]);
    }

    #[test]
    fn test_header_rejects_malicious_argon2_params() {
        let valid_header = Header::new(Argon2Params::TESTING).unwrap();
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

    #[test]
    fn proxy_config_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-keep");
        let storage = Storage::create(&path, "testpassword", Default::default()).unwrap();

        let config = ProxyConfig {
            enabled: true,
            port: 9051,
        };
        storage.set_proxy_config(&config).unwrap();
        let loaded = storage.get_proxy_config().unwrap();
        assert!(loaded.enabled);
        assert_eq!(loaded.port, 9051);
    }

    #[test]
    fn proxy_config_default_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-keep");
        let storage = Storage::create(&path, "testpassword", Default::default()).unwrap();

        let loaded = storage.get_proxy_config().unwrap();
        assert!(!loaded.enabled);
        assert_eq!(loaded.port, 9050);
    }

    #[test]
    fn relay_config_bunker_relays_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-keep");
        let storage = Storage::create(&path, "testpassword", Default::default()).unwrap();

        let key = [1u8; 32];
        let mut config = RelayConfig::new(key);
        config.bunker_relays = vec!["wss://relay.nsec.app/".into()];
        storage.store_relay_config(&config).unwrap();

        let loaded = storage.get_relay_config(&key).unwrap().unwrap();
        assert_eq!(loaded.bunker_relays, vec!["wss://relay.nsec.app/"]);
    }

    #[test]
    fn relay_config_bunker_relays_backward_compat() {
        let json = r#"{"group_pubkey":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"frost_relays":[],"profile_relays":[]}"#;
        let config: RelayConfig = serde_json::from_str(json).unwrap();
        assert!(config.bunker_relays.is_empty());
    }

    #[test]
    fn relay_config_peer_policies_backward_compat() {
        let json = r#"{"group_pubkey":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"frost_relays":[],"profile_relays":[]}"#;
        let config: RelayConfig = serde_json::from_str(json).unwrap();
        assert!(config.peer_policies.is_empty());
    }

    #[test]
    fn relay_config_peer_policies_roundtrip() {
        use crate::relay::PeerPolicyEntry;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-keep");
        let storage = Storage::create(&path, "testpassword", Default::default()).unwrap();

        let mut config = RelayConfig::new([2u8; 32]);
        config.peer_policies.push(PeerPolicyEntry {
            pubkey_hex: "ab".repeat(32),
            allow_send: false,
            allow_receive: true,
        });
        storage.store_relay_config(&config).unwrap();

        let loaded = storage.get_relay_config(&[2u8; 32]).unwrap().unwrap();
        assert_eq!(loaded.peer_policies.len(), 1);
        assert_eq!(loaded.peer_policies[0].pubkey_hex, "ab".repeat(32));
        assert!(!loaded.peer_policies[0].allow_send);
        assert!(loaded.peer_policies[0].allow_receive);
    }

    #[test]
    fn global_relay_key_sentinel() {
        use crate::relay::GLOBAL_RELAY_KEY;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-keep");
        let storage = Storage::create(&path, "testpassword", Default::default()).unwrap();

        let global = RelayConfig::new_global();
        storage.store_relay_config(&global).unwrap();

        let loaded = storage
            .get_relay_config(&GLOBAL_RELAY_KEY)
            .unwrap()
            .unwrap();
        assert!(!loaded.frost_relays.is_empty());
        assert_eq!(loaded.group_pubkey, GLOBAL_RELAY_KEY);
    }
}
