// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Portable encrypted vault backup and restore.

use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::audit::{AuditEntry, AuditLog};
use crate::crypto::{self, Argon2Params, EncryptedData, NONCE_SIZE, SALT_SIZE};
use crate::entropy;
use crate::error::{KeepError, Result};
use crate::frost::StoredShare;
use crate::keys::{KeyRecord, KeyType};
use crate::relay::RelayConfig;
use crate::storage::ProxyConfig;
use crate::wallet::{KeyHealthStatus, WalletDescriptor};
use crate::Keep;

fn decode_hex_32(hex_str: &str, label: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(hex_str).map_err(|e| KeepError::Other(format!("hex decode {label}: {e}")))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        KeepError::InvalidInput(format!(
            "invalid {label} length: {} (expected 32)",
            bytes.len()
        ))
    })
}

const MAGIC: &[u8; 8] = b"KEEPBACK";
const VERSION: u16 = 1;
const HEADER_SIZE: usize = 224;
/// Minimum passphrase length for backup encryption.
pub const MIN_PASSPHRASE_LEN: usize = 8;

/// Maximum backup file size (64 MiB).
pub const MAX_BACKUP_SIZE: usize = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct VaultBackup {
    version: u16,
    created_at: String,
    keys: Vec<BackupKey>,
    shares: Vec<BackupShare>,
    wallet_descriptors: Vec<WalletDescriptor>,
    relay_configs: Vec<RelayConfig>,
    health_statuses: Vec<KeyHealthStatus>,
    config: BackupConfig,
    /// Decrypted audit entries from the source vault. Re-encrypted under
    /// the restored vault's new data key on restore; the hash chain is
    /// re-derived from a fresh root, so individual entry hashes will
    /// differ from the source but the timeline of events is preserved.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    audit_entries: Vec<AuditEntry>,
}

/// A key entry in a backup file.
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct BackupKey {
    /// Hex-encoded public key.
    pub pubkey: String,
    /// Key type string (e.g. "Nostr", "Bitcoin").
    pub key_type: String,
    /// Human-readable name.
    pub name: String,
    /// Unix timestamp when the key was created.
    pub created_at: i64,
    /// Unix timestamp when the key was last used.
    pub last_used: Option<i64>,
    /// Number of signatures produced.
    pub sign_count: u64,
    /// Hex-encoded secret key bytes.
    pub secret: String,
}

/// A FROST share entry in a backup file.
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct BackupShare {
    /// Share identifier index.
    pub identifier: u16,
    /// Signing threshold.
    pub threshold: u16,
    /// Total number of shares.
    pub total_shares: u16,
    /// Hex-encoded group public key.
    pub group_pubkey: String,
    /// Human-readable name.
    pub name: String,
    /// Unix timestamp when the share was created.
    pub created_at: i64,
    /// Unix timestamp when the share was last used.
    pub last_used: Option<i64>,
    /// Number of signatures produced.
    pub sign_count: u64,
    /// Whether this share has been backed up.
    #[serde(default)]
    pub did_backup: bool,
    /// Hex-encoded serialized key package.
    pub key_package: String,
    /// Hex-encoded serialized public key package.
    pub pubkey_package: String,
    /// FROST ciphersuite of this share.
    ///
    /// Defaults to `Secp256k1Tr` so backups written before this field existed
    /// restore unchanged.
    #[serde(default)]
    #[zeroize(skip)]
    pub ciphersuite: crate::frost::Ciphersuite,
}

/// Configuration stored in a backup file.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BackupConfig {
    /// Whether the kill switch is enabled.
    pub kill_switch: bool,
    /// Optional proxy configuration.
    pub proxy: Option<ProxyConfig>,
}

impl std::fmt::Debug for BackupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupKey")
            .field("pubkey", &self.pubkey)
            .field("key_type", &self.key_type)
            .field("name", &self.name)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for BackupShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupShare")
            .field("identifier", &self.identifier)
            .field("group_pubkey", &self.group_pubkey)
            .field("name", &self.name)
            .field("key_package", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Summary information about a backup file.
#[derive(Debug, Clone)]
pub struct BackupInfo {
    /// Number of keys in the backup.
    pub key_count: usize,
    /// Number of FROST shares in the backup.
    pub share_count: usize,
    /// Number of wallet descriptors in the backup.
    pub descriptor_count: usize,
    /// ISO-8601 timestamp when the backup was created.
    pub created_at: String,
    /// Size of the backup file in bytes.
    pub file_size: usize,
}

/// Decrypted backup data with all vault contents.
pub struct DecryptedBackup {
    /// Standalone keys.
    pub keys: Vec<BackupKey>,
    /// FROST shares.
    pub shares: Vec<BackupShare>,
    /// Wallet descriptors.
    pub wallet_descriptors: Vec<WalletDescriptor>,
    /// Relay configurations.
    pub relay_configs: Vec<RelayConfig>,
    /// Key health statuses.
    pub health_statuses: Vec<KeyHealthStatus>,
    /// Backup configuration (kill switch, proxy).
    pub config: BackupConfig,
    /// Decrypted audit entries from the source vault.
    pub audit_entries: Vec<AuditEntry>,
    /// ISO-8601 timestamp when the backup was created.
    pub created_at: String,
}

impl Drop for DecryptedBackup {
    fn drop(&mut self) {
        self.keys.zeroize();
        self.shares.zeroize();
    }
}

fn key_type_to_string(kt: &KeyType) -> String {
    match kt {
        KeyType::Nostr => "Nostr".into(),
        KeyType::Bitcoin => "Bitcoin".into(),
        KeyType::FrostShare => "FrostShare".into(),
    }
}

fn string_to_key_type(s: &str) -> Result<KeyType> {
    match s {
        "Nostr" => Ok(KeyType::Nostr),
        "Bitcoin" => Ok(KeyType::Bitcoin),
        "FrostShare" => Ok(KeyType::FrostShare),
        other => Err(KeepError::InvalidInput(format!(
            "unknown key type: {other}"
        ))),
    }
}

/// Create an encrypted backup from pre-gathered data.
#[allow(clippy::too_many_arguments)]
pub fn create_backup_from_data(
    keys: Vec<BackupKey>,
    shares: Vec<BackupShare>,
    wallet_descriptors: Vec<WalletDescriptor>,
    relay_configs: Vec<RelayConfig>,
    health_statuses: Vec<KeyHealthStatus>,
    config: BackupConfig,
    audit_entries: Vec<AuditEntry>,
    passphrase: &str,
) -> Result<Vec<u8>> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(KeepError::InvalidInput(format!(
            "passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
        )));
    }

    let backup = VaultBackup {
        version: VERSION,
        created_at: chrono::Utc::now().to_rfc3339(),
        keys,
        shares,
        wallet_descriptors,
        relay_configs,
        health_statuses,
        config,
        audit_entries,
    };

    let mut json_bytes = serde_json::to_vec(&backup)
        .map_err(|e| KeepError::Other(format!("backup serialization failed: {e}")))?;

    let salt: [u8; SALT_SIZE] = entropy::random_bytes();
    let params = Argon2Params::DEFAULT;
    let key = crypto::derive_key(passphrase.as_bytes(), &salt, params)?;
    let encrypted = crypto::encrypt(&json_bytes, &key)?;
    json_bytes.zeroize();

    let mut output = Vec::with_capacity(HEADER_SIZE + encrypted.to_bytes().len());

    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&VERSION.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&params.memory_kib.to_le_bytes());
    output.extend_from_slice(&params.iterations.to_le_bytes());
    output.extend_from_slice(&params.parallelism.to_le_bytes());
    output.extend_from_slice(&encrypted.nonce);
    output.extend_from_slice(&[0u8; 32]);
    output.extend_from_slice(&[0u8; 112]);

    output.extend_from_slice(&encrypted.ciphertext);

    Ok(output)
}

/// Create an encrypted backup of all vault data.
pub fn create_backup(keep: &Keep, passphrase: &str) -> Result<Vec<u8>> {
    if !keep.is_unlocked() {
        return Err(KeepError::Locked);
    }

    let data_key = keep.data_key()?;

    let key_records = keep.list_keys()?;
    let mut backup_keys = Vec::with_capacity(key_records.len());
    for record in &key_records {
        let encrypted = EncryptedData::from_bytes(&record.encrypted_secret)?;
        let decrypted = crypto::decrypt(&encrypted, &data_key)?;
        let secret_bytes = decrypted.as_slice()?;
        backup_keys.push(BackupKey {
            pubkey: hex::encode(record.pubkey),
            key_type: key_type_to_string(&record.key_type),
            name: record.name.clone(),
            created_at: record.created_at,
            last_used: record.last_used,
            sign_count: record.sign_count,
            secret: hex::encode(secret_bytes.as_slice()),
        });
    }

    let stored_shares = keep.frost_list_shares()?;
    let mut backup_shares = Vec::with_capacity(stored_shares.len());
    for share in &stored_shares {
        let decrypted = share.decrypt(&data_key)?;
        backup_shares.push(BackupShare {
            identifier: share.metadata.identifier,
            threshold: share.metadata.threshold,
            total_shares: share.metadata.total_shares,
            group_pubkey: hex::encode(share.metadata.group_pubkey),
            name: share.metadata.name.clone(),
            created_at: share.metadata.created_at,
            last_used: share.metadata.last_used,
            sign_count: share.metadata.sign_count,
            did_backup: share.metadata.did_backup,
            key_package: hex::encode(decrypted.key_package_bytes()),
            pubkey_package: hex::encode(&share.pubkey_package),
            ciphersuite: share.ciphersuite,
        });
    }

    let descriptors = keep.list_all_wallet_descriptor_versions()?;
    let relay_configs = keep.list_relay_configs()?;
    let health_statuses = keep.list_health_statuses()?;
    let kill_switch = keep.get_kill_switch()?;
    let proxy = keep.get_proxy_config()?;
    let audit_entries = keep.read_audit_entries()?;

    create_backup_from_data(
        backup_keys,
        backup_shares,
        descriptors,
        relay_configs,
        health_statuses,
        BackupConfig {
            kill_switch,
            proxy: if proxy.enabled { Some(proxy) } else { None },
        },
        audit_entries,
        passphrase,
    )
}

struct ParsedHeader {
    salt: [u8; SALT_SIZE],
    params: Argon2Params,
    nonce: [u8; NONCE_SIZE],
}

fn parse_header(data: &[u8]) -> Result<ParsedHeader> {
    if data.len() < HEADER_SIZE {
        return Err(KeepError::InvalidInput("backup file too small".into()));
    }
    if data.len() > MAX_BACKUP_SIZE {
        return Err(KeepError::InvalidInput(format!(
            "backup file too large ({} bytes, max {MAX_BACKUP_SIZE})",
            data.len()
        )));
    }

    if &data[0..8] != MAGIC {
        return Err(KeepError::InvalidInput("invalid backup file magic".into()));
    }

    let version = u16::from_le_bytes([data[8], data[9]]);
    if version != VERSION {
        return Err(KeepError::InvalidInput(format!(
            "unsupported backup version: {version}"
        )));
    }

    let flags = u16::from_le_bytes([data[10], data[11]]);
    if flags != 0 {
        return Err(KeepError::InvalidInput(format!(
            "unsupported backup flags: {flags}"
        )));
    }

    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&data[12..44]);

    let le32 = |offset: usize| -> Result<u32> {
        let slice = data
            .get(offset..offset + 4)
            .ok_or_else(|| KeepError::InvalidInput("backup header truncated".into()))?;
        Ok(u32::from_le_bytes(slice.try_into().unwrap()))
    };
    let memory_kib = le32(44)?;
    let iterations = le32(48)?;
    let parallelism = le32(52)?;

    const MIN_MEMORY_KIB: u32 = 65_536; // 64 MiB
    const MAX_MEMORY_KIB: u32 = 256 * 1024; // 256 MiB
    const MIN_ITERATIONS: u32 = 2;
    const MAX_ITERATIONS: u32 = 64;
    const MAX_PARALLELISM: u32 = 16;
    if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory_kib) {
        return Err(KeepError::InvalidInput(format!(
            "backup argon2 memory out of range: {memory_kib} KiB (min {MIN_MEMORY_KIB}, max {MAX_MEMORY_KIB})"
        )));
    }
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        return Err(KeepError::InvalidInput(format!(
            "backup argon2 iterations out of range: {iterations} (min {MIN_ITERATIONS}, max {MAX_ITERATIONS})"
        )));
    }
    if parallelism == 0 || parallelism > MAX_PARALLELISM {
        return Err(KeepError::InvalidInput(format!(
            "backup argon2 parallelism out of range: {parallelism}"
        )));
    }

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&data[56..80]);

    Ok(ParsedHeader {
        salt,
        params: Argon2Params {
            memory_kib,
            iterations,
            parallelism,
        },
        nonce,
    })
}

/// Decrypt a backup file and return its contents.
pub fn decrypt_backup(data: &[u8], passphrase: &str) -> Result<DecryptedBackup> {
    let header = parse_header(data)?;
    let key = crypto::derive_key(passphrase.as_bytes(), &header.salt, header.params)?;

    let encrypted = EncryptedData {
        nonce: header.nonce,
        ciphertext: data[HEADER_SIZE..].to_vec(),
    };

    let decrypted = crypto::decrypt(&encrypted, &key)?;
    let json_bytes = decrypted.as_slice()?;

    let vault: VaultBackup = serde_json::from_slice(json_bytes.as_ref())
        .map_err(|e| KeepError::Other(format!("backup deserialization failed: {e}")))?;

    Ok(DecryptedBackup {
        keys: vault.keys,
        shares: vault.shares,
        wallet_descriptors: vault.wallet_descriptors,
        relay_configs: vault.relay_configs,
        health_statuses: vault.health_statuses,
        config: vault.config,
        audit_entries: vault.audit_entries,
        created_at: vault.created_at,
    })
}

/// Verify a backup file and return summary information.
pub fn verify_backup(data: &[u8], passphrase: &str) -> Result<BackupInfo> {
    let file_size = data.len();
    let decrypted = decrypt_backup(data, passphrase)?;
    Ok(BackupInfo {
        key_count: decrypted.keys.len(),
        share_count: decrypted.shares.len(),
        descriptor_count: decrypted.wallet_descriptors.len(),
        created_at: decrypted.created_at.clone(),
        file_size,
    })
}

fn restore_to_path(backup: &DecryptedBackup, path: &Path, vault_password: &str) -> Result<()> {
    let keep = Keep::create(path, vault_password)?;
    let data_key = keep.data_key()?;

    for bk in &backup.keys {
        let secret = decode_hex_32(&bk.secret, "secret")?;
        let encrypted = crypto::encrypt(&secret, &data_key)?;
        let pubkey = decode_hex_32(&bk.pubkey, "pubkey")?;

        let record = KeyRecord {
            id: crypto::blake2b_256(&pubkey),
            pubkey,
            key_type: string_to_key_type(&bk.key_type)?,
            name: bk.name.clone(),
            created_at: bk.created_at,
            last_used: bk.last_used,
            sign_count: bk.sign_count,
            encrypted_secret: encrypted.to_bytes(),
        };
        keep.restore_key_record(&record)?;
    }

    for bs in &backup.shares {
        let key_package_bytes = hex::decode(&bs.key_package)
            .map_err(|e| KeepError::Other(format!("hex decode key_package: {e}")))?;

        let pubkey_package = hex::decode(&bs.pubkey_package)
            .map_err(|e| KeepError::Other(format!("hex decode pubkey_package: {e}")))?;

        let group_pubkey = decode_hex_32(&bs.group_pubkey, "group pubkey")?;

        let metadata = crate::frost::ShareMetadata {
            identifier: bs.identifier,
            threshold: bs.threshold,
            total_shares: bs.total_shares,
            group_pubkey,
            name: bs.name.clone(),
            created_at: bs.created_at,
            last_used: bs.last_used,
            sign_count: bs.sign_count,
            did_backup: bs.did_backup,
        };
        let package =
            crate::frost::SharePackage::from_bytes(metadata, key_package_bytes, pubkey_package);
        let share = StoredShare::encrypt_with_ciphersuite(&package, bs.ciphersuite, &data_key)?;
        keep.restore_stored_share(&share)?;
    }

    for d in &backup.wallet_descriptors {
        keep.store_wallet_descriptor(d)?;
    }

    for c in &backup.relay_configs {
        keep.store_relay_config(c)?;
    }

    for h in &backup.health_statuses {
        keep.store_health_status(h)?;
    }

    keep.set_kill_switch(backup.config.kill_switch)?;
    if let Some(proxy) = &backup.config.proxy {
        keep.set_proxy_config(proxy)?;
    }

    if !backup.audit_entries.is_empty() {
        let data_key = keep.data_key()?;
        let mut audit = AuditLog::open(path, &data_key)?;
        for entry in &backup.audit_entries {
            audit.log(entry.clone(), &data_key)?;
        }
    }

    drop(keep);
    Ok(())
}

/// Restore a backup to a new vault at the target path.
pub fn restore_backup(
    data: &[u8],
    passphrase: &str,
    target: &Path,
    vault_password: &str,
) -> Result<BackupInfo> {
    let backup = decrypt_backup(data, passphrase)?;

    let info = BackupInfo {
        key_count: backup.keys.len(),
        share_count: backup.shares.len(),
        descriptor_count: backup.wallet_descriptors.len(),
        created_at: backup.created_at.clone(),
        file_size: data.len(),
    };

    if target.exists() {
        return Err(KeepError::AlreadyExists(target.display().to_string()));
    }

    let rand_suffix: [u8; 8] = entropy::random_bytes();
    let temp_name = format!(
        "{}.restore-{}",
        target
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| "vault".into()),
        hex::encode(rand_suffix)
    );
    let temp_target = target.with_file_name(temp_name);

    if let Err(e) = restore_to_path(&backup, &temp_target, vault_password) {
        let _ = std::fs::remove_dir_all(&temp_target);
        return Err(e);
    }

    std::fs::rename(&temp_target, target).map_err(|e| {
        let _ = std::fs::remove_dir_all(&temp_target);
        KeepError::Other(format!("failed to finalize restore: {e}"))
    })?;

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2Params;
    use tempfile::tempdir;

    fn create_test_keep(path: &Path) -> Keep {
        Keep::create_with_params(path, "test-password-123", Argon2Params::TESTING)
            .expect("create keep")
    }

    #[test]
    fn test_backup_roundtrip() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("source");
        let mut keep = create_test_keep(&vault_path);
        keep.generate_key("test-key").expect("generate key");

        let backup_data = create_backup(&keep, "backup-passphrase-ok").unwrap();
        assert!(backup_data.len() > HEADER_SIZE);

        let info = verify_backup(&backup_data, "backup-passphrase-ok").unwrap();
        assert_eq!(info.key_count, 1);
        assert_eq!(info.share_count, 0);
        assert_eq!(info.descriptor_count, 0);

        let restore_path = dir.path().join("restored");
        let info = restore_backup(
            &backup_data,
            "backup-passphrase-ok",
            &restore_path,
            "new-password-123",
        )
        .unwrap();
        assert_eq!(info.key_count, 1);

        let mut restored = Keep::open(&restore_path).unwrap();
        restored.unlock("new-password-123").unwrap();
        let keys = restored.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "test-key");
    }

    #[test]
    fn test_wrong_passphrase() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("source");
        let keep = create_test_keep(&vault_path);

        let backup_data = create_backup(&keep, "correct-passphrase").unwrap();
        let result = verify_backup(&backup_data, "wrong-passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_short_passphrase_rejected() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("source");
        let keep = create_test_keep(&vault_path);
        let result = create_backup(&keep, "short");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least"));
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = vec![0u8; HEADER_SIZE + 100];
        data[0..8].copy_from_slice(b"BADMAGIC");
        let result = verify_backup(&data, "any-pass");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("magic"));
    }

    #[test]
    fn test_audit_log_preserved_across_backup_restore() {
        // Backup must ship decrypted audit entries; restore must re-encrypt
        // them under the new vault's data key and emit a hash chain that
        // verifies cleanly. Without this, `audit list` / `audit verify` on a
        // restored vault sees zero history (the silent regression from #447).
        let dir = tempdir().unwrap();
        let src_path = dir.path().join("src");
        let mut keep = create_test_keep(&src_path);
        // `Keep::create_with_params` returns unlocked but with audit = None.
        // Call unlock so subsequent operations write audit entries (matches
        // the CLI flow which does Keep::open + unlock).
        keep.unlock("test-password-123").unwrap();
        keep.generate_key("k1").unwrap();
        keep.generate_key("k2").unwrap();

        let source_entries = keep.read_audit_entries().unwrap();
        let source_count = source_entries.len();
        assert!(source_count >= 2, "source audit must have entries");

        let backup_data = create_backup(&keep, "backup-passphrase-ok").unwrap();

        let dst_path = dir.path().join("dst");
        restore_backup(
            &backup_data,
            "backup-passphrase-ok",
            &dst_path,
            "new-password-456",
        )
        .unwrap();

        let mut restored = Keep::open(&dst_path).unwrap();
        restored.unlock("new-password-456").unwrap();
        let restored_entries = restored.read_audit_entries().unwrap();

        // Restored vault must contain at least every source entry, in source
        // order, before any post-restore entries the unlock above appended.
        assert!(
            restored_entries.len() >= source_count,
            "restored audit must include all source entries (have {}, want >= {})",
            restored_entries.len(),
            source_count
        );
        for (i, src) in source_entries.iter().enumerate() {
            let dst = &restored_entries[i];
            assert_eq!(dst.event_type, src.event_type, "entry {i} event_type");
            assert_eq!(dst.pubkey, src.pubkey, "entry {i} pubkey");
            assert_eq!(dst.timestamp, src.timestamp, "entry {i} timestamp");
        }
    }

    /// Pin that backup + restore preserves every stored row type — not just
    /// keys (already covered by `test_backup_roundtrip`). #437's acceptance
    /// criterion is "verify in-place migration succeeds without data loss",
    /// and the migration unit underneath restore is the whole vault. A future
    /// refactor that drops shares, descriptors, or relay configs from the
    /// backup envelope would have shipped past the existing tests.
    #[test]
    fn backup_roundtrip_preserves_shares_descriptors_and_relay_config() {
        use crate::relay::{
            RelayConfig, StoredBunkerPermission, StoredPermissionDuration, GLOBAL_RELAY_KEY,
        };
        use crate::wallet::{WalletDescriptor, INITIAL_DESCRIPTOR_VERSION};

        let dir = tempdir().unwrap();
        let src_path = dir.path().join("src");
        let mut keep = create_test_keep(&src_path);
        keep.unlock("test-password-123").unwrap();

        // Populate every row type the backup envelope ships.
        let key_pubkey = keep.generate_key("primary").unwrap();
        let shares = keep.frost_split("primary", 2, 3).unwrap();
        assert_eq!(shares.len(), 3, "split should produce 3 shares");
        let group_pubkey = shares[0].metadata.group_pubkey;

        let descriptor = WalletDescriptor {
            group_pubkey,
            external_descriptor: format!("tr({})/0/*)", hex::encode(group_pubkey)),
            internal_descriptor: format!("tr({})/1/*)", hex::encode(group_pubkey)),
            network: "signet".into(),
            created_at: 1_700_000_000,
            device_registrations: Vec::new(),
            policy_hash: [0x22; 32],
            version: INITIAL_DESCRIPTOR_VERSION,
            previous_descriptor_hash: None,
            policy: None,
        };
        keep.store_wallet_descriptor(&descriptor).unwrap();

        let mut relay_cfg = RelayConfig::with_defaults(GLOBAL_RELAY_KEY);
        relay_cfg.bunker_permissions.push(StoredBunkerPermission {
            pubkey_hex: "a".repeat(64),
            name: "test-app".to_string(),
            permissions: 0b1111,
            auto_approve_kinds: vec![1, 7],
            duration: StoredPermissionDuration::Forever,
            connected_at: 1_700_000_000,
            timed_kind_grants: Vec::new(),
        });
        relay_cfg.auto_approve_kinds = vec![22242];
        keep.store_relay_config(&relay_cfg).unwrap();

        let backup_data = create_backup(&keep, "backup-passphrase-ok").unwrap();

        let dst_path = dir.path().join("dst");
        let info = restore_backup(
            &backup_data,
            "backup-passphrase-ok",
            &dst_path,
            "new-password-456",
        )
        .unwrap();
        assert_eq!(info.key_count, 1);
        assert_eq!(info.share_count, 3);
        assert_eq!(info.descriptor_count, 1);

        let mut restored = Keep::open(&dst_path).unwrap();
        restored.unlock("new-password-456").unwrap();

        // Key survived (already covered by test_backup_roundtrip but pin
        // alongside the new assertions so a failure localizes here).
        let keys = restored.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "primary");
        assert_eq!(keys[0].pubkey, key_pubkey);

        // All three shares survived with intact metadata.
        let restored_shares = restored.frost_list_shares().unwrap();
        assert_eq!(restored_shares.len(), 3);
        for share in &restored_shares {
            assert_eq!(share.metadata.group_pubkey, group_pubkey);
            assert_eq!(share.metadata.threshold, 2);
            assert_eq!(share.metadata.total_shares, 3);
        }

        // Descriptor survived with the same canonical hash.
        let restored_descs = restored.list_wallet_descriptors().unwrap();
        assert_eq!(restored_descs.len(), 1);
        assert_eq!(
            restored_descs[0].canonical_hash(),
            descriptor.canonical_hash(),
            "descriptor canonical hash must survive restore"
        );

        // Relay config + bunker grants survived (without this, every NIP-46
        // pre-grant would silently vanish on restore).
        let restored_cfg = restored
            .get_relay_config(&GLOBAL_RELAY_KEY)
            .unwrap()
            .expect("relay config must survive restore");
        assert_eq!(restored_cfg.bunker_permissions.len(), 1);
        assert_eq!(restored_cfg.bunker_permissions[0].name, "test-app");
        assert_eq!(restored_cfg.auto_approve_kinds, vec![22242]);
    }
}
