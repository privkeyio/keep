// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Portable encrypted vault backup and restore.

use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
pub fn create_backup_from_data(
    keys: Vec<BackupKey>,
    shares: Vec<BackupShare>,
    wallet_descriptors: Vec<WalletDescriptor>,
    relay_configs: Vec<RelayConfig>,
    health_statuses: Vec<KeyHealthStatus>,
    config: BackupConfig,
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
        let encrypted = EncryptedData::from_bytes(&share.encrypted_key_package)?;
        let decrypted = crypto::decrypt(&encrypted, &data_key)?;
        let key_package_bytes = decrypted.as_slice()?;
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
            key_package: hex::encode(key_package_bytes.as_slice()),
            pubkey_package: hex::encode(&share.pubkey_package),
        });
    }

    let descriptors = keep.list_wallet_descriptors()?;
    let relay_configs = keep.list_relay_configs()?;
    let health_statuses = keep.list_health_statuses()?;
    let kill_switch = keep.get_kill_switch()?;
    let proxy = keep.get_proxy_config()?;

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
        let encrypted = crypto::encrypt(&key_package_bytes, &data_key)?;

        let pubkey_package = hex::decode(&bs.pubkey_package)
            .map_err(|e| KeepError::Other(format!("hex decode pubkey_package: {e}")))?;

        let group_pubkey = decode_hex_32(&bs.group_pubkey, "group pubkey")?;

        let share = StoredShare {
            metadata: crate::frost::ShareMetadata {
                identifier: bs.identifier,
                threshold: bs.threshold,
                total_shares: bs.total_shares,
                group_pubkey,
                name: bs.name.clone(),
                created_at: bs.created_at,
                last_used: bs.last_used,
                sign_count: bs.sign_count,
                did_backup: bs.did_backup,
            },
            encrypted_key_package: encrypted.to_bytes(),
            pubkey_package,
        };
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
}
