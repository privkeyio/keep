// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use bincode::Options;
use fs2::FileExt;
use subtle::ConstantTimeEq;
use tracing::warn;
use zeroize::Zeroizing;

use crate::backend::{
    RedbBackend, StorageBackend, DESCRIPTORS_TABLE, KEYS_TABLE, RELAY_CONFIGS_TABLE, SHARES_TABLE,
};
use crate::crypto::{self, EncryptedData, SecretKey};
use crate::error::{KeepError, Result};
use crate::frost::StoredShare;
use crate::keys::KeyRecord;
use crate::relay::RelayConfig;
use crate::storage::{
    bincode_options, descriptor_storage_key, deserialize_stored_share, serialize_stored_share,
    share_id, validate_new_password, Header, Storage,
};
use crate::wallet::WalletDescriptor;

fn secure_delete(path: &Path) -> std::io::Result<()> {
    if let Ok(metadata) = fs::metadata(path) {
        if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
            const CHUNK: usize = 8 * 1024;
            let zeros = [0u8; CHUNK];
            let mut remaining = metadata.len();
            if file.seek(SeekFrom::Start(0)).is_ok() {
                while remaining > 0 {
                    let to_write = std::cmp::min(CHUNK as u64, remaining) as usize;
                    if file.write_all(&zeros[..to_write]).is_err() {
                        break;
                    }
                    remaining -= to_write as u64;
                }
            }
            let _ = file.sync_all();
        }
    }
    fs::remove_file(path)
}

#[cfg(not(windows))]
fn fsync_dir(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("path has no parent directory"))?;
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
        validate_new_password(new_password)?;
        let lock = acquire_rotation_lock(&self.path)?;

        if !self.is_unlocked() {
            self.unlock(old_password)?;
        }

        let data_key = self.data_key.as_ref().ok_or(KeepError::Locked)?;
        let data_key_bytes = data_key.decrypt()?;

        // #581: verify `old_password` against the current header EVEN when the
        // vault is already unlocked. Without this check, anyone with access to
        // an unlocked Keep can re-wrap the data key under a new password
        // without knowing the prior credential, and the PasswordRotate audit
        // entry (#566) would attest a rotation that never proved knowledge of
        // `old_password`.
        self.verify_header_decryption(&self.header, old_password, &*data_key_bytes)?;
        let old_header = self.header.clone();
        let header_path = self.path.join("keep.hdr");
        let backup_path = self.path.join("keep.hdr.backup");

        copy_with_retry(&header_path, &backup_path)?;

        let new_header = match self.create_header_with_key(new_password, data_key) {
            Ok(h) => h,
            Err(e) => {
                let _ = secure_delete(&backup_path);
                drop(lock);
                cleanup_rotation_lock(&self.path);
                return Err(e);
            }
        };
        if let Err(e) = write_header_atomically(&self.path, &new_header) {
            let _ = secure_delete(&backup_path);
            drop(lock);
            cleanup_rotation_lock(&self.path);
            return Err(e);
        }
        self.header = new_header.clone();

        if let Err(e) = self.verify_header_decryption(&new_header, new_password, &*data_key_bytes) {
            self.header = old_header;
            if let Err(restore_err) = copy_with_retry(&backup_path, &header_path) {
                warn!(error = %restore_err, "failed to restore backup during rollback - vault may be corrupted");
                drop(lock);
                return Err(KeepError::RotationFailed(format!(
                    "verification failed and backup restoration failed: {e} (restore error: {restore_err})"
                )));
            }
            let _ = secure_delete(&backup_path);
            drop(lock);
            return Err(KeepError::RotationFailed(format!(
                "verification failed: {e}"
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

        // #581: verify `password` against the current header even when the
        // vault is already unlocked; same threat model as `rotate_password`.
        {
            let data_key_bytes = old_data_key.decrypt()?;
            self.verify_header_decryption(&self.header, password, &*data_key_bytes)?;
        }
        let header_path = self.path.join("keep.hdr");
        let backup_path = self.path.join("keep.hdr.backup");
        let db_path = self.path.join("keep.db");
        let db_backup_path = self.path.join("keep.db.backup");

        let keys = self.list_keys()?;
        let shares = self.list_shares()?;
        let descriptors = self.list_all_descriptor_versions()?;
        // Migration v4->v5 rekeys every legacy 32-byte descriptor row to a
        // versioned 36-byte key, and `Storage::open` runs all pending
        // migrations before rotation can be invoked. Guard that invariant
        // here so the re-encrypt count equality below cannot be subverted by
        // any straggler legacy row that would otherwise be silently skipped
        // by versioned-key parsers post-rotation.
        {
            let backend = self.backend.as_ref().ok_or(KeepError::Locked)?;
            let all_keys = backend.list_keys_with_prefix(DESCRIPTORS_TABLE, &[])?;
            if let Some(bad) = all_keys.iter().find(|k| k.len() != 36) {
                return Err(KeepError::RotationFailed(format!(
                    "legacy descriptor row with key length {} remains pre-rotation; refusing to rotate",
                    bad.len()
                )));
            }
        }
        let relay_configs = self.list_relay_configs()?;

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
            self.reencrypt_database(
                &decrypted_keys,
                &decrypted_shares,
                &descriptors,
                &relay_configs,
                &new_data_key,
            )?;

            let new_header = self.create_header_with_key(password, &new_data_key)?;
            write_header_atomically(&self.path, &new_header)?;

            self.header = new_header;
            self.data_key = Some(new_data_key);

            self.verify_rotation_integrity(
                &decrypted_keys,
                &decrypted_shares,
                &descriptors,
                &relay_configs,
            )?;

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
            drop(lock);
            if header_err.is_some() || db_err.is_some() {
                return Err(KeepError::RotationFailed(format!(
                    "rotation failed and backup restoration failed: {e} (header: {header_err:?}, db: {db_err:?})"
                )));
            }
            if let Err(err) = secure_delete(&backup_path) {
                warn!(path = %backup_path.display(), error = %err, "failed to securely delete backup file after rotation failure");
            }
            if let Err(err) = secure_delete(&db_backup_path) {
                warn!(path = %db_backup_path.display(), error = %err, "failed to securely delete database backup after rotation failure");
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
    ) -> Result<Vec<(KeyRecord, Zeroizing<Vec<u8>>)>> {
        keys.iter()
            .map(|record| {
                let encrypted = EncryptedData::from_bytes(&record.encrypted_secret)?;
                let secret = crypto::decrypt(&encrypted, data_key)?;
                Ok((record.clone(), secret.as_slice()?))
            })
            .collect()
    }

    fn decrypt_all_shares(
        &self,
        shares: &[StoredShare],
        data_key: &SecretKey,
    ) -> Result<Vec<(StoredShare, Zeroizing<Vec<u8>>)>> {
        shares
            .iter()
            .map(|stored| {
                let encrypted = EncryptedData::from_bytes(&stored.encrypted_key_package)?;
                let key_package_bytes =
                    crypto::decrypt_with_aad(&encrypted, stored.ciphersuite.aad(), data_key)?;
                Ok((stored.clone(), key_package_bytes.as_slice()?))
            })
            .collect()
    }

    fn reencrypt_database(
        &self,
        keys: &[(KeyRecord, Zeroizing<Vec<u8>>)],
        shares: &[(StoredShare, Zeroizing<Vec<u8>>)],
        descriptors: &[WalletDescriptor],
        relay_configs: &[RelayConfig],
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
            let package = crate::frost::SharePackage::from_bytes(
                stored.metadata.clone(),
                key_package_bytes.to_vec(),
                stored.pubkey_package.clone(),
            );
            let new_stored =
                StoredShare::encrypt_with_ciphersuite(&package, stored.ciphersuite, new_data_key)?;
            let serialized = serialize_stored_share(&new_stored)?;
            let record_encrypted = crypto::encrypt(&serialized, new_data_key)?;
            let id = share_id(&stored.metadata.group_pubkey, stored.metadata.identifier);
            backend.put(SHARES_TABLE, &id, &record_encrypted.to_bytes())?;
        }

        for descriptor in descriptors {
            let serialized = serde_json::to_vec(descriptor)
                .map_err(|e| KeepError::Other(format!("json serialization failed: {e}")))?;
            let encrypted = crypto::encrypt(&serialized, new_data_key)?;
            let key = descriptor_storage_key(&descriptor.group_pubkey, descriptor.version);
            backend.put(DESCRIPTORS_TABLE, &key, &encrypted.to_bytes())?;
        }

        for config in relay_configs {
            let serialized = serde_json::to_vec(config)
                .map_err(|e| KeepError::Other(format!("json serialization failed: {e}")))?;
            let encrypted = crypto::encrypt(&serialized, new_data_key)?;
            backend.put(
                RELAY_CONFIGS_TABLE,
                &config.group_pubkey,
                &encrypted.to_bytes(),
            )?;
        }

        Ok(())
    }

    fn verify_rotation_integrity(
        &self,
        original_keys: &[(KeyRecord, Zeroizing<Vec<u8>>)],
        original_shares: &[(StoredShare, Zeroizing<Vec<u8>>)],
        original_descriptors: &[WalletDescriptor],
        original_relay_configs: &[RelayConfig],
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
            let stored: StoredShare = deserialize_stored_share(&decrypted_bytes)?;
            let inner_encrypted = EncryptedData::from_bytes(&stored.encrypted_key_package)?;
            let inner_decrypted =
                crypto::decrypt_with_aad(&inner_encrypted, stored.ciphersuite.aad(), data_key)?;
            let inner_bytes = inner_decrypted.as_slice()?;
            if !bool::from(inner_bytes.ct_eq(original_key_package.as_slice())) {
                return Err(KeepError::RotationFailed(format!(
                    "share {} content mismatch after rotation",
                    original_stored.metadata.identifier
                )));
            }
        }

        let stored_descriptors = backend.list(DESCRIPTORS_TABLE)?;
        if stored_descriptors.len() != original_descriptors.len() {
            return Err(KeepError::RotationFailed(format!(
                "descriptor count mismatch: expected {}, found {}",
                original_descriptors.len(),
                stored_descriptors.len()
            )));
        }

        for original in original_descriptors {
            let key = descriptor_storage_key(&original.group_pubkey, original.version);
            let encrypted_bytes = backend.get(DESCRIPTORS_TABLE, &key)?.ok_or_else(|| {
                KeepError::RotationFailed(format!(
                    "descriptor for group {} version {} missing after rotation",
                    hex::encode(original.group_pubkey),
                    original.version
                ))
            })?;
            let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
            let decrypted = crypto::decrypt(&encrypted, data_key)?;
            let decrypted_bytes = decrypted.as_slice()?;
            let descriptor: WalletDescriptor = serde_json::from_slice(&decrypted_bytes)
                .map_err(|e| KeepError::Other(format!("json deserialization failed: {e}")))?;
            if descriptor.group_pubkey != original.group_pubkey
                || descriptor.external_descriptor != original.external_descriptor
                || descriptor.internal_descriptor != original.internal_descriptor
                || descriptor.network != original.network
                || descriptor.created_at != original.created_at
                || descriptor.version != original.version
                || descriptor.previous_descriptor_hash != original.previous_descriptor_hash
                || descriptor.policy_hash != original.policy_hash
                || descriptor.device_registrations != original.device_registrations
            {
                return Err(KeepError::RotationFailed(format!(
                    "descriptor for group {} version {} content mismatch after rotation",
                    hex::encode(original.group_pubkey),
                    original.version
                )));
            }
        }

        let stored_relay_configs = backend.list(RELAY_CONFIGS_TABLE)?;
        if stored_relay_configs.len() != original_relay_configs.len() {
            return Err(KeepError::RotationFailed(format!(
                "relay config count mismatch: expected {}, found {}",
                original_relay_configs.len(),
                stored_relay_configs.len()
            )));
        }

        for original in original_relay_configs {
            let encrypted_bytes = backend
                .get(RELAY_CONFIGS_TABLE, &original.group_pubkey)?
                .ok_or_else(|| {
                    KeepError::RotationFailed(format!(
                        "relay config for group {} missing after rotation",
                        hex::encode(original.group_pubkey)
                    ))
                })?;
            let encrypted = EncryptedData::from_bytes(&encrypted_bytes)?;
            let decrypted = crypto::decrypt(&encrypted, data_key)?;
            let decrypted_bytes = decrypted.as_slice()?;
            let config: RelayConfig = serde_json::from_slice(&decrypted_bytes)
                .map_err(|e| KeepError::Other(format!("json deserialization failed: {e}")))?;
            if config.group_pubkey != original.group_pubkey
                || config.frost_relays != original.frost_relays
                || config.profile_relays != original.profile_relays
            {
                return Err(KeepError::RotationFailed(format!(
                    "relay config for group {} content mismatch after rotation",
                    hex::encode(original.group_pubkey)
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2Params;
    use tempfile::tempdir;

    #[test]
    fn test_rotate_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-rotate-pw");

        {
            let storage = Storage::create(&path, "oldpass1", Argon2Params::TESTING).unwrap();
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
            storage.rotate_password("oldpass1", "newpass1").unwrap();
        }

        {
            let mut storage = Storage::open(&path).unwrap();
            assert!(storage.unlock("oldpass1").is_err());
        }

        {
            let mut storage = Storage::open(&path).unwrap();
            storage.unlock("newpass1").unwrap();
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

    // === #438: security-critical rotation property coverage ===

    /// Create an empty vault under a fresh temp dir and return the temp dir
    /// (the caller must keep it alive) together with its path. Every #438
    /// rejection test starts from the same empty vault; the password stays an
    /// explicit argument so each test still shows what it unlocks with.
    fn create_empty_vault(password: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let _ = Storage::create(&path, password, Argon2Params::TESTING).unwrap();
        (dir, path)
    }

    /// `rotate_password` MUST reject a wrong old password without touching
    /// the header. A regression that accepts any input here would let
    /// anyone with file access change the password.
    #[test]
    fn test_rotate_password_rejects_wrong_old_password() {
        let (_dir, path) = create_empty_vault("correctpass");

        let mut storage = Storage::open(&path).unwrap();
        let err = storage
            .rotate_password("WRONG_OLD_PASSWORD", "newpass1")
            .expect_err("wrong old password must be rejected");
        // Wrong old password fails at the unlock step inside rotate_password.
        // Pin the variant so a regression that rejects for an unrelated reason
        // (IO, lock contention, a future pre-unlock validation) doesn't pass
        // this test while the auth gate silently degrades.
        assert!(
            matches!(err, KeepError::DecryptionFailed),
            "expected DecryptionFailed, got {err:?}"
        );

        // The original password must still unlock the vault unchanged.
        let mut storage = Storage::open(&path).unwrap();
        storage
            .unlock("correctpass")
            .expect("original password must still work after failed rotation");
    }

    /// `rotate_password` MUST reject a new password that fails
    /// `validate_new_password` (too short). Without this, a rotation
    /// would silently weaken the vault to an empty-or-tiny password
    /// despite the create-time gate.
    #[test]
    fn test_rotate_password_rejects_short_new_password() {
        let (_dir, path) = create_empty_vault("validpass1");

        let mut storage = Storage::open(&path).unwrap();
        let err = storage
            .rotate_password("validpass1", "")
            .expect_err("empty new password must be refused");
        assert!(
            matches!(err, KeepError::InvalidInput(_)),
            "expected InvalidInput, got {err:?}"
        );

        let mut storage = Storage::open(&path).unwrap();
        let err = storage
            .rotate_password("validpass1", "a")
            .expect_err("too-short new password must be refused");
        assert!(
            matches!(err, KeepError::InvalidInput(_)),
            "expected InvalidInput, got {err:?}"
        );

        // Original password still works.
        let mut storage = Storage::open(&path).unwrap();
        storage.unlock("validpass1").unwrap();
    }

    /// `rotate_password` re-wraps the same data encryption key under the new
    /// password; it does not change the DEK or re-encrypt stored keys. This
    /// test confirms the DEK survives that re-wrap intact, so a stored secret
    /// still decrypts to the exact pre-rotation bytes under the new password.
    /// A regression that corrupted or replaced the DEK during the re-wrap
    /// would surface here as a decrypt failure or byte mismatch.
    #[test]
    fn test_rotate_password_preserves_decrypted_secret_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-decrypt-after-pw");
        let original_secret: Vec<u8> = (0u8..32).collect();
        let pubkey: [u8; 32] = [0xAA; 32];

        {
            let storage = Storage::create(&path, "oldpass1", Argon2Params::TESTING).unwrap();
            let encrypted = crypto::encrypt(&original_secret, storage.data_key().unwrap()).unwrap();
            let record = KeyRecord::new(
                pubkey,
                crate::keys::KeyType::Nostr,
                "decrypt-survives".into(),
                encrypted.to_bytes(),
            );
            storage.store_key(&record).unwrap();
        }

        {
            let mut storage = Storage::open(&path).unwrap();
            storage.rotate_password("oldpass1", "newpass1").unwrap();
        }

        let mut storage = Storage::open(&path).unwrap();
        storage.unlock("newpass1").unwrap();
        let data_key = storage.data_key().expect("unlocked has data_key");
        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        let record = &keys[0];
        let encrypted =
            crypto::EncryptedData::from_bytes(&record.encrypted_secret).expect("decode encrypted");
        let decrypted = crypto::decrypt(&encrypted, data_key).expect("decrypt after rotation");
        let plaintext = decrypted.as_slice().expect("secret bytes");
        assert_eq!(
            plaintext.as_slice(),
            original_secret.as_slice(),
            "decrypted secret bytes MUST match the pre-rotation value"
        );
    }

    /// `rotate_data_key` MUST reject a wrong password. Without the gate,
    /// an attacker with file access could re-encrypt all stored secrets
    /// to a new key without ever proving they hold the password.
    #[test]
    fn test_rotate_data_key_rejects_wrong_password() {
        let (_dir, path) = create_empty_vault("correctpass");

        let mut storage = Storage::open(&path).unwrap();
        let err = storage
            .rotate_data_key("WRONG_PASSWORD")
            .expect_err("wrong password to rotate_data_key must be refused");
        assert!(
            matches!(err, KeepError::DecryptionFailed),
            "expected DecryptionFailed, got {err:?}"
        );

        // Original password still unlocks.
        let mut storage = Storage::open(&path).unwrap();
        storage
            .unlock("correctpass")
            .expect("original password must still work after failed dek rotation");
    }

    /// `rotate_data_key` generates a fresh data encryption key and re-encrypts
    /// every stored secret under it. Verify three properties: the decrypted
    /// bytes round-trip unchanged, the on-disk ciphertext changes, and the OLD
    /// data key can no longer decrypt the new ciphertext. That last check is
    /// the proactive-security property, and unlike the ciphertext-changed
    /// check it cannot be satisfied by a fresh nonce alone, so it actually
    /// proves the key rotated rather than merely being re-encrypted in place.
    #[test]
    fn test_rotate_data_key_preserves_decrypted_secret_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-decrypt-after-dek");
        let original_secret: Vec<u8> = (10u8..42).collect();
        let pubkey: [u8; 32] = [0xCC; 32];

        let pre_ciphertext;
        let old_data_key;
        {
            let storage = Storage::create(&path, "password", Argon2Params::TESTING).unwrap();
            // Capture the pre-rotation data key so we can later prove it no
            // longer decrypts the rotated ciphertext.
            old_data_key = storage.data_key().unwrap().clone();
            let encrypted = crypto::encrypt(&original_secret, storage.data_key().unwrap()).unwrap();
            pre_ciphertext = encrypted.to_bytes();
            let record = KeyRecord::new(
                pubkey,
                crate::keys::KeyType::Nostr,
                "dek-decrypt-survives".into(),
                pre_ciphertext.clone(),
            );
            storage.store_key(&record).unwrap();
        }

        {
            let mut storage = Storage::open(&path).unwrap();
            storage.rotate_data_key("password").unwrap();
        }

        let mut storage = Storage::open(&path).unwrap();
        storage.unlock("password").unwrap();
        let data_key = storage.data_key().expect("unlocked has data_key");
        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        let record = &keys[0];

        // Ciphertext on disk MUST differ from pre-rotation. (Necessary but not
        // sufficient: a fresh nonce alone would change it, hence the old-key
        // check below.)
        assert_ne!(
            record.encrypted_secret, pre_ciphertext,
            "ciphertext must change after data-key rotation"
        );

        let encrypted =
            crypto::EncryptedData::from_bytes(&record.encrypted_secret).expect("decode encrypted");

        // The data key MUST have actually rotated: the OLD key can no longer
        // decrypt the post-rotation ciphertext (AEAD tag check fails under the
        // wrong key). This is the real proactive-security property.
        assert!(
            crypto::decrypt(&encrypted, &old_data_key).is_err(),
            "SECURITY VIOLATION: old data key still decrypts post-rotation \
             ciphertext; the data key was not actually rotated"
        );

        // The new key decrypts to the identical plaintext.
        let decrypted = crypto::decrypt(&encrypted, data_key).expect("decrypt after rotation");
        let plaintext = decrypted.as_slice().expect("secret bytes");
        assert_eq!(
            plaintext.as_slice(),
            original_secret.as_slice(),
            "decrypted secret bytes MUST match the pre-rotation value"
        );
    }
}
