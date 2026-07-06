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

    // === #565: rotation crash-recovery / interleaving tests ===
    //
    // A real process kill during `rotate_password` or `rotate_data_key` can
    // only leave the vault in one of two durable states, plus some inert
    // crash-orphan files. `Storage::open` reads exactly `keep.hdr` and never
    // consults `keep.hdr.backup`, `keep.hdr.tmp`, or `keep.db.backup`, so:
    //
    //   * If the atomic `tmp` + rename of the new header never completed, the
    //     old header is intact and the OLD credential still unlocks.
    //   * Once the rename completed, the NEW credential unlocks.
    //
    // These tests reconstruct the on-disk artifacts each crash point would
    // leave behind and assert two properties: (1) the vault opens with exactly
    // the credential its durable state implies (never a half-rotated in-between,
    // never a leaked alternate credential from an orphan backup), and (2) a
    // crash-orphaned `.backup`/`.tmp` file is inert: it neither blocks open nor
    // wedges a subsequent rotation (whose own `File::create` / `copy_with_retry`
    // truncates the stale artifact).
    //
    // The one crash point `Storage::open` cannot make whole is a kill mid
    // `reencrypt_database` for `rotate_data_key`: rows are re-encrypted under
    // the new DEK while `keep.hdr` still pins the old DEK, and no auto-recovery
    // path exists today. `crash_mid_reencrypt_data_key_leaves_db_backup_intact`
    // pins that gap (fail-closed, `keep.db.backup` preserved) so a follow-up
    // that adds auto-recovery has a concrete test to move.

    fn seed_key(storage: &Storage) -> (KeyRecord, Vec<u8>) {
        let pubkey: [u8; 32] = [0x77; 32];
        let secret: Vec<u8> = (0u8..24).collect();
        let encrypted = crypto::encrypt(&secret, storage.data_key().unwrap()).unwrap();
        let record = KeyRecord::new(
            pubkey,
            crate::keys::KeyType::Nostr,
            "crash-recovery-seed".into(),
            encrypted.to_bytes(),
        );
        storage.store_key(&record).unwrap();
        (record, secret)
    }

    fn assert_secret_decrypts(storage: &Storage, expected: &[u8]) {
        let data_key = storage.data_key().expect("unlocked storage has data_key");
        let keys = storage.list_keys().expect("list keys post-crash");
        assert_eq!(keys.len(), 1, "seeded key must survive simulated crash");
        let encrypted = crypto::EncryptedData::from_bytes(&keys[0].encrypted_secret)
            .expect("encrypted secret parses");
        let decrypted = crypto::decrypt(&encrypted, data_key).expect("decrypt seeded key");
        let plaintext = decrypted.as_slice().expect("secret bytes");
        assert_eq!(plaintext.as_slice(), expected);
    }

    /// #565 C1: crash-orphan `keep.hdr.backup` from an aborted `rotate_password`
    /// (written by `copy_with_retry` before `write_header_atomically` ran). The
    /// header was never touched, so the OLD password must still unlock, the
    /// never-committed new password must NOT unlock, and the stale backup must
    /// neither block open nor wedge a later rotation.
    #[test]
    fn crash_after_hdr_backup_leaves_vault_openable_with_old_pw() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let old_pw = "old-password-1";
        let secret;
        {
            let storage = Storage::create(&path, old_pw, Argon2Params::TESTING).unwrap();
            let (_r, s) = seed_key(&storage);
            secret = s;
        }

        // Simulate the copy_with_retry(&header_path, &backup_path) step
        // completing right before `write_header_atomically` would begin.
        fs::copy(path.join("keep.hdr"), path.join("keep.hdr.backup")).unwrap();

        let mut storage = Storage::open(&path).expect("open with orphan .hdr.backup");
        storage.unlock(old_pw).expect("old password unlocks");
        assert_secret_decrypts(&storage, &secret);

        // A never-committed new password must not accidentally work.
        drop(storage);
        let mut storage = Storage::open(&path).unwrap();
        assert!(storage.unlock("new-password-1").is_err());

        // The stale backup must not wedge a fresh rotation: copy_with_retry
        // truncates keep.hdr.backup, so a real rotation over it commits cleanly.
        assert!(path.join("keep.hdr.backup").exists());
        let mut storage = Storage::open(&path).unwrap();
        storage
            .rotate_password(old_pw, "committed-new-1")
            .expect("rotation succeeds despite an orphan .hdr.backup");
        drop(storage);
        let mut storage = Storage::open(&path).unwrap();
        storage
            .unlock("committed-new-1")
            .expect("committed new password unlocks after rotation over orphan backup");
        assert_secret_decrypts(&storage, &secret);
    }

    /// #565 C2: crash inside `write_header_atomically` after the temp write but
    /// before the atomic rename. `keep.hdr` is untouched so the OLD password
    /// still unlocks, and the leftover `keep.hdr.tmp` is inert: it does not
    /// block open, and a later rotation (whose own `File::create` truncates the
    /// same tmp path) still succeeds.
    #[test]
    fn crash_between_tmp_write_and_rename_keeps_old_credential() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let old_pw = "old-password-2";
        let secret;
        {
            let storage = Storage::create(&path, old_pw, Argon2Params::TESTING).unwrap();
            let (_r, s) = seed_key(&storage);
            secret = s;
        }

        // Simulate: backup was made and a bogus (or partial) tmp header exists.
        fs::copy(path.join("keep.hdr"), path.join("keep.hdr.backup")).unwrap();
        fs::write(path.join("keep.hdr.tmp"), vec![0xFFu8; 32]).unwrap();

        let mut storage = Storage::open(&path).expect("open ignores .hdr.tmp");
        storage.unlock(old_pw).expect("old password still unlocks");
        assert_secret_decrypts(&storage, &secret);

        // The leftover tmp must not wedge a fresh rotation: write_header_atomically
        // truncates keep.hdr.tmp via File::create, so a real rotation over it works.
        assert!(path.join("keep.hdr.tmp").exists());
        drop(storage);
        let mut storage = Storage::open(&path).unwrap();
        storage
            .rotate_password(old_pw, "committed-new-2")
            .expect("rotation succeeds despite an orphan .hdr.tmp");
        drop(storage);
        let mut storage = Storage::open(&path).unwrap();
        storage
            .unlock("committed-new-2")
            .expect("committed new password unlocks after rotation over orphan tmp");
        assert_secret_decrypts(&storage, &secret);
    }

    /// #565 C3/C4: crash in `rotate_password` after the new header has been
    /// renamed into place but before `verify_header_decryption` or the backup
    /// cleanup runs. From the caller's perspective the rotation has completed
    /// durably: the NEW password MUST unlock the vault. The orphan
    /// `keep.hdr.backup` (holding the OLD header) must not prevent open or leak
    /// an alternative credential.
    #[test]
    fn crash_after_header_rename_completes_rotation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let old_pw = "old-password-3";
        let new_pw = "new-password-3";
        let secret;
        {
            let storage = Storage::create(&path, old_pw, Argon2Params::TESTING).unwrap();
            let (_r, s) = seed_key(&storage);
            secret = s;
        }

        // Snapshot the old header, run a full rotation, then reintroduce the
        // pre-rotation header as the orphan backup that a crash between the
        // rename and the backup-delete would leave behind.
        let old_hdr_bytes = fs::read(path.join("keep.hdr")).unwrap();
        {
            let mut storage = Storage::open(&path).unwrap();
            storage.rotate_password(old_pw, new_pw).unwrap();
        }
        fs::write(path.join("keep.hdr.backup"), &old_hdr_bytes).unwrap();

        let mut storage = Storage::open(&path).expect("open with orphan pre-rotate backup");
        storage
            .unlock(new_pw)
            .expect("new password unlocks after rename-completed rotation");
        assert_secret_decrypts(&storage, &secret);

        // The old password (present in the orphan backup) must NOT unlock:
        // `Storage::open` reads `keep.hdr`, not `keep.hdr.backup`.
        drop(storage);
        let mut storage = Storage::open(&path).unwrap();
        assert!(storage.unlock(old_pw).is_err());
    }

    /// #565 D1: crash-orphan `keep.hdr.backup` from an aborted `rotate_data_key`
    /// (written before `keep.db.backup`). Nothing was mutated, so the password
    /// still unlocks under the OLD DEK, and the stale backup must not wedge a
    /// later data-key rotation.
    #[test]
    fn crash_after_hdr_backup_but_before_db_backup_keeps_old_dek() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let pw = "same-password-4";
        let secret;
        {
            let storage = Storage::create(&path, pw, Argon2Params::TESTING).unwrap();
            let (_r, s) = seed_key(&storage);
            secret = s;
        }

        fs::copy(path.join("keep.hdr"), path.join("keep.hdr.backup")).unwrap();

        let mut storage = Storage::open(&path).unwrap();
        storage
            .unlock(pw)
            .expect("password unlocks pre-rotation vault");
        assert_secret_decrypts(&storage, &secret);

        // The stale header backup must not wedge a fresh data-key rotation:
        // copy_with_retry truncates keep.hdr.backup, so rotation over it works
        // and the seeded secret survives, re-encrypted under the new DEK.
        assert!(path.join("keep.hdr.backup").exists());
        storage
            .rotate_data_key(pw)
            .expect("data-key rotation succeeds despite an orphan .hdr.backup");
        assert_secret_decrypts(&storage, &secret);
    }

    /// #565 D2: the one crash point `Storage::open` cannot make whole. After a
    /// kill mid `reencrypt_database`, `keep.db` holds rows under the NEW DEK
    /// while `keep.hdr` still pins the OLD DEK. There is no in-process seam to
    /// stop `reencrypt_database` midway, so we reproduce the observable state
    /// after the fact: run a full rotation (every row now under the new DEK)
    /// and roll `keep.hdr` back to the old header. With a single seeded row
    /// this is indistinguishable from a genuine torn write. The vault opens and
    /// the header unlocks, but decrypting any row under the OLD DEK must fail
    /// closed (AEAD auth failure, no panic, no silent success), and the
    /// pristine `keep.db.backup` must remain on disk as the recovery input.
    ///
    /// This pins the fail-closed behavior and the surviving backup so a
    /// follow-up that adds auto-recovery on open (restore `keep.db.backup` ->
    /// `keep.db`) has a concrete test. Any such recovery must be gated on an
    /// explicit in-header "rotation in progress" marker, not mere `.backup`
    /// file presence, so a planted stale backup pair cannot force a downgrade.
    #[test]
    fn crash_mid_reencrypt_data_key_leaves_db_backup_intact() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let pw = "same-password-5";
        {
            let storage = Storage::create(&path, pw, Argon2Params::TESTING).unwrap();
            let _ = seed_key(&storage);
        }

        // Snapshot the pre-rotation DB and header, then perform a full
        // rotation so `keep.db` is under a new DEK. Reintroduce the
        // pre-rotation snapshots as the `.backup` artifacts a real crash
        // would have left behind, while `keep.hdr` is rolled back to OLD.
        // The result: header pins OLD DEK, DB rows are under NEW DEK, matching
        // the observable state of a kill partway through `reencrypt_database`.
        let old_hdr = fs::read(path.join("keep.hdr")).unwrap();
        let old_db = fs::read(path.join("keep.db")).unwrap();
        {
            let mut storage = Storage::open(&path).unwrap();
            storage.rotate_data_key(pw).unwrap();
        }
        // Roll the header back to old; leave the DB in its rotated state.
        fs::write(path.join("keep.hdr"), &old_hdr).unwrap();
        fs::write(path.join("keep.hdr.backup"), &old_hdr).unwrap();
        fs::write(path.join("keep.db.backup"), &old_db).unwrap();

        // The vault opens and the header unlocks, but any decryption under
        // the OLD DEK against a NEW-DEK row must fail cleanly (no panic, no
        // silent success). The `.backup` files are the recovery input.
        let mut storage = Storage::open(&path).expect("mid-reencrypt state opens");
        storage.unlock(pw).expect("header unlocks under pw");
        // list_keys attempts to decrypt every row under the old DEK; at least
        // one row was re-encrypted under the new DEK, so this must fail.
        let listed = storage.list_keys();
        assert!(
            listed.is_err(),
            "OLD-DEK header + NEW-DEK db must not silently list rows"
        );
        assert!(
            path.join("keep.db.backup").exists(),
            "backup DB must remain on disk as the recovery input"
        );
    }

    /// #565 D3: crash in `rotate_data_key` after the header rename but before
    /// `verify_rotation_integrity`. From the caller's perspective the rotation
    /// completed durably: the password unlocks the NEW header, the NEW DEK
    /// decrypts the DB rows, and the orphan `.backup` files (holding old-DEK
    /// snapshots) do not leak an alternative credential.
    #[test]
    fn crash_after_data_key_rotation_completes_before_backup_delete() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let pw = "same-password-6";
        let secret;
        {
            let storage = Storage::create(&path, pw, Argon2Params::TESTING).unwrap();
            let (_r, s) = seed_key(&storage);
            secret = s;
        }

        // Snapshot old header + db to place as the orphan `.backup` files
        // that a real crash-after-verify-before-delete would leave behind.
        let old_hdr = fs::read(path.join("keep.hdr")).unwrap();
        let old_db = fs::read(path.join("keep.db")).unwrap();

        {
            let mut storage = Storage::open(&path).unwrap();
            storage.rotate_data_key(pw).unwrap();
        }

        fs::write(path.join("keep.hdr.backup"), &old_hdr).unwrap();
        fs::write(path.join("keep.db.backup"), &old_db).unwrap();

        let mut storage = Storage::open(&path).expect("open with orphan .backup files");
        storage
            .unlock(pw)
            .expect("password still unlocks after data-key rotation");
        assert_secret_decrypts(&storage, &secret);
    }

    /// #565 concurrency: `acquire_rotation_lock` must serialize rotations via an
    /// exclusive flock on `.rotation.lock`. This drives one real rotation while
    /// the test thread holds that lock by hand, asserts the rotation blocks
    /// until the lock is released, then completes and commits the new password.
    /// It proves mutual exclusion (a rotation cannot proceed while the lock is
    /// held), not two-way convergence of two concurrent rotations.
    ///
    /// Depends on fs2 using flock(2), which is per-open-file-description on
    /// Unix: the test's handle and rotate_password's own handle contend even
    /// within this single process. If the lock ever moved to fcntl(2) record
    /// locks (per-process), same-process calls would stop blocking and this
    /// test would silently invert.
    #[test]
    fn concurrent_rotations_serialize_via_flock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let old_pw = "shared-old-7";
        {
            let _ = Storage::create(&path, old_pw, Argon2Params::TESTING).unwrap();
        }

        let lock_path = path.join(".rotation.lock");
        let holder = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();
        holder.lock_exclusive().unwrap();

        let path_bg = path.clone();
        let handle = std::thread::spawn(move || {
            let mut storage = Storage::open(&path_bg).unwrap();
            storage
                .rotate_password("shared-old-7", "shared-new-7")
                .map(|_| ())
        });

        // Give the background thread time to reach `lock_exclusive()` inside
        // rotate_password and block. If the flock were not serializing us it
        // would race to completion here.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            !handle.is_finished(),
            "background rotate must block on the held lock"
        );

        // Release the lock; the background thread's rotation should complete.
        drop(holder);
        let result = handle.join().expect("background thread joins");
        result.expect("background rotate succeeds once the lock is released");

        // Vault is in a consistent post-rotation state.
        let mut storage = Storage::open(&path).unwrap();
        assert!(
            storage.unlock(old_pw).is_err(),
            "old password must not unlock after concurrent rotation"
        );
        let mut storage = Storage::open(&path).unwrap();
        storage
            .unlock("shared-new-7")
            .expect("new password unlocks the rotated vault");
    }
}
