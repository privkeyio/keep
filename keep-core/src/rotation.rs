// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use fs2::FileExt;
use subtle::ConstantTimeEq;
use tracing::warn;

use crate::backend::{RedbBackend, StorageBackend, KEYS_TABLE, SHARES_TABLE};
use crate::crypto::{self, EncryptedData, SecretKey};
use crate::error::{KeepError, Result};
use crate::frost::StoredShare;
use crate::keys::KeyRecord;
use crate::storage::{bincode_options, share_id, Header, Storage};

use bincode::Options;

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

            let new_header = self.create_header_with_key(password, &new_data_key)?;
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
                    "rotation failed and backup restoration failed: {e} (header: {header_err:?}, db: {db_err:?})"
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
}
