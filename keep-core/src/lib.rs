//! Keep Core - Sovereign key management for Nostr and Bitcoin
//!
//! This crate provides the core library functionality for Keep:
//! - Encrypted storage using Redb with XChaCha20-Poly1305
//! - Key derivation using Argon2id
//! - Nostr keypair management
//! - Hidden volumes for plausible deniability

pub mod crypto;
pub mod error;
pub mod frost;
pub mod hidden;
pub mod keyring;
pub mod keys;
pub mod storage;

use std::path::{Path, PathBuf};

use tracing::debug;
use zeroize::Zeroize;

use crate::crypto::{Argon2Params, SecretKey};
use crate::error::{KeepError, Result};
use crate::frost::{ShareExport, SharePackage, StoredShare, ThresholdConfig, TrustedDealer};
use crate::keyring::Keyring;
use crate::keys::{KeyRecord, KeyType, NostrKeypair};
use crate::storage::Storage;

/// Main Keep instance for managing encrypted key storage.
pub struct Keep {
    storage: Storage,
    keyring: Keyring,
}

impl Keep {
    /// Create a new Keep at the given path with the provided password.
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        let storage = Storage::create(path, password, Argon2Params::DEFAULT)?;

        Ok(Self {
            storage,
            keyring: Keyring::new(),
        })
    }

    /// Open an existing Keep at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let storage = Storage::open(path)?;

        Ok(Self {
            storage,
            keyring: Keyring::new(),
        })
    }

    /// Unlock the Keep with the given password.
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        self.storage.unlock(password)?;
        debug!("loading keys to keyring");
        self.load_keys_to_keyring()?;
        Ok(())
    }

    /// Lock the Keep, clearing all keys from memory.
    pub fn lock(&mut self) {
        self.keyring.clear();
        self.storage.lock();
    }

    /// Check if the Keep is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.storage.is_unlocked()
    }

    /// Generate a new Nostr keypair and store it with the given name.
    pub fn generate_key(&mut self, name: &str) -> Result<[u8; 32]> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let keypair = NostrKeypair::generate();
        let pubkey = *keypair.public_bytes();

        let data_key = self.get_data_key()?;
        let encrypted = crypto::encrypt(keypair.secret_bytes(), &data_key)?;

        let record = KeyRecord::new(
            pubkey,
            KeyType::Nostr,
            name.to_string(),
            encrypted.to_bytes(),
        );

        self.storage.store_key(&record)?;

        self.keyring.load_key(
            pubkey,
            *keypair.secret_bytes(),
            KeyType::Nostr,
            name.to_string(),
        )?;

        Ok(pubkey)
    }

    /// Import an nsec (Nostr secret key) and store it with the given name.
    pub fn import_nsec(&mut self, nsec: &str, name: &str) -> Result<[u8; 32]> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let keypair = NostrKeypair::from_nsec(nsec)?;
        let pubkey = *keypair.public_bytes();

        if self.keyring.get(&pubkey).is_some() {
            return Err(KeepError::KeyAlreadyExists(keypair.to_npub()));
        }

        let data_key = self.get_data_key()?;
        let encrypted = crypto::encrypt(keypair.secret_bytes(), &data_key)?;

        let record = KeyRecord::new(
            pubkey,
            KeyType::Nostr,
            name.to_string(),
            encrypted.to_bytes(),
        );

        self.storage.store_key(&record)?;

        self.keyring.load_key(
            pubkey,
            *keypair.secret_bytes(),
            KeyType::Nostr,
            name.to_string(),
        )?;

        Ok(pubkey)
    }

    /// Get the primary key slot from the keyring.
    pub fn get_primary_key(&self) -> Option<&keyring::KeySlot> {
        self.keyring.get_primary()
    }

    /// List all stored key records.
    pub fn list_keys(&self) -> Result<Vec<KeyRecord>> {
        self.storage.list_keys()
    }

    /// Delete a key by its public key.
    pub fn delete_key(&mut self, pubkey: &[u8; 32]) -> Result<()> {
        let id = crypto::blake2b_256(pubkey);
        self.storage.delete_key(&id)?;
        self.keyring.remove(pubkey)?;
        Ok(())
    }

    /// Get a reference to the keyring.
    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    /// Get a mutable reference to the keyring.
    pub fn keyring_mut(&mut self) -> &mut Keyring {
        &mut self.keyring
    }

    pub fn frost_generate(
        &mut self,
        threshold: u16,
        total_shares: u16,
        name: &str,
    ) -> Result<Vec<SharePackage>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let config = ThresholdConfig::new(threshold, total_shares)?;
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate(name)?;

        let data_key = self.get_data_key()?;
        for share in &shares {
            let stored = StoredShare::encrypt(share, &data_key)?;
            self.storage.store_share(&stored)?;
        }

        Ok(shares)
    }

    pub fn frost_split(
        &mut self,
        key_name: &str,
        threshold: u16,
        total_shares: u16,
    ) -> Result<Vec<SharePackage>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let slot = self
            .keyring
            .get_by_name(key_name)
            .ok_or_else(|| KeepError::KeyNotFound(key_name.to_string()))?;

        let secret = *slot.expose_secret();

        let config = ThresholdConfig::new(threshold, total_shares)?;
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.split_existing(&secret, key_name)?;

        let data_key = self.get_data_key()?;
        for share in &shares {
            let stored = StoredShare::encrypt(share, &data_key)?;
            self.storage.store_share(&stored)?;
        }

        Ok(shares)
    }

    pub fn frost_list_shares(&self) -> Result<Vec<StoredShare>> {
        self.storage.list_shares()
    }

    fn find_stored_share(&self, group_pubkey: &[u8; 32], identifier: u16) -> Result<StoredShare> {
        let shares = self.storage.list_shares()?;
        shares
            .into_iter()
            .find(|s| {
                s.metadata.group_pubkey == *group_pubkey && s.metadata.identifier == identifier
            })
            .ok_or_else(|| KeepError::KeyNotFound(format!("No share {} for group", identifier)))
    }

    pub fn frost_export_share(
        &self,
        group_pubkey: &[u8; 32],
        identifier: u16,
        passphrase: &str,
    ) -> Result<ShareExport> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let stored = self.find_stored_share(group_pubkey, identifier)?;
        let data_key = self.get_data_key()?;
        let share = stored.decrypt(&data_key)?;

        ShareExport::from_share(&share, passphrase)
    }

    pub fn frost_import_share(&mut self, export: &ShareExport, passphrase: &str) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let share = export.to_share(passphrase, &format!("imported-{}", export.identifier))?;
        let data_key = self.get_data_key()?;
        let stored = StoredShare::encrypt(&share, &data_key)?;
        self.storage.store_share(&stored)?;

        Ok(())
    }

    pub fn frost_delete_share(&mut self, group_pubkey: &[u8; 32], identifier: u16) -> Result<()> {
        self.storage.delete_share(group_pubkey, identifier)
    }

    pub fn frost_get_share(&self, group_pubkey: &[u8; 32]) -> Result<frost::SharePackage> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let data_key = self.get_data_key()?;
        let shares = self.storage.list_shares()?;
        let stored = shares
            .iter()
            .find(|s| s.metadata.group_pubkey == *group_pubkey)
            .ok_or_else(|| KeepError::KeyNotFound("No shares for group".into()))?;

        stored.decrypt(&data_key)
    }

    pub fn frost_get_share_by_index(
        &self,
        group_pubkey: &[u8; 32],
        identifier: u16,
    ) -> Result<frost::SharePackage> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let stored = self.find_stored_share(group_pubkey, identifier)?;
        let data_key = self.get_data_key()?;
        stored.decrypt(&data_key)
    }

    pub fn frost_sign(&self, group_pubkey: &[u8; 32], message: &[u8]) -> Result<[u8; 64]> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let data_key = self.get_data_key()?;
        let shares = self.storage.list_shares()?;
        let our_shares: Vec<_> = shares
            .iter()
            .filter(|s| s.metadata.group_pubkey == *group_pubkey)
            .collect();

        if our_shares.is_empty() {
            return Err(KeepError::KeyNotFound("No shares for group".into()));
        }

        let threshold = our_shares[0].metadata.threshold;

        if our_shares.len() < threshold as usize {
            return Err(KeepError::Frost(format!(
                "Need {} shares to sign, only {} available",
                threshold,
                our_shares.len()
            )));
        }

        let mut decrypted_shares = Vec::new();
        for stored in our_shares.iter().take(threshold as usize) {
            decrypted_shares.push(stored.decrypt(&data_key)?);
        }

        frost::sign_with_local_shares(&decrypted_shares, message)
    }

    fn load_keys_to_keyring(&mut self) -> Result<()> {
        let data_key = self.get_data_key()?;
        let records = self.storage.list_keys()?;

        for record in records {
            let encrypted = crypto::EncryptedData::from_bytes(&record.encrypted_secret)?;
            let secret_bytes = crypto::decrypt(&encrypted, &data_key)?;

            let mut secret = [0u8; 32];
            let decrypted = secret_bytes.as_slice()?;
            secret.copy_from_slice(&decrypted);

            self.keyring
                .load_key(record.pubkey, secret, record.key_type, record.name)?;

            secret.zeroize();
        }

        Ok(())
    }

    fn get_data_key(&self) -> Result<SecretKey> {
        self.storage.data_key().cloned().ok_or(KeepError::Locked)
    }

    /// Returns the data encryption key used to encrypt stored secrets.
    ///
    /// # Errors
    /// Returns [`KeepError::Locked`] if [`unlock()`](Self::unlock) has not been called.
    ///
    /// Exposed for FROST/FrostSigner integration to decrypt stored shares.
    pub fn data_key(&self) -> Result<SecretKey> {
        self.get_data_key()
    }
}

/// Get the default path for Keep storage (~/.keep).
pub fn default_keep_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".keep")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_keep(path: &Path) -> Keep {
        Storage::create(path, "testpass", crypto::Argon2Params::TESTING).unwrap();
        let mut keep = Keep::open(path).unwrap();
        keep.unlock("testpass").unwrap();
        keep
    }

    #[test]
    fn test_keep_create_and_unlock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        {
            let keep = Keep::create(&path, "password").unwrap();
            assert!(keep.is_unlocked());
        }

        {
            let mut keep = Keep::open(&path).unwrap();
            assert!(!keep.is_unlocked());
            keep.unlock("password").unwrap();
            assert!(keep.is_unlocked());
        }
    }

    #[test]
    fn test_keep_generate_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        let mut keep = test_keep(&path);
        let pubkey = keep.generate_key("test").unwrap();

        assert_eq!(keep.keyring().len(), 1);
        assert!(keep.keyring().get(&pubkey).is_some());
        assert!(keep.keyring().get_by_name("test").is_some());
    }

    #[test]
    fn test_keep_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        let mut keep = test_keep(&path);
        keep.generate_key("test").unwrap();
        assert!(keep.is_unlocked());

        keep.lock();
        assert!(!keep.is_unlocked());
        assert_eq!(keep.keyring().len(), 0);
    }

    #[test]
    fn test_keep_primary_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        let mut keep = test_keep(&path);
        assert!(keep.get_primary_key().is_none());

        keep.generate_key("first").unwrap();
        let primary = keep.get_primary_key().unwrap();
        assert_eq!(primary.name, "first");
    }

    #[test]
    fn test_frost_generate_and_sign() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        let mut keep = test_keep(&path);

        let shares = keep.frost_generate(2, 3, "frost-test").unwrap();
        assert_eq!(shares.len(), 3);

        let group_pubkey = *shares[0].group_pubkey();

        let message = b"test message to sign with FROST";
        let signature = keep.frost_sign(&group_pubkey, message).unwrap();

        assert_eq!(signature.len(), 64);

        let stored_shares = keep.frost_list_shares().unwrap();
        assert_eq!(stored_shares.len(), 3);
    }

    #[test]
    fn test_frost_split_preserves_npub() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        let mut keep = test_keep(&path);

        let pubkey = keep.generate_key("to-split").unwrap();

        let shares = keep.frost_split("to-split", 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        let frost_pubkey = *shares[0].group_pubkey();
        assert_eq!(frost_pubkey, pubkey);

        let message = b"sign with split key";
        let signature = keep.frost_sign(&frost_pubkey, message).unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_frost_insufficient_shares_fails() {
        use crate::frost::{SigningSession, ThresholdConfig, TrustedDealer};

        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let message = b"test".to_vec();
        let kp0 = shares[0].key_package().unwrap();

        let mut session = SigningSession::new(message, 2);
        session.generate_commitment(&kp0).unwrap();

        assert_eq!(session.commitments_needed(), 1);
        assert!(!session.is_complete());
    }
}
