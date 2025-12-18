pub mod bunker;
pub mod crypto;
pub mod error;
pub mod hidden;
pub mod keyring;
pub mod keys;
pub mod output;
pub mod server;
pub mod signer;
pub mod storage;
pub mod tui;

use std::path::{Path, PathBuf};

use tracing::debug;

use crate::crypto::{Argon2Params, SecretKey};
use crate::error::{KeepError, Result};
use crate::keyring::Keyring;
use crate::keys::{KeyRecord, KeyType, NostrKeypair};
use crate::storage::Storage;

pub struct Keep {
    storage: Storage,
    keyring: Keyring,
}

impl Keep {
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        let storage = Storage::create(path, password, Argon2Params::DEFAULT)?;

        Ok(Self {
            storage,
            keyring: Keyring::new(),
        })
    }

    pub fn open(path: &Path) -> Result<Self> {
        let storage = Storage::open(path)?;

        Ok(Self {
            storage,
            keyring: Keyring::new(),
        })
    }

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        self.storage.unlock(password)?;
        debug!("loading keys to keyring");
        self.load_keys_to_keyring()?;
        Ok(())
    }

    pub fn lock(&mut self) {
        self.keyring.clear();
        self.storage.lock();
    }

    pub fn is_unlocked(&self) -> bool {
        self.storage.is_unlocked()
    }

    pub fn generate_key(&mut self, name: &str) -> Result<[u8; 32]> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let keypair = NostrKeypair::generate();
        let pubkey = *keypair.public_bytes();

        let data_key = self.get_data_key()?;
        let encrypted = crypto::encrypt(keypair.secret_bytes(), &data_key)?;

        let record = KeyRecord::new(pubkey, KeyType::Nostr, name.to_string(), encrypted.to_bytes());

        self.storage.store_key(&record)?;

        self.keyring
            .load_key(pubkey, *keypair.secret_bytes(), KeyType::Nostr, name.to_string())?;

        Ok(pubkey)
    }

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

        let record = KeyRecord::new(pubkey, KeyType::Nostr, name.to_string(), encrypted.to_bytes());

        self.storage.store_key(&record)?;

        self.keyring
            .load_key(pubkey, *keypair.secret_bytes(), KeyType::Nostr, name.to_string())?;

        Ok(pubkey)
    }

    pub fn get_primary_key(&self) -> Option<&keyring::KeySlot> {
        self.keyring.get_primary()
    }

    pub fn list_keys(&self) -> Result<Vec<KeyRecord>> {
        self.storage.list_keys()
    }

    pub fn delete_key(&mut self, pubkey: &[u8; 32]) -> Result<()> {
        let id = crypto::blake2b_256(pubkey);
        self.storage.delete_key(&id)?;
        self.keyring.remove(pubkey)?;
        Ok(())
    }

    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    pub fn keyring_mut(&mut self) -> &mut Keyring {
        &mut self.keyring
    }

    fn load_keys_to_keyring(&mut self) -> Result<()> {
        let data_key = self.get_data_key()?;
        let records = self.storage.list_keys()?;

        for record in records {
            let encrypted = crypto::EncryptedData::from_bytes(&record.encrypted_secret)?;
            let secret_bytes = crypto::decrypt(&encrypted, &data_key)?;

            let mut secret = [0u8; 32];
            secret.copy_from_slice(&secret_bytes);

            self.keyring
                .load_key(record.pubkey, secret, record.key_type, record.name)?;

            secret.iter_mut().for_each(|b| *b = 0);
        }

        Ok(())
    }

    fn get_data_key(&self) -> Result<SecretKey> {
        self.storage
            .data_key()
            .cloned()
            .ok_or(KeepError::Locked)
    }
}

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
}
