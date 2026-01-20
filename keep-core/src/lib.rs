// SPDX-FileCopyrightText: (C) 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sovereign key management for Nostr and Bitcoin.
//!
//! This crate provides encrypted key storage with the following features:
//!
//! - **Encrypted storage** using Redb with XChaCha20-Poly1305
//! - **Key derivation** using Argon2id with configurable parameters
//! - **Nostr keypair management** with nsec/npub support
//! - **FROST threshold signatures** for distributed key management
//! - **Hidden volumes** for plausible deniability
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use keep_core::Keep;
//!
//! // Create a new Keep
//! let mut keep = Keep::create(Path::new("/tmp/my-keep"), "password")?;
//!
//! // Generate a new key
//! let pubkey = keep.generate_key("my-key")?;
//!
//! // Lock when done
//! keep.lock();
//! # Ok::<(), keep_core::error::KeepError>(())
//! ```

#![deny(missing_docs)]

/// Tamper-evident audit logging with hash chain integrity.
pub mod audit;
/// Pluggable storage backends.
pub mod backend;
/// Cryptographic primitives for encryption, key derivation, and hashing.
pub mod crypto;
/// Multi-source entropy mixing for defense-in-depth randomness.
pub mod entropy;
/// Error types and result aliases.
pub mod error;
/// FROST threshold signature implementation.
pub mod frost;
/// Hidden volume storage for plausible deniability.
pub mod hidden;
/// In-memory keyring for unlocked keys.
pub mod keyring;
/// Key types and Nostr keypair operations.
pub mod keys;
pub(crate) mod rate_limit;
/// Persistent encrypted storage backend.
pub mod storage;
/// Ephemeral time-limited secret vault.
pub mod vault;

use std::path::{Path, PathBuf};

use tracing::debug;
use zeroize::Zeroize;

use crate::audit::{AuditEntry, AuditEventType, AuditLog, RetentionPolicy};
use crate::crypto::{Argon2Params, SecretKey};
use crate::error::{KeepError, Result};
use crate::frost::{ShareExport, SharePackage, StoredShare, ThresholdConfig, TrustedDealer};
use crate::keyring::Keyring;
use crate::keys::{KeyRecord, KeyType, NostrKeypair};
use crate::storage::Storage;

/// The main Keep type for encrypted key management.
pub struct Keep {
    storage: Storage,
    keyring: Keyring,
    audit: Option<AuditLog>,
}

impl Keep {
    /// Create a new Keep with the given password.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use keep_core::Keep;
    ///
    /// let keep = Keep::create(Path::new("/tmp/my-keep"), "password")?;
    /// assert!(keep.is_unlocked());
    /// # Ok::<(), keep_core::error::KeepError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`KeepError::AlreadyExists`] if a Keep already exists at the path.
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        Self::create_with_params(path, password, Argon2Params::DEFAULT)
    }

    /// Create a new Keep with custom Argon2 parameters.
    pub fn create_with_params(path: &Path, password: &str, params: Argon2Params) -> Result<Self> {
        let storage = Storage::create(path, password, params)?;
        Ok(Self {
            storage,
            keyring: Keyring::new(),
            audit: None,
        })
    }

    /// Open an existing Keep.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use keep_core::Keep;
    ///
    /// let mut keep = Keep::open(Path::new("~/.keep"))?;
    /// keep.unlock("password")?;
    /// # Ok::<(), keep_core::error::KeepError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`KeepError::NotFound`] if no Keep exists at the path.
    pub fn open(path: &Path) -> Result<Self> {
        let storage = Storage::open(path)?;
        Ok(Self {
            storage,
            keyring: Keyring::new(),
            audit: None,
        })
    }

    /// Unlock with the given password.
    ///
    /// # Errors
    ///
    /// Returns [`KeepError::InvalidPassword`] if the password is incorrect.
    /// Returns [`KeepError::RateLimited`] after too many failed attempts.
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        self.storage.unlock(password)?;

        let data_key = self.get_data_key()?;
        self.audit = Some(AuditLog::open(self.storage.path(), &data_key)?);
        self.audit_event(AuditEventType::VaultUnlock, |e| e);
        debug!("loading keys to keyring");
        self.load_keys_to_keyring()
    }

    /// Lock and clear all keys from memory.
    pub fn lock(&mut self) {
        self.audit_event(AuditEventType::VaultLock, |e| e);
        self.keyring.clear();
        self.audit = None;
        self.storage.lock();
    }

    /// Returns true if unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.storage.is_unlocked()
    }

    /// Generate a new Nostr keypair and store it.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::path::Path;
    /// # use keep_core::Keep;
    /// # let mut keep = Keep::create(Path::new("/tmp/k"), "pw")?;
    /// let pubkey = keep.generate_key("my-nostr-key")?;
    /// println!("Created key: {}", hex::encode(pubkey));
    /// # Ok::<(), keep_core::error::KeepError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`KeepError::Locked`] if the Keep is not unlocked.
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

        self.audit_event(AuditEventType::KeyGenerate, |e| {
            e.with_pubkey(&pubkey).with_key_type("nostr")
        });

        Ok(pubkey)
    }

    /// Import an nsec and store it.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::path::Path;
    /// # use keep_core::Keep;
    /// # let mut keep = Keep::create(Path::new("/tmp/k"), "pw")?;
    /// let nsec = "nsec1...";
    /// let pubkey = keep.import_nsec(nsec, "imported-key")?;
    /// # Ok::<(), keep_core::error::KeepError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`KeepError::Locked`] if the Keep is not unlocked.
    /// Returns [`KeepError::InvalidNsec`] if the nsec format is invalid.
    /// Returns [`KeepError::KeyAlreadyExists`] if the key is already stored.
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

        self.audit_event(AuditEventType::KeyImport, |e| {
            e.with_pubkey(&pubkey).with_key_type("nostr")
        });

        Ok(pubkey)
    }

    /// The primary key slot, if set.
    pub fn get_primary_key(&self) -> Option<&keyring::KeySlot> {
        self.keyring.get_primary()
    }

    /// List all stored key records.
    pub fn list_keys(&self) -> Result<Vec<KeyRecord>> {
        self.storage.list_keys()
    }

    /// Delete a key.
    pub fn delete_key(&mut self, pubkey: &[u8; 32]) -> Result<()> {
        let id = crypto::blake2b_256(pubkey);
        self.storage.delete_key(&id)?;
        self.keyring.remove(pubkey)?;
        self.audit_event(AuditEventType::KeyDelete, |e| e.with_pubkey(pubkey));
        Ok(())
    }

    /// The keyring.
    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    /// Mutable access to the keyring.
    pub fn keyring_mut(&mut self) -> &mut Keyring {
        &mut self.keyring
    }

    /// Generate a new FROST key with the given threshold and total shares.
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

        let group_pubkey = *shares[0].group_pubkey();
        let participants: Vec<u16> = (1..=total_shares).collect();
        self.audit_event(AuditEventType::FrostGenerate, |e| {
            e.with_group(&group_pubkey)
                .with_threshold(threshold)
                .with_participants(participants)
        });

        Ok(shares)
    }

    /// Split an existing key into FROST shares.
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

        let group_pubkey = *shares[0].group_pubkey();
        let participants: Vec<u16> = (1..=total_shares).collect();
        self.audit_event(AuditEventType::FrostSplit, |e| {
            e.with_group(&group_pubkey)
                .with_threshold(threshold)
                .with_participants(participants)
        });

        Ok(shares)
    }

    /// List all stored FROST shares.
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

    /// Export a FROST share encrypted with a passphrase.
    pub fn frost_export_share(
        &mut self,
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

        self.audit_event(AuditEventType::FrostShareExport, |e| {
            e.with_group(group_pubkey)
                .with_participants(vec![identifier])
        });

        ShareExport::from_share(&share, passphrase)
    }

    /// Import a FROST share from an encrypted export.
    pub fn frost_import_share(&mut self, export: &ShareExport, passphrase: &str) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let share = export.to_share(passphrase, &format!("imported-{}", export.identifier))?;
        let data_key = self.get_data_key()?;
        let stored = StoredShare::encrypt(&share, &data_key)?;
        self.storage.store_share(&stored)?;

        let group = hex::decode(&export.group_pubkey)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .unwrap_or_else(|| crypto::blake2b_256(export.group_pubkey.as_bytes()));
        self.audit_event(AuditEventType::FrostShareImport, |e| {
            e.with_group(&group)
                .with_participants(vec![export.identifier])
        });

        Ok(())
    }

    /// Delete a FROST share.
    pub fn frost_delete_share(&mut self, group_pubkey: &[u8; 32], identifier: u16) -> Result<()> {
        self.storage.delete_share(group_pubkey, identifier)?;
        self.audit_event(AuditEventType::FrostShareDelete, |e| {
            e.with_group(group_pubkey)
                .with_participants(vec![identifier])
        });
        Ok(())
    }

    /// Get a FROST share by group public key.
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

    /// Get a FROST share by group public key and identifier index.
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

    /// Sign using local FROST shares. Requires threshold shares locally.
    pub fn frost_sign(&mut self, group_pubkey: &[u8; 32], message: &[u8]) -> Result<[u8; 64]> {
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
            self.audit_event(AuditEventType::FrostSignFailed, |e| {
                e.with_group(group_pubkey)
                    .with_message_hash(message)
                    .with_success(false)
                    .with_reason("Insufficient shares")
            });
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

        match frost::sign_with_local_shares(&decrypted_shares, message) {
            Ok(sig) => {
                self.audit_event(AuditEventType::FrostSign, |e| {
                    e.with_group(group_pubkey)
                        .with_message_hash(message)
                        .with_threshold(threshold)
                });
                Ok(sig)
            }
            Err(e) => {
                self.audit_event(AuditEventType::FrostSignFailed, |e| {
                    e.with_group(group_pubkey)
                        .with_message_hash(message)
                        .with_success(false)
                });
                Err(e)
            }
        }
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

    /// The data encryption key. Exposed for FROST integration.
    pub fn data_key(&self) -> Result<SecretKey> {
        self.get_data_key()
    }

    fn audit_event<F>(&mut self, event_type: AuditEventType, builder: F)
    where
        F: FnOnce(AuditEntry) -> AuditEntry,
    {
        let data_key = match self.get_data_key() {
            Ok(k) => k,
            Err(_) => return,
        };
        if let Some(ref mut audit) = self.audit {
            let entry = builder(AuditEntry::new(event_type, audit.last_hash()));
            if let Err(e) = audit.log(entry, &data_key) {
                tracing::warn!("Failed to write audit log entry for {}: {}", event_type, e);
            }
        }
    }

    /// Read all audit log entries.
    pub fn audit_read_all(&self) -> Result<Vec<AuditEntry>> {
        let (audit, data_key) = self.audit_with_key()?;
        audit.read_all(&data_key)
    }

    /// Verify the integrity of the audit log chain.
    pub fn audit_verify_chain(&self) -> Result<bool> {
        let (audit, data_key) = self.audit_with_key()?;
        audit.verify_chain(&data_key)
    }

    /// Export the audit log as JSON.
    pub fn audit_export(&self) -> Result<String> {
        let (audit, data_key) = self.audit_with_key()?;
        audit.export(&data_key)
    }

    fn audit_with_key(&self) -> Result<(&AuditLog, SecretKey)> {
        let audit = self.audit.as_ref().ok_or(KeepError::Locked)?;
        let data_key = self.get_data_key()?;
        Ok((audit, data_key))
    }

    /// Set the retention policy for the audit log.
    pub fn audit_set_retention(&mut self, policy: RetentionPolicy) {
        if let Some(ref mut audit) = self.audit {
            audit.set_retention(policy);
        }
    }

    /// Apply the retention policy and return the number of entries removed.
    pub fn audit_apply_retention(&mut self) -> Result<usize> {
        let data_key = self.get_data_key()?;
        let audit = self.audit.as_mut().ok_or(KeepError::Locked)?;
        audit.apply_retention(&data_key)
    }
}

/// Returns the default path to the Keep directory (~/.keep).
pub fn default_keep_path() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|p| p.join(".keep"))
        .ok_or(KeepError::HomeNotFound)
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
