// SPDX-FileCopyrightText: (C) 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![deny(unsafe_code)]

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
/// Portable encrypted vault backup and restore.
pub mod backup;
/// Cryptographic primitives for encryption, key derivation, and hashing.
pub mod crypto;
/// Shared text-level helpers for output descriptor strings.
pub mod descriptor;
/// Display formatting helpers for truncation and timestamps.
pub mod display;
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
pub mod migration;
/// BIP-39 mnemonic generation and validation.
pub mod mnemonic;
/// NIP-06 key derivation from mnemonic seed phrase.
pub mod nip06;
pub(crate) mod rate_limit;
/// Relay configuration for FROST shares.
pub mod relay;
mod rotation;
/// Persistent encrypted storage backend.
pub mod storage;
/// Ephemeral time-limited secret vault.
pub mod vault;
/// Wallet descriptor types for FROST group spending policies.
pub mod wallet;

use std::path::{Path, PathBuf};

use tracing::debug;
use zeroize::Zeroizing;

use crate::audit::{
    AuditEntry, AuditEventType, AuditLog, RetentionPolicy, SigningAuditEntry, SigningAuditLog,
};
use crate::crypto::{Argon2Params, SecretKey};
use crate::error::{KeepError, Result};
use crate::frost::{ShareExport, SharePackage, StoredShare, ThresholdConfig, TrustedDealer};
use crate::keyring::Keyring;
use crate::keys::{KeyRecord, KeyType, NostrKeypair};
pub use crate::relay::{PeerPolicyEntry, RelayConfig, GLOBAL_RELAY_KEY};
pub use crate::storage::ProxyConfig;
use crate::storage::Storage;
pub use crate::wallet::{DeviceRegistration, WalletDescriptor};

/// The main Keep type for encrypted key management.
pub struct Keep {
    storage: Storage,
    keyring: Keyring,
    audit: Option<AuditLog>,
    signing_audit: Option<SigningAuditLog>,
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
            signing_audit: None,
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
            signing_audit: None,
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
        self.signing_audit = Some(SigningAuditLog::open(self.storage.path(), &data_key)?);

        // Flush any rate-limit trip events queued by prior failed unlocks
        // before recording this success, so the audit chain reflects the
        // chronological order: lock-out events first, then the successful
        // unlock that observed and cleared them. The drain consumes the trip
        // file before the audit writes, so emission is best-effort: a failed
        // audit write loses that event at-most-once with no retry.
        let trips = self.storage.drain_pending_trips();
        for trip in trips {
            let trip_ts = i64::try_from(trip.timestamp).unwrap_or(i64::MAX);
            let reason = format!(
                "rate limit threshold reached after {} failed attempts",
                trip.failed_attempts
            );
            self.audit_event(AuditEventType::RateLimitTripped, |mut e| {
                e.timestamp = trip_ts;
                e.with_success(false).with_reason(&reason)
            });
        }

        self.audit_event(AuditEventType::VaultUnlock, |e| e);
        debug!("loading keys to keyring");
        self.load_keys_to_keyring()
    }

    /// Verify a password without changing the unlock state.
    pub fn verify_password(&self, password: &str) -> Result<()> {
        self.storage.verify_password(password)
    }

    /// Lock and clear all keys from memory.
    pub fn lock(&mut self) {
        self.audit_event(AuditEventType::VaultLock, |e| e);
        self.keyring.clear();
        self.audit = None;
        self.signing_audit = None;
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

        let keypair = NostrKeypair::generate()?;
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

        let name = name.trim();
        if name.is_empty() {
            return Err(KeepError::InvalidInput("name cannot be empty".into()));
        }
        if name.chars().count() > 64 {
            return Err(KeepError::InvalidInput(
                "name must be 64 characters or fewer".into(),
            ));
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

    /// Import a Nostr key from raw secret bytes.
    pub fn import_secret_bytes(&mut self, secret: &mut [u8; 32], name: &str) -> Result<[u8; 32]> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let name = name.trim();
        if name.is_empty() {
            return Err(KeepError::InvalidInput("name cannot be empty".into()));
        }
        if name.chars().count() > 64 {
            return Err(KeepError::InvalidInput(
                "name must be 64 characters or fewer".into(),
            ));
        }

        let keypair = NostrKeypair::from_secret_bytes(secret)?;
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

    /// Export a stored nsec key as NIP-49 ncryptsec.
    pub fn export_ncryptsec(&mut self, pubkey: &[u8; 32], password: &str) -> Result<String> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let slot = self
            .keyring
            .get(pubkey)
            .ok_or_else(|| KeepError::KeyNotFound(hex::encode(pubkey)))?;

        if slot.key_type != KeyType::Nostr {
            return Err(KeepError::InvalidInput("not a Nostr key".into()));
        }

        let result = keys::nip49::encrypt(slot.expose_secret(), password, None)?;
        self.audit_event(AuditEventType::KeyExport, |e| e.with_pubkey(pubkey));
        Ok(result)
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

    /// Decrypted audit log entries for this vault, in chronological order.
    /// Returns an empty vec if the audit log file does not exist yet.
    ///
    /// # Errors
    /// Returns [`KeepError::Locked`] if the vault is not unlocked.
    pub fn read_audit_entries(&self) -> Result<Vec<AuditEntry>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let data_key = self.get_data_key()?;
        let audit = AuditLog::open(self.storage.path(), &data_key)?;
        audit.read_all(&data_key)
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

        let secret = Zeroizing::new(*slot.expose_secret());

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

    fn find_stored_share(
        &self,
        group_pubkey: &[u8; 32],
        identifier: u16,
        ciphersuite: Option<crate::frost::Ciphersuite>,
    ) -> Result<StoredShare> {
        let shares = self.storage.list_shares()?;
        shares
            .into_iter()
            .find(|s| {
                s.metadata.group_pubkey == *group_pubkey
                    && s.metadata.identifier == identifier
                    && ciphersuite.is_none_or(|cs| s.ciphersuite == cs)
            })
            .ok_or_else(|| KeepError::KeyNotFound(format!("No share {identifier} for group")))
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

        let mut stored = self.find_stored_share(group_pubkey, identifier, None)?;
        let data_key = self.get_data_key()?;
        let share = stored.decrypt(&data_key)?;

        self.audit_event(AuditEventType::FrostShareExport, |e| {
            e.with_group(group_pubkey)
                .with_participants(vec![identifier])
        });

        let export =
            ShareExport::from_share_with_ciphersuite(&share, stored.ciphersuite, passphrase)?;

        // Exporting is the backup action: record it so the UI/clients can stop
        // nagging "not backed up". Best-effort; a storage error here must not
        // fail the export the caller already holds.
        if !stored.metadata.did_backup {
            stored.metadata.mark_backed_up();
            if let Err(e) = self.storage.store_share(&stored) {
                tracing::warn!(error = %e, "failed to persist did_backup after export");
            }
        }

        Ok(export)
    }

    /// Import a FROST share from an encrypted export.
    pub fn frost_import_share(
        &mut self,
        export: &ShareExport,
        passphrase: &str,
        name: &str,
    ) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let name = name.trim();
        if name.is_empty() {
            return Err(KeepError::InvalidInput("name cannot be empty".into()));
        }
        if name.chars().count() > 64 {
            return Err(KeepError::InvalidInput(
                "name must be 64 characters or fewer".into(),
            ));
        }

        let share = export.to_share(passphrase, name)?;
        let data_key = self.get_data_key()?;
        let stored = StoredShare::encrypt_with_ciphersuite(&share, export.ciphersuite, &data_key)?;
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

    /// Refresh all FROST shares for a group, invalidating old shares.
    pub fn frost_refresh(&mut self, group_pubkey: &[u8; 32]) -> Result<Vec<frost::ShareMetadata>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let data_key = self.get_data_key()?;
        let all_shares = self.storage.list_shares()?;
        let group_shares: Vec<_> = all_shares
            .into_iter()
            .filter(|s| {
                s.metadata.group_pubkey == *group_pubkey
                    && s.ciphersuite == crate::frost::Ciphersuite::Secp256k1Tr
            })
            .collect();

        if group_shares.is_empty() {
            return Err(KeepError::KeyNotFound("No shares for group".into()));
        }

        let threshold = group_shares[0].metadata.threshold;

        let share_count: u16 = group_shares
            .len()
            .try_into()
            .map_err(|_| KeepError::Frost("Too many shares".into()))?;
        if share_count < threshold {
            return Err(KeepError::Frost(format!(
                "Need at least {threshold} shares to refresh, only {share_count} available locally"
            )));
        }

        let decrypted: Vec<SharePackage> = group_shares
            .iter()
            .map(|s| s.decrypt(&data_key))
            .collect::<Result<_>>()?;

        let (refreshed, _) = frost::refresh_shares(&decrypted)?;

        let encrypted_shares: Vec<StoredShare> = refreshed
            .iter()
            .map(|share| StoredShare::encrypt(share, &data_key))
            .collect::<Result<_>>()?;

        self.storage.store_shares_atomic(&encrypted_shares)?;

        let metadata: Vec<_> = refreshed.iter().map(|s| s.metadata.clone()).collect();
        let participants: Vec<u16> = metadata.iter().map(|m| m.identifier).collect();
        self.audit_event(AuditEventType::FrostShareRefresh, |e| {
            e.with_group(group_pubkey)
                .with_threshold(threshold)
                .with_participants(participants)
        });

        Ok(metadata)
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

    /// Rename a stored FROST share (updates its display name only).
    pub fn frost_rename_share(
        &mut self,
        group_pubkey: &[u8; 32],
        identifier: u16,
        name: &str,
    ) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let name = name.trim();
        if name.is_empty() {
            return Err(KeepError::InvalidInput(
                "share name must not be empty".into(),
            ));
        }
        if name.chars().count() > 64 {
            return Err(KeepError::InvalidInput(
                "share name must not exceed 64 characters".into(),
            ));
        }
        let mut stored = self.find_stored_share(group_pubkey, identifier, None)?;
        stored.metadata.name = name.to_string();
        self.storage.store_share(&stored)?;
        Ok(())
    }

    /// Get the hex-encoded group pubkey of the active share, if set.
    pub fn get_active_share_key(&self) -> Option<String> {
        std::fs::read_to_string(self.active_share_path())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| is_valid_hex_pubkey(s))
    }

    /// Set the active share by hex-encoded group pubkey. Pass `None` to clear.
    pub fn set_active_share_key(&self, key: Option<&str>) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let path = self.active_share_path();
        match key {
            Some(k) => {
                if !is_valid_hex_pubkey(k) {
                    return Err(KeepError::InvalidInput(
                        "Group pubkey must be 64 hex characters".into(),
                    ));
                }
                let normalized = k.to_ascii_lowercase();
                write_restricted(&path, normalized.as_bytes())?;
            }
            None => {
                if let Err(e) = std::fs::remove_file(&path) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        return Err(e.into());
                    }
                }
            }
        }
        Ok(())
    }

    fn active_share_path(&self) -> PathBuf {
        self.storage.path.join("active_share")
    }

    /// Store a finalized wallet descriptor, associated with a FROST group.
    pub fn store_wallet_descriptor(&self, descriptor: &WalletDescriptor) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.store_descriptor(descriptor)
    }

    /// Get the wallet descriptor for a FROST group.
    pub fn get_wallet_descriptor(
        &self,
        group_pubkey: &[u8; 32],
    ) -> Result<Option<WalletDescriptor>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.get_descriptor(group_pubkey)
    }

    /// List the latest-version wallet descriptor for every group. Older
    /// descriptor versions are not returned; use
    /// [`list_all_wallet_descriptor_versions`] when every row is required
    /// (backup, rotation re-encryption verification, etc.).
    ///
    /// [`list_all_wallet_descriptor_versions`]: Self::list_all_wallet_descriptor_versions
    pub fn list_wallet_descriptors(&self) -> Result<Vec<WalletDescriptor>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.list_descriptors()
    }

    /// List every persisted wallet descriptor row across all groups and
    /// versions. Used by backup and rotation paths that must round-trip every
    /// stored record.
    pub fn list_all_wallet_descriptor_versions(&self) -> Result<Vec<WalletDescriptor>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.list_all_descriptor_versions()
    }

    /// Delete a wallet descriptor.
    pub fn delete_wallet_descriptor(&self, group_pubkey: &[u8; 32]) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.delete_descriptor(group_pubkey)
    }

    /// Atomically insert or update a device registration on the descriptor for
    /// the given FROST group. Performs the load-modify-store under the
    /// storage's descriptor write lock so concurrent callers cannot drop each
    /// other's updates.
    pub fn upsert_device_registration(
        &self,
        group_pubkey: &[u8; 32],
        registration: DeviceRegistration,
    ) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage
            .upsert_device_registration(group_pubkey, registration)
    }

    /// Store a key health status record.
    pub fn store_health_status(&self, status: &wallet::KeyHealthStatus) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.store_health_status(status)
    }

    /// Get a key health status record.
    pub fn get_health_status(
        &self,
        group_pubkey: &[u8; 32],
        share_index: u16,
    ) -> Result<Option<wallet::KeyHealthStatus>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.get_health_status(group_pubkey, share_index)
    }

    /// List all key health status records.
    pub fn list_health_statuses(&self) -> Result<Vec<wallet::KeyHealthStatus>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.list_health_statuses()
    }

    /// List health statuses that are stale (not checked within the threshold).
    pub fn list_stale_health_statuses(&self, now: u64) -> Result<Vec<wallet::KeyHealthStatus>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let all = self.storage.list_health_statuses()?;
        Ok(all.into_iter().filter(|s| s.is_stale(now)).collect())
    }

    /// Store relay configuration for a FROST share.
    pub fn store_relay_config(&self, config: &RelayConfig) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        let normalized_config = config.clone().normalize()?;
        self.storage.store_relay_config(&normalized_config)
    }

    /// Get relay configuration for a FROST share.
    pub fn get_relay_config(&self, group_pubkey: &[u8; 32]) -> Result<Option<RelayConfig>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.get_relay_config(group_pubkey)
    }

    /// Get relay configuration for a FROST share, returning defaults if none stored.
    pub fn get_relay_config_or_default(&self, group_pubkey: &[u8; 32]) -> Result<RelayConfig> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        Ok(self
            .storage
            .get_relay_config(group_pubkey)?
            .unwrap_or_else(|| RelayConfig::with_defaults(*group_pubkey)))
    }

    /// List all stored relay configurations.
    pub fn list_relay_configs(&self) -> Result<Vec<RelayConfig>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.list_relay_configs()
    }

    /// Delete relay configuration for a FROST share.
    pub fn delete_relay_config(&self, group_pubkey: &[u8; 32]) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.delete_relay_config(group_pubkey)
    }

    /// Get the kill switch state from the vault.
    pub fn get_kill_switch(&self) -> Result<bool> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.get_kill_switch()
    }

    /// Set the kill switch state in the vault.
    pub fn set_kill_switch(&self, active: bool) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.set_kill_switch(active)
    }

    /// Get the proxy configuration.
    pub fn get_proxy_config(&self) -> Result<ProxyConfig> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.get_proxy_config()
    }

    /// Set the proxy configuration.
    pub fn set_proxy_config(&self, config: &ProxyConfig) -> Result<()> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }
        self.storage.set_proxy_config(config)
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
            .find(|s| {
                s.metadata.group_pubkey == *group_pubkey
                    && s.ciphersuite == crate::frost::Ciphersuite::Secp256k1Tr
            })
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

        let stored = self.find_stored_share(group_pubkey, identifier, None)?;
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
            .filter(|s| {
                s.metadata.group_pubkey == *group_pubkey
                    && s.ciphersuite == crate::frost::Ciphersuite::Secp256k1Tr
            })
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

    /// Generate a FROST-Ed25519 threshold key and store its shares.
    ///
    /// Shares are tagged with [`Ciphersuite::Ed25519`], which is bound into the
    /// at-rest AEAD AAD so they cannot be confused with secp256k1 shares.
    #[cfg(feature = "ed25519")]
    pub fn frost_generate_ed25519(
        &mut self,
        threshold: u16,
        total_shares: u16,
        name: &str,
    ) -> Result<Vec<SharePackage>> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let config = ThresholdConfig::new(threshold, total_shares)?;
        let dealer = crate::frost::ed25519::TrustedDealer::new(config);
        let (shares, _) = dealer.generate(name)?;

        let data_key = self.get_data_key()?;
        for share in &shares {
            let stored = StoredShare::encrypt_with_ciphersuite(
                share,
                crate::frost::Ciphersuite::Ed25519,
                &data_key,
            )?;
            self.storage.store_share(&stored)?;
        }

        let group_pubkey = *shares[0].group_pubkey();
        let participants: Vec<u16> = shares.iter().map(|s| s.metadata.identifier).collect();
        self.audit_event(AuditEventType::FrostGenerate, |e| {
            e.with_group(&group_pubkey)
                .with_threshold(threshold)
                .with_participants(participants)
        });

        Ok(shares)
    }

    /// Sign a message with a threshold of local FROST-Ed25519 shares.
    ///
    /// Returns a detached 64-byte Ed25519 signature over the raw message
    /// (RFC 8032), verifiable by [`Keep::frost_verify_ed25519`] and by any
    /// standard Ed25519 verifier against the group public key.
    #[cfg(feature = "ed25519")]
    pub fn frost_sign_ed25519(
        &mut self,
        group_pubkey: &[u8; 32],
        message: &[u8],
    ) -> Result<[u8; 64]> {
        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        let decrypted_shares = match self.frost_ed25519_decrypt_threshold_shares(group_pubkey) {
            Ok(shares) => shares,
            Err(e) => {
                self.audit_event(AuditEventType::FrostSignFailed, |ev| {
                    ev.with_group(group_pubkey)
                        .with_message_hash(message)
                        .with_success(false)
                        .with_reason("Insufficient shares")
                });
                return Err(e);
            }
        };
        let threshold = decrypted_shares[0].metadata.threshold;

        match crate::frost::ed25519::sign_with_local_shares(&decrypted_shares, message) {
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

    /// Decrypt the threshold set of local Ed25519 shares for a group.
    ///
    /// Returns exactly `threshold` decrypted shares or a `KeyNotFound`/`Frost`
    /// error. Does not emit audit events; callers own audit semantics.
    #[cfg(feature = "ed25519")]
    fn frost_ed25519_decrypt_threshold_shares(
        &self,
        group_pubkey: &[u8; 32],
    ) -> Result<Vec<SharePackage>> {
        let data_key = self.get_data_key()?;
        let shares = self.storage.list_shares()?;
        let our_shares: Vec<_> = shares
            .iter()
            .filter(|s| {
                s.metadata.group_pubkey == *group_pubkey
                    && s.ciphersuite == crate::frost::Ciphersuite::Ed25519
            })
            .collect();

        if our_shares.is_empty() {
            return Err(KeepError::KeyNotFound("No Ed25519 shares for group".into()));
        }

        let threshold = our_shares[0].metadata.threshold;
        if our_shares.len() < threshold as usize {
            return Err(KeepError::Frost(format!(
                "Need {} shares to sign, only {} available",
                threshold,
                our_shares.len()
            )));
        }

        let mut decrypted_shares = Vec::with_capacity(threshold as usize);
        for stored in our_shares.iter().take(threshold as usize) {
            decrypted_shares.push(stored.decrypt(&data_key)?);
        }
        Ok(decrypted_shares)
    }

    /// Verify a detached Ed25519 signature against a group public key.
    #[cfg(feature = "ed25519")]
    pub fn frost_verify_ed25519(
        group_pubkey: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<()> {
        crate::frost::ed25519::verify(group_pubkey, message, signature)
    }

    /// Sign `message` and produce a minisign-compatible detached signature.
    ///
    /// Runs two FROST-Ed25519 threshold signing sessions: one over the
    /// BLAKE2b-512 prehash of the message (the `"ED"` file signature) and one
    /// over `file_signature || trusted_comment` (the global signature). The
    /// result verifies with the standard `minisign -V` tool against the
    /// exported group public key.
    #[cfg(feature = "ed25519")]
    pub fn frost_sign_ed25519_minisign(
        &mut self,
        group_pubkey: &[u8; 32],
        message: &[u8],
        untrusted_comment: String,
        trusted_comment: String,
    ) -> Result<crate::frost::ed25519::minisign::MinisignSignature> {
        use crate::frost::ed25519::minisign;

        if !self.is_unlocked() {
            return Err(KeepError::Locked);
        }

        minisign::validate_comment("untrusted", &untrusted_comment)?;
        minisign::validate_comment("trusted", &trusted_comment)?;

        let decrypted_shares = match self.frost_ed25519_decrypt_threshold_shares(group_pubkey) {
            Ok(shares) => shares,
            Err(e) => {
                self.audit_event(AuditEventType::FrostSignFailed, |ev| {
                    ev.with_group(group_pubkey)
                        .with_message_hash(message)
                        .with_success(false)
                        .with_reason("Insufficient shares")
                });
                return Err(e);
            }
        };
        let threshold = decrypted_shares[0].metadata.threshold;

        // Two independent threshold sessions over the same decrypted share set:
        // fresh nonces per session keep each signature secure.
        let prehash = minisign::prehash(message);
        let sign_both = (|| {
            let signature =
                crate::frost::ed25519::sign_with_local_shares(&decrypted_shares, &prehash)?;
            let global_bytes = minisign::global_signed_bytes(&signature, &trusted_comment);
            let global_signature =
                crate::frost::ed25519::sign_with_local_shares(&decrypted_shares, &global_bytes)?;
            Ok::<_, KeepError>((signature, global_signature))
        })();

        let (signature, global_signature) = match sign_both {
            Ok(pair) => {
                self.audit_event(AuditEventType::FrostSign, |e| {
                    e.with_group(group_pubkey)
                        .with_message_hash(message)
                        .with_threshold(threshold)
                });
                pair
            }
            Err(e) => {
                self.audit_event(AuditEventType::FrostSignFailed, |ev| {
                    ev.with_group(group_pubkey)
                        .with_message_hash(message)
                        .with_success(false)
                });
                return Err(e);
            }
        };

        Ok(minisign::MinisignSignature {
            sig_alg: minisign::ALG_PREHASHED,
            key_id: minisign::key_id(group_pubkey),
            signature,
            global_signature,
            untrusted_comment,
            trusted_comment,
        })
    }

    /// Verify a minisign-compatible detached signature against a group public
    /// key, checking both the file signature and the global signature using
    /// minisign's semantics (key-id match, prehash for `"ED"`, RFC 8032 strict
    /// cofactorless verification via frost-ed25519).
    #[cfg(feature = "ed25519")]
    pub fn frost_verify_ed25519_minisign(
        group_pubkey: &[u8; 32],
        message: &[u8],
        sig: &crate::frost::ed25519::minisign::MinisignSignature,
    ) -> Result<()> {
        use crate::frost::ed25519::minisign;

        if sig.key_id != minisign::key_id(group_pubkey) {
            return Err(KeepError::InvalidInput(
                "signature key id does not match group public key".into(),
            ));
        }

        let signed_message = match sig.sig_alg {
            minisign::ALG_PREHASHED => minisign::prehash(message).to_vec(),
            minisign::ALG_LEGACY => message.to_vec(),
            _ => {
                return Err(KeepError::InvalidInput(
                    "unknown signature algorithm".into(),
                ))
            }
        };

        crate::frost::ed25519::verify(group_pubkey, &signed_message, &sig.signature)?;

        let global_bytes = minisign::global_signed_bytes(&sig.signature, &sig.trusted_comment);
        crate::frost::ed25519::verify(group_pubkey, &global_bytes, &sig.global_signature)
    }

    fn load_keys_to_keyring(&mut self) -> Result<()> {
        let data_key = self.get_data_key()?;
        let records = self.storage.list_keys()?;

        for record in records {
            let encrypted = crypto::EncryptedData::from_bytes(&record.encrypted_secret)?;
            let secret_bytes = crypto::decrypt(&encrypted, &data_key)?;

            let mut secret = Zeroizing::new([0u8; 32]);
            let decrypted = secret_bytes.as_slice()?;
            secret.copy_from_slice(&decrypted);

            self.keyring
                .load_key(record.pubkey, *secret, record.key_type, record.name)?;
        }

        Ok(())
    }

    fn get_data_key(&self) -> Result<SecretKey> {
        self.storage.data_key().cloned().ok_or(KeepError::Locked)
    }

    /// Rotate the vault password.
    ///
    /// Re-encrypts the data encryption key with a new password-derived key.
    /// The data encryption key itself is unchanged, so stored secrets remain intact.
    ///
    /// Closes #579 (every post-storage-rotation failure path now emits a
    /// failure audit entry before propagating) and #580 (the success path
    /// uses `audit_event_required`, so a silent audit-write failure is
    /// surfaced as `KeepError::AuditWriteFailed`).
    pub fn rotate_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        let result = self.rotate_password_inner(old_password, new_password);
        match &result {
            Ok(()) => self.audit_event_required(AuditEventType::PasswordRotate, |e| e),
            Err(e) => {
                // Failed attempts are observable only when the vault was
                // unlocked before the call (audit log needs the data key).
                let reason = e.to_string();
                self.audit_event(AuditEventType::PasswordRotateFailed, |entry| {
                    entry.with_success(false).with_reason(&reason)
                });
                result
            }
        }
    }

    fn rotate_password_inner(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        self.storage.rotate_password(old_password, new_password)?;
        self.keyring.clear();
        self.load_keys_to_keyring()?;
        Ok(())
    }

    /// Rotate the data encryption key.
    ///
    /// Generates a new data encryption key and re-encrypts all stored keys and shares.
    ///
    /// Closes #579 (a failure before the storage commit audits
    /// DataKeyRotateFailed) and #580 (success path uses `audit_event_required`).
    pub fn rotate_data_key(&mut self, password: &str) -> Result<()> {
        // A locked vault has no data key, so the failure entry cannot be
        // encrypted/recorded here; `audit_event` no-ops in that case.
        let old_data_key = self.get_data_key()?;

        // Pre-commit phase. `storage.rotate_data_key` rolls back internally on
        // failure, so the on-disk data key is unchanged and the audit chains
        // still match `old_data_key` == the current data key. The failure entry
        // therefore encrypts under the key matching the on-disk chain (#579).
        if let Err(e) = self.storage.rotate_data_key(password) {
            let reason = e.to_string();
            self.audit_event(AuditEventType::DataKeyRotateFailed, |entry| {
                entry.with_success(false).with_reason(&reason)
            });
            return Err(e);
        }

        // Post-commit phase. Storage has durably committed the new data key, so
        // the rotation has already succeeded on disk; the audit chains are still
        // under `old_data_key` until re-encrypted below. A failure here must NOT
        // emit a DataKeyRotateFailed entry: it would be encrypted under the new
        // key and appended to a chain still under the old key (corrupting it,
        // since `reencrypt` is atomic and leaves the file under the old key on
        // failure), and it would misreport a rotation that already committed.
        let new_data_key = self.get_data_key()?;
        if let Some(ref mut audit) = self.audit {
            audit.reencrypt(&old_data_key, &new_data_key)?;
        }
        if let Some(ref mut signing_audit) = self.signing_audit {
            signing_audit.reencrypt(&old_data_key, &new_data_key)?;
        }
        self.keyring.clear();
        self.load_keys_to_keyring()?;

        // Both chains are now under `new_data_key`, so this success entry is
        // consistent with the on-disk chain (#580 fails closed).
        self.audit_event_required(AuditEventType::DataKeyRotate, |e| e)
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

    /// Store a pre-encrypted key record directly (for backup restore).
    pub(crate) fn restore_key_record(&self, record: &KeyRecord) -> Result<()> {
        self.get_data_key()?;
        self.storage.store_key(record)
    }

    /// Store a pre-encrypted share directly (for backup restore).
    pub(crate) fn restore_stored_share(&self, share: &StoredShare) -> Result<()> {
        self.get_data_key()?;
        self.storage.store_share(share)
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

    /// Audit-write that propagates failure to the caller. Used for
    /// security-critical events where a silent best-effort log (#580) is
    /// unacceptable: a successful return MUST mean the audit entry was
    /// persisted. Fails closed when the vault is locked or the audit log is
    /// unavailable.
    fn audit_event_required<F>(&mut self, event_type: AuditEventType, builder: F) -> Result<()>
    where
        F: FnOnce(AuditEntry) -> AuditEntry,
    {
        let data_key = self.get_data_key()?;
        let audit = self.audit.as_mut().ok_or_else(|| {
            KeepError::AuditWriteFailed(format!(
                "audit log not initialized; cannot record required event {event_type}"
            ))
        })?;
        let entry = builder(AuditEntry::new(event_type, audit.last_hash()));
        audit
            .log(entry, &data_key)
            .map_err(|e| KeepError::AuditWriteFailed(format!("{event_type}: {e}")))
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

    /// Log a signing audit entry.
    pub fn signing_audit_log(&mut self, entry: SigningAuditEntry) -> Result<()> {
        let data_key = self.get_data_key()?;
        let log = self.signing_audit.as_mut().ok_or(KeepError::Locked)?;
        log.log(entry, &data_key)
    }

    /// Get the last hash of the signing audit chain.
    pub fn signing_audit_last_hash(&self) -> Result<[u8; 32]> {
        let log = self.signing_audit.as_ref().ok_or(KeepError::Locked)?;
        Ok(log.last_hash())
    }

    /// Read a page of signing audit entries with metadata in a single decryption pass.
    pub fn signing_audit_read_page_with_metadata(
        &self,
        offset: usize,
        limit: usize,
        caller_filter: Option<&str>,
    ) -> Result<(Vec<SigningAuditEntry>, Vec<String>, usize)> {
        let (log, data_key) = self.signing_audit_with_key()?;
        log.read_page_with_metadata(&data_key, offset, limit, caller_filter)
    }

    /// Verify the integrity of the signing audit chain and return the entry count.
    pub fn signing_audit_verify_chain(&self) -> Result<(bool, usize)> {
        let (log, data_key) = self.signing_audit_with_key()?;
        log.verify_chain(&data_key)
    }

    fn signing_audit_with_key(&self) -> Result<(&SigningAuditLog, SecretKey)> {
        let log = self.signing_audit.as_ref().ok_or(KeepError::Locked)?;
        let data_key = self.get_data_key()?;
        Ok((log, data_key))
    }
}

fn is_valid_hex_pubkey(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn write_restricted(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(data)
}

/// Returns the default path to the Keep directory (~/.keep).
/// Override with the `KEEP_HOME` environment variable.
pub fn default_keep_path() -> Result<PathBuf> {
    match std::env::var("KEEP_HOME") {
        Ok(val) if !val.trim().is_empty() => {
            let path = PathBuf::from(&val);
            if path.is_absolute() {
                Ok(path)
            } else {
                Err(KeepError::InvalidInput(
                    "KEEP_HOME must be an absolute path".into(),
                ))
            }
        }
        _ => dirs::home_dir()
            .map(|p| p.join(".keep"))
            .ok_or(KeepError::HomeNotFound),
    }
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
    fn rate_limit_trip_emits_audit_entry_on_next_unlock() {
        // The rate limiter trips after MAX_ATTEMPTS (5) failed unlocks. The
        // trip event must surface as a `RateLimitTripped` audit entry the
        // next time the operator successfully unlocks (#495).
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        Storage::create(&path, "right-password", crypto::Argon2Params::TESTING).unwrap();

        // Five failed attempts trips the limiter.
        for _ in 0..5 {
            let mut keep = Keep::open(&path).unwrap();
            let _ = keep.unlock("wrong-password");
        }

        // The sixth attempt would hit the back-off; wait it out by clearing
        // the active rate-limit counter (the trip event lives in a separate
        // file that record_success deliberately does NOT touch).
        crate::rate_limit::record_success(&path);

        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("right-password").unwrap();

        let entries = keep.audit_read_all().unwrap();
        let trips: Vec<_> = entries
            .iter()
            .filter(|e| matches!(e.event_type, AuditEventType::RateLimitTripped))
            .collect();
        assert_eq!(trips.len(), 1, "expected one trip entry, got {trips:#?}");
        assert!(!trips[0].success, "trip entry must record success=false");
        assert!(
            trips[0]
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("rate limit")),
            "trip entry must carry a descriptive reason, got {:?}",
            trips[0].reason
        );

        // Chronological order: RateLimitTripped precedes the VaultUnlock it
        // was discovered by, so the audit chain reflects the actual sequence
        // of lockout then recovery.
        let trip_idx = entries
            .iter()
            .position(|e| matches!(e.event_type, AuditEventType::RateLimitTripped))
            .unwrap();
        let unlock_idx = entries
            .iter()
            .rposition(|e| matches!(e.event_type, AuditEventType::VaultUnlock))
            .unwrap();
        assert!(trip_idx < unlock_idx);

        // Subsequent unlocks don't re-emit the same trip.
        keep.lock();
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("right-password").unwrap();
        let entries = keep.audit_read_all().unwrap();
        let trip_count = entries
            .iter()
            .filter(|e| matches!(e.event_type, AuditEventType::RateLimitTripped))
            .count();
        assert_eq!(
            trip_count, 1,
            "trip entry must not duplicate on later unlocks"
        );
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

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_frost_ed25519_generate_sign_verify() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        let shares = keep.frost_generate_ed25519(2, 3, "release").unwrap();
        assert_eq!(shares.len(), 3);
        let group_pubkey = *shares[0].group_pubkey();

        let message = b"release artifact v1.0";
        let signature = keep.frost_sign_ed25519(&group_pubkey, message).unwrap();
        assert_eq!(signature.len(), 64);

        Keep::frost_verify_ed25519(&group_pubkey, message, &signature).unwrap();
        assert!(Keep::frost_verify_ed25519(&group_pubkey, b"tampered", &signature).is_err());

        // Shares persisted across reopen carry the Ed25519 ciphersuite tag and
        // still sign after the versioned-blob round-trip through storage.
        drop(keep);
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        let sig2 = keep.frost_sign_ed25519(&group_pubkey, message).unwrap();
        Keep::frost_verify_ed25519(&group_pubkey, message, &sig2).unwrap();
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_frost_ed25519_export_import_sign() {
        let src_dir = tempdir().unwrap();
        let src_path = src_dir.path().join("keep");
        let mut src = test_keep(&src_path);

        let shares = src.frost_generate_ed25519(2, 3, "release").unwrap();
        let group_pubkey = *shares[0].group_pubkey();

        let exports: Vec<_> = shares
            .iter()
            .take(2)
            .map(|s| {
                let export = src
                    .frost_export_share(&group_pubkey, s.metadata.identifier, "transfer-pass")
                    .unwrap();
                assert_eq!(export.ciphersuite, crate::frost::Ciphersuite::Ed25519);
                export
            })
            .collect();

        let dst_dir = tempdir().unwrap();
        let dst_path = dst_dir.path().join("keep");
        let mut dst = test_keep(&dst_path);

        for (i, export) in exports.iter().enumerate() {
            dst.frost_import_share(export, "transfer-pass", &format!("imported-{i}"))
                .unwrap();
        }

        let message = b"exported then imported";
        let sig = dst.frost_sign_ed25519(&group_pubkey, message).unwrap();
        Keep::frost_verify_ed25519(&group_pubkey, message, &sig).unwrap();
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_frost_ed25519_data_key_rotation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        let shares = keep.frost_generate_ed25519(2, 3, "release").unwrap();
        let group_pubkey = *shares[0].group_pubkey();

        // Rotation re-encrypts the inner key package under the ciphersuite AAD
        // and verifies it; an Ed25519 vault must rotate without failing.
        keep.rotate_data_key("testpass").unwrap();

        let message = b"after rotation";
        let sig = keep.frost_sign_ed25519(&group_pubkey, message).unwrap();
        Keep::frost_verify_ed25519(&group_pubkey, message, &sig).unwrap();
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_frost_ed25519_minisign_round_trip() {
        use crate::frost::ed25519::minisign::MinisignSignature;

        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        let shares = keep.frost_generate_ed25519(2, 3, "release").unwrap();
        let group_pubkey = *shares[0].group_pubkey();

        let message = b"release artifact v2.0";
        let sig = keep
            .frost_sign_ed25519_minisign(
                &group_pubkey,
                message,
                "untrusted".into(),
                "trusted:abc".into(),
            )
            .unwrap();

        // Full struct verifies (file + global signatures).
        Keep::frost_verify_ed25519_minisign(&group_pubkey, message, &sig).unwrap();

        // Survives encode/parse round-trip.
        let encoded = sig.encode().unwrap();
        let parsed = MinisignSignature::parse(&encoded).unwrap();
        Keep::frost_verify_ed25519_minisign(&group_pubkey, message, &parsed).unwrap();

        // Tampered message rejected.
        assert!(Keep::frost_verify_ed25519_minisign(&group_pubkey, b"tampered", &parsed).is_err());

        // Tampered trusted comment breaks the global signature.
        let mut bad = MinisignSignature::parse(&encoded).unwrap();
        bad.trusted_comment = "trusted:evil".into();
        assert!(Keep::frost_verify_ed25519_minisign(&group_pubkey, message, &bad).is_err());

        // Wrong group public key fails the key-id check.
        let wrong = [0u8; 32];
        assert!(Keep::frost_verify_ed25519_minisign(&wrong, message, &parsed).is_err());
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_frost_ed25519_minisign_external_binary() {
        use crate::frost::ed25519::minisign::MinisignPublicKey;
        use std::process::Command;

        // Prefer the C minisign binary; fall back to rsign2 (rsign), which is
        // byte-format compatible with minisign. Skip if neither is installed.
        let verifier = if Command::new("minisign").arg("-v").output().is_ok() {
            "minisign"
        } else if Command::new("rsign").arg("--help").output().is_ok() {
            "rsign"
        } else {
            eprintln!("no minisign/rsign binary installed; skipping external cross-check");
            return;
        };

        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        let shares = keep.frost_generate_ed25519(2, 3, "release").unwrap();
        let group_pubkey = *shares[0].group_pubkey();

        let data_path = dir.path().join("artifact.bin");
        std::fs::write(&data_path, b"external minisign cross-check payload").unwrap();
        let message = std::fs::read(&data_path).unwrap();

        let sig = keep
            .frost_sign_ed25519_minisign(
                &group_pubkey,
                &message,
                "keep test".into(),
                "timestamp:0\tfile:artifact.bin".into(),
            )
            .unwrap();
        let sig_path = dir.path().join("artifact.bin.minisig");
        std::fs::write(&sig_path, sig.encode().unwrap()).unwrap();

        let pk = MinisignPublicKey::from_group_pubkey(&group_pubkey, "keep test".into());
        let pk_path = dir.path().join("keep.pub");
        std::fs::write(&pk_path, pk.encode().unwrap()).unwrap();

        let output = match verifier {
            "minisign" => Command::new("minisign")
                .arg("-V")
                .arg("-p")
                .arg(&pk_path)
                .arg("-m")
                .arg(&data_path)
                .output()
                .expect("run minisign -V"),
            _ => Command::new("rsign")
                .arg("verify")
                .arg("-p")
                .arg(&pk_path)
                .arg("-x")
                .arg(&sig_path)
                .arg(&data_path)
                .output()
                .expect("run rsign verify"),
        };
        assert!(
            output.status.success(),
            "external verify ({verifier}) failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
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

    #[test]
    fn test_keep_rotate_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        {
            let mut keep = test_keep(&path);
            keep.generate_key("rotatetest").unwrap();
        }

        {
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("testpass").unwrap();
            keep.rotate_password("testpass", "newpass1").unwrap();
        }

        {
            let mut keep = Keep::open(&path).unwrap();
            assert!(keep.unlock("testpass").is_err());
        }

        {
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("newpass1").unwrap();
            assert!(keep.keyring().get_by_name("rotatetest").is_some());
        }
    }

    #[test]
    fn test_is_valid_hex_pubkey() {
        let valid = "a".repeat(64);
        assert!(is_valid_hex_pubkey(&valid));

        let mixed_hex = "0123456789abcdef".repeat(4);
        assert!(is_valid_hex_pubkey(&mixed_hex));

        // is_ascii_hexdigit accepts A-F; set_active_share_key normalizes
        // to lowercase before persisting.
        let upper = "A".repeat(64);
        assert!(is_valid_hex_pubkey(&upper));

        assert!(!is_valid_hex_pubkey(&"a".repeat(63)));
        assert!(!is_valid_hex_pubkey(&"a".repeat(65)));
        assert!(!is_valid_hex_pubkey(""));
        assert!(!is_valid_hex_pubkey(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ));
    }

    #[test]
    fn test_keep_rotate_data_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");

        let pubkey;
        {
            let mut keep = test_keep(&path);
            pubkey = keep.generate_key("dektest").unwrap();
        }

        {
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("testpass").unwrap();
            keep.rotate_data_key("testpass").unwrap();
            assert!(keep.keyring().get(&pubkey).is_some());
        }

        {
            let mut keep = Keep::open(&path).unwrap();
            keep.unlock("testpass").unwrap();
            let slot = keep.keyring().get(&pubkey).unwrap();
            assert_eq!(slot.name, "dektest");
        }
    }

    // === #566: audit-log entries for rotation security operations ===

    /// `Keep::rotate_password` MUST emit a `PasswordRotate` audit entry on
    /// success. Without this, security-sensitive password rotations leave no
    /// observable trace for the operator or for post-incident review.
    #[test]
    fn rotate_password_emits_success_audit_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        {
            let mut keep = test_keep(&path);
            keep.generate_key("audited").unwrap();
            keep.rotate_password("testpass", "newpass1").unwrap();
            let entries = keep.audit_read_all().unwrap();
            assert!(
                entries
                    .iter()
                    .any(|e| e.event_type == AuditEventType::PasswordRotate),
                "PasswordRotate entry missing from audit log: {:?}",
                entries.iter().map(|e| e.event_type).collect::<Vec<_>>()
            );
        }
        // Re-open with the NEW password to confirm the audit log survived the
        // header rotation and still chain-verifies.
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("newpass1").unwrap();
        keep.audit_verify_chain().unwrap();
        let entries = keep.audit_read_all().unwrap();
        assert!(entries
            .iter()
            .any(|e| e.event_type == AuditEventType::PasswordRotate));
    }

    /// `Keep::rotate_password` MUST emit a `PasswordRotateFailed` audit entry
    /// when the call is rejected, so failed attacker attempts are observable.
    /// Failed attempts on an already-locked vault cannot be recorded (data
    /// key unavailable); this test exercises the unlocked path and uses an
    /// invalid new password as the failure trigger because Storage's
    /// `rotate_password` short-circuits the wrong-old-password check when
    /// the vault is already unlocked (which is the path that admits audit
    /// writes), while `validate_new_password` is enforced unconditionally.
    #[test]
    fn rotate_password_emits_failure_audit_entry_when_unlocked() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);
        keep.generate_key("audited").unwrap();

        let pre = keep.audit_read_all().unwrap().len();

        // Empty new password: validate_new_password rejects.
        assert!(keep.rotate_password("testpass", "").is_err());
        let after_empty = keep.audit_read_all().unwrap();
        assert!(
            after_empty.len() > pre,
            "audit log should grow on empty-new-password rejection"
        );
        let failure = after_empty
            .iter()
            .find(|e| e.event_type == AuditEventType::PasswordRotateFailed)
            .expect("PasswordRotateFailed entry missing after empty-new-password rejection");
        assert!(
            !failure.success,
            "PasswordRotateFailed entry must be marked success=false"
        );
        assert!(
            failure.reason.is_some(),
            "PasswordRotateFailed entry must record a failure reason"
        );

        // Too-short new password: same rejection.
        let pre2 = keep.audit_read_all().unwrap().len();
        assert!(keep.rotate_password("testpass", "a").is_err());
        let entries = keep.audit_read_all().unwrap();
        assert!(
            entries.len() > pre2,
            "audit log should grow on too-short-new-password rejection"
        );
        // The original password still unlocks: failure paths don't corrupt
        // the header. Drop the first handle before reopening so the vault
        // file lock is released.
        drop(keep);
        let mut reopened = Keep::open(&path).unwrap();
        reopened.unlock("testpass").unwrap();
    }

    /// `Keep::rotate_data_key` MUST emit a `DataKeyRotate` audit entry on
    /// success. The entry's payload is encrypted under the NEW data key (the
    /// log gets re-encrypted as part of rotation); this test confirms the
    /// entry is readable after rotation and the chain still verifies.
    #[test]
    fn rotate_data_key_emits_success_audit_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        {
            let mut keep = test_keep(&path);
            keep.generate_key("dek-audit").unwrap();
            keep.rotate_data_key("testpass").unwrap();
            let entries = keep.audit_read_all().unwrap();
            assert!(
                entries
                    .iter()
                    .any(|e| e.event_type == AuditEventType::DataKeyRotate),
                "DataKeyRotate entry missing from audit log: {:?}",
                entries.iter().map(|e| e.event_type).collect::<Vec<_>>()
            );
            // The audit log was re-encrypted under the new data key during
            // rotation; the chain over both pre- and post-rotation entries
            // must remain valid.
            keep.audit_verify_chain().unwrap();
        }
        // Confirm persistence: re-open and the entry is still there.
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        let entries = keep.audit_read_all().unwrap();
        assert!(entries
            .iter()
            .any(|e| e.event_type == AuditEventType::DataKeyRotate));
    }

    // === #581 / #579 / #580: rotation hardening ===

    /// `Keep::rotate_password` MUST reject a wrong `old_password` even when the
    /// vault is already unlocked (#581). Without this, anyone with access to
    /// an unlocked Keep could re-wrap the data key without proving knowledge
    /// of the prior credential.
    #[test]
    fn rotate_password_rejects_wrong_old_password_when_already_unlocked() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        // Vault is unlocked. The rotation should still refuse without the
        // correct old password.
        let err = keep
            .rotate_password("NOT_THE_OLD_PASSWORD", "newpass1")
            .expect_err("wrong old password must be refused even when unlocked");
        let _ = err; // shape varies, pin only on error path

        // The original password still unlocks: failure paths do not corrupt
        // the header.
        drop(keep);
        let mut reopened = Keep::open(&path).unwrap();
        reopened.unlock("testpass").unwrap();
    }

    /// Same gap on `rotate_data_key`: wrong password rejected even when
    /// already unlocked (#581).
    #[test]
    fn rotate_data_key_rejects_wrong_password_when_already_unlocked() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        let err = keep
            .rotate_data_key("WRONG_PASSWORD")
            .expect_err("wrong password must be refused even when unlocked");
        let _ = err;

        drop(keep);
        let mut reopened = Keep::open(&path).unwrap();
        reopened.unlock("testpass").unwrap();
    }

    /// `Keep::rotate_password` MUST emit a `PasswordRotateFailed` audit entry
    /// when the wrong-old-password gate (#581) fires on an unlocked vault.
    /// Without this, an attacker's failed rotation attempts on a hijacked
    /// unlocked Keep would be unobservable.
    #[test]
    fn rotate_password_wrong_old_password_emits_failure_audit_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep");
        let mut keep = test_keep(&path);

        let pre = keep.audit_read_all().unwrap().len();
        assert!(keep
            .rotate_password("WRONG_OLD_PASSWORD", "newpass1")
            .is_err());
        let entries = keep.audit_read_all().unwrap();
        assert!(
            entries.len() > pre,
            "audit log must grow on a rejected rotation"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.event_type == AuditEventType::PasswordRotateFailed),
            "PasswordRotateFailed entry missing after wrong-old-password rejection"
        );
    }

    #[test]
    fn test_default_keep_path_from_env() {
        let abs_path = if cfg!(windows) {
            "C:\\tmp\\my-keep"
        } else {
            "/tmp/my-keep"
        };
        temp_env::with_var("KEEP_HOME", Some(abs_path), || {
            let p = default_keep_path().unwrap();
            assert_eq!(p, PathBuf::from(abs_path));
        });
    }

    #[test]
    fn test_default_keep_path_relative_env_rejected() {
        temp_env::with_var("KEEP_HOME", Some("relative/path"), || {
            let result = default_keep_path();
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_default_keep_path_empty_env_falls_back() {
        temp_env::with_var("KEEP_HOME", Some(""), || {
            let p = default_keep_path().unwrap();
            let expected = dirs::home_dir().unwrap().join(".keep");
            assert_eq!(p, expected);
        });
    }

    #[test]
    fn test_default_keep_path_blank_env_falls_back() {
        temp_env::with_var("KEEP_HOME", Some("   "), || {
            let p = default_keep_path().unwrap();
            let expected = dirs::home_dir().unwrap().join(".keep");
            assert_eq!(p, expected);
        });
    }
}
