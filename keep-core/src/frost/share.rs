// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! FROST share types and encrypted storage.

use frost_secp256k1_tr::{
    keys::{KeyPackage, PublicKeyPackage},
    Identifier,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{self, SecretKey};
use crate::error::{KeepError, Result};

/// The FROST ciphersuite a share belongs to.
///
/// The discriminant is bound into the AEAD associated data when a share is
/// encrypted (see [`StoredShare`]), so it cannot be flipped or stripped to force
/// cross-ciphersuite confusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Ciphersuite {
    /// FROST over secp256k1 with Taproot (BIP-340) — the Bitcoin/Nostr path.
    #[default]
    Secp256k1Tr,
    /// FROST over Ed25519.
    Ed25519,
}

impl Ciphersuite {
    /// Associated data binding this ciphersuite into the share's AEAD envelope.
    ///
    /// `Secp256k1Tr` intentionally maps to an empty AAD so that shares written
    /// before the ciphersuite tag existed (and the live Bitcoin path) remain
    /// byte-identical and continue to decrypt.
    pub(crate) fn aad(self) -> &'static [u8] {
        match self {
            Ciphersuite::Secp256k1Tr => &[],
            Ciphersuite::Ed25519 => b"keep-frost-ciphersuite:ed25519",
        }
    }
}

/// Metadata for a FROST share.
#[derive(Clone, Serialize, Deserialize)]
pub struct ShareMetadata {
    /// Share identifier (1-indexed).
    pub identifier: u16,
    /// Threshold required to sign.
    pub threshold: u16,
    /// Total number of shares.
    pub total_shares: u16,
    /// The group public key (x-only, 32 bytes).
    pub group_pubkey: [u8; 32],
    /// Human-readable name.
    pub name: String,
    /// Unix timestamp when created.
    pub created_at: i64,
    /// Unix timestamp of last use.
    pub last_used: Option<i64>,
    /// Number of signatures made.
    pub sign_count: u64,
    /// Whether this share has been backed up.
    #[serde(default)]
    pub did_backup: bool,
}

impl ShareMetadata {
    /// Create new share metadata.
    pub fn new(
        identifier: u16,
        threshold: u16,
        total_shares: u16,
        group_pubkey: [u8; 32],
        name: String,
    ) -> Self {
        Self {
            identifier,
            threshold,
            total_shares,
            group_pubkey,
            name,
            created_at: chrono::Utc::now().timestamp(),
            last_used: None,
            sign_count: 0,
            did_backup: false,
        }
    }

    /// Record usage timestamp.
    pub fn record_usage(&mut self) {
        self.last_used = Some(chrono::Utc::now().timestamp());
    }

    /// Mark this share as backed up.
    pub fn mark_backed_up(&mut self) {
        self.did_backup = true;
    }

    /// Increment signature count and record usage.
    pub fn increment_sign_count(&mut self) {
        self.sign_count += 1;
        self.record_usage();
    }
}

/// A FROST key share with metadata.
///
/// Contains the secret key package (zeroized on drop) and public key package.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharePackage {
    /// Share metadata.
    #[zeroize(skip)]
    pub metadata: ShareMetadata,
    key_package_bytes: Vec<u8>,
    #[zeroize(skip)]
    pubkey_package_bytes: Vec<u8>,
}

impl SharePackage {
    /// Create a new share package from FROST key packages.
    pub fn new(
        metadata: ShareMetadata,
        key_package: &KeyPackage,
        pubkey_package: &PublicKeyPackage,
    ) -> Result<Self> {
        let key_package_bytes = key_package
            .serialize()
            .map_err(|e| KeepError::Frost(format!("Failed to serialize key package: {e}")))?;

        let pubkey_package_bytes = pubkey_package
            .serialize()
            .map_err(|e| KeepError::Frost(format!("Failed to serialize pubkey package: {e}")))?;

        Ok(Self {
            metadata,
            key_package_bytes,
            pubkey_package_bytes,
        })
    }

    /// Create a share package from already-serialized package bytes.
    ///
    /// Used by ciphersuites whose package types are not the secp256k1 ones.
    pub fn from_bytes(
        metadata: ShareMetadata,
        key_package_bytes: Vec<u8>,
        pubkey_package_bytes: Vec<u8>,
    ) -> Self {
        Self {
            metadata,
            key_package_bytes,
            pubkey_package_bytes,
        }
    }

    /// The serialized key package bytes.
    pub fn key_package_bytes(&self) -> &[u8] {
        &self.key_package_bytes
    }

    /// The serialized public key package bytes.
    pub fn pubkey_package_bytes(&self) -> &[u8] {
        &self.pubkey_package_bytes
    }

    /// Deserialize and return the key package.
    pub fn key_package(&self) -> Result<KeyPackage> {
        KeyPackage::deserialize(&self.key_package_bytes)
            .map_err(|e| KeepError::Frost(format!("Failed to deserialize key package: {e}")))
    }

    /// Deserialize and return the public key package.
    pub fn pubkey_package(&self) -> Result<PublicKeyPackage> {
        PublicKeyPackage::deserialize(&self.pubkey_package_bytes)
            .map_err(|e| KeepError::Frost(format!("Failed to deserialize pubkey package: {e}")))
    }

    /// The FROST identifier for this share.
    pub fn identifier(&self) -> Result<Identifier> {
        let kp = self.key_package()?;
        Ok(*kp.identifier())
    }

    /// The group public key.
    pub fn group_pubkey(&self) -> &[u8; 32] {
        &self.metadata.group_pubkey
    }
}

/// An encrypted share for persistent storage.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredShare {
    /// Share metadata.
    pub metadata: ShareMetadata,
    /// Encrypted key package bytes.
    pub encrypted_key_package: Vec<u8>,
    /// Public key package bytes.
    pub pubkey_package: Vec<u8>,
    /// FROST ciphersuite of this share.
    ///
    /// Defaults to `Secp256k1Tr` so shares written before this field existed
    /// load unchanged. The value is authenticated via the AEAD associated data
    /// of `encrypted_key_package`, so it cannot be flipped without MAC failure.
    #[serde(default)]
    pub ciphersuite: Ciphersuite,
}

impl StoredShare {
    /// Encrypt a secp256k1 share package for storage.
    pub fn encrypt(share: &SharePackage, data_key: &SecretKey) -> Result<Self> {
        Self::encrypt_with_ciphersuite(share, Ciphersuite::Secp256k1Tr, data_key)
    }

    /// Encrypt a share package for storage, binding the given ciphersuite.
    pub fn encrypt_with_ciphersuite(
        share: &SharePackage,
        ciphersuite: Ciphersuite,
        data_key: &SecretKey,
    ) -> Result<Self> {
        let encrypted =
            crypto::encrypt_with_aad(&share.key_package_bytes, ciphersuite.aad(), data_key)?;

        Ok(Self {
            metadata: share.metadata.clone(),
            encrypted_key_package: encrypted.to_bytes(),
            pubkey_package: share.pubkey_package_bytes.clone(),
            ciphersuite,
        })
    }

    /// Decrypt and return the share package.
    pub fn decrypt(&self, data_key: &SecretKey) -> Result<SharePackage> {
        let encrypted = crypto::EncryptedData::from_bytes(&self.encrypted_key_package)?;
        let decrypted = crypto::decrypt_with_aad(&encrypted, self.ciphersuite.aad(), data_key)?;
        let key_package_bytes = decrypted.as_slice()?;

        Ok(SharePackage {
            metadata: self.metadata.clone(),
            key_package_bytes: key_package_bytes.to_vec(),
            pubkey_package_bytes: self.pubkey_package.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;
    use serde::{Deserialize, Serialize};

    fn sample_metadata() -> ShareMetadata {
        ShareMetadata::new(1, 2, 3, [7u8; 32], "test".into())
    }

    fn sample_package() -> SharePackage {
        SharePackage::from_bytes(sample_metadata(), vec![1, 2, 3, 4], vec![9, 9, 9])
    }

    #[test]
    fn test_default_ciphersuite_is_secp256k1() {
        assert_eq!(Ciphersuite::default(), Ciphersuite::Secp256k1Tr);
        assert!(Ciphersuite::Secp256k1Tr.aad().is_empty());
        assert!(!Ciphersuite::Ed25519.aad().is_empty());
    }

    #[test]
    fn test_secp256k1_envelope_byte_identical() {
        // The secp256k1 path uses empty AAD, so the ciphertext is byte-for-byte
        // what plain `crypto::encrypt` would have produced for the same key+nonce.
        let key = SecretKey::generate().unwrap();
        let pkg = sample_package();

        let stored = StoredShare::encrypt(&pkg, &key).unwrap();
        assert_eq!(stored.ciphersuite, Ciphersuite::Secp256k1Tr);

        let restored = stored.decrypt(&key).unwrap();
        assert_eq!(restored.key_package_bytes(), pkg.key_package_bytes());

        // A blob produced via the no-AAD primitive must also decrypt under the
        // secp256k1 (empty-AAD) path, proving envelope compatibility.
        let raw = crypto::encrypt(pkg.key_package_bytes(), &key).unwrap();
        let legacy = StoredShare {
            metadata: sample_metadata(),
            encrypted_key_package: raw.to_bytes(),
            pubkey_package: pkg.pubkey_package_bytes().to_vec(),
            ciphersuite: Ciphersuite::Secp256k1Tr,
        };
        let restored = legacy.decrypt(&key).unwrap();
        assert_eq!(restored.key_package_bytes(), pkg.key_package_bytes());
    }

    // Mirrors the pre-change StoredShare field layout (no ciphersuite tag).
    #[derive(Serialize, Deserialize)]
    struct LegacyStoredShare {
        metadata: ShareMetadata,
        encrypted_key_package: Vec<u8>,
        pubkey_package: Vec<u8>,
    }

    #[test]
    fn test_old_bincode_blob_is_not_self_describing() {
        // Documents why the storage layer needs an explicit legacy fallback:
        // bincode cannot fill a `#[serde(default)]` trailing field from an old
        // blob that lacks it. The recovery path is tested in storage.rs.
        use bincode::Options;

        let legacy = LegacyStoredShare {
            metadata: sample_metadata(),
            encrypted_key_package: vec![0u8; 40],
            pubkey_package: vec![9, 9, 9],
        };

        let opts = || {
            bincode::options()
                .with_fixint_encoding()
                .allow_trailing_bytes()
        };
        let blob = opts().serialize(&legacy).unwrap();

        assert!(opts().deserialize::<StoredShare>(&blob).is_err());
    }
}
