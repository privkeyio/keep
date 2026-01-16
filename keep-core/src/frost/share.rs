// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! FROST share types and encrypted storage.

#![forbid(unsafe_code)]
#![allow(unused_assignments)]

use frost_secp256k1_tr::{
    keys::{KeyPackage, PublicKeyPackage},
    Identifier,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{self, SecretKey};
use crate::error::{KeepError, Result};

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
        }
    }

    /// Record usage timestamp.
    pub fn record_usage(&mut self) {
        self.last_used = Some(chrono::Utc::now().timestamp());
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
            .map_err(|e| KeepError::Frost(format!("Failed to serialize key package: {}", e)))?;

        let pubkey_package_bytes = pubkey_package
            .serialize()
            .map_err(|e| KeepError::Frost(format!("Failed to serialize pubkey package: {}", e)))?;

        Ok(Self {
            metadata,
            key_package_bytes,
            pubkey_package_bytes,
        })
    }

    /// Deserialize and return the key package.
    pub fn key_package(&self) -> Result<KeyPackage> {
        KeyPackage::deserialize(&self.key_package_bytes)
            .map_err(|e| KeepError::Frost(format!("Failed to deserialize key package: {}", e)))
    }

    /// Deserialize and return the public key package.
    pub fn pubkey_package(&self) -> Result<PublicKeyPackage> {
        PublicKeyPackage::deserialize(&self.pubkey_package_bytes)
            .map_err(|e| KeepError::Frost(format!("Failed to deserialize pubkey package: {}", e)))
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
}

impl StoredShare {
    /// Encrypt a share package for storage.
    pub fn encrypt(share: &SharePackage, data_key: &SecretKey) -> Result<Self> {
        let encrypted = crypto::encrypt(&share.key_package_bytes, data_key)?;

        Ok(Self {
            metadata: share.metadata.clone(),
            encrypted_key_package: encrypted.to_bytes(),
            pubkey_package: share.pubkey_package_bytes.clone(),
        })
    }

    /// Decrypt and return the share package.
    pub fn decrypt(&self, data_key: &SecretKey) -> Result<SharePackage> {
        let encrypted = crypto::EncryptedData::from_bytes(&self.encrypted_key_package)?;
        let decrypted = crypto::decrypt(&encrypted, data_key)?;
        let key_package_bytes = decrypted.as_slice()?;

        Ok(SharePackage {
            metadata: self.metadata.clone(),
            key_package_bytes,
            pubkey_package_bytes: self.pubkey_package.clone(),
        })
    }
}
