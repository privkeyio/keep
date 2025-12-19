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

#[derive(Clone, Serialize, Deserialize)]
pub struct ShareMetadata {
    pub identifier: u16,
    pub threshold: u16,
    pub total_shares: u16,
    pub group_pubkey: [u8; 32],
    pub name: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub sign_count: u64,
}

impl ShareMetadata {
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

    pub fn record_usage(&mut self) {
        self.last_used = Some(chrono::Utc::now().timestamp());
    }

    pub fn increment_sign_count(&mut self) {
        self.sign_count += 1;
        self.record_usage();
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharePackage {
    #[zeroize(skip)]
    pub metadata: ShareMetadata,
    key_package_bytes: Vec<u8>,
    #[zeroize(skip)]
    pubkey_package_bytes: Vec<u8>,
}

impl SharePackage {
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

    pub fn key_package(&self) -> Result<KeyPackage> {
        KeyPackage::deserialize(&self.key_package_bytes)
            .map_err(|e| KeepError::Frost(format!("Failed to deserialize key package: {}", e)))
    }

    pub fn pubkey_package(&self) -> Result<PublicKeyPackage> {
        PublicKeyPackage::deserialize(&self.pubkey_package_bytes)
            .map_err(|e| KeepError::Frost(format!("Failed to deserialize pubkey package: {}", e)))
    }

    pub fn identifier(&self) -> Result<Identifier> {
        let kp = self.key_package()?;
        Ok(*kp.identifier())
    }

    pub fn group_pubkey(&self) -> &[u8; 32] {
        &self.metadata.group_pubkey
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredShare {
    pub metadata: ShareMetadata,
    pub encrypted_key_package: Vec<u8>,
    pub pubkey_package: Vec<u8>,
}

impl StoredShare {
    pub fn encrypt(share: &SharePackage, data_key: &SecretKey) -> Result<Self> {
        let encrypted = crypto::encrypt(&share.key_package_bytes, data_key)?;

        Ok(Self {
            metadata: share.metadata.clone(),
            encrypted_key_package: encrypted.to_bytes(),
            pubkey_package: share.pubkey_package_bytes.clone(),
        })
    }

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
