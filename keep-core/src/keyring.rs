// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-memory keyring for managing unlocked keys.
use std::collections::HashMap;

use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use crate::error::{KeepError, Result};
use crate::keys::{KeyType, NostrKeypair};

/// Maximum number of keys that can be held in the keyring.
pub const MAX_KEYS: usize = 64;

/// A single key slot in the keyring.
pub struct KeySlot {
    /// The public key bytes.
    pub pubkey: [u8; 32],
    secret: SecretBox<[u8; 32]>,
    /// The type of key (Nostr, Bitcoin, FrostShare).
    pub key_type: KeyType,
    /// Human-readable name for this key.
    pub name: String,
    /// Number of signatures made in this session.
    pub session_sign_count: u64,
}

impl KeySlot {
    /// Create a new key slot.
    pub fn new(pubkey: [u8; 32], secret: [u8; 32], key_type: KeyType, name: String) -> Self {
        Self {
            pubkey,
            secret: SecretBox::new(Box::new(secret)),
            key_type,
            name,
            session_sign_count: 0,
        }
    }

    /// Access the secret key bytes.
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.secret.expose_secret()
    }

    /// Convert this slot to a NostrKeypair.
    pub fn to_nostr_keypair(&self) -> Result<NostrKeypair> {
        let mut secret_copy = *self.secret.expose_secret();
        let result = NostrKeypair::from_secret_bytes(&mut secret_copy);
        secret_copy.zeroize();
        result
    }
}

/// In-memory collection of unlocked keys.
pub struct Keyring {
    slots: HashMap<[u8; 32], KeySlot>,
    primary: Option<[u8; 32]>,
}

impl Keyring {
    /// Create a new empty keyring.
    pub fn new() -> Self {
        Self {
            slots: HashMap::new(),
            primary: None,
        }
    }

    /// Load a key into the keyring.
    pub fn load_key(
        &mut self,
        pubkey: [u8; 32],
        secret: [u8; 32],
        key_type: KeyType,
        name: String,
    ) -> Result<()> {
        if self.slots.len() >= MAX_KEYS {
            return Err(KeepError::KeyringFull(MAX_KEYS));
        }

        if self.slots.contains_key(&pubkey) {
            return Err(KeepError::KeyAlreadyExists(hex::encode(pubkey)));
        }

        let slot = KeySlot::new(pubkey, secret, key_type, name);
        self.slots.insert(pubkey, slot);

        if self.primary.is_none() {
            self.primary = Some(pubkey);
        }

        Ok(())
    }

    /// Get a key slot by public key, if present.
    pub fn get(&self, pubkey: &[u8; 32]) -> Option<&KeySlot> {
        self.slots.get(pubkey)
    }

    /// Get a mutable key slot by public key, if present.
    pub fn get_mut(&mut self, pubkey: &[u8; 32]) -> Option<&mut KeySlot> {
        self.slots.get_mut(pubkey)
    }

    /// Get a key slot by name, if present.
    pub fn get_by_name(&self, name: &str) -> Option<&KeySlot> {
        self.slots.values().find(|slot| slot.name == name)
    }

    /// Get the primary key slot, if set.
    pub fn get_primary(&self) -> Option<&KeySlot> {
        self.primary.and_then(|pk| self.slots.get(&pk))
    }

    /// Get a mutable reference to the primary key slot, if set.
    pub fn get_primary_mut(&mut self) -> Option<&mut KeySlot> {
        if let Some(pk) = self.primary {
            self.slots.get_mut(&pk)
        } else {
            None
        }
    }

    /// Set the primary key.
    pub fn set_primary(&mut self, pubkey: [u8; 32]) -> Result<()> {
        if !self.slots.contains_key(&pubkey) {
            return Err(KeepError::KeyNotFound(hex::encode(pubkey)));
        }
        self.primary = Some(pubkey);
        Ok(())
    }

    /// Remove a key by public key.
    pub fn remove(&mut self, pubkey: &[u8; 32]) -> Result<()> {
        if self.slots.remove(pubkey).is_none() {
            return Err(KeepError::KeyNotFound(hex::encode(pubkey)));
        }

        if self.primary == Some(*pubkey) {
            self.primary = self.slots.keys().next().copied();
        }

        Ok(())
    }

    /// Iterate over all key slots.
    pub fn list(&self) -> impl Iterator<Item = &KeySlot> {
        self.slots.values()
    }

    /// Number of keys loaded.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Returns true if no keys are loaded.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Clear all loaded keys.
    pub fn clear(&mut self) {
        self.slots.clear();
        self.primary = None;
    }
}

impl Default for Keyring {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Keyring {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn test_keyring_basic() {
        let mut kr = Keyring::new();

        let pubkey: [u8; 32] = crypto::random_bytes();
        let secret: [u8; 32] = crypto::random_bytes();

        kr.load_key(pubkey, secret, KeyType::Nostr, "test".into())
            .unwrap();

        assert_eq!(kr.len(), 1);
        assert!(kr.get(&pubkey).is_some());
        assert!(kr.get_primary().is_some());
    }

    #[test]
    fn test_keyring_max_keys() {
        let mut kr = Keyring::new();

        for i in 0..MAX_KEYS {
            let mut pubkey: [u8; 32] = [0; 32];
            pubkey[0] = i as u8;
            let secret: [u8; 32] = crypto::random_bytes();

            kr.load_key(pubkey, secret, KeyType::Nostr, format!("key{i}"))
                .unwrap();
        }

        let pubkey: [u8; 32] = crypto::random_bytes();
        let secret: [u8; 32] = crypto::random_bytes();
        let result = kr.load_key(pubkey, secret, KeyType::Nostr, "overflow".into());

        assert!(matches!(result, Err(KeepError::KeyringFull(_))));
    }
}
