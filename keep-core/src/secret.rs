// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! Arbitrary-secret records (passwords, API tokens, notes) stored in the vault
//! alongside curve-key records.
//!
//! The vault below the record model is already secret-agnostic: the storage
//! backend is a plain encrypted key-value store and [`crate::crypto`] encrypts
//! arbitrary bytes, so storing generic secrets is an additive extension rather
//! than a new subsystem. A [`SecretRecord`] is bincode-serialized as a whole --
//! name, kind, AND the plaintext value -- then encrypted under the vault data
//! key at rest (see [`crate::storage::Storage::store_secret`]), so entry titles
//! are encrypted, not just the value. The plaintext `value` exists decrypted
//! only in memory and is scrubbed on drop.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::entropy;

/// Category of a stored secret. Additive: only APPEND new variants, so a record
/// written by an older build keeps decoding under bincode's integer tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretKind {
    /// A login password.
    Password,
    /// An API token or other bearer credential.
    ApiToken,
    /// A free-form secret note.
    Note,
    /// Any other secret material that does not fit the categories above.
    Generic,
}

/// A stored arbitrary secret sitting alongside curve-key records in the vault.
///
/// Unlike [`crate::keys::KeyRecord`], whose `id` is derived from a public key
/// (stable identity and dedup for free), a secret has no public key, so `id` is
/// random. Importing the same secret twice therefore creates two distinct rows.
/// This is intended for a password store, where two logins can legitimately
/// share one value; callers that need dedup must do it themselves.
///
/// Every field except the identity/metadata is zeroized on drop. `id`, `kind`,
/// and the timestamps are not secret and are skipped; `name` and `value` are
/// scrubbed because an entry title reveals what the secret is for.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretRecord {
    /// Random 32-byte identifier (a secret has no pubkey to derive one from),
    /// used as the storage key.
    #[zeroize(skip)]
    pub id: [u8; 32],
    /// Human-readable title (e.g. "GitHub login"). Sensitive: encrypted at rest
    /// with the value, and scrubbed from memory on drop.
    pub name: String,
    /// Category of secret.
    #[zeroize(skip)]
    pub kind: SecretKind,
    /// The plaintext secret bytes. Encrypted at rest via the record's outer
    /// encryption; held decrypted only in memory and scrubbed on drop.
    pub value: Vec<u8>,
    /// Unix timestamp when the secret was created.
    #[zeroize(skip)]
    pub created_at: i64,
    /// Unix timestamp of the last update.
    #[zeroize(skip)]
    pub updated_at: i64,
}

impl SecretRecord {
    /// Create a new secret record with a fresh random id and `created_at ==
    /// updated_at == now`.
    pub fn new(name: String, kind: SecretKind, value: Vec<u8>) -> Self {
        let id: [u8; 32] = entropy::random_bytes();
        let now = chrono::Utc::now().timestamp();
        Self {
            id,
            name,
            kind,
            value,
            created_at: now,
            updated_at: now,
        }
    }
}

impl std::fmt::Debug for SecretRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print `name` or `value`: both are secret. `name` leaks what the
        // secret is for; `value` is the secret itself.
        f.debug_struct("SecretRecord")
            .field("id", &hex::encode(self.id))
            .field("kind", &self.kind)
            .field("name", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_mints_a_random_id_and_equal_timestamps() {
        let a = SecretRecord::new("x".into(), SecretKind::Password, b"v".to_vec());
        let b = SecretRecord::new("x".into(), SecretKind::Password, b"v".to_vec());
        assert_ne!(a.id, b.id, "each secret gets a fresh random id");
        assert_eq!(a.created_at, a.updated_at);
    }

    #[test]
    fn debug_never_leaks_name_or_value() {
        let rec = SecretRecord::new(
            "GitHub login".into(),
            SecretKind::Password,
            b"hunter2".to_vec(),
        );
        let s = format!("{rec:?}");
        assert!(!s.contains("GitHub login"), "name must be redacted: {s}");
        assert!(!s.contains("hunter2"), "value must be redacted: {s}");
        assert!(s.contains("[REDACTED]"));
    }
}
