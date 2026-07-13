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
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{self, EncryptedData, SecretKey};
use crate::entropy;
use crate::error::Result;

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
    /// updated_at == now`. Returns `Err` (rather than panicking) if the CSPRNG
    /// health check fails, so a broken RNG cannot crash the process here.
    pub fn new(name: String, kind: SecretKind, value: Vec<u8>) -> Result<Self> {
        let id: [u8; 32] = entropy::try_random_bytes()?;
        let now = chrono::Utc::now().timestamp();
        Ok(Self {
            id,
            name,
            kind,
            value,
            created_at: now,
            updated_at: now,
        })
    }
}

/// The threshold seal that gates a secret's VALUE behind a t-of-n OPRF quorum.
///
/// The value is encrypted under a fresh random per-secret data-encryption key
/// (DEK); the DEK is itself encrypted ("wrapped") under the OPRF-quorum-derived
/// key ([`crate::oprf::derive_luks_key`]). Recovering the plaintext therefore
/// requires re-deriving the OPRF key, which needs a t-of-n quorum of devices --
/// a single device that never assembles the quorum cannot decrypt the value even
/// with the vault unlocked. Only the value is gated; a secret's name and kind
/// stay readable with the vault data key so the store remains browsable.
///
/// `wrapped_dek` is ciphertext, so the seal is not itself secret, but it is
/// stored encrypted under the vault data key at rest like every other record.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ThresholdSeal {
    /// The per-secret DEK, encrypted under the OPRF-quorum-derived key
    /// ([`EncryptedData::to_bytes`] output).
    pub wrapped_dek: Vec<u8>,
    /// OPRF domain-separation label fed to `derive_luks_key` (the secret id, hex),
    /// so the quorum re-derives the same key for this secret.
    #[zeroize(skip)]
    pub oprf_id: String,
    /// OPRF epoch: the rotation counter for the derived key, bumped to re-seal a
    /// secret under a fresh key without changing the OPRF root.
    #[zeroize(skip)]
    pub epoch: u32,
}

impl std::fmt::Debug for ThresholdSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdSeal")
            .field("oprf_id", &self.oprf_id)
            .field("epoch", &self.epoch)
            .field("wrapped_dek", &"[wrapped]")
            .finish()
    }
}

/// AAD binding the wrapped DEK to its secret id and OPRF epoch, so a wrapped DEK
/// cannot be lifted onto a different secret or a tampered epoch: altering the
/// stored `oprf_id`/`epoch` (which an attacker holding the vault data key could
/// otherwise do to redirect the quorum query) makes the unwrap fail rather than
/// silently succeed. Length-prefixed for injectivity, matching `derive_luks_key`.
fn wrap_aad(oprf_id: &str, epoch: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(23 + 8 + oprf_id.len() + 4);
    aad.extend_from_slice(b"keep/secret-seal/dek/v1");
    aad.extend_from_slice(&(oprf_id.len() as u64).to_be_bytes());
    aad.extend_from_slice(oprf_id.as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// AAD binding the value ciphertext to its secret id, so a value blob cannot be
/// swapped between secrets.
fn value_aad(oprf_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(25 + oprf_id.len());
    aad.extend_from_slice(b"keep/secret-seal/value/v1");
    aad.extend_from_slice(oprf_id.as_bytes());
    aad
}

/// Seal `plaintext` under a fresh per-secret DEK and wrap that DEK under
/// `oprf_key` (the t-of-n OPRF-quorum-derived key). Returns the value ciphertext
/// (to store as the record's `value`) and the matching [`ThresholdSeal`] (to
/// store alongside). `oprf_id`/`epoch` are recorded in the seal so the quorum can
/// later re-derive the same key, and are bound into both ciphertexts as AAD.
pub fn seal_value(
    plaintext: &[u8],
    oprf_key: &SecretKey,
    oprf_id: String,
    epoch: u32,
) -> Result<(Vec<u8>, ThresholdSeal)> {
    let dek = SecretKey::generate()?;
    let value_ciphertext =
        crypto::encrypt_with_aad(plaintext, &value_aad(&oprf_id), &dek)?.to_bytes();
    // Wrap the raw DEK bytes under the OPRF key. `decrypt` returns an mlocked,
    // zeroize-on-drop copy of the 32 DEK bytes.
    let dek_raw = dek.decrypt()?;
    let wrapped_dek =
        crypto::encrypt_with_aad(&dek_raw[..], &wrap_aad(&oprf_id, epoch), oprf_key)?.to_bytes();
    Ok((
        value_ciphertext,
        ThresholdSeal {
            wrapped_dek,
            oprf_id,
            epoch,
        },
    ))
}

/// Recover a sealed secret's plaintext from `value_ciphertext` given its
/// [`ThresholdSeal`] and the OPRF-quorum-derived key. Fails if `oprf_key` is
/// wrong (a single-device caller that never assembled the quorum cannot derive
/// it) or if the seal's bound `oprf_id`/`epoch` were tampered with: either way
/// the AEAD tag check fails and the value stays sealed.
pub fn unseal_value(
    value_ciphertext: &[u8],
    seal: &ThresholdSeal,
    oprf_key: &SecretKey,
) -> Result<Zeroizing<Vec<u8>>> {
    let wrapped = EncryptedData::from_bytes(&seal.wrapped_dek)?;
    let dek_bytes =
        crypto::decrypt_with_aad(&wrapped, &wrap_aad(&seal.oprf_id, seal.epoch), oprf_key)?
            .as_slice()?;
    let dek = SecretKey::from_slice(&dek_bytes)?;
    let value = EncryptedData::from_bytes(value_ciphertext)?;
    crypto::decrypt_with_aad(&value, &value_aad(&seal.oprf_id), &dek)?.as_slice()
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
        let a = SecretRecord::new("x".into(), SecretKind::Password, b"v".to_vec()).unwrap();
        let b = SecretRecord::new("x".into(), SecretKind::Password, b"v".to_vec()).unwrap();
        assert_ne!(a.id, b.id, "each secret gets a fresh random id");
        assert_eq!(a.created_at, a.updated_at);
    }

    #[test]
    fn seal_then_unseal_roundtrips_with_the_same_key() {
        let oprf_key = SecretKey::generate().unwrap();
        let (ct, seal) = seal_value(b"top-secret", &oprf_key, "abcd".into(), 0).unwrap();
        assert_ne!(ct, b"top-secret", "value must be encrypted, not stored raw");
        let plaintext = unseal_value(&ct, &seal, &oprf_key).unwrap();
        assert_eq!(&plaintext[..], b"top-secret");
        assert_eq!(seal.oprf_id, "abcd");
        assert_eq!(seal.epoch, 0);
    }

    /// The core threshold property: without the quorum-derived key (a single
    /// device that never assembled t-of-n), the wrapped DEK cannot be recovered,
    /// so the value stays sealed.
    #[test]
    fn unseal_fails_with_a_different_oprf_key() {
        let oprf_key = SecretKey::generate().unwrap();
        let wrong_key = SecretKey::generate().unwrap();
        let (ct, seal) = seal_value(b"top-secret", &oprf_key, "abcd".into(), 0).unwrap();
        assert!(
            unseal_value(&ct, &seal, &wrong_key).is_err(),
            "unsealing with the wrong OPRF key must fail"
        );
    }

    /// The seal's `oprf_id`/`epoch` are bound as AAD, so tampering with either
    /// (an attacker with the vault data key redirecting the quorum query) makes
    /// the unseal fail rather than silently proceed.
    #[test]
    fn unseal_fails_when_bound_oprf_params_are_tampered() {
        let oprf_key = SecretKey::generate().unwrap();
        let (ct, seal) = seal_value(b"v", &oprf_key, "abcd".into(), 0).unwrap();

        let mut bad_epoch = seal.clone();
        bad_epoch.epoch = 1;
        assert!(
            unseal_value(&ct, &bad_epoch, &oprf_key).is_err(),
            "a tampered epoch must break the wrapped-DEK AAD"
        );

        let mut bad_id = seal.clone();
        bad_id.oprf_id = "ffff".into();
        assert!(
            unseal_value(&ct, &bad_id, &oprf_key).is_err(),
            "a tampered oprf_id must break the AAD"
        );
    }

    #[test]
    fn each_seal_uses_a_distinct_dek() {
        let oprf_key = SecretKey::generate().unwrap();
        let (_, seal_a) = seal_value(b"v", &oprf_key, "a".into(), 0).unwrap();
        let (_, seal_b) = seal_value(b"v", &oprf_key, "b".into(), 0).unwrap();
        assert_ne!(
            seal_a.wrapped_dek, seal_b.wrapped_dek,
            "each secret must get a fresh random DEK"
        );
    }

    #[test]
    fn threshold_seal_debug_never_leaks_wrapped_dek() {
        let oprf_key = SecretKey::generate().unwrap();
        let (_, seal) = seal_value(b"v", &oprf_key, "abcd".into(), 3).unwrap();
        let s = format!("{seal:?}");
        assert!(s.contains("abcd") && s.contains('3'));
        assert!(!s.contains(&hex::encode(&seal.wrapped_dek)));
    }

    #[test]
    fn debug_never_leaks_name_or_value() {
        let rec = SecretRecord::new(
            "GitHub login".into(),
            SecretKind::Password,
            b"hunter2".to_vec(),
        )
        .unwrap();
        let s = format!("{rec:?}");
        assert!(!s.contains("GitHub login"), "name must be redacted: {s}");
        assert!(!s.contains("hunter2"), "value must be redacted: {s}");
        assert!(s.contains("[REDACTED]"));
    }
}
