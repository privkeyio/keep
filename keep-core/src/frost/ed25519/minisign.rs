// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! minisign-compatible detached signatures and public keys.
//!
//! Implements the on-disk container format used by the standard, audited
//! [`minisign`](https://jedisct1.github.io/minisign/) tool so that third
//! parties can verify FROST-Ed25519 threshold release signatures with
//! `minisign -V` without trusting this implementation.
//!
//! # Signature file layout (4 lines)
//!
//! ```text
//! untrusted comment: <text>
//! base64( sig_alg[2] || key_id[8] || ed25519_signature[64] )
//! trusted comment: <text>
//! base64( ed25519_global_signature[64] )
//! ```
//!
//! - `sig_alg` is `"Ed"` for a signature over the raw file, or `"ED"` for a
//!   signature over the BLAKE2b-512 prehash of the file. We use `"ED"`
//!   (prehashed) to match the default of current minisign releases; this lets
//!   the file be streamed/hashed once and keeps the signed message a fixed
//!   64 bytes regardless of file size.
//! - The global signature is an Ed25519 signature over
//!   `ed25519_signature[64] || trusted_comment_bytes`, binding the trusted
//!   comment to the signature so it cannot be altered post-hoc. Both the file
//!   signature and the global signature are produced by the FROST threshold
//!   group (two threshold signing sessions per `sign`).
//!
//! # Public key file layout (2 lines)
//!
//! ```text
//! untrusted comment: <text>
//! base64( "Ed"[2] || key_id[8] || ed25519_public_key[32] )
//! ```
//!
//! The public-key algorithm field is always `"Ed"` in minisign; the `Ed`/`ED`
//! distinction lives only in the signature.
//!
//! # key_id derivation
//!
//! minisign stores a random 8-byte key id in the secret/public key and copies
//! it into each signature so a verifier can reject a signature made by the
//! wrong key. We have no persistent secret-key file to carry a random id, so we
//! derive a stable id deterministically from the group verifying key:
//!
//! ```text
//! key_id = BLAKE2b-512( "keep-frost-ed25519-minisign-keyid-v1" || group_pubkey[32] )[..8]
//! ```
//!
//! The id is purely an anti-mixup hint; it is not security-relevant (the
//! Ed25519 verification over the actual public key is what provides security),
//! so a deterministic, collision-resistant derivation is sufficient and gives a
//! stable id for a given group.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use blake2::{Blake2b512, Digest};

use crate::error::{KeepError, Result};

const KEY_ID_DOMAIN: &[u8] = b"keep-frost-ed25519-minisign-keyid-v1";

/// Signature algorithm: raw-message Ed25519 (`"Ed"`).
pub const ALG_LEGACY: [u8; 2] = *b"Ed";
/// Signature algorithm: BLAKE2b-512 prehashed Ed25519 (`"ED"`).
pub const ALG_PREHASHED: [u8; 2] = *b"ED";

/// Deterministic 8-byte minisign key id for a group verifying key.
pub fn key_id(group_pubkey: &[u8; 32]) -> [u8; 8] {
    let mut hasher = Blake2b512::new();
    hasher.update(KEY_ID_DOMAIN);
    hasher.update(group_pubkey);
    let digest = hasher.finalize();
    let mut id = [0u8; 8];
    id.copy_from_slice(&digest[..8]);
    id
}

/// BLAKE2b-512 prehash of a message, as signed under the `"ED"` algorithm.
pub fn prehash(message: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    hasher.update(message);
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// The bytes the global signature is computed over: `signature || trusted_comment`.
pub fn global_signed_bytes(signature: &[u8; 64], trusted_comment: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + trusted_comment.len());
    buf.extend_from_slice(signature);
    buf.extend_from_slice(trusted_comment.as_bytes());
    buf
}

/// A parsed/owned minisign detached signature.
pub struct MinisignSignature {
    /// Signature algorithm: [`ALG_LEGACY`] (`"Ed"`) or [`ALG_PREHASHED`] (`"ED"`).
    pub sig_alg: [u8; 2],
    /// 8-byte key id identifying the signing group (see [`key_id`]).
    pub key_id: [u8; 8],
    /// Ed25519 signature over the file (or its prehash for `"ED"`).
    pub signature: [u8; 64],
    /// Ed25519 signature over `signature || trusted_comment`.
    pub global_signature: [u8; 64],
    /// Free-form comment not covered by any signature.
    pub untrusted_comment: String,
    /// Comment bound into the global signature.
    pub trusted_comment: String,
}

impl MinisignSignature {
    /// Render to the 4-line minisign `.sig` text format.
    pub fn encode(&self) -> String {
        let mut sig_blob = Vec::with_capacity(2 + 8 + 64);
        sig_blob.extend_from_slice(&self.sig_alg);
        sig_blob.extend_from_slice(&self.key_id);
        sig_blob.extend_from_slice(&self.signature);

        format!(
            "untrusted comment: {}\n{}\ntrusted comment: {}\n{}\n",
            self.untrusted_comment,
            B64.encode(&sig_blob),
            self.trusted_comment,
            B64.encode(self.global_signature),
        )
    }

    /// Parse the 4-line minisign `.sig` text format.
    pub fn parse(text: &str) -> Result<Self> {
        let mut lines = text.lines();

        let untrusted_comment = lines
            .next()
            .and_then(|l| l.strip_prefix("untrusted comment: "))
            .ok_or_else(|| KeepError::InvalidInput("missing untrusted comment line".into()))?
            .to_string();

        let sig_blob_b64 = lines
            .next()
            .ok_or_else(|| KeepError::InvalidInput("missing signature line".into()))?
            .trim();
        let sig_blob = B64
            .decode(sig_blob_b64)
            .map_err(|_| KeepError::InvalidInput("invalid base64 in signature line".into()))?;
        if sig_blob.len() != 2 + 8 + 64 {
            return Err(KeepError::InvalidInput(
                "signature blob has wrong length".into(),
            ));
        }
        let mut sig_alg = [0u8; 2];
        sig_alg.copy_from_slice(&sig_blob[..2]);
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&sig_blob[2..10]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig_blob[10..74]);

        let trusted_comment = lines
            .next()
            .and_then(|l| l.strip_prefix("trusted comment: "))
            .ok_or_else(|| KeepError::InvalidInput("missing trusted comment line".into()))?
            .to_string();

        let global_b64 = lines
            .next()
            .ok_or_else(|| KeepError::InvalidInput("missing global signature line".into()))?
            .trim();
        let global = B64.decode(global_b64).map_err(|_| {
            KeepError::InvalidInput("invalid base64 in global signature line".into())
        })?;
        if global.len() != 64 {
            return Err(KeepError::InvalidInput(
                "global signature has wrong length".into(),
            ));
        }
        let mut global_signature = [0u8; 64];
        global_signature.copy_from_slice(&global);

        Ok(Self {
            sig_alg,
            key_id,
            signature,
            global_signature,
            untrusted_comment,
            trusted_comment,
        })
    }
}

/// A parsed/owned minisign public key.
pub struct MinisignPublicKey {
    /// 8-byte key id derived from the public key (see [`key_id`]).
    pub key_id: [u8; 8],
    /// 32-byte Ed25519 group verifying key.
    pub public_key: [u8; 32],
    /// Free-form comment.
    pub untrusted_comment: String,
}

impl MinisignPublicKey {
    /// Build a public-key record from a group verifying key.
    pub fn from_group_pubkey(group_pubkey: &[u8; 32], untrusted_comment: String) -> Self {
        Self {
            key_id: key_id(group_pubkey),
            public_key: *group_pubkey,
            untrusted_comment,
        }
    }

    /// Render to the 2-line minisign public-key text format.
    pub fn encode(&self) -> String {
        let mut blob = Vec::with_capacity(2 + 8 + 32);
        blob.extend_from_slice(&ALG_LEGACY);
        blob.extend_from_slice(&self.key_id);
        blob.extend_from_slice(&self.public_key);
        format!(
            "untrusted comment: {}\n{}\n",
            self.untrusted_comment,
            B64.encode(&blob),
        )
    }

    /// Parse the 2-line minisign public-key text format.
    pub fn parse(text: &str) -> Result<Self> {
        let mut lines = text.lines();
        let untrusted_comment = lines
            .next()
            .and_then(|l| l.strip_prefix("untrusted comment: "))
            .ok_or_else(|| KeepError::InvalidInput("missing untrusted comment line".into()))?
            .to_string();
        let blob_b64 = lines
            .next()
            .ok_or_else(|| KeepError::InvalidInput("missing public key line".into()))?
            .trim();
        let blob = B64
            .decode(blob_b64)
            .map_err(|_| KeepError::InvalidInput("invalid base64 in public key line".into()))?;
        if blob.len() != 2 + 8 + 32 {
            return Err(KeepError::InvalidInput(
                "public key blob has wrong length".into(),
            ));
        }
        if blob[..2] != ALG_LEGACY {
            return Err(KeepError::InvalidInput(
                "unexpected public key algorithm".into(),
            ));
        }
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&blob[2..10]);
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&blob[10..42]);
        Ok(Self {
            key_id,
            public_key,
            untrusted_comment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_is_deterministic_and_stable() {
        let pk = [7u8; 32];
        assert_eq!(key_id(&pk), key_id(&pk));
        let pk2 = [8u8; 32];
        assert_ne!(key_id(&pk), key_id(&pk2));
    }

    #[test]
    fn signature_round_trips() {
        let sig = MinisignSignature {
            sig_alg: ALG_PREHASHED,
            key_id: [1, 2, 3, 4, 5, 6, 7, 8],
            signature: [9u8; 64],
            global_signature: [10u8; 64],
            untrusted_comment: "signature from keep".to_string(),
            trusted_comment: "timestamp:123\tfile:x".to_string(),
        };
        let encoded = sig.encode();
        let parsed = MinisignSignature::parse(&encoded).unwrap();
        assert_eq!(parsed.sig_alg, sig.sig_alg);
        assert_eq!(parsed.key_id, sig.key_id);
        assert_eq!(parsed.signature, sig.signature);
        assert_eq!(parsed.global_signature, sig.global_signature);
        assert_eq!(parsed.untrusted_comment, sig.untrusted_comment);
        assert_eq!(parsed.trusted_comment, sig.trusted_comment);
    }

    #[test]
    fn pubkey_round_trips() {
        let group_pubkey = [42u8; 32];
        let pk = MinisignPublicKey::from_group_pubkey(&group_pubkey, "keep pubkey".to_string());
        let encoded = pk.encode();
        let parsed = MinisignPublicKey::parse(&encoded).unwrap();
        assert_eq!(parsed.key_id, key_id(&group_pubkey));
        assert_eq!(parsed.public_key, group_pubkey);
        assert_eq!(parsed.untrusted_comment, "keep pubkey");
    }
}
