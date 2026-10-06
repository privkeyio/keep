// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Transport formats for FROST shares and messages.
use bech32::{Bech32m, Hrp};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::{KeepError, Result};

use super::share::{Ciphersuite, SharePackage};

const SHARE_HRP: &str = "kshare";
const MAX_FRAME_COUNT: usize = 100;
const MAX_ASSEMBLED_SIZE: usize = 64 * 1024;

/// AAD domain-separating the optional encrypted public-key-package envelope from
/// the encrypted key package, so the two ciphertexts (same passphrase key) can
/// never be confused or swapped.
const PUBKEY_PACKAGE_AAD: &[u8] = b"keep-share-pubkey-package";

/// Domain of the AEAD associated data for the compact verifying-share list.
const VERIFYING_SHARES_AAD: &[u8] = b"keep-share-verifying-shares";

/// First byte of the binary bech32 payload; a JSON payload starts with `{`.
const COMPACT_VERSION: u8 = 2;

/// Size of one compressed secp256k1 verifying share.
const VERIFYING_SHARE_LEN: usize = 33;

/// An encrypted share export for backup and transfer.
#[derive(Serialize, Deserialize, Clone)]
pub struct ShareExport {
    /// Format version.
    pub version: u8,
    /// Threshold required to sign.
    pub threshold: u16,
    /// Total number of shares.
    pub total: u16,
    /// Share identifier.
    pub identifier: u16,
    /// Group public key (hex).
    pub group_pubkey: String,
    /// Encrypted share data (hex).
    pub encrypted_share: String,
    /// Encryption nonce (hex).
    pub nonce: String,
    /// Key derivation salt (hex).
    pub salt: String,
    /// FROST ciphersuite of this share.
    ///
    /// Defaults to `Secp256k1Tr` so exports written before this field existed
    /// parse unchanged. Authenticated via the AEAD associated data of
    /// `encrypted_share`, so it cannot be flipped without decryption failure.
    #[serde(default)]
    pub ciphersuite: Ciphersuite,
    /// Encrypted full FROST public-key package (every participant's verifying
    /// share), hex. Lets an imported holder enforce the canonical verifying-share
    /// binding for co-signers instead of only its own share. Optional and
    /// separately authenticated (own AAD + fresh nonce, same passphrase key):
    /// absent in exports written before this field existed and left out of the
    /// size-limited [`Self::to_bech32`] form (which carries the compact
    /// verifying-share list instead); import falls back on absence, tampering,
    /// or mismatch. `version` stays `1` so older clients ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_pubkey_package: Option<String>,
    /// Fresh nonce (hex) for [`Self::encrypted_pubkey_package`]; distinct from
    /// `nonce` (never reuse a key+nonce pair).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey_nonce: Option<String>,
    /// Every member's verifying share in index order (33 bytes each for
    /// indices 1..=total), encrypted under the share key with associated data
    /// binding the group key, threshold and total, hex. Compact enough for the
    /// bech32 form, so every import can bind each member to its canonical
    /// verifying share. Absent for Ed25519 shares and for shares stored without
    /// the full set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_verifying_shares: Option<String>,
    /// Fresh nonce (hex) for [`Self::encrypted_verifying_shares`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifying_shares_nonce: Option<String>,
}

impl ShareExport {
    /// Create an encrypted secp256k1 export from a share package.
    pub fn from_share(share: &SharePackage, passphrase: &str) -> Result<Self> {
        Self::from_share_with_ciphersuite(share, Ciphersuite::Secp256k1Tr, passphrase)
    }

    /// Create an encrypted export from a share package, binding the ciphersuite.
    pub fn from_share_with_ciphersuite(
        share: &SharePackage,
        ciphersuite: Ciphersuite,
        passphrase: &str,
    ) -> Result<Self> {
        let salt: [u8; 32] = crypto::try_random_bytes()?;
        let key = crypto::derive_key(passphrase.as_bytes(), &salt, crypto::Argon2Params::DEFAULT)?;

        // A secp256k1 share refreshed before its stored bytes were normalized
        // would otherwise export its stale verifying share.
        let key_bytes = match ciphersuite {
            Ciphersuite::Secp256k1Tr => share
                .key_package()?
                .serialize()
                .map_err(|e| KeepError::Frost(format!("Failed to serialize key package: {e}")))?,
            Ciphersuite::Ed25519 => share.key_package_bytes().to_vec(),
        };

        let encrypted = crypto::encrypt_with_aad(&key_bytes, ciphersuite.aad(), &key)?;

        // Also carry the full public-key package. It is public data, but it is
        // encrypted-and-authenticated (distinct AAD + its own fresh nonce, same
        // key) so an importer can trust it as the canonical verifying-share map
        // rather than only its own single entry. Left out of the size-limited
        // bech32 form, which carries the compact verifying-share list instead.
        let encrypted_pubkey =
            crypto::encrypt_with_aad(share.pubkey_package_bytes(), PUBKEY_PACKAGE_AAD, &key)?;

        let verifying_shares = match ciphersuite {
            Ciphersuite::Secp256k1Tr => ordered_verifying_shares(share)?,
            Ciphersuite::Ed25519 => None,
        };
        let encrypted_verifying_shares = match verifying_shares {
            Some(list) => Some(crypto::encrypt_with_aad(
                &list,
                &verifying_shares_aad(
                    &share.metadata.group_pubkey,
                    share.metadata.threshold,
                    share.metadata.total_shares,
                ),
                &key,
            )?),
            None => None,
        };

        Ok(Self {
            version: 1,
            threshold: share.metadata.threshold,
            total: share.metadata.total_shares,
            identifier: share.metadata.identifier,
            group_pubkey: hex::encode(share.metadata.group_pubkey),
            encrypted_share: hex::encode(&encrypted.ciphertext),
            nonce: hex::encode(encrypted.nonce),
            salt: hex::encode(salt),
            ciphersuite,
            encrypted_pubkey_package: Some(hex::encode(&encrypted_pubkey.ciphertext)),
            pubkey_nonce: Some(hex::encode(encrypted_pubkey.nonce)),
            encrypted_verifying_shares: encrypted_verifying_shares
                .as_ref()
                .map(|e| hex::encode(&e.ciphertext)),
            verifying_shares_nonce: encrypted_verifying_shares.map(|e| hex::encode(e.nonce)),
        })
    }

    /// Decrypt and restore the share package.
    pub fn to_share(&self, passphrase: &str, name: &str) -> Result<SharePackage> {
        const INVALID_SHARE: &str = "Invalid or corrupted share data";

        if self.version != 1 {
            return Err(KeepError::Frost(format!(
                "Unsupported version: {}",
                self.version
            )));
        }

        let salt_bytes =
            hex::decode(&self.salt).map_err(|_| KeepError::Frost(INVALID_SHARE.into()))?;
        if salt_bytes.len() != 32 {
            return Err(KeepError::Frost(INVALID_SHARE.into()));
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&salt_bytes);

        let key = crypto::derive_key(passphrase.as_bytes(), &salt, crypto::Argon2Params::DEFAULT)?;

        let nonce_bytes =
            hex::decode(&self.nonce).map_err(|_| KeepError::Frost(INVALID_SHARE.into()))?;
        if nonce_bytes.len() != 24 {
            return Err(KeepError::Frost(INVALID_SHARE.into()));
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_bytes);

        let ciphertext = hex::decode(&self.encrypted_share)
            .map_err(|_| KeepError::Frost(INVALID_SHARE.into()))?;

        let encrypted = crypto::EncryptedData { ciphertext, nonce };
        let decrypted = crypto::decrypt_with_aad(&encrypted, self.ciphersuite.aad(), &key)?;
        let key_bytes = decrypted.as_slice()?;

        let group_pubkey_bytes =
            hex::decode(&self.group_pubkey).map_err(|_| KeepError::Frost(INVALID_SHARE.into()))?;
        if group_pubkey_bytes.len() != 32 {
            return Err(KeepError::Frost(INVALID_SHARE.into()));
        }
        let mut group_pubkey = [0u8; 32];
        group_pubkey.copy_from_slice(&group_pubkey_bytes);

        let metadata = super::share::ShareMetadata::new(
            self.identifier,
            self.threshold,
            self.total,
            group_pubkey,
            name.to_string(),
        );

        match self.ciphersuite {
            Ciphersuite::Secp256k1Tr => {
                let key_package = frost_secp256k1_tr::keys::KeyPackage::deserialize(&key_bytes)
                    .map(|kp| super::share::with_consistent_verifying_share(&kp))
                    .map_err(|e| {
                        KeepError::Frost(format!("Failed to deserialize key package: {e}"))
                    })?;
                check_metadata_matches(self, &key_package, &group_pubkey)?;
                // Prefer the exported full public-key package, then the compact
                // verifying-share list; both let an imported holder bind every
                // member. Without either, a single-entry package remains.
                let pubkey_package = match self.recover_full_pubkey_package(&key, &key_package) {
                    Some(pkg) => pkg,
                    None => {
                        match self.recover_verifying_shares(&key, &key_package, &group_pubkey)? {
                            Some(pkg) => pkg,
                            None => derive_pubkey_package(&key_package)?,
                        }
                    }
                };
                check_member_indices(&pubkey_package, self.total)?;
                SharePackage::new(metadata, &key_package, &pubkey_package)
            }
            Ciphersuite::Ed25519 => import_ed25519_share(metadata, &key_bytes),
        }
    }

    /// Decrypt and validate the optional exported full public-key package.
    /// Returns `None` (caller falls back to a single-entry package) on absence,
    /// hex/decrypt/deserialize failure, or if the recovered package does not
    /// anchor to the AEAD-authenticated key package — so a tampered or mismatched
    /// field can only degrade to the fallback, never inject a forged canonical
    /// binding. Never errors; secret recovery does not depend on it.
    fn recover_full_pubkey_package(
        &self,
        key: &crypto::SecretKey,
        key_package: &frost_secp256k1_tr::keys::KeyPackage,
    ) -> Option<frost_secp256k1_tr::keys::PublicKeyPackage> {
        let ciphertext = hex::decode(self.encrypted_pubkey_package.as_ref()?).ok()?;
        let nonce_bytes = hex::decode(self.pubkey_nonce.as_ref()?).ok()?;
        if nonce_bytes.len() != 24 {
            return None;
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_bytes);
        let encrypted = crypto::EncryptedData { ciphertext, nonce };
        let decrypted = crypto::decrypt_with_aad(&encrypted, PUBKEY_PACKAGE_AAD, key).ok()?;
        let bytes = decrypted.as_slice().ok()?;
        let pkg = frost_secp256k1_tr::keys::PublicKeyPackage::deserialize(&bytes).ok()?;
        // Anchor to the authenticated key package: same group verifying key and a
        // matching own-index verifying share. Otherwise reject and fall back.
        if pkg.verifying_key() != key_package.verifying_key() {
            return None;
        }
        match pkg.verifying_shares().get(key_package.identifier()) {
            Some(vs) if vs == key_package.verifying_share() => Some(pkg),
            _ => None,
        }
    }

    /// Decrypt and check the compact verifying-share list. `None` when the
    /// export carries none (written before the field existed, or Ed25519); an
    /// error when it is present but fails authentication or does not anchor to
    /// the decrypted key package, so a damaged list is never silently dropped.
    fn recover_verifying_shares(
        &self,
        key: &crypto::SecretKey,
        key_package: &frost_secp256k1_tr::keys::KeyPackage,
        group_pubkey: &[u8; 32],
    ) -> Result<Option<frost_secp256k1_tr::keys::PublicKeyPackage>> {
        use frost_secp256k1_tr::keys::{PublicKeyPackage, VerifyingShare};
        use frost_secp256k1_tr::Identifier;

        let (Some(ciphertext_hex), Some(nonce_hex)) = (
            self.encrypted_verifying_shares.as_ref(),
            self.verifying_shares_nonce.as_ref(),
        ) else {
            return Ok(None);
        };
        let invalid = || KeepError::Frost("Invalid verifying shares in share export".into());
        let ciphertext = hex::decode(ciphertext_hex).map_err(|_| invalid())?;
        let nonce: [u8; 24] = hex::decode(nonce_hex)
            .map_err(|_| invalid())?
            .try_into()
            .map_err(|_| invalid())?;
        let decrypted = crypto::decrypt_with_aad(
            &crypto::EncryptedData { ciphertext, nonce },
            &verifying_shares_aad(group_pubkey, self.threshold, self.total),
            key,
        )
        .map_err(|_| invalid())?;
        let list = decrypted.as_slice()?;
        if list.len() != usize::from(self.total) * VERIFYING_SHARE_LEN {
            return Err(invalid());
        }
        let mut shares = std::collections::BTreeMap::new();
        for (i, bytes) in (1..=self.total).zip(list.chunks_exact(VERIFYING_SHARE_LEN)) {
            let id = Identifier::try_from(i).map_err(|_| invalid())?;
            let share = VerifyingShare::deserialize(bytes).map_err(|_| invalid())?;
            shares.insert(id, share);
        }
        if shares.get(key_package.identifier()) != Some(key_package.verifying_share()) {
            return Err(invalid());
        }
        Ok(Some(PublicKeyPackage::new(
            shares,
            *key_package.verifying_key(),
            Some(*key_package.min_signers()),
        )))
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| KeepError::Frost(format!("JSON serialization failed: {e}")))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| KeepError::Frost(format!("JSON deserialization failed: {e}")))
    }

    /// Parse from either bech32 or JSON format, auto-detecting based on prefix.
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        let is_bech32 = input
            .find('1')
            .map(|sep| input[..sep].eq_ignore_ascii_case(SHARE_HRP))
            .unwrap_or(false);
        if is_bech32 {
            Self::from_bech32(input)
        } else {
            Self::from_json(input)
        }
    }

    /// Encode as a bech32 string with `kshare` prefix.
    ///
    /// Uses a compact binary payload that carries the verifying-share list but
    /// not the full public-key package (which rides the JSON / animated-frame
    /// exports). A group too large for one bech32 string is refused with a
    /// pointer to those forms rather than silently dropping the list.
    pub fn to_bech32(&self) -> Result<String> {
        if self.version != 1 {
            return Err(KeepError::Frost(format!(
                "Unsupported version: {}",
                self.version
            )));
        }
        let invalid = || KeepError::Frost("Invalid share export".into());
        let decode_fixed = |hex_str: &str, len: usize| -> Result<Vec<u8>> {
            let bytes = hex::decode(hex_str).map_err(|_| invalid())?;
            if bytes.len() != len {
                return Err(invalid());
            }
            Ok(bytes)
        };
        let encrypted_share = hex::decode(&self.encrypted_share).map_err(|_| invalid())?;
        let mut out = vec![
            COMPACT_VERSION,
            match self.ciphersuite {
                Ciphersuite::Secp256k1Tr => 0,
                Ciphersuite::Ed25519 => 1,
            },
        ];
        out.extend_from_slice(&self.threshold.to_be_bytes());
        out.extend_from_slice(&self.total.to_be_bytes());
        out.extend_from_slice(&self.identifier.to_be_bytes());
        out.extend(decode_fixed(&self.group_pubkey, 32)?);
        out.extend(decode_fixed(&self.salt, 32)?);
        out.extend(decode_fixed(&self.nonce, 24)?);
        push_with_len(&mut out, &encrypted_share)?;
        match (
            &self.encrypted_verifying_shares,
            &self.verifying_shares_nonce,
        ) {
            (Some(ciphertext), Some(nonce)) => {
                out.push(1);
                out.extend(decode_fixed(nonce, 24)?);
                push_with_len(&mut out, &hex::decode(ciphertext).map_err(|_| invalid())?)?;
            }
            _ => out.push(0),
        }
        let hrp =
            Hrp::parse(SHARE_HRP).map_err(|e| KeepError::Frost(format!("Invalid HRP: {e}")))?;
        bech32::encode::<Bech32m>(hrp, &out).map_err(|_| {
            KeepError::Frost(format!(
                "A {}-member share does not fit one bech32 string; use the JSON or animated export",
                self.total
            ))
        })
    }

    /// The shortest text form: bech32 when the share fits one string, JSON
    /// (which also carries the full public-key package) otherwise. Both parse
    /// with [`Self::parse`].
    pub fn to_text(&self) -> Result<String> {
        self.to_bech32().or_else(|_| self.to_json())
    }

    /// Decode from a bech32 string: the compact binary payload, or the JSON
    /// payload of earlier exports.
    pub fn from_bech32(encoded: &str) -> Result<Self> {
        let (hrp, data) = bech32::decode(encoded)
            .map_err(|e| KeepError::Frost(format!("Bech32 decoding failed: {e}")))?;

        if !hrp.as_str().eq_ignore_ascii_case(SHARE_HRP) {
            return Err(KeepError::Frost(format!(
                "Invalid prefix: expected {}, got {}",
                SHARE_HRP,
                hrp.as_str()
            )));
        }

        if data.first() == Some(&COMPACT_VERSION) {
            return Self::from_compact(&data);
        }

        let json = String::from_utf8(data)
            .map_err(|_| KeepError::Frost("Invalid UTF-8 in share".into()))?;

        Self::from_json(&json)
    }

    fn from_compact(data: &[u8]) -> Result<Self> {
        let mut r = CompactReader { data, pos: 1 };
        let ciphersuite = match r.take(1)?[0] {
            0 => Ciphersuite::Secp256k1Tr,
            1 => Ciphersuite::Ed25519,
            _ => return Err(KeepError::Frost("Invalid share export".into())),
        };
        let threshold = r.u16()?;
        let total = r.u16()?;
        let identifier = r.u16()?;
        let group_pubkey = hex::encode(r.take(32)?);
        let salt = hex::encode(r.take(32)?);
        let nonce = hex::encode(r.take(24)?);
        let encrypted_share = hex::encode(r.with_len()?);
        let (encrypted_verifying_shares, verifying_shares_nonce) = match r.take(1)?[0] {
            0 => (None, None),
            1 => {
                let nonce = hex::encode(r.take(24)?);
                (Some(hex::encode(r.with_len()?)), Some(nonce))
            }
            _ => return Err(KeepError::Frost("Invalid share export".into())),
        };
        if r.pos != data.len() {
            return Err(KeepError::Frost("Invalid share export".into()));
        }
        Ok(Self {
            version: 1,
            threshold,
            total,
            identifier,
            group_pubkey,
            encrypted_share,
            nonce,
            salt,
            ciphersuite,
            encrypted_pubkey_package: None,
            pubkey_nonce: None,
            encrypted_verifying_shares,
            verifying_shares_nonce,
        })
    }
}

/// The export's identifier, threshold and group key sit outside the share's
/// authenticated ciphertext, so they must agree with the decrypted key package.
fn check_metadata_matches(
    export: &ShareExport,
    key_package: &frost_secp256k1_tr::keys::KeyPackage,
    group_pubkey: &[u8; 32],
) -> Result<()> {
    let mismatch = || KeepError::Frost("Share export metadata does not match the share".into());
    let identifier =
        frost_secp256k1_tr::Identifier::try_from(export.identifier).map_err(|_| mismatch())?;
    let verifying_key = key_package
        .verifying_key()
        .serialize()
        .map_err(|_| mismatch())?;
    if *key_package.identifier() != identifier
        || *key_package.min_signers() != export.threshold
        || export.threshold > export.total
        || verifying_key.get(1..33) != Some(group_pubkey.as_slice())
    {
        return Err(mismatch());
    }
    Ok(())
}

/// Every member in the recovered package must be one of indices 1..=total,
/// and a package holding more than this share's own entry must hold all of
/// them, so a `total` edited in the export cannot pass.
fn check_member_indices(
    package: &frost_secp256k1_tr::keys::PublicKeyPackage,
    total: u16,
) -> Result<()> {
    let members: Vec<frost_secp256k1_tr::Identifier> = (1..=total)
        .filter_map(|i| frost_secp256k1_tr::Identifier::try_from(i).ok())
        .collect();
    let entries = package.verifying_shares();
    if entries.keys().all(|id| members.contains(id))
        && (entries.len() == 1 || entries.len() == members.len())
    {
        Ok(())
    } else {
        Err(KeepError::Frost(
            "Share export metadata does not match the share".into(),
        ))
    }
}

fn push_with_len(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len =
        u16::try_from(bytes.len()).map_err(|_| KeepError::Frost("Invalid share export".into()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

struct CompactReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CompactReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.data.len())
            .ok_or_else(|| KeepError::Frost("Invalid share export".into()))?;
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn with_len(&mut self) -> Result<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }
}

/// Every member's verifying share in index order, or `None` when the stored
/// package lacks any of them.
fn ordered_verifying_shares(share: &SharePackage) -> Result<Option<Vec<u8>>> {
    use frost_secp256k1_tr::Identifier;

    let package = share.pubkey_package()?;
    let key_package = share.key_package()?;
    if package.verifying_shares().get(key_package.identifier())
        != Some(key_package.verifying_share())
    {
        return Ok(None);
    }
    let mut list =
        Vec::with_capacity(usize::from(share.metadata.total_shares) * VERIFYING_SHARE_LEN);
    for i in 1..=share.metadata.total_shares {
        let id = Identifier::try_from(i)
            .map_err(|e| KeepError::Frost(format!("Invalid identifier {i}: {e}")))?;
        let Some(vs) = package.verifying_shares().get(&id) else {
            return Ok(None);
        };
        let bytes = vs
            .serialize()
            .map_err(|e| KeepError::Frost(format!("Failed to serialize verifying share: {e}")))?;
        list.extend_from_slice(&bytes);
    }
    Ok(Some(list))
}

fn verifying_shares_aad(group_pubkey: &[u8; 32], threshold: u16, total: u16) -> Vec<u8> {
    let mut aad = VERIFYING_SHARES_AAD.to_vec();
    aad.extend_from_slice(group_pubkey);
    aad.extend_from_slice(&threshold.to_be_bytes());
    aad.extend_from_slice(&total.to_be_bytes());
    aad
}

#[cfg(feature = "ed25519")]
fn import_ed25519_share(
    metadata: super::share::ShareMetadata,
    key_bytes: &[u8],
) -> Result<SharePackage> {
    use frost_ed25519 as frost;
    use std::collections::BTreeMap;

    let key_package = frost::keys::KeyPackage::deserialize(key_bytes)
        .map_err(|e| KeepError::Frost(format!("Failed to deserialize key package: {e}")))?;

    let mut verifying_shares = BTreeMap::new();
    verifying_shares.insert(*key_package.identifier(), *key_package.verifying_share());
    let pubkey_package = frost::keys::PublicKeyPackage::new(
        verifying_shares,
        *key_package.verifying_key(),
        Some(*key_package.min_signers()),
    );

    let key_package_bytes = key_package
        .serialize()
        .map_err(|e| KeepError::Frost(format!("Failed to serialize key package: {e}")))?;
    let pubkey_package_bytes = pubkey_package
        .serialize()
        .map_err(|e| KeepError::Frost(format!("Failed to serialize pubkey package: {e}")))?;

    Ok(SharePackage::from_bytes(
        metadata,
        key_package_bytes,
        pubkey_package_bytes,
    ))
}

#[cfg(not(feature = "ed25519"))]
fn import_ed25519_share(
    _metadata: super::share::ShareMetadata,
    _key_bytes: &[u8],
) -> Result<SharePackage> {
    Err(KeepError::Frost(
        "Ed25519 share import requires the ed25519 feature".into(),
    ))
}

fn derive_pubkey_package(
    key_package: &frost_secp256k1_tr::keys::KeyPackage,
) -> Result<frost_secp256k1_tr::keys::PublicKeyPackage> {
    use frost_secp256k1_tr::keys::PublicKeyPackage;
    use std::collections::BTreeMap;

    let verifying_share = key_package.verifying_share();
    let verifying_key = key_package.verifying_key();

    let mut verifying_shares = BTreeMap::new();
    verifying_shares.insert(*key_package.identifier(), *verifying_share);

    Ok(PublicKeyPackage::new(
        verifying_shares,
        *verifying_key,
        Some(*key_package.min_signers()),
    ))
}

/// A FROST protocol message for network transport.
#[derive(Serialize, Deserialize)]
pub struct FrostMessage {
    /// Message type (commitment or share).
    #[serde(rename = "type")]
    pub msg_type: FrostMessageType,
    /// Session identifier (hex).
    pub session_id: String,
    /// Participant identifier.
    pub identifier: u16,
    /// Message payload (hex).
    pub payload: String,
}

/// Type of FROST protocol message.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FrostMessageType {
    /// Round 1 commitment.
    Round1Commitment,
    /// Round 2 signature share.
    Round2Share,
}

impl FrostMessage {
    /// Create a round 1 commitment message.
    pub fn commitment(session_id: &[u8; 32], identifier: u16, commitment_bytes: &[u8]) -> Self {
        Self {
            msg_type: FrostMessageType::Round1Commitment,
            session_id: hex::encode(session_id),
            identifier,
            payload: hex::encode(commitment_bytes),
        }
    }

    /// Create a round 2 signature share message.
    pub fn signature_share(session_id: &[u8; 32], identifier: u16, share_bytes: &[u8]) -> Self {
        Self {
            msg_type: FrostMessageType::Round2Share,
            session_id: hex::encode(session_id),
            identifier,
            payload: hex::encode(share_bytes),
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| KeepError::Frost(format!("JSON encode failed: {e}")))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| KeepError::Frost(format!("JSON decode failed: {e}")))
    }

    /// Decode the payload from hex.
    pub fn payload_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.payload).map_err(|_| KeepError::Frost("Invalid payload hex".into()))
    }

    /// Decode the session ID from hex.
    pub fn session_id_bytes(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(&self.session_id)
            .map_err(|_| KeepError::Frost("Invalid session_id hex".into()))?;
        if bytes.len() != 32 {
            return Err(KeepError::Frost("Invalid session_id length".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl ShareExport {
    /// Split into animated QR code frames.
    pub fn to_animated_frames(&self, max_bytes: usize) -> Result<Vec<String>> {
        let full = self.to_json()?;

        if full.len() <= max_bytes {
            return Ok(vec![full]);
        }

        let total_frames = full.len().div_ceil(max_bytes);
        let frames: Vec<String> = full
            .as_bytes()
            .chunks(max_bytes)
            .enumerate()
            .map(|(i, chunk)| {
                let chunk_hex = hex::encode(chunk);
                format!("{{\"f\":{i},\"t\":{total_frames},\"d\":\"{chunk_hex}\"}}")
            })
            .collect();

        Ok(frames)
    }

    /// Reassemble from animated QR code frames.
    pub fn from_animated_frames(frames: &[String]) -> Result<Self> {
        if frames.is_empty() {
            return Err(KeepError::Frost("No frames provided".into()));
        }

        if frames.len() > MAX_FRAME_COUNT {
            return Err(KeepError::Frost("Too many frames".into()));
        }

        if frames.len() == 1 {
            if let Ok(export) = Self::from_json(&frames[0]) {
                return Ok(export);
            }
        }

        let mut sorted: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut total_size = 0usize;
        let mut seen_indices = std::collections::HashSet::new();

        for frame in frames {
            let parsed: serde_json::Value = serde_json::from_str(frame)
                .map_err(|e| KeepError::Frost(format!("Invalid frame JSON: {e}")))?;

            let idx = parsed["f"]
                .as_u64()
                .ok_or_else(|| KeepError::Frost("Missing frame index".into()))?
                as usize;

            if idx >= MAX_FRAME_COUNT {
                return Err(KeepError::Frost("Frame index out of range".into()));
            }

            if !seen_indices.insert(idx) {
                return Err(KeepError::Frost("Duplicate frame index".into()));
            }

            let data_hex = parsed["d"]
                .as_str()
                .ok_or_else(|| KeepError::Frost("Missing frame data".into()))?;
            let data = hex::decode(data_hex)
                .map_err(|_| KeepError::Frost("Invalid frame data hex".into()))?;

            total_size = total_size
                .checked_add(data.len())
                .ok_or_else(|| KeepError::Frost("Total size overflow".into()))?;

            if total_size > MAX_ASSEMBLED_SIZE {
                return Err(KeepError::Frost("Assembled data too large".into()));
            }

            sorted.push((idx, data));
        }

        sorted.sort_by_key(|(idx, _)| *idx);

        let full_bytes: Vec<u8> = sorted.into_iter().flat_map(|(_, data)| data).collect();
        let full_str = String::from_utf8(full_bytes)
            .map_err(|_| KeepError::Frost("Invalid UTF-8 in assembled frames".into()))?;

        Self::from_json(&full_str).or_else(|_| Self::from_bech32(&full_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{ThresholdConfig, TrustedDealer};

    #[test]
    fn export_of_a_stale_stored_share_carries_a_consistent_key_package() {
        let stored = crate::frost::share::stale_refreshed_share();
        let export = ShareExport::from_share(&stored, "pass").unwrap();
        let salt: [u8; 32] = hex::decode(&export.salt).unwrap().try_into().unwrap();
        let key = crypto::derive_key(b"pass", &salt, crypto::Argon2Params::DEFAULT).unwrap();
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&hex::decode(&export.nonce).unwrap());
        let encrypted = crypto::EncryptedData {
            ciphertext: hex::decode(&export.encrypted_share).unwrap(),
            nonce,
        };
        let plain =
            crypto::decrypt_with_aad(&encrypted, Ciphersuite::Secp256k1Tr.aad(), &key).unwrap();
        let kp =
            frost_secp256k1_tr::keys::KeyPackage::deserialize(&plain.as_slice().unwrap()).unwrap();
        assert_eq!(
            *kp.verifying_share(),
            frost_secp256k1_tr::keys::VerifyingShare::from(*kp.signing_share()),
            "the export must not carry the stale verifying share"
        );
    }

    #[test]
    fn old_export_with_a_stale_key_package_imports_with_its_full_pubkey_package() {
        let stored = crate::frost::share::stale_refreshed_share();
        let mut export = ShareExport::from_share(&stored, "pass").unwrap();
        // An export written before the fix carried the stale stored bytes.
        let salt: [u8; 32] = hex::decode(&export.salt).unwrap().try_into().unwrap();
        let key = crypto::derive_key(b"pass", &salt, crypto::Argon2Params::DEFAULT).unwrap();
        let stale = crypto::encrypt_with_aad(
            stored.key_package_bytes(),
            Ciphersuite::Secp256k1Tr.aad(),
            &key,
        )
        .unwrap();
        export.encrypted_share = hex::encode(&stale.ciphertext);
        export.nonce = hex::encode(stale.nonce);
        let restored = ShareExport::from_json(&export.to_json().unwrap())
            .unwrap()
            .to_share("pass", "restored")
            .unwrap();
        assert_eq!(
            restored.pubkey_package().unwrap().verifying_shares().len(),
            3
        );
    }

    #[test]
    fn refreshed_share_keeps_its_full_pubkey_package_through_export() {
        let (shares, _) = TrustedDealer::new(ThresholdConfig::two_of_three())
            .generate("refresh")
            .unwrap();
        let (refreshed, _) = crate::frost::refresh_shares(&shares).unwrap();
        let export = ShareExport::from_share(&refreshed[0], "pass").unwrap();
        let restored = ShareExport::from_json(&export.to_json().unwrap())
            .unwrap()
            .to_share("pass", "restored")
            .unwrap();
        assert_eq!(
            restored.pubkey_package().unwrap().verifying_shares().len(),
            3,
            "the full verifying-share set must survive, not fall back to one entry"
        );
    }

    #[test]
    fn test_share_export_roundtrip() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let passphrase = "test passphrase";
        let export = ShareExport::from_share(&shares[0], passphrase).unwrap();

        let json = export.to_json().unwrap();
        let reimported = ShareExport::from_json(&json).unwrap();
        let share = reimported.to_share(passphrase, "imported").unwrap();

        assert_eq!(share.metadata.threshold, shares[0].metadata.threshold);
        assert_eq!(share.metadata.identifier, shares[0].metadata.identifier);
        assert_eq!(share.group_pubkey(), shares[0].group_pubkey());
    }

    #[test]
    fn test_bech32_roundtrip() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let export = ShareExport::from_share(&shares[0], "pass").unwrap();
        let encoded = export.to_bech32().unwrap();

        assert!(encoded.starts_with(SHARE_HRP));

        let decoded = ShareExport::from_bech32(&encoded).unwrap();
        assert_eq!(decoded.identifier, export.identifier);
        assert_eq!(decoded.threshold, export.threshold);
    }

    #[test]
    fn full_pubkey_package_survives_json_roundtrip() {
        // A DKG holder's export carries the full verifying-share map; JSON transport
        // keeps it, so an imported holder can bind co-signers, not just its own index.
        let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
        let (shares, _) = dealer.generate("test").unwrap();

        let export = ShareExport::from_share(&shares[0], "pass").unwrap();
        assert!(export.encrypted_pubkey_package.is_some());

        let imported = ShareExport::from_json(&export.to_json().unwrap())
            .unwrap()
            .to_share("pass", "imported")
            .unwrap();
        assert_eq!(
            imported.pubkey_package().unwrap().verifying_shares().len(),
            3,
            "imported holder should carry the full 3-party verifying-share map"
        );
    }

    fn bech32_import(threshold: u16, total: u16) -> (SharePackage, SharePackage) {
        let dealer = TrustedDealer::new(ThresholdConfig::new(threshold, total).unwrap());
        let (mut shares, _) = dealer.generate("test").unwrap();
        let original = shares.remove(0);
        let export = ShareExport::from_share(&original, "pass").unwrap();
        let imported = ShareExport::parse(&export.to_bech32().unwrap())
            .unwrap()
            .to_share("pass", "imported")
            .unwrap();
        (original, imported)
    }

    #[test]
    fn bech32_import_carries_every_verifying_share() {
        for (threshold, total) in [(2, 3), (3, 5), (5, 10)] {
            let (original, imported) = bech32_import(threshold, total);
            let expected = original.pubkey_package().unwrap();
            let got = imported.pubkey_package().unwrap();
            assert_eq!(got.verifying_shares(), expected.verifying_shares());
            assert_eq!(got.verifying_key(), expected.verifying_key());
            assert_eq!(
                imported.key_package_bytes(),
                original.key_package_bytes(),
                "{threshold}-of-{total}"
            );
        }
    }

    #[test]
    fn bech32_refuses_a_group_too_large_for_one_string() {
        let dealer = TrustedDealer::new(ThresholdConfig::new(2, 11).unwrap());
        let (shares, _) = dealer.generate("test").unwrap();
        let export = ShareExport::from_share(&shares[0], "pass").unwrap();
        let err = export.to_bech32().unwrap_err().to_string();
        assert!(err.contains("use the JSON or animated export"), "{err}");
    }

    #[test]
    fn tampered_verifying_shares_fail_the_import() {
        let dealer = TrustedDealer::new(ThresholdConfig::new(3, 5).unwrap());
        let (shares, _) = dealer.generate("test").unwrap();
        let mut export = ShareExport::from_share(&shares[0], "pass").unwrap();
        export.encrypted_pubkey_package = None;
        export.pubkey_nonce = None;
        let mut ciphertext =
            hex::decode(export.encrypted_verifying_shares.as_ref().unwrap()).unwrap();
        ciphertext[0] ^= 1;
        export.encrypted_verifying_shares = Some(hex::encode(&ciphertext));
        assert!(export.to_share("pass", "imported").is_err());

        let mut export = ShareExport::from_share(&shares[0], "pass").unwrap();
        export.encrypted_pubkey_package = None;
        export.pubkey_nonce = None;
        export.total = 6;
        assert!(export.to_share("pass", "imported").is_err());
    }

    #[test]
    fn json_bech32_from_earlier_exports_still_imports() {
        let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
        let (shares, _) = dealer.generate("test").unwrap();
        let mut export = ShareExport::from_share(&shares[0], "pass").unwrap();
        export.encrypted_pubkey_package = None;
        export.pubkey_nonce = None;
        export.encrypted_verifying_shares = None;
        export.verifying_shares_nonce = None;
        let legacy = bech32::encode::<Bech32m>(
            Hrp::parse(SHARE_HRP).unwrap(),
            export.to_json().unwrap().as_bytes(),
        )
        .unwrap();
        let imported = ShareExport::parse(&legacy)
            .unwrap()
            .to_share("pass", "imported")
            .unwrap();
        assert_eq!(
            imported.pubkey_package().unwrap().verifying_shares().len(),
            1
        );
        assert_eq!(imported.key_package_bytes(), shares[0].key_package_bytes());
    }

    #[test]
    fn truncated_compact_payload_is_refused() {
        let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
        let (shares, _) = dealer.generate("test").unwrap();
        let encoded = ShareExport::from_share(&shares[0], "pass")
            .unwrap()
            .to_bech32()
            .unwrap();
        let (hrp, data) = bech32::decode(&encoded).unwrap();
        for cut in [1, 10, data.len() - 1] {
            let short = bech32::encode::<Bech32m>(hrp, &data[..cut]).unwrap();
            assert!(ShareExport::from_bech32(&short).is_err(), "cut at {cut}");
        }
        let mut long = data.clone();
        long.push(0);
        let long = bech32::encode::<Bech32m>(hrp, &long).unwrap();
        assert!(ShareExport::from_bech32(&long).is_err());
    }

    #[test]
    fn absent_pubkey_package_falls_back_to_single_entry() {
        // A legacy (v1) export with the field absent imports via the single-entry
        // fallback, unchanged.
        let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
        let (shares, _) = dealer.generate("test").unwrap();

        let mut export = ShareExport::from_share(&shares[0], "pass").unwrap();
        export.encrypted_pubkey_package = None;
        export.pubkey_nonce = None;
        export.encrypted_verifying_shares = None;
        export.verifying_shares_nonce = None;

        let imported = export.to_share("pass", "imported").unwrap();
        assert_eq!(
            imported.pubkey_package().unwrap().verifying_shares().len(),
            1
        );
    }

    #[test]
    fn tampered_pubkey_package_falls_back_never_errors() {
        // Flipping a byte of the authenticated package fails the MAC; import must
        // fall back to single-entry (never panic, never yield the tampered map),
        // and secret recovery still succeeds.
        let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
        let (shares, _) = dealer.generate("test").unwrap();

        let mut export = ShareExport::from_share(&shares[0], "pass").unwrap();
        let mut ct = hex::decode(export.encrypted_pubkey_package.as_ref().unwrap()).unwrap();
        ct[0] ^= 0xff;
        export.encrypted_pubkey_package = Some(hex::encode(&ct));

        let imported = export.to_share("pass", "imported").unwrap();
        assert_eq!(
            imported.pubkey_package().unwrap().verifying_shares(),
            shares[0].pubkey_package().unwrap().verifying_shares(),
            "the authenticated verifying-share list replaces the damaged package"
        );

        export.encrypted_verifying_shares = None;
        export.verifying_shares_nonce = None;
        let imported = export.to_share("pass", "imported").unwrap();
        assert_eq!(
            imported.pubkey_package().unwrap().verifying_shares().len(),
            1
        );
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let export = ShareExport::from_share(&shares[0], "correct").unwrap();
        let result = export.to_share("wrong", "imported");

        assert!(result.is_err());
    }

    #[test]
    fn test_animated_frames_roundtrip() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let export = ShareExport::from_share(&shares[0], "pass").unwrap();

        let frames = export.to_animated_frames(100).unwrap();
        assert!(frames.len() > 1);

        let reconstructed = ShareExport::from_animated_frames(&frames).unwrap();
        assert_eq!(reconstructed.identifier, export.identifier);
        assert_eq!(reconstructed.threshold, export.threshold);
        assert_eq!(reconstructed.group_pubkey, export.group_pubkey);
    }

    #[test]
    fn test_animated_frames_single() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let export = ShareExport::from_share(&shares[0], "pass").unwrap();

        let frames = export.to_animated_frames(10000).unwrap();
        assert_eq!(frames.len(), 1);

        let reconstructed = ShareExport::from_animated_frames(&frames).unwrap();
        assert_eq!(reconstructed.identifier, export.identifier);
    }

    #[test]
    fn test_frost_message_roundtrip() {
        let session_id = [42u8; 32];
        let commitment_data = vec![1, 2, 3, 4, 5];

        let msg = FrostMessage::commitment(&session_id, 1, &commitment_data);
        assert_eq!(msg.msg_type, FrostMessageType::Round1Commitment);
        assert_eq!(msg.identifier, 1);

        let json = msg.to_json().unwrap();
        let parsed = FrostMessage::from_json(&json).unwrap();

        assert_eq!(parsed.msg_type, FrostMessageType::Round1Commitment);
        assert_eq!(parsed.identifier, 1);
        assert_eq!(parsed.payload_bytes().unwrap(), commitment_data);
        assert_eq!(parsed.session_id_bytes().unwrap(), session_id);
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_ed25519_share_export_roundtrip() {
        use crate::frost::ed25519::TrustedDealer as Ed25519Dealer;

        let dealer = Ed25519Dealer::new(ThresholdConfig::two_of_three());
        let (shares, _) = dealer.generate("ed-test").unwrap();

        let passphrase = "ed pass";
        let export =
            ShareExport::from_share_with_ciphersuite(&shares[0], Ciphersuite::Ed25519, passphrase)
                .unwrap();
        assert_eq!(export.ciphersuite, Ciphersuite::Ed25519);

        let json = export.to_json().unwrap();
        let reimported = ShareExport::from_json(&json).unwrap();
        let restored = reimported.to_share(passphrase, "imported").unwrap();

        assert_eq!(restored.group_pubkey(), shares[0].group_pubkey());
        assert_eq!(restored.key_package_bytes(), shares[0].key_package_bytes());
    }

    #[test]
    fn test_frost_message_signature_share() {
        let session_id = [99u8; 32];
        let share_data = vec![10, 20, 30];

        let msg = FrostMessage::signature_share(&session_id, 2, &share_data);
        assert_eq!(msg.msg_type, FrostMessageType::Round2Share);
        assert_eq!(msg.identifier, 2);

        let json = msg.to_json().unwrap();
        assert!(json.contains("round2_share"));
    }

    // === #440: FrostMessage rejection coverage for interactive sign ===

    /// `FrostMessage::from_json` is the parse boundary the interactive
    /// signer pastes into. Malformed input MUST surface a clean error
    /// rather than panic. Pin three classes: complete garbage, valid JSON
    /// with wrong shape, and an empty string.
    #[test]
    fn test_frost_message_from_json_rejects_malformed_input() {
        assert!(FrostMessage::from_json("not-json").is_err());
        assert!(FrostMessage::from_json("").is_err());
        // Valid JSON but missing required fields:
        assert!(FrostMessage::from_json(r#"{"foo": "bar"}"#).is_err());
    }

    /// The interactive signer compares the parsed `session_id` hex against
    /// its own session digest to defend against cross-session reuse. The
    /// `session_id_bytes()` accessor MUST refuse hex that doesn't decode
    /// to exactly 32 bytes, otherwise the gate could be bypassed by a
    /// short prefix that happens to match.
    #[test]
    fn test_frost_message_session_id_bytes_rejects_wrong_length_hex() {
        let session_id = [7u8; 32];
        let payload = vec![1, 2, 3];
        let mut msg = FrostMessage::commitment(&session_id, 1, &payload);

        // 31-byte hex (62 chars): refused.
        msg.session_id = "aa".repeat(31);
        assert!(
            msg.session_id_bytes().is_err(),
            "31-byte session_id hex must be refused"
        );

        // 33-byte hex (66 chars): refused.
        msg.session_id = "bb".repeat(33);
        assert!(
            msg.session_id_bytes().is_err(),
            "33-byte session_id hex must be refused"
        );

        // Non-hex characters: refused.
        msg.session_id = "z".repeat(64);
        assert!(
            msg.session_id_bytes().is_err(),
            "non-hex session_id must be refused"
        );

        // Exactly 32 bytes (64 hex chars) of valid hex: accepted, and
        // round-trips to the same bytes.
        msg.session_id = "cc".repeat(32);
        let bytes = msg.session_id_bytes().expect("32-byte hex must parse");
        assert_eq!(bytes, [0xCCu8; 32]);
    }

    #[test]
    fn large_group_text_export_falls_back_to_json_and_imports() {
        let dealer = TrustedDealer::new(ThresholdConfig::new(3, 15).unwrap());
        let (shares, _) = dealer.generate("test").unwrap();
        let text = ShareExport::from_share(&shares[0], "pass")
            .unwrap()
            .to_text()
            .unwrap();
        assert!(text.starts_with('{'));
        let imported = ShareExport::parse(&text)
            .unwrap()
            .to_share("pass", "imported")
            .unwrap();
        assert_eq!(
            imported.pubkey_package().unwrap().verifying_shares().len(),
            15
        );
    }

    #[test]
    fn export_metadata_must_match_the_key_package() {
        let dealer = TrustedDealer::new(ThresholdConfig::new(3, 5).unwrap());
        let (shares, _) = dealer.generate("test").unwrap();
        let export = ShareExport::from_share(&shares[0], "pass").unwrap();

        let mut wrong_id = export.clone();
        wrong_id.identifier = 2;
        assert!(wrong_id.to_share("pass", "x").is_err());

        let mut wrong_threshold = export.clone();
        wrong_threshold.threshold = 2;
        wrong_threshold.encrypted_verifying_shares = None;
        wrong_threshold.verifying_shares_nonce = None;
        assert!(wrong_threshold.to_share("pass", "x").is_err());

        let mut wrong_group = export.clone();
        wrong_group.group_pubkey = hex::encode([9u8; 32]);
        wrong_group.encrypted_verifying_shares = None;
        wrong_group.verifying_shares_nonce = None;
        assert!(wrong_group.to_share("pass", "x").is_err());

        let mut small_total = export.clone();
        small_total.total = 4;
        small_total.encrypted_verifying_shares = None;
        small_total.verifying_shares_nonce = None;
        assert!(small_total.to_share("pass", "x").is_err());

        export.to_share("pass", "x").unwrap();
    }

    #[test]
    fn largest_group_text_export_stays_under_the_mobile_import_limit() {
        let dealer = TrustedDealer::new(ThresholdConfig::new(2, 255).unwrap());
        let (shares, _) = dealer.generate("test").unwrap();
        let text = ShareExport::from_share(&shares[0], "pass")
            .unwrap()
            .to_text()
            .unwrap();
        // keep-mobile refuses imports above 64 KiB.
        assert!(text.len() < 64 * 1024, "{} bytes", text.len());
    }
}
