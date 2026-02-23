// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Key types and Nostr keypair operations.
use bech32::{Bech32, Hrp};
use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{self, MlockedBox};
use crate::error::{CryptoError, KeepError, Result};

/// The type of key stored in Keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// A Nostr secp256k1 keypair.
    Nostr,
    /// A Bitcoin key (reserved for future use).
    Bitcoin,
    /// A FROST threshold signature share.
    FrostShare,
}

/// A Nostr keypair with memory-locked secret key.
///
/// # Example
///
/// ```
/// use keep_core::keys::NostrKeypair;
///
/// let keypair = NostrKeypair::generate()?;
/// println!("npub: {}", keypair.to_npub());
/// println!("nsec: {}", keypair.to_nsec());
///
/// let signature = keypair.sign(b"hello nostr")?;
/// # Ok::<(), keep_core::error::KeepError>(())
/// ```
pub struct NostrKeypair {
    secret_key: MlockedBox<32>,
    public_key: [u8; 32],
}

impl NostrKeypair {
    /// Generate a new random keypair.
    pub fn generate() -> Result<Self> {
        const MAX_RETRIES: usize = 64;
        for _ in 0..MAX_RETRIES {
            let mut secret_bytes: [u8; 32] = crypto::random_bytes();
            if let Ok(signing_key) = SigningKey::from_bytes(&secret_bytes) {
                let verifying_key = signing_key.verifying_key();
                return Ok(Self {
                    secret_key: MlockedBox::new(&mut secret_bytes),
                    public_key: verifying_key.to_bytes().into(),
                });
            }
            secret_bytes.zeroize();
        }
        Err(CryptoError::invalid_key("failed to generate valid keypair after 64 attempts").into())
    }

    /// Create a keypair from secret bytes. Zeroes the source.
    pub fn from_secret_bytes(secret: &mut [u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(secret)
            .map_err(|_| CryptoError::invalid_key("invalid secret key"))?;
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            secret_key: MlockedBox::new(secret),
            public_key: verifying_key.to_bytes().into(),
        })
    }

    /// Create a keypair from a bech32 nsec string.
    ///
    /// # Example
    ///
    /// ```
    /// use keep_core::keys::NostrKeypair;
    ///
    /// let keypair = NostrKeypair::generate()?;
    /// let nsec = keypair.to_nsec();
    ///
    /// let restored = NostrKeypair::from_nsec(&nsec)?;
    /// assert_eq!(keypair.public_bytes(), restored.public_bytes());
    /// # Ok::<(), keep_core::error::KeepError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`KeepError::InvalidNsec`] if the string is not a valid nsec.
    pub fn from_nsec(nsec: &str) -> Result<Self> {
        let (hrp, mut data) = bech32::decode(nsec).map_err(|_| KeepError::InvalidNsec)?;

        if hrp.as_str() != "nsec" {
            data.zeroize();
            return Err(KeepError::InvalidNsec);
        }

        if data.len() != 32 {
            data.zeroize();
            return Err(KeepError::InvalidNsec);
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&data);
        data.zeroize();
        Self::from_secret_bytes(&mut secret)
    }

    /// Export as a bech32 nsec string.
    pub fn to_nsec(&self) -> String {
        const NSEC_HRP: Hrp = Hrp::parse_unchecked("nsec");
        bech32::encode::<Bech32>(NSEC_HRP, &*self.secret_key)
            .expect("bech32 encode of 32-byte secret with valid HRP is infallible")
    }

    /// Export as a bech32 npub string.
    pub fn to_npub(&self) -> String {
        const NPUB_HRP: Hrp = Hrp::parse_unchecked("npub");
        bech32::encode::<Bech32>(NPUB_HRP, &self.public_key)
            .expect("bech32 encode of 32-byte pubkey with valid HRP is infallible")
    }

    /// The secret key bytes.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret_key
    }

    /// The public key bytes.
    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// The public key as hex.
    pub fn public_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// Sign a message, returning a 64-byte Schnorr signature.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        use k256::schnorr::signature::Signer;

        let signing_key = SigningKey::from_bytes(&*self.secret_key)
            .map_err(|_| CryptoError::invalid_key("invalid signing key"))?;

        let signature = signing_key.sign(message);
        Ok(signature.to_bytes())
    }
}

impl Clone for NostrKeypair {
    fn clone(&self) -> Self {
        let mut secret_copy = *self.secret_key;
        Self {
            secret_key: MlockedBox::new(&mut secret_copy),
            public_key: self.public_key,
        }
    }
}

/// Metadata for a stored key record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    /// Unique identifier derived from public key.
    pub id: [u8; 32],
    /// The public key bytes.
    pub pubkey: [u8; 32],
    /// Type of key.
    pub key_type: KeyType,
    /// Human-readable name.
    pub name: String,
    /// Unix timestamp when the key was created.
    pub created_at: i64,
    /// Unix timestamp of last use.
    pub last_used: Option<i64>,
    /// Number of signatures made with this key.
    pub sign_count: u64,
    /// The encrypted secret key bytes.
    pub encrypted_secret: Vec<u8>,
}

impl KeyRecord {
    /// Create a new key record.
    pub fn new(
        pubkey: [u8; 32],
        key_type: KeyType,
        name: String,
        encrypted_secret: Vec<u8>,
    ) -> Self {
        let id = crypto::blake2b_256(&pubkey);
        let created_at = chrono::Utc::now().timestamp();

        Self {
            id,
            pubkey,
            key_type,
            name,
            created_at,
            last_used: None,
            sign_count: 0,
            encrypted_secret,
        }
    }

    /// The npub string, if this is a Nostr key.
    pub fn npub(&self) -> Option<String> {
        if self.key_type == KeyType::Nostr {
            const NPUB_HRP: Hrp = Hrp::parse_unchecked("npub");
            Some(
                bech32::encode::<Bech32>(NPUB_HRP, &self.pubkey)
                    .expect("bech32 encode of 32-byte pubkey with valid HRP is infallible"),
            )
        } else {
            None
        }
    }
}

/// Decode an npub to raw bytes.
///
/// # Example
///
/// ```
/// use keep_core::keys::{NostrKeypair, npub_to_bytes};
///
/// let keypair = NostrKeypair::generate()?;
/// let npub = keypair.to_npub();
/// let bytes = npub_to_bytes(&npub)?;
/// assert_eq!(&bytes, keypair.public_bytes());
/// # Ok::<(), keep_core::error::KeepError>(())
/// ```
///
/// # Errors
///
/// Returns [`KeepError::InvalidNpub`] if the string is not a valid npub.
pub fn npub_to_bytes(npub: &str) -> Result<[u8; 32]> {
    let (hrp, data) = bech32::decode(npub).map_err(|_| KeepError::InvalidNpub)?;

    if hrp.as_str() != "npub" {
        return Err(KeepError::InvalidNpub);
    }

    if data.len() != 32 {
        return Err(KeepError::InvalidNpub);
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&data);
    Ok(pubkey)
}

/// Encode raw bytes as an npub.
///
/// # Example
///
/// ```
/// use keep_core::keys::{NostrKeypair, bytes_to_npub};
///
/// let keypair = NostrKeypair::generate().unwrap();
/// let npub = bytes_to_npub(keypair.public_bytes());
/// assert!(npub.starts_with("npub1"));
/// ```
pub fn bytes_to_npub(pubkey: &[u8; 32]) -> String {
    const NPUB_HRP: Hrp = Hrp::parse_unchecked("npub");
    bech32::encode::<Bech32>(NPUB_HRP, pubkey)
        .expect("bech32 encode of 32-byte pubkey with valid HRP is infallible")
}

/// NIP-49 encrypted private key (ncryptsec) support.
pub mod nip49 {
    use bech32::{Bech32, Hrp};
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::XChaCha20Poly1305;
    use unicode_normalization::UnicodeNormalization;
    use zeroize::{Zeroize, Zeroizing};

    use crate::entropy;
    use crate::error::{CryptoError, KeepError, Result};

    const VERSION: u8 = 0x02;
    const DEFAULT_LOG_N: u8 = 16;
    const MAX_LOG_N: u8 = 20;

    /// Encrypt a secret key with a password, returning an ncryptsec string.
    pub fn encrypt(secret_key: &[u8; 32], password: &str, log_n: Option<u8>) -> Result<String> {
        if password.is_empty() {
            return Err(KeepError::InvalidInput(
                "ncryptsec password must not be empty".into(),
            ));
        }
        let log_n = log_n.unwrap_or(DEFAULT_LOG_N);
        if log_n > MAX_LOG_N {
            return Err(KeepError::InvalidInput(format!(
                "ncryptsec log_n too large: {log_n} (max {MAX_LOG_N})"
            )));
        }
        let password_nfkc = Zeroizing::new(password.nfkc().collect::<String>());

        let salt: [u8; 16] = entropy::random_bytes();
        let symmetric_key = derive_key(&password_nfkc, &salt, log_n)?;

        let nonce: [u8; 24] = entropy::random_bytes();
        let key_security_byte: u8 = 0x01;

        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(symmetric_key.as_ref()));
        let payload = Payload {
            msg: secret_key.as_slice(),
            aad: &[key_security_byte],
        };
        let ciphertext = cipher
            .encrypt(GenericArray::from_slice(&nonce), payload)
            .map_err(|_| CryptoError::encryption("NIP-49 encryption failed"))?;

        let mut concat = Vec::with_capacity(91);
        concat.push(VERSION);
        concat.push(log_n);
        concat.extend_from_slice(&salt);
        concat.extend_from_slice(&nonce);
        concat.push(key_security_byte);
        concat.extend_from_slice(&ciphertext);

        const NCRYPTSEC_HRP: Hrp = Hrp::parse_unchecked("ncryptsec");
        bech32::encode::<Bech32>(NCRYPTSEC_HRP, &concat)
            .map_err(|_| CryptoError::encryption("bech32 encoding failed").into())
    }

    /// Decrypt an ncryptsec string with a password, returning the secret key.
    pub fn decrypt(ncryptsec: &str, password: &str) -> Result<Zeroizing<[u8; 32]>> {
        let (hrp, mut data) = bech32::decode(ncryptsec)
            .map_err(|_| KeepError::InvalidInput("invalid bech32".into()))?;

        if hrp.as_str() != "ncryptsec" {
            data.zeroize();
            return Err(KeepError::InvalidInput("not an ncryptsec string".into()));
        }

        if data.len() != 91 {
            data.zeroize();
            return Err(KeepError::InvalidInput(format!(
                "invalid ncryptsec length: expected 91, got {}",
                data.len()
            )));
        }

        let version = data[0];
        if version != VERSION {
            data.zeroize();
            return Err(KeepError::InvalidInput(format!(
                "unsupported ncryptsec version: {version}"
            )));
        }

        let log_n = data[1];
        if log_n > MAX_LOG_N {
            data.zeroize();
            return Err(KeepError::InvalidInput(format!(
                "ncryptsec log_n too large: {log_n} (max {MAX_LOG_N})"
            )));
        }
        let salt: [u8; 16] = data[2..18].try_into().expect("length checked");
        let nonce: [u8; 24] = data[18..42].try_into().expect("length checked");
        let key_security_byte = data[42];
        let ciphertext = data[43..].to_vec();
        data.zeroize();

        let password_nfkc = Zeroizing::new(password.nfkc().collect::<String>());
        let symmetric_key = derive_key(&password_nfkc, &salt, log_n)?;

        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(symmetric_key.as_ref()));
        let payload = Payload {
            msg: &ciphertext,
            aad: &[key_security_byte],
        };
        let mut plaintext = cipher
            .decrypt(GenericArray::from_slice(&nonce), payload)
            .map_err(|_| KeepError::DecryptionFailed)?;

        if plaintext.len() != 32 {
            plaintext.zeroize();
            return Err(CryptoError::decryption("invalid decrypted key length").into());
        }

        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(key)
    }

    fn derive_key(password: &str, salt: &[u8; 16], log_n: u8) -> Result<Zeroizing<[u8; 32]>> {
        let params = scrypt::Params::new(log_n, 8, 1, 32)
            .map_err(|e| CryptoError::kdf(format!("scrypt params: {e}")))?;

        let mut key = Zeroizing::new([0u8; 32]);
        scrypt::scrypt(password.as_bytes(), salt, &params, &mut *key)
            .map_err(|e| CryptoError::kdf(format!("scrypt: {e}")))?;

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = NostrKeypair::generate().unwrap();

        let nsec = kp.to_nsec();
        let npub = kp.to_npub();

        assert!(nsec.starts_with("nsec1"));
        assert!(npub.starts_with("npub1"));
    }

    #[test]
    fn test_nsec_roundtrip() {
        let kp = NostrKeypair::generate().unwrap();
        let nsec = kp.to_nsec();

        let kp2 = NostrKeypair::from_nsec(&nsec).unwrap();

        assert_eq!(kp.secret_bytes(), kp2.secret_bytes());
        assert_eq!(kp.public_bytes(), kp2.public_bytes());
    }

    #[test]
    fn test_sign_verify() {
        let kp = NostrKeypair::generate().unwrap();
        let message = b"test message";

        let sig = kp.sign(message).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_invalid_nsec() {
        let result = NostrKeypair::from_nsec("invalid");
        assert!(result.is_err());

        let result = NostrKeypair::from_nsec("npub1abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_nip49_roundtrip() {
        let kp = NostrKeypair::generate().unwrap();
        let password = "test-password-123";

        let ncryptsec = nip49::encrypt(kp.secret_bytes(), password, Some(16)).unwrap();
        assert!(ncryptsec.starts_with("ncryptsec1"));

        let decrypted = nip49::decrypt(&ncryptsec, password).unwrap();
        assert_eq!(&*decrypted, kp.secret_bytes());
    }

    #[test]
    fn test_nip49_wrong_password() {
        let kp = NostrKeypair::generate().unwrap();
        let ncryptsec = nip49::encrypt(kp.secret_bytes(), "correct", Some(16)).unwrap();
        let result = nip49::decrypt(&ncryptsec, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_nip49_spec_vector() {
        let ncryptsec = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
        let expected_hex = "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683";
        let expected: Vec<u8> = hex::decode(expected_hex).unwrap();

        let decrypted = nip49::decrypt(ncryptsec, "nostr").unwrap();
        assert_eq!(decrypted.as_slice(), expected.as_slice());
    }
}
