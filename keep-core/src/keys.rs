//! Key types and Nostr keypair operations.

#![forbid(unsafe_code)]

use bech32::{Bech32, Hrp};
use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};

use crate::crypto::{self, MlockedBox};
use crate::error::{KeepError, Result};

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
pub struct NostrKeypair {
    secret_key: MlockedBox<32>,
    public_key: [u8; 32],
}

impl NostrKeypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let mut secret_bytes: [u8; 32] = crypto::random_bytes();
        let signing_key = SigningKey::from_bytes(&secret_bytes).expect("valid key");
        let verifying_key = signing_key.verifying_key();

        Self {
            secret_key: MlockedBox::new(&mut secret_bytes),
            public_key: verifying_key.to_bytes().into(),
        }
    }

    /// Create a keypair from secret bytes. Zeroes the source.
    pub fn from_secret_bytes(secret: &mut [u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(secret)
            .map_err(|_| KeepError::Other("Invalid secret key".into()))?;
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            secret_key: MlockedBox::new(secret),
            public_key: verifying_key.to_bytes().into(),
        })
    }

    /// Create a keypair from a bech32 nsec string.
    pub fn from_nsec(nsec: &str) -> Result<Self> {
        let (hrp, data) = bech32::decode(nsec).map_err(|_| KeepError::InvalidNsec)?;

        if hrp.as_str() != "nsec" {
            return Err(KeepError::InvalidNsec);
        }

        if data.len() != 32 {
            return Err(KeepError::InvalidNsec);
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&data);
        Self::from_secret_bytes(&mut secret)
    }

    /// Export as a bech32 nsec string.
    pub fn to_nsec(&self) -> String {
        let hrp = Hrp::parse("nsec").unwrap();
        bech32::encode::<Bech32>(hrp, &*self.secret_key).unwrap()
    }

    /// Export as a bech32 npub string.
    pub fn to_npub(&self) -> String {
        let hrp = Hrp::parse("npub").unwrap();
        bech32::encode::<Bech32>(hrp, &self.public_key).unwrap()
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
            .map_err(|_| KeepError::Other("Invalid signing key".into()))?;

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
            let hrp = Hrp::parse("npub").unwrap();
            Some(bech32::encode::<Bech32>(hrp, &self.pubkey).unwrap())
        } else {
            None
        }
    }
}

/// Decode an npub to raw bytes.
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
pub fn bytes_to_npub(pubkey: &[u8; 32]) -> String {
    let hrp = Hrp::parse("npub").unwrap();
    bech32::encode::<Bech32>(hrp, pubkey).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = NostrKeypair::generate();

        let nsec = kp.to_nsec();
        let npub = kp.to_npub();

        assert!(nsec.starts_with("nsec1"));
        assert!(npub.starts_with("npub1"));
    }

    #[test]
    fn test_nsec_roundtrip() {
        let kp = NostrKeypair::generate();
        let nsec = kp.to_nsec();

        let kp2 = NostrKeypair::from_nsec(&nsec).unwrap();

        assert_eq!(kp.secret_bytes(), kp2.secret_bytes());
        assert_eq!(kp.public_bytes(), kp2.public_bytes());
    }

    #[test]
    fn test_sign_verify() {
        let kp = NostrKeypair::generate();
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
}
