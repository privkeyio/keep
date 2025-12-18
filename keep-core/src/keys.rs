#![forbid(unsafe_code)]

use bech32::{Bech32m, Hrp};
use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::crypto;
use crate::error::{KeepError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Nostr,
    Bitcoin,
    FrostShare,
}

#[derive(ZeroizeOnDrop)]
pub struct NostrKeypair {
    #[zeroize]
    secret_key: [u8; 32],
    public_key: [u8; 32],
}

impl NostrKeypair {
    pub fn generate() -> Self {
        let secret_bytes: [u8; 32] = crypto::random_bytes();
        let signing_key = SigningKey::from_bytes(&secret_bytes).expect("valid key");
        let verifying_key = signing_key.verifying_key();

        Self {
            secret_key: secret_bytes,
            public_key: verifying_key.to_bytes().into(),
        }
    }

    pub fn from_secret_bytes(secret: &[u8; 32]) -> Result<Self> {
        let signing_key =
            SigningKey::from_bytes(secret).map_err(|_| KeepError::Other("Invalid secret key".into()))?;
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            secret_key: *secret,
            public_key: verifying_key.to_bytes().into(),
        })
    }

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
        Self::from_secret_bytes(&secret)
    }

    pub fn to_nsec(&self) -> String {
        let hrp = Hrp::parse("nsec").unwrap();
        bech32::encode::<Bech32m>(hrp, &self.secret_key).unwrap()
    }

    pub fn to_npub(&self) -> String {
        let hrp = Hrp::parse("npub").unwrap();
        bech32::encode::<Bech32m>(hrp, &self.public_key).unwrap()
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret_key
    }

    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        use k256::schnorr::signature::Signer;

        let signing_key =
            SigningKey::from_bytes(&self.secret_key).map_err(|_| KeepError::Other("Invalid signing key".into()))?;

        let signature = signing_key.sign(message);
        Ok(signature.to_bytes().into())
    }
}

impl Clone for NostrKeypair {
    fn clone(&self) -> Self {
        Self {
            secret_key: self.secret_key,
            public_key: self.public_key,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub id: [u8; 32],
    pub pubkey: [u8; 32],
    pub key_type: KeyType,
    pub name: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub sign_count: u64,
    pub encrypted_secret: Vec<u8>,
}

impl KeyRecord {
    pub fn new(pubkey: [u8; 32], key_type: KeyType, name: String, encrypted_secret: Vec<u8>) -> Self {
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

    pub fn npub(&self) -> Option<String> {
        if self.key_type == KeyType::Nostr {
            let hrp = Hrp::parse("npub").unwrap();
            Some(bech32::encode::<Bech32m>(hrp, &self.pubkey).unwrap())
        } else {
            None
        }
    }
}

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

pub fn bytes_to_npub(pubkey: &[u8; 32]) -> String {
    let hrp = Hrp::parse("npub").unwrap();
    bech32::encode::<Bech32m>(hrp, pubkey).unwrap()
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
