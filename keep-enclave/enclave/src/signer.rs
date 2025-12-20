use crate::error::{EnclaveError, Result};
use k256::schnorr::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtData {
    pub inputs: Vec<PsbtInput>,
    pub raw_psbt: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtInput {
    pub tap_internal_key: Option<[u8; 32]>,
    pub sighash: Option<Vec<u8>>,
    pub tap_key_sig: Option<Vec<u8>>,
}

#[derive(ZeroizeOnDrop)]
pub struct EnclaveSigner {
    #[zeroize(skip)]
    keys: HashMap<String, KeyEntry>,
    #[zeroize(skip)]
    frost_nonces: HashMap<[u8; 32], FrostNonces>,
    ephemeral_secret: [u8; 32],
}

#[derive(ZeroizeOnDrop)]
struct KeyEntry {
    secret: [u8; 32],
    #[zeroize(skip)]
    pubkey: [u8; 32],
    #[zeroize(skip)]
    name: String,
}

struct FrostNonces {
    _nonces: Vec<u8>,
    message: Vec<u8>,
}

impl EnclaveSigner {
    pub fn new() -> Self {
        let mut ephemeral_secret = [0u8; 32];
        let _ = getrandom(&mut ephemeral_secret);

        Self {
            keys: HashMap::new(),
            frost_nonces: HashMap::new(),
            ephemeral_secret,
        }
    }

    pub fn get_ephemeral_pubkey(&self) -> [u8; 32] {
        if let Ok(signing_key) = SigningKey::from_bytes(&self.ephemeral_secret) {
            let verifying_key = signing_key.verifying_key();
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&verifying_key.to_bytes());
            pubkey
        } else {
            [0u8; 32]
        }
    }

    pub fn generate_key(&mut self, name: &str) -> Result<[u8; 32]> {
        let mut secret = [0u8; 32];
        getrandom(&mut secret)?;

        let signing_key = SigningKey::from_bytes(&secret)
            .map_err(|e| EnclaveError::InvalidKey(format!("Invalid key: {}", e)))?;
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_bytes();

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&pubkey_bytes);

        let entry = KeyEntry {
            secret,
            pubkey,
            name: name.to_string(),
        };

        self.keys.insert(name.to_string(), entry);

        Ok(pubkey)
    }

    pub fn import_key(&mut self, name: &str, secret: &[u8]) -> Result<[u8; 32]> {
        if secret.len() != 32 {
            return Err(EnclaveError::InvalidKey("Secret must be 32 bytes".into()));
        }

        let mut secret_arr = [0u8; 32];
        secret_arr.copy_from_slice(secret);

        let signing_key = SigningKey::from_bytes(&secret_arr)
            .map_err(|e| EnclaveError::InvalidKey(format!("Invalid key: {}", e)))?;
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_bytes();

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&pubkey_bytes);

        let entry = KeyEntry {
            secret: secret_arr,
            pubkey,
            name: name.to_string(),
        };

        self.keys.insert(name.to_string(), entry);

        Ok(pubkey)
    }

    pub fn get_public_key(&self, key_id: &str) -> Result<[u8; 32]> {
        let entry = self
            .keys
            .get(key_id)
            .ok_or_else(|| EnclaveError::KeyNotFound(key_id.into()))?;
        Ok(entry.pubkey)
    }

    pub fn sign(&self, key_id: &str, message: &[u8]) -> Result<[u8; 64]> {
        let entry = self
            .keys
            .get(key_id)
            .ok_or_else(|| EnclaveError::KeyNotFound(key_id.into()))?;

        let signing_key = SigningKey::from_bytes(&entry.secret)
            .map_err(|e| EnclaveError::Signing(format!("Invalid key: {}", e)))?;

        let signature = signing_key.sign(message);
        let sig_bytes = signature.to_bytes();

        let mut result = [0u8; 64];
        result.copy_from_slice(&sig_bytes);

        Ok(result)
    }

    pub fn sign_psbt(&self, key_id: &str, psbt_bytes: &[u8]) -> Result<(Vec<u8>, usize)> {
        let entry = self
            .keys
            .get(key_id)
            .ok_or_else(|| EnclaveError::KeyNotFound(key_id.into()))?;

        let signing_key = SigningKey::from_bytes(&entry.secret)
            .map_err(|e| EnclaveError::Signing(format!("Invalid key: {}", e)))?;

        let x_only_pubkey = signing_key.verifying_key().to_bytes();

        let mut psbt: PsbtData = postcard::from_bytes(psbt_bytes)
            .map_err(|e| EnclaveError::Signing(format!("Invalid PSBT format: {}", e)))?;

        let mut signed_count = 0;

        for input in &mut psbt.inputs {
            if input.tap_internal_key.as_ref() == Some(&x_only_pubkey) && input.tap_key_sig.is_none() {
                if let Some(ref sighash) = input.sighash {
                    let signature = signing_key.sign(sighash);
                    input.tap_key_sig = Some(signature.to_bytes().to_vec());
                    signed_count += 1;
                }
            }
        }

        let signed_bytes = postcard::to_allocvec(&psbt)
            .map_err(|e| EnclaveError::Signing(format!("Serialization failed: {}", e)))?;

        Ok((signed_bytes, signed_count))
    }

    pub fn frost_round1(
        &mut self,
        key_id: &str,
        message: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32])> {
        let _entry = self
            .keys
            .get(key_id)
            .ok_or_else(|| EnclaveError::KeyNotFound(key_id.into()))?;

        let mut nonces_id = [0u8; 32];
        getrandom(&mut nonces_id)?;

        let commitment = vec![0u8; 64];

        self.frost_nonces.insert(
            nonces_id,
            FrostNonces {
                _nonces: vec![],
                message: message.to_vec(),
            },
        );

        Ok((commitment, nonces_id))
    }

    pub fn frost_round2(
        &mut self,
        _commitments: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let nonces_entry = self
            .frost_nonces
            .iter()
            .find(|(_, v)| v.message == message)
            .map(|(k, _)| *k);

        if let Some(nonces_id) = nonces_entry {
            self.frost_nonces.remove(&nonces_id);
        }

        Ok(vec![0u8; 32])
    }

    pub fn list_keys(&self) -> Vec<(&str, [u8; 32])> {
        self.keys
            .iter()
            .map(|(name, entry)| (name.as_str(), entry.pubkey))
            .collect()
    }
}

impl Default for EnclaveSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
fn getrandom(buf: &mut [u8]) -> Result<()> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::nsm_process_request;

    let request = Request::GetRandom {};
    let response = nsm_process_request(request);

    match response {
        Response::GetRandom { random } => {
            let copy_len = buf.len().min(random.len());
            buf[..copy_len].copy_from_slice(&random[..copy_len]);
            Ok(())
        }
        Response::Error(e) => Err(EnclaveError::Nsm(format!("GetRandom failed: {:?}", e))),
        _ => Err(EnclaveError::Nsm("Unexpected response".into())),
    }
}

#[cfg(not(target_os = "linux"))]
fn getrandom(buf: &mut [u8]) -> Result<()> {
    use rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(buf);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign() {
        let mut signer = EnclaveSigner::new();

        let pubkey = signer.generate_key("test").unwrap();
        assert_eq!(pubkey.len(), 32);

        let message = b"test message";
        let signature = signer.sign("test", message).unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_import_key() {
        let mut signer = EnclaveSigner::new();

        let secret = [1u8; 32];
        let pubkey = signer.import_key("imported", &secret).unwrap();
        assert_eq!(pubkey.len(), 32);

        let retrieved = signer.get_public_key("imported").unwrap();
        assert_eq!(pubkey, retrieved);
    }

    #[test]
    fn test_key_not_found() {
        let signer = EnclaveSigner::new();
        let result = signer.sign("nonexistent", b"test");
        assert!(result.is_err());
    }
}
