// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![deny(unsafe_code)]

use crate::audit::SigningAuditLog;
use crate::error::{EnclaveError, Result};
use crate::mlock::{MlockedBox, MlockedVec};
use crate::psbt::{PsbtAnalysis, PsbtKeys};
use bitcoin::psbt::Psbt;
use bitcoin::Network;
use frost_secp256k1_tr as frost;
use k256::schnorr::SigningKey;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use signature::Signer;
use std::collections::{BTreeMap, HashMap};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
pub struct EnclaveSigner {
    #[zeroize(skip)]
    keys: HashMap<String, KeyEntry>,
    #[zeroize(skip)]
    frost_keys: HashMap<String, FrostKeyEntry>,
    #[zeroize(skip)]
    frost_sessions: HashMap<[u8; 32], FrostSession>,
    ephemeral_secret: MlockedBox<32>,
    audit_log: SigningAuditLog,
}

#[derive(ZeroizeOnDrop)]
struct KeyEntry {
    secret: MlockedBox<32>,
    #[zeroize(skip)]
    pubkey: [u8; 32],
    #[zeroize(skip)]
    name: String,
}

#[derive(ZeroizeOnDrop)]
struct FrostKeyEntry {
    key_package_bytes: MlockedVec,
    #[zeroize(skip)]
    pubkey_package_bytes: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct FrostSession {
    nonces: frost::round1::SigningNonces,
    #[zeroize(skip)]
    commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    message: Vec<u8>,
    #[zeroize(skip)]
    key_id: String,
}

impl EnclaveSigner {
    pub fn new() -> Result<Self> {
        let mut ephemeral_secret = [0u8; 32];
        getrandom(&mut ephemeral_secret)?;

        let audit_hmac_key = derive_audit_hmac_key(&ephemeral_secret);
        let audit_log = SigningAuditLog::new(audit_hmac_key);

        Ok(Self {
            keys: HashMap::new(),
            frost_keys: HashMap::new(),
            frost_sessions: HashMap::new(),
            ephemeral_secret: MlockedBox::new(&mut ephemeral_secret),
            audit_log,
        })
    }

    pub fn with_ephemeral_secret(mut ephemeral_secret: [u8; 32]) -> Self {
        let audit_hmac_key = derive_audit_hmac_key(&ephemeral_secret);
        let audit_log = SigningAuditLog::new(audit_hmac_key);

        Self {
            keys: HashMap::new(),
            frost_keys: HashMap::new(),
            frost_sessions: HashMap::new(),
            ephemeral_secret: MlockedBox::new(&mut ephemeral_secret),
            audit_log,
        }
    }

    pub fn audit_log(&self) -> &SigningAuditLog {
        &self.audit_log
    }

    pub fn create_kms(&self) -> crate::kms::EnclaveKms {
        let mut secret_copy = *self.ephemeral_secret;
        crate::kms::EnclaveKms::new(&mut secret_copy)
    }

    pub fn get_ephemeral_pubkey(&self) -> Result<[u8; 32]> {
        let signing_key = SigningKey::from_bytes(&*self.ephemeral_secret)
            .map_err(|e| EnclaveError::InvalidKey(format!("Invalid ephemeral secret: {}", e)))?;
        let verifying_key = signing_key.verifying_key();
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&verifying_key.to_bytes());
        Ok(pubkey)
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
            secret: MlockedBox::new(&mut secret),
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
            secret: MlockedBox::new(&mut secret_arr),
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

    pub fn sign(&mut self, key_id: &str, message: &[u8]) -> Result<[u8; 64]> {
        let entry = self
            .keys
            .get(key_id)
            .ok_or_else(|| EnclaveError::KeyNotFound(key_id.into()))?;

        let signing_key = SigningKey::from_bytes(&*entry.secret)
            .map_err(|e| EnclaveError::Signing(format!("Invalid key: {}", e)))?;

        let signature = signing_key.sign(message);
        let sig_bytes = signature.to_bytes();

        let mut result = [0u8; 64];
        result.copy_from_slice(&sig_bytes);

        self.audit_log.log_single_sign(key_id, message, &result);

        Ok(result)
    }

    pub fn sign_psbt(
        &mut self,
        key_id: &str,
        psbt_bytes: &[u8],
        network: Network,
    ) -> Result<(Vec<u8>, usize)> {
        let entry = self
            .keys
            .get(key_id)
            .ok_or_else(|| EnclaveError::KeyNotFound(key_id.into()))?;
        let mut psbt = Psbt::deserialize(psbt_bytes)
            .map_err(|e| EnclaveError::Signing(format!("Invalid PSBT: {}", e)))?;
        let signed_count = PsbtKeys::new(&entry.secret, network)?.sign(&mut psbt)?;
        let signed_bytes = psbt.serialize();

        self.audit_log.log_psbt_sign(key_id, psbt_bytes, signed_count);

        Ok((signed_bytes, signed_count))
    }

    pub fn analyze_psbt_for_key(
        &self,
        key_id: &str,
        psbt_bytes: &[u8],
        network: Network,
    ) -> Result<PsbtAnalysis> {
        let entry = self
            .keys
            .get(key_id)
            .ok_or_else(|| EnclaveError::KeyNotFound(key_id.into()))?;
        let psbt = Psbt::deserialize(psbt_bytes)
            .map_err(|e| EnclaveError::Signing(format!("Invalid PSBT: {}", e)))?;
        PsbtKeys::new(&entry.secret, network)?.analyze(&psbt)
    }

    pub fn import_frost_key(
        &mut self,
        name: &str,
        key_package_bytes: Vec<u8>,
        pubkey_package_bytes: Vec<u8>,
    ) -> Result<[u8; 32]> {
        let key_package = frost::keys::KeyPackage::deserialize(&key_package_bytes)
            .map_err(|e| EnclaveError::InvalidKey(format!("Invalid FROST key package: {}", e)))?;

        let pubkey = key_package.verifying_key().serialize()
            .map_err(|e| EnclaveError::InvalidKey(format!("Failed to serialize pubkey: {}", e)))?;
        let mut pubkey_arr = [0u8; 32];
        pubkey_arr.copy_from_slice(&pubkey[1..33]);

        self.frost_keys.insert(
            name.to_string(),
            FrostKeyEntry {
                key_package_bytes: MlockedVec::new(key_package_bytes),
                pubkey_package_bytes,
            },
        );

        Ok(pubkey_arr)
    }

    pub fn frost_round1(
        &mut self,
        key_id: &str,
        message: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32])> {
        let entry = self.frost_keys.get(key_id)
            .ok_or_else(|| EnclaveError::KeyNotFound(key_id.into()))?;

        let key_package = frost::keys::KeyPackage::deserialize(entry.key_package_bytes.as_slice())
            .map_err(|e| EnclaveError::Signing(format!("Invalid key package: {}", e)))?;

        let mut rng = OsRng;
        let (nonces, our_commitment) = frost::round1::commit(key_package.signing_share(), &mut rng);

        let commitment_bytes = our_commitment.serialize()
            .map_err(|e| EnclaveError::Signing(format!("Failed to serialize commitment: {}", e)))?;

        let mut session_id = [0u8; 32];
        getrandom(&mut session_id)?;

        let mut commitments = BTreeMap::new();
        commitments.insert(*key_package.identifier(), our_commitment);

        self.frost_sessions.insert(session_id, FrostSession {
            nonces,
            commitments,
            message: message.to_vec(),
            key_id: key_id.to_string(),
        });

        self.audit_log.log_frost_round1(key_id, message, session_id);

        Ok((commitment_bytes, session_id))
    }

    pub fn frost_add_commitment(
        &mut self,
        session_id: [u8; 32],
        identifier_bytes: &[u8],
        commitment_bytes: &[u8],
    ) -> Result<()> {
        let session = self.frost_sessions.get_mut(&session_id)
            .ok_or_else(|| EnclaveError::Signing("Session not found".into()))?;

        let identifier = frost::Identifier::deserialize(identifier_bytes)
            .map_err(|e| EnclaveError::Signing(format!("Invalid identifier: {}", e)))?;
        let commitment = frost::round1::SigningCommitments::deserialize(commitment_bytes)
            .map_err(|e| EnclaveError::Signing(format!("Invalid commitment: {}", e)))?;

        session.commitments.insert(identifier, commitment);
        Ok(())
    }

    pub fn frost_round2(
        &mut self,
        session_id: [u8; 32],
    ) -> Result<Vec<u8>> {
        let session = self.frost_sessions.remove(&session_id)
            .ok_or_else(|| EnclaveError::Signing("Session not found".into()))?;

        let key_id = session.key_id.clone();

        let entry = self.frost_keys.get(&key_id)
            .ok_or_else(|| EnclaveError::KeyNotFound(key_id.clone()))?;

        let key_package = frost::keys::KeyPackage::deserialize(entry.key_package_bytes.as_slice())
            .map_err(|e| EnclaveError::Signing(format!("Invalid key package: {}", e)))?;

        let signing_package = frost::SigningPackage::new(session.commitments.clone(), &session.message);

        let signature_share = frost::round2::sign(&signing_package, &session.nonces, &key_package)
            .map_err(|e| EnclaveError::Signing(format!("FROST signing failed: {}", e)))?;

        let share_bytes = signature_share.serialize();

        self.audit_log.log_frost_round2(&key_id, session_id, &share_bytes);

        Ok(share_bytes)
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
        Self::new().expect("Failed to initialize EnclaveSigner")
    }
}

fn derive_audit_hmac_key(ephemeral_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"keep-enclave-audit-hmac-v1");
    hasher.update(ephemeral_secret);
    hasher.finalize().into()
}

#[cfg(target_os = "linux")]
fn report_nsm_unavailable() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let msg = "NSM unavailable; entropy is coming from the OS RNG, not the Nitro Secure Module";
        #[cfg(feature = "tracing")]
        tracing::warn!("{}", msg);
        #[cfg(not(feature = "tracing"))]
        eprintln!("{}", msg);
    });
}

#[cfg(target_os = "linux")]
fn getrandom(buf: &mut [u8]) -> Result<()> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

    let fd = nsm_init();
    if fd < 0 {
        // Outside an enclave (dev boxes are target_os = "linux" too) this is the
        // only path that works, so it stays a fallback rather than an error. But
        // inside one, losing the NSM while still handing back bytes is a quiet
        // downgrade of the attested entropy source, so say so: once, not per
        // draw, since key generation calls this in a loop.
        report_nsm_unavailable();
        ::getrandom::getrandom(buf)
            .map_err(|e| EnclaveError::Nsm(format!("getrandom fallback failed: {}", e)))?;
        return Ok(());
    }

    // Ask the NSM again for the remainder rather than topping the buffer up from
    // the OS RNG. A short GetRandom response is normal (the NSM returns what it
    // has), and silently filling the tail from a different source is a partial
    // downgrade of the attested entropy for every draw larger than one response
    // -- which is every 32-byte key. keep-agent's fill_from_nsm loops for the
    // same reason; this is the same behaviour, on the crate's own nsm-api major.
    let mut filled = 0;
    let mut result = Ok(());
    while filled < buf.len() {
        let response = nsm_process_request(fd, Request::GetRandom {});
        match response {
            Response::GetRandom { random } => {
                if random.is_empty() {
                    // Would spin forever; treat an empty response as a failure.
                    result = Err(EnclaveError::Nsm("GetRandom returned no bytes".into()));
                    break;
                }
                let copy_len = (buf.len() - filled).min(random.len());
                buf[filled..filled + copy_len].copy_from_slice(&random[..copy_len]);
                filled += copy_len;
            }
            Response::Error(e) => {
                result = Err(EnclaveError::Nsm(format!("GetRandom failed: {:?}", e)));
                break;
            }
            _ => {
                result = Err(EnclaveError::Nsm("Unexpected response".into()));
                break;
            }
        }
    }
    nsm_exit(fd);
    result
}

#[cfg(not(target_os = "linux"))]
fn getrandom(buf: &mut [u8]) -> Result<()> {
    ::getrandom::getrandom(buf)
        .map_err(|e| EnclaveError::Nsm(format!("getrandom failed: {}", e)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signer() -> EnclaveSigner {
        EnclaveSigner::with_ephemeral_secret([42u8; 32])
    }

    #[test]
    fn test_generate_and_sign() {
        let mut signer = test_signer();

        let pubkey = signer.generate_key("test").unwrap();
        assert_eq!(pubkey.len(), 32);

        let message = b"test message";
        let signature = signer.sign("test", message).unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_import_key() {
        let mut signer = test_signer();

        let secret = [1u8; 32];
        let pubkey = signer.import_key("imported", &secret).unwrap();
        assert_eq!(pubkey.len(), 32);

        let retrieved = signer.get_public_key("imported").unwrap();
        assert_eq!(pubkey, retrieved);
    }

    #[test]
    fn test_key_not_found() {
        let mut signer = test_signer();
        let result = signer.sign("nonexistent", b"test");
        assert!(result.is_err());
    }
}
