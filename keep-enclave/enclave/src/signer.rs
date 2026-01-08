#![deny(unsafe_code)]

use crate::audit::SigningAuditLog;
use crate::error::{EnclaveError, Result};
use crate::mlock::{MlockedBox, MlockedVec};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::Signature as TaprootSignature;
use bitcoin::{Address, Network, TxOut, XOnlyPublicKey};
use frost_secp256k1_tr as frost;
use k256::schnorr::SigningKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signature::Signer;
use std::collections::{BTreeMap, HashMap};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtAnalysis {
    pub total_input_sats: u64,
    pub total_output_sats: u64,
    pub fee_sats: u64,
    pub destinations: Vec<PsbtDestination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtDestination {
    pub address: Option<String>,
    pub amount_sats: u64,
    pub is_change: bool,
}

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
    ) -> Result<(Vec<u8>, usize, PsbtAnalysis)> {
        let entry = self
            .keys
            .get(key_id)
            .ok_or_else(|| EnclaveError::KeyNotFound(key_id.into()))?;

        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &*entry.secret)
            .map_err(|e| EnclaveError::Signing(format!("Invalid key: {}", e)))?;
        let (x_only_pubkey, _) = keypair.x_only_public_key();

        let mut psbt = Psbt::deserialize(psbt_bytes)
            .map_err(|e| EnclaveError::Signing(format!("Invalid PSBT: {}", e)))?;

        let analysis = self.analyze_psbt(&psbt, &x_only_pubkey, network)?;

        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| {
                input
                    .witness_utxo
                    .clone()
                    .ok_or_else(|| {
                        EnclaveError::Signing(format!("Missing witness UTXO for input {}", idx))
                    })
            })
            .collect::<Result<Vec<_>>>()?;

        let prevouts_ref = Prevouts::All(&prevouts);
        let mut signed_count = 0;

        for i in 0..psbt.inputs.len() {
            if !self.should_sign_input(&psbt, i, &x_only_pubkey, &secp, network)? {
                continue;
            }

            let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
            let sighash = sighash_cache
                .taproot_key_spend_signature_hash(i, &prevouts_ref, TapSighashType::Default)
                .map_err(|e| EnclaveError::Signing(format!("Sighash failed: {}", e)))?;

            let msg = Message::from_digest_slice(sighash.as_ref())
                .map_err(|e| EnclaveError::Signing(format!("Message failed: {}", e)))?;

            let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

            psbt.inputs[i].tap_key_sig = Some(TaprootSignature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            });
            signed_count += 1;
        }

        let signed_bytes = psbt.serialize();

        self.audit_log.log_psbt_sign(key_id, psbt_bytes, signed_count);

        Ok((signed_bytes, signed_count, analysis))
    }

    fn analyze_psbt(
        &self,
        psbt: &Psbt,
        our_pubkey: &XOnlyPublicKey,
        network: Network,
    ) -> Result<PsbtAnalysis> {
        let secp = Secp256k1::new();
        let mut total_input_sats = 0u64;

        for input in &psbt.inputs {
            if let Some(utxo) = &input.witness_utxo {
                total_input_sats += utxo.value.to_sat();
            }
        }

        let mut destinations = Vec::new();
        let mut total_output_sats = 0u64;

        for (i, output) in psbt.unsigned_tx.output.iter().enumerate() {
            total_output_sats += output.value.to_sat();

            let address = Address::from_script(&output.script_pubkey, network)
                .ok()
                .map(|a| a.to_string());

            let is_change = self.is_change_output(psbt, i, our_pubkey, &secp, network);

            destinations.push(PsbtDestination {
                address,
                amount_sats: output.value.to_sat(),
                is_change,
            });
        }

        Ok(PsbtAnalysis {
            total_input_sats,
            total_output_sats,
            fee_sats: total_input_sats.saturating_sub(total_output_sats),
            destinations,
        })
    }

    fn should_sign_input(
        &self,
        psbt: &Psbt,
        index: usize,
        our_pubkey: &XOnlyPublicKey,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        network: Network,
    ) -> Result<bool> {
        let input = &psbt.inputs[index];

        if let Some(tap_internal_key) = &input.tap_internal_key {
            if tap_internal_key == our_pubkey {
                return Ok(true);
            }
        }

        for (pubkey, _) in &input.tap_key_origins {
            if pubkey == our_pubkey {
                return Ok(true);
            }
        }

        if let Some(utxo) = &input.witness_utxo {
            let our_address = Address::p2tr(secp, *our_pubkey, None, network);
            if utxo.script_pubkey == our_address.script_pubkey() {
                return Ok(true);
            }
        }

        Ok(false)
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

        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &*entry.secret)
            .map_err(|e| EnclaveError::Signing(format!("Invalid key: {}", e)))?;
        let (x_only_pubkey, _) = keypair.x_only_public_key();

        let psbt = Psbt::deserialize(psbt_bytes)
            .map_err(|e| EnclaveError::Signing(format!("Invalid PSBT: {}", e)))?;

        self.analyze_psbt(&psbt, &x_only_pubkey, network)
    }

    fn is_change_output(
        &self,
        psbt: &Psbt,
        index: usize,
        our_pubkey: &XOnlyPublicKey,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        network: Network,
    ) -> bool {
        if let Some(output) = psbt.outputs.get(index) {
            for (pubkey, _) in &output.tap_key_origins {
                if pubkey == our_pubkey {
                    return true;
                }
            }
            if let Some(internal_key) = &output.tap_internal_key {
                if internal_key == our_pubkey {
                    return true;
                }
            }
        }

        if let Some(tx_output) = psbt.unsigned_tx.output.get(index) {
            let our_address = Address::p2tr(secp, *our_pubkey, None, network);
            if tx_output.script_pubkey == our_address.script_pubkey() {
                return true;
            }
        }

        false
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
fn getrandom(buf: &mut [u8]) -> Result<()> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

    let fd = nsm_init();
    if fd < 0 {
        ::getrandom::getrandom(buf)
            .map_err(|e| EnclaveError::Nsm(format!("getrandom fallback failed: {}", e)))?;
        return Ok(());
    }

    let request = Request::GetRandom {};
    let response = nsm_process_request(fd, request);
    nsm_exit(fd);

    match response {
        Response::GetRandom { random } => {
            let copy_len = buf.len().min(random.len());
            buf[..copy_len].copy_from_slice(&random[..copy_len]);
            if copy_len < buf.len() {
                ::getrandom::getrandom(&mut buf[copy_len..]).map_err(|e| {
                    EnclaveError::Nsm(format!("getrandom fallback for remainder failed: {}", e))
                })?;
            }
            Ok(())
        }
        Response::Error(e) => Err(EnclaveError::Nsm(format!("GetRandom failed: {:?}", e))),
        _ => Err(EnclaveError::Nsm("Unexpected response".into())),
    }
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
