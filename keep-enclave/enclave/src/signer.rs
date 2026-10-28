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
use sha2::{Digest, Sha256};
use signature::Signer;
use std::collections::{BTreeMap, HashMap};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[path = "../../../keep-core/src/frost/checked_rng.rs"]
mod checked_rng;

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
    #[zeroize(skip)]
    group_pubkey: [u8; 32],
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct FrostSession {
    nonces: frost::round1::SigningNonces,
    #[zeroize(skip)]
    commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    message: Vec<u8>,
    #[zeroize(skip)]
    key_id: String,
    #[zeroize(skip)]
    group_pubkey: [u8; 32],
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

        self.audit_log
            .log_psbt_sign(key_id, psbt_bytes, signed_count);

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
        // Locked before parsing, so bytes that fail to parse (a wallet secret
        // sent as a share, say) are wiped on the way out too.
        let key_package_bytes = MlockedVec::new(key_package_bytes);
        let key_package = frost::keys::KeyPackage::deserialize(key_package_bytes.as_slice())
            .map_err(|e| EnclaveError::InvalidKey(format!("Invalid FROST key package: {}", e)))?;

        let pubkey = key_package
            .verifying_key()
            .serialize()
            .map_err(|e| EnclaveError::InvalidKey(format!("Failed to serialize pubkey: {}", e)))?;
        let mut pubkey_arr = [0u8; 32];
        pubkey_arr.copy_from_slice(&pubkey[1..33]);

        self.frost_keys.insert(
            name.to_string(),
            FrostKeyEntry {
                key_package_bytes,
                pubkey_package_bytes,
                group_pubkey: pubkey_arr,
            },
        );

        Ok(pubkey_arr)
    }

    /// The x-only group public key of the FROST share named `key_id`.
    pub fn frost_public_key(&self, key_id: &str) -> Result<[u8; 32]> {
        self.frost_keys
            .get(key_id)
            .map(|entry| entry.group_pubkey)
            .ok_or_else(|| EnclaveError::KeyNotFound(key_id.into()))
    }

    /// The group public key of the share an open FROST session was opened
    /// with.
    pub fn frost_session_pubkey(&self, session_id: &[u8; 32]) -> Result<[u8; 32]> {
        self.frost_sessions
            .get(session_id)
            .map(|session| session.group_pubkey)
            .ok_or_else(|| EnclaveError::Signing("Session not found".into()))
    }

    /// Close a FROST session without signing, destroying its nonces.
    pub fn drop_frost_session(&mut self, session_id: &[u8; 32]) {
        self.frost_sessions.remove(session_id);
    }

    pub fn frost_round1(&mut self, key_id: &str, message: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        let entry = self
            .frost_keys
            .get(key_id)
            .ok_or_else(|| EnclaveError::KeyNotFound(key_id.into()))?;

        let key_package = frost::keys::KeyPackage::deserialize(entry.key_package_bytes.as_slice())
            .map_err(|e| EnclaveError::Signing(format!("Invalid key package: {}", e)))?;

        let identifier = *key_package.identifier();
        let group_pubkey = entry.group_pubkey;
        // commit_checked certifies the OsRng frost-core reads. The NSM-backed
        // getrandom below only names the session.
        let drawn = checked_rng::commit_checked(key_package.signing_share())
            .map_err(|e| EnclaveError::Signing(e.to_string()));
        self.store_round1(key_id, group_pubkey, message, identifier, drawn)
    }

    fn store_round1(
        &mut self,
        key_id: &str,
        group_pubkey: [u8; 32],
        message: &[u8],
        identifier: frost::Identifier,
        drawn: std::result::Result<
            (
                frost::round1::SigningNonces,
                frost::round1::SigningCommitments,
            ),
            EnclaveError,
        >,
    ) -> Result<(Vec<u8>, [u8; 32])> {
        let (nonces, our_commitment) = drawn?;

        let commitment_bytes = our_commitment
            .serialize()
            .map_err(|e| EnclaveError::Signing(format!("Failed to serialize commitment: {}", e)))?;

        let mut session_id = [0u8; 32];
        getrandom(&mut session_id)?;

        let mut commitments = BTreeMap::new();
        commitments.insert(identifier, our_commitment);

        self.frost_sessions.insert(
            session_id,
            FrostSession {
                nonces,
                commitments,
                message: message.to_vec(),
                key_id: key_id.to_string(),
                group_pubkey,
            },
        );

        self.audit_log.log_frost_round1(key_id, message, session_id);

        Ok((commitment_bytes, session_id))
    }

    pub fn frost_add_commitment(
        &mut self,
        session_id: [u8; 32],
        identifier_bytes: &[u8],
        commitment_bytes: &[u8],
    ) -> Result<()> {
        let session = self
            .frost_sessions
            .get_mut(&session_id)
            .ok_or_else(|| EnclaveError::Signing("Session not found".into()))?;

        let identifier = frost::Identifier::deserialize(identifier_bytes)
            .map_err(|e| EnclaveError::Signing(format!("Invalid identifier: {}", e)))?;
        let commitment = frost::round1::SigningCommitments::deserialize(commitment_bytes)
            .map_err(|e| EnclaveError::Signing(format!("Invalid commitment: {}", e)))?;

        session.commitments.insert(identifier, commitment);
        Ok(())
    }

    pub fn frost_round2(&mut self, session_id: [u8; 32]) -> Result<Vec<u8>> {
        let session = self
            .frost_sessions
            .remove(&session_id)
            .ok_or_else(|| EnclaveError::Signing("Session not found".into()))?;

        let key_id = session.key_id.clone();

        let entry = self
            .frost_keys
            .get(&key_id)
            .ok_or_else(|| EnclaveError::KeyNotFound(key_id.clone()))?;

        // A share imported under the same name since round 1 is not the one
        // the session's policy check and commitments were made for.
        if entry.group_pubkey != session.group_pubkey {
            return Err(EnclaveError::Signing("Share changed since round 1".into()));
        }

        let key_package = frost::keys::KeyPackage::deserialize(entry.key_package_bytes.as_slice())
            .map_err(|e| EnclaveError::Signing(format!("Invalid key package: {}", e)))?;

        let signing_package =
            frost::SigningPackage::new(session.commitments.clone(), &session.message);

        let signature_share = frost::round2::sign(&signing_package, &session.nonces, &key_package)
            .map_err(|e| EnclaveError::Signing(format!("FROST signing failed: {}", e)))?;

        let share_bytes = signature_share.serialize();

        self.audit_log
            .log_frost_round2(&key_id, session_id, &share_bytes);

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

    #[test]
    fn two_round1_draws_do_not_repeat_a_commitment() {
        let mut signer = signer_with_share();
        let (first, _) = signer.frost_round1("group", b"one").unwrap();
        let (second, _) = signer.frost_round1("group", b"two").unwrap();
        assert_ne!(first, second);
        assert_eq!(signer.frost_sessions.len(), 2);
    }

    #[test]
    fn a_refused_draw_stores_no_session() {
        let mut signer = test_signer();
        let err = signer
            .store_round1(
                "group",
                [0u8; 32],
                b"msg",
                frost::Identifier::try_from(1u16).unwrap(),
                Err(EnclaveError::Signing(
                    "RNG health check failed: constant or zero output detected".into(),
                )),
            )
            .unwrap_err();
        assert!(err.to_string().contains("RNG health check failed"), "{err}");
        assert!(signer.frost_sessions.is_empty());
    }

    #[test]
    fn a_checked_round1_completes_a_verifying_signature() {
        let (shares, pubkey_package) = frost::keys::generate_with_dealer(
            2,
            2,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .unwrap();
        let mut packages = shares
            .into_iter()
            .map(|(_, secret)| frost::keys::KeyPackage::try_from(secret).unwrap());
        let our_key = packages.next().unwrap();
        let their_key = packages.next().unwrap();

        let mut signer = test_signer();
        signer
            .import_frost_key(
                "group",
                our_key.serialize().unwrap(),
                pubkey_package.serialize().unwrap(),
            )
            .unwrap();

        let message = b"pay the allowed destination";
        let (our_commitment_bytes, session_id) = signer.frost_round1("group", message).unwrap();
        let our_commitment =
            frost::round1::SigningCommitments::deserialize(&our_commitment_bytes).unwrap();
        let (their_nonces, their_commitment) =
            checked_rng::commit_checked(their_key.signing_share()).unwrap();
        signer
            .frost_add_commitment(
                session_id,
                &their_key.identifier().serialize(),
                &their_commitment.serialize().unwrap(),
            )
            .unwrap();

        let mut commitments = BTreeMap::new();
        commitments.insert(*our_key.identifier(), our_commitment);
        commitments.insert(*their_key.identifier(), their_commitment);
        let signing_package = frost::SigningPackage::new(commitments, message);

        let our_share_bytes = signer.frost_round2(session_id).unwrap();
        let our_share = frost::round2::SignatureShare::deserialize(&our_share_bytes).unwrap();
        let their_share = frost::round2::sign(&signing_package, &their_nonces, &their_key).unwrap();

        let mut signature_shares = BTreeMap::new();
        signature_shares.insert(*our_key.identifier(), our_share);
        signature_shares.insert(*their_key.identifier(), their_share);
        let signature =
            frost::aggregate(&signing_package, &signature_shares, &pubkey_package).unwrap();
        pubkey_package
            .verifying_key()
            .verify(message, &signature)
            .unwrap();
        assert!(signer.frost_sessions.is_empty());
    }

    fn signer_with_share() -> EnclaveSigner {
        let (shares, pubkey_package) = frost::keys::generate_with_dealer(
            2,
            2,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .unwrap();
        let (_, secret) = shares.into_iter().next().unwrap();
        let key = frost::keys::KeyPackage::try_from(secret).unwrap();
        let mut signer = test_signer();
        signer
            .import_frost_key(
                "group",
                key.serialize().unwrap(),
                pubkey_package.serialize().unwrap(),
            )
            .unwrap();
        signer
    }
}
