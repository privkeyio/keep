// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! keep-mobile's approver as a stand-in phone, as keep-mobile's
//! `mobile_approver` example drives it: in-memory storage, and a software
//! P-256 approver key with an attestation under the test root that only an
//! end-to-end build of the gateway trusts. Not for real use.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use keep_mobile::{
    ApprovalRequest, ApproverCallbacks, ApproverEvent, ApproverHandler, ApproverStatus, KeepMobile,
    KeepMobileError, SecureStorage, ShareMetadataInfo, ShareProbe,
};
use p256::ecdsa::signature::Signer;

#[derive(Default)]
struct Memory(Mutex<HashMap<String, Vec<u8>>>);

impl SecureStorage for Memory {
    fn quarantine_share_by_key(&self, _: String) -> Result<(), KeepMobileError> {
        Err(KeepMobileError::StorageError {
            msg: "quarantine unsupported".into(),
        })
    }
    fn restore_quarantined_share(&self, _: String) -> Result<(), KeepMobileError> {
        Err(KeepMobileError::StorageError {
            msg: "quarantine unsupported".into(),
        })
    }
    fn list_quarantined_share_keys(&self) -> Result<Vec<String>, KeepMobileError> {
        Ok(Vec::new())
    }
    fn probe_share_by_key(&self, _: String) -> Result<ShareProbe, KeepMobileError> {
        Ok(ShareProbe::Unknown)
    }
    fn store_share(&self, _: Vec<u8>, _: ShareMetadataInfo) -> Result<(), KeepMobileError> {
        Ok(())
    }
    fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
        Err(KeepMobileError::StorageNotFound)
    }
    fn has_share(&self) -> bool {
        false
    }
    fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
        None
    }
    fn delete_share(&self) -> Result<(), KeepMobileError> {
        Ok(())
    }
    fn store_share_by_key(
        &self,
        key: String,
        data: Vec<u8>,
        _: ShareMetadataInfo,
    ) -> Result<(), KeepMobileError> {
        self.0.lock().unwrap().insert(key, data);
        Ok(())
    }
    fn load_share_by_key(&self, key: String) -> Result<Vec<u8>, KeepMobileError> {
        self.0
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .ok_or(KeepMobileError::StorageNotFound)
    }
    fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
        Vec::new()
    }
    fn read_share_registry(&self) -> keep_mobile::ShareRegistryRead {
        keep_mobile::ShareRegistryRead::Readable {
            shares: self.list_all_shares(),
            unreadable: vec![],
        }
    }
    fn delete_share_by_key(&self, key: String) -> Result<(), KeepMobileError> {
        self.0.lock().unwrap().remove(&key);
        Ok(())
    }
    fn get_active_share_key(&self) -> Option<String> {
        None
    }
    fn read_active_share_key(&self) -> keep_mobile::StorageRead {
        match self.get_active_share_key() {
            Some(value) => keep_mobile::StorageRead::Found { value },
            None => keep_mobile::StorageRead::Absent,
        }
    }
    fn set_active_share_key(&self, _: Option<String>) -> Result<(), KeepMobileError> {
        Ok(())
    }
}

/// A software approver key that signs as the Keystore does: SHA-256 over
/// the digest, DER, and `s` negated every other time, so half come high.
struct Keystore {
    key: p256::ecdsa::SigningKey,
    flip: bool,
}

impl Keystore {
    fn generate() -> Result<Self, String> {
        let seed = zeroize::Zeroizing::new(
            keep_core::entropy::try_random_bytes::<32>().map_err(|e| e.to_string())?,
        );
        let key = p256::ecdsa::SigningKey::from_slice(&*seed).map_err(|e| e.to_string())?;
        Ok(Self { key, flip: false })
    }

    fn public(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    fn sign(&mut self, digest: &[u8]) -> Vec<u8> {
        let sig: p256::ecdsa::Signature = self.key.sign(digest);
        self.flip = !self.flip;
        let sig = if self.flip {
            let (r, s) = sig.split_scalars();
            p256::ecdsa::Signature::from_scalars(r.to_bytes(), (-*s).to_bytes())
                .expect("negating s keeps it in range")
        } else {
            sig
        };
        sig.to_der().as_bytes().to_vec()
    }
}

struct Log(Arc<Mutex<Vec<String>>>);

impl ApproverCallbacks for Log {
    fn on_event(&self, event: ApproverEvent) {
        let line = match event {
            ApproverEvent::Paired { fingerprint } => format!("Paired, fingerprint {fingerprint}"),
            ApproverEvent::PairingRefused { reason, ended, .. } => format!(
                "Pairing refused: {reason}{}",
                if ended {
                    " (pairing ended)"
                } else {
                    " (still waiting)"
                }
            ),
            ApproverEvent::Request { request } => format!(
                "Request {}: {}, {}",
                request.request_id, request.op, request.reason
            ),
            ApproverEvent::RequestRefused { reason } => format!("Request refused: {reason}"),
            ApproverEvent::RequestExpired { request_id } => format!("Request {request_id} lapsed"),
            ApproverEvent::Outcome {
                request_id,
                outcome,
            } => format!("Request {request_id}: {outcome}"),
            ApproverEvent::Anchor {
                epoch,
                all_frozen,
                audit_seq,
                ..
            } => format!("Anchor: epoch {epoch}, all frozen {all_frozen}, audit seq {audit_seq}"),
            ApproverEvent::Alert { message, .. } => format!("Alert: {message}"),
        };
        let at = chrono::Local::now().format("%H:%M:%S");
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!("{at} {line}"));
    }
}

pub struct Snapshot {
    pub status: ApproverStatus,
    pub waiting: Vec<ApprovalRequest>,
    pub log: Vec<String>,
}

/// Holds a tokio runtime inside keep-mobile: drop it only outside async
/// code (the app keeps it for its whole run).
pub struct TestApprover {
    handler: Arc<ApproverHandler>,
    keystore: Mutex<Keystore>,
    log: Arc<Mutex<Vec<String>>>,
}

fn err(e: KeepMobileError) -> String {
    e.to_string()
}

impl TestApprover {
    pub fn new() -> Result<Self, String> {
        let mobile = Arc::new(KeepMobile::new(Arc::new(Memory::default())).map_err(err)?);
        Ok(Self {
            handler: ApproverHandler::new(mobile).map_err(err)?,
            keystore: Mutex::new(Keystore::generate()?),
            log: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn sign(&self, digest: &[u8]) -> Vec<u8> {
        self.keystore
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sign(digest)
    }

    /// Pairs with a fresh approver key, as the Keystore makes one per
    /// pairing, and returns the fingerprint to compare with the gateway's.
    pub fn pair(&self, uri: &str) -> Result<String, String> {
        self.pair_with(uri, Arc::new(Log(self.log.clone())))
    }

    /// [`Self::pair`], with events going to `callbacks` instead of the log.
    pub fn pair_with(
        &self,
        uri: &str,
        callbacks: Arc<dyn ApproverCallbacks>,
    ) -> Result<String, String> {
        let challenge = self
            .handler
            .pairing_attestation_challenge(uri.to_string())
            .map_err(err)?;
        let challenge: [u8; 32] = challenge
            .try_into()
            .map_err(|_| "the attestation challenge is not 32 bytes".to_string())?;
        let (public, attestation) = {
            let mut keystore = self.keystore.lock().unwrap_or_else(|e| e.into_inner());
            *keystore = Keystore::generate()?;
            let public = keystore.public();
            let compressed: [u8; 33] = public
                .as_slice()
                .try_into()
                .map_err(|_| "the approver key is not 33 bytes".to_string())?;
            let chain = keep_approval::test_attestation::chain(&compressed, &challenge);
            (public, chain)
        };
        let start = self
            .handler
            .begin_pairing(uri.to_string(), public, "desktop test approver".into())
            .map_err(err)?;
        let signature = self.sign(&start.digest);
        self.handler
            .clone()
            .finish_pairing(signature, attestation.0, callbacks)
            .map_err(err)?;
        Ok(start.fingerprint)
    }

    fn decide(&self, request_id: &str, approve: bool) -> Result<(), String> {
        let digest = self
            .handler
            .decision_digest(request_id.to_string(), approve)
            .map_err(err)?;
        let signature = self.sign(&digest);
        self.handler
            .send_decision(request_id.to_string(), approve, signature)
            .map_err(err)
    }

    pub fn approve(&self, request_id: &str) -> Result<(), String> {
        self.decide(request_id, true)
    }

    pub fn deny(&self, request_id: &str) -> Result<(), String> {
        self.decide(request_id, false)
    }

    pub fn freeze_all(&self) -> Result<(), String> {
        self.handler.freeze(None).map_err(err)
    }

    pub fn unfreeze_all(&self) -> Result<(), String> {
        let digest = self.handler.unfreeze_digest(None).map_err(err)?;
        let signature = self.sign(&digest);
        self.handler.send_unfreeze(None, signature).map_err(err)
    }

    pub fn forget(&self) -> Result<(), String> {
        self.handler.forget().map_err(err)
    }

    pub fn is_waiting(&self, request_id: &str) -> bool {
        self.handler
            .waiting_requests()
            .iter()
            .any(|r| r.request_id == request_id)
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            status: self.handler.status(),
            waiting: self.handler.waiting_requests(),
            log: std::mem::take(&mut *self.log.lock().unwrap_or_else(|e| e.into_inner())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn starts_unpaired_and_refuses_a_bad_link() {
        let approver = TestApprover::new().unwrap();
        assert!(approver.pair("not a pairing link").is_err());
        let snapshot = approver.snapshot();
        assert!(!snapshot.status.paired && !snapshot.status.pairing);
        assert!(snapshot.waiting.is_empty());
        assert!(approver.approve(&"00".repeat(32)).is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pairs_from_a_blocking_thread_as_the_app_does() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let uri = keep_approval::pairing::PairingUri {
            gateway: nostr_sdk::Keys::generate().public_key().to_bytes(),
            secret: zeroize::Zeroizing::new([7; 32]),
            relays: vec![format!("ws://127.0.0.1:{port}")],
        }
        .to_uri()
        .unwrap();
        let outcome = tokio::task::spawn_blocking(move || {
            let approver = TestApprover::new().unwrap();
            let paired = approver.pair(&uri);
            (paired, approver.snapshot().status)
        })
        .await
        .expect("no panic on a blocking thread");
        assert!(outcome.0.is_err(), "no relay listens: {:?}", outcome.0);
        assert!(!outcome.1.paired);
    }

    #[test]
    fn signs_der_with_s_flipped_every_other_time() {
        let mut keystore = Keystore::generate().unwrap();
        let verifying = *keystore.key.verifying_key();
        let highs: Vec<bool> = (0..2)
            .map(|_| {
                let der = keystore.sign(b"digest");
                let sig = p256::ecdsa::Signature::from_der(&der).unwrap();
                let high = sig.normalize_s().is_some();
                verifying
                    .verify(b"digest", &sig.normalize_s().unwrap_or(sig))
                    .unwrap();
                high
            })
            .collect();
        assert_ne!(highs[0], highs[1]);
    }
}
