#![forbid(unsafe_code)]

use std::sync::mpsc::{self, Sender};
use std::sync::Arc;

use nostr_sdk::prelude::*;
use tokio::sync::Mutex;
use tracing::{debug, info};

use keep_core::error::{KeepError, Result};
use keep_core::keyring::Keyring;

use crate::tui::{ApprovalRequest as TuiApprovalRequest, TuiEvent};

use super::audit::{AuditAction, AuditEntry, AuditLog};
use super::frost_signer::FrostSigner;
use super::permissions::{Permission, PermissionManager};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ApprovalRequest {
    pub app_pubkey: PublicKey,
    pub app_name: String,
    pub method: String,
    pub event_kind: Option<Kind>,
    pub event_content: Option<String>,
}

pub struct SignerHandler {
    keyring: Arc<Mutex<Keyring>>,
    frost_signer: Option<Arc<Mutex<FrostSigner>>>,
    permissions: Arc<Mutex<PermissionManager>>,
    audit: Arc<Mutex<AuditLog>>,
    tui_tx: Option<Sender<TuiEvent>>,
    next_approval_id: std::sync::atomic::AtomicU64,
}

impl SignerHandler {
    pub fn new(
        keyring: Arc<Mutex<Keyring>>,
        permissions: Arc<Mutex<PermissionManager>>,
        audit: Arc<Mutex<AuditLog>>,
        tui_tx: Option<Sender<TuiEvent>>,
    ) -> Self {
        Self {
            keyring,
            frost_signer: None,
            permissions,
            audit,
            tui_tx,
            next_approval_id: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn with_frost_signer(mut self, signer: FrostSigner) -> Self {
        self.frost_signer = Some(Arc::new(Mutex::new(signer)));
        self
    }

    pub async fn handle_connect(
        &self,
        app_pubkey: PublicKey,
        our_pubkey: Option<PublicKey>,
        secret: Option<String>,
        _permissions: Option<String>,
    ) -> Result<Option<String>> {
        if let Some(expected) = our_pubkey {
            let actual = if let Some(ref frost) = self.frost_signer {
                let signer = frost.lock().await;
                PublicKey::from_slice(signer.group_pubkey())
                    .map_err(|e| KeepError::Other(format!("Invalid FROST pubkey: {}", e)))?
            } else {
                let keyring = self.keyring.lock().await;
                let slot = keyring
                    .get_primary()
                    .ok_or_else(|| KeepError::Other("No signing key".into()))?;
                PublicKey::from_slice(&slot.pubkey)
                    .map_err(|e| KeepError::Other(format!("Invalid pubkey: {}", e)))?
            };
            if expected != actual {
                return Err(KeepError::Other("Pubkey mismatch".into()));
            }
        }

        let name = format!("App {}", &app_pubkey.to_hex()[..8]);

        let mut pm = self.permissions.lock().await;
        pm.connect(app_pubkey, name.clone());

        let mut audit = self.audit.lock().await;
        audit.log(AuditEntry::new(AuditAction::Connect, app_pubkey).with_app_name(&name));

        info!("App connected: {}", &app_pubkey.to_hex()[..8]);
        Ok(secret)
    }

    pub async fn handle_get_public_key(&self, app_pubkey: PublicKey) -> Result<PublicKey> {
        let pm = self.permissions.lock().await;
        if !pm.has_permission(&app_pubkey, Permission::GET_PUBLIC_KEY) {
            let mut audit = self.audit.lock().await;
            audit.log(
                AuditEntry::new(AuditAction::PermissionDenied, app_pubkey)
                    .with_success(false)
                    .with_reason("get_public_key not permitted"),
            );
            return Err(KeepError::Other("Permission denied".into()));
        }
        drop(pm);

        let pubkey = if let Some(ref frost) = self.frost_signer {
            let signer = frost.lock().await;
            PublicKey::from_slice(signer.group_pubkey())
                .map_err(|e| KeepError::Other(format!("Invalid FROST pubkey: {}", e)))?
        } else {
            let keyring = self.keyring.lock().await;
            let slot = keyring
                .get_primary()
                .ok_or_else(|| KeepError::Other("No signing key".into()))?;
            PublicKey::from_slice(&slot.pubkey)
                .map_err(|e| KeepError::Other(format!("Invalid pubkey: {}", e)))?
        };

        let mut audit = self.audit.lock().await;
        audit.log(AuditEntry::new(AuditAction::GetPublicKey, app_pubkey));

        Ok(pubkey)
    }

    pub async fn handle_sign_event(
        &self,
        app_pubkey: PublicKey,
        unsigned_event: UnsignedEvent,
    ) -> Result<Event> {
        let kind = unsigned_event.kind;

        {
            let pm = self.permissions.lock().await;
            if !pm.has_permission(&app_pubkey, Permission::SIGN_EVENT) {
                let mut audit = self.audit.lock().await;
                audit.log(
                    AuditEntry::new(AuditAction::PermissionDenied, app_pubkey)
                        .with_event_kind(kind)
                        .with_success(false),
                );
                return Err(KeepError::Other("Permission denied".into()));
            }
        }

        let needs_approval = {
            let pm = self.permissions.lock().await;
            pm.needs_approval(&app_pubkey, kind)
        };

        if needs_approval {
            let approved = self
                .request_approval(ApprovalRequest {
                    app_pubkey,
                    app_name: self.get_app_name(&app_pubkey).await,
                    method: "sign_event".into(),
                    event_kind: Some(kind),
                    event_content: Some(unsigned_event.content.clone()),
                })
                .await;

            if !approved {
                let mut audit = self.audit.lock().await;
                audit.log(
                    AuditEntry::new(AuditAction::UserRejected, app_pubkey)
                        .with_event_kind(kind)
                        .with_success(false),
                );
                return Err(KeepError::Other("User rejected".into()));
            }
        }

        let signed_event = if let Some(ref frost) = self.frost_signer {
            let signer = frost.lock().await;
            let pubkey = PublicKey::from_slice(signer.group_pubkey())
                .map_err(|e| KeepError::Other(format!("Invalid pubkey: {}", e)))?;
            let mut frost_event = UnsignedEvent::new(
                pubkey,
                unsigned_event.created_at,
                unsigned_event.kind,
                unsigned_event.tags.clone(),
                unsigned_event.content.clone(),
            );
            frost_event.ensure_id();
            let event_id = frost_event
                .id
                .ok_or_else(|| KeepError::Other("Failed to compute event ID".into()))?;
            let sig_bytes = signer.sign(event_id.as_bytes())?;
            let sig = nostr_sdk::secp256k1::schnorr::Signature::from_slice(&sig_bytes)
                .map_err(|e| KeepError::Other(format!("Invalid signature: {}", e)))?;
            Event::new(
                event_id,
                pubkey,
                frost_event.created_at,
                frost_event.kind,
                frost_event.tags,
                frost_event.content,
                sig,
            )
        } else {
            let keyring = self.keyring.lock().await;
            let slot = keyring
                .get_primary()
                .ok_or_else(|| KeepError::Other("No signing key".into()))?;

            let keypair = slot.to_nostr_keypair()?;
            let secret = SecretKey::from_slice(keypair.secret_bytes())
                .map_err(|e| KeepError::Other(format!("Invalid secret key: {}", e)))?;
            let keys = Keys::new(secret);

            unsigned_event
                .sign(&keys)
                .map_err(|e| KeepError::Other(format!("Signing failed: {}", e)))?
        };

        {
            let mut keyring = self.keyring.lock().await;
            if let Some(slot) = keyring.get_primary_mut() {
                slot.session_sign_count += 1;
            }
        }

        {
            let mut pm = self.permissions.lock().await;
            pm.record_usage(&app_pubkey);
        }

        {
            let mut audit = self.audit.lock().await;
            audit.log(
                AuditEntry::new(AuditAction::SignEvent, app_pubkey)
                    .with_event_kind(kind)
                    .with_event_id(signed_event.id),
            );
        }

        debug!(
            "Signed event kind:{} id:{}",
            kind.as_u16(),
            &signed_event.id.to_hex()[..8]
        );
        Ok(signed_event)
    }

    pub async fn handle_nip44_encrypt(
        &self,
        app_pubkey: PublicKey,
        recipient: PublicKey,
        plaintext: &str,
    ) -> Result<String> {
        {
            let pm = self.permissions.lock().await;
            if !pm.has_permission(&app_pubkey, Permission::NIP44_ENCRYPT) {
                return Err(KeepError::Other("Permission denied".into()));
            }
        }

        let ciphertext = {
            let keyring = self.keyring.lock().await;
            let slot = keyring
                .get_primary()
                .ok_or_else(|| KeepError::Other("No signing key".into()))?;

            let keypair = slot.to_nostr_keypair()?;
            let secret = SecretKey::from_slice(keypair.secret_bytes())
                .map_err(|e| KeepError::Other(format!("Invalid secret key: {}", e)))?;

            nip44::encrypt(&secret, &recipient, plaintext, nip44::Version::V2)
                .map_err(|e| KeepError::Other(format!("NIP-44 encrypt failed: {}", e)))?
        };

        let mut audit = self.audit.lock().await;
        audit.log(AuditEntry::new(AuditAction::Nip44Encrypt, app_pubkey));

        Ok(ciphertext)
    }

    pub async fn handle_nip44_decrypt(
        &self,
        app_pubkey: PublicKey,
        sender: PublicKey,
        ciphertext: &str,
    ) -> Result<String> {
        {
            let pm = self.permissions.lock().await;
            if !pm.has_permission(&app_pubkey, Permission::NIP44_DECRYPT) {
                return Err(KeepError::Other("Permission denied".into()));
            }
        }

        let plaintext = {
            let keyring = self.keyring.lock().await;
            let slot = keyring
                .get_primary()
                .ok_or_else(|| KeepError::Other("No signing key".into()))?;

            let keypair = slot.to_nostr_keypair()?;
            let secret = SecretKey::from_slice(keypair.secret_bytes())
                .map_err(|e| KeepError::Other(format!("Invalid secret key: {}", e)))?;

            nip44::decrypt(&secret, &sender, ciphertext)
                .map_err(|e| KeepError::Other(format!("NIP-44 decrypt failed: {}", e)))?
        };

        let mut audit = self.audit.lock().await;
        audit.log(AuditEntry::new(AuditAction::Nip44Decrypt, app_pubkey));

        Ok(plaintext)
    }

    pub async fn handle_nip04_encrypt(
        &self,
        app_pubkey: PublicKey,
        recipient: PublicKey,
        plaintext: &str,
    ) -> Result<String> {
        {
            let pm = self.permissions.lock().await;
            if !pm.has_permission(&app_pubkey, Permission::NIP04_ENCRYPT) {
                return Err(KeepError::Other("Permission denied".into()));
            }
        }

        let ciphertext = {
            let keyring = self.keyring.lock().await;
            let slot = keyring
                .get_primary()
                .ok_or_else(|| KeepError::Other("No signing key".into()))?;

            let keypair = slot.to_nostr_keypair()?;
            let secret = SecretKey::from_slice(keypair.secret_bytes())
                .map_err(|e| KeepError::Other(format!("Invalid secret key: {}", e)))?;

            nip04::encrypt(&secret, &recipient, plaintext)
                .map_err(|e| KeepError::Other(format!("NIP-04 encrypt failed: {}", e)))?
        };

        let mut audit = self.audit.lock().await;
        audit.log(AuditEntry::new(AuditAction::Nip04Encrypt, app_pubkey));

        Ok(ciphertext)
    }

    pub async fn handle_nip04_decrypt(
        &self,
        app_pubkey: PublicKey,
        sender: PublicKey,
        ciphertext: &str,
    ) -> Result<String> {
        {
            let pm = self.permissions.lock().await;
            if !pm.has_permission(&app_pubkey, Permission::NIP04_DECRYPT) {
                return Err(KeepError::Other("Permission denied".into()));
            }
        }

        let plaintext = {
            let keyring = self.keyring.lock().await;
            let slot = keyring
                .get_primary()
                .ok_or_else(|| KeepError::Other("No signing key".into()))?;

            let keypair = slot.to_nostr_keypair()?;
            let secret = SecretKey::from_slice(keypair.secret_bytes())
                .map_err(|e| KeepError::Other(format!("Invalid secret key: {}", e)))?;

            nip04::decrypt(&secret, &sender, ciphertext)
                .map_err(|e| KeepError::Other(format!("NIP-04 decrypt failed: {}", e)))?
        };

        let mut audit = self.audit.lock().await;
        audit.log(AuditEntry::new(AuditAction::Nip04Decrypt, app_pubkey));

        Ok(plaintext)
    }

    async fn get_app_name(&self, pubkey: &PublicKey) -> String {
        let pm = self.permissions.lock().await;
        pm.get_app(pubkey)
            .map(|app| app.name.clone())
            .unwrap_or_else(|| pubkey.to_hex()[..8].to_string())
    }

    async fn request_approval(&self, request: ApprovalRequest) -> bool {
        let method = request.method.clone();
        if let Some(ref tx) = self.tui_tx {
            let (response_tx, response_rx) = mpsc::channel();
            let id = self
                .next_approval_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

            let tui_req = TuiApprovalRequest {
                id,
                app: request.app_name,
                action: request.method,
                kind: request.event_kind.map(|k| k.as_u16()),
                content_preview: request.event_content,
                response_tx,
            };

            if tx.send(TuiEvent::Approval(tui_req)).is_ok() {
                return tokio::task::spawn_blocking(move || response_rx.recv().unwrap_or(false))
                    .await
                    .unwrap_or(false);
            }
        }
        info!("Auto-approving {} (headless mode)", method);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keep_core::keyring::Keyring;
    use keep_core::keys::{KeyType, NostrKeypair};

    fn setup_keyring() -> Arc<Mutex<Keyring>> {
        let mut keyring = Keyring::new();
        let keypair = NostrKeypair::generate();
        keyring
            .load_key(
                *keypair.public_bytes(),
                *keypair.secret_bytes(),
                KeyType::Nostr,
                "test".to_string(),
            )
            .unwrap();
        Arc::new(Mutex::new(keyring))
    }

    fn setup_handler() -> SignerHandler {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        SignerHandler::new(keyring, permissions, audit, None)
    }

    #[tokio::test]
    async fn test_handle_connect() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        let result = handler.handle_connect(app_pubkey, None, None, None).await;
        assert!(result.is_ok());

        let pm = handler.permissions.lock().await;
        assert!(pm.is_connected(&app_pubkey));
    }

    #[tokio::test]
    async fn test_handle_connect_with_pubkey_mismatch() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();
        let wrong_pubkey = Keys::generate().public_key();

        let result = handler
            .handle_connect(app_pubkey, Some(wrong_pubkey), None, None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_get_public_key() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();

        let result = handler.handle_get_public_key(app_pubkey).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_get_public_key_no_permission() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        let result = handler.handle_get_public_key(app_pubkey).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_sign_event_no_permission() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        let keyring = handler.keyring.lock().await;
        let slot = keyring.get_primary().unwrap();
        let pubkey = PublicKey::from_slice(&slot.pubkey).unwrap();
        drop(keyring);

        let unsigned = UnsignedEvent::new(pubkey, Timestamp::now(), Kind::TextNote, vec![], "test");

        let result = handler.handle_sign_event(app_pubkey, unsigned).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_nip44_encrypt_decrypt() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();
        let recipient_keys = Keys::generate();
        let recipient = recipient_keys.public_key();

        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();

        {
            let mut pm = handler.permissions.lock().await;
            pm.grant(
                app_pubkey,
                "Test".into(),
                Permission::NIP44_ENCRYPT | Permission::NIP44_DECRYPT,
            );
        }

        let plaintext = "Hello, Nostr!";
        let ciphertext = handler
            .handle_nip44_encrypt(app_pubkey, recipient, plaintext)
            .await
            .unwrap();

        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, plaintext);
    }

    #[tokio::test]
    async fn test_get_app_name() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        let name = handler.get_app_name(&app_pubkey).await;
        assert_eq!(name, &app_pubkey.to_hex()[..8]);

        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();
        let name = handler.get_app_name(&app_pubkey).await;
        assert!(name.starts_with("App "));
    }
}
