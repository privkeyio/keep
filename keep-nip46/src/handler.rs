// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::HashMap;
use std::sync::Arc;

use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use keep_core::error::{CryptoError, KeepError, Result};
use keep_core::keyring::Keyring;

use crate::audit::{AuditAction, AuditEntry, AuditLog};
use crate::frost_signer::{FrostSigner, NetworkFrostSigner};
use crate::permissions::{AppPermission, Permission, PermissionManager};
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::types::{ApprovalRequest, ServerCallbacks};

fn prepare_frost_event(
    pubkey: PublicKey,
    unsigned: &UnsignedEvent,
) -> Result<(UnsignedEvent, EventId)> {
    let mut frost_event = UnsignedEvent::new(
        pubkey,
        unsigned.created_at,
        unsigned.kind,
        unsigned.tags.clone(),
        unsigned.content.clone(),
    );
    frost_event.ensure_id();
    let event_id = frost_event
        .id
        .ok_or_else(|| KeepError::Runtime("failed to compute event ID".into()))?;
    Ok((frost_event, event_id))
}

fn assemble_signed_event(
    event_id: EventId,
    pubkey: PublicKey,
    frost_event: UnsignedEvent,
    sig_bytes: &[u8],
) -> Result<Event> {
    let sig = nostr_sdk::secp256k1::schnorr::Signature::from_slice(sig_bytes)
        .map_err(|e| CryptoError::invalid_signature(e.to_string()))?;
    Ok(Event::new(
        event_id,
        pubkey,
        frost_event.created_at,
        frost_event.kind,
        frost_event.tags,
        frost_event.content,
        sig,
    ))
}

fn parse_permission_string(perms: &str) -> Permission {
    let mut result = Permission::empty();
    for part in perms.split(',') {
        match part.trim() {
            "get_public_key" => result |= Permission::GET_PUBLIC_KEY,
            "sign_event" => result |= Permission::SIGN_EVENT,
            "nip04_encrypt" => result |= Permission::NIP04_ENCRYPT,
            "nip04_decrypt" => result |= Permission::NIP04_DECRYPT,
            "nip44_encrypt" => result |= Permission::NIP44_ENCRYPT,
            "nip44_decrypt" => result |= Permission::NIP44_DECRYPT,
            _ => {}
        }
    }
    if result.is_empty() {
        Permission::DEFAULT
    } else {
        result | Permission::GET_PUBLIC_KEY
    }
}

pub struct SignerHandler {
    keyring: Arc<Mutex<Keyring>>,
    frost_signer: Option<Arc<Mutex<FrostSigner>>>,
    network_frost_signer: Option<Arc<NetworkFrostSigner>>,
    permissions: Arc<Mutex<PermissionManager>>,
    audit: Arc<Mutex<AuditLog>>,
    callbacks: Option<Arc<dyn ServerCallbacks>>,
    rate_limiters: Mutex<HashMap<PublicKey, RateLimiter>>,
    rate_limit_config: Option<RateLimitConfig>,
    expected_secret: Option<String>,
    auto_approve: bool,
}

impl SignerHandler {
    pub fn new(
        keyring: Arc<Mutex<Keyring>>,
        permissions: Arc<Mutex<PermissionManager>>,
        audit: Arc<Mutex<AuditLog>>,
        callbacks: Option<Arc<dyn ServerCallbacks>>,
    ) -> Self {
        Self {
            keyring,
            frost_signer: None,
            network_frost_signer: None,
            permissions,
            audit,
            callbacks,
            rate_limiters: Mutex::new(HashMap::new()),
            rate_limit_config: None,
            expected_secret: None,
            auto_approve: false,
        }
    }

    pub fn with_expected_secret(mut self, secret: String) -> Self {
        self.expected_secret = Some(secret);
        self
    }

    pub fn with_auto_approve(mut self, auto_approve: bool) -> Self {
        self.auto_approve = auto_approve;
        self
    }

    pub fn with_frost_signer(mut self, signer: FrostSigner) -> Self {
        self.frost_signer = Some(Arc::new(Mutex::new(signer)));
        self
    }

    pub fn with_network_frost_signer(mut self, signer: NetworkFrostSigner) -> Self {
        self.network_frost_signer = Some(Arc::new(signer));
        self
    }

    pub fn with_rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit_config = Some(config);
        self
    }

    const MAX_RATE_LIMITERS: usize = 1_000;

    async fn check_rate_limit(&self, app_pubkey: &PublicKey) -> Result<()> {
        let config = match &self.rate_limit_config {
            Some(c) => c,
            None => return Ok(()),
        };

        let mut limiters = self.rate_limiters.lock().await;

        if limiters.len() >= Self::MAX_RATE_LIMITERS && !limiters.contains_key(app_pubkey) {
            limiters.retain(|_, rl| {
                rl.cleanup();
                !rl.is_empty()
            });
            if limiters.len() >= Self::MAX_RATE_LIMITERS {
                let oldest_key = limiters
                    .iter()
                    .min_by_key(|(_, rl)| rl.last_used())
                    .map(|(k, _)| *k);
                if let Some(key) = oldest_key {
                    limiters.remove(&key);
                }
            }
        }

        let limiter = limiters
            .entry(*app_pubkey)
            .or_insert_with(|| RateLimiter::new(config.clone()));

        if limiter.check_and_record().is_allowed() {
            Ok(())
        } else {
            Err(KeepError::RateLimited(60))
        }
    }

    async fn require_permission(&self, app_pubkey: &PublicKey, perm: Permission) -> Result<()> {
        let pm = self.permissions.lock().await;
        if pm.has_permission(app_pubkey, perm) {
            Ok(())
        } else {
            Err(KeepError::PermissionDenied(
                "operation not permitted".into(),
            ))
        }
    }

    async fn our_pubkey(&self) -> Result<PublicKey> {
        if let Some(ref net_frost) = self.network_frost_signer {
            Ok(PublicKey::from_slice(net_frost.group_pubkey())
                .map_err(|e| CryptoError::invalid_key(format!("FROST pubkey: {e}")))?)
        } else if let Some(ref frost) = self.frost_signer {
            let signer = frost.lock().await;
            Ok(PublicKey::from_slice(signer.group_pubkey())
                .map_err(|e| CryptoError::invalid_key(format!("FROST pubkey: {e}")))?)
        } else {
            let keyring = self.keyring.lock().await;
            let slot = keyring
                .get_primary()
                .ok_or_else(|| KeepError::KeyNotFound("no signing key".into()))?;
            Ok(PublicKey::from_slice(&slot.pubkey)
                .map_err(|e| CryptoError::invalid_key(format!("pubkey: {e}")))?)
        }
    }

    pub async fn handle_connect(
        &self,
        app_pubkey: PublicKey,
        our_pubkey: Option<PublicKey>,
        secret: Option<String>,
        permissions: Option<String>,
    ) -> Result<()> {
        self.check_rate_limit(&app_pubkey).await?;

        let app_id = &app_pubkey.to_hex()[..8];
        let name = format!("App {app_id}");

        if let Some(ref expected) = self.expected_secret {
            let expected_hash = Sha256::digest(expected.as_bytes());
            let valid = match &secret {
                Some(s) => {
                    let provided_hash = Sha256::digest(s.as_bytes());
                    provided_hash.ct_eq(&expected_hash).into()
                }
                None => false,
            };
            if !valid {
                let mut audit = self.audit.lock().await;
                audit.log(
                    AuditEntry::new(AuditAction::Connect, app_pubkey)
                        .with_success(false)
                        .with_reason("invalid secret"),
                );
                return Err(KeepError::PermissionDenied("invalid secret".into()));
            }
        } else if !self.auto_approve {
            let approved = self
                .request_approval(ApprovalRequest {
                    app_pubkey,
                    app_name: name.clone(),
                    method: "connect".into(),
                    event_kind: None,
                    event_content: None,
                })
                .await;
            if !approved {
                return Err(KeepError::UserRejected);
            }
        }

        if let Some(expected) = our_pubkey {
            let actual = self.our_pubkey().await?;
            if expected != actual {
                return Err(CryptoError::invalid_key("pubkey mismatch").into());
            }
        }

        let requested_perms = permissions
            .as_deref()
            .map(parse_permission_string)
            .unwrap_or(Permission::DEFAULT);

        let mut pm = self.permissions.lock().await;
        if !pm.connect_with_permissions(app_pubkey, name.clone(), requested_perms) {
            return Err(KeepError::CapacityExceeded(
                "too many connected apps".into(),
            ));
        }

        let mut audit = self.audit.lock().await;
        audit.log(AuditEntry::new(AuditAction::Connect, app_pubkey).with_app_name(&name));

        info!(app_id, "app connected");
        Ok(())
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
            return Err(KeepError::PermissionDenied(
                "operation not permitted".into(),
            ));
        }
        drop(pm);

        let pubkey = self.our_pubkey().await?;

        let mut audit = self.audit.lock().await;
        audit.log(AuditEntry::new(AuditAction::GetPublicKey, app_pubkey));

        Ok(pubkey)
    }

    pub async fn handle_sign_event(
        &self,
        app_pubkey: PublicKey,
        unsigned_event: UnsignedEvent,
    ) -> Result<Event> {
        self.check_rate_limit(&app_pubkey).await?;

        let kind = unsigned_event.kind;

        let needs_approval = {
            let pm = self.permissions.lock().await;
            if !pm.has_permission(&app_pubkey, Permission::SIGN_EVENT) {
                let mut audit = self.audit.lock().await;
                audit.log(
                    AuditEntry::new(AuditAction::PermissionDenied, app_pubkey)
                        .with_event_kind(kind)
                        .with_success(false),
                );
                return Err(KeepError::PermissionDenied(
                    "operation not permitted".into(),
                ));
            }
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
                return Err(KeepError::UserRejected);
            }
        }

        let signed_event = if let Some(ref net_frost) = self.network_frost_signer {
            let pubkey = PublicKey::from_slice(net_frost.group_pubkey())
                .map_err(|e| CryptoError::invalid_key(format!("pubkey: {e}")))?;
            let (frost_event, event_id) = prepare_frost_event(pubkey, &unsigned_event)?;
            let sig_bytes = net_frost.sign(event_id.as_bytes()).await?;
            assemble_signed_event(event_id, pubkey, frost_event, &sig_bytes)?
        } else if let Some(ref frost) = self.frost_signer {
            let signer = frost.lock().await;
            let pubkey = PublicKey::from_slice(signer.group_pubkey())
                .map_err(|e| CryptoError::invalid_key(format!("pubkey: {e}")))?;
            let (frost_event, event_id) = prepare_frost_event(pubkey, &unsigned_event)?;
            let sig_bytes = signer.sign(event_id.as_bytes())?;
            assemble_signed_event(event_id, pubkey, frost_event, &sig_bytes)?
        } else {
            let keyring = self.keyring.lock().await;
            let slot = keyring
                .get_primary()
                .ok_or_else(|| KeepError::KeyNotFound("no signing key".into()))?;

            let keypair = slot.to_nostr_keypair()?;
            let secret = SecretKey::from_slice(keypair.secret_bytes())
                .map_err(|e| CryptoError::invalid_key(format!("secret key: {e}")))?;
            let keys = Keys::new(secret);

            unsigned_event
                .sign(&keys)
                .await
                .map_err(|e| CryptoError::invalid_signature(format!("signing: {e}")))?
        };

        let mut keyring = self.keyring.lock().await;
        if let Some(slot) = keyring.get_primary_mut() {
            slot.session_sign_count += 1;
        }
        drop(keyring);

        self.permissions.lock().await.record_usage(&app_pubkey);

        self.audit.lock().await.log(
            AuditEntry::new(AuditAction::SignEvent, app_pubkey)
                .with_event_kind(kind)
                .with_event_id(signed_event.id),
        );

        let event_kind = kind.as_u16();
        let event_id = &signed_event.id.to_hex()[..8];
        debug!(event_kind, event_id, "signed event");
        Ok(signed_event)
    }

    pub async fn handle_nip44_encrypt(
        &self,
        app_pubkey: PublicKey,
        recipient: PublicKey,
        plaintext: &str,
    ) -> Result<String> {
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::NIP44_ENCRYPT)
            .await?;

        let keyring = self.keyring.lock().await;
        let slot = keyring
            .get_primary()
            .ok_or_else(|| KeepError::KeyNotFound("no signing key".into()))?;

        let keypair = slot.to_nostr_keypair()?;
        let secret = SecretKey::from_slice(keypair.secret_bytes())
            .map_err(|e| CryptoError::invalid_key(format!("secret key: {e}")))?;

        let ciphertext = nip44::encrypt(&secret, &recipient, plaintext, nip44::Version::V2)
            .map_err(|e| CryptoError::encryption(format!("NIP-44: {e}")))?;
        drop(keyring);

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::Nip44Encrypt, app_pubkey));

        Ok(ciphertext)
    }

    pub async fn handle_nip44_decrypt(
        &self,
        app_pubkey: PublicKey,
        sender: PublicKey,
        ciphertext: &str,
    ) -> Result<String> {
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::NIP44_DECRYPT)
            .await?;

        let approved = self
            .request_approval(ApprovalRequest {
                app_pubkey,
                app_name: self.get_app_name(&app_pubkey).await,
                method: "nip44_decrypt".into(),
                event_kind: None,
                event_content: None,
            })
            .await;
        if !approved {
            return Err(KeepError::UserRejected);
        }

        let keyring = self.keyring.lock().await;
        let slot = keyring
            .get_primary()
            .ok_or_else(|| KeepError::KeyNotFound("no signing key".into()))?;

        let keypair = slot.to_nostr_keypair()?;
        let secret = SecretKey::from_slice(keypair.secret_bytes())
            .map_err(|e| CryptoError::invalid_key(format!("secret key: {e}")))?;

        let plaintext = nip44::decrypt(&secret, &sender, ciphertext)
            .map_err(|e| CryptoError::decryption(format!("NIP-44: {e}")))?;
        drop(keyring);

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::Nip44Decrypt, app_pubkey));

        Ok(plaintext)
    }

    pub async fn handle_nip04_encrypt(
        &self,
        app_pubkey: PublicKey,
        recipient: PublicKey,
        plaintext: &str,
    ) -> Result<String> {
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::NIP04_ENCRYPT)
            .await?;

        let keyring = self.keyring.lock().await;
        let slot = keyring
            .get_primary()
            .ok_or_else(|| KeepError::KeyNotFound("no signing key".into()))?;

        let keypair = slot.to_nostr_keypair()?;
        let secret = SecretKey::from_slice(keypair.secret_bytes())
            .map_err(|e| CryptoError::invalid_key(format!("secret key: {e}")))?;

        let ciphertext = nip04::encrypt(&secret, &recipient, plaintext)
            .map_err(|e| CryptoError::encryption(format!("NIP-04: {e}")))?;
        drop(keyring);

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::Nip04Encrypt, app_pubkey));

        Ok(ciphertext)
    }

    pub async fn handle_nip04_decrypt(
        &self,
        app_pubkey: PublicKey,
        sender: PublicKey,
        ciphertext: &str,
    ) -> Result<String> {
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::NIP04_DECRYPT)
            .await?;

        let approved = self
            .request_approval(ApprovalRequest {
                app_pubkey,
                app_name: self.get_app_name(&app_pubkey).await,
                method: "nip04_decrypt".into(),
                event_kind: None,
                event_content: None,
            })
            .await;
        if !approved {
            return Err(KeepError::UserRejected);
        }

        let keyring = self.keyring.lock().await;
        let slot = keyring
            .get_primary()
            .ok_or_else(|| KeepError::KeyNotFound("no signing key".into()))?;

        let keypair = slot.to_nostr_keypair()?;
        let secret = SecretKey::from_slice(keypair.secret_bytes())
            .map_err(|e| CryptoError::invalid_key(format!("secret key: {e}")))?;

        let plaintext = nip04::decrypt(&secret, &sender, ciphertext)
            .map_err(|e| CryptoError::decryption(format!("NIP-04: {e}")))?;
        drop(keyring);

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::Nip04Decrypt, app_pubkey));

        Ok(plaintext)
    }

    pub async fn list_clients(&self) -> Vec<AppPermission> {
        let pm = self.permissions.lock().await;
        pm.list_apps().cloned().collect()
    }

    pub async fn revoke_client(&self, pubkey: &PublicKey) {
        let mut pm = self.permissions.lock().await;
        pm.revoke(pubkey);
    }

    pub async fn revoke_all_clients(&self) {
        let mut pm = self.permissions.lock().await;
        pm.revoke_all();
    }

    pub(crate) async fn get_app_name(&self, pubkey: &PublicKey) -> String {
        let pm = self.permissions.lock().await;
        pm.get_app(pubkey)
            .map(|app| app.name.clone())
            .unwrap_or_else(|| pubkey.to_hex()[..8].to_string())
    }

    async fn request_approval(&self, request: ApprovalRequest) -> bool {
        if let Some(ref callbacks) = self.callbacks {
            return callbacks.request_approval(request);
        }
        if self.auto_approve {
            warn!(method = %request.method, "auto-approving in headless mode");
            return true;
        }
        warn!(method = %request.method, "denying request: no approval callbacks configured");
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;
    use crate::permissions::PermissionManager;
    use keep_core::keyring::Keyring;
    use keep_core::keys::{KeyType, NostrKeypair};

    fn setup_keyring() -> Arc<Mutex<Keyring>> {
        let mut keyring = Keyring::new();
        let keypair = NostrKeypair::generate().unwrap();
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
        SignerHandler::new(keyring, permissions, audit, None).with_auto_approve(true)
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
