// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use keep_core::error::{CryptoError, KeepError, Result};
use keep_core::keyring::Keyring;

use crate::audit::{AuditAction, AuditEntry, AuditLog};
use crate::frost_signer::{FrostSigner, NetworkFrostSigner};
use crate::permissions::{AppPermission, Permission, PermissionDuration, PermissionManager};
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

fn parse_permission_string(perms: &str) -> (Permission, HashSet<Kind>) {
    let mut result = Permission::empty();
    let mut auto_kinds = HashSet::new();
    for part in perms.split(',') {
        let trimmed = part.trim();
        if let Some(kind_str) = trimmed.strip_prefix("sign_event:") {
            result |= Permission::SIGN_EVENT;
            if let Ok(kind_num) = kind_str.parse::<u16>() {
                auto_kinds.insert(Kind::from(kind_num));
            }
        } else {
            match trimmed {
                "get_public_key" => result |= Permission::GET_PUBLIC_KEY,
                "sign_event" => result |= Permission::SIGN_EVENT,
                "nip04_encrypt" => result |= Permission::NIP04_ENCRYPT,
                "nip04_decrypt" => result |= Permission::NIP04_DECRYPT,
                "nip44_encrypt" => result |= Permission::NIP44_ENCRYPT,
                "nip44_decrypt" => result |= Permission::NIP44_DECRYPT,
                _ => {}
            }
        }
    }
    if result.is_empty() {
        (Permission::DEFAULT, auto_kinds)
    } else {
        (result | Permission::GET_PUBLIC_KEY, auto_kinds)
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
    new_conn_timestamps: Mutex<VecDeque<Instant>>,
    expected_secret: Option<String>,
    auto_approve: bool,
    relay_urls: Vec<String>,
    kill_switch: Arc<AtomicBool>,
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
            new_conn_timestamps: Mutex::new(VecDeque::new()),
            expected_secret: None,
            auto_approve: false,
            relay_urls: Vec::new(),
            kill_switch: Arc::new(AtomicBool::new(false)),
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

    pub fn with_relay_urls(mut self, urls: Vec<String>) -> Self {
        self.relay_urls = urls;
        self
    }

    pub fn with_kill_switch(mut self, kill_switch: Arc<AtomicBool>) -> Self {
        self.kill_switch = kill_switch;
        self
    }

    pub fn set_kill_switch(&self, active: bool) {
        self.kill_switch.store(active, Ordering::Release);
    }

    fn check_kill_switch(&self) -> Result<()> {
        if self.kill_switch.load(Ordering::Acquire) {
            Err(KeepError::PermissionDenied(
                "kill switch active — all signing blocked".into(),
            ))
        } else {
            Ok(())
        }
    }

    const MAX_RATE_LIMITERS: usize = 1_000;
    const MAX_NEW_CONNS_PER_MINUTE: usize = 50;

    async fn check_rate_limit(&self, app_pubkey: &PublicKey) -> Result<()> {
        let config = match &self.rate_limit_config {
            Some(c) => c,
            None => return Ok(()),
        };

        let mut limiters = self.rate_limiters.lock().await;

        if !limiters.contains_key(app_pubkey) {
            let mut timestamps = self.new_conn_timestamps.lock().await;
            let cutoff = Instant::now() - std::time::Duration::from_secs(60);
            while timestamps.front().is_some_and(|&t| t < cutoff) {
                timestamps.pop_front();
            }
            if timestamps.len() >= Self::MAX_NEW_CONNS_PER_MINUTE {
                return Err(KeepError::RateLimited(60));
            }
            timestamps.push_back(Instant::now());

            if limiters.len() >= Self::MAX_RATE_LIMITERS {
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
            drop(pm);
            self.audit.lock().await.log(
                AuditEntry::new(AuditAction::PermissionDenied, *app_pubkey)
                    .with_success(false)
                    .with_reason(format!("{perm:?} not permitted")),
            );
            Err(KeepError::PermissionDenied(
                "operation not permitted".into(),
            ))
        }
    }

    async fn our_pubkey(&self) -> Result<PublicKey> {
        if let Some(ref net_frost) = self.network_frost_signer {
            Ok(PublicKey::from_slice(net_frost.group_pubkey())
                .map_err(|e| CryptoError::invalid_key(format!("pubkey: {e}")))?)
        } else if let Some(ref frost) = self.frost_signer {
            let signer = frost.lock().await;
            Ok(PublicKey::from_slice(signer.group_pubkey())
                .map_err(|e| CryptoError::invalid_key(format!("pubkey: {e}")))?)
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
                self.audit.lock().await.log(
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
                    requested_permissions: permissions.clone(),
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

        let (requested_perms, auto_kinds) = permissions
            .as_deref()
            .map(parse_permission_string)
            .unwrap_or((Permission::DEFAULT, HashSet::new()));

        let mut pm = self.permissions.lock().await;
        if !pm.connect_with_permissions(app_pubkey, name.clone(), requested_perms, auto_kinds) {
            return Err(KeepError::CapacityExceeded(
                "too many connected apps".into(),
            ));
        }
        drop(pm);

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::Connect, app_pubkey).with_app_name(&name));

        info!(app_id, "app connected");
        Ok(())
    }

    pub async fn handle_get_public_key(&self, app_pubkey: PublicKey) -> Result<PublicKey> {
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::GET_PUBLIC_KEY)
            .await?;

        let pubkey = self.our_pubkey().await?;

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::GetPublicKey, app_pubkey));

        Ok(pubkey)
    }

    pub async fn handle_sign_event(
        &self,
        app_pubkey: PublicKey,
        unsigned_event: UnsignedEvent,
    ) -> Result<Event> {
        self.check_kill_switch()?;
        self.check_rate_limit(&app_pubkey).await?;

        let kind = unsigned_event.kind;

        self.require_permission(&app_pubkey, Permission::SIGN_EVENT)
            .await?;

        let needs_approval = self
            .permissions
            .lock()
            .await
            .needs_approval(&app_pubkey, kind);

        if needs_approval {
            let approved = self
                .request_approval(ApprovalRequest {
                    app_pubkey,
                    app_name: self.get_app_name(&app_pubkey).await,
                    method: "sign_event".into(),
                    event_kind: Some(kind),
                    event_content: Some(unsigned_event.content.clone()),
                    requested_permissions: None,
                })
                .await;

            if !approved {
                self.audit.lock().await.log(
                    AuditEntry::new(AuditAction::UserRejected, app_pubkey)
                        .with_event_kind(kind)
                        .with_success(false),
                );
                return Err(KeepError::UserRejected);
            }
        }

        self.check_kill_switch()?;

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

    async fn primary_secret_key(&self) -> Result<SecretKey> {
        let keyring = self.keyring.lock().await;
        let slot = keyring
            .get_primary()
            .ok_or_else(|| KeepError::KeyNotFound("no signing key".into()))?;
        let keypair = slot.to_nostr_keypair()?;
        Ok(SecretKey::from_slice(keypair.secret_bytes())
            .map_err(|e| CryptoError::invalid_key(format!("secret key: {e}")))?)
    }

    async fn require_approval(&self, app_pubkey: PublicKey, method: &str) -> Result<()> {
        let request = ApprovalRequest {
            app_pubkey,
            app_name: self.get_app_name(&app_pubkey).await,
            method: method.into(),
            event_kind: None,
            event_content: None,
            requested_permissions: None,
        };
        if self.request_approval(request).await {
            Ok(())
        } else {
            self.audit
                .lock()
                .await
                .log(AuditEntry::new(AuditAction::UserRejected, app_pubkey).with_reason(method));
            Err(KeepError::UserRejected)
        }
    }

    pub async fn handle_nip44_encrypt(
        &self,
        app_pubkey: PublicKey,
        recipient: PublicKey,
        plaintext: &str,
    ) -> Result<String> {
        self.check_kill_switch()?;
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::NIP44_ENCRYPT)
            .await?;
        let secret = self.primary_secret_key().await?;
        let ciphertext = nip44::encrypt(&secret, &recipient, plaintext, nip44::Version::V2)
            .map_err(|e| CryptoError::encryption(format!("NIP-44: {e}")))?;

        self.audit.lock().await.log(
            AuditEntry::new(AuditAction::Nip44Encrypt, app_pubkey).with_peer_pubkey(recipient),
        );

        Ok(ciphertext)
    }

    pub async fn handle_nip44_decrypt(
        &self,
        app_pubkey: PublicKey,
        sender: PublicKey,
        ciphertext: &str,
    ) -> Result<String> {
        self.check_kill_switch()?;
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::NIP44_DECRYPT)
            .await?;
        self.require_approval(app_pubkey, "nip44_decrypt").await?;
        self.check_kill_switch()?;

        let secret = self.primary_secret_key().await?;
        let plaintext = nip44::decrypt(&secret, &sender, ciphertext)
            .map_err(|e| CryptoError::decryption(format!("NIP-44: {e}")))?;

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::Nip44Decrypt, app_pubkey).with_peer_pubkey(sender));

        Ok(plaintext)
    }

    pub async fn handle_nip04_encrypt(
        &self,
        app_pubkey: PublicKey,
        recipient: PublicKey,
        plaintext: &str,
    ) -> Result<String> {
        self.check_kill_switch()?;
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::NIP04_ENCRYPT)
            .await?;
        let secret = self.primary_secret_key().await?;
        let ciphertext = nip04::encrypt(&secret, &recipient, plaintext)
            .map_err(|e| CryptoError::encryption(format!("NIP-04: {e}")))?;

        self.audit.lock().await.log(
            AuditEntry::new(AuditAction::Nip04Encrypt, app_pubkey).with_peer_pubkey(recipient),
        );

        Ok(ciphertext)
    }

    pub async fn handle_nip04_decrypt(
        &self,
        app_pubkey: PublicKey,
        sender: PublicKey,
        ciphertext: &str,
    ) -> Result<String> {
        self.check_kill_switch()?;
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::NIP04_DECRYPT)
            .await?;
        self.require_approval(app_pubkey, "nip04_decrypt").await?;
        self.check_kill_switch()?;

        let secret = self.primary_secret_key().await?;
        let plaintext = nip04::decrypt(&secret, &sender, ciphertext)
            .map_err(|e| CryptoError::decryption(format!("NIP-04: {e}")))?;

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::Nip04Decrypt, app_pubkey).with_peer_pubkey(sender));

        Ok(plaintext)
    }

    pub async fn handle_switch_relays(&self, app_pubkey: PublicKey) -> Result<Option<Vec<String>>> {
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::GET_PUBLIC_KEY)
            .await?;

        self.audit.lock().await.log(
            AuditEntry::new(AuditAction::GetPublicKey, app_pubkey).with_reason("switch_relays"),
        );

        let relays = (!self.relay_urls.is_empty()).then(|| self.relay_urls.clone());
        Ok(relays)
    }

    pub async fn register_client(
        &self,
        app_pubkey: PublicKey,
        name: String,
        permissions_str: Option<&str>,
    ) -> Result<()> {
        self.check_rate_limit(&app_pubkey).await?;

        let (requested_perms, auto_kinds) = permissions_str
            .map(parse_permission_string)
            .unwrap_or((Permission::DEFAULT, HashSet::new()));

        let mut pm = self.permissions.lock().await;
        if !pm.connect_with_permissions(app_pubkey, name.clone(), requested_perms, auto_kinds) {
            return Err(KeepError::CapacityExceeded(
                "too many connected apps".into(),
            ));
        }
        drop(pm);

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::Connect, app_pubkey).with_app_name(&name));

        info!(app_id = &app_pubkey.to_hex()[..8], "client registered");
        Ok(())
    }

    pub async fn update_client_permissions(&self, pubkey: &PublicKey, permissions: Permission) {
        let mut pm = self.permissions.lock().await;
        pm.set_permissions(pubkey, permissions);
        drop(pm);
        self.audit.lock().await.log(
            AuditEntry::new(AuditAction::PermissionChanged, *pubkey)
                .with_reason(format!("permissions={permissions:?}")),
        );
    }

    pub async fn update_client_duration(&self, pubkey: &PublicKey, duration: PermissionDuration) {
        let mut pm = self.permissions.lock().await;
        pm.set_duration(pubkey, duration);
        drop(pm);
        self.audit.lock().await.log(
            AuditEntry::new(AuditAction::PermissionChanged, *pubkey)
                .with_reason(format!("duration={duration:?}")),
        );
    }

    pub async fn update_client_auto_kinds(&self, pubkey: &PublicKey, kinds: HashSet<Kind>) {
        let mut pm = self.permissions.lock().await;
        pm.set_auto_approve_kinds_for_app(pubkey, kinds);
        drop(pm);
        self.audit.lock().await.log(
            AuditEntry::new(AuditAction::PermissionChanged, *pubkey)
                .with_reason("auto_approve_kinds updated"),
        );
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

    pub async fn revoke_session_apps(&self) {
        let mut pm = self.permissions.lock().await;
        pm.revoke_session_apps();
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

    #[test]
    fn test_parse_permission_string_with_kinds() {
        let (perms, kinds) = parse_permission_string("sign_event:1,sign_event:7,nip44_encrypt");
        assert!(perms.contains(Permission::SIGN_EVENT));
        assert!(perms.contains(Permission::NIP44_ENCRYPT));
        assert!(perms.contains(Permission::GET_PUBLIC_KEY));
        assert!(kinds.contains(&Kind::TextNote));
        assert!(kinds.contains(&Kind::Reaction));
        assert_eq!(kinds.len(), 2);
    }

    #[test]
    fn test_parse_permission_string_empty() {
        let (perms, kinds) = parse_permission_string("");
        assert_eq!(perms, Permission::DEFAULT);
        assert!(kinds.is_empty());
    }

    #[test]
    fn test_parse_permission_string_basic() {
        let (perms, kinds) = parse_permission_string("get_public_key,sign_event");
        assert!(perms.contains(Permission::GET_PUBLIC_KEY));
        assert!(perms.contains(Permission::SIGN_EVENT));
        assert!(!perms.contains(Permission::NIP44_ENCRYPT));
        assert!(kinds.is_empty());
    }

    #[tokio::test]
    async fn test_connect_with_kind_permissions() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        handler
            .handle_connect(
                app_pubkey,
                None,
                None,
                Some("sign_event:1,sign_event:7".to_string()),
            )
            .await
            .unwrap();

        let pm = handler.permissions.lock().await;
        assert!(pm.has_permission(&app_pubkey, Permission::SIGN_EVENT));
        assert!(!pm.needs_approval(&app_pubkey, Kind::TextNote));
        assert!(!pm.needs_approval(&app_pubkey, Kind::Reaction));
        assert!(pm.needs_approval(&app_pubkey, Kind::from(30023)));
    }

    #[tokio::test]
    async fn test_switch_relays_empty() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();
        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();

        let result = handler.handle_switch_relays(app_pubkey).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_switch_relays_with_urls() {
        let handler = setup_handler().with_relay_urls(vec!["wss://relay.example.com".into()]);
        let app_pubkey = Keys::generate().public_key();
        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();

        let result = handler.handle_switch_relays(app_pubkey).await.unwrap();
        assert_eq!(result, Some(vec!["wss://relay.example.com".to_string()]));
    }

    #[tokio::test]
    async fn test_update_client_permissions() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();
        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();

        assert!(!handler
            .permissions
            .lock()
            .await
            .has_permission(&app_pubkey, Permission::SIGN_EVENT));

        handler
            .update_client_permissions(
                &app_pubkey,
                Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT,
            )
            .await;

        assert!(handler
            .permissions
            .lock()
            .await
            .has_permission(&app_pubkey, Permission::SIGN_EVENT));
    }

    #[tokio::test]
    async fn test_update_client_duration() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();
        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();

        handler
            .update_client_duration(&app_pubkey, PermissionDuration::Seconds(3600))
            .await;

        let pm = handler.permissions.lock().await;
        let app = pm.get_app(&app_pubkey).unwrap();
        assert!(matches!(app.duration, PermissionDuration::Seconds(3600)));
    }

    #[tokio::test]
    async fn test_connect_rejects_wrong_secret() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None)
            .with_expected_secret("correct_secret_value".into());

        let app_pubkey = Keys::generate().public_key();
        let result = handler
            .handle_connect(app_pubkey, None, Some("wrong_secret".into()), None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_rejects_missing_secret_when_expected() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None)
            .with_expected_secret("required_secret".into());

        let app_pubkey = Keys::generate().public_key();
        let result = handler.handle_connect(app_pubkey, None, None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_accepts_correct_secret() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None)
            .with_expected_secret("correct_secret_value".into());

        let app_pubkey = Keys::generate().public_key();
        let result = handler
            .handle_connect(app_pubkey, None, Some("correct_secret_value".into()), None)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limit_blocks_excess_requests() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None)
            .with_auto_approve(true)
            .with_rate_limit(RateLimitConfig::new(3, 100, 1000));

        let app_pubkey = Keys::generate().public_key();

        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();

        let pk_result1 = handler.handle_get_public_key(app_pubkey).await;
        assert!(pk_result1.is_ok());

        let pk_result2 = handler.handle_get_public_key(app_pubkey).await;
        assert!(pk_result2.is_ok());

        let pk_result3 = handler.handle_get_public_key(app_pubkey).await;
        assert!(
            pk_result3.is_err(),
            "should be rate limited after exceeding per-minute limit"
        );
    }

    #[tokio::test]
    async fn test_rate_limit_per_app_isolation() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None)
            .with_auto_approve(true)
            .with_rate_limit(RateLimitConfig::new(2, 100, 1000));

        let app1 = Keys::generate().public_key();
        let app2 = Keys::generate().public_key();

        handler
            .handle_connect(app1, None, None, None)
            .await
            .unwrap();
        handler
            .handle_connect(app2, None, None, None)
            .await
            .unwrap();

        assert!(handler.handle_get_public_key(app1).await.is_ok());
        assert!(handler.handle_get_public_key(app2).await.is_ok());

        assert!(handler.handle_get_public_key(app1).await.is_err());
        assert!(handler.handle_get_public_key(app2).await.is_err());
    }

    #[tokio::test]
    async fn test_global_conn_cap_before_limiter_saturation() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None)
            .with_auto_approve(true)
            .with_rate_limit(RateLimitConfig::new(100, 10_000, 100_000));

        for i in 0..SignerHandler::MAX_NEW_CONNS_PER_MINUTE {
            let pubkey = Keys::generate().public_key();
            let result = handler.handle_connect(pubkey, None, None, None).await;
            assert!(result.is_ok(), "connection {i} should succeed");
        }

        let pubkey = Keys::generate().public_key();
        let result = handler.handle_connect(pubkey, None, None, None).await;
        assert!(result.is_err(), "should hit global new-connection cap");
    }

    #[tokio::test]
    async fn test_connect_without_auto_approve_or_callbacks_is_rejected() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None);

        let app_pubkey = Keys::generate().public_key();
        let result = handler.handle_connect(app_pubkey, None, None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_revoke_client_denies_subsequent_requests() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();
        assert!(handler.handle_get_public_key(app_pubkey).await.is_ok());

        handler.revoke_client(&app_pubkey).await;
        assert!(handler.handle_get_public_key(app_pubkey).await.is_err());
    }

    #[tokio::test]
    async fn test_revoke_all_clients() {
        let handler = setup_handler();
        let app1 = Keys::generate().public_key();
        let app2 = Keys::generate().public_key();

        handler
            .handle_connect(app1, None, None, None)
            .await
            .unwrap();
        handler
            .handle_connect(app2, None, None, None)
            .await
            .unwrap();
        assert_eq!(handler.list_clients().await.len(), 2);

        handler.revoke_all_clients().await;
        assert_eq!(handler.list_clients().await.len(), 0);
    }
}
