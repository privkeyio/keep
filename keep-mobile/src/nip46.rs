// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use crate::network::validate_relay_url;
use crate::{KeepMobile, KeepMobileError};
use keep_nip46::types::{
    ApprovalRequest, ApprovalResult, LogEvent, RememberDuration, ServerCallbacks,
};
use keep_nip46::{
    NetworkFrostSigner, Permission, PreGrantedApp, RateLimitConfig, Server, ServerConfig,
    SignerHandler,
};
use nostr_sdk::{Kind, PublicKey};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

const STATUS_STOPPED: u8 = 0;
const STATUS_STARTING: u8 = 1;
const STATUS_RUNNING: u8 = 2;
const STATUS_ERROR: u8 = 3;

#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum BunkerStatus {
    Stopped,
    Starting,
    Running,
    Error,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct BunkerLogEvent {
    pub app: String,
    pub action: String,
    pub success: bool,
    pub detail: Option<String>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct BunkerApprovalRequest {
    pub app_pubkey: String,
    pub app_name: String,
    pub method: String,
    pub event_kind: Option<u32>,
    pub event_content: Option<String>,
    pub requested_permissions: Option<String>,
}

/// How long an approval persists. Mirrors keep-android's
/// `nip55/PermissionEntities.kt::PermissionDuration` and Amber's `RememberType`
/// so the same enum maps cleanly to the existing `Nip46ApprovalScreen` picker.
/// `JustThisTime` is the one-shot default (no grant persisted); `Forever`
/// permanently auto-approves the (app, kind) pair; the timed variants persist
/// a per-(app, kind) grant with the matching expiry.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum BunkerRememberDuration {
    JustThisTime,
    OneMinute,
    FiveMinutes,
    TenMinutes,
    OneHour,
    OneDay,
    Forever,
}

impl From<BunkerRememberDuration> for RememberDuration {
    fn from(d: BunkerRememberDuration) -> Self {
        match d {
            BunkerRememberDuration::JustThisTime => RememberDuration::JustThisTime,
            BunkerRememberDuration::OneMinute => RememberDuration::OneMinute,
            BunkerRememberDuration::FiveMinutes => RememberDuration::FiveMinutes,
            BunkerRememberDuration::TenMinutes => RememberDuration::TenMinutes,
            BunkerRememberDuration::OneHour => RememberDuration::OneHour,
            BunkerRememberDuration::OneDay => RememberDuration::OneDay,
            BunkerRememberDuration::Forever => RememberDuration::Forever,
        }
    }
}

/// Result of an approval prompt as returned by the native UI. `approved=false`
/// always means reject and `remember` is ignored. `approved=true` plus a non-
/// `JustThisTime` duration persists a per-(app, kind) grant in the bunker so
/// subsequent requests within the window auto-approve without re-prompting.
#[derive(uniffi::Record, Clone, Copy, Debug)]
pub struct BunkerApprovalResult {
    pub approved: bool,
    pub remember: BunkerRememberDuration,
}

impl From<BunkerApprovalResult> for ApprovalResult {
    fn from(r: BunkerApprovalResult) -> Self {
        ApprovalResult {
            approved: r.approved,
            remember: r.remember.into(),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct ParsedBunkerUrl {
    pub pubkey: String,
    pub relays: Vec<String>,
    pub secret: Option<String>,
}

#[uniffi::export]
pub fn parse_bunker_url(url: &str) -> Result<ParsedBunkerUrl, KeepMobileError> {
    let (pubkey, relays, secret) = keep_nip46::parse_bunker_url(url)
        .map_err(|e| KeepMobileError::InvalidRelayUrl { msg: e })?;
    Ok(ParsedBunkerUrl {
        pubkey: pubkey.to_hex(),
        relays,
        secret,
    })
}

#[uniffi::export(with_foreign)]
pub trait BunkerCallbacks: Send + Sync {
    fn on_log(&self, event: BunkerLogEvent);
    fn request_approval(&self, request: BunkerApprovalRequest) -> BunkerApprovalResult;
    /// Fired when an app completes the NIP-46 connect handshake. `pubkey` and
    /// `name` are untrusted, remote-derived values: render them as inert text,
    /// never as markup.
    fn on_connect(&self, pubkey: String, name: String);
}

struct CallbackBridge {
    callbacks: Arc<dyn BunkerCallbacks>,
    mobile: Arc<KeepMobile>,
}

impl ServerCallbacks for CallbackBridge {
    fn on_log(&self, event: LogEvent) {
        self.callbacks.on_log(BunkerLogEvent {
            app: event.app,
            action: event.action,
            success: event.success,
            detail: event.detail,
        });
    }

    fn request_approval(&self, request: ApprovalRequest) -> ApprovalResult {
        self.callbacks
            .request_approval(BunkerApprovalRequest {
                app_pubkey: request.app_pubkey.to_hex(),
                app_name: request.app_name,
                method: request.method,
                event_kind: request.event_kind.map(|k| k.as_u16() as u32),
                event_content: request.event_content,
                requested_permissions: request.requested_permissions,
            })
            .into()
    }

    fn on_connect(&self, pubkey: &str, name: &str) {
        self.callbacks
            .on_connect(pubkey.to_string(), name.to_string());
    }

    fn persist_permissions(&self, grants: Vec<keep_core::relay::StoredBunkerPermission>) {
        if let Err(e) = self.mobile.persist_bunker_permissions(grants) {
            tracing::warn!("failed to persist bunker permissions: {e}");
        }
    }
}

#[derive(uniffi::Object)]
pub struct BunkerHandler {
    mobile: Arc<KeepMobile>,
    status: Arc<AtomicU8>,
    bunker_url: std::sync::Mutex<Option<String>>,
    shutdown_tx: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    handler: std::sync::Mutex<Option<Arc<SignerHandler>>>,
}

impl BunkerHandler {
    fn set_status(&self, status: u8) {
        self.status.store(status, Ordering::Release);
    }

    fn load_status(&self) -> u8 {
        self.status.load(Ordering::Acquire)
    }
}

#[uniffi::export]
impl BunkerHandler {
    #[uniffi::constructor]
    pub fn new(mobile: Arc<KeepMobile>) -> Self {
        Self {
            mobile,
            status: Arc::new(AtomicU8::new(STATUS_STOPPED)),
            bunker_url: std::sync::Mutex::new(None),
            shutdown_tx: std::sync::Mutex::new(None),
            handler: std::sync::Mutex::new(None),
        }
    }

    pub fn start_bunker(
        &self,
        relays: Vec<String>,
        callbacks: Arc<dyn BunkerCallbacks>,
    ) -> Result<(), KeepMobileError> {
        self.do_start_bunker(relays, callbacks, None)
    }

    pub fn start_bunker_with_proxy(
        &self,
        relays: Vec<String>,
        callbacks: Arc<dyn BunkerCallbacks>,
        proxy_host: String,
        proxy_port: u16,
    ) -> Result<(), KeepMobileError> {
        let proxy = crate::network::parse_loopback_proxy(&proxy_host, proxy_port)?;
        self.do_start_bunker(relays, callbacks, Some(proxy))
    }

    pub fn stop_bunker(&self) {
        let tx = self
            .shutdown_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }
        *self.bunker_url.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self.handler.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Revokes a single client, dropping its in-memory permission grants in the
    /// running engine so any remembered (auto-approved) kinds stop signing
    /// immediately. No-op when the bunker is not running. The pubkey is the
    /// client's hex-encoded x-only public key.
    pub fn revoke_client(&self, pubkey: String) -> Result<(), KeepMobileError> {
        let handler = self
            .handler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(handler) = handler else {
            return Ok(());
        };
        let pubkey = PublicKey::from_hex(&pubkey).map_err(|_| KeepMobileError::InvalidInput {
            msg: "Invalid client pubkey hex".into(),
        })?;
        self.mobile
            .runtime
            .block_on(async { handler.revoke_client(&pubkey).await });
        Ok(())
    }

    /// Revokes every client, clearing all in-memory permission grants in the
    /// running engine. No-op when the bunker is not running.
    pub fn revoke_all_clients(&self) {
        let handler = self
            .handler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(handler) = handler {
            self.mobile
                .runtime
                .block_on(async { handler.revoke_all_clients().await });
        }
    }

    pub fn get_bunker_url(&self) -> Option<String> {
        self.bunker_url
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn get_bunker_status(&self) -> BunkerStatus {
        match self.load_status() {
            STATUS_STARTING => BunkerStatus::Starting,
            STATUS_RUNNING => BunkerStatus::Running,
            STATUS_ERROR => BunkerStatus::Error,
            _ => BunkerStatus::Stopped,
        }
    }
}

/// Global event kinds the bunker signs without a per-request prompt for any
/// client. Kept to the safe engine default (kind 7 reactions) only. NIP-98 is
/// NOT global; see `bunker_connect_auto_approve_kinds`.
fn bunker_auto_approve_kinds() -> std::collections::HashSet<Kind> {
    std::collections::HashSet::from([Kind::Reaction])
}

/// Event kinds auto-approved per-app for each client that completes the connect
/// handshake, scoped to that client's pubkey instead of granted globally.
///
/// **Empty by default as of #575.** Previously this returned `{NIP98_HTTP_AUTH}`
/// so web clients such as nostr-tools' `BunkerSigner` (which signs a fresh NIP-98
/// event per HTTP call) would not be blocked by a 60s-per-request prompt. That
/// silent grant turned the bunker URL + connect secret into an HTTP-auth bearer
/// credential: anyone holding it could mint NIP-98 tokens authenticating as the
/// user to any URL/method with no prompt. Per-app scoping does not bound that
/// threat as long as the connect secret is reusable.
///
/// NIP-98 sign requests now fall through to the existing per-request approval
/// callback. The next step (mobile UI, tracked as a follow-up under #575) is to
/// extend the approval response with a remember-duration so the user can opt in
/// to "remember for 1 hour / 1 day / always" after seeing the first request,
/// matching Amber's UX without the silent-grant trade-off.
fn bunker_connect_auto_approve_kinds() -> std::collections::HashSet<Kind> {
    std::collections::HashSet::new()
}

/// Decodes a persisted transport secret, returning `None` when the stored value
/// is malformed, the wrong length, or not a valid secp256k1 scalar (zero or
/// `>=` the curve order). The value is persisted and reused on every start, so a
/// corrupt-but-32-byte hex string would otherwise be cached forever and brick
/// the bunker permanently; rejecting it here lets `load_or_create_bunker_keys`
/// regenerate and self-heal. The decoded buffer is zeroized on drop.
fn decode_transport_secret(hex_str: &str) -> Option<Zeroizing<[u8; 32]>> {
    let decoded = Zeroizing::new(hex::decode(hex_str).ok()?);
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(decoded.as_slice().try_into().ok()?);
    nostr_sdk::secp256k1::SecretKey::from_slice(bytes.as_slice()).ok()?;
    Some(bytes)
}

/// Loads the persisted bunker transport key + connect secret, generating and
/// persisting fresh values on first start (or when absent/corrupt). The
/// bunker:// pubkey is derived from the transport key and the URL embeds the
/// connect secret, so reusing the persisted values keeps the bunker URL stable
/// across service restarts — saved client sessions (readstr and the like) keep
/// receiving responses after a reboot or off/on toggle. The secrets live in the
/// same SQLCipher-backed SecureStorage as the FROST share material.
fn load_or_create_bunker_keys(
    mobile: &KeepMobile,
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<String>), KeepMobileError> {
    let storage = &mobile.storage;

    // Serialize the whole load-modify-store against `save_bunker_config`, which
    // performs the same read-modify-write on this record. Without the lock a
    // config save that read a stale snapshot (transport_secret: None) could
    // overwrite the keys we generate and persist here, rotating the bunker URL
    // and breaking already-paired clients — the failure this code prevents.
    let _guard = mobile
        .bunker_config_lock
        .lock()
        .map_err(|_| KeepMobileError::StorageError {
            msg: "bunker config lock poisoned".into(),
        })?;

    let mut stored =
        crate::persistence::load_bunker_config(storage, crate::BUNKER_CONFIG_STORAGE_KEY)?
            .unwrap_or_default();

    let mut dirty = false;

    let transport_secret = match stored
        .transport_secret
        .as_deref()
        .and_then(decode_transport_secret)
    {
        Some(bytes) => bytes,
        None => {
            let bytes = Zeroizing::new(keep_core::crypto::random_bytes::<32>());
            stored.transport_secret = Some(hex::encode(&bytes[..]));
            dirty = true;
            bytes
        }
    };

    let connect_secret = match stored.connect_secret.as_deref() {
        Some(secret) if !secret.is_empty() => Zeroizing::new(secret.to_owned()),
        _ => {
            let secret = Zeroizing::new(hex::encode(keep_core::crypto::random_bytes::<16>()));
            stored.connect_secret = Some(secret.as_str().to_owned());
            dirty = true;
            secret
        }
    };

    if dirty {
        crate::persistence::persist_bunker_config(
            storage,
            crate::BUNKER_CONFIG_STORAGE_KEY,
            &stored,
        )?;
    }

    // `stored` still holds a plaintext hex copy of the transport and connect
    // secrets; clear them before drop so the decrypted key material does not
    // linger in memory.
    if let Some(s) = stored.transport_secret.as_mut() {
        s.zeroize();
    }
    if let Some(s) = stored.connect_secret.as_mut() {
        s.zeroize();
    }

    Ok((transport_secret, connect_secret))
}

impl BunkerHandler {
    fn do_start_bunker(
        &self,
        relays: Vec<String>,
        callbacks: Arc<dyn BunkerCallbacks>,
        proxy: Option<std::net::SocketAddr>,
    ) -> Result<(), KeepMobileError> {
        if relays.is_empty() {
            return Err(KeepMobileError::InvalidRelayUrl {
                msg: "At least one relay required".into(),
            });
        }

        for relay in &relays {
            validate_relay_url(relay)?;
        }

        if self
            .status
            .compare_exchange(
                STATUS_STOPPED,
                STATUS_STARTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(KeepMobileError::InitializationFailed {
                msg: "Bunker already running or starting".into(),
            });
        }

        let result = self.mobile.runtime.block_on(async {
            let node_guard = self.mobile.node.read().await;
            let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;

            let share_info = self
                .mobile
                .get_share_info()
                .ok_or(KeepMobileError::NotInitialized)?;

            let group_pubkey_bytes: [u8; 32] = hex::decode(&share_info.group_pubkey)
                .map_err(|_| KeepMobileError::FrostError {
                    msg: "Invalid group pubkey hex".into(),
                })?
                .try_into()
                .map_err(|_| KeepMobileError::FrostError {
                    msg: "Invalid group pubkey length".into(),
                })?;

            let network_signer =
                NetworkFrostSigner::with_shared_node(group_pubkey_bytes, Arc::clone(node));

            let (transport_secret, connect_secret) = load_or_create_bunker_keys(&self.mobile)?;

            // Restore persisted per-(app, kind) remember-grants so they survive a
            // bunker restart. The engine is the single source of truth for these
            // grants; they are durably mirrored to the relay config on every
            // grant/revoke via the `persist_permissions` callback below.
            let pre_grants: Vec<PreGrantedApp> = self
                .mobile
                .load_bunker_permissions()
                .iter()
                .filter_map(PreGrantedApp::from_stored)
                .collect();

            let config = ServerConfig {
                rate_limit: Some(RateLimitConfig::default()),
                expected_secret: Some(connect_secret.as_str().to_owned()),
                pre_grants,
                // Approving the bunker connection (the secret in the bunker URL
                // is the grant) must let the client sign, mirroring the
                // always-on bunker in keep-web. Without this the client only
                // gets get_public_key and every sign_event is denied — the
                // client logs in but its signed-request calls all fail.
                //
                // TRUST MODEL: this connect grant authorizes signing, but
                // NIP-98 (kind 27235) is NEVER auto-approved. Per #575 it always
                // falls through to the per-request approval prompt and is never
                // remembered (see `bunker_connect_auto_approve_kinds`, now
                // empty), so a shared connect secret cannot silently mint NIP-98
                // HTTP-auth tokens. The connect secret is still a shared bearer
                // credential for non-NIP-98 signing; a per-app/URL-method
                // allowlist is follow-up work.
                connect_grant: Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT,
                auto_approve_kinds: bunker_auto_approve_kinds(),
                connect_auto_approve_kinds: bunker_connect_auto_approve_kinds(),
                ..ServerConfig::default()
            };

            let server = Server::new_network_frost_with_proxy(
                network_signer,
                *transport_secret,
                &relays,
                Some(Arc::new(CallbackBridge {
                    callbacks,
                    mobile: Arc::clone(&self.mobile),
                }) as Arc<dyn ServerCallbacks>),
                config,
                proxy,
            )
            .await
            .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?;

            *self.bunker_url.lock().unwrap_or_else(|e| e.into_inner()) = Some(server.bunker_url());
            *self.handler.lock().unwrap_or_else(|e| e.into_inner()) = Some(server.handler());

            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
            *self.shutdown_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(shutdown_tx);

            let status = Arc::clone(&self.status);
            tokio::spawn(async move {
                status.store(STATUS_RUNNING, Ordering::Release);
                run_server(server, shutdown_rx, status).await;
            });

            Ok::<(), KeepMobileError>(())
        });

        if result.is_err() {
            self.set_status(STATUS_STOPPED);
        }
        result
    }
}

async fn run_server(
    mut server: Server,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    status: Arc<AtomicU8>,
) {
    tokio::select! {
        result = server.run() => {
            match result {
                Ok(()) => status.store(STATUS_STOPPED, Ordering::Release),
                Err(_) => status.store(STATUS_ERROR, Ordering::Release),
            };
        }
        _ = shutdown_rx => {
            server.stop().await;
            status.store(STATUS_STOPPED, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{load_bunker_config, persist_bunker_config, StoredBunkerConfig};
    use crate::storage::{SecureStorage, ShareMetadataInfo};
    use crate::KeepMobileError;
    use crate::BUNKER_CONFIG_STORAGE_KEY;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemStorage {
        data: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl SecureStorage for MemStorage {
        fn store_share(
            &self,
            _data: Vec<u8>,
            _metadata: ShareMetadataInfo,
        ) -> Result<(), KeepMobileError> {
            unimplemented!()
        }
        fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
            unimplemented!()
        }
        fn has_share(&self) -> bool {
            false
        }
        fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
            None
        }
        fn delete_share(&self) -> Result<(), KeepMobileError> {
            unimplemented!()
        }
        fn store_share_by_key(
            &self,
            key: String,
            data: Vec<u8>,
            _metadata: ShareMetadataInfo,
        ) -> Result<(), KeepMobileError> {
            self.data.lock().unwrap().insert(key, data);
            Ok(())
        }
        fn load_share_by_key(&self, key: String) -> Result<Vec<u8>, KeepMobileError> {
            self.data
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .ok_or(KeepMobileError::StorageNotFound)
        }
        fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
            Vec::new()
        }
        fn delete_share_by_key(&self, key: String) -> Result<(), KeepMobileError> {
            self.data.lock().unwrap().remove(&key);
            Ok(())
        }
        fn get_active_share_key(&self) -> Option<String> {
            None
        }
        fn set_active_share_key(&self, _key: Option<String>) -> Result<(), KeepMobileError> {
            Ok(())
        }
    }

    // (a) Configs serialized before the transport_secret/connect_secret fields
    // existed must still deserialize, leaving the new fields as None.
    #[test]
    fn old_bunker_config_deserializes() {
        let legacy = br#"{"enabled":true,"authorized_clients":["abc"]}"#;
        let config: StoredBunkerConfig = serde_json::from_slice(legacy).unwrap();
        assert!(config.enabled);
        assert_eq!(config.authorized_clients, vec!["abc".to_string()]);
        assert!(config.transport_secret.is_none());
        assert!(config.connect_secret.is_none());
    }

    // (c) A fresh storage generates and persists new transport key + secret.
    #[test]
    fn fresh_storage_generates_and_persists() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());

        assert!(load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .is_none());

        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let (transport, secret) = load_or_create_bunker_keys(&mobile).unwrap();
        assert!(!secret.is_empty());

        let stored = load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .expect("config persisted on first start");
        assert_eq!(
            stored
                .transport_secret
                .as_deref()
                .and_then(decode_transport_secret)
                .map(|t| *t),
            Some(*transport)
        );
        assert_eq!(stored.connect_secret.as_deref(), Some(secret.as_str()));
    }

    // (b) Starting the bunker twice against the same storage reuses the same
    // transport key + connect secret, so the derived bunker:// URI is stable.
    #[test]
    fn restart_reuses_persisted_keys() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());

        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let (transport1, secret1) = load_or_create_bunker_keys(&mobile).unwrap();
        let (transport2, secret2) = load_or_create_bunker_keys(&mobile).unwrap();

        assert_eq!(*transport1, *transport2);
        assert_eq!(*secret1, *secret2);
    }

    // Corrupt (invalid-hex transport) or empty (blank connect secret) persisted
    // values must be treated as absent: regenerated to valid material, persisted,
    // and stable across the next load — the junk is never propagated.
    #[test]
    fn corrupt_or_empty_keys_regenerate_and_persist() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());

        let stored = StoredBunkerConfig {
            transport_secret: Some("zzz".into()),
            connect_secret: Some(String::new()),
            ..StoredBunkerConfig::default()
        };
        persist_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY, &stored).unwrap();

        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let (transport, secret) = load_or_create_bunker_keys(&mobile).unwrap();
        assert!(!secret.is_empty());
        assert_ne!(secret.as_str(), "");
        assert_eq!(transport.len(), 32);

        let reloaded = load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .expect("regenerated config persisted");
        assert_eq!(
            reloaded
                .transport_secret
                .as_deref()
                .and_then(decode_transport_secret)
                .map(|t| *t),
            Some(*transport)
        );
        assert_eq!(reloaded.connect_secret.as_deref(), Some(secret.as_str()));

        let (transport2, secret2) = load_or_create_bunker_keys(&mobile).unwrap();
        assert_eq!(*transport, *transport2);
        assert_eq!(*secret, *secret2);
    }

    // A persisted transport secret that is valid 32-byte hex but not a valid
    // secp256k1 scalar (here all-zero) must be rejected and regenerated, so a
    // corrupt key cannot brick the bunker permanently.
    #[test]
    fn invalid_scalar_transport_secret_regenerates() {
        assert!(decode_transport_secret(&"00".repeat(32)).is_none());

        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let stored = StoredBunkerConfig {
            transport_secret: Some("00".repeat(32)),
            connect_secret: Some("preserved-secret".into()),
            ..StoredBunkerConfig::default()
        };
        persist_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY, &stored).unwrap();

        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let (transport, secret) = load_or_create_bunker_keys(&mobile).unwrap();
        assert_ne!(*transport, [0u8; 32]);
        assert!(nostr_sdk::secp256k1::SecretKey::from_slice(&transport[..]).is_ok());
        // Regenerating the corrupt transport key must not rotate the still-valid
        // connect secret, or the bunker URL would change on next restart.
        assert_eq!(*secret, "preserved-secret");
        let reloaded = load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .expect("config persisted");
        assert_eq!(reloaded.connect_secret.as_deref(), Some("preserved-secret"));
        let (_, secret2) = load_or_create_bunker_keys(&mobile).unwrap();
        assert_eq!(*secret2, "preserved-secret");
    }

    // Drive the real `KeepMobile::save_bunker_config`: persisted transport key +
    // connect secret survive an unrelated config save (disable + add a client).
    #[test]
    fn save_bunker_config_preserves_secrets() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());

        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let (transport, secret) = load_or_create_bunker_keys(&mobile).unwrap();

        mobile
            .save_bunker_config(crate::BunkerConfigInfo {
                enabled: false,
                authorized_clients: vec!["c".into()],
            })
            .unwrap();

        let reloaded = load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .expect("config persisted");
        assert!(!reloaded.enabled);
        assert_eq!(reloaded.authorized_clients, vec!["c".to_string()]);
        assert_eq!(
            reloaded
                .transport_secret
                .as_deref()
                .and_then(decode_transport_secret)
                .map(|t| *t),
            Some(*transport)
        );
        assert_eq!(reloaded.connect_secret.as_deref(), Some(secret.as_str()));
    }

    // Saving unrelated config (e.g. toggling enabled) must not rotate the keys.
    #[test]
    fn rewriting_config_preserves_keys() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());

        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let (transport1, secret1) = load_or_create_bunker_keys(&mobile).unwrap();

        let mut stored = load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .unwrap();
        stored.enabled = false;
        stored.authorized_clients.push("client".into());
        persist_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY, &stored).unwrap();

        let (transport2, secret2) = load_or_create_bunker_keys(&mobile).unwrap();
        assert_eq!(*transport1, *transport2);
        assert_eq!(*secret1, *secret2);
    }
}
