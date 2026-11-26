// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use nostr_sdk::prelude::*;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use keep_core::error::{CryptoError, KeepError, NetworkError, StorageError};
use keep_core::keyring::Keyring;

use crate::audit::AuditLog;
use crate::bunker::generate_bunker_url;
use crate::error::Result;
use crate::frost_signer::{FrostSigner, NetworkFrostSigner};
use crate::handler::SignerHandler;
use crate::permissions::{Permission, PermissionDuration, PermissionManager};
use crate::rate_limit::RateLimitConfig;
use crate::types::{
    ConnectAuthorization, LogEvent, Nip46Request, Nip46Response, PartialEvent, ServerCallbacks,
};
use keep_core::relay::TIMESTAMP_TWEAK_RANGE;

pub struct ServerConfig {
    pub max_event_json_size: usize,
    pub audit_log_capacity: usize,
    pub rate_limit: Option<RateLimitConfig>,
    pub auto_approve: bool,
    pub expected_secret: Option<String>,
    pub kill_switch: Option<Arc<AtomicBool>>,
    /// Permissions granted when a client connects without requesting any.
    /// Defaults to least-privilege `Permission::DEFAULT`; an always-on bunker
    /// (keep-web) sets this to `Permission::ALL` so approving a connection lets
    /// the client sign.
    pub connect_grant: Permission,
    /// Pre-grants that the PermissionManager is populated with at startup.
    /// Lets a headless bunker accept signing requests from CLI-managed apps
    /// (`keep nip46 grant <pubkey> ...`) without an interactive approval prompt.
    pub pre_grants: Vec<PreGrantedApp>,
    /// Global event kinds that skip the approval prompt for every client,
    /// independent of any per-app `auto_approve_kinds`. Set via
    /// `keep nip46 auto-approve`. Only meaningful for interactive serving;
    /// in headless mode every request is auto-approved regardless.
    pub auto_approve_kinds: std::collections::HashSet<nostr_sdk::Kind>,
    /// Event kinds auto-approved per-app for each client that completes the
    /// connect handshake, scoped to that app's pubkey instead of the global
    /// `auto_approve_kinds`. The only source of connect-time kinds: the kinds a
    /// client names in its own request are never auto-approved. NIP-98 (kind
    /// 27235) is stripped from it.
    pub connect_auto_approve_kinds: std::collections::HashSet<nostr_sdk::Kind>,
    /// Enforces the relay's SPKI pin inside the TLS handshake of the sockets
    /// that carry remote-signing traffic, not only on a pre-flight probe. Left
    /// `None` the client does standard WebPKI validation only, which is what
    /// every caller got before this existed.
    pub tls_pinning: Option<keep_frost_net::TlsPinning>,
}

/// A NIP-46 client app whose permissions are loaded into the
/// `PermissionManager` when a `Server` starts. Constructed from the persisted
/// `keep_core::relay::StoredBunkerPermission` in the CLI/web entry points.
#[derive(Debug, Clone)]
pub struct PreGrantedApp {
    pub pubkey: PublicKey,
    pub name: String,
    pub permissions: Permission,
    pub auto_approve_kinds: std::collections::HashSet<nostr_sdk::Kind>,
    pub duration: PermissionDuration,
    pub connected_at: Timestamp,
    pub timed_kind_grants: std::collections::HashMap<nostr_sdk::Kind, u64>,
    /// `None` for a legacy row predating the flag; the restore path then falls
    /// back to inspecting the row's grants.
    pub explicitly_remembered: Option<bool>,
    /// Paired through a `nostrconnect://` approval, so restored on that alone.
    pub paired: bool,
}

impl PreGrantedApp {
    /// Build a runtime `PreGrantedApp` from a persisted
    /// `keep_core::relay::StoredBunkerPermission`. Returns `None` and logs at
    /// warn-level when the stored row is malformed (bad hex pubkey) so one
    /// bad row never takes the bunker down. Session / expired Seconds rows
    /// are kept here and skipped later by `PermissionManager::restore_persisted`,
    /// so the mapping stays a pure function of the stored bytes.
    pub fn from_stored(stored: &keep_core::relay::StoredBunkerPermission) -> Option<Self> {
        let pk_bytes = match hex::decode(&stored.pubkey_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                tracing::warn!(
                    pubkey_hex = %stored.pubkey_hex,
                    "PreGrantedApp::from_stored: skipping malformed pubkey hex"
                );
                return None;
            }
        };
        let Ok(pubkey) = PublicKey::from_slice(&pk_bytes) else {
            tracing::warn!(
                pubkey_hex = %stored.pubkey_hex,
                "PreGrantedApp::from_stored: skipping invalid pubkey"
            );
            return None;
        };
        let permissions = Permission::from_bits_truncate(stored.permissions);
        if !stored.kinds_vetted && !stored.auto_approve_kinds.is_empty() {
            tracing::warn!(
                pubkey_hex = %stored.pubkey_hex,
                "PreGrantedApp::from_stored: dropping auto-approve kinds from a row \
                 written before they were vetted; the client must be approved again"
            );
        }
        let auto_approve_kinds: std::collections::HashSet<nostr_sdk::Kind> = stored
            .auto_approve_kinds
            .iter()
            .copied()
            .filter(|_| stored.kinds_vetted)
            .map(nostr_sdk::Kind::from)
            .collect();
        let timed_kind_grants: std::collections::HashMap<nostr_sdk::Kind, u64> = stored
            .timed_kind_grants
            .iter()
            .map(|g| (nostr_sdk::Kind::from(g.kind), g.expires_at))
            .collect();
        let duration = match &stored.duration {
            keep_core::relay::StoredPermissionDuration::Session => PermissionDuration::Session,
            keep_core::relay::StoredPermissionDuration::Seconds(s) => {
                PermissionDuration::Seconds(*s)
            }
            keep_core::relay::StoredPermissionDuration::Forever => PermissionDuration::Forever,
        };
        Some(Self {
            pubkey,
            name: stored.name.clone(),
            permissions,
            auto_approve_kinds,
            duration,
            connected_at: Timestamp::from_secs(stored.connected_at),
            timed_kind_grants,
            explicitly_remembered: stored.explicitly_remembered,
            paired: stored.paired,
        })
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_event_json_size: 64 * 1024,
            audit_log_capacity: 10_000,
            rate_limit: None,
            auto_approve: false,
            expected_secret: None,
            kill_switch: None,
            connect_grant: Permission::DEFAULT,
            pre_grants: Vec::new(),
            auto_approve_kinds: std::collections::HashSet::from([nostr_sdk::Kind::Reaction]),
            connect_auto_approve_kinds: std::collections::HashSet::new(),
            tls_pinning: None,
        }
    }
}

pub struct Server {
    keys: Keys,
    relay_url: String,
    relay_urls: Vec<String>,
    client: Client,
    /// `relay_urls`, as the pool keys them.
    own_relays: Arc<[RelayUrl]>,
    routes: ClientRoutes,
    joining: Arc<Mutex<()>>,
    handler: Arc<SignerHandler>,
    running: bool,
    callbacks: Option<Arc<dyn ServerCallbacks>>,
    config: ServerConfig,
    bunker_secret: Option<Zeroizing<String>>,
    /// When the last `start` began serving, less `REQUEST_CLOCK_SKEW_SECS`.
    /// Requests created before it are not handled: a relay that keeps NIP-46
    /// events replays them to every new subscription, and nothing here
    /// remembers what a previous run handled.
    serving_since: Timestamp,
}

/// How far behind the bunker's clock a client's may run before its requests
/// made just after a start are taken for replays from before it. After a
/// restart, a request answered within this long before it can be answered
/// again, to the same client.
const REQUEST_CLOCK_SKEW_SECS: u64 = 30;

/// How far ahead of the bunker's clock a client's may run. A request dated
/// later would pass every later start's `since` until that date, and so be
/// replayed on each restart; one within this is replayed only by a restart
/// this soon after it.
const REQUEST_FUTURE_SKEW_SECS: u64 = 120;

/// Whether a request is dated before a bunker that started serving at `since`
/// began, or too far ahead of `now`.
fn is_out_of_window(event: &Event, since: Timestamp, now: Timestamp) -> bool {
    event.created_at < since || is_too_far_ahead(event, now)
}

fn is_too_far_ahead(event: &Event, now: Timestamp) -> bool {
    event.created_at > now + std::time::Duration::from_secs(REQUEST_FUTURE_SKEW_SECS)
}

fn relay_options(proxy: Option<SocketAddr>) -> nostr_sdk::RelayOptions {
    let opts = nostr_sdk::RelayOptions::default()
        .reconnect(true)
        .ping(true)
        .retry_interval(std::time::Duration::from_secs(10))
        .adjust_retry_interval(true);
    keep_frost_net::with_proxy(opts, proxy)
}

async fn add_relays(
    client: &Client,
    relay_urls: &[String],
    proxy: Option<SocketAddr>,
) -> Result<()> {
    let opts = relay_options(proxy);

    for relay_url in relay_urls {
        client
            .pool()
            .add_relay(relay_url, opts.clone())
            .await
            .map_err(|e| NetworkError::relay(e.to_string()))?;
    }
    Ok(())
}

fn require_relay_urls(relay_urls: &[String]) -> Result<()> {
    if relay_urls.is_empty() {
        return Err(NetworkError::relay("at least one relay required".to_string()).into());
    }
    Ok(())
}

async fn apply_pre_grants(
    permissions: &Arc<Mutex<PermissionManager>>,
    pre_grants: &[PreGrantedApp],
) {
    if pre_grants.is_empty() {
        return;
    }
    let mut pm = permissions.lock().await;
    for app in pre_grants {
        pm.restore_persisted(
            app.pubkey,
            app.name.clone(),
            app.permissions,
            app.auto_approve_kinds.clone(),
            app.duration,
            app.connected_at,
            app.timed_kind_grants.clone(),
            app.explicitly_remembered,
            app.paired,
        );
    }
}

fn finalize_handler(
    mut handler: SignerHandler,
    config: &ServerConfig,
    relay_urls: &[String],
) -> Result<(SignerHandler, Option<Zeroizing<String>>)> {
    handler = handler.with_relay_urls(relay_urls.to_vec());
    if let Some(ref rl_config) = config.rate_limit {
        handler = handler.with_rate_limit(rl_config.clone());
    }
    if let Some(ref ks) = config.kill_switch {
        handler = handler.with_kill_switch(ks.clone());
    }
    let bunker_secret = if config.auto_approve && config.expected_secret.is_none() {
        let secret = hex::encode(keep_core::crypto::try_random_bytes::<16>()?);
        warn!("headless mode: bunker secret required for authentication");
        handler = handler.with_expected_secret(secret.clone());
        Some(Zeroizing::new(secret))
    } else if let Some(ref secret) = config.expected_secret {
        handler = handler.with_expected_secret(secret.clone());
        // Surface the configured secret in the bunker URL so clients (which
        // require it in the connect handshake) can authenticate.
        Some(Zeroizing::new(secret.clone()))
    } else {
        None
    };
    Ok((handler, bunker_secret))
}

/// Why the notification loop stopped on its own.
#[derive(Debug, PartialEq, Eq)]
enum NotificationsEnded {
    /// The pool shut down, which a caller asked for.
    Shutdown,
    /// The stream closed with no shutdown, which nothing asked for.
    Closed,
}

/// Feeds each relay notification to `on_notification` until the pool shuts
/// down, and says why it stopped.
///
/// Driven here rather than through `Client::handle_notifications`, which loops
/// on `while let Ok(..) = receiver.recv()`. A broadcast receiver that falls
/// more than the channel's capacity behind (4096 in nostr-relay-pool 0.44.3)
/// answers `Err(Lagged)`, and that loop treats it exactly like a clean stop:
/// it returns `Ok(())`, so the bunker stopped answering and reported a
/// successful, intentional exit with nothing logged. Requests are handled one
/// at a time per app, and an approval can hold an app's queue for a minute.
///
/// A lag now costs only what it skipped: the receiver resumes from the oldest
/// notification still held, the count is logged, and clients whose requests
/// were dropped time out and retry. Restarting instead would lose the queued
/// ones too. A stream that closes without a shutdown is reported as an error,
/// so the caller can tell it from a requested stop.
async fn drive_notifications<F, Fut>(
    mut notifications: tokio::sync::broadcast::Receiver<RelayPoolNotification>,
    mut on_notification: F,
) -> NotificationsEnded
where
    F: FnMut(RelayPoolNotification) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use tokio::sync::broadcast::error::RecvError;

    loop {
        match notifications.recv().await {
            Ok(RelayPoolNotification::Shutdown) => return NotificationsEnded::Shutdown,
            Ok(notification) => on_notification(notification).await,
            Err(RecvError::Lagged(skipped)) => {
                warn!(
                    skipped,
                    "NIP-46 notifications fell behind and some were dropped; still serving"
                );
            }
            Err(RecvError::Closed) => return NotificationsEnded::Closed,
        }
    }
}

impl Server {
    fn build(
        keys: Keys,
        relay_urls: &[String],
        client: Client,
        handler: SignerHandler,
        callbacks: Option<Arc<dyn ServerCallbacks>>,
        config: ServerConfig,
        bunker_secret: Option<Zeroizing<String>>,
    ) -> Self {
        Self {
            keys,
            relay_url: relay_urls[0].clone(),
            relay_urls: relay_urls.to_vec(),
            own_relays: relay_urls
                .iter()
                .filter_map(|url| RelayUrl::parse(url).ok())
                .collect(),
            routes: ClientRoutes::default(),
            joining: Arc::new(Mutex::new(())),
            client,
            handler: Arc::new(handler),
            running: false,
            callbacks,
            config,
            bunker_secret,
            serving_since: Timestamp::now(),
        }
    }

    pub async fn new(
        keyring: Arc<Mutex<Keyring>>,
        relay_urls: &[String],
        callbacks: Option<Arc<dyn ServerCallbacks>>,
    ) -> Result<Self> {
        Self::new_with_proxy(keyring, relay_urls, callbacks, None).await
    }

    pub async fn new_with_proxy(
        keyring: Arc<Mutex<Keyring>>,
        relay_urls: &[String],
        callbacks: Option<Arc<dyn ServerCallbacks>>,
        proxy: Option<SocketAddr>,
    ) -> Result<Self> {
        Self::new_with_config_and_proxy(
            keyring,
            None,
            None,
            relay_urls,
            callbacks,
            ServerConfig::default(),
            proxy,
        )
        .await
    }

    pub async fn new_with_frost(
        keyring: Arc<Mutex<Keyring>>,
        frost_signer: Option<FrostSigner>,
        transport_secret: Option<[u8; 32]>,
        relay_urls: &[String],
        callbacks: Option<Arc<dyn ServerCallbacks>>,
    ) -> Result<Self> {
        Self::new_with_config(
            keyring,
            frost_signer,
            transport_secret,
            relay_urls,
            callbacks,
            ServerConfig::default(),
        )
        .await
    }

    pub async fn new_with_config(
        keyring: Arc<Mutex<Keyring>>,
        frost_signer: Option<FrostSigner>,
        transport_secret: Option<[u8; 32]>,
        relay_urls: &[String],
        callbacks: Option<Arc<dyn ServerCallbacks>>,
        config: ServerConfig,
    ) -> Result<Self> {
        Self::new_with_config_and_proxy(
            keyring,
            frost_signer,
            transport_secret,
            relay_urls,
            callbacks,
            config,
            None,
        )
        .await
    }

    pub async fn new_with_config_and_proxy(
        keyring: Arc<Mutex<Keyring>>,
        frost_signer: Option<FrostSigner>,
        transport_secret: Option<[u8; 32]>,
        relay_urls: &[String],
        callbacks: Option<Arc<dyn ServerCallbacks>>,
        config: ServerConfig,
        proxy: Option<SocketAddr>,
    ) -> Result<Self> {
        require_relay_urls(relay_urls)?;

        let keys = if let Some(secret_bytes) = transport_secret {
            let secret = SecretKey::from_slice(&secret_bytes)
                .map_err(|e| CryptoError::invalid_key(format!("transport key: {e}")))?;
            Keys::new(secret)
        } else {
            let kr = keyring.lock().await;
            let slot = kr
                .get_primary()
                .ok_or_else(|| KeepError::KeyNotFound("no signing key".into()))?;

            let secret = SecretKey::from_slice(slot.expose_secret())
                .map_err(|e| CryptoError::invalid_key(format!("secret key: {e}")))?;

            Keys::new(secret)
        };

        let client = keep_frost_net::build_client(&keys, proxy, config.tls_pinning.clone())
            .map_err(|e| NetworkError::connection(format!("relay client: {e}")))?;
        add_relays(&client, relay_urls, proxy).await?;

        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        apply_pre_grants(&permissions, &config.pre_grants).await;
        permissions
            .lock()
            .await
            .set_auto_approve_kinds(config.auto_approve_kinds.clone());
        let audit = Arc::new(Mutex::new(AuditLog::new(config.audit_log_capacity)));
        let mut handler = SignerHandler::new(keyring, permissions, audit, callbacks.clone())
            .with_auto_approve(config.auto_approve)
            .with_connect_grant(config.connect_grant)
            .with_connect_auto_approve_kinds(config.connect_auto_approve_kinds.clone())
            .with_transport_pubkey(keys.public_key());
        if let Some(frost) = frost_signer {
            handler = handler.with_frost_signer(frost);
        }
        let (handler, bunker_secret) = finalize_handler(handler, &config, relay_urls)?;

        Ok(Self::build(
            keys,
            relay_urls,
            client,
            handler,
            callbacks,
            config,
            bunker_secret,
        ))
    }

    pub async fn new_frost(
        frost_signer: FrostSigner,
        transport_secret: [u8; 32],
        relay_urls: &[String],
        callbacks: Option<Arc<dyn ServerCallbacks>>,
    ) -> Result<Self> {
        let keyring = Arc::new(Mutex::new(Keyring::new()));
        Self::new_with_frost(
            keyring,
            Some(frost_signer),
            Some(transport_secret),
            relay_urls,
            callbacks,
        )
        .await
    }

    pub async fn new_frost_with_proxy(
        frost_signer: FrostSigner,
        transport_secret: [u8; 32],
        relay_urls: &[String],
        callbacks: Option<Arc<dyn ServerCallbacks>>,
        config: ServerConfig,
        proxy: Option<SocketAddr>,
    ) -> Result<Self> {
        let keyring = Arc::new(Mutex::new(Keyring::new()));
        Self::new_with_config_and_proxy(
            keyring,
            Some(frost_signer),
            Some(transport_secret),
            relay_urls,
            callbacks,
            config,
            proxy,
        )
        .await
    }

    pub async fn new_network_frost(
        network_signer: NetworkFrostSigner,
        transport_secret: [u8; 32],
        relay_urls: &[String],
        callbacks: Option<Arc<dyn ServerCallbacks>>,
    ) -> Result<Self> {
        Self::new_network_frost_with_config(
            network_signer,
            transport_secret,
            relay_urls,
            callbacks,
            ServerConfig::default(),
        )
        .await
    }

    pub async fn new_network_frost_with_config(
        network_signer: NetworkFrostSigner,
        transport_secret: [u8; 32],
        relay_urls: &[String],
        callbacks: Option<Arc<dyn ServerCallbacks>>,
        config: ServerConfig,
    ) -> Result<Self> {
        Self::new_network_frost_with_proxy(
            network_signer,
            transport_secret,
            relay_urls,
            callbacks,
            config,
            None,
        )
        .await
    }

    pub async fn new_network_frost_with_proxy(
        network_signer: NetworkFrostSigner,
        transport_secret: [u8; 32],
        relay_urls: &[String],
        callbacks: Option<Arc<dyn ServerCallbacks>>,
        config: ServerConfig,
        proxy: Option<SocketAddr>,
    ) -> Result<Self> {
        require_relay_urls(relay_urls)?;

        let secret = SecretKey::from_slice(&transport_secret)
            .map_err(|e| CryptoError::invalid_key(format!("transport key: {e}")))?;
        let keys = Keys::new(secret);

        let client = keep_frost_net::build_client(&keys, proxy, config.tls_pinning.clone())
            .map_err(|e| NetworkError::connection(format!("relay client: {e}")))?;
        add_relays(&client, relay_urls, proxy).await?;

        let keyring = Arc::new(Mutex::new(Keyring::new()));
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        apply_pre_grants(&permissions, &config.pre_grants).await;
        permissions
            .lock()
            .await
            .set_auto_approve_kinds(config.auto_approve_kinds.clone());
        let audit = Arc::new(Mutex::new(AuditLog::new(config.audit_log_capacity)));
        let handler = SignerHandler::new(keyring, permissions, audit, callbacks.clone())
            .with_network_frost_signer(network_signer)
            .with_auto_approve(config.auto_approve)
            .with_connect_grant(config.connect_grant)
            .with_connect_auto_approve_kinds(config.connect_auto_approve_kinds.clone())
            .with_transport_pubkey(keys.public_key());
        let (handler, bunker_secret) = finalize_handler(handler, &config, relay_urls)?;

        Ok(Self::build(
            keys,
            relay_urls,
            client,
            handler,
            callbacks,
            config,
            bunker_secret,
        ))
    }

    pub fn bunker_url(&self) -> String {
        generate_bunker_url(
            &self.keys.public_key(),
            &self.relay_urls,
            self.bunker_secret.as_ref().map(|s| s.as_str()),
        )
    }

    pub fn pubkey(&self) -> PublicKey {
        self.keys.public_key()
    }

    pub fn transport_secret(&self) -> SecretKey {
        self.keys.secret_key().clone()
    }

    /// Sends `event` to the bunker's own relays, not to any a
    /// `nostrconnect://` client added.
    pub async fn send_event(&self, event: &Event) -> Result<()> {
        self.client
            .send_event_to(self.own_relays.iter(), event)
            .await
            .map_err(|e| NetworkError::relay(format!("send event: {e}")))?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        info!(relay = %self.relay_url, "connecting to relay");

        self.client.connect().await;

        // `connect()` only spawns background attempts and `subscribe` queues
        // against an empty pool, so both return `Ok` while the pinned transport
        // is refusing every socket (a certificate that no longer matches the
        // pin, or a scheme it cannot pin). Without this the bunker reports
        // running and publishes a URL that can never receive a request.
        //
        // Gated on pinning being installed on purpose. The always-on bunkers in
        // keep-cli and keep-web pass no pinning and are built to start before a
        // relay is reachable and let the pool reconnect, so failing their start
        // on a transient relay outage would trade availability for a diagnostic.
        if self.config.tls_pinning.is_some() {
            keep_frost_net::wait_for_any_relay(&self.client, std::time::Duration::from_secs(10))
                .await
                .map_err(|e| NetworkError::connection(e.to_string()))?;
        }

        self.serving_since =
            Timestamp::now() - std::time::Duration::from_secs(REQUEST_CLOCK_SKEW_SECS);
        let filter = Filter::new()
            .kind(Kind::NostrConnect)
            .pubkey(self.keys.public_key())
            .since(self.serving_since);

        self.client
            .subscribe(filter, None)
            .await
            .map_err(|e| NetworkError::subscribe(e.to_string()))?;

        self.running = true;

        let pubkey = self.keys.public_key().to_hex();
        let relay = &self.relay_url;
        debug!(pubkey, relay, "listening for NIP-46 requests");

        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        self.start().await?;

        let handler = self.handler.clone();
        let keys = self.keys.clone();
        let client = self.client.clone();
        let own_relays = Arc::clone(&self.own_relays);
        let routes = Arc::clone(&self.routes);
        let callbacks = self.callbacks.clone();
        let max_event_json_size = self.config.max_event_json_size;
        let since = self.serving_since;

        let serve: crate::scheduler::Serve = Arc::new(move |event: Event| {
            let handler = handler.clone();
            let keys = keys.clone();
            let client = client.clone();
            let own_relays = Arc::clone(&own_relays);
            let routes = Arc::clone(&routes);
            let callbacks = callbacks.clone();
            Box::pin(async move {
                let relays = response_relays(&own_relays, &routes, &event.pubkey);
                if let Err(e) = Self::handle_nip46_event(
                    &handler,
                    &keys,
                    &client,
                    &relays,
                    &event,
                    callbacks.as_deref(),
                    max_event_json_size,
                )
                .await
                {
                    warn!(error = %e, "error handling NIP-46 event");
                }
            })
        });
        // Dropped when serving ends, which aborts the requests still queued.
        let mut scheduler = crate::scheduler::AppScheduler::new(serve);

        let ended = drive_notifications(self.client.notifications(), |notification| {
            if let RelayPoolNotification::Event { event, .. } = notification {
                // `since` is checked here as well as in the filter: the pool
                // does not hold a relay to it.
                let now = Timestamp::now();
                if event.kind == Kind::NostrConnect && is_out_of_window(&event, since, now) {
                    let app_id = &event.pubkey.to_hex()[..8];
                    if is_too_far_ahead(&event, now) {
                        // Most likely a client whose clock is set ahead,
                        // which otherwise just sees every request hang.
                        warn!(app_id, "ignoring a NIP-46 request dated too far ahead");
                    } else {
                        debug!(
                            app_id,
                            "ignoring a NIP-46 request from before this bunker started"
                        );
                    }
                } else if event.kind == Kind::NostrConnect {
                    scheduler.dispatch(*event);
                }
            }
            std::future::ready(())
        })
        .await;
        drop(scheduler);

        self.running = false;
        match ended {
            NotificationsEnded::Shutdown => Ok(()),
            NotificationsEnded::Closed => Err(NetworkError::relay(
                "the relay notification stream closed without a shutdown",
            )
            .into()),
        }
    }

    async fn handle_nip46_event(
        handler: &SignerHandler,
        keys: &Keys,
        client: &Client,
        relays: &[RelayUrl],
        event: &Event,
        callbacks: Option<&dyn ServerCallbacks>,
        max_event_json_size: usize,
    ) -> Result<()> {
        let app_pubkey = event.pubkey;
        let app_id = &app_pubkey.to_hex()[..8];

        let decrypted = nip44::decrypt(keys.secret_key(), &app_pubkey, &event.content)
            .map_err(|e| CryptoError::decryption(e.to_string()))?;

        if decrypted.len() > max_event_json_size {
            return Err(KeepError::InvalidInput("NIP-46 request too large".into()));
        }

        let request: Nip46Request = serde_json::from_str(&decrypted)
            .map_err(|e| StorageError::invalid_format(format!("NIP-46 request: {e}")))?;

        if request.id.len() > 64
            || !request
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(KeepError::InvalidInput("invalid request ID".into()));
        }

        const MAX_NIP46_PARAMS: usize = 10;
        if request.params.len() > MAX_NIP46_PARAMS {
            return Err(KeepError::InvalidInput("too many request params".into()));
        }

        debug!(method = %request.method, app_id, "NIP-46 request");

        let method = request.method.clone();
        let mut connect_auth = None;
        let response = dispatch_request(
            handler,
            keys.public_key(),
            app_pubkey,
            request,
            max_event_json_size,
            &mut connect_auth,
        )
        .await;

        let success = response.error.is_none();
        if let Some(cb) = callbacks {
            cb.on_log(LogEvent {
                app: app_id.to_string(),
                action: method.clone(),
                success,
                detail: response.error.clone(),
            });

            // connect_auth is Some only when handle_connect authorized the connect,
            // so on_connect fires with the explicit authorization reason.
            if let Some(auth) = connect_auth {
                cb.on_connect(&app_pubkey.to_hex(), &format!("App {app_id}"), auth);
            }
        }

        let response_json = serde_json::to_string(&response)
            .map_err(|e| StorageError::serialization(e.to_string()))?;

        let encrypted = nip44::encrypt(
            keys.secret_key(),
            &app_pubkey,
            &response_json,
            nip44::Version::V2,
        )
        .map_err(|e| CryptoError::encryption(e.to_string()))?;

        let response_event = EventBuilder::new(Kind::NostrConnect, encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(app_pubkey))
            .sign_with_keys(keys)
            .map_err(|e| CryptoError::invalid_signature(format!("sign response: {e}")))?;

        if send_to_relays(client, relays, &response_event).await == 0 {
            error!("failed to send response: no relay accepted it");
        }

        Ok(())
    }
}

pub(crate) async fn dispatch_request(
    handler: &SignerHandler,
    user_pubkey: PublicKey,
    app_pubkey: PublicKey,
    request: Nip46Request,
    max_event_json_size: usize,
    connect_auth: &mut Option<ConnectAuthorization>,
) -> Nip46Response {
    let id = request.id.clone();

    match request.method.as_str() {
        "connect" => {
            let our_pubkey = request
                .params
                .first()
                .and_then(|s| PublicKey::from_hex(s).ok());
            let secret = request.params.get(1).cloned();
            let permissions = request.params.get(2).cloned();
            match handler
                .handle_connect(app_pubkey, our_pubkey, secret, permissions)
                .await
            {
                Ok(auth) => {
                    *connect_auth = Some(auth);
                    Nip46Response::ok(id, "ack")
                }
                Err(e) => {
                    warn!(error = %e, "connect failed");
                    Nip46Response::error(id, crate::error::sanitize_error_for_client(&e))
                }
            }
        }
        "get_public_key" => match handler.handle_get_public_key(app_pubkey).await {
            Ok(pk) => Nip46Response::ok(id, &pk.to_hex()),
            Err(e) => {
                warn!(error = %e, "get_public_key failed");
                Nip46Response::error(id, crate::error::sanitize_error_for_client(&e))
            }
        },
        "sign_event" => {
            let event_json = match request.params.first() {
                Some(json) => json,
                None => return Nip46Response::error(id, "Missing event parameter"),
            };

            if event_json.len() > max_event_json_size {
                return Nip46Response::error(id, "Event JSON too large");
            }

            let partial: PartialEvent = match serde_json::from_str(event_json) {
                Ok(p) => p,
                Err(_) => return Nip46Response::error(id, "Invalid event format"),
            };

            if partial.created_at < 0 {
                return Nip46Response::error(id, "Invalid created_at timestamp");
            }

            let max_future = Timestamp::now().as_secs() + 86_400;
            if partial.created_at as u64 > max_future {
                return Nip46Response::error(id, "created_at timestamp too far in the future");
            }

            let mut tags = Vec::with_capacity(partial.tags.len());
            for t in &partial.tags {
                match Tag::parse(t) {
                    Ok(tag) => tags.push(tag),
                    Err(_) => return Nip46Response::error(id, "Invalid tag in event"),
                }
            }

            let unsigned = UnsignedEvent::new(
                user_pubkey,
                Timestamp::from(partial.created_at as u64),
                Kind::from(partial.kind),
                tags,
                &partial.content,
            );

            match handler.handle_sign_event(app_pubkey, unsigned).await {
                Ok(event) => match serde_json::to_string(&event) {
                    Ok(json) => Nip46Response::ok(id, &json),
                    Err(e) => {
                        warn!(error = %e, "sign_event serialization failed");
                        Nip46Response::error(id, "Serialization failed")
                    }
                },
                Err(e) => {
                    warn!(error = %e, "sign_event failed");
                    Nip46Response::error(id, crate::error::sanitize_error_for_client(&e))
                }
            }
        }
        "nip44_encrypt" | "nip44_decrypt" | "nip04_encrypt" | "nip04_decrypt" => {
            if request.params.len() < 2 {
                return Nip46Response::error(id, "Missing parameters");
            }
            let peer = match PublicKey::from_hex(&request.params[0]) {
                Ok(pk) => pk,
                Err(_) => return Nip46Response::error(id, "Invalid pubkey"),
            };
            let result = match request.method.as_str() {
                "nip44_encrypt" => {
                    handler
                        .handle_nip44_encrypt(app_pubkey, peer, &request.params[1])
                        .await
                }
                "nip44_decrypt" => {
                    handler
                        .handle_nip44_decrypt(app_pubkey, peer, &request.params[1])
                        .await
                }
                "nip04_encrypt" => {
                    handler
                        .handle_nip04_encrypt(app_pubkey, peer, &request.params[1])
                        .await
                }
                "nip04_decrypt" => {
                    handler
                        .handle_nip04_decrypt(app_pubkey, peer, &request.params[1])
                        .await
                }
                // The outer dispatch arm routes exactly the four methods above
                // here, so this is unreachable today; fail closed instead of
                // panicking so a future divergence between the two lists cannot
                // let an attacker-supplied method string crash the signer.
                other => {
                    warn!(method = %other, "encryption dispatch received unrouted method");
                    return Nip46Response::error(id, "Unsupported method");
                }
            };
            match result {
                Ok(data) => Nip46Response::ok(id, &data),
                Err(e) => {
                    warn!(error = %e, method = %request.method, "encryption method failed");
                    Nip46Response::error(id, crate::error::sanitize_error_for_client(&e))
                }
            }
        }
        "nip44v3_encrypt" | "nip44v3_decrypt" => {
            // The v3 param layout is exactly [pubkey, kind, scope, payload]. Require all
            // four so a short vector (e.g. [pubkey, kind, payload]) fails loud rather
            // than silently binding scope=payload via positional defaulting.
            if request.params.len() < 4 {
                return Nip46Response::error(id, "Missing parameters");
            }
            let peer = match PublicKey::from_hex(&request.params[0]) {
                Ok(pk) => pk,
                Err(_) => return Nip46Response::error(id, "Invalid pubkey"),
            };
            // kind is mandatory and must be a u32 — fail closed on missing/unparseable.
            let kind = match request.params[1].parse::<u32>() {
                Ok(k) => k,
                Err(_) => return Nip46Response::error(id, "Invalid or missing kind"),
            };
            let scope = request.params[2].as_str();
            let payload = request.params[3].as_str();
            let result = match request.method.as_str() {
                "nip44v3_encrypt" => {
                    handler
                        .handle_nip44_v3_encrypt(app_pubkey, peer, kind, scope, payload)
                        .await
                }
                "nip44v3_decrypt" => {
                    handler
                        .handle_nip44_v3_decrypt(app_pubkey, peer, kind, scope, payload)
                        .await
                }
                other => {
                    warn!(method = %other, "v3 encryption dispatch received unrouted method");
                    return Nip46Response::error(id, "Unsupported method");
                }
            };
            match result {
                Ok(data) => Nip46Response::ok(id, &data),
                Err(e) => {
                    warn!(error = %e, method = %request.method, "v3 encryption method failed");
                    Nip46Response::error(id, crate::error::sanitize_error_for_client(&e))
                }
            }
        }
        "switch_relays" => match handler.handle_switch_relays(app_pubkey).await {
            Ok(Some(relays)) => match serde_json::to_string(&relays) {
                Ok(json) => Nip46Response::ok(id, &json),
                Err(_) => Nip46Response::error(id, "Serialization failed"),
            },
            Ok(None) => Nip46Response::ok(id, "null"),
            Err(e) => {
                warn!(error = %e, "switch_relays failed");
                Nip46Response::error(id, crate::error::sanitize_error_for_client(&e))
            }
        },
        "ping" => Nip46Response::ok(id, "pong"),
        _ => Nip46Response::error(id, "Unknown method"),
    }
}

/// The relays each `nostrconnect://` client picked, keyed by the client. Its
/// responses go to these as well as the bunker's own relays; no other
/// client's response is sent to them.
type ClientRoutes = Arc<std::sync::RwLock<std::collections::HashMap<PublicKey, Vec<RelayUrl>>>>;

/// Sends `event` to each of `urls` the pool holds, all at once and without the
/// pool's lock held while a relay is awaited, so a relay slow to answer holds
/// up only the send that went to it. Returns how many relays accepted it.
async fn send_to_relays(client: &Client, urls: &[RelayUrl], event: &Event) -> usize {
    let mut sends = spawn_sends(client, urls, event).await;
    let mut accepted = 0;
    while let Some(sent) = sends.join_next().await {
        if matches!(sent, Ok(true)) {
            accepted += 1;
        }
    }
    accepted
}

/// Sends `event` to every relay of `urls` at once, and returns once one has
/// accepted it, leaving the others to finish on their own, or once all have
/// refused it.
async fn send_until_one_accepts(client: &Client, urls: &[RelayUrl], event: &Event) -> bool {
    let mut sends = spawn_sends(client, urls, event).await;
    while let Some(sent) = sends.join_next().await {
        if matches!(sent, Ok(true)) {
            sends.detach_all();
            return true;
        }
    }
    false
}

async fn spawn_sends(
    client: &Client,
    urls: &[RelayUrl],
    event: &Event,
) -> tokio::task::JoinSet<bool> {
    let mut sends = tokio::task::JoinSet::new();
    for url in urls {
        match client.relay(url).await {
            Ok(relay) => {
                let event = event.clone();
                sends.spawn(async move { relay.send_event(&event).await.is_ok() });
            }
            Err(e) => debug!(relay = %url, error = %e, "relay left the pool before a send"),
        }
    }
    sends
}

/// The relays a response to `app` goes to: the bunker's own and, for a
/// `nostrconnect://` client, the ones it picked.
fn response_relays(own: &[RelayUrl], routes: &ClientRoutes, app: &PublicKey) -> Vec<RelayUrl> {
    let mut urls = own.to_vec();
    let routes = routes.read().unwrap_or_else(|e| e.into_inner());
    for url in routes.get(app).into_iter().flatten() {
        if !urls.contains(url) {
            urls.push(url.clone());
        }
    }
    urls
}

/// Parses `relay_urls` and drops any naming a relay listed earlier, however
/// it was spelled.
fn distinct_relay_urls(relay_urls: &[String]) -> Result<Vec<RelayUrl>> {
    let mut urls: Vec<RelayUrl> = Vec::with_capacity(relay_urls.len());
    for url in relay_urls {
        let url = RelayUrl::parse(url).map_err(|e| NetworkError::relay(e.to_string()))?;
        if !urls.contains(&url) {
            urls.push(url);
        }
    }
    Ok(urls)
}

/// A handle on a bunker's relay pool and transport key that stays usable
/// after the server itself has moved into the task that runs it. It lets a
/// caller reach a `nostrconnect://` client on relays the client picked
/// without replacing the bunker's own.
///
/// Added relays inherit the bunker's subscription and dial through the same
/// transport, so the TLS pinning the server was built with is enforced on
/// their handshakes against the pin set it holds. That set is the one
/// [`ServerRelays::tls_pinning`] returns: a pin the caller learns for a new
/// host must be added to it before the host is joined, or the handshake gets
/// only standard certificate validation.
///
/// A client's relays only carry that client's responses: every response goes
/// to the bunker's own relays and the requester's own ones, never to relays
/// another client picked.
#[derive(Clone)]
pub struct ServerRelays {
    client: Client,
    keys: Keys,
    routes: ClientRoutes,
    joining: Arc<Mutex<()>>,
    tls_pinning: Option<keep_frost_net::TlsPinning>,
}

/// Relays a [`ServerRelays::join`] reached for one client. Joins are taken
/// one at a time until this is handed to [`ServerRelays::route`] or
/// [`ServerRelays::abandon`], so a relay one join added is never one another
/// counts on.
pub struct JoinedRelays {
    reached: Vec<RelayUrl>,
    added: Vec<RelayUrl>,
    /// The client [`ServerRelays::route`] routed through these relays.
    routed: Option<PublicKey>,
    _one_at_a_time: Arc<tokio::sync::OwnedMutexGuard<()>>,
}

/// The relays a [`ServerRelays::rejoin`] reached for each client, not yet
/// routed.
pub struct Rejoined {
    joined: JoinedRelays,
    clients: Vec<(PublicKey, Vec<RelayUrl>)>,
}

impl Rejoined {
    /// The clients at least one of whose relays was reached.
    pub fn clients(&self) -> Vec<PublicKey> {
        self.clients.iter().map(|(client, _)| *client).collect()
    }
}

impl JoinedRelays {
    pub fn reached(&self) -> Vec<String> {
        self.reached.iter().map(ToString::to_string).collect()
    }
}

impl ServerRelays {
    /// The pinning the bunker's transport enforces, when it was built with
    /// one.
    pub fn tls_pinning(&self) -> Option<&keep_frost_net::TlsPinning> {
        self.tls_pinning.as_ref()
    }

    /// Adds `relay_urls` to the pool and connects to them all at once, each
    /// given `timeout`, keeping those reached. Equivalent spellings of one
    /// relay are joined once. A relay added here that cannot be reached is
    /// removed again, as is every one added when the call fails; one the pool
    /// already held is left as it was. A removal the pool holds up past
    /// `timeout` finishes after the call returns, and no other join starts
    /// before it does. Fails when none is reached, and times out when the
    /// relays cannot be added within `timeout`, in which case those added are
    /// removed once the pool lets them be.
    pub async fn join(
        &self,
        relay_urls: &[String],
        proxy: Option<SocketAddr>,
        timeout: std::time::Duration,
    ) -> Result<JoinedRelays> {
        debug_assert!(relay_urls.len() <= keep_core::relay::MAX_RELAYS);
        self.join_all(relay_urls, proxy, timeout).await
    }

    /// Joins the relays of each of `clients` again, on a server started
    /// after they were accepted, as [`ServerRelays::join`] joins them: all
    /// at once within `timeout`, those not reached removed again. No client
    /// is routed yet: [`ServerRelays::route_rejoined`] does that once the
    /// caller has seen the clients may still be served, and
    /// [`ServerRelays::release_rejoined`] then drops the relays no route
    /// uses. Joins are taken one at a time until then.
    pub async fn rejoin(
        &self,
        clients: &[(PublicKey, Vec<String>)],
        proxy: Option<SocketAddr>,
        timeout: std::time::Duration,
    ) -> Result<Rejoined> {
        let mut all: Vec<String> = Vec::new();
        for relay in clients.iter().flat_map(|(_, relays)| relays) {
            if !all.contains(relay) {
                all.push(relay.clone());
            }
        }
        if all.is_empty() {
            return Err(NetworkError::relay("no nostrconnect relay to join").into());
        }
        let joined = self.join_all(&all, proxy, timeout).await?;
        let clients = clients
            .iter()
            .filter_map(|(client, relays)| {
                let reached: Vec<RelayUrl> = distinct_relay_urls(relays)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|url| joined.reached.contains(url))
                    .collect();
                (!reached.is_empty()).then_some((*client, reached))
            })
            .collect();
        Ok(Rejoined { joined, clients })
    }

    /// Sends the responses of each client `rejoined` reached that `keep`
    /// accepts to those of its relays reached, as [`ServerRelays::route`]
    /// does for one. Returns the clients routed.
    pub fn route_rejoined(
        &self,
        rejoined: &Rejoined,
        keep: impl Fn(&PublicKey) -> bool,
    ) -> Vec<PublicKey> {
        let mut routes = self.routes.write().unwrap_or_else(|e| e.into_inner());
        let mut routed = Vec::new();
        for (client, reached) in rejoined.clients.iter().filter(|(c, _)| keep(c)) {
            routes.insert(*client, reached.clone());
            routed.push(*client);
        }
        routed
    }

    /// Ends a [`ServerRelays::rejoin`]: the relays it added that no route
    /// uses are removed, and the next join may start.
    pub async fn release_rejoined(&self, rejoined: Rejoined) {
        let unused: Vec<RelayUrl> = {
            let routes = self.routes.read().unwrap_or_else(|e| e.into_inner());
            rejoined
                .joined
                .added
                .iter()
                .filter(|url| !routes.values().flatten().any(|used| used == *url))
                .cloned()
                .collect()
        };
        self.remove_relays(&unused).await;
    }

    /// The relays `client`'s responses are routed to beyond the bunker's own.
    pub fn routed_relays(&self, client: &PublicKey) -> Vec<String> {
        self.routes
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(client)
            .into_iter()
            .flatten()
            .map(ToString::to_string)
            .collect()
    }

    async fn join_all(
        &self,
        relay_urls: &[String],
        proxy: Option<SocketAddr>,
        timeout: std::time::Duration,
    ) -> Result<JoinedRelays> {
        let urls = distinct_relay_urls(relay_urls)?;
        // Waiting on another join counts against `timeout`, so the call as a
        // whole never runs past it.
        let started = tokio::time::Instant::now();
        let budget = timeout;
        let one_at_a_time = tokio::time::timeout(timeout, Arc::clone(&self.joining).lock_owned())
            .await
            .map_err(|_| NetworkError::timeout("waiting on another nostrconnect join"))?;
        let mut joined = JoinedRelays {
            reached: Vec::new(),
            added: Vec::new(),
            routed: None,
            _one_at_a_time: Arc::new(one_at_a_time),
        };
        let opts = relay_options(proxy);
        // An add waits for the pool's write lock, which a send in flight
        // holds shared while it waits on relays' replies.
        for url in &urls {
            let left = timeout.saturating_sub(started.elapsed());
            let added = tokio::time::timeout(left, self.client.pool().add_relay(url, opts.clone()))
                .await
                .map_err(|_| NetworkError::timeout("waiting to add a nostrconnect relay"));
            match added {
                Ok(Ok(true)) => joined.added.push(url.clone()),
                Ok(Ok(false)) => {}
                Ok(Err(e)) => {
                    self.abandon_later(joined);
                    return Err(NetworkError::relay(e.to_string()).into());
                }
                Err(e) => {
                    self.abandon_later(joined);
                    return Err(e.into());
                }
            }
        }
        let timeout = timeout.saturating_sub(started.elapsed());
        let mut attempts = tokio::task::JoinSet::new();
        for url in urls {
            let client = self.client.clone();
            attempts.spawn(async move {
                let result = client.try_connect_relay(&url, timeout).await;
                (url, result)
            });
        }
        let mut unreached = Vec::new();
        while let Some(attempt) = attempts.join_next().await {
            let Ok((url, result)) = attempt else { continue };
            match result {
                Ok(()) => joined.reached.push(url),
                Err(e) => {
                    warn!(relay = %url, error = %e, "could not reach a nostrconnect relay");
                    if joined.added.contains(&url) {
                        unreached.push(url);
                    }
                }
            }
        }
        joined.added.retain(|url| !unreached.contains(url));
        // A removal waits for the pool's write lock too. One that cannot
        // take it in time finishes in a task of its own, which holds this
        // join's turn until it does.
        let left = budget.saturating_sub(started.elapsed());
        let lingering = self.remove_relays_within(&unreached, left).await;
        if !lingering.is_empty() {
            let relays = self.clone();
            let turn = Arc::clone(&joined._one_at_a_time);
            tokio::spawn(async move {
                relays.remove_relays(&lingering).await;
                drop(turn);
            });
        }
        if joined.reached.is_empty() {
            self.abandon(joined).await;
            return Err(NetworkError::relay("none of the client's relays could be reached").into());
        }
        Ok(joined)
    }

    /// Sends `client`'s responses to the relays `joined` reached as well as
    /// the bunker's own, from now until the server stops or
    /// [`ServerRelays::abandon`] is called for `joined`.
    pub fn route(&self, joined: &mut JoinedRelays, client: PublicKey) {
        self.routes
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(client, joined.reached.clone());
        joined.routed = Some(client);
    }

    /// Undoes a join: the route it installed, if any, is dropped, and the
    /// relays it added are removed from the pool. A route another join
    /// installed for the same client is left alone.
    pub async fn abandon(&self, joined: JoinedRelays) {
        if let Some(client) = joined.routed {
            self.routes
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&client);
        }
        self.remove_relays(&joined.added).await;
    }

    /// [`ServerRelays::abandon`] in a task of its own, so a caller bounded by
    /// a deadline need not wait on the pool's write lock.
    fn abandon_later(&self, joined: JoinedRelays) {
        let relays = self.clone();
        tokio::spawn(async move { relays.abandon(joined).await });
    }

    /// Whether the pool holds `url`.
    pub async fn holds(&self, url: &str) -> bool {
        self.client.relay(url).await.is_ok()
    }

    async fn remove_relays(&self, urls: &[RelayUrl]) {
        for url in urls {
            if let Err(e) = self.client.force_remove_relay(url).await {
                warn!(relay = %url, error = %e, "could not remove a nostrconnect relay");
            }
        }
    }

    /// [`ServerRelays::remove_relays`] for at most `timeout`, returning the
    /// relays it did not get to. A removal cut short has removed nothing,
    /// since its only wait is for the pool's write lock.
    async fn remove_relays_within(
        &self,
        urls: &[RelayUrl],
        timeout: std::time::Duration,
    ) -> Vec<RelayUrl> {
        let deadline = tokio::time::Instant::now() + timeout;
        for (i, url) in urls.iter().enumerate() {
            match tokio::time::timeout_at(deadline, self.client.force_remove_relay(url)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    warn!(relay = %url, error = %e, "could not remove a nostrconnect relay")
                }
                Err(_) => return urls[i..].to_vec(),
            }
        }
        Vec::new()
    }

    /// Answers a `nostrconnect://` request on the relays `joined` reached: a
    /// kind 24133 event signed with the transport key and NIP-44 encrypted to
    /// the client, whose `result` is the client's own secret. Succeeds as soon
    /// as one relay accepts it, without waiting on the others, and fails only
    /// when every relay refused it.
    pub async fn send_nostrconnect_response(
        &self,
        request: &crate::bunker::NostrConnectRequest,
        joined: &JoinedRelays,
    ) -> Result<()> {
        debug_assert!(!joined.reached.is_empty());
        let response_id = keep_core::crypto::try_random_bytes::<16>()?;
        let response = serde_json::json!({
            "id": hex::encode(response_id),
            "result": request.secret.as_str(),
        });
        let response_json = Zeroizing::new(
            serde_json::to_string(&response)
                .map_err(|e| StorageError::serialization(e.to_string()))?,
        );
        let encrypted = nip44::encrypt(
            self.keys.secret_key(),
            &request.client_pubkey,
            response_json.as_str(),
            nip44::Version::V2,
        )
        .map_err(|e| CryptoError::encryption(e.to_string()))?;
        let event = EventBuilder::new(Kind::NostrConnect, encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(request.client_pubkey))
            .sign_with_keys(&self.keys)
            .map_err(|e| CryptoError::invalid_signature(format!("sign response: {e}")))?;

        if !send_until_one_accepts(&self.client, &joined.reached, &event).await {
            return Err(NetworkError::relay("no relay accepted the connect response").into());
        }
        Ok(())
    }
}

impl Server {
    pub fn handler(&self) -> Arc<SignerHandler> {
        self.handler.clone()
    }

    pub fn relays(&self) -> ServerRelays {
        ServerRelays {
            client: self.client.clone(),
            keys: self.keys.clone(),
            routes: Arc::clone(&self.routes),
            joining: Arc::clone(&self.joining),
            tls_pinning: self.config.tls_pinning.clone(),
        }
    }

    /// Stops serving and shuts the relay pool down, dropping every relay a
    /// `nostrconnect://` client added. The server cannot be started again,
    /// and a [`ServerRelays`] taken from it can no longer join a relay.
    #[allow(dead_code)]
    pub async fn stop(&mut self) {
        self.handler.revoke_session_apps().await;
        self.running = false;
        self.client.shutdown().await;
        self.routes
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

#[cfg(test)]
mod tests {

    // A request created at either edge of the window is handled, and one a
    // second beyond it is not. Checked here without a relay, since the
    // filter's `since` would hide a regression in the check from any test that
    // goes through one.
    #[test]
    fn a_request_outside_the_window_is_recognized() {
        let keys = Keys::generate();
        let since = Timestamp::from_secs(1_800_000_000);
        let now = Timestamp::from_secs(1_800_001_000);
        let at = |secs: u64| {
            EventBuilder::new(Kind::NostrConnect, "")
                .custom_created_at(Timestamp::from_secs(secs))
                .sign_with_keys(&keys)
                .unwrap()
        };
        let skew = REQUEST_FUTURE_SKEW_SECS;
        assert!(!is_out_of_window(&at(1_800_000_000), since, now));
        assert!(is_out_of_window(&at(1_799_999_999), since, now));
        assert!(!is_out_of_window(&at(1_800_001_000 + skew), since, now));
        assert!(is_out_of_window(&at(1_800_001_001 + skew), since, now));
    }
    use super::*;

    // `pool().add_relay` takes the relay options verbatim, so the proxy has to
    // ride on them; a client-level connection option never reaches these
    // sockets and the bunker would connect directly while the user believes
    // their traffic is proxied.
    #[tokio::test]
    async fn a_configured_proxy_reaches_the_bunker_relay_sockets() {
        use nostr_sdk::prelude::ConnectionMode;

        let proxy: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let relays = vec!["wss://relay.example.com".to_string()];

        let client = keep_frost_net::build_client(&Keys::generate(), Some(proxy), None).unwrap();
        add_relays(&client, &relays, Some(proxy)).await.unwrap();
        let relay = client.relay(&relays[0]).await.unwrap();
        assert_eq!(*relay.connection_mode(), ConnectionMode::Proxy(proxy));

        let direct = keep_frost_net::build_client(&Keys::generate(), None, None).unwrap();
        add_relays(&direct, &relays, None).await.unwrap();
        let relay = direct.relay(&relays[0]).await.unwrap();
        assert_eq!(*relay.connection_mode(), ConnectionMode::Direct);
    }

    // A response goes to the bunker's own relays and the requester's own
    // ones, never to relays another client picked.
    #[test]
    fn a_response_goes_only_to_its_requesters_relays() {
        let own = vec![RelayUrl::parse("wss://own.example.com").unwrap()];
        let theirs = RelayUrl::parse("wss://theirs.example.com").unwrap();
        let picker = Keys::generate().public_key();
        let other = Keys::generate().public_key();
        let routes = ClientRoutes::default();
        routes
            .write()
            .unwrap()
            .insert(picker, vec![theirs.clone(), own[0].clone()]);

        assert_eq!(response_relays(&own, &routes, &other), own);
        assert_eq!(
            response_relays(&own, &routes, &picker),
            vec![own[0].clone(), theirs]
        );
    }

    // A join reaches each relay once however it is spelled, keeps what it
    // reached, and drops what it added and could not reach; abandoning it
    // removes what it added and leaves what the pool held before.
    #[tokio::test]
    async fn a_join_leaves_the_pool_as_it_found_it_when_abandoned() {
        let own = nostr_relay_builder::MockRelay::run().await.unwrap();
        let own_url = own.url().await.to_string();
        let theirs = nostr_relay_builder::MockRelay::run().await.unwrap();
        let their_url = theirs.url().await.to_string();
        let closed = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("ws://{}", listener.local_addr().unwrap())
        };
        let mut keyring = Keyring::new();
        let keypair = keep_core::keys::NostrKeypair::generate().unwrap();
        keyring
            .load_key(
                *keypair.public_bytes(),
                *keypair.secret_bytes(),
                keep_core::keys::KeyType::Nostr,
                "test".into(),
            )
            .unwrap();
        let server = Server::new(
            Arc::new(Mutex::new(keyring)),
            std::slice::from_ref(&own_url),
            None,
        )
        .await
        .unwrap();
        let relays = server.relays();

        let asked = [
            own_url.clone(),
            their_url.clone(),
            their_url.replacen("ws://", "WS://", 1),
            closed.clone(),
        ];
        let joined = relays
            .join(&asked, None, std::time::Duration::from_secs(2))
            .await
            .unwrap();
        let mut reached = joined.reached();
        reached.sort();
        let mut expected = vec![own_url.clone(), their_url.clone()];
        expected.sort();
        assert_eq!(reached, expected);
        assert!(relays.holds(&their_url).await);
        assert!(
            !relays.holds(&closed).await,
            "an unreached relay is dropped"
        );

        relays.abandon(joined).await;
        assert!(relays.holds(&own_url).await, "the bunker's own relay stays");
        assert!(!relays.holds(&their_url).await);

        let none = relays
            .join(
                std::slice::from_ref(&closed),
                None,
                std::time::Duration::from_secs(2),
            )
            .await;
        assert!(none.is_err());
        assert!(!relays.holds(&closed).await);
    }

    // A join that waits on another and then dials a relay that never
    // answers still returns within its timeout as a whole.
    #[tokio::test]
    async fn a_join_stays_within_its_timeout() {
        let own = nostr_relay_builder::MockRelay::run().await.unwrap();
        let own_url = own.url().await.to_string();
        let (dialed_tx, dialed) = std::sync::mpsc::channel();
        let hanging = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            std::thread::spawn(move || {
                let mut held = Vec::new();
                for stream in listener.incoming() {
                    held.push(stream);
                    let _ = dialed_tx.send(());
                }
            });
            url
        };
        let mut keyring = Keyring::new();
        let keypair = keep_core::keys::NostrKeypair::generate().unwrap();
        keyring
            .load_key(
                *keypair.public_bytes(),
                *keypair.secret_bytes(),
                keep_core::keys::KeyType::Nostr,
                "test".into(),
            )
            .unwrap();
        let server = Server::new(
            Arc::new(Mutex::new(keyring)),
            std::slice::from_ref(&own_url),
            None,
        )
        .await
        .unwrap();
        let relays = server.relays();
        let first = relays
            .join(
                std::slice::from_ref(&own_url),
                None,
                std::time::Duration::from_secs(2),
            )
            .await
            .unwrap();

        let timeout = std::time::Duration::from_secs(2);
        // Each handle on the lock is a count: the clone moved into the task
        // and the one the join takes to wait for the lock.
        let waiting = Arc::strong_count(&relays.joining) + 2;
        let started = std::time::Instant::now();
        let second = {
            let relays = relays.clone();
            tokio::spawn(async move { relays.join(&[hanging], None, timeout).await })
        };
        while Arc::strong_count(&relays.joining) < waiting {
            assert!(
                started.elapsed() < timeout,
                "the second join never waited on the lock"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(!second.is_finished(), "the second join did not wait");
        relays.abandon(first).await;
        assert!(second.await.unwrap().is_err());
        assert!(
            dialed.try_recv().is_ok(),
            "the second join never dialed the hanging relay"
        );
        assert!(
            started.elapsed() < timeout + std::time::Duration::from_millis(500),
            "the join ran past its timeout"
        );
    }

    /// A relay write policy that never answers, counting the events it holds.
    #[derive(Debug)]
    struct HoldsEveryOk(Arc<std::sync::atomic::AtomicUsize>);

    impl nostr_relay_builder::prelude::WritePolicy for HoldsEveryOk {
        fn admit_event<'a>(
            &'a self,
            _event: &'a Event,
            _addr: &'a SocketAddr,
        ) -> nostr_relay_builder::prelude::BoxedFuture<'a, nostr_relay_builder::prelude::PolicyResult>
        {
            self.0.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            Box::pin(std::future::pending())
        }
    }

    // A join that cannot add its relays while a send in flight holds the
    // pool waits for it only until its timeout, and leaves none of them in
    // the pool.
    #[tokio::test]
    async fn a_join_waits_on_a_send_in_flight_only_until_its_timeout() {
        let held = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let holding = nostr_relay_builder::LocalRelay::new(
            nostr_relay_builder::RelayBuilder::default()
                .write_policy(HoldsEveryOk(Arc::clone(&held))),
        );
        holding.run().await.unwrap();
        let holding_url = holding.url().await.to_string();
        let theirs = nostr_relay_builder::MockRelay::run().await.unwrap();
        let their_url = theirs.url().await.to_string();
        let mut keyring = Keyring::new();
        let keypair = keep_core::keys::NostrKeypair::generate().unwrap();
        keyring
            .load_key(
                *keypair.public_bytes(),
                *keypair.secret_bytes(),
                keep_core::keys::KeyType::Nostr,
                "test".into(),
            )
            .unwrap();
        let server = Server::new(
            Arc::new(Mutex::new(keyring)),
            std::slice::from_ref(&holding_url),
            None,
        )
        .await
        .unwrap();
        let relays = server.relays();
        relays
            .client
            .try_connect_relay(&holding_url, std::time::Duration::from_secs(2))
            .await
            .unwrap();
        let event = EventBuilder::text_note("held")
            .sign_with_keys(&Keys::generate())
            .unwrap();
        let sending = {
            let client = relays.client.clone();
            tokio::spawn(async move { client.send_event_to([holding_url], &event).await })
        };
        let started = std::time::Instant::now();
        while held.load(std::sync::atomic::Ordering::Acquire) == 0 {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "the send never reached the holding relay"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let timeout = std::time::Duration::from_secs(1);
        let started = std::time::Instant::now();
        let joined = relays
            .join(std::slice::from_ref(&their_url), None, timeout)
            .await;
        assert!(
            started.elapsed() < timeout + std::time::Duration::from_millis(500),
            "the join ran past its timeout"
        );
        assert!(joined.is_err());
        assert!(!sending.is_finished(), "the send let the pool go");
        assert!(!relays.holds(&their_url).await);
    }

    // A send that takes the pool while a join dials holds up the removal of
    // the relay the join could not reach. The join still returns within its
    // timeout, and the relay is removed once the send lets the pool go,
    // before another join starts.
    #[tokio::test]
    async fn a_join_does_not_wait_past_its_timeout_to_drop_an_unreached_relay() {
        let held = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let holding = nostr_relay_builder::LocalRelay::new(
            nostr_relay_builder::RelayBuilder::default()
                .write_policy(HoldsEveryOk(Arc::clone(&held))),
        );
        holding.run().await.unwrap();
        let holding_url = holding.url().await.to_string();
        let theirs = nostr_relay_builder::MockRelay::run().await.unwrap();
        let their_url = theirs.url().await.to_string();
        let hanging = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            std::thread::spawn(move || {
                let mut held = Vec::new();
                for stream in listener.incoming() {
                    held.push(stream);
                }
            });
            url
        };
        let mut keyring = Keyring::new();
        let keypair = keep_core::keys::NostrKeypair::generate().unwrap();
        keyring
            .load_key(
                *keypair.public_bytes(),
                *keypair.secret_bytes(),
                keep_core::keys::KeyType::Nostr,
                "test".into(),
            )
            .unwrap();
        let server = Server::new(
            Arc::new(Mutex::new(keyring)),
            std::slice::from_ref(&holding_url),
            None,
        )
        .await
        .unwrap();
        let relays = server.relays();
        relays
            .client
            .try_connect_relay(&holding_url, std::time::Duration::from_secs(2))
            .await
            .unwrap();

        let timeout = std::time::Duration::from_secs(2);
        let started = std::time::Instant::now();
        let joining = {
            let relays = relays.clone();
            let asked = [their_url.clone(), hanging.clone()];
            tokio::spawn(async move { relays.join(&asked, None, timeout).await })
        };
        while !relays.holds(&hanging).await {
            assert!(
                started.elapsed() < timeout,
                "the join never added the relay"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let event = EventBuilder::text_note("held")
            .sign_with_keys(&Keys::generate())
            .unwrap();
        let sending = {
            let client = relays.client.clone();
            tokio::spawn(async move { client.send_event_to([holding_url], &event).await })
        };
        while held.load(std::sync::atomic::Ordering::Acquire) == 0 {
            assert!(
                started.elapsed() < timeout,
                "the send never reached the holding relay"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let joined = joining.await.unwrap().unwrap();
        assert!(
            started.elapsed() < timeout + std::time::Duration::from_millis(500),
            "the join ran past its timeout"
        );
        assert_eq!(joined.reached(), vec![their_url.clone()]);
        assert!(!sending.is_finished(), "the send let the pool go");

        drop(joined);
        assert!(
            relays.joining.try_lock().is_err(),
            "another join could start before the removal"
        );
        sending.abort();
        let removed = std::time::Instant::now();
        while relays.joining.try_lock().is_err() {
            assert!(
                removed.elapsed() < std::time::Duration::from_secs(5),
                "the removal never finished"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(!relays.holds(&hanging).await, "the unreached relay stayed");
    }

    // An explicitly-configured `expected_secret` must surface as the bunker
    // secret, which `bunker_url()` embeds; otherwise clients get a secret-less
    // URL and reject the connect.
    #[test]
    fn expected_secret_surfaces_in_bunker_secret() {
        let keyring = Arc::new(Mutex::new(Keyring::new()));
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None);
        let config = ServerConfig {
            expected_secret: Some("my-secret".to_string()),
            ..ServerConfig::default()
        };

        let (_handler, bunker_secret) =
            finalize_handler(handler, &config, &["wss://relay.example.com".to_string()]).unwrap();

        let secret = bunker_secret.expect("expected_secret should surface as bunker secret");
        assert_eq!(secret.as_str(), "my-secret");
    }

    #[tokio::test]
    async fn dispatch_v3_fails_closed_on_bad_kind() {
        // A v3 request whose kind is missing or unparseable must return an error
        // from the dispatch layer without ever invoking the cipher. The keyring
        // holds no key, so any call into the crypto path would fail differently.
        let keyring = Arc::new(Mutex::new(Keyring::new()));
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None);
        let user = nostr_sdk::Keys::generate().public_key();
        let app = nostr_sdk::Keys::generate().public_key();
        let peer = nostr_sdk::Keys::generate().public_key();

        // Non-numeric kind -> "Invalid or missing kind".
        let mut connect_auth = None;
        let resp = dispatch_request(
            &handler,
            user,
            app,
            Nip46Request {
                id: "1".into(),
                method: "nip44v3_encrypt".into(),
                params: vec![peer.to_hex(), "notanumber".into(), "dm".into(), "hi".into()],
            },
            65536,
            &mut connect_auth,
        )
        .await;
        // Rejected at the dispatch layer (kind parse), before any permission or cipher.
        assert_eq!(resp.error.as_deref(), Some("Invalid or missing kind"));
        assert!(resp.result.is_none());

        // Too few params (only the pubkey) -> "Missing parameters", before kind parse.
        let resp = dispatch_request(
            &handler,
            user,
            app,
            Nip46Request {
                id: "2".into(),
                method: "nip44v3_decrypt".into(),
                params: vec![peer.to_hex()],
            },
            65536,
            &mut connect_auth,
        )
        .await;
        assert_eq!(resp.error.as_deref(), Some("Missing parameters"));
        assert!(resp.result.is_none());
    }

    fn sample_stored(
        pubkey_hex: &str,
        duration: keep_core::relay::StoredPermissionDuration,
        connected_at: u64,
    ) -> keep_core::relay::StoredBunkerPermission {
        keep_core::relay::StoredBunkerPermission {
            pubkey_hex: pubkey_hex.to_string(),
            name: "test app".to_string(),
            permissions: Permission::GET_PUBLIC_KEY.bits() | Permission::SIGN_EVENT.bits(),
            auto_approve_kinds: vec![1, 7],
            duration,
            connected_at,
            timed_kind_grants: Vec::new(),
            explicitly_remembered: None,
            kinds_vetted: true,
            paired: false,
        }
    }

    fn good_pubkey_hex() -> String {
        nostr_sdk::Keys::generate().public_key().to_hex()
    }

    #[test]
    fn from_stored_returns_none_on_malformed_pubkey() {
        let stored = sample_stored(
            "not-a-pubkey",
            keep_core::relay::StoredPermissionDuration::Forever,
            0,
        );
        assert!(PreGrantedApp::from_stored(&stored).is_none());

        let stored_short = sample_stored(
            "1234",
            keep_core::relay::StoredPermissionDuration::Forever,
            0,
        );
        assert!(PreGrantedApp::from_stored(&stored_short).is_none());
    }

    #[test]
    fn from_stored_translates_duration_and_kinds() {
        let pk_hex = good_pubkey_hex();
        let stored = sample_stored(
            &pk_hex,
            keep_core::relay::StoredPermissionDuration::Seconds(3600),
            42,
        );
        let app = PreGrantedApp::from_stored(&stored).expect("valid stored row");
        assert_eq!(app.name, "test app");
        assert_eq!(app.connected_at.as_secs(), 42);
        assert!(matches!(app.duration, PermissionDuration::Seconds(3600)));
        assert!(app.auto_approve_kinds.contains(&nostr_sdk::Kind::Custom(1)));
        assert!(app.permissions.contains(Permission::SIGN_EVENT));
    }

    #[test]
    fn from_stored_maps_timed_kind_grants() {
        let mut stored = sample_stored(
            &good_pubkey_hex(),
            keep_core::relay::StoredPermissionDuration::Forever,
            42,
        );
        stored.timed_kind_grants = vec![keep_core::relay::StoredTimedKindGrant {
            kind: 1,
            expires_at: 1_900_000_000,
        }];
        let app = PreGrantedApp::from_stored(&stored).expect("valid stored row");
        assert_eq!(
            app.timed_kind_grants.get(&nostr_sdk::Kind::Custom(1)),
            Some(&1_900_000_000)
        );
    }

    // A row from before kinds were vetted may hold kinds a client named in its
    // own connect request, so it restores without auto-approve kinds. Timed
    // grants only ever came from a prompt the user answered, so they stay.
    #[tokio::test]
    async fn an_unvetted_row_restores_without_its_auto_approve_kinds() {
        let mut stored = sample_stored(
            &good_pubkey_hex(),
            keep_core::relay::StoredPermissionDuration::Forever,
            0,
        );
        stored.kinds_vetted = false;
        stored.explicitly_remembered = Some(true);
        stored.timed_kind_grants = vec![keep_core::relay::StoredTimedKindGrant {
            kind: 3,
            expires_at: u64::MAX,
        }];
        let app = PreGrantedApp::from_stored(&stored).expect("valid stored row");
        assert!(app.auto_approve_kinds.is_empty());

        let pm = Arc::new(Mutex::new(PermissionManager::new()));
        apply_pre_grants(&pm, &[app]).await;
        let pm = pm.lock().await;
        let pubkey = PublicKey::from_hex(&stored.pubkey_hex).unwrap();
        assert!(pm.needs_approval(&pubkey, nostr_sdk::Kind::TextNote));
        assert!(!pm.needs_approval(&pubkey, nostr_sdk::Kind::ContactList));
        let snapshot = pm.stored_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot[0].kinds_vetted);
        assert!(!snapshot[0].auto_approve_kinds.contains(&1));
    }

    #[tokio::test]
    async fn apply_pre_grants_skips_session_and_expired() {
        let pm = Arc::new(Mutex::new(PermissionManager::new()));

        // Forever: kept.
        let forever_stored = sample_stored(
            &good_pubkey_hex(),
            keep_core::relay::StoredPermissionDuration::Forever,
            0,
        );
        // Session: dropped by restore_persisted.
        let session_stored = sample_stored(
            &good_pubkey_hex(),
            keep_core::relay::StoredPermissionDuration::Session,
            0,
        );
        // Expired Seconds (connected long ago, very short ttl): dropped.
        let expired_stored = sample_stored(
            &good_pubkey_hex(),
            keep_core::relay::StoredPermissionDuration::Seconds(1),
            1,
        );

        let pre_grants: Vec<PreGrantedApp> = [&forever_stored, &session_stored, &expired_stored]
            .iter()
            .filter_map(|s| PreGrantedApp::from_stored(s))
            .collect();

        apply_pre_grants(&pm, &pre_grants).await;
        let count = pm.lock().await.list_apps().count();
        assert_eq!(
            count, 1,
            "only the Forever grant should land in the manager"
        );
    }

    #[tokio::test]
    async fn apply_pre_grants_round_trips_timed_grant_but_drops_nip98() {
        use crate::NIP98_HTTP_AUTH;

        let pm = Arc::new(Mutex::new(PermissionManager::new()));
        let pk_hex = good_pubkey_hex();
        let mut stored = sample_stored(
            &pk_hex,
            keep_core::relay::StoredPermissionDuration::Forever,
            0,
        );
        // A persisted (legacy/hostile) config carrying both a NIP-98 grant and a
        // benign TextNote grant in every channel.
        stored.auto_approve_kinds = vec![NIP98_HTTP_AUTH.as_u16(), 1];
        stored.timed_kind_grants = vec![
            keep_core::relay::StoredTimedKindGrant {
                kind: NIP98_HTTP_AUTH.as_u16(),
                expires_at: 1_900_000_000,
            },
            keep_core::relay::StoredTimedKindGrant {
                kind: 1,
                expires_at: 1_900_000_000,
            },
        ];

        let pre = PreGrantedApp::from_stored(&stored).expect("valid stored row");
        apply_pre_grants(&pm, &[pre]).await;

        let pubkey = nostr_sdk::PublicKey::from_hex(&pk_hex).unwrap();
        let guard = pm.lock().await;
        // Benign grant survives the persistence round trip.
        assert!(!guard.needs_approval(&pubkey, nostr_sdk::Kind::TextNote));
        // NIP-98 is dropped and always prompts.
        assert!(guard.needs_approval(&pubkey, NIP98_HTTP_AUTH));
        let app = guard.get_app(&pubkey).unwrap();
        assert!(!app.auto_approve_kinds.contains(&NIP98_HTTP_AUTH));
        assert!(!app.timed_kind_grants.contains_key(&NIP98_HTTP_AUTH));
    }

    // === #417 round 5: targeted unit tests killing the surviving mutations ===

    /// `PreGrantedApp::from_stored` MUST reject pubkey-hex strings whose
    /// decoded byte length is anything other than 32. Pin that boundary
    /// with the 0-, 31-, and 33-byte cases: all must produce None.
    /// Note the `b.len() == 32` match guard is backstopped by
    /// `PublicKey::from_slice`, which itself rejects any non-32-byte slice,
    /// so mutating the guard alone is an equivalent mutation (the result
    /// stays None). This test pins the contract, not that specific guard.
    #[test]
    fn from_stored_rejects_pubkey_byte_lengths_other_than_32() {
        // 31 bytes = 62 hex chars.
        let stored_31 = sample_stored(
            &"ab".repeat(31),
            keep_core::relay::StoredPermissionDuration::Forever,
            0,
        );
        assert!(
            PreGrantedApp::from_stored(&stored_31).is_none(),
            "31-byte decoded pubkey must be rejected"
        );

        // 33 bytes = 66 hex chars.
        let stored_33 = sample_stored(
            &"ab".repeat(33),
            keep_core::relay::StoredPermissionDuration::Forever,
            0,
        );
        assert!(
            PreGrantedApp::from_stored(&stored_33).is_none(),
            "33-byte decoded pubkey must be rejected"
        );

        // Empty hex (decodes to zero bytes) — also rejected.
        let stored_0 = sample_stored("", keep_core::relay::StoredPermissionDuration::Forever, 0);
        assert!(
            PreGrantedApp::from_stored(&stored_0).is_none(),
            "empty hex (zero-length pubkey) must be rejected"
        );
    }

    /// `require_relay_urls` MUST refuse empty input. An `Ok(())`-return
    /// regression would let the server start with no relays, silently
    /// failing every connect attempt without surfacing a config error.
    #[test]
    fn require_relay_urls_rejects_empty_and_accepts_one() {
        assert!(
            require_relay_urls(&[]).is_err(),
            "empty relay set must be refused"
        );
        assert!(require_relay_urls(&["wss://relay.example.com".into()]).is_ok());
        // Multiple relays also accepted.
        assert!(require_relay_urls(&[
            "wss://relay.example.com".into(),
            "wss://other.example.com".into(),
        ])
        .is_ok());
    }

    /// `finalize_handler` generates a fresh random bunker secret ONLY when
    /// BOTH headless (`auto_approve == true`) AND no explicit
    /// `expected_secret` is configured. A `&&` ↔ `||` mutation would
    /// generate a secret in either non-headless mode (defeating the
    /// auth contract) or whenever an explicit secret is set (overwriting
    /// the operator's configured value).
    #[test]
    fn finalize_handler_generates_secret_only_in_auto_approve_and_no_explicit_secret() {
        // (auto_approve=true, expected_secret=None) → random secret generated.
        let keyring = Arc::new(Mutex::new(Keyring::new()));
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None);
        let config = ServerConfig {
            auto_approve: true,
            expected_secret: None,
            ..ServerConfig::default()
        };
        let (_h, sec) =
            finalize_handler(handler, &config, &["wss://relay.example.com".to_string()]).unwrap();
        let generated = sec.expect("headless without explicit secret must generate one");
        assert!(
            !generated.is_empty(),
            "generated bunker secret must not be empty"
        );

        // (auto_approve=false, expected_secret=None) → no secret.
        let keyring = Arc::new(Mutex::new(Keyring::new()));
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None);
        let config = ServerConfig {
            auto_approve: false,
            expected_secret: None,
            ..ServerConfig::default()
        };
        let (_h, sec) =
            finalize_handler(handler, &config, &["wss://relay.example.com".to_string()]).unwrap();
        assert!(
            sec.is_none(),
            "interactive mode without explicit secret must NOT generate one"
        );

        // (auto_approve=true, expected_secret=Some(...)) → operator's value,
        // not a generated one. Already covered by
        // `expected_secret_surfaces_in_bunker_secret` but pin again here for
        // the `&&` mutation's specific case: the random-generation branch
        // must NOT fire when an explicit secret is configured.
        let keyring = Arc::new(Mutex::new(Keyring::new()));
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None);
        let config = ServerConfig {
            auto_approve: true,
            expected_secret: Some("operator-supplied".to_string()),
            ..ServerConfig::default()
        };
        let (_h, sec) =
            finalize_handler(handler, &config, &["wss://relay.example.com".to_string()]).unwrap();
        assert_eq!(
            sec.expect("explicit secret should surface").as_str(),
            "operator-supplied"
        );
    }

    fn an_event_notification() -> RelayPoolNotification {
        let event = EventBuilder::text_note("x")
            .sign_with_keys(&Keys::generate())
            .unwrap();
        RelayPoolNotification::Event {
            relay_url: RelayUrl::parse("wss://relay.example").unwrap(),
            subscription_id: SubscriptionId::new("nip46"),
            event: Box::new(event),
        }
    }

    /// A receiver that falls behind keeps serving rather than stopping. The
    /// channel here holds two, and six are sent before the loop reads any, so
    /// its first read is `Lagged`. The old loop ended on that read and
    /// returned as if shut down, handling nothing; this one logs the loss,
    /// handles what is still held, and stops only on the real shutdown.
    #[tokio::test]
    async fn a_lagged_receiver_keeps_serving_until_the_real_shutdown() {
        let (tx, rx) = tokio::sync::broadcast::channel(2);
        for _ in 0..5 {
            tx.send(an_event_notification()).unwrap();
        }
        tx.send(RelayPoolNotification::Shutdown).unwrap();

        let handled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&handled);
        let ended = drive_notifications(rx, move |_| {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        })
        .await;

        assert_eq!(ended, NotificationsEnded::Shutdown);
        assert_eq!(
            handled.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the event still held after the lag is handled, not dropped with it"
        );
    }

    /// A stream that ends with no shutdown is reported as such, so a caller can
    /// tell it from a stop it asked for instead of going quietly deaf.
    #[tokio::test]
    async fn a_stream_closing_without_a_shutdown_is_not_a_clean_stop() {
        let (tx, rx) = tokio::sync::broadcast::channel(4);
        tx.send(an_event_notification()).unwrap();
        drop(tx);

        let ended = drive_notifications(rx, |_| async {}).await;
        assert_eq!(ended, NotificationsEnded::Closed);
    }

    #[tokio::test]
    async fn a_shutdown_is_a_clean_stop() {
        let (tx, rx) = tokio::sync::broadcast::channel(4);
        tx.send(an_event_notification()).unwrap();
        tx.send(RelayPoolNotification::Shutdown).unwrap();

        let ended = drive_notifications(rx, |_| async {}).await;
        assert_eq!(ended, NotificationsEnded::Shutdown);
    }
}
