// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
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
use crate::permissions::PermissionManager;
use crate::rate_limit::RateLimitConfig;
use crate::types::{LogEvent, Nip46Request, Nip46Response, PartialEvent, ServerCallbacks};

pub struct ServerConfig {
    pub max_event_json_size: usize,
    pub audit_log_capacity: usize,
    pub rate_limit: Option<RateLimitConfig>,
    pub auto_approve: bool,
    pub expected_secret: Option<String>,
    pub kill_switch: Option<Arc<AtomicBool>>,
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
        }
    }
}

pub struct Server {
    keys: Keys,
    relay_url: String,
    relay_urls: Vec<String>,
    client: Client,
    handler: Arc<SignerHandler>,
    running: bool,
    callbacks: Option<Arc<dyn ServerCallbacks>>,
    config: ServerConfig,
    bunker_secret: Option<Zeroizing<String>>,
}

async fn add_relays(client: &Client, relay_urls: &[String]) -> Result<()> {
    for relay_url in relay_urls {
        client
            .add_relay(relay_url)
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

fn finalize_handler(
    mut handler: SignerHandler,
    config: &ServerConfig,
    relay_urls: &[String],
) -> (SignerHandler, Option<Zeroizing<String>>) {
    handler = handler.with_relay_urls(relay_urls.to_vec());
    if let Some(ref rl_config) = config.rate_limit {
        handler = handler.with_rate_limit(rl_config.clone());
    }
    if let Some(ref ks) = config.kill_switch {
        handler = handler.with_kill_switch(ks.clone());
    }
    let bunker_secret = if config.auto_approve && config.expected_secret.is_none() {
        let secret = hex::encode(keep_core::crypto::random_bytes::<16>());
        warn!("headless mode: bunker secret required for authentication");
        handler = handler.with_expected_secret(secret.clone());
        Some(Zeroizing::new(secret))
    } else if let Some(ref secret) = config.expected_secret {
        handler = handler.with_expected_secret(secret.clone());
        None
    } else {
        None
    };
    (handler, bunker_secret)
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
            client,
            handler: Arc::new(handler),
            running: false,
            callbacks,
            config,
            bunker_secret,
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

        let client = match proxy {
            Some(addr) => {
                let connection = Connection::new().proxy(addr).target(ConnectionTarget::All);
                let opts = ClientOptions::new().connection(connection);
                Client::builder().signer(keys.clone()).opts(opts).build()
            }
            None => Client::new(keys.clone()),
        };
        add_relays(&client, relay_urls).await?;

        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(config.audit_log_capacity)));
        let mut handler = SignerHandler::new(keyring, permissions, audit, callbacks.clone())
            .with_auto_approve(config.auto_approve);
        if let Some(frost) = frost_signer {
            handler = handler.with_frost_signer(frost);
        }
        let (handler, bunker_secret) = finalize_handler(handler, &config, relay_urls);

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

        let client = match proxy {
            Some(addr) => {
                let connection = Connection::new().proxy(addr).target(ConnectionTarget::All);
                let opts = ClientOptions::new().connection(connection);
                Client::builder().signer(keys.clone()).opts(opts).build()
            }
            None => Client::new(keys.clone()),
        };
        add_relays(&client, relay_urls).await?;

        let keyring = Arc::new(Mutex::new(Keyring::new()));
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(config.audit_log_capacity)));
        let handler = SignerHandler::new(keyring, permissions, audit, callbacks.clone())
            .with_network_frost_signer(network_signer)
            .with_auto_approve(config.auto_approve);
        let (handler, bunker_secret) = finalize_handler(handler, &config, relay_urls);

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

    pub async fn send_event(&self, event: &Event) -> Result<()> {
        self.client
            .send_event(event)
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

        let filter = Filter::new()
            .kind(Kind::NostrConnect)
            .pubkey(self.keys.public_key());

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
        let callbacks = self.callbacks.clone();
        let max_event_json_size = self.config.max_event_json_size;

        let result = self
            .client
            .handle_notifications(|notification| {
                let handler = handler.clone();
                let keys = keys.clone();
                let client = client.clone();
                let callbacks = callbacks.clone();

                async move {
                    if let RelayPoolNotification::Event { event, .. } = notification {
                        if event.kind == Kind::NostrConnect {
                            if let Err(e) = Self::handle_nip46_event(
                                &handler,
                                &keys,
                                &client,
                                &event,
                                callbacks.as_deref(),
                                max_event_json_size,
                            )
                            .await
                            {
                                warn!(error = %e, "error handling NIP-46 event");
                            }
                        }
                    }
                    Ok(false)
                }
            })
            .await;

        self.running = false;
        result.map_err(|e| NetworkError::relay(format!("notification handler: {e}")))?;

        Ok(())
    }

    async fn handle_nip46_event(
        handler: &SignerHandler,
        keys: &Keys,
        client: &Client,
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
        let response = Self::dispatch_request(
            handler,
            keys.public_key(),
            app_pubkey,
            request,
            max_event_json_size,
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

            if method == "connect" && success {
                cb.on_connect(&app_pubkey.to_hex(), &format!("App {app_id}"));
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
            .tag(Tag::public_key(app_pubkey))
            .sign_with_keys(keys)
            .map_err(|e| CryptoError::invalid_signature(format!("sign response: {e}")))?;

        if let Err(e) = client.send_event(&response_event).await {
            error!(error = %e, "failed to send response");
        }

        Ok(())
    }

    async fn dispatch_request(
        handler: &SignerHandler,
        user_pubkey: PublicKey,
        app_pubkey: PublicKey,
        request: Nip46Request,
        max_event_json_size: usize,
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
                    Ok(()) => Nip46Response::ok(id, "ack"),
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
                    _ => unreachable!(),
                };
                match result {
                    Ok(data) => Nip46Response::ok(id, &data),
                    Err(e) => {
                        warn!(error = %e, method = %request.method, "encryption method failed");
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

    pub fn handler(&self) -> Arc<SignerHandler> {
        self.handler.clone()
    }

    #[allow(dead_code)]
    pub async fn stop(&mut self) {
        self.handler.revoke_session_apps().await;
        self.running = false;
        self.client.disconnect().await;
    }
}
