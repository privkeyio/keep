// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::sync::mpsc::Sender;
use std::sync::Arc;

use nostr_sdk::prelude::*;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use keep_core::error::{CryptoError, KeepError, NetworkError, Result, StorageError};
use keep_core::keyring::Keyring;

use crate::bunker::generate_bunker_url;
use crate::signer::{AuditLog, FrostSigner, NetworkFrostSigner, PermissionManager, SignerHandler};
use crate::tui::{LogEntry, TuiEvent};

const MAX_EVENT_JSON_SIZE: usize = 64 * 1024;

pub struct Server {
    keys: Keys,
    relay_url: String,
    client: Client,
    handler: Arc<SignerHandler>,
    running: bool,
    tui_tx: Option<Sender<TuiEvent>>,
}

impl Server {
    pub async fn new(
        keyring: Arc<Mutex<Keyring>>,
        relay_url: &str,
        tui_tx: Option<Sender<TuiEvent>>,
    ) -> Result<Self> {
        Self::new_with_frost(keyring, None, None, relay_url, tui_tx).await
    }

    pub async fn new_with_frost(
        keyring: Arc<Mutex<Keyring>>,
        frost_signer: Option<FrostSigner>,
        transport_secret: Option<[u8; 32]>,
        relay_url: &str,
        tui_tx: Option<Sender<TuiEvent>>,
    ) -> Result<Self> {
        let keys = if let Some(secret_bytes) = transport_secret {
            let secret = SecretKey::from_slice(&secret_bytes)
                .map_err(|e| CryptoError::invalid_key(format!("transport key: {}", e)))?;
            Keys::new(secret)
        } else {
            let kr = keyring.lock().await;
            let slot = kr
                .get_primary()
                .ok_or_else(|| KeepError::KeyNotFound("no signing key".into()))?;

            let secret = SecretKey::from_slice(slot.expose_secret())
                .map_err(|e| CryptoError::invalid_key(format!("secret key: {}", e)))?;

            Keys::new(secret)
        };

        let client = Client::new(keys.clone());

        client
            .add_relay(relay_url)
            .await
            .map_err(|e| NetworkError::relay(e.to_string()))?;

        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(10000)));
        let mut handler = SignerHandler::new(keyring, permissions, audit, tui_tx.clone());
        if let Some(frost) = frost_signer {
            handler = handler.with_frost_signer(frost);
        }

        Ok(Self {
            keys,
            relay_url: relay_url.to_string(),
            client,
            handler: Arc::new(handler),
            running: false,
            tui_tx,
        })
    }

    pub async fn new_frost(
        frost_signer: FrostSigner,
        transport_secret: [u8; 32],
        relay_url: &str,
        tui_tx: Option<Sender<TuiEvent>>,
    ) -> Result<Self> {
        let keyring = Arc::new(Mutex::new(Keyring::new()));
        Self::new_with_frost(
            keyring,
            Some(frost_signer),
            Some(transport_secret),
            relay_url,
            tui_tx,
        )
        .await
    }

    pub async fn new_network_frost(
        network_signer: NetworkFrostSigner,
        transport_secret: [u8; 32],
        relay_url: &str,
        tui_tx: Option<Sender<TuiEvent>>,
    ) -> Result<Self> {
        let secret = SecretKey::from_slice(&transport_secret)
            .map_err(|e| CryptoError::invalid_key(format!("transport key: {}", e)))?;
        let keys = Keys::new(secret);

        let client = Client::new(keys.clone());

        client
            .add_relay(relay_url)
            .await
            .map_err(|e| NetworkError::relay(e.to_string()))?;

        let keyring = Arc::new(Mutex::new(Keyring::new()));
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(10000)));
        let handler = SignerHandler::new(keyring, permissions, audit, tui_tx.clone())
            .with_network_frost_signer(network_signer);

        Ok(Self {
            keys,
            relay_url: relay_url.to_string(),
            client,
            handler: Arc::new(handler),
            running: false,
            tui_tx,
        })
    }

    pub fn bunker_url(&self) -> String {
        generate_bunker_url(&self.keys.public_key(), &self.relay_url, None)
    }

    pub fn pubkey(&self) -> PublicKey {
        self.keys.public_key()
    }

    #[tracing::instrument(skip(self))]
    pub async fn start(&mut self) -> Result<()> {
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

        let bunker_url = self.bunker_url();
        info!(bunker_url, "listening for NIP-46 requests");

        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        self.start().await?;

        let handler = self.handler.clone();
        let keys = self.keys.clone();
        let client = self.client.clone();
        let tui_tx = self.tui_tx.clone();

        self.client
            .handle_notifications(|notification| {
                let handler = handler.clone();
                let keys = keys.clone();
                let client = client.clone();
                let tui_tx = tui_tx.clone();

                async move {
                    if let RelayPoolNotification::Event { event, .. } = notification {
                        if event.kind == Kind::NostrConnect {
                            if let Err(e) = Self::handle_nip46_event(
                                &handler,
                                &keys,
                                &client,
                                &event,
                                tui_tx.as_ref(),
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
            .await
            .map_err(|e| NetworkError::relay(format!("notification handler: {}", e)))?;

        Ok(())
    }

    async fn handle_nip46_event(
        handler: &SignerHandler,
        keys: &Keys,
        client: &Client,
        event: &Event,
        tui_tx: Option<&Sender<TuiEvent>>,
    ) -> Result<()> {
        let app_pubkey = event.pubkey;
        let app_id = &app_pubkey.to_hex()[..8];

        let decrypted = nip44::decrypt(keys.secret_key(), &app_pubkey, &event.content)
            .map_err(|e| CryptoError::decryption(e.to_string()))?;

        let request: Nip46Request = serde_json::from_str(&decrypted)
            .map_err(|e| StorageError::invalid_format(format!("NIP-46 request: {}", e)))?;

        debug!(method = %request.method, app_id, "NIP-46 request");

        let method = request.method.clone();
        let response =
            Self::dispatch_request(handler, keys.public_key(), app_pubkey, request, tui_tx).await;

        let success = response.error.is_none();
        if let Some(tx) = tui_tx {
            let detail = response.error.as_deref();
            let _ = tx.send(TuiEvent::Log(
                LogEntry::new(app_id, &method, success).with_detail(detail.unwrap_or("")),
            ));
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
            .map_err(|e| CryptoError::invalid_signature(format!("sign response: {}", e)))?;

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
        _tui_tx: Option<&Sender<TuiEvent>>,
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
                    Ok(Some(s)) => Nip46Response::ok(id, &s),
                    Ok(None) => Nip46Response::ok(id, "ack"),
                    Err(e) => {
                        warn!(error = %e, "connect failed");
                        Nip46Response::error(id, sanitize_error_for_client(&e))
                    }
                }
            }
            "get_public_key" => match handler.handle_get_public_key(app_pubkey).await {
                Ok(pk) => Nip46Response::ok(id, &pk.to_hex()),
                Err(e) => {
                    warn!(error = %e, "get_public_key failed");
                    Nip46Response::error(id, sanitize_error_for_client(&e))
                }
            },
            "sign_event" => {
                let event_json = match request.params.first() {
                    Some(json) => json,
                    None => return Nip46Response::error(id, "Missing event parameter"),
                };

                if event_json.len() > MAX_EVENT_JSON_SIZE {
                    return Nip46Response::error(id, "Event JSON too large");
                }

                let partial: PartialEvent = match serde_json::from_str(event_json) {
                    Ok(p) => p,
                    Err(e) => return Nip46Response::error(id, &format!("Invalid event: {}", e)),
                };

                let tags: Vec<Tag> = partial
                    .tags
                    .into_iter()
                    .filter_map(|t| Tag::parse(&t).ok())
                    .collect();

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
                        Nip46Response::error(id, sanitize_error_for_client(&e))
                    }
                }
            }
            "nip44_encrypt" => {
                if request.params.len() < 2 {
                    return Nip46Response::error(id, "Missing parameters");
                }
                let recipient = match PublicKey::from_hex(&request.params[0]) {
                    Ok(pk) => pk,
                    Err(_) => return Nip46Response::error(id, "Invalid pubkey"),
                };
                match handler
                    .handle_nip44_encrypt(app_pubkey, recipient, &request.params[1])
                    .await
                {
                    Ok(ct) => Nip46Response::ok(id, &ct),
                    Err(e) => {
                        warn!(error = %e, "nip44_encrypt failed");
                        Nip46Response::error(id, sanitize_error_for_client(&e))
                    }
                }
            }
            "nip44_decrypt" => {
                if request.params.len() < 2 {
                    return Nip46Response::error(id, "Missing parameters");
                }
                let sender = match PublicKey::from_hex(&request.params[0]) {
                    Ok(pk) => pk,
                    Err(_) => return Nip46Response::error(id, "Invalid pubkey"),
                };
                match handler
                    .handle_nip44_decrypt(app_pubkey, sender, &request.params[1])
                    .await
                {
                    Ok(pt) => Nip46Response::ok(id, &pt),
                    Err(e) => {
                        warn!(error = %e, "nip44_decrypt failed");
                        Nip46Response::error(id, sanitize_error_for_client(&e))
                    }
                }
            }
            "nip04_encrypt" => {
                if request.params.len() < 2 {
                    return Nip46Response::error(id, "Missing parameters");
                }
                let recipient = match PublicKey::from_hex(&request.params[0]) {
                    Ok(pk) => pk,
                    Err(_) => return Nip46Response::error(id, "Invalid pubkey"),
                };
                match handler
                    .handle_nip04_encrypt(app_pubkey, recipient, &request.params[1])
                    .await
                {
                    Ok(ct) => Nip46Response::ok(id, &ct),
                    Err(e) => {
                        warn!(error = %e, "nip04_encrypt failed");
                        Nip46Response::error(id, sanitize_error_for_client(&e))
                    }
                }
            }
            "nip04_decrypt" => {
                if request.params.len() < 2 {
                    return Nip46Response::error(id, "Missing parameters");
                }
                let sender = match PublicKey::from_hex(&request.params[0]) {
                    Ok(pk) => pk,
                    Err(_) => return Nip46Response::error(id, "Invalid pubkey"),
                };
                match handler
                    .handle_nip04_decrypt(app_pubkey, sender, &request.params[1])
                    .await
                {
                    Ok(pt) => Nip46Response::ok(id, &pt),
                    Err(e) => {
                        warn!(error = %e, "nip04_decrypt failed");
                        Nip46Response::error(id, sanitize_error_for_client(&e))
                    }
                }
            }
            "ping" => Nip46Response::ok(id, "pong"),
            _ => Nip46Response::error(id, &format!("Unknown method: {}", request.method)),
        }
    }

    #[allow(dead_code)]
    pub async fn stop(&mut self) {
        self.running = false;
        self.client.disconnect().await;
    }
}

#[derive(Debug, serde::Deserialize)]
struct Nip46Request {
    id: String,
    method: String,
    #[serde(default)]
    params: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct PartialEvent {
    kind: u16,
    content: String,
    #[serde(default)]
    tags: Vec<Vec<String>>,
    created_at: i64,
}

#[derive(Debug, serde::Serialize)]
struct Nip46Response {
    id: String,
    result: Option<String>,
    error: Option<String>,
}

impl Nip46Response {
    fn ok(id: String, result: &str) -> Self {
        Self {
            id,
            result: Some(result.to_string()),
            error: None,
        }
    }

    fn error(id: String, error: &str) -> Self {
        Self {
            id,
            result: None,
            error: Some(error.to_string()),
        }
    }
}

fn sanitize_error_for_client(e: &KeepError) -> &'static str {
    match e {
        KeepError::InvalidPassword => "Authentication failed",
        KeepError::RateLimited(_) => "Rate limited",
        KeepError::DecryptionFailed | KeepError::RotationFailed(_) => "Operation failed",
        KeepError::KeyNotFound(_) => "Key not found",
        KeepError::KeyAlreadyExists(_) => "Key already exists",
        KeepError::InvalidNsec | KeepError::InvalidNpub => "Invalid key format",
        KeepError::KeyringFull(_) => "Storage limit reached",
        KeepError::Locked => "Signer locked",
        KeepError::AlreadyExists(_) | KeepError::NotFound(_) => "Resource error",
        KeepError::InvalidNetwork(_) => "Invalid network",
        KeepError::Encryption(_) | KeepError::CryptoErr(_) => "Cryptographic operation failed",
        KeepError::Database(_) | KeepError::Migration(_) | KeepError::StorageErr(_) => {
            "Storage error"
        }
        KeepError::HomeNotFound | KeepError::Config(_) => "Configuration error",
        KeepError::PermissionDenied(_) => "Permission denied",
        KeepError::UserRejected => "User rejected",
        KeepError::InvalidInput(_) => "Invalid input",
        KeepError::NotImplemented(_) => "Not supported",
        KeepError::Runtime(_) => "Internal error",
        KeepError::Frost(_) | KeepError::FrostErr(_) => "Signing protocol error",
        KeepError::NetworkErr(_) => "Network error",
        KeepError::Serialization(_) => "Data format error",
        KeepError::Io(_) => "IO error",
        _ => "Unknown error",
    }
}
