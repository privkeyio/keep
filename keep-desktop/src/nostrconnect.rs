// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::{Arc, Mutex};

use iced::Task;
use keep_nip46::NostrConnectRequest;
use nostr_sdk::prelude::*;

use keep_core::relay::{normalize_relay_url, validate_relay_url};

use crate::app::{App, ToastKind, RECONNECT_BASE_MS, RECONNECT_MAX_ATTEMPTS, RECONNECT_MAX_MS};
use crate::bunker_service::{extract_keyring, BunkerSetup, DesktopCallbacks};
use crate::message::Message;
use crate::screen::bunker::PendingApprovalDisplay;
use crate::screen::Screen;

impl App {
    pub(crate) fn process_pending_nostrconnect(
        &mut self,
        request: NostrConnectRequest,
    ) -> Task<Message> {
        let display = PendingApprovalDisplay {
            app_pubkey: request.client_pubkey.to_hex(),
            app_name: request.name.clone().unwrap_or_else(|| "Unknown App".into()),
            method: "connect".into(),
            event_kind: None,
            event_content: request.url.clone(),
            requested_permissions: request.perms.clone(),
        };
        self.bunker_pending_approval = Some(display);

        self.nostrconnect_pending = Some(request);

        self.screen = Screen::Bunker(Box::new(self.create_bunker_screen()));
        Task::none()
    }

    pub(crate) fn handle_nostrconnect_approve(&mut self) -> Task<Message> {
        let Some(request) = self.nostrconnect_pending.take() else {
            return Task::none();
        };

        self.bunker_pending_approval = None;
        if let Screen::Bunker(s) = &mut self.screen {
            s.pending_approval = None;
        }

        if self.bunker.is_some() {
            self.set_toast(
                "Bunker already running; stop it first".into(),
                ToastKind::Error,
            );
            return Task::none();
        }

        let valid_relays: Vec<String> = request
            .relays
            .iter()
            .filter(|url| {
                if let Err(e) = validate_relay_url(url) {
                    tracing::warn!(url, "skipping invalid nostrconnect relay: {e}");
                    false
                } else {
                    true
                }
            })
            .map(|url| normalize_relay_url(url))
            .collect();

        if valid_relays.is_empty() {
            if let Screen::Bunker(s) = &mut self.screen {
                s.starting = false;
                s.error = Some("No valid relay URLs in nostrconnect request".into());
            }
            return Task::none();
        }

        self.bunker_relays = valid_relays.clone();
        if let Screen::Bunker(s) = &mut self.screen {
            s.relays = valid_relays.clone();
            s.starting = true;
            s.error = None;
        }

        let keep_arc = self.keep.clone();
        let setup_arc = Arc::new(Mutex::new(None));
        self.bunker_pending_setup = Some(setup_arc.clone());
        let proxy = self.proxy_addr();

        Task::perform(
            async move {
                let keyring = tokio::task::spawn_blocking(move || extract_keyring(&keep_arc))
                    .await
                    .map_err(|_| "Background task failed".to_string())??;

                let (event_tx, event_rx) = std::sync::mpsc::channel();
                let callbacks: Arc<dyn keep_nip46::types::ServerCallbacks> =
                    Arc::new(DesktopCallbacks { tx: event_tx });

                let relay_urls = valid_relays;
                let config = keep_nip46::ServerConfig {
                    rate_limit: Some(keep_nip46::RateLimitConfig::conservative()),
                    expected_secret: Some(request.secret.clone()),
                    ..Default::default()
                };
                let mut server = keep_nip46::Server::new_with_config_and_proxy(
                    keyring,
                    None,
                    None,
                    &relay_urls,
                    Some(callbacks),
                    config,
                    proxy,
                )
                .await
                .map_err(|e| format!("Failed to start bunker: {e}"))?;

                let handler = server.handler();
                let url = server.bunker_url();

                server
                    .start()
                    .await
                    .map_err(|e| format!("Failed to connect to relays: {e}"))?;

                let app_name = request
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("App {}", &request.client_pubkey.to_hex()[..8]));
                handler
                    .register_client(request.client_pubkey, app_name, request.perms.as_deref())
                    .await
                    .map_err(|e| format!("Failed to register client: {e}"))?;

                send_nostrconnect_response(&server, &request)
                    .await
                    .map_err(|e| format!("Failed to send connect response: {e}"))?;

                let handle = tokio::spawn(async move {
                    let mut attempts = 0u32;
                    loop {
                        match server.run().await {
                            Ok(()) => break,
                            Err(e) => {
                                attempts += 1;
                                if attempts > RECONNECT_MAX_ATTEMPTS {
                                    tracing::error!(error = %e, "bunker server giving up after {RECONNECT_MAX_ATTEMPTS} reconnect attempts");
                                    break;
                                }
                                let base_ms =
                                    (RECONNECT_BASE_MS << attempts.min(7)).min(RECONNECT_MAX_MS);
                                let jitter_ms = rand::Rng::gen_range(
                                    &mut rand::rng(),
                                    0..=base_ms / 2,
                                );
                                let delay_ms = base_ms + jitter_ms;
                                tracing::error!(error = %e, attempt = attempts, "bunker server error, reconnecting in {delay_ms}ms");
                                tokio::time::sleep(std::time::Duration::from_millis(delay_ms))
                                    .await;
                            }
                        }
                    }
                });

                let mut guard = match setup_arc.lock() {
                    Ok(g) => g,
                    Err(e) => e.into_inner(),
                };
                *guard = Some(BunkerSetup {
                    handler,
                    event_rx,
                    handle,
                });

                Ok(url)
            },
            Message::BunkerStartResult,
        )
    }

    pub(crate) fn handle_nostrconnect_reject(&mut self) -> Task<Message> {
        self.nostrconnect_pending = None;
        self.bunker_pending_approval = None;
        if let Screen::Bunker(s) = &mut self.screen {
            s.pending_approval = None;
        }
        self.set_toast("Connection request rejected".into(), ToastKind::Success);
        Task::none()
    }
}

async fn send_nostrconnect_response(
    server: &keep_nip46::Server,
    request: &NostrConnectRequest,
) -> Result<(), String> {
    let keys = Keys::new(server.transport_secret());

    let response = serde_json::json!({
        "id": hex::encode(keep_core::crypto::random_bytes::<16>()),
        "result": keys.public_key().to_hex(),
    });
    let response_json =
        serde_json::to_string(&response).map_err(|e| format!("serialization: {e}"))?;

    let encrypted = nip44::encrypt(
        keys.secret_key(),
        &request.client_pubkey,
        &response_json,
        nip44::Version::V2,
    )
    .map_err(|e| format!("encryption: {e}"))?;

    let event = EventBuilder::new(Kind::NostrConnect, encrypted)
        .tag(Tag::public_key(request.client_pubkey))
        .sign_with_keys(&keys)
        .map_err(|e| format!("signing: {e}"))?;

    tracing::debug!(
        client_pubkey = %request.client_pubkey.to_hex(),
        signer_pubkey = %keys.public_key().to_hex(),
        "sending nostrconnect response"
    );

    server
        .send_event(&event)
        .await
        .map_err(|e| format!("relay send: {e}"))
}
