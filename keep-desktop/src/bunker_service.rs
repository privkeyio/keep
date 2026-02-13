// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iced::Task;
use keep_core::relay::{normalize_relay_url, validate_relay_url};
use zeroize::Zeroizing;

use crate::app::{
    lock_keep, App, ToastKind, BUNKER_APPROVAL_TIMEOUT, CLIPBOARD_CLEAR_SECS,
    MAX_BUNKER_LOG_ENTRIES,
};
use crate::message::Message;
use crate::screen::bunker::{
    BunkerScreen, ConnectedClient, DurationChoice, LogDisplayEntry, PendingApprovalDisplay,
    DURATION_OPTIONS,
};
use crate::screen::Screen;

pub(crate) enum BunkerEvent {
    Log {
        app: String,
        action: String,
        success: bool,
    },
    Approval {
        display: PendingApprovalDisplay,
        response_tx: std::sync::mpsc::Sender<bool>,
    },
    Connected {
        pubkey: String,
        name: String,
    },
}

pub(crate) struct DesktopCallbacks {
    pub tx: std::sync::mpsc::Sender<BunkerEvent>,
}

impl keep_nip46::types::ServerCallbacks for DesktopCallbacks {
    fn on_log(&self, event: keep_nip46::types::LogEvent) {
        let _ = self.tx.send(BunkerEvent::Log {
            app: event.app,
            action: event.action,
            success: event.success,
        });
    }

    fn request_approval(&self, request: keep_nip46::types::ApprovalRequest) -> bool {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        let display = PendingApprovalDisplay {
            app_pubkey: request.app_pubkey.to_hex(),
            app_name: request.app_name,
            method: request.method,
            event_kind: request.event_kind.map(|k| u32::from(k.as_u16())),
            event_content: request.event_content,
            requested_permissions: request.requested_permissions,
        };
        if self
            .tx
            .send(BunkerEvent::Approval {
                display,
                response_tx,
            })
            .is_err()
        {
            return false;
        }
        tokio::task::block_in_place(|| {
            response_rx
                .recv_timeout(BUNKER_APPROVAL_TIMEOUT)
                .unwrap_or(false)
        })
    }

    fn on_connect(&self, pubkey: &str, name: &str) {
        let _ = self.tx.send(BunkerEvent::Connected {
            pubkey: pubkey.to_string(),
            name: name.to_string(),
        });
    }
}

pub(crate) struct BunkerSetup {
    pub handler: Arc<keep_nip46::SignerHandler>,
    pub event_rx: std::sync::mpsc::Receiver<BunkerEvent>,
    pub handle: tokio::task::JoinHandle<()>,
}

pub(crate) struct RunningBunker {
    pub url: String,
    pub handler: Arc<keep_nip46::SignerHandler>,
    pub event_rx: Arc<Mutex<std::sync::mpsc::Receiver<BunkerEvent>>>,
    pub handle: tokio::task::JoinHandle<()>,
    pub clients: Vec<ConnectedClient>,
    pub log: VecDeque<LogDisplayEntry>,
}

impl App {
    pub(crate) fn handle_bunker_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::BunkerRelayInputChanged(input) => {
                if let Screen::Bunker(s) = &mut self.screen {
                    s.relay_input = input;
                }
                Task::none()
            }
            Message::BunkerAddRelay => {
                if let Screen::Bunker(s) = &mut self.screen {
                    let url = s.relay_input.trim().to_string();
                    if let Err(e) = validate_relay_url(&url) {
                        self.set_toast(format!("Invalid relay URL: {e}"), ToastKind::Error);
                        return Task::none();
                    }
                    let relay = normalize_relay_url(&url);
                    if s.relays.contains(&relay) || self.bunker_relays.contains(&relay) {
                        return Task::none();
                    }
                    if s.relays.len() < 5 {
                        s.relays.push(relay.clone());
                        self.bunker_relays.push(relay);
                        s.relay_input.clear();
                    }
                }
                Task::none()
            }
            Message::BunkerRemoveRelay(i) => {
                if let Screen::Bunker(s) = &mut self.screen {
                    if i < s.relays.len() {
                        s.relays.remove(i);
                        self.bunker_relays = s.relays.clone();
                    }
                }
                Task::none()
            }
            Message::BunkerStart => self.handle_bunker_start(),
            Message::BunkerStartResult(result) => self.handle_bunker_start_result(result),
            Message::BunkerStop => {
                self.stop_bunker();
                if let Screen::Bunker(s) = &mut self.screen {
                    s.running = false;
                    s.starting = false;
                    s.url = None;
                    s.clients.clear();
                    s.pending_approval = None;
                }
                self.set_toast("Bunker stopped".into(), ToastKind::Success);
                Task::none()
            }
            Message::BunkerApprove | Message::BunkerReject => {
                let approved = matches!(message, Message::BunkerApprove);

                let duration_choice = if let Screen::Bunker(s) = &self.screen {
                    DURATION_OPTIONS
                        .get(s.approval_duration)
                        .map(|(_, d)| *d)
                        .unwrap_or(DurationChoice::JustThisTime)
                } else {
                    DurationChoice::JustThisTime
                };

                let app_pubkey = self
                    .bunker_pending_approval
                    .as_ref()
                    .map(|a| a.app_pubkey.clone());

                if let Some(tx) = self.bunker_approval_tx.take() {
                    let _ = tx.send(approved);
                }
                self.bunker_pending_approval = None;
                if let Screen::Bunker(s) = &mut self.screen {
                    s.pending_approval = None;
                    s.approval_duration = 0; // Reset to JustThisTime
                }

                if approved {
                    if let (Some(hex), Some(ref bunker)) = (app_pubkey, &self.bunker) {
                        let handler = bunker.handler.clone();
                        let nip46_duration = match duration_choice {
                            DurationChoice::JustThisTime => keep_nip46::PermissionDuration::Session,
                            DurationChoice::Minutes(m) => {
                                keep_nip46::PermissionDuration::Seconds(m * 60)
                            }
                            DurationChoice::Forever => keep_nip46::PermissionDuration::Forever,
                        };
                        return Task::perform(
                            async move {
                                if let Ok(pk) = nostr_sdk::PublicKey::from_hex(&hex) {
                                    handler.update_client_duration(&pk, nip46_duration).await;
                                }
                                Ok::<(), String>(())
                            },
                            Message::BunkerPermissionUpdated,
                        );
                    }
                }
                Task::none()
            }
            Message::BunkerRevokeClient(i) => {
                let pubkey_hex = if let Screen::Bunker(s) = &self.screen {
                    s.clients.get(i).map(|c| c.pubkey.clone())
                } else {
                    None
                };
                if let (Some(hex), Some(ref bunker)) = (pubkey_hex, &self.bunker) {
                    let handler = bunker.handler.clone();
                    return Task::perform(
                        async move {
                            if let Ok(pk) = nostr_sdk::PublicKey::from_hex(&hex) {
                                handler.revoke_client(&pk).await;
                            }
                            Ok::<(), String>(())
                        },
                        Message::BunkerRevokeResult,
                    );
                }
                Task::none()
            }
            Message::BunkerRevokeResult(result) => {
                if let Err(e) = result {
                    if let Screen::Bunker(s) = &mut self.screen {
                        s.error = Some(e);
                    }
                }
                self.sync_bunker_clients()
            }
            Message::BunkerClientsLoaded(clients) => {
                if let Some(ref mut bunker) = self.bunker {
                    bunker.clients = clients.clone();
                }
                if let Screen::Bunker(s) = &mut self.screen {
                    s.clients = clients;
                    s.revoke_all_confirm = false;
                }
                Task::none()
            }
            Message::BunkerConfirmRevokeAll => {
                if let Screen::Bunker(s) = &mut self.screen {
                    s.revoke_all_confirm = true;
                }
                Task::none()
            }
            Message::BunkerCancelRevokeAll => {
                if let Screen::Bunker(s) = &mut self.screen {
                    s.revoke_all_confirm = false;
                }
                Task::none()
            }
            Message::BunkerRevokeAll => {
                if let Some(ref bunker) = self.bunker {
                    let handler = bunker.handler.clone();
                    return Task::perform(
                        async move {
                            handler.revoke_all_clients().await;
                            Ok::<(), String>(())
                        },
                        Message::BunkerRevokeResult,
                    );
                }
                Task::none()
            }
            Message::BunkerCopyUrl => {
                if let Some(ref bunker) = self.bunker {
                    self.clipboard_clear_at =
                        Some(Instant::now() + Duration::from_secs(CLIPBOARD_CLEAR_SECS));
                    return iced::clipboard::write(bunker.url.clone());
                }
                Task::none()
            }
            Message::BunkerToggleClient(i) => {
                if let Screen::Bunker(s) = &mut self.screen {
                    s.expanded_client = if s.expanded_client == Some(i) {
                        None
                    } else {
                        Some(i)
                    };
                }
                Task::none()
            }
            Message::BunkerSetApprovalDuration(i) => {
                if let Screen::Bunker(s) = &mut self.screen {
                    s.approval_duration = i;
                }
                Task::none()
            }
            Message::BunkerTogglePermission(client_idx, flag) => {
                let pubkey_hex = if let Screen::Bunker(s) = &self.screen {
                    s.clients
                        .get(client_idx)
                        .map(|c| (c.pubkey.clone(), c.permissions))
                } else {
                    None
                };
                if let (Some((hex, current_perms)), Some(ref bunker)) = (pubkey_hex, &self.bunker) {
                    let new_perms = current_perms ^ flag;
                    let handler = bunker.handler.clone();
                    return Task::perform(
                        async move {
                            if let Ok(pk) = nostr_sdk::PublicKey::from_hex(&hex) {
                                handler
                                    .update_client_permissions(
                                        &pk,
                                        keep_nip46::Permission::from_bits_truncate(new_perms),
                                    )
                                    .await;
                            }
                            Ok::<(), String>(())
                        },
                        Message::BunkerPermissionUpdated,
                    );
                }
                Task::none()
            }
            Message::BunkerPermissionUpdated(result) => {
                if let Err(e) = result {
                    if let Screen::Bunker(s) = &mut self.screen {
                        s.error = Some(e);
                    }
                }
                self.sync_bunker_clients()
            }
            _ => Task::none(),
        }
    }

    pub(crate) fn create_bunker_screen(&self) -> BunkerScreen {
        if let Some(ref bunker) = self.bunker {
            BunkerScreen::with_state(
                true,
                Some(bunker.url.clone()),
                self.bunker_relays.clone(),
                bunker.clients.clone(),
                bunker.log.clone(),
                self.bunker_pending_approval.clone(),
            )
        } else {
            BunkerScreen::new(self.bunker_relays.clone())
        }
    }

    pub(crate) fn handle_bunker_start(&mut self) -> Task<Message> {
        if self.bunker.is_some() {
            return Task::none();
        }

        if let Screen::Bunker(s) = &mut self.screen {
            if s.starting || s.relays.is_empty() {
                return Task::none();
            }
            s.starting = true;
            s.error = None;
        }

        let keep_arc = self.keep.clone();
        if self.bunker_relays.is_empty() {
            return Task::none();
        }
        let relay_urls = self.bunker_relays.clone();

        let setup_arc = Arc::new(Mutex::new(None));
        self.bunker_pending_setup = Some(setup_arc.clone());

        Task::perform(
            async move {
                let keyring = tokio::task::spawn_blocking(move || {
                    let guard = lock_keep(&keep_arc);
                    let keep = guard
                        .as_ref()
                        .ok_or_else(|| "Vault is locked".to_string())?;
                    let kr = keep.keyring();
                    let slot = kr
                        .get_primary()
                        .ok_or_else(|| "No signing key available".to_string())?;

                    let pubkey = slot.pubkey;
                    let secret = Zeroizing::new(*slot.expose_secret());
                    let key_type = slot.key_type;
                    let name = slot.name.clone();

                    let mut new_kr = keep_core::keyring::Keyring::new();
                    new_kr
                        .load_key(pubkey, *secret, key_type, name)
                        .map_err(|e| format!("Failed to prepare keyring: {e}"))?;

                    Ok::<_, String>(Arc::new(tokio::sync::Mutex::new(new_kr)))
                })
                .await
                .map_err(|_| "Background task failed".to_string())??;

                let (event_tx, event_rx) = std::sync::mpsc::channel();
                let callbacks: Arc<dyn keep_nip46::types::ServerCallbacks> =
                    Arc::new(DesktopCallbacks { tx: event_tx });

                let mut server = keep_nip46::Server::new(keyring, &relay_urls, Some(callbacks))
                    .await
                    .map_err(|e| format!("Failed to start bunker: {e}"))?;

                let handler = server.handler();
                let url = server.bunker_url();

                let handle = tokio::spawn(async move {
                    if let Err(e) = server.run().await {
                        tracing::error!(error = %e, "bunker server error");
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

    fn set_bunker_error(&mut self, msg: String) {
        self.set_toast(msg.clone(), ToastKind::Error);
        if let Screen::Bunker(s) = &mut self.screen {
            s.starting = false;
            s.error = Some(msg);
        }
    }

    pub(crate) fn handle_bunker_start_result(
        &mut self,
        result: Result<String, String>,
    ) -> Task<Message> {
        match result {
            Ok(url) => {
                let setup = match self.bunker_pending_setup.take() {
                    Some(arc) => match arc.lock() {
                        Ok(mut guard) => guard.take(),
                        Err(_) => {
                            self.set_bunker_error(
                                "Internal error: bunker setup state corrupted".into(),
                            );
                            return Task::none();
                        }
                    },
                    None => None,
                };

                let Some(setup) = setup else {
                    self.set_bunker_error("Internal error: bunker setup missing".into());
                    return Task::none();
                };

                self.bunker = Some(RunningBunker {
                    url: url.clone(),
                    handler: setup.handler,
                    event_rx: Arc::new(Mutex::new(setup.event_rx)),
                    handle: setup.handle,
                    clients: Vec::new(),
                    log: VecDeque::new(),
                });

                if let Screen::Bunker(s) = &mut self.screen {
                    s.running = true;
                    s.starting = false;
                    s.qr_data = iced::widget::qr_code::Data::new(&url).ok();
                    s.url = Some(url);
                    s.error = None;
                }
            }
            Err(e) => {
                self.bunker_pending_setup = None;
                self.set_bunker_error(e);
            }
        }
        Task::none()
    }

    pub(crate) fn stop_bunker(&mut self) {
        if let Some(tx) = self.bunker_approval_tx.take() {
            let _ = tx.send(false);
        }
        self.bunker_pending_approval = None;

        if let Some(bunker) = self.bunker.take() {
            bunker.handle.abort();
        }
    }

    pub(crate) fn poll_bunker_events(&mut self) {
        let Some(ref mut bunker) = self.bunker else {
            return;
        };

        let Ok(rx) = bunker.event_rx.lock() else {
            return;
        };

        while let Ok(event) = rx.try_recv() {
            match event {
                BunkerEvent::Connected { pubkey, name } => {
                    if !bunker.clients.iter().any(|c| c.pubkey == pubkey) {
                        let client = ConnectedClient {
                            pubkey,
                            name,
                            permissions: keep_nip46::Permission::DEFAULT.bits(),
                            auto_approve_kinds: Vec::new(),
                            request_count: 0,
                            duration: "Forever".into(),
                        };
                        bunker.clients.push(client.clone());
                        if let Screen::Bunker(s) = &mut self.screen {
                            s.clients.push(client);
                        }
                    }
                }
                BunkerEvent::Log {
                    app,
                    action,
                    success,
                } => {
                    let entry = LogDisplayEntry {
                        app,
                        action,
                        success,
                    };
                    if bunker.log.len() >= MAX_BUNKER_LOG_ENTRIES {
                        bunker.log.pop_front();
                    }
                    bunker.log.push_back(entry.clone());
                    if let Screen::Bunker(s) = &mut self.screen {
                        if s.log.len() >= MAX_BUNKER_LOG_ENTRIES {
                            s.log.pop_front();
                        }
                        s.log.push_back(entry);
                    }
                }
                BunkerEvent::Approval {
                    display,
                    response_tx,
                } => {
                    if let Some(prev_tx) = self.bunker_approval_tx.take() {
                        let _ = prev_tx.send(false);
                    }
                    self.bunker_pending_approval = Some(display.clone());
                    self.bunker_approval_tx = Some(response_tx);
                    if let Screen::Bunker(s) = &mut self.screen {
                        s.pending_approval = Some(display);
                    }
                }
            }
        }
    }

    pub(crate) fn sync_bunker_clients(&self) -> Task<Message> {
        if let Some(ref bunker) = self.bunker {
            let handler = bunker.handler.clone();
            Task::perform(
                async move {
                    handler
                        .list_clients()
                        .await
                        .into_iter()
                        .map(|app| {
                            let duration_str = match app.duration {
                                keep_nip46::PermissionDuration::Session => "Session".into(),
                                keep_nip46::PermissionDuration::Seconds(s) => {
                                    if s < 3600 {
                                        format!("{}m", s / 60)
                                    } else if s < 86400 {
                                        format!("{}h", s / 3600)
                                    } else {
                                        format!("{}d", s / 86400)
                                    }
                                }
                                keep_nip46::PermissionDuration::Forever => "Forever".into(),
                            };
                            ConnectedClient {
                                pubkey: app.pubkey.to_hex(),
                                name: app.name,
                                permissions: app.permissions.bits(),
                                auto_approve_kinds: app
                                    .auto_approve_kinds
                                    .iter()
                                    .map(|k| k.as_u16())
                                    .collect(),
                                request_count: app.request_count,
                                duration: duration_str,
                            }
                        })
                        .collect()
                },
                Message::BunkerClientsLoaded,
            )
        } else {
            Task::none()
        }
    }
}
