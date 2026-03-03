// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use iced::Task;

use crate::app::{
    save_settings, App, ToastKind, BUNKER_APPROVAL_TIMEOUT, MAX_BUNKER_LOG_ENTRIES,
};
use crate::bunker_service::extract_keyring;
use crate::message::Message;
use crate::screen::local_signer::{ConnectedClient, LogDisplayEntry, PendingApprovalDisplay};
use crate::screen::Screen;

pub(crate) enum LocalSignerEvent {
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
        client_id: String,
        name: String,
    },
}

pub(crate) struct LocalSignerCallbacks {
    pub tx: std::sync::mpsc::Sender<LocalSignerEvent>,
}

impl keep_nip46::types::ServerCallbacks for LocalSignerCallbacks {
    fn on_log(&self, event: keep_nip46::types::LogEvent) {
        let _ = self.tx.send(LocalSignerEvent::Log {
            app: event.app,
            action: event.action,
            success: event.success,
        });
    }

    fn request_approval(&self, request: keep_nip46::types::ApprovalRequest) -> bool {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        let display = PendingApprovalDisplay {
            app_name: request.app_name,
            method: request.method,
            event_kind: request.event_kind.map(|k| u32::from(k.as_u16())),
            event_content: request.event_content,
        };
        if self
            .tx
            .send(LocalSignerEvent::Approval {
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

    fn on_connect(&self, client_id: &str, name: &str) {
        let _ = self.tx.send(LocalSignerEvent::Connected {
            client_id: client_id.to_string(),
            name: name.to_string(),
        });
    }
}

pub(crate) struct LocalSignerSetup {
    pub handler: Arc<keep_nip46::SignerHandler>,
    pub event_rx: std::sync::mpsc::Receiver<LocalSignerEvent>,
    pub handle: tokio::task::JoinHandle<()>,
}

pub(crate) struct RunningLocalSigner {
    pub socket_path: String,
    pub handler: Arc<keep_nip46::SignerHandler>,
    pub event_rx: Arc<Mutex<std::sync::mpsc::Receiver<LocalSignerEvent>>>,
    pub handle: tokio::task::JoinHandle<()>,
    pub clients: Vec<ConnectedClient>,
    pub log: VecDeque<LogDisplayEntry>,
}

impl App {
    pub(crate) fn local_signer_socket_path(&self) -> PathBuf {
        if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
            let p = PathBuf::from(runtime).join("keep");
            let _ = std::fs::create_dir_all(&p);
            p.join("signer.sock")
        } else {
            self.keep_path.join("signer.sock")
        }
    }

    pub(crate) fn handle_local_signer_start(&mut self) -> Task<Message> {
        if self.is_kill_switch_active() {
            self.set_toast(
                "Kill switch is active - signing blocked".into(),
                ToastKind::Error,
            );
            return Task::none();
        }
        if self.local_signer.is_some() {
            return Task::none();
        }

        if let Screen::LocalSigner(s) = &mut self.screen {
            s.starting = true;
            s.error = None;
        }

        let keep_arc = self.keep.clone();
        let kill_switch = self.kill_switch.clone();
        let socket_path = self.local_signer_socket_path();
        let setup_arc: Arc<Mutex<Option<LocalSignerSetup>>> = Arc::new(Mutex::new(None));
        self.local_signer_pending_setup = Some(setup_arc.clone());

        Task::perform(
            async move {
                let keyring = tokio::task::spawn_blocking(move || extract_keyring(&keep_arc))
                    .await
                    .map_err(|_| "Background task failed".to_string())?
                    .map_err(|e| e.to_string())?;

                let (event_tx, event_rx) = std::sync::mpsc::channel();
                let callbacks: Arc<dyn keep_nip46::types::ServerCallbacks> =
                    Arc::new(LocalSignerCallbacks { tx: event_tx });

                let config = keep_nip46::LocalServerConfig {
                    rate_limit: Some(keep_nip46::RateLimitConfig::conservative()),
                    kill_switch: Some(kill_switch),
                    ..Default::default()
                };
                let socket_path_str = socket_path.display().to_string();
                let server = keep_nip46::LocalServer::new(keyring, socket_path, Some(callbacks), config)
                    .map_err(|e| format!("Failed to start local signer: {e}"))?;

                let handler = server.handler();
                let handle = tokio::spawn(async move {
                    if let Err(e) = server.run().await {
                        tracing::error!(error = %e, "local signer error");
                    }
                });

                let mut guard = setup_arc.lock().unwrap_or_else(|e| e.into_inner());
                *guard = Some(LocalSignerSetup {
                    handler,
                    event_rx,
                    handle,
                });
                Ok(socket_path_str)
            },
            Message::LocalSignerStartResult,
        )
    }

    pub(crate) fn handle_local_signer_start_result(
        &mut self,
        result: Result<String, String>,
    ) -> Task<Message> {
        match result {
            Ok(socket_path) => {
                let setup = self
                    .local_signer_pending_setup
                    .take()
                    .and_then(|arc| arc.lock().ok().and_then(|mut g| g.take()));

                let Some(setup) = setup else {
                    self.set_toast(
                        "Internal error: local signer setup missing".into(),
                        ToastKind::Error,
                    );
                    if let Screen::LocalSigner(s) = &mut self.screen {
                        s.starting = false;
                    }
                    return Task::none();
                };

                self.local_signer = Some(RunningLocalSigner {
                    socket_path: socket_path.clone(),
                    handler: setup.handler,
                    event_rx: Arc::new(Mutex::new(setup.event_rx)),
                    handle: setup.handle,
                    clients: Vec::new(),
                    log: VecDeque::new(),
                });

                self.settings.local_signer_auto_start = true;
                save_settings(&self.keep_path, &self.settings);

                if let Screen::LocalSigner(s) = &mut self.screen {
                    s.running = true;
                    s.starting = false;
                    s.socket_path = Some(socket_path);
                    s.error = None;
                }
            }
            Err(e) => {
                self.local_signer_pending_setup = None;
                self.set_toast(e.clone(), ToastKind::Error);
                if let Screen::LocalSigner(s) = &mut self.screen {
                    s.starting = false;
                    s.error = Some(e);
                }
            }
        }
        Task::none()
    }

    pub(crate) fn stop_local_signer(&mut self) {
        if let Some(tx) = self.local_signer_approval_tx.take() {
            let _ = tx.send(false);
        }
        self.local_signer_pending_approval = None;

        if let Some(ls) = self.local_signer.take() {
            ls.handle.abort();
        }
    }

    pub(crate) fn handle_local_signer_stop(&mut self) -> Task<Message> {
        self.stop_local_signer();
        self.settings.local_signer_auto_start = false;
        save_settings(&self.keep_path, &self.settings);
        if let Screen::LocalSigner(s) = &mut self.screen {
            s.running = false;
            s.starting = false;
            s.socket_path = None;
            s.clients.clear();
            s.pending_approval = None;
        }
        self.set_toast("Local signer stopped".into(), ToastKind::Success);
        Task::none()
    }

    pub(crate) fn poll_local_signer_events(&mut self) {
        let events: Vec<LocalSignerEvent> = {
            let Some(ref ls) = self.local_signer else {
                return;
            };
            let Ok(rx) = ls.event_rx.lock() else {
                return;
            };
            rx.try_iter().collect()
        };

        for event in events {
            match event {
                LocalSignerEvent::Connected { client_id, name } => {
                    let Some(ref mut ls) = self.local_signer else {
                        continue;
                    };
                    if !ls.clients.iter().any(|c| c.client_id == client_id) {
                        let client = ConnectedClient {
                            client_id,
                            name,
                        };
                        ls.clients.push(client.clone());
                        if let Screen::LocalSigner(s) = &mut self.screen {
                            s.clients.push(client);
                        }
                    }
                }
                LocalSignerEvent::Log {
                    app,
                    action,
                    success,
                } => {
                    let Some(ref mut ls) = self.local_signer else {
                        continue;
                    };
                    let entry = LogDisplayEntry {
                        app,
                        action,
                        success,
                    };
                    if ls.log.len() >= MAX_BUNKER_LOG_ENTRIES {
                        ls.log.pop_front();
                    }
                    ls.log.push_back(entry.clone());
                    if let Screen::LocalSigner(s) = &mut self.screen {
                        if s.log.len() >= MAX_BUNKER_LOG_ENTRIES {
                            s.log.pop_front();
                        }
                        s.log.push_back(entry);
                    }
                }
                LocalSignerEvent::Approval {
                    display,
                    response_tx,
                } => {
                    if let Some(prev_tx) = self.local_signer_approval_tx.take() {
                        let _ = prev_tx.send(false);
                    }
                    self.local_signer_pending_approval = Some(display.clone());
                    self.local_signer_approval_tx = Some(response_tx);
                    if let Screen::LocalSigner(s) = &mut self.screen {
                        s.pending_approval = Some(display);
                    }
                }
            }
        }
    }

    pub(crate) fn handle_local_signer_message(
        &mut self,
        msg: crate::screen::local_signer::Message,
    ) -> Task<Message> {
        let Screen::LocalSigner(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        use crate::screen::local_signer::Event;
        match event {
            Event::Start => self.handle_local_signer_start(),
            Event::Stop => self.handle_local_signer_stop(),
            Event::Approve => {
                if self.is_kill_switch_active() {
                    self.set_toast(
                        "Kill switch is active - signing blocked".into(),
                        ToastKind::Error,
                    );
                    return Task::none();
                }
                if let Some(tx) = self.local_signer_approval_tx.take() {
                    let _ = tx.send(true);
                }
                self.local_signer_pending_approval = None;
                if let Screen::LocalSigner(s) = &mut self.screen {
                    s.approval_cleared();
                }
                Task::none()
            }
            Event::Reject => {
                if let Some(tx) = self.local_signer_approval_tx.take() {
                    let _ = tx.send(false);
                }
                self.local_signer_pending_approval = None;
                if let Screen::LocalSigner(s) = &mut self.screen {
                    s.approval_cleared();
                }
                Task::none()
            }
            Event::RevokeClient(i) => {
                let client_id = if let Screen::LocalSigner(s) = &self.screen {
                    s.clients.get(i).map(|c| c.client_id.clone())
                } else {
                    None
                };
                if let (Some(id), Some(ref ls)) = (client_id, &self.local_signer) {
                    let handler = ls.handler.clone();
                    return Task::perform(
                        async move {
                            let app_pubkey = keep_nip46::LocalServer::pseudo_pubkey_for(&id);
                            handler.revoke_client(&app_pubkey).await;
                            Ok::<(), String>(())
                        },
                        Message::LocalSignerRevokeResult,
                    );
                }
                Task::none()
            }
            Event::CopyPath => {
                let Some(path) = self.local_signer.as_ref().map(|ls| ls.socket_path.clone())
                else {
                    return Task::none();
                };
                self.start_clipboard_timer();
                iced::clipboard::write(path)
            }
        }
    }

    pub(crate) fn create_local_signer_screen(&self) -> crate::screen::local_signer::State {
        use crate::screen::local_signer;
        if let Some(ref ls) = self.local_signer {
            local_signer::State::with_state(
                true,
                Some(ls.socket_path.clone()),
                ls.clients.clone(),
                ls.log.clone(),
                self.local_signer_pending_approval.clone(),
            )
        } else {
            local_signer::State::new()
        }
    }
}
