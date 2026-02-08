// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use iced::{Element, Task};
use keep_core::frost::ShareExport;
use keep_core::Keep;
use tracing::error;
use zeroize::Zeroizing;

use crate::message::{Message, ShareIdentity};
use crate::screen::create::CreateScreen;
use crate::screen::export::ExportScreen;
use crate::screen::import::ImportScreen;
use crate::screen::shares::{ShareEntry, ShareListScreen};
use crate::screen::unlock::UnlockScreen;
use crate::screen::Screen;

pub struct App {
    keep: Arc<Mutex<Option<Keep>>>,
    keep_path: PathBuf,
    screen: Screen,
}

fn lock_keep(keep: &Arc<Mutex<Option<Keep>>>) -> std::sync::MutexGuard<'_, Option<Keep>> {
    keep.lock().unwrap_or_else(|e| e.into_inner())
}

fn with_keep_blocking<T: Send + 'static>(
    keep_arc: &Arc<Mutex<Option<Keep>>>,
    panic_msg: &'static str,
    f: impl FnOnce(&mut Keep) -> Result<T, String> + Send + std::panic::UnwindSafe + 'static,
) -> Result<T, String> {
    let mut keep = lock_keep(keep_arc)
        .take()
        .ok_or_else(|| "Keep not available".to_string())?;

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| f(&mut keep)));

    *lock_keep(keep_arc) = Some(keep);

    match result {
        Ok(r) => r,
        Err(_) => Err(panic_msg.to_string()),
    }
}

impl App {
    pub fn new() -> (Self, Task<Message>) {
        let keep_path = match keep_core::default_keep_path() {
            Ok(p) => p,
            Err(_) => match dirs::home_dir() {
                Some(home) => home.join(".keep"),
                None => {
                    return (
                        Self {
                            keep: Arc::new(Mutex::new(None)),
                            keep_path: PathBuf::new(),
                            screen: Screen::Unlock(UnlockScreen::with_error(
                                "Cannot determine home directory. Set $HOME and restart.".into(),
                            )),
                        },
                        Task::none(),
                    );
                }
            },
        };
        let vault_exists = keep_path.exists();
        (
            Self {
                keep: Arc::new(Mutex::new(None)),
                keep_path,
                screen: Screen::Unlock(UnlockScreen::new(vault_exists)),
            },
            Task::none(),
        )
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::PasswordChanged(p) => {
                if let Screen::Unlock(s) = &mut self.screen {
                    *s.password = p;
                }
                Task::none()
            }
            Message::ConfirmPasswordChanged(p) => {
                if let Screen::Unlock(s) = &mut self.screen {
                    *s.confirm_password = p;
                }
                Task::none()
            }
            Message::Unlock => self.handle_unlock(),
            Message::UnlockResult(result) => self.handle_shares_result(result),
            Message::StartFresh => {
                if let Screen::Unlock(s) = &mut self.screen {
                    s.start_fresh_confirm = true;
                }
                Task::none()
            }
            Message::CancelStartFresh => {
                if let Screen::Unlock(s) = &mut self.screen {
                    s.start_fresh_confirm = false;
                }
                Task::none()
            }
            Message::ConfirmStartFresh => {
                *lock_keep(&self.keep) = None;
                if self.keep_path.exists() {
                    if let Err(e) = std::fs::remove_dir_all(&self.keep_path) {
                        if let Screen::Unlock(s) = &mut self.screen {
                            s.error = Some(format!("Failed to remove vault: {e}"));
                            s.start_fresh_confirm = false;
                        }
                        return Task::none();
                    }
                }
                self.screen = Screen::Unlock(UnlockScreen::new(false));
                Task::none()
            }

            Message::GoToCreate => {
                self.screen = Screen::Create(CreateScreen::new());
                Task::none()
            }
            Message::GoToImport => {
                self.screen = Screen::Import(ImportScreen::new());
                Task::none()
            }
            Message::GoToExport(index) => {
                let shares = self.current_shares();
                if let Some(share) = shares.get(index).cloned() {
                    self.screen = Screen::Export(ExportScreen::new(share));
                }
                Task::none()
            }
            Message::GoBack => {
                let shares = self.current_shares();
                self.screen = Screen::ShareList(ShareListScreen::new(shares));
                Task::none()
            }
            Message::Lock => {
                let mut guard = lock_keep(&self.keep);
                if let Some(keep) = guard.as_mut() {
                    keep.lock();
                }
                *guard = None;
                drop(guard);
                self.screen = Screen::Unlock(UnlockScreen::new(true));
                Task::none()
            }

            Message::RequestDelete(i) => {
                if let Screen::ShareList(s) = &mut self.screen {
                    s.delete_confirm = Some(i);
                }
                Task::none()
            }
            Message::ConfirmDelete(id) => {
                self.handle_delete(id);
                Task::none()
            }
            Message::CancelDelete => {
                if let Screen::ShareList(s) = &mut self.screen {
                    s.delete_confirm = None;
                }
                Task::none()
            }

            Message::CreateNameChanged(n) => {
                if let Screen::Create(s) = &mut self.screen {
                    s.name = n;
                }
                Task::none()
            }
            Message::CreateThresholdChanged(t) => {
                if let Screen::Create(s) = &mut self.screen {
                    s.threshold = t;
                }
                Task::none()
            }
            Message::CreateTotalChanged(t) => {
                if let Screen::Create(s) = &mut self.screen {
                    s.total = t;
                }
                Task::none()
            }
            Message::CreateKeyset => self.handle_create_keyset(),
            Message::CreateResult(result) => self.handle_shares_result(result),

            Message::ExportPassphraseChanged(p) => {
                if let Screen::Export(s) = &mut self.screen {
                    *s.passphrase = p;
                }
                Task::none()
            }
            Message::GenerateExport => self.handle_generate_export(),
            Message::ExportGenerated(result) => self.handle_export_generated(result),
            Message::CopyToClipboard(t) => iced::clipboard::write(t),

            Message::ImportDataChanged(d) => {
                if let Screen::Import(s) = &mut self.screen {
                    s.data = d;
                }
                Task::none()
            }
            Message::ImportPassphraseChanged(p) => {
                if let Screen::Import(s) = &mut self.screen {
                    *s.passphrase = p;
                }
                Task::none()
            }
            Message::ImportShare => self.handle_import(),
            Message::ImportResult(result) => self.handle_shares_result(result),
        }
    }

    pub fn view(&self) -> Element<Message> {
        self.screen.view()
    }

    fn current_shares(&self) -> Vec<ShareEntry> {
        let guard = lock_keep(&self.keep);
        let Some(keep) = guard.as_ref() else {
            return Vec::new();
        };
        match keep.frost_list_shares() {
            Ok(stored) => stored.iter().map(ShareEntry::from_stored).collect(),
            Err(e) => {
                error!("Failed to list shares: {e}");
                Vec::new()
            }
        }
    }

    fn refresh_shares(&mut self) {
        let shares = self.current_shares();
        if let Screen::ShareList(s) = &mut self.screen {
            s.shares = shares;
            s.delete_confirm = None;
            s.error = None;
        }
    }

    fn handle_unlock(&mut self) -> Task<Message> {
        let (password, vault_exists) = match &mut self.screen {
            Screen::Unlock(s) => {
                if s.password.is_empty() {
                    s.error = Some("Password required".into());
                    return Task::none();
                }
                if !s.vault_exists && *s.password != *s.confirm_password {
                    s.error = Some("Passwords do not match".into());
                    return Task::none();
                }
                s.loading = true;
                s.error = None;
                (Zeroizing::new(s.password.to_string()), s.vault_exists)
            }
            _ => return Task::none(),
        };

        let path = self.keep_path.clone();
        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let result =
                        std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, String> {
                            let mut keep = if vault_exists {
                                Keep::open(&path).map_err(|e| e.to_string())?
                            } else {
                                Keep::create(&path, &password).map_err(|e| e.to_string())?
                            };

                            if vault_exists {
                                keep.unlock(&password).map_err(|e| e.to_string())?;
                            }

                            let shares = keep
                                .frost_list_shares()
                                .map_err(|e| e.to_string())?
                                .iter()
                                .map(ShareEntry::from_stored)
                                .collect();

                            *lock_keep(&keep_arc) = Some(keep);
                            Ok(shares)
                        }));

                    match result {
                        Ok(r) => r,
                        Err(_) => Err("Internal error during unlock".to_string()),
                    }
                })
                .await
                .map_err(|e| e.to_string())?
            },
            Message::UnlockResult,
        )
    }

    fn handle_shares_result(&mut self, result: Result<Vec<ShareEntry>, String>) -> Task<Message> {
        match result {
            Ok(shares) => self.screen = Screen::ShareList(ShareListScreen::new(shares)),
            Err(e) => self.screen.set_loading_error(e),
        }
        Task::none()
    }

    fn handle_delete(&mut self, id: ShareIdentity) {
        let result = {
            let mut guard = lock_keep(&self.keep);
            guard
                .as_mut()
                .map(|keep| keep.frost_delete_share(&id.group_pubkey, id.identifier))
        };

        match result {
            Some(Ok(())) => self.refresh_shares(),
            Some(Err(e)) => {
                if let Screen::ShareList(s) = &mut self.screen {
                    s.error = Some(e.to_string());
                    s.delete_confirm = None;
                }
            }
            None => {}
        }
    }

    fn handle_create_keyset(&mut self) -> Task<Message> {
        let (name, threshold, total) = match &mut self.screen {
            Screen::Create(s) => {
                let threshold: u16 = match s.threshold.parse() {
                    Ok(v) if v >= 2 => v,
                    _ => {
                        s.error = Some("Threshold must be at least 2".into());
                        return Task::none();
                    }
                };
                let total: u16 = match s.total.parse() {
                    Ok(v) if v >= threshold => v,
                    _ => {
                        s.error = Some(format!("Total must be at least {threshold}"));
                        return Task::none();
                    }
                };
                if s.name.is_empty() {
                    s.error = Some("Name is required".into());
                    return Task::none();
                }
                s.loading = true;
                s.error = None;
                (s.name.clone(), threshold, total)
            }
            _ => return Task::none(),
        };

        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    with_keep_blocking(
                        &keep_arc,
                        "Internal error during keyset creation",
                        move |keep| {
                            keep.frost_generate(threshold, total, &name)
                                .map_err(|e| e.to_string())?;
                            Ok(keep
                                .frost_list_shares()
                                .map_err(|e| e.to_string())?
                                .iter()
                                .map(ShareEntry::from_stored)
                                .collect())
                        },
                    )
                })
                .await
                .map_err(|e| e.to_string())?
            },
            Message::CreateResult,
        )
    }

    fn handle_generate_export(&mut self) -> Task<Message> {
        let (share, passphrase) = match &mut self.screen {
            Screen::Export(s) => {
                s.loading = true;
                s.error = None;
                (s.share.clone(), Zeroizing::new(s.passphrase.to_string()))
            }
            _ => return Task::none(),
        };

        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    with_keep_blocking(&keep_arc, "Internal error during export", move |keep| {
                        let export = keep
                            .frost_export_share(&share.group_pubkey, share.identifier, &passphrase)
                            .map_err(|e| e.to_string())?;
                        export.to_bech32().map_err(|e| e.to_string())
                    })
                })
                .await
                .map_err(|e| e.to_string())?
            },
            Message::ExportGenerated,
        )
    }

    fn handle_export_generated(&mut self, result: Result<String, String>) -> Task<Message> {
        match result {
            Ok(bech32) => {
                if let Screen::Export(s) = &mut self.screen {
                    s.set_bech32(bech32);
                }
            }
            Err(e) => self.screen.set_loading_error(e),
        }
        Task::none()
    }

    fn handle_import(&mut self) -> Task<Message> {
        let (data, passphrase) = match &mut self.screen {
            Screen::Import(s) => {
                s.loading = true;
                s.error = None;
                (s.data.clone(), Zeroizing::new(s.passphrase.to_string()))
            }
            _ => return Task::none(),
        };

        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    with_keep_blocking(&keep_arc, "Internal error during import", move |keep| {
                        let export = ShareExport::parse(&data).map_err(|e| e.to_string())?;
                        keep.frost_import_share(&export, &passphrase)
                            .map_err(|e| e.to_string())?;
                        Ok(keep
                            .frost_list_shares()
                            .map_err(|e| e.to_string())?
                            .iter()
                            .map(ShareEntry::from_stored)
                            .collect())
                    })
                })
                .await
                .map_err(|e| e.to_string())?
            },
            Message::ImportResult,
        )
    }
}
