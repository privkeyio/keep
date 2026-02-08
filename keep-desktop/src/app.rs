// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use iced::{Element, Task};
use keep_core::frost::ShareExport;
use keep_core::Keep;
use tracing::error;

use crate::message::Message;
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

impl App {
    pub fn new() -> (Self, Task<Message>) {
        let keep_path = keep_core::default_keep_path()
            .unwrap_or_else(|_| dirs::home_dir().unwrap_or_default().join(".keep"));
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
                    s.password = p;
                }
                Task::none()
            }
            Message::ConfirmPasswordChanged(p) => {
                if let Screen::Unlock(s) = &mut self.screen {
                    s.confirm_password = p;
                }
                Task::none()
            }
            Message::Unlock => self.handle_unlock(),
            Message::UnlockResult(result) => self.handle_unlock_result(result),

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
                let mut guard = self.keep.lock().unwrap();
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
            Message::ConfirmDelete(i) => {
                self.handle_delete(i);
                Task::none()
            }
            Message::CancelDelete => {
                if let Screen::ShareList(s) = &mut self.screen {
                    s.delete_confirm = None;
                }
                Task::none()
            }

            Message::ExportPassphraseChanged(p) => {
                if let Screen::Export(s) = &mut self.screen {
                    s.passphrase = p;
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
                    s.passphrase = p;
                }
                Task::none()
            }
            Message::ImportShare => self.handle_import(),
            Message::ImportResult(result) => self.handle_import_result(result),
        }
    }

    pub fn view(&self) -> Element<Message> {
        self.screen.view()
    }

    fn current_shares(&self) -> Vec<ShareEntry> {
        let guard = self.keep.lock().unwrap();
        if let Some(keep) = guard.as_ref() {
            match keep.frost_list_shares() {
                Ok(stored) => stored.iter().map(ShareEntry::from_stored).collect(),
                Err(e) => {
                    error!("Failed to list shares: {e}");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
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
                if !s.vault_exists && s.password != s.confirm_password {
                    s.error = Some("Passwords do not match".into());
                    return Task::none();
                }
                s.loading = true;
                s.error = None;
                (s.password.clone(), s.vault_exists)
            }
            _ => return Task::none(),
        };

        let path = self.keep_path.clone();
        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
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

                    *keep_arc.lock().unwrap() = Some(keep);
                    Ok(shares)
                })
                .await
                .map_err(|e| e.to_string())?
            },
            Message::UnlockResult,
        )
    }

    fn handle_unlock_result(
        &mut self,
        result: Result<Vec<ShareEntry>, String>,
    ) -> Task<Message> {
        match result {
            Ok(shares) => {
                self.screen = Screen::ShareList(ShareListScreen::new(shares));
            }
            Err(e) => {
                if let Screen::Unlock(s) = &mut self.screen {
                    s.loading = false;
                    s.error = Some(e);
                }
            }
        }
        Task::none()
    }

    fn handle_delete(&mut self, index: usize) {
        let shares = self.current_shares();
        let share = match shares.get(index) {
            Some(s) => s.clone(),
            None => return,
        };

        let result = {
            let mut guard = self.keep.lock().unwrap();
            if let Some(keep) = guard.as_mut() {
                Some(keep.frost_delete_share(&share.group_pubkey, share.identifier))
            } else {
                None
            }
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

    fn handle_generate_export(&mut self) -> Task<Message> {
        let (share, passphrase) = match &mut self.screen {
            Screen::Export(s) => {
                s.loading = true;
                s.error = None;
                (s.share.clone(), s.passphrase.clone())
            }
            _ => return Task::none(),
        };

        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let mut keep = keep_arc
                        .lock()
                        .unwrap()
                        .take()
                        .ok_or_else(|| "Keep not available".to_string())?;

                    let result = (|| {
                        let export = keep
                            .frost_export_share(
                                &share.group_pubkey,
                                share.identifier,
                                &passphrase,
                            )
                            .map_err(|e| e.to_string())?;
                        export.to_bech32().map_err(|e| e.to_string())
                    })();

                    *keep_arc.lock().unwrap() = Some(keep);
                    result
                })
                .await
                .map_err(|e| e.to_string())?
            },
            Message::ExportGenerated,
        )
    }

    fn handle_export_generated(
        &mut self,
        result: Result<String, String>,
    ) -> Task<Message> {
        match result {
            Ok(bech32) => {
                if let Screen::Export(s) = &mut self.screen {
                    s.set_bech32(bech32);
                }
            }
            Err(e) => {
                if let Screen::Export(s) = &mut self.screen {
                    s.loading = false;
                    s.error = Some(e);
                }
            }
        }
        Task::none()
    }

    fn handle_import(&mut self) -> Task<Message> {
        let (data, passphrase) = match &mut self.screen {
            Screen::Import(s) => {
                s.loading = true;
                s.error = None;
                (s.data.clone(), s.passphrase.clone())
            }
            _ => return Task::none(),
        };

        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let mut keep = keep_arc
                        .lock()
                        .unwrap()
                        .take()
                        .ok_or_else(|| "Keep not available".to_string())?;

                    let result = (|| {
                        let export =
                            ShareExport::parse(&data).map_err(|e| e.to_string())?;
                        keep.frost_import_share(&export, &passphrase)
                            .map_err(|e| e.to_string())?;
                        let shares = keep
                            .frost_list_shares()
                            .map_err(|e| e.to_string())?
                            .iter()
                            .map(ShareEntry::from_stored)
                            .collect();
                        Ok(shares)
                    })();

                    *keep_arc.lock().unwrap() = Some(keep);
                    result
                })
                .await
                .map_err(|e| e.to_string())?
            },
            Message::ImportResult,
        )
    }

    fn handle_import_result(
        &mut self,
        result: Result<Vec<ShareEntry>, String>,
    ) -> Task<Message> {
        match result {
            Ok(shares) => {
                self.screen = Screen::ShareList(ShareListScreen::new(shares));
            }
            Err(e) => {
                if let Screen::Import(s) = &mut self.screen {
                    s.loading = false;
                    s.error = Some(e);
                }
            }
        }
        Task::none()
    }
}
