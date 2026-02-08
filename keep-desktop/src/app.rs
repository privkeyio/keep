// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iced::{Element, Subscription, Task};
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

const AUTO_LOCK_SECS: u64 = 300;
const CLIPBOARD_CLEAR_SECS: u64 = 30;
const MIN_PASSWORD_LEN: usize = 8;

pub struct App {
    keep: Arc<Mutex<Option<Keep>>>,
    keep_path: PathBuf,
    screen: Screen,
    last_activity: Instant,
    clipboard_clear_at: Option<Instant>,
}

fn lock_keep(keep: &Arc<Mutex<Option<Keep>>>) -> std::sync::MutexGuard<'_, Option<Keep>> {
    match keep.lock() {
        Ok(guard) => guard,
        Err(e) => {
            let mut guard = e.into_inner();
            *guard = None;
            guard
        }
    }
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

fn collect_shares(keep: &Keep) -> Result<Vec<ShareEntry>, String> {
    keep.frost_list_shares()
        .map(|stored| stored.iter().map(ShareEntry::from_stored).collect())
        .map_err(|e| e.to_string())
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

    match result {
        Ok(r) => {
            *lock_keep(keep_arc) = Some(keep);
            r
        }
        Err(payload) => {
            error!("{}: {}", panic_msg, panic_message(&payload));
            Err(format!("{panic_msg}; please re-unlock your vault"))
        }
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
                                false,
                                "Cannot determine home directory. Set $HOME and restart.".into(),
                            )),
                            last_activity: Instant::now(),
                            clipboard_clear_at: None,
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
                last_activity: Instant::now(),
                clipboard_clear_at: None,
            },
            Task::none(),
        )
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        if !matches!(message, Message::Tick) {
            self.last_activity = Instant::now();
        }

        match message {
            Message::Tick => {
                if self.last_activity.elapsed() >= Duration::from_secs(AUTO_LOCK_SECS)
                    && !matches!(self.screen, Screen::Unlock(_))
                {
                    return self.do_lock();
                }
                if let Some(clear_at) = self.clipboard_clear_at {
                    if Instant::now() >= clear_at {
                        self.clipboard_clear_at = None;
                        return iced::clipboard::write(String::new());
                    }
                }
                Task::none()
            }

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
                    self.screen = Screen::Export(Box::new(ExportScreen::new(share)));
                }
                Task::none()
            }
            Message::GoBack => {
                let shares = self.current_shares();
                self.screen = Screen::ShareList(ShareListScreen::new(shares));
                Task::none()
            }
            Message::Lock => self.do_lock(),

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
                    s.passphrase = p;
                }
                Task::none()
            }
            Message::GenerateExport => self.handle_generate_export(),
            Message::ExportGenerated(result) => self.handle_export_generated(result),
            Message::CopyToClipboard(t) => {
                self.clipboard_clear_at =
                    Some(Instant::now() + Duration::from_secs(CLIPBOARD_CLEAR_SECS));
                iced::clipboard::write(t.to_string())
            }

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
            Message::ImportResult(result) => self.handle_shares_result(result),
        }
    }

    pub fn view(&self) -> Element<Message> {
        self.screen.view()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        if matches!(self.screen, Screen::Unlock(_)) {
            Subscription::none()
        } else {
            iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick)
        }
    }

    fn do_lock(&mut self) -> Task<Message> {
        let mut guard = lock_keep(&self.keep);
        if let Some(keep) = guard.as_mut() {
            keep.lock();
        }
        *guard = None;
        drop(guard);
        let clear_clipboard = self.clipboard_clear_at.take().is_some();
        self.screen = Screen::Unlock(UnlockScreen::new(true));
        if clear_clipboard {
            iced::clipboard::write(String::new())
        } else {
            Task::none()
        }
    }

    fn current_shares(&self) -> Vec<ShareEntry> {
        let guard = lock_keep(&self.keep);
        let Some(keep) = guard.as_ref() else {
            return Vec::new();
        };
        collect_shares(keep).unwrap_or_else(|e| {
            error!("Failed to list shares: {e}");
            Vec::new()
        })
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
                if s.loading {
                    return Task::none();
                }
                if s.password.is_empty() {
                    s.error = Some("Password required".into());
                    return Task::none();
                }
                if !s.vault_exists && s.password.len() < MIN_PASSWORD_LEN {
                    s.error = Some(format!(
                        "Password must be at least {MIN_PASSWORD_LEN} characters"
                    ));
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

                            let shares = collect_shares(&keep)?;
                            *lock_keep(&keep_arc) = Some(keep);
                            Ok(shares)
                        }));

                    match result {
                        Ok(r) => r,
                        Err(payload) => {
                            error!("Panic during unlock: {}", panic_message(&payload));
                            Err("Internal error during unlock".to_string())
                        }
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
                if s.loading {
                    return Task::none();
                }
                let threshold: u16 = match s.threshold.parse() {
                    Ok(v) if (2..=255).contains(&v) => v,
                    _ => {
                        s.error = Some("Threshold must be between 2 and 255".into());
                        return Task::none();
                    }
                };
                let total: u16 = match s.total.parse() {
                    Ok(v) if v >= threshold && v <= 255 => v,
                    _ => {
                        s.error = Some(format!("Total must be between {threshold} and 255"));
                        return Task::none();
                    }
                };
                if s.name.is_empty() {
                    s.error = Some("Name is required".into());
                    return Task::none();
                }
                if s.name.len() > 64 {
                    s.error = Some("Name must be 64 characters or fewer".into());
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
                            collect_shares(keep)
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
                if s.loading || s.passphrase.is_empty() {
                    return Task::none();
                }
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
                    with_keep_blocking(&keep_arc, "Internal error during export", move |keep| {
                        let export = keep
                            .frost_export_share(&share.group_pubkey, share.identifier, &passphrase)
                            .map_err(|e| e.to_string())?;
                        export
                            .to_bech32()
                            .map(Zeroizing::new)
                            .map_err(|e| e.to_string())
                    })
                })
                .await
                .map_err(|e| e.to_string())?
            },
            Message::ExportGenerated,
        )
    }

    fn handle_export_generated(
        &mut self,
        result: Result<Zeroizing<String>, String>,
    ) -> Task<Message> {
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
                if s.loading || s.data.is_empty() || s.passphrase.is_empty() {
                    return Task::none();
                }
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
                    with_keep_blocking(&keep_arc, "Internal error during import", move |keep| {
                        let export = ShareExport::parse(&data).map_err(|e| e.to_string())?;
                        keep.frost_import_share(&export, &passphrase)
                            .map_err(|e| e.to_string())?;
                        collect_shares(keep)
                    })
                })
                .await
                .map_err(|e| e.to_string())?
            },
            Message::ImportResult,
        )
    }
}
