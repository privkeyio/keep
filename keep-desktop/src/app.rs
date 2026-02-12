// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iced::widget::{column, container, text};
use iced::{Background, Element, Length, Subscription, Task};
use keep_core::frost::ShareExport;
use keep_core::Keep;
use tracing::error;
use zeroize::Zeroizing;

use crate::message::{ExportData, Message, ShareIdentity};
use crate::screen::create::CreateScreen;
use crate::screen::export::ExportScreen;
use crate::screen::import::ImportScreen;
use crate::screen::relays::{self, RelayScreen, RelayShareEntry};
use crate::screen::shares::{ShareEntry, ShareListScreen};
use crate::screen::unlock::UnlockScreen;
use crate::screen::wallet::{WalletEntry, WalletScreen};
use crate::screen::Screen;

const AUTO_LOCK_SECS: u64 = 300;
const CLIPBOARD_CLEAR_SECS: u64 = 30;
const MIN_PASSWORD_LEN: usize = 8;
pub const MIN_EXPORT_PASSPHRASE_LEN: usize = 15;
const TOAST_DURATION_SECS: u64 = 5;

#[derive(Clone)]
pub enum ToastKind {
    Success,
    Error,
}

#[derive(Clone)]
pub struct Toast {
    pub message: String,
    pub kind: ToastKind,
}

pub struct App {
    keep: Arc<Mutex<Option<Keep>>>,
    keep_path: PathBuf,
    screen: Screen,
    active_share_hex: Option<String>,
    last_activity: Instant,
    clipboard_clear_at: Option<Instant>,
    copy_feedback_until: Option<Instant>,
    toast: Option<Toast>,
    toast_dismiss_at: Option<Instant>,
}

fn lock_keep(keep: &Arc<Mutex<Option<Keep>>>) -> std::sync::MutexGuard<'_, Option<Keep>> {
    match keep.lock() {
        Ok(guard) => guard,
        Err(e) => {
            let mut guard = e.into_inner();
            if let Some(ref mut k) = *guard {
                k.lock();
            }
            *guard = None;
            guard
        }
    }
}

fn friendly_err(e: keep_core::error::KeepError) -> String {
    use keep_core::error::KeepError;
    match &e {
        KeepError::InvalidPassword => "Invalid password".into(),
        KeepError::RateLimited(secs) => format!("Too many attempts. Try again in {secs} seconds"),
        KeepError::DecryptionFailed => {
            "Decryption failed - wrong password or corrupted data".into()
        }
        KeepError::Locked => "Vault is locked".into(),
        KeepError::AlreadyExists(_) => "Vault already exists".into(),
        KeepError::NotFound(_) => "Vault not found".into(),
        KeepError::InvalidInput(msg) => format!("Invalid input: {msg}"),
        KeepError::InvalidNsec => "Invalid secret key format".into(),
        KeepError::InvalidNpub => "Invalid public key format".into(),
        KeepError::KeyAlreadyExists(_) => "A key with this name already exists".into(),
        KeepError::KeyNotFound(_) => "Key not found".into(),
        KeepError::KeyringFull(_) => "Keyring is full".into(),
        KeepError::Frost(_) | KeepError::FrostErr(_) => "FROST operation failed".into(),
        KeepError::PermissionDenied(_) => "Permission denied".into(),
        KeepError::HomeNotFound => "Home directory not found".into(),
        KeepError::UserRejected => "Operation cancelled".into(),
        KeepError::Io(_) => "File system error".into(),
        _ => {
            tracing::warn!("Unmapped keep error: {e}");
            "Operation failed".into()
        }
    }
}

fn collect_shares(keep: &Keep) -> Result<Vec<ShareEntry>, String> {
    keep.frost_list_shares()
        .map(|stored| stored.iter().map(ShareEntry::from_stored).collect())
        .map_err(friendly_err)
}

fn load_relay_entries(keep_arc: &Arc<Mutex<Option<Keep>>>) -> Result<Vec<RelayShareEntry>, String> {
    let guard = lock_keep(keep_arc);
    let keep = guard.as_ref().ok_or("Keep not available".to_string())?;

    let shares = keep.frost_list_shares().map_err(friendly_err)?;

    let mut seen_groups: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut entries = Vec::new();

    for stored in &shares {
        let gp = stored.metadata.group_pubkey;
        if !seen_groups.insert(gp) {
            continue;
        }

        let config = keep
            .get_relay_config_or_default(&gp)
            .map_err(friendly_err)?;

        entries.push(RelayShareEntry {
            group_pubkey: gp,
            group_hex: hex::encode(gp),
            name: stored.metadata.name.clone(),
            frost_relays: config.frost_relays,
            profile_relays: config.profile_relays,
        });
    }

    Ok(entries)
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
            let detail = payload
                .downcast::<String>()
                .map(|s| *s)
                .or_else(|p| p.downcast::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|_| "unknown".to_string());
            error!("{panic_msg}: {detail}");
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
                            active_share_hex: None,
                            last_activity: Instant::now(),
                            clipboard_clear_at: None,
                            copy_feedback_until: None,
                            toast: None,
                            toast_dismiss_at: None,
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
                active_share_hex: None,
                last_activity: Instant::now(),
                clipboard_clear_at: None,
                copy_feedback_until: None,
                toast: None,
                toast_dismiss_at: None,
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
                let now = Instant::now();
                if self.clipboard_clear_at.is_some_and(|t| now >= t) {
                    self.clipboard_clear_at = None;
                    return iced::clipboard::write(String::new());
                }
                if self.copy_feedback_until.is_some_and(|t| now >= t) {
                    self.copy_feedback_until = None;
                    if let Screen::Export(s) = &mut self.screen {
                        s.copied = false;
                    }
                }
                if self.toast_dismiss_at.is_some_and(|t| now >= t) {
                    self.toast = None;
                    self.toast_dismiss_at = None;
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
            Message::ConfirmStartFresh => self.handle_start_fresh(),
            Message::StartFreshResult(result) => {
                match result {
                    Ok(()) => {
                        *lock_keep(&self.keep) = None;
                        self.screen = Screen::Unlock(UnlockScreen::new(false));
                    }
                    Err(e) => {
                        if let Screen::Unlock(s) = &mut self.screen {
                            s.loading = false;
                            s.error = Some(e);
                            s.start_fresh_confirm = false;
                        }
                    }
                }
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
            Message::NavigateShares | Message::GoBack => {
                if matches!(self.screen, Screen::ShareList(_)) {
                    return Task::none();
                }
                self.copy_feedback_until = None;
                let shares = self.current_shares();
                self.screen =
                    Screen::ShareList(ShareListScreen::new(shares, self.active_share_hex.clone()));
                Task::none()
            }
            Message::NavigateWallets => {
                if matches!(self.screen, Screen::Wallet(_)) {
                    return Task::none();
                }
                let keep_arc = self.keep.clone();
                Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            let guard = lock_keep(&keep_arc);
                            let Some(keep) = guard.as_ref() else {
                                return Err("Keep not available".to_string());
                            };
                            keep.list_wallet_descriptors()
                                .map(|ds| ds.iter().map(WalletEntry::from_descriptor).collect())
                                .map_err(friendly_err)
                        })
                        .await
                        .map_err(|_| "Background task failed".to_string())?
                    },
                    Message::WalletsLoaded,
                )
            }
            Message::WalletsLoaded(result) => {
                match result {
                    Ok(entries) => {
                        self.screen = Screen::Wallet(WalletScreen::new(entries));
                    }
                    Err(e) => {
                        self.set_toast(e, ToastKind::Error);
                    }
                }
                Task::none()
            }
            Message::Lock => self.do_lock(),

            Message::ToggleShareDetails(i) => {
                if let Screen::ShareList(s) = &mut self.screen {
                    s.expanded = if s.expanded == Some(i) { None } else { Some(i) };
                }
                Task::none()
            }
            Message::SetActiveShare(hex) => {
                let shares = self.current_shares();
                let exists = shares.iter().any(|s| s.group_pubkey_hex == hex);
                if !exists {
                    self.set_toast("Share not found".into(), ToastKind::Error);
                    return Task::none();
                }

                let result = lock_keep(&self.keep)
                    .as_ref()
                    .map(|k| k.set_active_share_key(Some(&hex)));

                match result {
                    Some(Ok(())) => {
                        self.active_share_hex = Some(hex);
                        if let Screen::ShareList(s) = &mut self.screen {
                            s.active_share_hex = self.active_share_hex.clone();
                        }
                    }
                    Some(Err(e)) => self.set_toast(friendly_err(e), ToastKind::Error),
                    None => {}
                }
                Task::none()
            }
            Message::RequestDelete(id) => {
                if let Screen::ShareList(s) = &mut self.screen {
                    s.delete_confirm = Some(id);
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
            Message::CreateResult(result) => match result {
                Ok(shares) => {
                    self.resolve_active_share(&shares);
                    self.screen = Screen::ShareList(ShareListScreen::new(
                        shares,
                        self.active_share_hex.clone(),
                    ));
                    self.set_toast(
                        "Keyset created! Tap a share and use Export QR to send it to your phone."
                            .into(),
                        ToastKind::Success,
                    );
                    Task::none()
                }
                Err(e) => {
                    self.screen.set_loading_error(e);
                    Task::none()
                }
            },

            Message::ExportPassphraseChanged(p) => {
                if let Screen::Export(s) = &mut self.screen {
                    s.passphrase = p;
                    s.confirm_passphrase = Zeroizing::new(String::new());
                }
                Task::none()
            }
            Message::ExportConfirmPassphraseChanged(p) => {
                if let Screen::Export(s) = &mut self.screen {
                    s.confirm_passphrase = p;
                }
                Task::none()
            }
            Message::GenerateExport => self.handle_generate_export(),
            Message::ExportGenerated(result) => self.handle_export_generated(result),
            Message::AdvanceQrFrame => {
                if let Screen::Export(s) = &mut self.screen {
                    s.advance_frame();
                }
                Task::none()
            }
            Message::CopyToClipboard(t) => {
                self.clipboard_clear_at =
                    Some(Instant::now() + Duration::from_secs(CLIPBOARD_CLEAR_SECS));
                self.copy_feedback_until = Some(Instant::now() + Duration::from_secs(2));
                if let Screen::Export(s) = &mut self.screen {
                    s.copied = true;
                }
                let plain = (*t).clone();
                iced::clipboard::write(plain)
            }
            Message::ResetExport => {
                self.copy_feedback_until = None;
                if let Screen::Export(s) = &mut self.screen {
                    s.reset();
                }
                Task::none()
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
            Message::ImportResult(result) => self.handle_import_result(result),

            Message::CopyNpub(npub) => iced::clipboard::write(npub),
            Message::CopyDescriptor(desc) => iced::clipboard::write(desc),
            Message::ToggleWalletDetails(i) => {
                if let Screen::Wallet(s) = &mut self.screen {
                    s.expanded = if s.expanded == Some(i) { None } else { Some(i) };
                }
                Task::none()
            }

            Message::NavigateRelays => {
                if matches!(self.screen, Screen::Relays(_)) {
                    return Task::none();
                }
                let keep_arc = self.keep.clone();
                Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || load_relay_entries(&keep_arc))
                            .await
                            .map_err(|_| "Background task failed".to_string())?
                    },
                    Message::RelaysLoaded,
                )
            }
            Message::RelaysLoaded(result) => {
                match result {
                    Ok(entries) => {
                        self.screen = Screen::Relays(RelayScreen::new(entries));
                    }
                    Err(e) => {
                        self.set_toast(e, ToastKind::Error);
                    }
                }
                Task::none()
            }
            Message::ToggleRelayDetails(i) => {
                if let Screen::Relays(s) = &mut self.screen {
                    if s.expanded == Some(i) {
                        s.expanded = None;
                    } else {
                        s.expanded = Some(i);
                        s.frost_input.clear();
                        s.profile_input.clear();
                        s.error = None;
                    }
                }
                Task::none()
            }
            Message::FrostRelayInputChanged(input) => {
                if let Screen::Relays(s) = &mut self.screen {
                    s.frost_input = input;
                    s.error = None;
                }
                Task::none()
            }
            Message::ProfileRelayInputChanged(input) => {
                if let Screen::Relays(s) = &mut self.screen {
                    s.profile_input = input;
                    s.error = None;
                }
                Task::none()
            }
            Message::AddFrostRelay(share_idx) => self.add_relay(
                share_idx,
                |s| &s.frost_input,
                |e| &e.frost_relays,
                |config, url| config.frost_relays.push(url),
            ),
            Message::AddProfileRelay(share_idx) => self.add_relay(
                share_idx,
                |s| &s.profile_input,
                |e| &e.profile_relays,
                |config, url| config.profile_relays.push(url),
            ),
            Message::RemoveFrostRelay(share_idx, url) => {
                self.remove_relay(share_idx, url, |config, u| {
                    config.frost_relays.retain(|r| *r != u);
                })
            }
            Message::RemoveProfileRelay(share_idx, url) => {
                self.remove_relay(share_idx, url, |config, u| {
                    config.profile_relays.retain(|r| *r != u);
                })
            }
            Message::ResetFrostRelays(share_idx) => {
                let group_pubkey = match &self.screen {
                    Screen::Relays(s) => match s.shares.get(share_idx) {
                        Some(entry) => entry.group_pubkey,
                        None => return Task::none(),
                    },
                    _ => return Task::none(),
                };
                self.modify_relay_config(group_pubkey, |config| {
                    config.frost_relays = keep_core::relay::default_frost_relays();
                })
            }
            Message::RelaySaved(result) => {
                match result {
                    Ok(entries) => {
                        if let Screen::Relays(s) = &mut self.screen {
                            s.shares = entries;
                            s.frost_input.clear();
                            s.profile_input.clear();
                            s.error = None;
                        }
                    }
                    Err(e) => {
                        if let Screen::Relays(s) = &mut self.screen {
                            s.error = Some(e.clone());
                        }
                        self.set_toast(e, ToastKind::Error);
                    }
                }
                Task::none()
            }
        }
    }

    pub fn view(&self) -> Element<Message> {
        let screen = self.screen.view();
        let Some(toast) = &self.toast else {
            return screen;
        };
        let bg_color = match toast.kind {
            ToastKind::Success => crate::theme::color::SUCCESS,
            ToastKind::Error => crate::theme::color::ERROR,
        };
        let banner = container(
            text(&toast.message)
                .size(crate::theme::size::BODY)
                .color(iced::Color::WHITE),
        )
        .padding([crate::theme::space::SM, crate::theme::space::LG])
        .width(Length::Fill)
        .style(move |_theme: &iced::Theme| container::Style {
            background: Some(Background::Color(bg_color)),
            ..Default::default()
        });
        column![banner, screen].into()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        if matches!(self.screen, Screen::Unlock(_)) {
            return Subscription::none();
        }
        let mut subs = vec![iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick)];

        if matches!(
            self.screen,
            Screen::Create(_) | Screen::Export(_) | Screen::Import(_)
        ) {
            subs.push(iced::keyboard::listen().filter_map(|event| match event {
                iced::keyboard::Event::KeyPressed {
                    key: iced::keyboard::Key::Named(iced::keyboard::key::Named::Escape),
                    ..
                } => Some(Message::GoBack),
                _ => None,
            }));
        }

        if let Screen::Export(s) = &self.screen {
            if s.is_animated() {
                subs.push(
                    iced::time::every(Duration::from_millis(800)).map(|_| Message::AdvanceQrFrame),
                );
            }
        }

        Subscription::batch(subs)
    }

    fn do_lock(&mut self) -> Task<Message> {
        let mut guard = lock_keep(&self.keep);
        if let Some(keep) = guard.as_mut() {
            keep.lock();
        }
        *guard = None;
        drop(guard);
        let clear_clipboard = self.clipboard_clear_at.take().is_some();
        self.active_share_hex = None;
        self.toast = None;
        self.toast_dismiss_at = None;
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
        self.resolve_active_share(&shares);
        if let Screen::ShareList(s) = &mut self.screen {
            s.shares = shares;
            s.active_share_hex = self.active_share_hex.clone();
            s.delete_confirm = None;
        }
    }

    fn resolve_active_share(&mut self, shares: &[ShareEntry]) {
        let guard = lock_keep(&self.keep);
        let Some(keep) = guard.as_ref() else {
            return;
        };

        let current = keep.get_active_share_key();
        let still_valid = current
            .as_ref()
            .is_some_and(|key| shares.iter().any(|s| s.group_pubkey_hex == *key));

        if still_valid {
            self.active_share_hex = current;
            return;
        }

        let first = shares.first().map(|s| s.group_pubkey_hex.as_str());
        let all_same_group =
            first.is_some_and(|f| shares.iter().all(|s| s.group_pubkey_hex == f));
        let new_key = if all_same_group { first } else { None };

        if keep.set_active_share_key(new_key).is_ok() {
            self.active_share_hex = new_key.map(String::from);
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
                (s.password.clone(), s.vault_exists)
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
                                Keep::open(&path).map_err(friendly_err)?
                            } else {
                                Keep::create(&path, &password).map_err(friendly_err)?
                            };

                            if vault_exists {
                                keep.unlock(&password).map_err(friendly_err)?;
                            }

                            let shares = collect_shares(&keep)?;
                            *lock_keep(&keep_arc) = Some(keep);
                            Ok(shares)
                        }));

                    match result {
                        Ok(r) => r,
                        Err(payload) => {
                            error!("Panic during unlock: {:?}", payload.type_id());
                            Err("Internal error during unlock".to_string())
                        }
                    }
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::UnlockResult,
        )
    }

    fn handle_start_fresh(&mut self) -> Task<Message> {
        let password = match &mut self.screen {
            Screen::Unlock(s) => {
                if s.password.is_empty() {
                    s.error = Some("Enter your vault password to confirm deletion".into());
                    return Task::none();
                }
                if s.loading {
                    return Task::none();
                }
                s.loading = true;
                s.error = None;
                s.password.clone()
            }
            _ => return Task::none(),
        };
        let path = self.keep_path.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let result =
                        std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
                            let mut keep = Keep::open(&path).map_err(friendly_err)?;
                            keep.unlock(&password).map_err(friendly_err)?;
                            drop(keep);
                            let meta = std::fs::symlink_metadata(&path)
                                .map_err(|e| format!("Failed to read vault metadata: {e}"))?;
                            if meta.file_type().is_symlink() {
                                return Err("Vault path is a symlink; refusing to delete".into());
                            }
                            std::fs::remove_dir_all(&path)
                                .map_err(|e| format!("Failed to remove vault: {e}"))
                        }));
                    match result {
                        Ok(r) => r,
                        Err(payload) => {
                            error!("Panic during start fresh: {:?}", payload.type_id());
                            Err("Internal error; please restart the application".into())
                        }
                    }
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::StartFreshResult,
        )
    }

    fn set_toast(&mut self, message: String, kind: ToastKind) {
        self.toast = Some(Toast { message, kind });
        self.toast_dismiss_at = Some(Instant::now() + Duration::from_secs(TOAST_DURATION_SECS));
    }

    fn handle_shares_result(&mut self, result: Result<Vec<ShareEntry>, String>) -> Task<Message> {
        match result {
            Ok(shares) => {
                self.resolve_active_share(&shares);
                self.screen = Screen::ShareList(ShareListScreen::new(
                    shares,
                    self.active_share_hex.clone(),
                ));
            }
            Err(e) => self.screen.set_loading_error(e),
        }
        Task::none()
    }

    fn handle_import_result(
        &mut self,
        result: Result<(Vec<ShareEntry>, String), String>,
    ) -> Task<Message> {
        match result {
            Ok((shares, name)) => {
                self.resolve_active_share(&shares);
                self.screen = Screen::ShareList(ShareListScreen::new(
                    shares,
                    self.active_share_hex.clone(),
                ));
                self.set_toast(
                    format!("Share '{name}' imported successfully"),
                    ToastKind::Success,
                );
            }
            Err(e) => self.screen.set_loading_error(e),
        }
        Task::none()
    }

    fn handle_delete(&mut self, id: ShareIdentity) {
        let result = {
            let mut guard = lock_keep(&self.keep);
            let Some(keep) = guard.as_mut() else {
                return;
            };
            keep.frost_delete_share(&id.group_pubkey, id.identifier)
        };
        match result {
            Ok(()) => self.refresh_shares(),
            Err(e) => {
                if let Screen::ShareList(s) = &mut self.screen {
                    s.delete_confirm = None;
                }
                self.set_toast(friendly_err(e), ToastKind::Error);
            }
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
                                .map_err(friendly_err)?;
                            collect_shares(keep)
                        },
                    )
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::CreateResult,
        )
    }

    fn handle_generate_export(&mut self) -> Task<Message> {
        let (share, passphrase) = match &mut self.screen {
            Screen::Export(s) => {
                if s.loading || s.passphrase.chars().count() < MIN_EXPORT_PASSPHRASE_LEN {
                    return Task::none();
                }
                if *s.passphrase != *s.confirm_passphrase {
                    s.error = Some("Passphrases do not match".into());
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
                            .map_err(friendly_err)?;
                        let bech32 = export
                            .to_bech32()
                            .map(Zeroizing::new)
                            .map_err(friendly_err)?;
                        let frames: Vec<Zeroizing<String>> = export
                            .to_animated_frames(600)
                            .map_err(friendly_err)?
                            .into_iter()
                            .map(Zeroizing::new)
                            .collect();
                        Ok(ExportData { bech32, frames })
                    })
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::ExportGenerated,
        )
    }

    fn handle_export_generated(&mut self, result: Result<ExportData, String>) -> Task<Message> {
        match result {
            Ok(data) => {
                if let Screen::Export(s) = &mut self.screen {
                    s.set_export(data.bech32, data.frames);
                }
            }
            Err(e) => self.screen.set_loading_error(e),
        }
        Task::none()
    }

    fn modify_relay_config(
        &self,
        group_pubkey: [u8; 32],
        modify: impl FnOnce(&mut keep_core::RelayConfig) + Send + 'static,
    ) -> Task<Message> {
        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let mut guard = lock_keep(&keep_arc);
                    let keep = guard.as_mut().ok_or("Keep not available".to_string())?;
                    let mut config = keep
                        .get_relay_config_or_default(&group_pubkey)
                        .map_err(friendly_err)?;
                    modify(&mut config);
                    keep.store_relay_config(&config).map_err(friendly_err)?;
                    drop(guard);
                    load_relay_entries(&keep_arc)
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::RelaySaved,
        )
    }

    fn add_relay(
        &mut self,
        share_idx: usize,
        get_input: fn(&RelayScreen) -> &str,
        get_relays: fn(&RelayShareEntry) -> &[String],
        push_relay: impl FnOnce(&mut keep_core::RelayConfig, String) + Send + 'static,
    ) -> Task<Message> {
        let (group_pubkey, url) = match &mut self.screen {
            Screen::Relays(s) => {
                let input = get_input(s).to_owned();
                match relays::validate_and_normalize(&input) {
                    Ok(url) => {
                        if let Some(entry) = s.shares.get(share_idx) {
                            if get_relays(entry).contains(&url) {
                                s.error = Some("Relay already added".into());
                                return Task::none();
                            }
                            (entry.group_pubkey, url)
                        } else {
                            return Task::none();
                        }
                    }
                    Err(e) => {
                        s.error = Some(e);
                        return Task::none();
                    }
                }
            }
            _ => return Task::none(),
        };
        self.modify_relay_config(group_pubkey, |config| push_relay(config, url))
    }

    fn remove_relay(
        &self,
        share_idx: usize,
        url: String,
        remove: impl FnOnce(&mut keep_core::RelayConfig, &str) + Send + 'static,
    ) -> Task<Message> {
        let group_pubkey = match &self.screen {
            Screen::Relays(s) => match s.shares.get(share_idx) {
                Some(entry) => entry.group_pubkey,
                None => return Task::none(),
            },
            _ => return Task::none(),
        };
        self.modify_relay_config(group_pubkey, move |config| remove(config, &url))
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
                        let export = ShareExport::parse(&data).map_err(friendly_err)?;
                        let name = format!("imported-{}", export.identifier);
                        keep.frost_import_share(&export, &passphrase)
                            .map_err(friendly_err)?;
                        let shares = collect_shares(keep)?;
                        Ok((shares, name))
                    })
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::ImportResult,
        )
    }
}
