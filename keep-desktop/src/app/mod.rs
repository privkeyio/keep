// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

mod audit;
mod backup;
mod config;
mod helpers;
mod identity;
mod navigation;
mod relay;
mod settings;
mod shares;
mod util;
mod wallet;

pub use config::Settings;
pub(crate) use config::{load_settings, save_settings};
pub use util::set_pending_nostrconnect;
pub(crate) use util::{
    collect_shares, default_bunker_relays, friendly_err, load_cert_pins, lock_keep, parse_hex_key,
    save_cert_pins, take_pending_nostrconnect, to_display_entry, with_keep_blocking,
    write_private_bytes,
};

use std::collections::{HashMap, VecDeque};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keep_nip46::NostrConnectRequest;

use iced::widget::{button, column, container, row, text};
use iced::{Background, Element, Length, Subscription, Task};
use keep_core::Keep;
use tokio::sync::mpsc;
use tracing::error;
use zeroize::Zeroizing;

use crate::bunker_service::{BunkerSetup, RunningBunker};
use crate::frost::PendingRequestEntry;
use crate::message::{
    ConnectionStatus, EventLogEntry, FrostNodeMsg, Identity, Message, PeerEntry, PendingSignRequest,
};
use crate::screen::bunker::PendingApprovalDisplay;
use crate::screen::layout::SidebarState;
use crate::screen::unlock;
use crate::screen::Screen;
use crate::screen::{distribute, export, recovery};
use crate::theme;
use crate::tray::{TrayEvent, TrayState};

const AUTO_LOCK_SECS: u64 = 300;
const CLIPBOARD_CLEAR_SECS: u64 = 30;
const DEFAULT_PROXY_PORT: u16 = 9050;
const PROXY_SESSION_TIMEOUT: Duration = Duration::from_secs(90);
pub const MIN_EXPORT_PASSPHRASE_LEN: usize = 15;
const TOAST_DURATION_SECS: u64 = 5;
pub(crate) const SIGNING_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const MAX_PENDING_REQUESTS: usize = 10;
pub(crate) const MAX_REQUESTS_PER_PEER: usize = 3;
pub(crate) const RATE_LIMIT_WINDOW_SECS: u64 = 60;
pub(crate) const RATE_LIMIT_PER_PEER: usize = 30;
pub(crate) const RATE_LIMIT_GLOBAL: usize = 100;
pub(crate) const RECONNECT_BASE_MS: u64 = 200;
pub(crate) const RECONNECT_MAX_MS: u64 = 30_000;
pub(crate) const RECONNECT_MAX_ATTEMPTS: u32 = 10;
pub(crate) const BUNKER_APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);
const IMPORT_COOLDOWN: Duration = Duration::from_secs(5);
pub(crate) const MAX_BUNKER_LOG_ENTRIES: usize = 1000;
pub(crate) const MAX_ACTIVE_COORDINATIONS: usize = 64;

const DEFAULT_BUNKER_RELAYS: &[&str] = &["wss://relay.damus.io", "wss://relay.nsec.app"];

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

pub(crate) struct ActiveCoordination {
    pub group_pubkey: [u8; 32],
    pub network: String,
    pub is_initiator: bool,
}

type VaultShareResult = Result<(Zeroizing<String>, Zeroizing<String>), String>;

pub struct App {
    pub(crate) keep: Arc<Mutex<Option<Keep>>>,
    pub(crate) keep_path: PathBuf,
    pub(crate) screen: Screen,
    pub(crate) active_share_hex: Option<String>,
    identities: Vec<Identity>,
    identity_switcher_open: bool,
    delete_identity_confirm: Option<String>,
    last_activity: Instant,
    pub(crate) clipboard_clear_at: Option<Instant>,
    clipboard_has_secret: bool,
    copy_feedback_until: Option<Instant>,
    pub(crate) toast: Option<Toast>,
    toast_dismiss_at: Option<Instant>,
    pub(crate) frost_shutdown: Arc<Mutex<Option<mpsc::Sender<()>>>>,
    pub(crate) frost_events: Arc<Mutex<VecDeque<FrostNodeMsg>>>,
    pub(crate) pending_sign_requests: Arc<Mutex<Vec<PendingRequestEntry>>>,
    pub(crate) relay_urls: Vec<String>,
    pub(crate) frost_status: ConnectionStatus,
    pub(crate) frost_peers: Vec<PeerEntry>,
    pub(crate) frost_event_log: VecDeque<EventLogEntry>,
    pub(crate) saved_peer_policies: Vec<keep_core::PeerPolicyEntry>,
    pub(crate) pending_sign_display: Vec<PendingSignRequest>,
    pub(crate) frost_reconnect_attempts: u32,
    pub(crate) frost_reconnect_at: Option<Instant>,
    pub(crate) frost_node: Arc<Mutex<Option<Arc<keep_frost_net::KfpNode>>>>,
    pub(crate) frost_last_share: Option<crate::screen::shares::ShareEntry>,
    pub(crate) frost_last_relay_urls: Option<Vec<String>>,
    pub(crate) bunker: Option<RunningBunker>,
    pub(crate) bunker_relays: Vec<String>,
    pub(crate) bunker_approval_tx: Option<std::sync::mpsc::Sender<bool>>,
    pub(crate) bunker_pending_approval: Option<PendingApprovalDisplay>,
    pub(crate) bunker_pending_setup: Option<Arc<Mutex<Option<BunkerSetup>>>>,
    #[cfg(unix)]
    pub(crate) local_signer: Option<crate::local_signer_service::RunningLocalSigner>,
    #[cfg(unix)]
    pub(crate) local_signer_approval_tx: Option<std::sync::mpsc::Sender<bool>>,
    #[cfg(unix)]
    pub(crate) local_signer_pending_approval:
        Option<crate::screen::local_signer::PendingApprovalDisplay>,
    #[cfg(unix)]
    pub(crate) local_signer_pending_setup: Option<crate::local_signer_service::PendingSetup>,
    pub(crate) nostrconnect_pending: Option<NostrConnectRequest>,
    pub(crate) proxy_enabled: bool,
    pub(crate) proxy_port: u16,
    pub(crate) settings: Settings,
    pub(crate) kill_switch: Arc<AtomicBool>,
    pub(crate) tray: Option<TrayState>,
    pub(crate) has_tray: bool,
    pub(crate) window_visible: bool,
    tray_last_connected: bool,
    tray_last_bunker: bool,
    scanner_rx: Option<tokio::sync::mpsc::Receiver<crate::screen::scanner::CameraEvent>>,
    pub(crate) certificate_pins: Arc<Mutex<keep_frost_net::CertificatePinSet>>,
    pub(crate) pin_mismatch: Option<crate::message::PinMismatchInfo>,
    pub(crate) pin_mismatch_confirm: bool,
    pub(crate) bunker_cert_pin_failed: bool,
    pub(crate) active_coordinations: HashMap<[u8; 32], ActiveCoordination>,
    pub(crate) peer_xpubs: HashMap<u16, Vec<keep_frost_net::AnnouncedXpub>>,
    import_return_to_nsec: bool,
    distribute_state: Option<distribute::State>,
    distribute_export_id: Option<u16>,
    scanner_recovery: Option<(recovery::State, usize)>,
    pending_vault_share: Option<VaultShareResult>,
    last_recovery_attempt: Option<Instant>,
    last_import_attempt: Option<Instant>,
    cached_share_count: usize,
    cached_nsec_count: usize,
}

impl App {
    fn init(
        keep_path: PathBuf,
        screen: Screen,
        relay_urls: Vec<String>,
        settings: Settings,
    ) -> Self {
        let kill_switch = Arc::new(AtomicBool::new(settings.kill_switch_active));
        let certificate_pins = Arc::new(Mutex::new(load_cert_pins(&keep_path)));
        let tray = match TrayState::new(false) {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::warn!("Failed to create tray icon: {e}");
                None
            }
        };
        Self {
            keep: Arc::new(Mutex::new(None)),
            keep_path,
            screen,
            active_share_hex: None,
            identities: Vec::new(),
            identity_switcher_open: false,
            delete_identity_confirm: None,
            last_activity: Instant::now(),
            clipboard_clear_at: None,
            clipboard_has_secret: false,
            copy_feedback_until: None,
            toast: None,
            toast_dismiss_at: None,
            frost_shutdown: Arc::new(Mutex::new(None)),
            frost_events: Arc::new(Mutex::new(VecDeque::new())),
            pending_sign_requests: Arc::new(Mutex::new(Vec::new())),
            relay_urls,
            frost_status: ConnectionStatus::Disconnected,
            frost_peers: Vec::new(),
            frost_event_log: VecDeque::new(),
            saved_peer_policies: Vec::new(),
            pending_sign_display: Vec::new(),
            frost_reconnect_attempts: 0,
            frost_reconnect_at: None,
            frost_node: Arc::new(Mutex::new(None)),
            frost_last_share: None,
            frost_last_relay_urls: None,
            bunker: None,
            bunker_relays: default_bunker_relays(),
            bunker_approval_tx: None,
            bunker_pending_approval: None,
            bunker_pending_setup: None,
            #[cfg(unix)]
            local_signer: None,
            #[cfg(unix)]
            local_signer_approval_tx: None,
            #[cfg(unix)]
            local_signer_pending_approval: None,
            #[cfg(unix)]
            local_signer_pending_setup: None,
            nostrconnect_pending: None,
            proxy_enabled: false,
            proxy_port: DEFAULT_PROXY_PORT,
            has_tray: tray.is_some(),
            window_visible: tray.is_none()
                || !settings.start_minimized
                || !settings.minimize_to_tray,
            tray_last_connected: false,
            tray_last_bunker: false,
            scanner_rx: None,
            active_coordinations: HashMap::new(),
            peer_xpubs: HashMap::new(),
            import_return_to_nsec: false,
            distribute_state: None,
            distribute_export_id: None,
            scanner_recovery: None,
            pending_vault_share: None,
            last_recovery_attempt: None,
            last_import_attempt: None,
            cached_share_count: 0,
            cached_nsec_count: 0,
            settings,
            kill_switch,
            tray,
            certificate_pins,
            pin_mismatch: None,
            pin_mismatch_confirm: false,
            bunker_cert_pin_failed: false,
        }
    }

    pub fn new() -> (Self, Task<Message>) {
        let keep_path = match keep_core::default_keep_path() {
            Ok(p) => p,
            Err(_) => match dirs::home_dir() {
                Some(home) => home.join(".keep"),
                None => {
                    let screen = Screen::Unlock(unlock::State::with_error(
                        false,
                        "Cannot determine home directory. Set $HOME and restart.".into(),
                    ));
                    return (
                        Self::init(PathBuf::new(), screen, Vec::new(), Settings::default()),
                        Task::none(),
                    );
                }
            },
        };
        let vault_exists = keep_path.exists();
        let (settings, tray_migrated) = load_settings(&keep_path);
        let screen = Screen::Unlock(unlock::State::new(vault_exists));
        let start_minimized = settings.start_minimized;
        let mut app = Self::init(keep_path, screen, Vec::new(), settings);
        if tray_migrated {
            app.set_toast(
                "New option: enable minimize-to-tray in Settings".into(),
                ToastKind::Success,
            );
        }
        let task = if start_minimized && app.has_tray && app.settings.minimize_to_tray {
            iced::window::oldest()
                .and_then(|id| iced::window::set_mode(id, iced::window::Mode::Hidden))
        } else {
            Task::none()
        };
        (app, task)
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        let is_background = matches!(
            message,
            Message::Tick
                | Message::ScannerPoll
                | Message::UnlockResult(..)
                | Message::StartFreshResult(..)
                | Message::CreateResult(..)
                | Message::ExportGenerated(..)
                | Message::NcryptsecGenerated(..)
                | Message::RecoveryResult(..)
                | Message::VaultShareExported(..)
                | Message::ImportResult(..)
                | Message::ImportNsecResult(..)
                | Message::ImportNcryptsecResult(..)
                | Message::WalletsLoaded(..)
                | Message::WalletSessionStarted(..)
                | Message::WalletDescriptorProgress(..)
                | Message::WalletAnnounceResult(..)
                | Message::WalletRegisterResult(..)
                | Message::ConnectRelayResult(..)
                | Message::BunkerStartResult(..)
                | Message::BunkerRevokeResult(..)
                | Message::BunkerClientsLoaded(..)
                | Message::BunkerPermissionUpdated(..)
                | Message::AuditLoaded(..)
                | Message::AuditPageLoaded(..)
                | Message::AuditChainVerified(..)
                | Message::BackupResult(..)
                | Message::RestorePickFailed(..)
                | Message::RestoreFileLoaded(..)
                | Message::RestoreVerified(..)
                | Message::RestoreResult(..)
                | Message::KillSwitchDeactivateResult(..)
        );
        #[cfg(unix)]
        let is_background = is_background
            || matches!(
                message,
                Message::LocalSignerStartResult(..) | Message::LocalSignerRevokeResult(..)
            );
        if !is_background {
            self.last_activity = Instant::now();
        }

        match message {
            Message::Tick => self.handle_tick(),

            Message::Unlock(msg) => self.handle_unlock_message(msg),
            Message::UnlockResult(result) => self.handle_shares_result(result),
            Message::StartFreshResult(result) => {
                match result {
                    Ok(()) => {
                        *lock_keep(&self.keep) = None;
                        self.screen = Screen::Unlock(unlock::State::new(false));
                    }
                    Err(e) => {
                        if let Screen::Unlock(s) = &mut self.screen {
                            s.start_fresh_failed(e);
                        }
                    }
                }
                Task::none()
            }

            Message::GoToCreate
            | Message::GoToImport
            | Message::GoToExport(..)
            | Message::NavigateShares
            | Message::NavigateNsecKeys
            | Message::GoBack
            | Message::NavigateWallets
            | Message::NavigateRelay
            | Message::NavigateBunker
            | Message::NavigateSettings
            | Message::Lock => self.handle_navigation_message(message),
            #[cfg(unix)]
            Message::NavigateLocalSigner => self.handle_navigation_message(message),

            Message::ShareList(msg) => self.handle_share_list_message(msg),

            Message::NsecKeys(msg) => self.handle_nsec_keys_message(msg),

            Message::Create(msg) => self.handle_create_message(msg),
            Message::CreateResult(result) => self.handle_create_result(result),

            Message::Distribute(msg) => self.handle_distribute_message(msg),

            Message::Export(msg) => self.handle_export_message(msg),
            Message::ExportGenerated(result) => self.handle_export_generated(result),

            Message::GoToExportNcryptsec(hex) => self.handle_go_to_export_ncryptsec(hex),
            Message::ExportNcryptsec(msg) => self.handle_ncryptsec_export_message(msg),
            Message::NcryptsecGenerated(result) => self.handle_ncryptsec_generated(result),

            Message::Import(msg) => self.handle_import_message(msg),
            Message::Recovery(msg) => self.handle_recovery_message(msg),
            Message::RecoveryResult(result) => self.handle_recovery_result(result),
            Message::VaultShareExported(result) => self.handle_vault_share_exported(result),
            Message::ImportResult(result) => self.handle_import_result(result),
            Message::ImportNsecResult(result) => self.handle_import_nsec_result(result),
            Message::ImportNcryptsecResult(result) => self.handle_import_nsec_result(result),

            Message::Scanner(msg) => self.handle_scanner_message(msg),
            Message::ScannerPoll => {
                self.drain_scanner_events();
                Task::none()
            }

            Message::Wallet(msg) => self.handle_wallet_message(msg),
            Message::WalletsLoaded(..)
            | Message::WalletSessionStarted(..)
            | Message::WalletDescriptorProgress(..)
            | Message::WalletAnnounceResult(..)
            | Message::WalletRegisterResult(..) => self.handle_wallet_global_message(message),

            Message::Relay(msg) => self.handle_relay_message(msg),
            Message::ConnectRelayResult(result) => self.handle_connect_relay_result(result),

            Message::Bunker(msg) => self.handle_bunker_message(msg),
            Message::BunkerStartResult(result) => self.handle_bunker_start_result(result),
            Message::BunkerRevokeResult(result) => self.handle_bunker_revoke_result(result),
            Message::BunkerClientsLoaded(clients) => self.handle_bunker_clients_loaded(clients),
            Message::BunkerPermissionUpdated(result) => {
                self.handle_bunker_permission_updated(result)
            }

            #[cfg(unix)]
            Message::LocalSigner(msg) => self.handle_local_signer_message(msg),
            #[cfg(unix)]
            Message::LocalSignerStartResult(result) => {
                self.handle_local_signer_start_result(result)
            }
            #[cfg(unix)]
            Message::LocalSignerRevokeResult(result) => {
                self.handle_local_signer_revoke_result(result)
            }

            Message::SigningAudit(msg) => self.handle_signing_audit_message(msg),
            Message::NavigateAudit
            | Message::AuditLoaded(..)
            | Message::AuditPageLoaded(..)
            | Message::AuditChainVerified(..) => self.handle_audit_message(message),

            Message::ToggleIdentitySwitcher
            | Message::SwitchIdentity(..)
            | Message::RequestDeleteIdentity(..)
            | Message::ConfirmDeleteIdentity(..)
            | Message::CancelDeleteIdentity => self.handle_identity_message(message),

            Message::Settings(msg) => self.handle_settings_message_new(msg),
            Message::KillSwitchDeactivateResult(result) => {
                self.handle_kill_switch_deactivate_result(result)
            }

            Message::BackupResult(result) => self.handle_backup_result(result),
            Message::RestorePickFailed(e) => {
                self.set_toast(e, ToastKind::Error);
                Task::none()
            }
            Message::RestoreFileLoaded(name, data) => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.restore_file_loaded(name, data);
                }
                Task::none()
            }
            Message::RestoreVerified(result) => self.handle_restore_verified(result),
            Message::RestoreResult(result) => self.handle_restore_result(result),

            Message::CertPinMismatchDismiss
            | Message::CertPinMismatchClearAndRetry
            | Message::CertPinMismatchConfirmClear => self.handle_cert_pin_message(message),

            Message::WindowCloseRequested(id) => self.handle_window_close(id),
        }
    }

    fn handle_tick(&mut self) -> Task<Message> {
        if self.settings.auto_lock_secs > 0
            && self.last_activity.elapsed() >= Duration::from_secs(self.settings.auto_lock_secs)
            && !matches!(self.screen, Screen::Unlock(_))
        {
            return self.do_lock();
        }
        let now = Instant::now();
        if self.clipboard_clear_at.is_some_and(|t| now >= t) {
            self.clipboard_clear_at = None;
            self.clipboard_has_secret = false;
            return iced::clipboard::write(String::new());
        }
        if let Screen::Recovery(s) = &mut self.screen {
            if s.has_active_timer() {
                s.update(recovery::Message::AutoClearTick);
            }
        }
        if let Some((ref mut state, _)) = self.scanner_recovery {
            if state.has_active_timer() {
                state.update(recovery::Message::AutoClearTick);
            }
        }
        if self.copy_feedback_until.is_some_and(|t| now >= t) {
            self.copy_feedback_until = None;
            match &mut self.screen {
                Screen::Export(s) => s.copied = false,
                Screen::ExportNcryptsec(s) => s.copied = false,
                _ => {}
            }
        }
        if self.toast_dismiss_at.is_some_and(|t| now >= t) {
            self.toast = None;
            self.toast_dismiss_at = None;
        }
        if self.frost_reconnect_at.is_some_and(|t| now >= t) {
            self.frost_reconnect_at = None;
            let frost_task = self.drain_frost_events();
            let reconnect_task = self.handle_reconnect_relay();
            return Task::batch([frost_task, reconnect_task]);
        }
        let frost_task = self.drain_frost_events();
        let bunker_task = self.poll_bunker_events();
        #[cfg(unix)]
        self.poll_local_signer_events();
        self.sync_tray_status();
        let tray_events = self.poll_tray_events();
        let mut tasks: Vec<_> = tray_events
            .into_iter()
            .map(|event| match event {
                TrayEvent::ShowWindow => self.handle_tray_show(),
                TrayEvent::ToggleBunker => self.handle_tray_toggle_bunker(),
                TrayEvent::Lock => self.do_lock(),
                TrayEvent::Quit => self.handle_tray_quit(),
            })
            .collect();
        tasks.push(frost_task);
        tasks.push(bunker_task);
        Task::batch(tasks)
    }

    fn handle_unlock_message(&mut self, msg: unlock::Message) -> Task<Message> {
        let screen = match &mut self.screen {
            Screen::Unlock(s) => s,
            _ => return Task::none(),
        };
        let Some(event) = screen.update(msg) else {
            return Task::none();
        };
        match event {
            unlock::Event::Unlock {
                password,
                vault_exists,
            } => {
                let path = self.keep_path.clone();
                let keep_arc = self.keep.clone();
                Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            let result = std::panic::catch_unwind(AssertUnwindSafe(
                                || -> Result<_, String> {
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
                                },
                            ));
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
            unlock::Event::StartFresh { password } => {
                let path = self.keep_path.clone();
                Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            let result = std::panic::catch_unwind(AssertUnwindSafe(
                                || -> Result<(), String> {
                                    let keep = Keep::open(&path).map_err(friendly_err)?;
                                    keep.verify_password(&password).map_err(friendly_err)?;
                                    drop(keep);
                                    let meta = std::fs::symlink_metadata(&path).map_err(|e| {
                                        format!("Failed to read vault metadata: {e}")
                                    })?;
                                    if meta.is_symlink() {
                                        return Err(
                                            "Vault path is a symlink; refusing to delete".into()
                                        );
                                    }
                                    std::fs::remove_dir_all(&path)
                                        .map_err(|e| format!("Failed to remove vault: {e}"))
                                },
                            ));
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
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let pending_count = self.pending_sign_display.len();
        let sidebar_state = SidebarState {
            identities: &self.identities,
            active_identity: self.active_share_hex.as_deref(),
            switcher_open: self.identity_switcher_open,
            delete_confirm: self.delete_identity_confirm.as_deref(),
        };
        let share_count = if self.cached_share_count > 0 {
            Some(self.cached_share_count)
        } else {
            None
        };
        let nsec_count = if self.cached_nsec_count > 0 {
            Some(self.cached_nsec_count)
        } else {
            None
        };
        let screen = self.screen.view(
            &sidebar_state,
            share_count,
            nsec_count,
            pending_count,
            self.settings.kill_switch_active,
        );
        let screen = if let Some(ref mismatch) = self.pin_mismatch {
            let warning = container(
                column![
                    text("Certificate Pin Mismatch")
                        .size(theme::size::HEADING)
                        .color(theme::color::ERROR),
                    text(format!(
                        "The certificate for {} has changed. This could indicate a security issue or a legitimate certificate rotation.",
                        mismatch.hostname
                    ))
                    .size(theme::size::BODY),
                    text(format!(
                        "Expected: {}...  Actual: {}...",
                        mismatch.expected.get(..16).unwrap_or(&mismatch.expected),
                        mismatch.actual.get(..16).unwrap_or(&mismatch.actual),
                    ))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                    if self.pin_mismatch_confirm {
                        row![
                            text("Clear pin and reconnect?")
                                .size(theme::size::BODY)
                                .color(theme::color::ERROR),
                            iced::widget::Space::new().width(Length::Fill),
                            button(text("Yes, Clear").size(theme::size::SMALL))
                                .on_press(Message::CertPinMismatchConfirmClear)
                                .style(theme::danger_button)
                                .padding([theme::space::SM, theme::space::MD]),
                            button(text("Cancel").size(theme::size::SMALL))
                                .on_press(Message::CertPinMismatchDismiss)
                                .style(theme::secondary_button)
                                .padding([theme::space::SM, theme::space::MD]),
                        ]
                        .spacing(theme::space::SM)
                        .align_y(iced::Alignment::Center)
                    } else {
                        row![
                            button(text("Clear Pin & Retry").size(theme::size::SMALL))
                                .on_press(Message::CertPinMismatchClearAndRetry)
                                .style(theme::danger_button)
                                .padding([theme::space::SM, theme::space::MD]),
                            button(text("Dismiss").size(theme::size::SMALL))
                                .on_press(Message::CertPinMismatchDismiss)
                                .style(theme::secondary_button)
                                .padding([theme::space::SM, theme::space::MD]),
                        ]
                        .spacing(theme::space::SM)
                    },
                ]
                .spacing(theme::space::SM),
            )
            .style(theme::warning_style)
            .padding(theme::space::LG)
            .width(Length::Fill);
            column![warning, screen].into()
        } else {
            screen
        };
        let Some(toast) = &self.toast else {
            return screen;
        };
        let bg_color = match toast.kind {
            ToastKind::Success => theme::color::SUCCESS,
            ToastKind::Error => theme::color::ERROR,
        };
        let banner = container(
            text(&toast.message)
                .size(theme::size::BODY)
                .color(iced::Color::WHITE),
        )
        .padding([theme::space::SM, theme::space::LG])
        .width(Length::Fill)
        .style(move |_theme: &iced::Theme| container::Style {
            background: Some(Background::Color(bg_color)),
            ..Default::default()
        });
        column![banner, screen].into()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let mut subs = vec![
            iced::window::close_requests().map(Message::WindowCloseRequested),
            iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick),
        ];

        if matches!(self.screen, Screen::Unlock(_)) {
            return Subscription::batch(subs);
        }

        if matches!(
            self.screen,
            Screen::Create(_)
                | Screen::Export(_)
                | Screen::ExportNcryptsec(_)
                | Screen::Import(_)
                | Screen::Scanner(_)
        ) {
            subs.push(iced::keyboard::listen().filter_map(|event| match event {
                iced::keyboard::Event::KeyPressed {
                    key: iced::keyboard::Key::Named(iced::keyboard::key::Named::Escape),
                    ..
                } => Some(Message::GoBack),
                _ => None,
            }));
        }

        if matches!(self.screen, Screen::Scanner(_)) {
            subs.push(iced::time::every(Duration::from_millis(33)).map(|_| Message::ScannerPoll));
        }

        if let Screen::Export(s) = &self.screen {
            if s.is_animated() {
                subs.push(
                    iced::time::every(Duration::from_millis(800))
                        .map(|_| Message::Export(export::Message::AdvanceFrame)),
                );
            }
        }

        Subscription::batch(subs)
    }

    #[cfg(test)]
    fn test_new(settings: Settings, has_tray: bool) -> Self {
        let keep_path = PathBuf::from("/tmp/keep-test-nonexistent");
        let screen = Screen::Unlock(crate::screen::unlock::State::new(false));
        let kill_switch = Arc::new(AtomicBool::new(settings.kill_switch_active));
        Self {
            keep: Arc::new(Mutex::new(None)),
            keep_path,
            screen,
            active_share_hex: None,
            identities: Vec::new(),
            identity_switcher_open: false,
            delete_identity_confirm: None,
            last_activity: Instant::now(),
            clipboard_clear_at: None,
            clipboard_has_secret: false,
            copy_feedback_until: None,
            toast: None,
            toast_dismiss_at: None,
            frost_shutdown: Arc::new(Mutex::new(None)),
            frost_events: Arc::new(Mutex::new(VecDeque::new())),
            pending_sign_requests: Arc::new(Mutex::new(Vec::new())),
            relay_urls: Vec::new(),
            frost_status: ConnectionStatus::Disconnected,
            frost_peers: Vec::new(),
            frost_event_log: VecDeque::new(),
            saved_peer_policies: Vec::new(),
            pending_sign_display: Vec::new(),
            frost_reconnect_attempts: 0,
            frost_reconnect_at: None,
            frost_node: Arc::new(Mutex::new(None)),
            frost_last_share: None,
            frost_last_relay_urls: None,
            bunker: None,
            bunker_relays: Vec::new(),
            bunker_approval_tx: None,
            bunker_pending_approval: None,
            bunker_pending_setup: None,
            #[cfg(unix)]
            local_signer: None,
            #[cfg(unix)]
            local_signer_approval_tx: None,
            #[cfg(unix)]
            local_signer_pending_approval: None,
            #[cfg(unix)]
            local_signer_pending_setup: None,
            nostrconnect_pending: None,
            proxy_enabled: false,
            proxy_port: DEFAULT_PROXY_PORT,
            has_tray,
            window_visible: !has_tray || !settings.start_minimized || !settings.minimize_to_tray,
            tray_last_connected: false,
            tray_last_bunker: false,
            scanner_rx: None,
            active_coordinations: HashMap::new(),
            peer_xpubs: HashMap::new(),
            import_return_to_nsec: false,
            distribute_state: None,
            distribute_export_id: None,
            scanner_recovery: None,
            pending_vault_share: None,
            last_recovery_attempt: None,
            last_import_attempt: None,
            cached_share_count: 0,
            cached_nsec_count: 0,
            settings,
            kill_switch,
            tray: None,
            certificate_pins: Arc::new(Mutex::new(keep_frost_net::CertificatePinSet::new())),
            pin_mismatch: None,
            pin_mismatch_confirm: false,
            bunker_cert_pin_failed: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screen::bunker::PendingApprovalDisplay;

    fn default_settings() -> Settings {
        Settings::default()
    }

    #[test]
    fn window_close_with_minimize_to_tray_hides_window() {
        let mut settings = default_settings();
        settings.minimize_to_tray = true;
        let mut app = App::test_new(settings, true);
        app.window_visible = true;

        assert!(app.settings.minimize_to_tray);
        assert!(app.has_tray);

        let fake_id = iced::window::Id::unique();
        let _task = app.handle_window_close(fake_id);

        assert!(!app.window_visible);
    }

    #[test]
    fn window_close_without_minimize_to_tray_exits() {
        let mut settings = default_settings();
        settings.minimize_to_tray = false;
        let mut app = App::test_new(settings, false);
        app.window_visible = true;

        let fake_id = iced::window::Id::unique();
        let _task = app.handle_window_close(fake_id);

        assert!(app.window_visible);
    }

    #[test]
    fn start_minimized_sets_window_hidden_when_tray_present() {
        let mut settings = default_settings();
        settings.start_minimized = true;
        settings.minimize_to_tray = true;
        let app = App::test_new(settings, true);
        assert!(!app.window_visible);
    }

    #[test]
    fn start_minimized_without_minimize_to_tray_keeps_window_visible() {
        let mut settings = default_settings();
        settings.start_minimized = true;
        settings.minimize_to_tray = false;
        let app = App::test_new(settings, true);
        assert!(app.window_visible);
    }

    #[test]
    fn start_minimized_without_tray_keeps_window_visible() {
        let mut settings = default_settings();
        settings.start_minimized = true;
        let app = App::test_new(settings, false);
        assert!(app.window_visible);
    }

    #[test]
    fn start_not_minimized_window_visible() {
        let settings = default_settings();
        let app = App::test_new(settings, true);
        assert!(app.window_visible);
    }

    #[test]
    fn tray_show_when_hidden_sets_visible() {
        let mut app = App::test_new(default_settings(), true);
        app.window_visible = false;
        let _task = app.handle_tray_show();
        assert!(app.window_visible);
    }

    #[test]
    fn tray_show_when_already_visible_stays_visible() {
        let mut app = App::test_new(default_settings(), true);
        app.window_visible = true;
        let _task = app.handle_tray_show();
        assert!(app.window_visible);
    }

    fn set_settings_screen(app: &mut App) {
        use crate::screen::settings::SettingsScreen;
        app.screen = Screen::Settings(SettingsScreen::new(
            app.settings.auto_lock_secs,
            app.settings.clipboard_clear_secs,
            app.keep_path.display().to_string(),
            app.proxy_enabled,
            app.proxy_port,
            app.settings.kill_switch_active,
            app.settings.minimize_to_tray,
            app.settings.start_minimized,
            false,
            Vec::new(),
        ));
    }

    #[test]
    fn disable_minimize_to_tray_while_hidden_reappears_window() {
        use crate::screen::settings;
        let mut s = default_settings();
        s.minimize_to_tray = true;
        let mut app = App::test_new(s, true);
        app.window_visible = false;
        set_settings_screen(&mut app);

        let _task =
            app.handle_settings_message_new(settings::Message::MinimizeToTrayToggled(false));

        assert!(app.window_visible);
        assert!(!app.settings.minimize_to_tray);
    }

    #[test]
    fn disable_minimize_to_tray_while_visible_no_change() {
        use crate::screen::settings;
        let mut s = default_settings();
        s.minimize_to_tray = true;
        let mut app = App::test_new(s, true);
        app.window_visible = true;
        set_settings_screen(&mut app);

        let _task =
            app.handle_settings_message_new(settings::Message::MinimizeToTrayToggled(false));

        assert!(app.window_visible);
        assert!(!app.settings.minimize_to_tray);
    }

    #[test]
    fn enable_minimize_to_tray_setting() {
        use crate::screen::settings;
        let mut s = default_settings();
        s.minimize_to_tray = false;
        let mut app = App::test_new(s, true);
        app.window_visible = true;
        set_settings_screen(&mut app);

        let _task = app.handle_settings_message_new(settings::Message::MinimizeToTrayToggled(true));

        assert!(app.settings.minimize_to_tray);
        assert!(app.window_visible);
    }

    #[test]
    fn enable_start_minimized_setting() {
        use crate::screen::settings;
        let mut s = default_settings();
        s.start_minimized = false;
        let mut app = App::test_new(s, true);
        set_settings_screen(&mut app);

        let _task = app.handle_settings_message_new(settings::Message::StartMinimizedToggled(true));

        assert!(app.settings.start_minimized);
    }

    #[test]
    fn disable_start_minimized_setting() {
        use crate::screen::settings;
        let mut s = default_settings();
        s.start_minimized = true;
        let mut app = App::test_new(s, true);
        set_settings_screen(&mut app);

        let _task =
            app.handle_settings_message_new(settings::Message::StartMinimizedToggled(false));

        assert!(!app.settings.start_minimized);
    }

    #[test]
    fn poll_tray_events_with_no_tray_returns_empty() {
        let app = App::test_new(default_settings(), false);
        let events = app.poll_tray_events();
        assert!(events.is_empty());
    }

    #[test]
    fn sync_tray_status_no_tray_does_not_panic() {
        let mut app = App::test_new(default_settings(), false);
        app.sync_tray_status();
    }

    #[test]
    fn sync_tray_connected_status_tracks_state() {
        let mut app = App::test_new(default_settings(), false);
        assert!(!app.tray_last_connected);

        app.frost_status = ConnectionStatus::Connected;
        app.sync_tray_status();
        assert!(!app.tray_last_connected);
    }

    #[test]
    fn notify_sign_request_only_when_hidden() {
        let mut app = App::test_new(default_settings(), true);
        app.window_visible = true;

        let req = PendingSignRequest {
            id: "test".into(),
            message_preview: "preview".into(),
            from_peer: 1,
            timestamp: 0,
        };
        app.notify_sign_request(&req);
    }

    #[test]
    fn notify_bunker_approval_only_when_hidden() {
        let mut app = App::test_new(default_settings(), true);
        app.window_visible = true;

        let display = PendingApprovalDisplay {
            app_pubkey: "abc123".into(),
            app_name: "TestApp".into(),
            method: "sign_event".into(),
            event_kind: None,
            event_content: None,
            requested_permissions: None,
        };
        app.notify_bunker_approval(&display);
    }

    #[test]
    fn tray_quit_disconnects_and_stops_bunker() {
        let mut app = App::test_new(default_settings(), true);
        app.window_visible = true;
        let _task = app.handle_tray_quit();
    }

    #[test]
    fn tray_toggle_bunker_locked_shows_error() {
        let mut app = App::test_new(default_settings(), true);
        app.window_visible = false;
        let _task = app.handle_tray_toggle_bunker();
        assert!(app.toast.is_some());
        let toast = app.toast.as_ref().unwrap();
        assert_eq!(toast.message, "Vault is locked");
        assert!(app.window_visible);
    }

    #[test]
    fn default_settings_minimize_to_tray_off() {
        let s = Settings::default();
        assert!(!s.minimize_to_tray);
        assert!(!s.start_minimized);
    }

    #[test]
    fn settings_serialize_deserialize_roundtrip() {
        let s = Settings {
            auto_lock_secs: 60,
            clipboard_clear_secs: 10,
            kill_switch_active: false,
            minimize_to_tray: false,
            start_minimized: true,
            bunker_auto_start: false,
            local_signer_auto_start: false,
        };
        let json = serde_json::to_string(&s).unwrap();
        let parsed: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.auto_lock_secs, 60);
        assert_eq!(parsed.clipboard_clear_secs, 10);
        assert!(!parsed.minimize_to_tray);
        assert!(parsed.start_minimized);
        assert!(!parsed.local_signer_auto_start);
    }

    #[test]
    fn settings_missing_tray_fields_get_defaults() {
        let json = r#"{"auto_lock_secs":300,"clipboard_clear_secs":30}"#;
        let parsed: Settings = serde_json::from_str(json).unwrap();
        assert!(!parsed.minimize_to_tray);
        assert!(!parsed.start_minimized);
    }

    #[test]
    fn window_close_minimize_to_tray_with_no_tray_exits() {
        let mut settings = default_settings();
        settings.minimize_to_tray = true;
        let mut app = App::test_new(settings, false);
        app.window_visible = true;
        assert!(!app.has_tray);

        let fake_id = iced::window::Id::unique();
        let _task = app.handle_window_close(fake_id);
        assert!(app.window_visible);
    }
}
