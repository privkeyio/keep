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
    cert_pin_store_corruption, cert_pins_path, collect_shares, default_bunker_relays, friendly_err,
    load_cert_pins, lock_keep, parse_hex_key, save_cert_pins, take_pending_nostrconnect,
    to_display_entry, with_keep_blocking, write_private_bytes,
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

/// How long a new approval prompt is on screen before Approve takes effect.
/// The next prompt can replace an answered or timed out card within the same
/// poll, under a click aimed at the card it replaced.
pub(crate) const APPROVE_SETTLE: Duration = Duration::from_secs(1);

static NEXT_APPROVAL_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub(crate) fn next_approval_id() -> u64 {
    NEXT_APPROVAL_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
const IMPORT_COOLDOWN: Duration = Duration::from_secs(5);
pub(crate) const MAX_BUNKER_LOG_ENTRIES: usize = 1000;
pub(crate) const MAX_ACTIVE_COORDINATIONS: usize = 64;

const DEFAULT_BUNKER_RELAYS: &[&str] = &["wss://bucket.coracle.social"];

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
    pub(crate) bunker_approval_tx: Option<crate::bunker_service::ApprovalReply>,
    pub(crate) bunker_pending_approval: Option<PendingApprovalDisplay>,
    pub(crate) bunker_approval_shown_at: Option<std::time::Instant>,
    pub(crate) bunker_pending_setup: Option<Arc<Mutex<Option<BunkerSetup>>>>,
    #[cfg(unix)]
    pub(crate) local_signer: Option<crate::local_signer_service::RunningLocalSigner>,
    #[cfg(unix)]
    pub(crate) local_signer_approval_tx: Option<std::sync::mpsc::Sender<bool>>,
    #[cfg(unix)]
    pub(crate) local_signer_pending_approval:
        Option<crate::screen::local_signer::PendingApprovalDisplay>,
    #[cfg(unix)]
    pub(crate) local_signer_approval_shown_at: Option<std::time::Instant>,
    #[cfg(unix)]
    pub(crate) local_signer_pending_setup: Option<crate::local_signer_service::PendingSetup>,
    pub(crate) nostrconnect_pending: Option<NostrConnectRequest>,
    pub(crate) proxy_enabled: bool,
    pub(crate) proxy_port: u16,
    /// The stored proxy setting could not be read, so no relay socket may
    /// open until it is set again.
    pub(crate) proxy_unreadable: bool,
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
    pub(crate) pending_psbt_signatures: Vec<crate::screen::wallet::PsbtPendingDisplay>,
    pub(crate) active_psbt_spend: Option<[u8; 32]>,
    import_return_to_nsec: bool,
    distribute_state: Option<distribute::State>,
    distribute_export_id: Option<u16>,
    scanner_recovery: Option<(recovery::State, usize)>,
    pending_vault_share: Option<VaultShareResult>,
    last_recovery_attempt: Option<Instant>,
    last_import_attempt: Option<Instant>,
    cached_share_count: usize,
    cached_nsec_count: usize,
    /// What the vault says about its audit logs, shown until acknowledged.
    audit_warnings: Vec<String>,
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
            bunker_approval_shown_at: None,
            bunker_pending_setup: None,
            #[cfg(unix)]
            local_signer: None,
            #[cfg(unix)]
            local_signer_approval_tx: None,
            #[cfg(unix)]
            local_signer_pending_approval: None,
            #[cfg(unix)]
            local_signer_approval_shown_at: None,
            #[cfg(unix)]
            local_signer_pending_setup: None,
            nostrconnect_pending: None,
            proxy_enabled: false,
            proxy_port: DEFAULT_PROXY_PORT,
            proxy_unreadable: true,
            has_tray: tray.is_some(),
            window_visible: tray.is_none()
                || !settings.start_minimized
                || !settings.minimize_to_tray,
            tray_last_connected: false,
            tray_last_bunker: false,
            scanner_rx: None,
            active_coordinations: HashMap::new(),
            peer_xpubs: HashMap::new(),
            pending_psbt_signatures: Vec::new(),
            active_psbt_spend: None,
            import_return_to_nsec: false,
            distribute_state: None,
            distribute_export_id: None,
            scanner_recovery: None,
            pending_vault_share: None,
            last_recovery_attempt: None,
            last_import_attempt: None,
            cached_share_count: 0,
            cached_nsec_count: 0,
            audit_warnings: Vec::new(),
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
                | Message::RejectPsbtSignatureResult(..)
                | Message::ApprovePsbtResult(..)
                | Message::CancelSpendResult(..)
                | Message::SpendStartedResult(..)
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
            | Message::WalletRegisterResult(..)
            | Message::RejectPsbtSignature(..)
            | Message::RejectPsbtSignatureResult(..)
            | Message::ApprovePsbtResult(..)
            | Message::CancelSpendResult(..)
            | Message::SpendStartedResult(..) => self.handle_wallet_global_message(message),

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
        let screen = if self.audit_warnings.is_empty() {
            screen
        } else {
            let warnings = self
                .audit_warnings
                .iter()
                .fold(column![].spacing(theme::space::XS), |col, w| {
                    col.push(text(w).size(theme::size::SMALL).color(iced::Color::WHITE))
                });
            let banner = container(
                column![
                    text("Audit log warning")
                        .size(theme::size::BODY)
                        .color(iced::Color::WHITE),
                    warnings,
                ]
                .spacing(theme::space::XS),
            )
            .style(theme::kill_switch_banner_style)
            .padding(theme::space::MD)
            .width(Length::Fill);
            column![banner, screen].into()
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
            bunker_approval_shown_at: None,
            bunker_pending_setup: None,
            #[cfg(unix)]
            local_signer: None,
            #[cfg(unix)]
            local_signer_approval_tx: None,
            #[cfg(unix)]
            local_signer_pending_approval: None,
            #[cfg(unix)]
            local_signer_approval_shown_at: None,
            #[cfg(unix)]
            local_signer_pending_setup: None,
            nostrconnect_pending: None,
            proxy_enabled: false,
            proxy_port: DEFAULT_PROXY_PORT,
            proxy_unreadable: false,
            has_tray,
            window_visible: !has_tray || !settings.start_minimized || !settings.minimize_to_tray,
            tray_last_connected: false,
            tray_last_bunker: false,
            scanner_rx: None,
            active_coordinations: HashMap::new(),
            peer_xpubs: HashMap::new(),
            pending_psbt_signatures: Vec::new(),
            active_psbt_spend: None,
            import_return_to_nsec: false,
            distribute_state: None,
            distribute_export_id: None,
            scanner_recovery: None,
            pending_vault_share: None,
            last_recovery_attempt: None,
            last_import_attempt: None,
            cached_share_count: 0,
            cached_nsec_count: 0,
            audit_warnings: Vec::new(),
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
    use std::net::{Ipv4Addr, SocketAddr};

    fn default_settings() -> Settings {
        Settings::default()
    }

    #[test]
    fn proxy_addr_refuses_a_setting_it_cannot_use() {
        let mut app = App::test_new(default_settings(), false);
        assert_eq!(app.proxy_addr(), Ok(None));

        app.proxy_enabled = true;
        app.proxy_port = 9050;
        assert_eq!(
            app.proxy_addr(),
            Ok(Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9050))))
        );

        app.proxy_port = 0;
        assert!(app.proxy_addr().unwrap_err().contains("no port"));
        assert!(app.network_config().is_err());

        app.proxy_enabled = false;
        app.proxy_unreadable = true;
        assert!(app.proxy_addr().unwrap_err().contains("could not be read"));
        assert!(app.network_config().is_err());
    }

    #[test]
    fn an_unreadable_proxy_setting_refuses_until_it_is_saved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        let mut keep = Keep::create(&path, "correct horse battery staple").unwrap();
        keep.set_proxy_config(&keep_core::ProxyConfig {
            enabled: true,
            port: 9050,
        })
        .unwrap();
        keep.lock();
        let mut app = App::test_new(default_settings(), false);
        app.keep_path = dir.path().to_path_buf();
        *app.keep.lock().unwrap() = Some(keep);

        app.load_config_from_vault();
        assert!(app.proxy_unreadable);
        assert!(app.proxy_addr().is_err());

        app.save_proxy_config();
        assert!(app.proxy_unreadable, "a failed save keeps refusing");

        app.keep
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .unlock("correct horse battery staple")
            .unwrap();
        app.proxy_enabled = true;
        app.proxy_port = 9050;
        app.save_proxy_config();
        assert!(!app.proxy_unreadable, "setting it again clears the refusal");
        app.proxy_unreadable = true;
        app.load_config_from_vault();
        assert!(!app.proxy_unreadable);
        assert_eq!(
            app.proxy_addr(),
            Ok(Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9050))))
        );
    }

    fn app_with_vault(proxy: keep_core::ProxyConfig) -> (App, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let keep = Keep::create(&dir.path().join("vault"), "correct horse battery staple").unwrap();
        keep.set_proxy_config(&proxy).unwrap();
        let mut app = App::test_new(default_settings(), false);
        app.keep_path = dir.path().to_path_buf();
        *app.keep.lock().unwrap() = Some(keep);
        (app, dir)
    }

    #[test]
    fn a_port_edit_does_not_stand_in_for_an_unreadable_proxy_setting() {
        use crate::screen::settings;
        let (mut app, _dir) = app_with_vault(keep_core::ProxyConfig {
            enabled: true,
            port: 9050,
        });
        app.proxy_unreadable = true;
        set_settings_screen(&mut app);
        let _ = app.handle_settings_message_new(settings::Message::ProxyPortChanged("9150".into()));
        assert!(app.proxy_unreadable, "still refusing");
        let stored = app
            .keep
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .get_proxy_config()
            .unwrap();
        assert!(stored.enabled && stored.port == 9050, "{stored:?}");

        let _ = app.handle_settings_message_new(settings::Message::ProxyToggled(true));
        assert!(!app.proxy_unreadable, "the toggle sets it again");
        let stored = app
            .keep
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .get_proxy_config()
            .unwrap();
        assert!(stored.enabled && stored.port == 9150, "{stored:?}");
    }

    #[test]
    fn a_legacy_proxy_moves_once_and_one_that_cannot_move_refuses() {
        let (mut app, dir) = app_with_vault(keep_core::ProxyConfig::default());
        let settings_json = dir.path().join("settings.json");
        std::fs::write(
            &settings_json,
            r#"{"minimize_to_tray":false,"proxy_enabled":true,"proxy_port":9150}"#,
        )
        .unwrap();
        app.load_config_from_vault();
        assert!(!app.proxy_unreadable);
        assert_eq!(
            app.proxy_addr(),
            Ok(Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9150))))
        );
        let left = std::fs::read_to_string(&settings_json).unwrap();
        assert!(!left.contains("proxy_"), "{left}");
        assert!(left.contains("minimize_to_tray"), "{left}");

        std::fs::write(
            &settings_json,
            r#"{"minimize_to_tray":false,"proxy_enabled":true,"proxy_port":0}"#,
        )
        .unwrap();
        app.load_config_from_vault();
        assert!(
            app.proxy_unreadable,
            "an on proxy that could not move refuses"
        );
        assert!(app.proxy_addr().is_err());
    }

    #[test]
    fn a_proxy_change_that_cannot_be_saved_is_not_applied() {
        use crate::screen::settings;
        let (mut app, _dir) = app_with_vault(keep_core::ProxyConfig::default());
        app.load_config_from_vault();
        set_settings_screen(&mut app);
        app.keep.lock().unwrap().as_mut().unwrap().lock();

        let _ = app.handle_settings_message_new(settings::Message::ProxyToggled(true));
        assert!(!app.proxy_enabled, "the stored setting is still off");

        app.proxy_enabled = true;
        let _ = app.handle_settings_message_new(settings::Message::ProxyPortChanged("9150".into()));
        assert_eq!(app.proxy_port, DEFAULT_PROXY_PORT);
    }

    #[test]
    fn locking_forgets_the_proxy_setting_until_the_next_read() {
        let (mut app, _dir) = app_with_vault(keep_core::ProxyConfig::default());
        app.load_config_from_vault();
        assert!(!app.proxy_unreadable);
        let _ = app.do_lock();
        assert!(app.proxy_unreadable);
        assert!(app.proxy_addr().is_err());
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
            app.settings.strict_cert_pinning,
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
    fn strict_pinning_toggle_updates_settings_and_screen_and_defaults_off() {
        use crate::screen::settings;
        let s = default_settings();
        assert!(
            !s.strict_cert_pinning,
            "strict pinning must be opt-in (default off)"
        );
        let mut app = App::test_new(s, false);
        set_settings_screen(&mut app);

        let _task = app.handle_settings_message_new(settings::Message::StrictPinningToggled(true));
        assert!(app.settings.strict_cert_pinning);
        if let Screen::Settings(scr) = &app.screen {
            assert!(scr.strict_cert_pinning);
        } else {
            panic!("expected settings screen");
        }

        let _task = app.handle_settings_message_new(settings::Message::StrictPinningToggled(false));
        assert!(!app.settings.strict_cert_pinning);
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
            id: 1,
            app_pubkey: "abc123".into(),
            app_name: "TestApp".into(),
            method: "sign_event".into(),
            event_kind: None,
            event_content: None,
            requested_permissions: None,
            http_auth: None,
        };
        app.notify_bunker_approval(&display);
    }

    use crate::bunker_service::ApprovalReply;

    fn bunker_prompt(id: u64) -> PendingApprovalDisplay {
        PendingApprovalDisplay {
            id,
            app_pubkey: format!("{id:064x}"),
            app_name: format!("client-{id}"),
            method: "sign_event".into(),
            event_kind: None,
            event_content: None,
            requested_permissions: None,
            http_auth: None,
        }
    }

    fn bunker_app() -> App {
        let mut app = App::test_new(default_settings(), true);
        app.window_visible = true;
        app.screen = Screen::Bunker(Box::new(crate::screen::bunker::State::new(vec![])));
        app
    }

    fn settle_bunker_prompt(app: &mut App) {
        app.bunker_approval_shown_at =
            Some(std::time::Instant::now() - std::time::Duration::from_secs(2));
    }

    // A click made on a card the next request has already replaced names
    // that card, and the replacement does not take it.
    #[test]
    fn a_bunker_answer_reaches_only_the_prompt_it_names() {
        use crate::screen::bunker::Message as B;
        let mut app = bunker_app();
        let (tx, rx) = std::sync::mpsc::channel();
        app.show_bunker_approval(bunker_prompt(2), ApprovalReply::new(tx));
        settle_bunker_prompt(&mut app);

        let _ = app.handle_bunker_message(B::Approve(1));
        let _ = app.handle_bunker_message(B::Reject(1));
        assert!(rx.try_recv().is_err(), "an answer for 1 reached 2");

        app.bunker_approval_timed_out(1);
        assert_eq!(app.bunker_pending_approval.as_ref().map(|p| p.id), Some(2));

        let _ = app.handle_bunker_message(B::Approve(2));
        assert_eq!(rx.try_recv(), Ok(true));
        assert!(app.bunker_pending_approval.is_none());
    }

    // Approve does nothing until the card has been on screen long enough to
    // be read. Reject is taken at once.
    #[test]
    fn a_new_bunker_prompt_ignores_approve_until_it_settles() {
        use crate::screen::bunker::Message as B;
        let mut app = bunker_app();
        let (tx, rx) = std::sync::mpsc::channel();
        app.show_bunker_approval(bunker_prompt(7), ApprovalReply::new(tx));

        let _ = app.handle_bunker_message(B::Approve(7));
        assert!(rx.try_recv().is_err());
        let _ = app.handle_bunker_message(B::Reject(7));
        assert_eq!(rx.try_recv(), Ok(false));
    }

    // A timed out request stops waiting, so its card is taken down rather
    // than left for a click that would reach nobody.
    #[test]
    fn a_bunker_timeout_clears_its_own_prompt() {
        let mut app = bunker_app();
        let (tx, _rx) = std::sync::mpsc::channel();
        app.show_bunker_approval(bunker_prompt(3), ApprovalReply::new(tx));
        app.bunker_approval_timed_out(3);
        assert!(app.bunker_pending_approval.is_none());
        assert!(app.bunker_approval_tx.is_none());
        if let Screen::Bunker(s) = &app.screen {
            assert!(s.pending_approval.is_none());
        }
    }

    // An approval that reaches no waiting request reports it, so the caller
    // does not widen the client's remembered access for it.
    #[test]
    fn an_approval_nobody_receives_is_reported_undelivered() {
        let mut app = bunker_app();
        let (tx, rx) = std::sync::mpsc::channel();
        app.show_bunker_approval(bunker_prompt(4), ApprovalReply::new(tx));
        settle_bunker_prompt(&mut app);
        drop(rx);
        assert_eq!(app.resolve_bunker_approval(4, true), Some(false));
        assert!(app.bunker_pending_approval.is_none());
    }

    // The duration picked on one card does not carry to the card that
    // replaces it.
    #[test]
    fn a_new_bunker_prompt_starts_from_the_default_duration() {
        use crate::screen::bunker::{Event, Message as B};
        let mut state = crate::screen::bunker::State::new(vec![]);
        state.approval_shown(bunker_prompt(1));
        assert!(state.update(B::SetApprovalDuration(1, 4)).is_none());
        state.approval_shown(bunker_prompt(2));
        assert!(state.update(B::SetApprovalDuration(1, 3)).is_none());
        assert!(matches!(
            state.update(B::Approve(2)),
            Some(Event::Approve {
                id: 2,
                duration_index: 0
            })
        ));
    }

    // Once a request stops waiting, an answer clicked after that reaches
    // nobody and is reported undelivered, so it grants nothing.
    #[test]
    fn an_answer_after_the_request_gave_up_is_undelivered() {
        let (tx, rx) = std::sync::mpsc::channel();
        let reply = ApprovalReply::new(tx);
        assert_eq!(
            crate::bunker_service::wait_for_answer(
                &rx,
                &reply,
                std::time::Duration::from_millis(10)
            ),
            None
        );
        assert!(!reply.answer(true));
        assert!(rx.try_recv().is_err());
    }

    // The screen sending as the request gives up: the request waits for the
    // send to finish and takes the answer, so the two never disagree.
    #[test]
    fn an_answer_sent_as_the_request_gives_up_is_taken() {
        let (tx, rx) = std::sync::mpsc::channel();
        let reply = ApprovalReply::new(tx);
        let screen = reply.clone();
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let sender = std::thread::spawn(move || {
            let mut slot = screen.0.lock().unwrap();
            locked_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
            slot.take().unwrap().send(true).unwrap();
        });
        locked_rx.recv().unwrap();
        assert_eq!(
            crate::bunker_service::wait_for_answer(
                &rx,
                &reply,
                std::time::Duration::from_millis(10)
            ),
            Some(true)
        );
        sender.join().unwrap();
    }

    // A request whose card can no longer be shown, its event dropped unread
    // when the bunker stopped, stops waiting at once instead of holding a
    // worker for the whole timeout.
    #[test]
    fn a_request_nobody_can_answer_stops_waiting() {
        let (tx, rx) = std::sync::mpsc::channel();
        let reply = ApprovalReply::new(tx);
        let event = reply.clone();
        drop(event);
        let started = std::time::Instant::now();
        assert_eq!(
            crate::bunker_service::wait_for_answer(&rx, &reply, std::time::Duration::from_secs(30)),
            None
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn an_answer_given_in_time_is_delivered() {
        let (tx, rx) = std::sync::mpsc::channel();
        let reply = ApprovalReply::new(tx);
        assert!(reply.answer(true));
        assert_eq!(
            crate::bunker_service::wait_for_answer(
                &rx,
                &reply,
                std::time::Duration::from_millis(10)
            ),
            Some(true)
        );
    }

    // Stopping the bunker refuses the request on the card and takes it down.
    #[test]
    fn stopping_the_bunker_refuses_and_clears_the_prompt() {
        let mut app = bunker_app();
        let (tx, rx) = std::sync::mpsc::channel();
        app.show_bunker_approval(bunker_prompt(5), ApprovalReply::new(tx));
        app.stop_bunker();
        assert_eq!(rx.try_recv(), Ok(false));
        assert!(app.bunker_pending_approval.is_none());
        assert!(app.bunker_approval_shown_at.is_none());
        assert!(app.bunker_approval_tx.is_none());
    }

    #[test]
    fn stopping_the_bunker_drops_a_pending_nostrconnect_request() {
        let mut app = bunker_app();
        let uri = format!(
            "nostrconnect://{}?relay=wss%3A%2F%2Frelay.example.com&secret=0123456789abcdef",
            nostr_sdk::Keys::generate().public_key().to_hex()
        );
        let _ = app.process_pending_nostrconnect(keep_nip46::parse_nostrconnect_uri(&uri).unwrap());
        app.stop_bunker();
        assert!(app.nostrconnect_pending.is_none());
        assert!(app.bunker_pending_approval.is_none());
    }

    // Showing a bunker request takes the card from a pending nostrconnect
    // request, so an answer to the new card cannot reach the old one.
    #[test]
    fn a_bunker_prompt_replaces_a_pending_nostrconnect_request() {
        let mut app = bunker_app();
        let uri = format!(
            "nostrconnect://{}?relay=wss%3A%2F%2Frelay.example.com&secret=0123456789abcdef",
            nostr_sdk::Keys::generate().public_key().to_hex()
        );
        let request = keep_nip46::parse_nostrconnect_uri(&uri).unwrap();
        let _ = app.process_pending_nostrconnect(request);
        assert!(app.nostrconnect_pending.is_some());
        let Screen::Bunker(s) = &app.screen else {
            panic!("the nostrconnect request did not open the bunker screen");
        };
        assert_eq!(
            s.pending_approval.as_ref().map(|p| p.id),
            app.bunker_pending_approval.as_ref().map(|p| p.id),
            "the nostrconnect card is not on screen"
        );
        let (tx, _rx) = std::sync::mpsc::channel();
        app.show_bunker_approval(bunker_prompt(9), ApprovalReply::new(tx));
        assert!(app.nostrconnect_pending.is_none());
        assert_eq!(app.bunker_pending_approval.as_ref().map(|p| p.id), Some(9));
    }

    #[cfg(unix)]
    fn local_prompt(id: u64) -> crate::screen::local_signer::PendingApprovalDisplay {
        crate::screen::local_signer::PendingApprovalDisplay {
            id,
            app_name: format!("client-{id}"),
            method: "sign_event".into(),
            event_kind: None,
            event_content: None,
            http_auth: None,
        }
    }

    // A click on a card the next prompt has already replaced names the card
    // it was made on, and the replacement does not take it.
    #[cfg(unix)]
    #[test]
    fn a_local_signer_answer_reaches_only_the_prompt_it_names() {
        let mut app = App::test_new(default_settings(), true);
        app.window_visible = true;
        let (tx, rx) = std::sync::mpsc::channel();
        app.show_local_signer_approval(local_prompt(2), tx);
        app.local_signer_approval_shown_at =
            Some(std::time::Instant::now() - std::time::Duration::from_secs(2));

        assert!(!app.resolve_local_signer_approval(1, true));
        assert!(!app.resolve_local_signer_approval(1, false));
        assert!(rx.try_recv().is_err(), "an answer for 1 reached 2");

        app.local_signer_approval_timed_out(1);
        assert_eq!(
            app.local_signer_pending_approval.as_ref().map(|p| p.id),
            Some(2)
        );

        assert!(app.resolve_local_signer_approval(2, true));
        assert_eq!(rx.try_recv(), Ok(true));
        assert!(app.local_signer_pending_approval.is_none());
    }

    // Approve does nothing until the prompt has been on screen long enough
    // to have been read, so a second click aimed at the previous card cannot
    // approve the one that replaced it. Reject is taken at once.
    #[cfg(unix)]
    #[test]
    fn a_new_local_signer_prompt_ignores_approve_until_it_settles() {
        let mut app = App::test_new(default_settings(), true);
        app.window_visible = true;
        let (tx, rx) = std::sync::mpsc::channel();
        app.show_local_signer_approval(local_prompt(7), tx);

        assert!(!app.resolve_local_signer_approval(7, true));
        assert!(rx.try_recv().is_err());
        assert!(app.resolve_local_signer_approval(7, false));
        assert_eq!(rx.try_recv(), Ok(false));
    }

    #[cfg(unix)]
    #[test]
    fn a_local_signer_timeout_clears_its_own_prompt() {
        let mut app = App::test_new(default_settings(), true);
        app.window_visible = true;
        let (tx, _rx) = std::sync::mpsc::channel();
        app.show_local_signer_approval(local_prompt(3), tx);
        app.local_signer_approval_timed_out(3);
        assert!(app.local_signer_pending_approval.is_none());
        assert!(app.local_signer_approval_tx.is_none());
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
            strict_cert_pinning: false,
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
