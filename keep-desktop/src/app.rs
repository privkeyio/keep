// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use keep_nip46::NostrConnectRequest;

use iced::widget::{button, column, container, row, text};
use iced::{Background, Element, Length, Subscription, Task};
use keep_core::frost::ShareExport;
use keep_core::relay::{normalize_relay_url, validate_relay_url, MAX_RELAYS};
use keep_core::Keep;
use tokio::sync::mpsc;
use tracing::error;
use zeroize::Zeroizing;

use crate::bunker_service::{BunkerSetup, RunningBunker};
use crate::frost::PendingRequestEntry;
use crate::message::{
    AuditLoadResult, ConnectionStatus, ExportData, FrostNodeMsg, Identity, IdentityKind, Message,
    PeerEntry, PendingSignRequest, ShareIdentity,
};
use crate::screen::bunker::PendingApprovalDisplay;
use crate::screen::create::CreateScreen;
use crate::screen::export::ExportScreen;
use crate::screen::export_ncryptsec::ExportNcryptsecScreen;
use crate::screen::import::{ImportMode, ImportScreen};
use crate::screen::layout::SidebarState;
use crate::screen::relay::RelayScreen;
use crate::screen::settings::SettingsScreen;
use crate::screen::shares::{ShareEntry, ShareListScreen};
use crate::screen::signing_audit::{AuditDisplayEntry, ChainStatus, SigningAuditScreen};
use crate::screen::unlock::UnlockScreen;
use crate::screen::wallet::{
    DescriptorProgress, SetupPhase, SetupState, TierConfig, WalletEntry, WalletScreen,
};
use crate::screen::Screen;
use crate::theme;
use crate::tray::{TrayEvent, TrayState};

static PENDING_NOSTRCONNECT: OnceLock<Mutex<Option<NostrConnectRequest>>> = OnceLock::new();

pub fn set_pending_nostrconnect(request: Option<NostrConnectRequest>) {
    let cell = PENDING_NOSTRCONNECT.get_or_init(|| Mutex::new(None));
    match cell.lock() {
        Ok(mut guard) => *guard = request,
        Err(e) => {
            tracing::warn!("nostrconnect mutex poisoned, recovering");
            *e.into_inner() = request;
        }
    }
}

fn take_pending_nostrconnect() -> Option<NostrConnectRequest> {
    let cell = PENDING_NOSTRCONNECT.get()?;
    match cell.lock() {
        Ok(mut guard) => guard.take(),
        Err(e) => e.into_inner().take(),
    }
}

const AUTO_LOCK_SECS: u64 = 300;
const CLIPBOARD_CLEAR_SECS: u64 = 30;
const DEFAULT_PROXY_PORT: u16 = 9050;
const PROXY_SESSION_TIMEOUT: Duration = Duration::from_secs(90);
const MIN_PASSWORD_LEN: usize = 8;
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
pub(crate) const MAX_BUNKER_LOG_ENTRIES: usize = 1000;

const DEFAULT_BUNKER_RELAYS: &[&str] = &["wss://relay.damus.io", "wss://relay.nsec.app"];

fn default_bunker_relays() -> Vec<String> {
    DEFAULT_BUNKER_RELAYS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

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
    pub(crate) keep: Arc<Mutex<Option<Keep>>>,
    pub(crate) keep_path: PathBuf,
    pub(crate) screen: Screen,
    pub(crate) active_share_hex: Option<String>,
    identities: Vec<Identity>,
    identity_switcher_open: bool,
    delete_identity_confirm: Option<String>,
    last_activity: Instant,
    pub(crate) clipboard_clear_at: Option<Instant>,
    copy_feedback_until: Option<Instant>,
    pub(crate) toast: Option<Toast>,
    toast_dismiss_at: Option<Instant>,
    pub(crate) frost_shutdown: Arc<Mutex<Option<mpsc::Sender<()>>>>,
    pub(crate) frost_events: Arc<Mutex<VecDeque<FrostNodeMsg>>>,
    pub(crate) pending_sign_requests: Arc<Mutex<Vec<PendingRequestEntry>>>,
    pub(crate) relay_urls: Vec<String>,
    pub(crate) frost_status: ConnectionStatus,
    pub(crate) frost_peers: Vec<PeerEntry>,
    pub(crate) pending_sign_display: Vec<PendingSignRequest>,
    pub(crate) frost_reconnect_attempts: u32,
    pub(crate) frost_reconnect_at: Option<Instant>,
    pub(crate) frost_node: Arc<Mutex<Option<Arc<keep_frost_net::KfpNode>>>>,
    pub(crate) frost_last_share: Option<ShareEntry>,
    pub(crate) frost_last_relay_urls: Option<Vec<String>>,
    pub(crate) bunker: Option<RunningBunker>,
    pub(crate) bunker_relays: Vec<String>,
    pub(crate) bunker_approval_tx: Option<std::sync::mpsc::Sender<bool>>,
    pub(crate) bunker_pending_approval: Option<PendingApprovalDisplay>,
    pub(crate) bunker_pending_setup: Option<Arc<Mutex<Option<BunkerSetup>>>>,
    pub(crate) nostrconnect_pending: Option<NostrConnectRequest>,
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
}

pub(crate) fn lock_keep(
    keep: &Arc<Mutex<Option<Keep>>>,
) -> std::sync::MutexGuard<'_, Option<Keep>> {
    match keep.lock() {
        Ok(guard) => guard,
        Err(e) => {
            let mut guard = e.into_inner();
            if let Some(ref mut k) = *guard {
                let _ = std::panic::catch_unwind(AssertUnwindSafe(|| k.lock()));
            }
            *guard = None;
            guard
        }
    }
}

pub(crate) fn friendly_err(e: keep_core::error::KeepError) -> String {
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

fn to_display_entry(e: keep_core::audit::SigningAuditEntry) -> AuditDisplayEntry {
    AuditDisplayEntry {
        timestamp: e.timestamp,
        request_type: e.request_type.to_string(),
        decision: e.decision.to_string(),
        was_automatic: e.was_automatic,
        caller: e.caller,
        caller_name: e.caller_name,
        event_kind: e.event_kind,
    }
}

fn collect_shares(keep: &Keep) -> Result<Vec<ShareEntry>, String> {
    keep.frost_list_shares()
        .map(|stored| stored.iter().map(ShareEntry::from_stored).collect())
        .map_err(friendly_err)
}

pub(crate) fn with_keep_blocking<T: Send + 'static>(
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

fn relay_config_path(keep_path: &std::path::Path) -> PathBuf {
    keep_path.join("relays.json")
}

fn relay_config_path_for(keep_path: &std::path::Path, pubkey_hex: &str) -> PathBuf {
    keep_path.join(format!("relays-{pubkey_hex}.json"))
}

fn bunker_relay_config_path(keep_path: &std::path::Path) -> PathBuf {
    keep_path.join("bunker-relays.json")
}

fn bunker_relay_config_path_for(keep_path: &std::path::Path, pubkey_hex: &str) -> PathBuf {
    keep_path.join(format!("bunker-relays-{pubkey_hex}.json"))
}

fn cert_pins_path(keep_path: &std::path::Path) -> PathBuf {
    keep_path.join("cert-pins.json")
}

fn load_cert_pins(keep_path: &std::path::Path) -> keep_frost_net::CertificatePinSet {
    let path = cert_pins_path(keep_path);
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return keep_frost_net::CertificatePinSet::new();
    };
    let map: std::collections::HashMap<String, String> =
        serde_json::from_str(&contents).unwrap_or_default();
    let mut pins = keep_frost_net::CertificatePinSet::new();
    for (hostname, hex_hash) in map {
        let Ok(bytes) = hex::decode(&hex_hash) else {
            continue;
        };
        let Ok(hash) = <[u8; 32]>::try_from(bytes.as_slice()) else {
            continue;
        };
        pins.add_pin(hostname, hash);
    }
    pins
}

pub(crate) fn save_cert_pins(
    keep_path: &std::path::Path,
    pins: &keep_frost_net::CertificatePinSet,
) {
    let path = cert_pins_path(keep_path);
    let map: std::collections::HashMap<&String, String> = pins
        .pins()
        .iter()
        .map(|(k, v)| (k, hex::encode(v)))
        .collect();
    if let Ok(json) = serde_json::to_string_pretty(&map) {
        if let Err(e) = write_private(&path, &json) {
            tracing::error!("Failed to save certificate pins: {e}");
        }
    }
}

fn load_relay_urls(keep_path: &std::path::Path) -> Vec<String> {
    let path = relay_config_path(keep_path);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn load_relay_urls_for(keep_path: &std::path::Path, pubkey_hex: &str) -> Vec<String> {
    let path = relay_config_path_for(keep_path, pubkey_hex);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| load_relay_urls(keep_path))
}

fn save_relay_urls_for(keep_path: &std::path::Path, pubkey_hex: &str, urls: &[String]) {
    let path = relay_config_path_for(keep_path, pubkey_hex);
    if let Ok(json) = serde_json::to_string_pretty(urls) {
        if let Err(e) = write_private(&path, &json) {
            tracing::error!("Failed to save relay config: {e}");
        }
    }
}

fn load_bunker_relays(keep_path: &std::path::Path) -> Vec<String> {
    let path = bunker_relay_config_path(keep_path);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(default_bunker_relays)
}

fn load_bunker_relays_for(keep_path: &std::path::Path, pubkey_hex: &str) -> Vec<String> {
    let path = bunker_relay_config_path_for(keep_path, pubkey_hex);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| load_bunker_relays(keep_path))
}

fn save_bunker_relays(keep_path: &std::path::Path, urls: &[String]) {
    let path = bunker_relay_config_path(keep_path);
    if let Ok(json) = serde_json::to_string_pretty(urls) {
        if let Err(e) = write_private(&path, &json) {
            tracing::error!(
                "Failed to save bunker relay config to {}: {e}",
                path.display()
            );
        }
    }
}

pub(crate) fn save_bunker_relays_for(
    keep_path: &std::path::Path,
    pubkey_hex: &str,
    urls: &[String],
) {
    let path = bunker_relay_config_path_for(keep_path, pubkey_hex);
    if let Ok(json) = serde_json::to_string_pretty(urls) {
        if let Err(e) = write_private(&path, &json) {
            tracing::error!("Failed to save bunker relay config: {e}");
        }
    }
}

fn write_private(path: &std::path::Path, data: &str) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or(path);
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    {
        use std::io::Write;
        tmp.write_all(data.as_bytes())?;
        tmp.as_file().sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    tmp.persist(path).map_err(std::io::Error::other)?;
    Ok(())
}

fn save_relay_urls(keep_path: &std::path::Path, urls: &[String]) {
    let path = relay_config_path(keep_path);
    if let Ok(json) = serde_json::to_string_pretty(urls) {
        if let Err(e) = write_private(&path, &json) {
            tracing::error!("Failed to save relay config to {}: {e}", path.display());
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Settings {
    #[serde(default = "default_auto_lock_secs")]
    pub auto_lock_secs: u64,
    #[serde(default = "default_clipboard_clear_secs")]
    pub clipboard_clear_secs: u64,
    #[serde(default)]
    pub proxy_enabled: bool,
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    #[serde(default)]
    pub kill_switch_active: bool,
    #[serde(default)]
    pub minimize_to_tray: bool,
    #[serde(default)]
    pub start_minimized: bool,
    #[serde(default)]
    pub bunker_auto_start: bool,
}

fn default_auto_lock_secs() -> u64 {
    AUTO_LOCK_SECS
}

fn default_clipboard_clear_secs() -> u64 {
    CLIPBOARD_CLEAR_SECS
}

fn default_proxy_port() -> u16 {
    DEFAULT_PROXY_PORT
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_secs: AUTO_LOCK_SECS,
            clipboard_clear_secs: CLIPBOARD_CLEAR_SECS,
            proxy_enabled: false,
            proxy_port: DEFAULT_PROXY_PORT,
            kill_switch_active: false,
            minimize_to_tray: false,
            start_minimized: false,
            bunker_auto_start: false,
        }
    }
}

fn settings_path(keep_path: &std::path::Path) -> PathBuf {
    keep_path.join("settings.json")
}

fn load_settings(keep_path: &std::path::Path) -> (Settings, bool) {
    let path = settings_path(keep_path);
    let Some(contents) = std::fs::read_to_string(&path).ok() else {
        return (Settings::default(), false);
    };
    let settings: Settings = serde_json::from_str(&contents).unwrap_or_default();
    let migrated = serde_json::from_str::<serde_json::Value>(&contents)
        .ok()
        .map(|v| v.get("minimize_to_tray").is_none())
        .unwrap_or(false);
    if migrated {
        save_settings(keep_path, &settings);
        tracing::info!("Settings migrated: minimize_to_tray now defaults to off");
    }
    (settings, migrated)
}

pub(crate) fn save_settings(keep_path: &std::path::Path, settings: &Settings) {
    let path = settings_path(keep_path);
    if let Ok(json) = serde_json::to_string_pretty(settings) {
        if let Err(e) = write_private(&path, &json) {
            tracing::error!("Failed to save settings to {}: {e}", path.display());
        }
    }
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
            copy_feedback_until: None,
            toast: None,
            toast_dismiss_at: None,
            frost_shutdown: Arc::new(Mutex::new(None)),
            frost_events: Arc::new(Mutex::new(VecDeque::new())),
            pending_sign_requests: Arc::new(Mutex::new(Vec::new())),
            relay_urls,
            frost_status: ConnectionStatus::Disconnected,
            frost_peers: Vec::new(),
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
            nostrconnect_pending: None,
            has_tray: tray.is_some(),
            window_visible: tray.is_none()
                || !settings.start_minimized
                || !settings.minimize_to_tray,
            tray_last_connected: false,
            tray_last_bunker: false,
            scanner_rx: None,
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
                    let screen = Screen::Unlock(UnlockScreen::with_error(
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
        let relay_urls = load_relay_urls(&keep_path);
        let (settings, tray_migrated) = load_settings(&keep_path);
        let screen = Screen::Unlock(UnlockScreen::new(vault_exists));
        let start_minimized = settings.start_minimized;
        let mut app = Self::init(keep_path, screen, relay_urls, settings);
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
        if !matches!(message, Message::Tick) {
            self.last_activity = Instant::now();
        }

        match message {
            Message::Tick => self.handle_tick(),

            Message::PasswordChanged(..)
            | Message::ConfirmPasswordChanged(..)
            | Message::Unlock
            | Message::UnlockResult(..)
            | Message::StartFresh
            | Message::CancelStartFresh
            | Message::ConfirmStartFresh
            | Message::StartFreshResult(..) => self.handle_unlock_message(message),

            Message::GoToCreate
            | Message::GoToImport
            | Message::GoToExport(..)
            | Message::NavigateShares
            | Message::GoBack
            | Message::NavigateWallets
            | Message::WalletsLoaded(..)
            | Message::NavigateRelay
            | Message::NavigateBunker
            | Message::NavigateSettings
            | Message::Lock => self.handle_navigation_message(message),

            Message::ToggleShareDetails(..)
            | Message::SetActiveShare(..)
            | Message::RequestDelete(..)
            | Message::ConfirmDelete(..)
            | Message::CancelDelete => self.handle_share_list_message(message),

            Message::CreateNameChanged(..)
            | Message::CreateThresholdChanged(..)
            | Message::CreateTotalChanged(..)
            | Message::CreateKeyset
            | Message::CreateResult(..) => self.handle_create_message(message),

            Message::ExportPassphraseChanged(..)
            | Message::ExportConfirmPassphraseChanged(..)
            | Message::GenerateExport
            | Message::ExportGenerated(..)
            | Message::AdvanceQrFrame
            | Message::CopyToClipboard(..)
            | Message::ResetExport => self.handle_export_message(message),

            Message::GoToExportNcryptsec(..)
            | Message::ExportNcryptsecPasswordChanged(..)
            | Message::ExportNcryptsecConfirmChanged(..)
            | Message::GenerateNcryptsec
            | Message::NcryptsecGenerated(..)
            | Message::ResetNcryptsec => self.handle_ncryptsec_export_message(message),

            Message::ImportDataChanged(..)
            | Message::ImportPassphraseChanged(..)
            | Message::ImportNameChanged(..)
            | Message::ImportToggleVisibility
            | Message::ImportShare
            | Message::ImportNsec
            | Message::ImportNcryptsec
            | Message::ImportResult(..)
            | Message::ImportNsecResult(..)
            | Message::ImportNcryptsecResult(..) => self.handle_import_message(message),

            Message::ScannerOpen
            | Message::ScannerClose
            | Message::ScannerRetry
            | Message::ScannerPoll => self.handle_scanner_message(message),

            Message::CopyNpub(..)
            | Message::CopyDescriptor(..)
            | Message::ToggleWalletDetails(..)
            | Message::WalletStartSetup
            | Message::WalletSelectShare(..)
            | Message::WalletNetworkChanged(..)
            | Message::WalletThresholdChanged(..)
            | Message::WalletTimelockChanged(..)
            | Message::WalletAddTier
            | Message::WalletRemoveTier(..)
            | Message::WalletBeginCoordination
            | Message::WalletCancelSetup
            | Message::WalletSessionStarted(..)
            | Message::WalletDescriptorProgress(..) => self.handle_wallet_message(message),

            Message::RelayUrlChanged(..)
            | Message::ConnectPasswordChanged(..)
            | Message::AddRelay
            | Message::RemoveRelay(..)
            | Message::SelectShareForRelay(..)
            | Message::ConnectRelay
            | Message::DisconnectRelay
            | Message::ConnectRelayResult(..)
            | Message::ApproveSignRequest(..)
            | Message::RejectSignRequest(..) => self.handle_relay_message(message),

            Message::BunkerRelayInputChanged(..)
            | Message::BunkerAddRelay
            | Message::BunkerRemoveRelay(..)
            | Message::BunkerStart
            | Message::BunkerStartResult(..)
            | Message::BunkerStop
            | Message::BunkerApprove
            | Message::BunkerReject
            | Message::BunkerRevokeClient(..)
            | Message::BunkerConfirmRevokeAll
            | Message::BunkerCancelRevokeAll
            | Message::BunkerRevokeAll
            | Message::BunkerCopyUrl
            | Message::BunkerRevokeResult(..)
            | Message::BunkerClientsLoaded(..)
            | Message::BunkerToggleClient(..)
            | Message::BunkerTogglePermission(..)
            | Message::BunkerSetApprovalDuration(..)
            | Message::BunkerPermissionUpdated(..) => self.handle_bunker_message(message),

            Message::NavigateAudit
            | Message::AuditLoaded(..)
            | Message::AuditPageLoaded(..)
            | Message::AuditChainVerified(..)
            | Message::AuditFilterChanged(..)
            | Message::AuditLoadMore => self.handle_audit_message(message),

            Message::ToggleIdentitySwitcher
            | Message::SwitchIdentity(..)
            | Message::RequestDeleteIdentity(..)
            | Message::ConfirmDeleteIdentity(..)
            | Message::CancelDeleteIdentity => self.handle_identity_message(message),

            Message::SettingsAutoLockChanged(..)
            | Message::SettingsClipboardClearChanged(..)
            | Message::SettingsProxyToggled(..)
            | Message::SettingsProxyPortChanged(..)
            | Message::SettingsMinimizeToTrayToggled(..)
            | Message::SettingsStartMinimizedToggled(..) => self.handle_settings_message(message),

            Message::KillSwitchRequestConfirm
            | Message::KillSwitchCancelConfirm
            | Message::KillSwitchActivate
            | Message::KillSwitchPasswordChanged(..)
            | Message::KillSwitchDeactivate
            | Message::KillSwitchDeactivateResult(..) => self.handle_kill_switch_message(message),

            Message::CertPinClear(..)
            | Message::CertPinClearAllRequest
            | Message::CertPinClearAllConfirm
            | Message::CertPinClearAllCancel
            | Message::CertPinMismatchDismiss
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
            return iced::clipboard::write(String::new());
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
        self.poll_bunker_events();
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
        Task::batch(tasks)
    }

    fn handle_unlock_message(&mut self, message: Message) -> Task<Message> {
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
            _ => Task::none(),
        }
    }

    fn handle_navigation_message(&mut self, message: Message) -> Task<Message> {
        match message {
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
                self.stop_scanner();
                self.copy_feedback_until = None;
                self.set_share_screen(self.current_shares());
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
            Message::NavigateRelay => {
                if matches!(self.screen, Screen::Relay(_)) {
                    return Task::none();
                }
                self.screen = Screen::Relay(RelayScreen::new(
                    self.current_shares(),
                    self.relay_urls.clone(),
                    self.frost_status.clone(),
                    self.frost_peers.clone(),
                    self.pending_sign_display.clone(),
                ));
                Task::none()
            }
            Message::NavigateBunker => {
                if matches!(self.screen, Screen::Bunker(_)) {
                    return Task::none();
                }
                self.screen = Screen::Bunker(Box::new(self.create_bunker_screen()));
                Task::none()
            }
            Message::NavigateSettings => {
                if matches!(self.screen, Screen::Settings(_)) {
                    return Task::none();
                }
                self.screen = Screen::Settings(SettingsScreen::new(
                    self.settings.auto_lock_secs,
                    self.settings.clipboard_clear_secs,
                    self.keep_path.display().to_string(),
                    self.settings.proxy_enabled,
                    self.settings.proxy_port,
                    self.settings.kill_switch_active,
                    self.settings.minimize_to_tray,
                    self.settings.start_minimized,
                    self.has_tray,
                    self.cert_pin_display_entries(),
                ));
                Task::none()
            }
            Message::Lock => self.do_lock(),
            _ => Task::none(),
        }
    }

    fn handle_share_list_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ToggleShareDetails(i) => {
                if let Screen::ShareList(s) = &mut self.screen {
                    s.expanded = if s.expanded == Some(i) { None } else { Some(i) };
                }
                Task::none()
            }
            Message::SetActiveShare(hex) => {
                self.handle_identity_message(Message::SwitchIdentity(hex))
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
            _ => Task::none(),
        }
    }

    fn handle_create_message(&mut self, message: Message) -> Task<Message> {
        match message {
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
                    self.set_share_screen(shares);
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
            _ => Task::none(),
        }
    }

    fn handle_export_message(&mut self, message: Message) -> Task<Message> {
        match message {
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
                self.start_clipboard_timer();
                self.copy_feedback_until = Some(Instant::now() + Duration::from_secs(2));
                match &mut self.screen {
                    Screen::Export(s) => s.copied = true,
                    Screen::ExportNcryptsec(s) => s.copied = true,
                    _ => {}
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
            _ => Task::none(),
        }
    }

    fn handle_import_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ImportDataChanged(d) => {
                if let Screen::Import(s) = &mut self.screen {
                    let trimmed = d.trim();
                    let new_mode = ImportScreen::detect_mode(trimmed);
                    if new_mode != s.mode {
                        s.passphrase = Zeroizing::new(String::new());
                    }
                    s.mode = new_mode;
                    s.npub_preview = if s.mode == ImportMode::Nsec {
                        keep_core::keys::NostrKeypair::from_nsec(trimmed)
                            .ok()
                            .map(|kp| kp.to_npub())
                    } else {
                        None
                    };
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
            Message::ImportNameChanged(n) => {
                if let Screen::Import(s) = &mut self.screen {
                    if n.chars().count() <= 64 {
                        s.name = n;
                    }
                }
                Task::none()
            }
            Message::ImportToggleVisibility => {
                if let Screen::Import(s) = &mut self.screen {
                    s.nsec_visible = !s.nsec_visible;
                }
                Task::none()
            }
            Message::ImportShare => self.handle_import(),
            Message::ImportNsec => self.handle_import_nsec(),
            Message::ImportNcryptsec => self.handle_import_ncryptsec(),
            Message::ImportResult(result) => self.handle_import_result(result),
            Message::ImportNsecResult(result) => self.handle_import_nsec_result(result),
            Message::ImportNcryptsecResult(result) => self.handle_import_result(result),
            _ => Task::none(),
        }
    }

    fn handle_scanner_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ScannerOpen | Message::ScannerRetry => {
                self.stop_scanner();
                self.open_scanner();
                Task::none()
            }
            Message::ScannerClose => {
                self.stop_scanner();
                self.screen = Screen::Import(ImportScreen::new());
                Task::none()
            }
            Message::ScannerPoll => {
                self.drain_scanner_events();
                Task::none()
            }
            _ => Task::none(),
        }
    }

    fn open_scanner(&mut self) {
        use crate::screen::scanner::{self, ScannerScreen};

        let scanner = ScannerScreen::new();
        let active = scanner.camera_active.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(3);
        scanner::start_camera(active, tx);
        self.scanner_rx = Some(rx);
        self.screen = Screen::Scanner(scanner);
    }

    fn stop_scanner(&mut self) {
        if let Screen::Scanner(s) = &self.screen {
            s.stop_camera();
        }
        self.scanner_rx = None;
    }

    fn drain_scanner_events(&mut self) {
        use crate::screen::scanner::CameraEvent;

        let rx = match &mut self.scanner_rx {
            Some(rx) => rx,
            None => return,
        };

        let mut last_frame: Option<CameraEvent> = None;
        let mut events: Vec<CameraEvent> = Vec::new();

        while let Ok(event) = rx.try_recv() {
            match &event {
                CameraEvent::Frame { .. } => last_frame = Some(event),
                _ => events.push(event),
            }
        }

        for event in events {
            self.apply_scanner_event(event);
        }
        if let Some(frame) = last_frame {
            self.apply_scanner_event(frame);
        }
    }

    fn apply_scanner_event(&mut self, event: crate::screen::scanner::CameraEvent) {
        use crate::screen::scanner::{CameraEvent, ScannerStatus};

        if let Screen::Scanner(s) = &mut self.screen {
            match event {
                CameraEvent::Ready => {
                    s.status = ScannerStatus::Scanning;
                }
                CameraEvent::Frame {
                    rgba,
                    width,
                    height,
                    decoded,
                } => {
                    s.frame_handle =
                        Some(iced::widget::image::Handle::from_rgba(width, height, rgba));

                    if let Some(content) = decoded {
                        if let Some(result) = s.process_qr_content(&content) {
                            s.stop_camera();
                            self.scanner_rx = None;
                            let mut import = ImportScreen::new();
                            let trimmed = result.trim();
                            let mode = ImportScreen::detect_mode(trimmed);
                            import.npub_preview = if mode == ImportMode::Nsec {
                                keep_core::keys::NostrKeypair::from_nsec(trimmed)
                                    .ok()
                                    .map(|kp| kp.to_npub())
                            } else {
                                None
                            };
                            import.mode = mode;
                            import.data = Zeroizing::new(result);
                            self.screen = Screen::Import(import);
                        }
                    }
                }
                CameraEvent::Error(e) => {
                    s.status = ScannerStatus::Error(e);
                }
            }
        }
    }

    fn handle_wallet_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::CopyNpub(npub) => iced::clipboard::write(npub),
            Message::CopyDescriptor(desc) => iced::clipboard::write(desc),
            Message::ToggleWalletDetails(i) => {
                if let Screen::Wallet(s) = &mut self.screen {
                    s.expanded = if s.expanded == Some(i) { None } else { Some(i) };
                }
                Task::none()
            }
            Message::WalletStartSetup => {
                let shares = self.current_shares();
                let selected = if shares.len() == 1 { Some(0) } else { None };
                if let Screen::Wallet(s) = &mut self.screen {
                    s.setup = Some(SetupState {
                        shares,
                        selected_share: selected,
                        network: "signet".into(),
                        tiers: vec![TierConfig::default()],
                        phase: SetupPhase::Configure,
                        error: None,
                        session_id: None,
                    });
                }
                Task::none()
            }
            Message::WalletSelectShare(i) => {
                if let Screen::Wallet(WalletScreen { setup: Some(s), .. }) = &mut self.screen {
                    s.selected_share = Some(i);
                }
                Task::none()
            }
            Message::WalletNetworkChanged(n) => {
                const VALID_NETWORKS: &[&str] = &["bitcoin", "testnet", "signet", "regtest"];
                if VALID_NETWORKS.contains(&n.as_str()) {
                    if let Screen::Wallet(WalletScreen { setup: Some(s), .. }) = &mut self.screen {
                        s.network = n;
                    }
                }
                Task::none()
            }
            Message::WalletThresholdChanged(encoded) => {
                self.update_tier_field(&encoded, |tier, val| tier.threshold = val);
                Task::none()
            }
            Message::WalletTimelockChanged(encoded) => {
                self.update_tier_field(&encoded, |tier, val| tier.timelock_months = val);
                Task::none()
            }
            Message::WalletAddTier => {
                if let Screen::Wallet(WalletScreen { setup: Some(s), .. }) = &mut self.screen {
                    if s.tiers.len() < 5 {
                        s.tiers.push(TierConfig::default());
                    }
                }
                Task::none()
            }
            Message::WalletRemoveTier(i) => {
                if let Screen::Wallet(WalletScreen { setup: Some(s), .. }) = &mut self.screen {
                    if s.tiers.len() > 1 && i < s.tiers.len() {
                        s.tiers.remove(i);
                    }
                }
                Task::none()
            }
            Message::WalletBeginCoordination => self.begin_descriptor_coordination(),
            Message::WalletSessionStarted(result) => {
                if let Screen::Wallet(WalletScreen { setup: Some(s), .. }) = &mut self.screen {
                    match result {
                        Ok(session_id) => s.session_id = Some(session_id),
                        Err(e) => {
                            s.phase =
                                SetupPhase::Coordinating(DescriptorProgress::Failed(e.clone()));
                            s.error = Some(e);
                        }
                    }
                }
                Task::none()
            }
            Message::WalletCancelSetup => {
                if let Screen::Wallet(s) = &mut self.screen {
                    let session_id = s.setup.as_ref().and_then(|st| st.session_id);
                    s.setup = None;
                    if let Some(sid) = session_id {
                        if let Some(node) = self.get_frost_node() {
                            node.cancel_descriptor_session(&sid);
                        }
                    }
                }
                Task::none()
            }
            Message::WalletDescriptorProgress(progress) => {
                if let Screen::Wallet(WalletScreen { setup: Some(s), .. }) = &mut self.screen {
                    s.phase = SetupPhase::Coordinating(progress);
                }
                Task::none()
            }
            _ => Task::none(),
        }
    }

    fn update_tier_field(&mut self, encoded: &str, f: impl FnOnce(&mut TierConfig, String)) {
        if let Screen::Wallet(WalletScreen { setup: Some(s), .. }) = &mut self.screen {
            if let Some((idx_str, val)) = encoded.split_once(':') {
                if let Ok(idx) = idx_str.parse::<usize>() {
                    if let Some(tier) = s.tiers.get_mut(idx) {
                        f(tier, val.to_string());
                    }
                }
            }
        }
    }

    fn begin_descriptor_coordination(&mut self) -> Task<Message> {
        use keep_frost_net::{KeySlot, PolicyTier, WalletPolicy};

        let (share, network, policy) = match &mut self.screen {
            Screen::Wallet(WalletScreen { setup: Some(s), .. }) => {
                let Some(idx) = s.selected_share else {
                    s.error = Some("Select a share".into());
                    return Task::none();
                };
                let Some(share) = s.shares.get(idx).cloned() else {
                    s.error = Some("Invalid share selection".into());
                    return Task::none();
                };

                let mut tiers = Vec::new();
                for tier_cfg in &s.tiers {
                    let threshold: u32 = match tier_cfg.threshold.parse() {
                        Ok(v) if v >= 1 && v <= share.total_shares as u32 => v,
                        _ => {
                            s.error = Some("Invalid threshold value".into());
                            return Task::none();
                        }
                    };
                    let timelock_months: u32 = match tier_cfg.timelock_months.parse() {
                        Ok(v) if v > 0 => v,
                        _ => {
                            s.error = Some("Invalid timelock value".into());
                            return Task::none();
                        }
                    };

                    let key_slots = (1..=share.total_shares)
                        .map(|i| KeySlot::Participant { share_index: i })
                        .collect();

                    tiers.push(PolicyTier {
                        threshold,
                        key_slots,
                        timelock_months,
                    });
                }

                let policy = WalletPolicy {
                    recovery_tiers: tiers,
                };

                s.error = None;
                (share, s.network.clone(), policy)
            }
            _ => return Task::none(),
        };

        if !matches!(self.frost_status, ConnectionStatus::Connected) {
            if let Screen::Wallet(WalletScreen { setup: Some(s), .. }) = &mut self.screen {
                s.error = Some("Connect to relay first".into());
            }
            return Task::none();
        }

        let Some(node) = self.get_frost_node() else {
            if let Screen::Wallet(WalletScreen { setup: Some(s), .. }) = &mut self.screen {
                s.error = Some("Relay node not available".into());
            }
            return Task::none();
        };

        let expected_total = keep_frost_net::participant_indices(&policy).len();

        if let Screen::Wallet(WalletScreen { setup: Some(s), .. }) = &mut self.screen {
            s.phase = SetupPhase::Coordinating(DescriptorProgress::WaitingContributions {
                received: 1,
                expected: expected_total,
            });
        }

        let keep_arc = self.keep.clone();
        let net = network.clone();

        Task::perform(
            async move {
                let (xpub_str, fingerprint_str) = crate::frost::derive_xpub(
                    keep_arc,
                    share.group_pubkey,
                    share.identifier,
                    net.clone(),
                )
                .await?;

                let session_id = node
                    .request_descriptor(policy, &net, &xpub_str, &fingerprint_str)
                    .await
                    .map_err(|e| format!("{e}"))?;

                Ok::<[u8; 32], String>(session_id)
            },
            Message::WalletSessionStarted,
        )
    }

    fn handle_relay_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::RelayUrlChanged(url) => {
                if let Screen::Relay(s) = &mut self.screen {
                    s.relay_url_input = url;
                }
                Task::none()
            }
            Message::ConnectPasswordChanged(p) => {
                if let Screen::Relay(s) = &mut self.screen {
                    s.connect_password = p;
                }
                Task::none()
            }
            Message::AddRelay => {
                let url = match &self.screen {
                    Screen::Relay(s) => s.relay_url_input.trim().to_string(),
                    _ => return Task::none(),
                };
                if self.relay_urls.len() >= MAX_RELAYS {
                    self.set_toast(
                        format!("Maximum of {MAX_RELAYS} relays allowed"),
                        ToastKind::Error,
                    );
                    return Task::none();
                }
                if let Err(e) = validate_relay_url(&url) {
                    self.set_toast(format!("Invalid relay URL: {e}"), ToastKind::Error);
                    return Task::none();
                }
                let normalized = normalize_relay_url(&url);
                let is_new = !self.relay_urls.contains(&normalized);
                if is_new {
                    self.relay_urls.push(normalized.clone());
                    self.save_relay_urls();
                }
                if let Screen::Relay(s) = &mut self.screen {
                    if is_new {
                        s.relay_urls.push(normalized);
                    }
                    s.relay_url_input.clear();
                }
                Task::none()
            }
            Message::RemoveRelay(i) => {
                if let Screen::Relay(s) = &mut self.screen {
                    if i < s.relay_urls.len() {
                        s.relay_urls.remove(i);
                        self.relay_urls = s.relay_urls.clone();
                        self.save_relay_urls();
                    }
                }
                Task::none()
            }
            Message::SelectShareForRelay(i) => {
                if let Screen::Relay(s) = &mut self.screen {
                    s.selected_share = Some(i);
                }
                Task::none()
            }
            Message::ConnectRelay => self.handle_connect_relay(),
            Message::DisconnectRelay => {
                self.handle_disconnect_relay();
                Task::none()
            }
            Message::ConnectRelayResult(result) => self.handle_connect_relay_result(result),
            Message::ApproveSignRequest(id) => {
                self.respond_to_sign_request(&id, true);
                Task::none()
            }
            Message::RejectSignRequest(id) => {
                self.respond_to_sign_request(&id, false);
                Task::none()
            }
            _ => Task::none(),
        }
    }

    pub fn view(&self) -> Element<Message> {
        let pending_count = self.pending_sign_display.len();
        let sidebar_state = SidebarState {
            identities: &self.identities,
            active_identity: self.active_share_hex.as_deref(),
            switcher_open: self.identity_switcher_open,
            delete_confirm: self.delete_identity_confirm.as_deref(),
        };
        let share_count = match &self.screen {
            Screen::ShareList(s) if !s.shares.is_empty() => Some(s.shares.len()),
            _ => None,
        };
        let screen = self.screen.view(
            &sidebar_state,
            share_count,
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
                    iced::time::every(Duration::from_millis(800)).map(|_| Message::AdvanceQrFrame),
                );
            }
        }

        Subscription::batch(subs)
    }

    fn do_lock(&mut self) -> Task<Message> {
        self.stop_scanner();
        self.handle_disconnect_relay();
        self.stop_bunker();

        let mut guard = lock_keep(&self.keep);
        if let Some(keep) = guard.as_mut() {
            keep.lock();
        }
        *guard = None;
        drop(guard);
        let clear_clipboard = self.clipboard_clear_at.take().is_some();
        self.active_share_hex = None;
        self.identities.clear();
        self.identity_switcher_open = false;
        self.delete_identity_confirm = None;
        self.toast = None;
        self.toast_dismiss_at = None;
        self.pin_mismatch = None;
        self.pin_mismatch_confirm = false;
        self.bunker_cert_pin_failed = false;
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
        self.refresh_identities(&shares);
        if let Screen::ShareList(s) = &mut self.screen {
            s.shares = shares;
            s.active_share_hex = self.active_share_hex.clone();
            s.delete_confirm = None;
        }
    }

    fn set_share_screen(&mut self, shares: Vec<ShareEntry>) {
        self.resolve_active_share(&shares);
        self.refresh_identities(&shares);
        self.screen =
            Screen::ShareList(ShareListScreen::new(shares, self.active_share_hex.clone()));
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
        let all_same_group = first.is_some_and(|f| shares.iter().all(|s| s.group_pubkey_hex == f));
        let new_key = if all_same_group { first } else { None };

        match keep.set_active_share_key(new_key) {
            Ok(()) => self.active_share_hex = new_key.map(String::from),
            Err(e) => {
                tracing::warn!("Failed to persist active share: {e}");
                self.active_share_hex = None;
            }
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
                            if meta.is_symlink() {
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

    pub(crate) fn set_toast(&mut self, message: String, kind: ToastKind) {
        self.toast = Some(Toast { message, kind });
        self.toast_dismiss_at = Some(Instant::now() + Duration::from_secs(TOAST_DURATION_SECS));
    }

    pub(crate) fn proxy_addr(&self) -> Option<SocketAddr> {
        if self.settings.proxy_enabled && self.settings.proxy_port > 0 {
            Some(SocketAddr::from((
                Ipv4Addr::LOCALHOST,
                self.settings.proxy_port,
            )))
        } else {
            None
        }
    }

    pub(crate) fn frost_channels(&self) -> crate::frost::FrostChannels {
        crate::frost::FrostChannels {
            events: self.frost_events.clone(),
            pending_requests: self.pending_sign_requests.clone(),
            shutdown: self.frost_shutdown.clone(),
        }
    }

    pub(crate) fn network_config(&self) -> crate::frost::NetworkConfig {
        crate::frost::NetworkConfig {
            proxy: self.proxy_addr(),
            session_timeout: if self.settings.proxy_enabled {
                Some(PROXY_SESSION_TIMEOUT)
            } else {
                None
            },
            certificate_pins: self.certificate_pins.clone(),
            keep_path: self.keep_path.clone(),
        }
    }

    pub(crate) fn save_relay_urls(&self) {
        match &self.active_share_hex {
            Some(hex) => save_relay_urls_for(&self.keep_path, hex, &self.relay_urls),
            None => save_relay_urls(&self.keep_path, &self.relay_urls),
        }
    }

    pub(crate) fn save_bunker_relays(&self) {
        match &self.active_share_hex {
            Some(hex) => save_bunker_relays_for(&self.keep_path, hex, &self.bunker_relays),
            None => save_bunker_relays(&self.keep_path, &self.bunker_relays),
        }
    }

    pub(crate) fn start_clipboard_timer(&mut self) {
        self.clipboard_clear_at = if self.settings.clipboard_clear_secs > 0 {
            Some(Instant::now() + Duration::from_secs(self.settings.clipboard_clear_secs))
        } else {
            None
        };
    }

    fn handle_shares_result(&mut self, result: Result<Vec<ShareEntry>, String>) -> Task<Message> {
        match result {
            Ok(shares) => {
                self.reconcile_kill_switch();
                self.set_share_screen(shares);
                if let Some(request) = take_pending_nostrconnect() {
                    return self.process_pending_nostrconnect(request);
                }
                if self.settings.bunker_auto_start && !self.settings.kill_switch_active {
                    return self.handle_bunker_start();
                }
            }
            Err(e) => self.screen.set_loading_error(e),
        }
        Task::none()
    }

    fn reconcile_kill_switch(&mut self) {
        let vault_state = {
            let guard = lock_keep(&self.keep);
            match guard.as_ref().and_then(|k| k.get_kill_switch().ok()) {
                Some(state) => state,
                None => return,
            }
        };
        self.kill_switch.store(vault_state, Ordering::Release);
        if self.settings.kill_switch_active != vault_state {
            self.settings.kill_switch_active = vault_state;
            save_settings(&self.keep_path, &self.settings);
        }
    }

    fn handle_import_result(
        &mut self,
        result: Result<(Vec<ShareEntry>, String), String>,
    ) -> Task<Message> {
        match result {
            Ok((shares, name)) => {
                self.set_share_screen(shares);
                self.set_toast(
                    format!("'{name}' imported successfully"),
                    ToastKind::Success,
                );
            }
            Err(e) => self.screen.set_loading_error(e),
        }
        Task::none()
    }

    fn handle_delete(&mut self, id: ShareIdentity) {
        let group_hex = hex::encode(id.group_pubkey);
        if self.active_share_hex.as_deref() == Some(group_hex.as_str()) {
            self.handle_disconnect_relay();
            self.stop_bunker();
        }
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

    fn handle_import_nsec(&mut self) -> Task<Message> {
        let (data, name) = match &mut self.screen {
            Screen::Import(s) => {
                if s.loading || s.data.is_empty() || s.name.trim().is_empty() {
                    return Task::none();
                }
                s.loading = true;
                s.error = None;
                (s.data.clone(), s.name.clone())
            }
            _ => return Task::none(),
        };

        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    with_keep_blocking(&keep_arc, "Internal error during import", move |keep| {
                        keep.import_nsec(data.trim(), &name).map_err(friendly_err)?;
                        let shares = collect_shares(keep)?;
                        Ok((shares, name))
                    })
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::ImportNsecResult,
        )
    }

    fn handle_import_nsec_result(
        &mut self,
        result: Result<(Vec<ShareEntry>, String), String>,
    ) -> Task<Message> {
        self.handle_import_result(result)
    }

    fn handle_import_ncryptsec(&mut self) -> Task<Message> {
        let (data, password, name) = match &mut self.screen {
            Screen::Import(s) => {
                if s.loading
                    || s.data.is_empty()
                    || s.passphrase.is_empty()
                    || s.name.trim().is_empty()
                {
                    return Task::none();
                }
                s.loading = true;
                s.error = None;
                (s.data.clone(), s.passphrase.clone(), s.name.clone())
            }
            _ => return Task::none(),
        };

        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    with_keep_blocking(&keep_arc, "Internal error during import", move |keep| {
                        let mut secret = keep_core::keys::nip49::decrypt(data.trim(), &password)
                            .map_err(friendly_err)?;
                        keep.import_secret_bytes(&mut secret, &name)
                            .map_err(friendly_err)?;
                        let shares = collect_shares(keep)?;
                        Ok((shares, name))
                    })
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::ImportNcryptsecResult,
        )
    }

    fn handle_ncryptsec_export_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::GoToExportNcryptsec(pubkey_hex) => {
                let identity = self.identities.iter().find(|i| i.pubkey_hex == pubkey_hex);
                if let Some(id) = identity {
                    self.screen = Screen::ExportNcryptsec(Box::new(ExportNcryptsecScreen::new(
                        id.pubkey_hex.clone(),
                        id.name.clone(),
                        id.npub.clone(),
                    )));
                }
                Task::none()
            }
            Message::ExportNcryptsecPasswordChanged(p) => {
                if let Screen::ExportNcryptsec(s) = &mut self.screen {
                    s.password = p;
                    s.confirm_password = Zeroizing::new(String::new());
                    s.error = None;
                }
                Task::none()
            }
            Message::ExportNcryptsecConfirmChanged(p) => {
                if let Screen::ExportNcryptsec(s) = &mut self.screen {
                    s.confirm_password = p;
                    s.error = None;
                }
                Task::none()
            }
            Message::GenerateNcryptsec => {
                let (pubkey_hex, password) = match &mut self.screen {
                    Screen::ExportNcryptsec(s) => {
                        if s.loading || s.password.chars().count() < MIN_EXPORT_PASSPHRASE_LEN {
                            return Task::none();
                        }
                        if *s.password != *s.confirm_password {
                            s.error = Some("Passwords do not match".into());
                            return Task::none();
                        }
                        s.loading = true;
                        s.error = None;
                        (s.pubkey_hex.clone(), s.password.clone())
                    }
                    _ => return Task::none(),
                };

                let Some(pubkey_bytes) = hex::decode(&pubkey_hex)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                else {
                    self.screen.set_loading_error("Invalid public key".into());
                    return Task::none();
                };

                let keep_arc = self.keep.clone();
                Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            with_keep_blocking(
                                &keep_arc,
                                "Internal error during export",
                                move |keep| {
                                    let ncryptsec = keep
                                        .export_ncryptsec(&pubkey_bytes, &password)
                                        .map_err(friendly_err)?;
                                    Ok(ExportData {
                                        bech32: Zeroizing::new(ncryptsec),
                                        frames: Vec::new(),
                                    })
                                },
                            )
                        })
                        .await
                        .map_err(|_| "Background task failed".to_string())?
                    },
                    Message::NcryptsecGenerated,
                )
            }
            Message::NcryptsecGenerated(Ok(data)) => {
                if let Screen::ExportNcryptsec(s) = &mut self.screen {
                    s.set_result(data.bech32);
                }
                Task::none()
            }
            Message::NcryptsecGenerated(Err(e)) => {
                self.screen.set_loading_error(e);
                Task::none()
            }
            Message::ResetNcryptsec => {
                self.copy_feedback_until = None;
                if let Screen::ExportNcryptsec(s) = &mut self.screen {
                    s.reset();
                }
                Task::none()
            }
            _ => Task::none(),
        }
    }

    fn load_audit_page(
        keep_arc: Arc<Mutex<Option<Keep>>>,
        offset: usize,
        caller: Option<String>,
        on_done: fn(Result<AuditLoadResult, String>) -> Message,
    ) -> Task<Message> {
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let guard = lock_keep(&keep_arc);
                    let keep = guard
                        .as_ref()
                        .ok_or_else(|| "Vault is locked".to_string())?;
                    let page_size = SigningAuditScreen::page_size();
                    let (entries, callers, count) = keep
                        .signing_audit_read_page_with_metadata(offset, page_size, caller.as_deref())
                        .map_err(friendly_err)?;
                    let display: Vec<AuditDisplayEntry> =
                        entries.into_iter().map(to_display_entry).collect();
                    let has_more = display.len() == page_size;
                    Ok(AuditLoadResult {
                        entries: display,
                        callers,
                        count,
                        has_more,
                    })
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            on_done,
        )
    }

    fn handle_audit_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::NavigateAudit => {
                if matches!(self.screen, Screen::SigningAudit(_)) {
                    return Task::none();
                }
                self.screen = Screen::SigningAudit(SigningAuditScreen::new());
                let load_task =
                    Self::load_audit_page(self.keep.clone(), 0, None, Message::AuditLoaded);
                let keep_arc = self.keep.clone();
                let verify_task = Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            let guard = lock_keep(&keep_arc);
                            let keep = guard
                                .as_ref()
                                .ok_or_else(|| "Vault is locked".to_string())?;
                            keep.signing_audit_verify_chain().map_err(friendly_err)
                        })
                        .await
                        .map_err(|_| "Background task failed".to_string())?
                    },
                    Message::AuditChainVerified,
                );
                Task::batch([load_task, verify_task])
            }
            Message::AuditLoaded(result) => {
                match result {
                    Ok(data) => {
                        if let Screen::SigningAudit(s) = &mut self.screen {
                            s.entries = data.entries;
                            s.callers = data.callers;
                            s.entry_count = data.count;
                            s.has_more = data.has_more;
                            s.loading = false;
                            s.load_error = None;
                        }
                    }
                    Err(e) => {
                        if let Screen::SigningAudit(s) = &mut self.screen {
                            s.loading = false;
                            tracing::warn!("Audit log load failed: {e}");
                            s.load_error = Some(e);
                        }
                    }
                }
                Task::none()
            }
            Message::AuditChainVerified(result) => {
                if let Screen::SigningAudit(s) = &mut self.screen {
                    s.chain_status = match result {
                        Ok((true, count)) => {
                            s.entry_count = count;
                            ChainStatus::Valid(count)
                        }
                        Ok((false, _)) => ChainStatus::Invalid,
                        Err(e) => {
                            tracing::warn!("Chain verification failed: {e}");
                            ChainStatus::Error(e)
                        }
                    };
                }
                Task::none()
            }
            Message::AuditFilterChanged(caller) => {
                if let Screen::SigningAudit(s) = &mut self.screen {
                    s.selected_caller = caller.clone();
                    s.entries.clear();
                    s.loading = true;
                    s.has_more = false;
                }
                Self::load_audit_page(self.keep.clone(), 0, caller, Message::AuditLoaded)
            }
            Message::AuditPageLoaded(result) => {
                match result {
                    Ok(data) => {
                        if let Screen::SigningAudit(s) = &mut self.screen {
                            s.entries.extend(data.entries);
                            s.has_more = data.has_more;
                            s.loading = false;
                        }
                    }
                    Err(e) => {
                        if let Screen::SigningAudit(s) = &mut self.screen {
                            s.loading = false;
                        }
                        self.set_toast(e, ToastKind::Error);
                    }
                }
                Task::none()
            }
            Message::AuditLoadMore => {
                let (offset, caller) = match &mut self.screen {
                    Screen::SigningAudit(s) => {
                        if s.loading || !s.has_more {
                            return Task::none();
                        }
                        s.loading = true;
                        (s.entries.len(), s.selected_caller.clone())
                    }
                    _ => return Task::none(),
                };
                Self::load_audit_page(self.keep.clone(), offset, caller, Message::AuditPageLoaded)
            }
            _ => Task::none(),
        }
    }

    fn collect_identities(&self, shares: &[ShareEntry]) -> Vec<Identity> {
        let mut identities: Vec<Identity> = Vec::new();
        let mut seen_groups: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for share in shares {
            if let Some(&idx) = seen_groups.get(&share.group_pubkey_hex) {
                if let IdentityKind::Frost {
                    ref mut share_count,
                    ..
                } = identities[idx].kind
                {
                    *share_count += 1;
                }
            } else {
                seen_groups.insert(share.group_pubkey_hex.clone(), identities.len());
                identities.push(Identity {
                    pubkey_hex: share.group_pubkey_hex.clone(),
                    npub: share.npub.clone(),
                    name: share.name.clone(),
                    kind: IdentityKind::Frost {
                        threshold: share.threshold,
                        total_shares: share.total_shares,
                        share_count: 1,
                    },
                });
            }
        }

        let guard = lock_keep(&self.keep);
        if let Some(keep) = guard.as_ref() {
            if let Ok(keys) = keep.list_keys() {
                for key in keys {
                    if key.key_type != keep_core::keys::KeyType::Nostr {
                        continue;
                    }
                    let hex = hex::encode(key.pubkey);
                    if !seen_groups.contains_key(&hex) {
                        seen_groups.insert(hex.clone(), identities.len());
                        identities.push(Identity {
                            pubkey_hex: hex,
                            npub: keep_core::keys::bytes_to_npub(&key.pubkey),
                            name: key.name,
                            kind: IdentityKind::Nsec,
                        });
                    }
                }
            }
        }

        identities
    }

    fn refresh_identities(&mut self, shares: &[ShareEntry]) {
        self.identities = self.collect_identities(shares);
        if self.active_share_hex.is_none() && self.identities.len() == 1 {
            let hex = self.identities[0].pubkey_hex.clone();
            let guard = lock_keep(&self.keep);
            if let Some(keep) = guard.as_ref() {
                let _ = keep.set_active_share_key(Some(&hex));
            }
            drop(guard);
            self.active_share_hex = Some(hex);
        }
    }

    fn handle_identity_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ToggleIdentitySwitcher => {
                self.identity_switcher_open = !self.identity_switcher_open;
                if !self.identity_switcher_open {
                    self.delete_identity_confirm = None;
                }
                Task::none()
            }
            Message::SwitchIdentity(pubkey_hex) => {
                if self.active_share_hex.as_deref() == Some(&pubkey_hex) {
                    return Task::none();
                }

                self.save_relay_urls();
                self.save_bunker_relays();

                self.handle_disconnect_relay();
                self.stop_bunker();

                self.relay_urls = load_relay_urls_for(&self.keep_path, &pubkey_hex);
                self.bunker_relays = load_bunker_relays_for(&self.keep_path, &pubkey_hex);

                {
                    let guard = lock_keep(&self.keep);
                    if let Some(keep) = guard.as_ref() {
                        let _ = keep.set_active_share_key(Some(&pubkey_hex));
                    }
                }

                let is_nsec = self
                    .identities
                    .iter()
                    .any(|i| i.pubkey_hex == pubkey_hex && matches!(i.kind, IdentityKind::Nsec));
                if is_nsec {
                    if let Ok(bytes) = hex::decode(&pubkey_hex) {
                        if let Ok(pubkey_bytes) = <[u8; 32]>::try_from(bytes) {
                            let mut guard = lock_keep(&self.keep);
                            if let Some(keep) = guard.as_mut() {
                                let _ = keep.keyring_mut().set_primary(pubkey_bytes);
                            }
                        }
                    }
                }

                self.active_share_hex = Some(pubkey_hex);
                self.identity_switcher_open = false;
                self.delete_identity_confirm = None;

                let shares = self.current_shares();
                match &self.screen {
                    Screen::ShareList(_) => {
                        self.screen = Screen::ShareList(ShareListScreen::new(
                            shares,
                            self.active_share_hex.clone(),
                        ));
                    }
                    Screen::Relay(_) => {
                        self.screen = Screen::Relay(RelayScreen::new(
                            shares,
                            self.relay_urls.clone(),
                            self.frost_status.clone(),
                            self.frost_peers.clone(),
                            self.pending_sign_display.clone(),
                        ));
                    }
                    Screen::Bunker(_) => {
                        self.screen = Screen::Bunker(Box::new(self.create_bunker_screen()));
                    }
                    _ => {}
                }

                self.set_toast("Identity switched".into(), ToastKind::Success);
                Task::none()
            }
            Message::RequestDeleteIdentity(pubkey_hex) => {
                self.delete_identity_confirm = Some(pubkey_hex);
                Task::none()
            }
            Message::ConfirmDeleteIdentity(pubkey_hex) => {
                self.delete_identity_confirm = None;

                let identity = self
                    .identities
                    .iter()
                    .find(|i| i.pubkey_hex == pubkey_hex)
                    .cloned();
                let Some(identity) = identity else {
                    self.set_toast("Identity not found".into(), ToastKind::Error);
                    return Task::none();
                };

                let is_active = self.active_share_hex.as_deref() == Some(&pubkey_hex);
                if is_active {
                    self.handle_disconnect_relay();
                    self.stop_bunker();
                }

                let result = match &identity.kind {
                    IdentityKind::Frost { .. } => {
                        let shares = self.current_shares();
                        let group_shares: Vec<_> = shares
                            .iter()
                            .filter(|s| s.group_pubkey_hex == pubkey_hex)
                            .collect();
                        let total = group_shares.len();
                        let mut deleted = 0usize;
                        let mut delete_err: Option<String> = None;
                        for share in &group_shares {
                            let res = {
                                let mut guard = lock_keep(&self.keep);
                                guard.as_mut().map(|keep| {
                                    keep.frost_delete_share(&share.group_pubkey, share.identifier)
                                })
                            };
                            match res {
                                Some(Ok(())) => deleted += 1,
                                Some(Err(e)) => {
                                    delete_err = Some(friendly_err(e));
                                    break;
                                }
                                None => {
                                    delete_err = Some("Vault is locked".into());
                                    break;
                                }
                            }
                        }
                        if let Some(err_msg) = delete_err {
                            self.refresh_shares();
                            self.set_toast(
                                format!("Deleted {deleted}/{total} shares: {err_msg}"),
                                ToastKind::Error,
                            );
                            false
                        } else {
                            true
                        }
                    }
                    IdentityKind::Nsec => {
                        let Ok(bytes) = hex::decode(&pubkey_hex) else {
                            return Task::none();
                        };
                        let Ok(pubkey_bytes) = <[u8; 32]>::try_from(bytes) else {
                            return Task::none();
                        };
                        let delete_result = {
                            let mut guard = lock_keep(&self.keep);
                            guard.as_mut().map(|keep| keep.delete_key(&pubkey_bytes))
                        };
                        match delete_result {
                            Some(Ok(())) => true,
                            Some(Err(e)) => {
                                self.set_toast(friendly_err(e), ToastKind::Error);
                                false
                            }
                            None => false,
                        }
                    }
                };

                if result {
                    let _ =
                        std::fs::remove_file(relay_config_path_for(&self.keep_path, &pubkey_hex));
                    let _ = std::fs::remove_file(bunker_relay_config_path_for(
                        &self.keep_path,
                        &pubkey_hex,
                    ));

                    self.refresh_shares();
                    self.set_toast(format!("'{}' deleted", identity.name), ToastKind::Success);
                }

                Task::none()
            }
            Message::CancelDeleteIdentity => {
                self.delete_identity_confirm = None;
                Task::none()
            }
            _ => Task::none(),
        }
    }

    fn handle_settings_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::SettingsAutoLockChanged(secs) => {
                self.settings.auto_lock_secs = secs;
            }
            Message::SettingsClipboardClearChanged(secs) => {
                self.settings.clipboard_clear_secs = secs;
                if secs == 0 {
                    self.clipboard_clear_at = None;
                }
            }
            Message::SettingsProxyToggled(enabled) => {
                self.settings.proxy_enabled = enabled;
                let frost_active = matches!(
                    self.frost_status,
                    ConnectionStatus::Connected | ConnectionStatus::Connecting
                );
                let bunker_active = self.bunker.is_some();
                save_settings(&self.keep_path, &self.settings);
                if let Screen::Settings(s) = &mut self.screen {
                    s.proxy_enabled = self.settings.proxy_enabled;
                }
                let mut tasks = Vec::new();
                if frost_active {
                    tasks.push(self.handle_reconnect_relay());
                }
                if bunker_active {
                    self.stop_bunker();
                    tasks.push(self.handle_bunker_start());
                }
                if !tasks.is_empty() {
                    let label = if enabled { "enabled" } else { "disabled" };
                    self.set_toast(
                        format!("Proxy {label}, reconnecting..."),
                        ToastKind::Success,
                    );
                }
                return Task::batch(tasks);
            }
            Message::SettingsProxyPortChanged(port_str) => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.proxy_port_input = port_str.clone();
                }
                match port_str.parse::<u16>() {
                    Ok(port) if port > 0 => self.settings.proxy_port = port,
                    _ => return Task::none(),
                }
            }
            Message::SettingsMinimizeToTrayToggled(v) => {
                self.settings.minimize_to_tray = v;
                if !v && !self.window_visible {
                    self.window_visible = true;
                    save_settings(&self.keep_path, &self.settings);
                    self.sync_settings_screen();
                    return iced::window::oldest().and_then(|id| {
                        Task::batch([
                            iced::window::set_mode(id, iced::window::Mode::Windowed),
                            iced::window::gain_focus(id),
                        ])
                    });
                }
            }
            Message::SettingsStartMinimizedToggled(v) => {
                self.settings.start_minimized = v;
            }
            _ => return Task::none(),
        }
        save_settings(&self.keep_path, &self.settings);
        self.sync_settings_screen();
        Task::none()
    }

    fn sync_settings_screen(&mut self) {
        if let Screen::Settings(s) = &mut self.screen {
            s.auto_lock_secs = self.settings.auto_lock_secs;
            s.clipboard_clear_secs = self.settings.clipboard_clear_secs;
            s.proxy_enabled = self.settings.proxy_enabled;
            s.proxy_port = self.settings.proxy_port;
            s.minimize_to_tray = self.settings.minimize_to_tray;
            s.start_minimized = self.settings.start_minimized;
            let formatted = self.settings.proxy_port.to_string();
            if s.proxy_port_input != formatted {
                s.proxy_port_input = formatted;
            }
        }
    }

    fn handle_cert_pin_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::CertPinClear(hostname) => {
                let ok = if let Ok(mut pins) = self.certificate_pins.lock() {
                    pins.remove_pin(&hostname);
                    save_cert_pins(&self.keep_path, &pins);
                    true
                } else {
                    false
                };
                if ok {
                    self.sync_cert_pins_to_screen();
                    self.set_toast(format!("Cleared pin for {hostname}"), ToastKind::Success);
                } else {
                    self.set_toast("Failed to clear pin".into(), ToastKind::Error);
                }
            }
            Message::CertPinClearAllRequest => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.clear_all_pins_confirm = true;
                }
            }
            Message::CertPinClearAllCancel => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.clear_all_pins_confirm = false;
                }
            }
            Message::CertPinClearAllConfirm => {
                let ok = if let Ok(mut pins) = self.certificate_pins.lock() {
                    *pins = keep_frost_net::CertificatePinSet::new();
                    save_cert_pins(&self.keep_path, &pins);
                    true
                } else {
                    false
                };
                if ok {
                    self.sync_cert_pins_to_screen();
                    if let Screen::Settings(s) = &mut self.screen {
                        s.clear_all_pins_confirm = false;
                    }
                    self.set_toast("Cleared all certificate pins".into(), ToastKind::Success);
                } else {
                    self.set_toast("Failed to clear pins".into(), ToastKind::Error);
                }
            }
            Message::CertPinMismatchDismiss => {
                self.pin_mismatch = None;
                self.pin_mismatch_confirm = false;
            }
            Message::CertPinMismatchClearAndRetry => {
                self.pin_mismatch_confirm = true;
            }
            Message::CertPinMismatchConfirmClear => {
                self.pin_mismatch_confirm = false;
                let Some(mismatch) = self.pin_mismatch.as_ref() else {
                    return Task::none();
                };
                let ok = if let Ok(mut pins) = self.certificate_pins.lock() {
                    pins.remove_pin(&mismatch.hostname);
                    save_cert_pins(&self.keep_path, &pins);
                    true
                } else {
                    false
                };
                if !ok {
                    self.set_toast("Failed to clear pin".into(), ToastKind::Error);
                    return Task::none();
                }
                self.pin_mismatch = None;
                self.sync_cert_pins_to_screen();
                let mut tasks = Vec::new();
                if matches!(self.frost_status, ConnectionStatus::Error(_)) {
                    tasks.push(self.handle_reconnect_relay());
                }
                if self.bunker.is_none() && self.bunker_cert_pin_failed {
                    self.bunker_cert_pin_failed = false;
                    tasks.push(self.handle_bunker_start());
                }
                return Task::batch(tasks);
            }
            _ => {}
        }
        Task::none()
    }

    pub(crate) fn cert_pin_display_entries(&self) -> Vec<(String, String)> {
        let Ok(pins) = self.certificate_pins.lock() else {
            return Vec::new();
        };
        let mut entries: Vec<(String, String)> = pins
            .pins()
            .iter()
            .map(|(host, hash)| (host.clone(), hex::encode(hash)))
            .collect();
        entries.sort_unstable();
        entries
    }

    fn sync_cert_pins_to_screen(&mut self) {
        let entries = self.cert_pin_display_entries();
        if let Screen::Settings(s) = &mut self.screen {
            s.certificate_pins = entries;
        }
    }

    fn handle_kill_switch_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::KillSwitchRequestConfirm | Message::KillSwitchCancelConfirm => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.kill_switch_confirm = matches!(message, Message::KillSwitchRequestConfirm);
                }
            }
            Message::KillSwitchActivate => {
                let vault_err = {
                    let mut guard = lock_keep(&self.keep);
                    guard
                        .as_mut()
                        .and_then(|keep| keep.set_kill_switch(true).err())
                };
                if let Some(e) = vault_err {
                    self.set_toast(friendly_err(e), ToastKind::Error);
                    return Task::none();
                }
                self.settings.kill_switch_active = true;
                save_settings(&self.keep_path, &self.settings);
                self.kill_switch.store(true, Ordering::Release);

                self.log_kill_switch_event(true);
                self.handle_disconnect_relay();
                self.stop_bunker();

                if let Screen::Settings(s) = &mut self.screen {
                    s.kill_switch_confirm = false;
                    s.kill_switch_active = true;
                }
                self.set_toast(
                    "Kill switch activated - all signing blocked".into(),
                    ToastKind::Success,
                );
            }
            Message::KillSwitchPasswordChanged(p) => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.kill_switch_password = p;
                }
            }
            Message::KillSwitchDeactivate => {
                let password = if let Screen::Settings(s) = &mut self.screen {
                    if s.kill_switch_password.is_empty() {
                        s.kill_switch_error = Some("Password required".into());
                        return Task::none();
                    }
                    s.kill_switch_loading = true;
                    s.kill_switch_error = None;
                    s.kill_switch_password.clone()
                } else {
                    return Task::none();
                };

                let keep_arc = self.keep.clone();
                return Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            let guard = lock_keep(&keep_arc);
                            match guard.as_ref() {
                                None => Err("Vault is locked".to_string()),
                                Some(keep) => keep.verify_password(&password).map_err(friendly_err),
                            }
                        })
                        .await
                        .map_err(|_| "Background task failed".to_string())?
                    },
                    Message::KillSwitchDeactivateResult,
                );
            }
            Message::KillSwitchDeactivateResult(result) => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.kill_switch_loading = false;
                    s.kill_switch_password = Zeroizing::new(String::new());
                }
                match result {
                    Ok(()) => {
                        {
                            let mut guard = lock_keep(&self.keep);
                            if let Some(keep) = guard.as_mut() {
                                if let Err(e) = keep.set_kill_switch(false) {
                                    if let Screen::Settings(s) = &mut self.screen {
                                        s.kill_switch_error = Some(friendly_err(e));
                                    }
                                    return Task::none();
                                }
                            }
                        }
                        self.kill_switch.store(false, Ordering::Release);
                        self.settings.kill_switch_active = false;
                        save_settings(&self.keep_path, &self.settings);
                        self.log_kill_switch_event(false);
                        if let Screen::Settings(s) = &mut self.screen {
                            s.kill_switch_active = false;
                            s.kill_switch_error = None;
                        }
                        self.set_toast(
                            "Kill switch deactivated - signing re-enabled".into(),
                            ToastKind::Success,
                        );
                    }
                    Err(e) => {
                        if let Screen::Settings(s) = &mut self.screen {
                            s.kill_switch_error = Some(e);
                        }
                    }
                }
            }
            _ => {}
        }
        Task::none()
    }

    fn log_kill_switch_event(&self, activated: bool) {
        use keep_core::audit::{SigningAuditEntry, SigningDecision, SigningRequestType};
        let decision = if activated {
            SigningDecision::Denied
        } else {
            SigningDecision::Approved
        };
        let mut guard = lock_keep(&self.keep);
        if let Some(keep) = guard.as_mut() {
            let hash = keep.signing_audit_last_hash().unwrap_or([0u8; 32]);
            let reason = if activated {
                "activated"
            } else {
                "deactivated"
            };
            let entry = SigningAuditEntry::new(
                SigningRequestType::KillSwitch,
                decision,
                false,
                "desktop".into(),
                hash,
            )
            .with_reason(reason);
            if let Err(e) = keep.signing_audit_log(entry) {
                tracing::warn!("Failed to log kill switch event: {e}");
            }
        }
    }

    pub(crate) fn is_kill_switch_active(&self) -> bool {
        self.kill_switch.load(Ordering::Acquire)
    }

    fn handle_window_close(&mut self, id: iced::window::Id) -> Task<Message> {
        if self.settings.minimize_to_tray && self.has_tray {
            self.window_visible = false;
            iced::window::set_mode(id, iced::window::Mode::Hidden)
        } else {
            self.handle_disconnect_relay();
            self.stop_bunker();
            iced::exit()
        }
    }

    fn handle_tray_show(&mut self) -> Task<Message> {
        if self.window_visible {
            return iced::window::oldest().and_then(iced::window::gain_focus);
        }
        self.window_visible = true;
        iced::window::oldest().and_then(|id| {
            Task::batch([
                iced::window::set_mode(id, iced::window::Mode::Windowed),
                iced::window::gain_focus(id),
            ])
        })
    }

    fn handle_tray_toggle_bunker(&mut self) -> Task<Message> {
        if self.bunker.is_some() {
            self.handle_bunker_stop()
        } else if lock_keep(&self.keep).is_none() {
            self.set_toast("Vault is locked".into(), ToastKind::Error);
            self.handle_tray_show()
        } else {
            self.handle_bunker_start()
        }
    }

    fn handle_tray_quit(&mut self) -> Task<Message> {
        self.handle_disconnect_relay();
        self.stop_bunker();
        iced::exit()
    }

    fn sync_tray_status(&mut self) {
        let Some(ref tray) = self.tray else {
            return;
        };
        let connected = matches!(self.frost_status, ConnectionStatus::Connected);
        if connected != self.tray_last_connected {
            tray.update_status(connected);
            self.tray_last_connected = connected;
        }
        let bunker_running = self.bunker.is_some();
        if bunker_running != self.tray_last_bunker {
            tray.update_bunker_label(bunker_running);
            self.tray_last_bunker = bunker_running;
        }
    }

    fn poll_tray_events(&self) -> Vec<crate::tray::TrayEvent> {
        self.tray
            .as_ref()
            .map(|tray| tray.event_rx.try_iter().collect())
            .unwrap_or_default()
    }

    pub(crate) fn notify_sign_request(&self, _req: &PendingSignRequest) {
        if !self.window_visible {
            let tx = self.tray.as_ref().map(|t| &t.event_tx);
            crate::tray::send_sign_request_notification(tx);
        }
    }

    pub(crate) fn notify_bunker_approval(&self, display: &PendingApprovalDisplay) {
        if !self.window_visible {
            let tx = self.tray.as_ref().map(|t| &t.event_tx);
            crate::tray::send_bunker_approval_notification(&display.app_name, &display.method, tx);
        }
    }

    #[cfg(test)]
    fn test_new(settings: Settings, has_tray: bool) -> Self {
        let keep_path = PathBuf::from("/tmp/keep-test-nonexistent");
        let screen = Screen::Unlock(crate::screen::unlock::UnlockScreen::new(false));
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
            copy_feedback_until: None,
            toast: None,
            toast_dismiss_at: None,
            frost_shutdown: Arc::new(Mutex::new(None)),
            frost_events: Arc::new(Mutex::new(VecDeque::new())),
            pending_sign_requests: Arc::new(Mutex::new(Vec::new())),
            relay_urls: Vec::new(),
            frost_status: ConnectionStatus::Disconnected,
            frost_peers: Vec::new(),
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
            nostrconnect_pending: None,
            has_tray,
            window_visible: !has_tray || !settings.start_minimized || !settings.minimize_to_tray,
            tray_last_connected: false,
            tray_last_bunker: false,
            scanner_rx: None,
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

    #[test]
    fn disable_minimize_to_tray_while_hidden_reappears_window() {
        let mut settings = default_settings();
        settings.minimize_to_tray = true;
        let mut app = App::test_new(settings, true);
        app.window_visible = false;

        let _task = app.handle_settings_message(Message::SettingsMinimizeToTrayToggled(false));

        assert!(app.window_visible);
        assert!(!app.settings.minimize_to_tray);
    }

    #[test]
    fn disable_minimize_to_tray_while_visible_no_change() {
        let mut settings = default_settings();
        settings.minimize_to_tray = true;
        let mut app = App::test_new(settings, true);
        app.window_visible = true;

        let _task = app.handle_settings_message(Message::SettingsMinimizeToTrayToggled(false));

        assert!(app.window_visible);
        assert!(!app.settings.minimize_to_tray);
    }

    #[test]
    fn enable_minimize_to_tray_setting() {
        let mut settings = default_settings();
        settings.minimize_to_tray = false;
        let mut app = App::test_new(settings, true);
        app.window_visible = true;

        let _task = app.handle_settings_message(Message::SettingsMinimizeToTrayToggled(true));

        assert!(app.settings.minimize_to_tray);
        assert!(app.window_visible);
    }

    #[test]
    fn enable_start_minimized_setting() {
        let mut settings = default_settings();
        settings.start_minimized = false;
        let mut app = App::test_new(settings, true);

        let _task = app.handle_settings_message(Message::SettingsStartMinimizedToggled(true));

        assert!(app.settings.start_minimized);
    }

    #[test]
    fn disable_start_minimized_setting() {
        let mut settings = default_settings();
        settings.start_minimized = true;
        let mut app = App::test_new(settings, true);

        let _task = app.handle_settings_message(Message::SettingsStartMinimizedToggled(false));

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
            proxy_enabled: true,
            proxy_port: 9051,
            kill_switch_active: false,
            minimize_to_tray: false,
            start_minimized: true,
            bunker_auto_start: false,
        };
        let json = serde_json::to_string(&s).unwrap();
        let parsed: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.auto_lock_secs, 60);
        assert_eq!(parsed.clipboard_clear_secs, 10);
        assert!(parsed.proxy_enabled);
        assert_eq!(parsed.proxy_port, 9051);
        assert!(!parsed.minimize_to_tray);
        assert!(parsed.start_minimized);
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
