// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::{HashMap, VecDeque};
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
use crate::screen::layout::SidebarState;
use crate::screen::nsec_keys::NsecKeyEntry;
use crate::screen::settings::SettingsScreen;
use crate::screen::shares::ShareEntry;
use crate::screen::signing_audit::{AuditDisplayEntry, ChainStatus, SigningAuditScreen};
use crate::screen::unlock;
use crate::screen::wallet::{DescriptorProgress, SetupPhase, WalletEntry};
use crate::screen::Screen;
use crate::screen::{
    create, export, export_ncryptsec, import, nsec_keys, relay, scanner, shares, wallet,
};
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
pub(crate) const MAX_ACTIVE_COORDINATIONS: usize = 64;

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

pub(crate) struct ActiveCoordination {
    pub group_pubkey: [u8; 32],
    pub network: String,
    pub is_initiator: bool,
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
    cached_share_count: usize,
    cached_nsec_count: usize,
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
        KeepError::Database(msg) => {
            tracing::warn!("Database error: {msg}");
            "Database error".into()
        }
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

fn write_private_bytes(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(path);
    let tmp = tempfile::NamedTempFile::new_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    (&tmp).write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
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

fn parse_hex_key(hex: &str) -> Option<[u8; 32]> {
    hex::decode(hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
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

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Settings {
    #[serde(default = "default_auto_lock_secs")]
    pub auto_lock_secs: u64,
    #[serde(default = "default_clipboard_clear_secs")]
    pub clipboard_clear_secs: u64,
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

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_secs: AUTO_LOCK_SECS,
            clipboard_clear_secs: CLIPBOARD_CLEAR_SECS,
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

fn migrate_json_config_to_vault(keep: &keep_core::Keep, keep_path: &std::path::Path) {
    let global_exists = match keep.get_relay_config(&keep_core::GLOBAL_RELAY_KEY) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            tracing::warn!("Failed to check existing relay config, skipping migration: {e}");
            return;
        }
    };

    if !global_exists {
        let mut config = keep_core::RelayConfig::new_global();

        let relay_path = keep_path.join("relays.json");
        if let Ok(contents) = std::fs::read_to_string(&relay_path) {
            if let Ok(urls) = serde_json::from_str::<Vec<String>>(&contents) {
                if !urls.is_empty() {
                    config.frost_relays = urls;
                }
            }
        }

        let bunker_path = keep_path.join("bunker-relays.json");
        if let Ok(contents) = std::fs::read_to_string(&bunker_path) {
            if let Ok(urls) = serde_json::from_str::<Vec<String>>(&contents) {
                if !urls.is_empty() {
                    config.bunker_relays = urls;
                }
            }
        }

        match keep.store_relay_config(&config) {
            Ok(()) => {
                let _ = std::fs::remove_file(&relay_path);
                let _ = std::fs::remove_file(&bunker_path);
            }
            Err(e) => {
                tracing::warn!("Failed to migrate global relay config to vault: {e}");
            }
        }
    }

    let settings_path = keep_path.join("settings.json");
    if let Ok(contents) = std::fs::read_to_string(&settings_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&contents) {
            let enabled = json
                .get("proxy_enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let port = json
                .get("proxy_port")
                .and_then(|v| v.as_u64())
                .and_then(|p| u16::try_from(p).ok())
                .unwrap_or(DEFAULT_PROXY_PORT);
            if enabled || port != DEFAULT_PROXY_PORT {
                let proxy = keep_core::ProxyConfig { enabled, port };
                if let Err(e) = keep.set_proxy_config(&proxy) {
                    tracing::warn!(
                        enabled,
                        port,
                        "Failed to migrate proxy config to vault: {e}"
                    );
                }
            }
        }
    }

    if let Ok(entries) = std::fs::read_dir(keep_path) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let Some(hex) = name_str
                .strip_prefix("relays-")
                .and_then(|s| s.strip_suffix(".json"))
            else {
                continue;
            };
            let Some(key) = parse_hex_key(hex) else {
                continue;
            };
            let mut per_key_config = keep_core::RelayConfig::new(key);
            if let Ok(contents) = std::fs::read_to_string(entry.path()) {
                if let Ok(urls) = serde_json::from_str::<Vec<String>>(&contents) {
                    per_key_config.frost_relays = urls;
                }
            }
            let bunker_file = keep_path.join(format!("bunker-relays-{hex}.json"));
            if let Ok(contents) = std::fs::read_to_string(&bunker_file) {
                if let Ok(urls) = serde_json::from_str::<Vec<String>>(&contents) {
                    per_key_config.bunker_relays = urls;
                }
            }
            match keep.store_relay_config(&per_key_config) {
                Ok(()) => {
                    let _ = std::fs::remove_file(entry.path());
                    let _ = std::fs::remove_file(&bunker_file);
                }
                Err(e) => {
                    tracing::warn!("Failed to migrate relay config for {hex}: {e}");
                }
            }
        }
    }

    tracing::info!("Migrated relay/proxy config from JSON files to vault");
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
        if !matches!(message, Message::Tick) {
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

            Message::ShareList(msg) => self.handle_share_list_message(msg),

            Message::NsecKeys(msg) => self.handle_nsec_keys_message(msg),

            Message::Create(msg) => self.handle_create_message(msg),
            Message::CreateResult(result) => self.handle_create_result(result),

            Message::Export(msg) => self.handle_export_message(msg),
            Message::ExportGenerated(result) => self.handle_export_generated(result),

            Message::GoToExportNcryptsec(hex) => self.handle_go_to_export_ncryptsec(hex),
            Message::ExportNcryptsec(msg) => self.handle_ncryptsec_export_message(msg),
            Message::NcryptsecGenerated(result) => self.handle_ncryptsec_generated(result),

            Message::Import(msg) => self.handle_import_message(msg),
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
            | Message::WalletAnnounceResult(..) => self.handle_wallet_global_message(message),

            Message::Relay(msg) => self.handle_relay_message(msg),
            Message::ConnectRelayResult(result) => self.handle_connect_relay_result(result),

            Message::Bunker(msg) => self.handle_bunker_message(msg),
            Message::BunkerStartResult(result) => self.handle_bunker_start_result(result),
            Message::BunkerRevokeResult(result) => self.handle_bunker_revoke_result(result),
            Message::BunkerClientsLoaded(clients) => self.handle_bunker_clients_loaded(clients),
            Message::BunkerPermissionUpdated(result) => {
                self.handle_bunker_permission_updated(result)
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
            Message::RestoreFileLoaded(name, data) => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.restore_file_loaded(name, data);
                }
                Task::none()
            }
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

    fn handle_navigation_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::GoToCreate => {
                self.screen = Screen::Create(create::State::new());
                Task::none()
            }
            Message::GoToImport => {
                self.import_return_to_nsec = matches!(self.screen, Screen::NsecKeys(_));
                self.screen = Screen::Import(import::State::new());
                Task::none()
            }
            Message::GoToExport(index) => {
                let shares = self.current_shares();
                if let Some(share) = shares.get(index).cloned() {
                    self.screen = Screen::Export(Box::new(export::State::new(share)));
                }
                Task::none()
            }
            Message::NavigateShares => {
                if matches!(self.screen, Screen::ShareList(_)) {
                    return Task::none();
                }
                self.stop_scanner();
                self.copy_feedback_until = None;
                self.set_share_screen(self.current_shares());
                Task::none()
            }
            Message::GoBack => {
                self.stop_scanner();
                self.copy_feedback_until = None;
                let return_to_nsec = matches!(self.screen, Screen::ExportNcryptsec(_))
                    || (matches!(self.screen, Screen::Import(_)) && self.import_return_to_nsec);
                if return_to_nsec {
                    self.import_return_to_nsec = false;
                    self.set_nsec_keys_screen();
                } else {
                    self.set_share_screen(self.current_shares());
                }
                Task::none()
            }
            Message::NavigateNsecKeys => {
                if matches!(self.screen, Screen::NsecKeys(_)) {
                    return Task::none();
                }
                self.stop_scanner();
                self.copy_feedback_until = None;
                self.set_nsec_keys_screen();
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
            Message::NavigateRelay => {
                if matches!(self.screen, Screen::Relay(_)) {
                    return Task::none();
                }
                self.screen = Screen::Relay(relay::State::new(
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
                    self.proxy_enabled,
                    self.proxy_port,
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

    fn handle_share_list_message(&mut self, msg: shares::Message) -> Task<Message> {
        let Screen::ShareList(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            shares::Event::GoToExport(i) => self.handle_navigation_message(Message::GoToExport(i)),
            shares::Event::GoToCreate => self.handle_navigation_message(Message::GoToCreate),
            shares::Event::GoToImport => self.handle_navigation_message(Message::GoToImport),
            shares::Event::ActivateShare(hex) => {
                self.handle_identity_message(Message::SwitchIdentity(hex))
            }
            shares::Event::CopyNpub(npub) => self.handle_copy_npub(npub),
            shares::Event::ConfirmDelete(id) => {
                self.handle_delete(id);
                Task::none()
            }
        }
    }

    fn handle_create_message(&mut self, msg: create::Message) -> Task<Message> {
        let Screen::Create(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            create::Event::GoBack => self.handle_navigation_message(Message::GoBack),
            create::Event::Create {
                name,
                threshold,
                total,
            } => self.handle_create_keyset_validated(name, threshold, total),
        }
    }

    fn handle_create_result(&mut self, result: Result<Vec<ShareEntry>, String>) -> Task<Message> {
        match result {
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
        }
    }

    fn handle_export_message(&mut self, msg: export::Message) -> Task<Message> {
        let Screen::Export(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            export::Event::GoBack => self.handle_navigation_message(Message::GoBack),
            export::Event::Generate { share, passphrase } => {
                self.handle_generate_export_validated(share, passphrase)
            }
            export::Event::CopyToClipboard(t) => self.handle_copy_sensitive(t),
            export::Event::Reset => {
                self.copy_feedback_until = None;
                if let Screen::Export(s) = &mut self.screen {
                    s.reset();
                }
                Task::none()
            }
        }
    }

    fn handle_import_message(&mut self, msg: import::Message) -> Task<Message> {
        let Screen::Import(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            import::Event::GoBack => self.handle_navigation_message(Message::GoBack),
            import::Event::ScannerOpen => {
                self.stop_scanner();
                self.open_scanner();
                Task::none()
            }
            import::Event::ImportShare { data, passphrase } => {
                self.handle_import_share(data, passphrase)
            }
            import::Event::ImportNsec { data, name } => self.handle_import_nsec(data, name),
            import::Event::ImportNcryptsec {
                data,
                password,
                name,
            } => self.handle_import_ncryptsec(data, password, name),
        }
    }

    fn handle_scanner_message(&mut self, msg: scanner::Message) -> Task<Message> {
        let Screen::Scanner(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            scanner::Event::Close => {
                self.stop_scanner();
                self.screen = Screen::Import(import::State::new());
                Task::none()
            }
            scanner::Event::Retry => {
                self.stop_scanner();
                self.open_scanner();
                Task::none()
            }
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
                            let import = import::State::with_data(result);
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

    fn handle_wallet_message(&mut self, msg: wallet::Message) -> Task<Message> {
        let Screen::Wallet(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            wallet::Event::StartSetup => {
                let shares = self.current_shares();
                if let Screen::Wallet(s) = &mut self.screen {
                    s.begin_setup(shares);
                }
                Task::none()
            }
            wallet::Event::BeginCoordination => self.begin_descriptor_coordination(),
            wallet::Event::CancelSetup { session_id } => {
                if let Some(sid) = session_id {
                    self.active_coordinations.remove(&sid);
                    if let Some(node) = self.get_frost_node() {
                        node.cancel_descriptor_session(&sid);
                    }
                }
                Task::none()
            }
            wallet::Event::StartAnnounce => {
                if let Screen::Wallet(s) = &mut self.screen {
                    s.begin_announce();
                }
                Task::none()
            }
            wallet::Event::SubmitAnnounce {
                xpub,
                fingerprint,
                label,
            } => {
                let Some(node) = self.get_frost_node() else {
                    if let Screen::Wallet(s) = &mut self.screen {
                        s.announce_not_connected();
                    }
                    return Task::none();
                };

                let announced = keep_frost_net::AnnouncedXpub {
                    xpub,
                    fingerprint,
                    label: if label.is_empty() { None } else { Some(label) },
                };

                Task::perform(
                    async move {
                        node.announce_xpubs(vec![announced])
                            .await
                            .map_err(|e| format!("{e}"))
                    },
                    Message::WalletAnnounceResult,
                )
            }
            wallet::Event::CopyDescriptor(desc) => iced::clipboard::write(desc),
        }
    }

    fn handle_wallet_global_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::WalletsLoaded(result) => {
                match result {
                    Ok(wallets) => {
                        let mut ws = wallet::State::new(wallets);
                        ws.peer_xpubs = self.peer_xpubs.clone();
                        self.screen = Screen::Wallet(ws);
                    }
                    Err(e) => {
                        self.set_toast(e, ToastKind::Error);
                    }
                }
                Task::none()
            }
            Message::WalletSessionStarted(result) => {
                match result {
                    Ok((session_id, group_pubkey, network, _expected_participants)) => {
                        let on_wallet_screen = matches!(
                            self.screen,
                            Screen::Wallet(wallet::State { setup: Some(_), .. })
                        );
                        if !on_wallet_screen {
                            if let Some(node) = self.get_frost_node() {
                                node.cancel_descriptor_session(&session_id);
                            }
                        } else if self.active_coordinations.len() >= MAX_ACTIVE_COORDINATIONS {
                            if let Some(node) = self.get_frost_node() {
                                node.cancel_descriptor_session(&session_id);
                            }
                            if let Screen::Wallet(wallet::State { setup: Some(s), .. }) =
                                &mut self.screen
                            {
                                s.phase = SetupPhase::Coordinating(DescriptorProgress::Failed(
                                    "Too many active coordinations".to_string(),
                                ));
                            }
                        } else {
                            self.active_coordinations.insert(
                                session_id,
                                ActiveCoordination {
                                    group_pubkey,
                                    network,
                                    is_initiator: true,
                                },
                            );
                            if let Screen::Wallet(wallet::State { setup: Some(s), .. }) =
                                &mut self.screen
                            {
                                s.session_id = Some(session_id);
                            }
                        }
                    }
                    Err(e) => {
                        if let Screen::Wallet(wallet::State { setup: Some(s), .. }) =
                            &mut self.screen
                        {
                            s.phase =
                                SetupPhase::Coordinating(DescriptorProgress::Failed(e.clone()));
                            s.error = Some(e);
                        }
                    }
                }
                Task::none()
            }
            Message::WalletDescriptorProgress(progress, session_id) => {
                if let Some(sid) = session_id {
                    if matches!(progress, DescriptorProgress::Failed(_)) {
                        self.active_coordinations.remove(&sid);
                    }
                    self.update_wallet_setup(&sid, |setup| {
                        setup.phase = SetupPhase::Coordinating(progress);
                    });
                } else if matches!(progress, DescriptorProgress::Contributed) {
                    if let Screen::Wallet(wallet::State { setup: Some(s), .. }) = &mut self.screen {
                        s.phase = SetupPhase::Coordinating(progress);
                    }
                }
                Task::none()
            }
            Message::WalletAnnounceResult(result) => {
                match result {
                    Ok(()) => {
                        if let Screen::Wallet(s) = &mut self.screen {
                            s.announce_submitted();
                        }
                    }
                    Err(e) => {
                        if let Screen::Wallet(s) = &mut self.screen {
                            s.announce_failed(e);
                        }
                    }
                }
                Task::none()
            }
            _ => Task::none(),
        }
    }

    fn begin_descriptor_coordination(&mut self) -> Task<Message> {
        use keep_frost_net::{KeySlot, PolicyTier, WalletPolicy};

        let (share, network, policy) = match &mut self.screen {
            Screen::Wallet(wallet::State { setup: Some(s), .. }) => {
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
            if let Screen::Wallet(wallet::State { setup: Some(s), .. }) = &mut self.screen {
                s.error = Some("Connect to relay first".into());
            }
            return Task::none();
        }

        let Some(node) = self.get_frost_node() else {
            if let Screen::Wallet(wallet::State { setup: Some(s), .. }) = &mut self.screen {
                s.error = Some("Relay node not available".into());
            }
            return Task::none();
        };

        let expected_total = keep_frost_net::participant_indices(&policy).len();

        if let Screen::Wallet(wallet::State { setup: Some(s), .. }) = &mut self.screen {
            s.phase = SetupPhase::Coordinating(DescriptorProgress::WaitingContributions {
                received: 1,
                expected: expected_total,
            });
        }

        let keep_arc = self.keep.clone();
        let net = network.clone();
        let group_pubkey = share.group_pubkey;

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

                Ok::<([u8; 32], [u8; 32], String, usize), String>((
                    session_id,
                    group_pubkey,
                    net,
                    expected_total,
                ))
            },
            Message::WalletSessionStarted,
        )
    }

    fn handle_relay_message(&mut self, msg: relay::Message) -> Task<Message> {
        let Screen::Relay(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            relay::Event::AddRelay(url) => {
                if self.relay_urls.len() >= MAX_RELAYS {
                    self.set_toast(
                        format!("Maximum of {MAX_RELAYS} relays allowed"),
                        ToastKind::Error,
                    );
                    if let Screen::Relay(s) = &mut self.screen {
                        s.clear_input();
                    }
                    return Task::none();
                }
                if let Err(e) = validate_relay_url(&url) {
                    self.set_toast(format!("Invalid relay URL: {e}"), ToastKind::Error);
                    if let Screen::Relay(s) = &mut self.screen {
                        s.clear_input();
                    }
                    return Task::none();
                }
                let normalized = normalize_relay_url(&url);
                let is_new = !self.relay_urls.contains(&normalized);
                if is_new {
                    self.relay_urls.push(normalized.clone());
                    self.save_relay_urls();
                    if let Screen::Relay(s) = &mut self.screen {
                        s.relay_added(normalized);
                    }
                } else if let Screen::Relay(s) = &mut self.screen {
                    s.clear_input();
                }
                Task::none()
            }
            relay::Event::RemoveRelay(i) => {
                if let Screen::Relay(s) = &mut self.screen {
                    if i < s.relay_urls.len() {
                        s.relay_urls.remove(i);
                        self.relay_urls = s.relay_urls.clone();
                        self.save_relay_urls();
                    }
                }
                Task::none()
            }
            relay::Event::Connect => self.handle_connect_relay(),
            relay::Event::Disconnect => {
                self.handle_disconnect_relay();
                Task::none()
            }
            relay::Event::ApproveSignRequest(id) => {
                self.respond_to_sign_request(&id, true);
                Task::none()
            }
            relay::Event::RejectSignRequest(id) => {
                self.respond_to_sign_request(&id, false);
                Task::none()
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
        self.active_coordinations.clear();
        self.peer_xpubs.clear();
        self.identities.clear();
        self.cached_share_count = 0;
        self.cached_nsec_count = 0;
        self.identity_switcher_open = false;
        self.delete_identity_confirm = None;
        self.toast = None;
        self.toast_dismiss_at = None;
        self.frost_last_share = None;
        self.frost_last_relay_urls = None;
        self.nostrconnect_pending = None;
        self.bunker_pending_setup = None;
        self.pin_mismatch = None;
        self.pin_mismatch_confirm = false;
        self.bunker_cert_pin_failed = false;
        self.screen = Screen::Unlock(unlock::State::new(true));
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
        self.cached_share_count = shares.len();
        self.cached_nsec_count = self.current_nsec_keys().len();
        self.resolve_active_share(&shares);
        self.refresh_identities(&shares);
        if matches!(self.screen, Screen::NsecKeys(_)) {
            self.set_nsec_keys_screen();
        } else if let Screen::ShareList(s) = &mut self.screen {
            s.refresh(shares, self.active_share_hex.clone());
        }
    }

    fn set_share_screen(&mut self, shares: Vec<ShareEntry>) {
        self.cached_share_count = shares.len();
        self.cached_nsec_count = self.current_nsec_keys().len();
        self.resolve_active_share(&shares);
        self.refresh_identities(&shares);
        self.screen = Screen::ShareList(shares::State::new(shares, self.active_share_hex.clone()));
    }

    fn current_nsec_keys(&self) -> Vec<NsecKeyEntry> {
        let guard = lock_keep(&self.keep);
        let Some(keep) = guard.as_ref() else {
            return Vec::new();
        };
        keep.list_keys()
            .unwrap_or_default()
            .iter()
            .filter_map(NsecKeyEntry::from_record)
            .collect()
    }

    fn set_nsec_keys_screen(&mut self) {
        let keys = self.current_nsec_keys();
        self.cached_nsec_count = keys.len();
        self.screen = Screen::NsecKeys(nsec_keys::State::new(keys, self.active_share_hex.clone()));
    }

    fn handle_nsec_keys_message(&mut self, msg: nsec_keys::Message) -> Task<Message> {
        let Screen::NsecKeys(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            nsec_keys::Event::GoToImport => self.handle_navigation_message(Message::GoToImport),
            nsec_keys::Event::ActivateKey(hex) => {
                self.handle_identity_message(Message::SwitchIdentity(hex))
            }
            nsec_keys::Event::ExportNcryptsec(hex) => self.handle_go_to_export_ncryptsec(hex),
            nsec_keys::Event::CopyNpub(npub) => self.handle_copy_npub(npub),
            nsec_keys::Event::ConfirmDelete(hex) => self.handle_nsec_key_delete(hex),
        }
    }

    fn handle_nsec_key_delete(&mut self, hex: String) -> Task<Message> {
        let Screen::NsecKeys(s) = &self.screen else {
            return Task::none();
        };
        let Some(key) = s.keys().iter().find(|k| k.pubkey_hex == hex) else {
            return Task::none();
        };
        let (pubkey, name) = (key.pubkey, key.name.clone());
        if self.active_share_hex.as_deref() == Some(hex.as_str()) {
            self.handle_disconnect_relay();
            self.stop_bunker();
        }
        let delete_result = {
            let mut guard = lock_keep(&self.keep);
            guard.as_mut().map(|keep| keep.delete_key(&pubkey))
        };
        match delete_result {
            Some(Ok(())) => {
                {
                    let guard = lock_keep(&self.keep);
                    if let Some(keep) = guard.as_ref() {
                        let _ = keep.delete_relay_config(&pubkey);
                    }
                }
                self.refresh_shares();
                self.set_toast(format!("'{name}' deleted"), ToastKind::Success);
            }
            Some(Err(e)) => {
                if let Screen::NsecKeys(s) = &mut self.screen {
                    s.clear_delete_confirm();
                }
                self.set_toast(friendly_err(e), ToastKind::Error);
            }
            None => {
                if let Screen::NsecKeys(s) = &mut self.screen {
                    s.clear_delete_confirm();
                }
                self.set_toast("Vault locked or unavailable".into(), ToastKind::Error);
            }
        }
        Task::none()
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

    pub(crate) fn set_toast(&mut self, message: String, kind: ToastKind) {
        self.toast = Some(Toast { message, kind });
        self.toast_dismiss_at = Some(Instant::now() + Duration::from_secs(TOAST_DURATION_SECS));
    }

    pub(crate) fn proxy_addr(&self) -> Option<SocketAddr> {
        if self.proxy_enabled && self.proxy_port > 0 {
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, self.proxy_port)))
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
            session_timeout: if self.proxy_enabled {
                Some(PROXY_SESSION_TIMEOUT)
            } else {
                None
            },
            certificate_pins: self.certificate_pins.clone(),
            keep_path: self.keep_path.clone(),
        }
    }

    fn active_group_pubkey_bytes(&self) -> Option<[u8; 32]> {
        self.active_share_hex.as_deref().and_then(parse_hex_key)
    }

    fn update_relay_config(&self, f: impl FnOnce(&mut keep_core::RelayConfig)) {
        let guard = lock_keep(&self.keep);
        let Some(keep) = guard.as_ref() else { return };
        let key = self
            .active_group_pubkey_bytes()
            .unwrap_or(keep_core::GLOBAL_RELAY_KEY);
        let mut config = keep
            .get_relay_config(&key)
            .ok()
            .flatten()
            .unwrap_or_else(|| keep_core::RelayConfig::new(key));
        f(&mut config);
        if let Err(e) = keep.store_relay_config(&config) {
            tracing::error!("Failed to save relay config: {e}");
        }
    }

    pub(crate) fn save_relay_urls(&self) {
        let urls = self.relay_urls.clone();
        self.update_relay_config(|config| config.frost_relays = urls);
    }

    pub(crate) fn save_bunker_relays(&self) {
        let relays = self.bunker_relays.clone();
        self.update_relay_config(|config| config.bunker_relays = relays);
    }

    fn save_proxy_config(&self) {
        let guard = lock_keep(&self.keep);
        if let Some(keep) = guard.as_ref() {
            let proxy = keep_core::ProxyConfig {
                enabled: self.proxy_enabled,
                port: self.proxy_port,
            };
            if let Err(e) = keep.set_proxy_config(&proxy) {
                tracing::error!("Failed to save proxy config: {e}");
            }
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
                self.load_config_from_vault();
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

    fn apply_relay_config(&mut self, config: keep_core::RelayConfig) {
        self.relay_urls = config.frost_relays;
        self.bunker_relays = if config.bunker_relays.is_empty() {
            default_bunker_relays()
        } else {
            config.bunker_relays
        };
    }

    fn load_config_from_vault(&mut self) {
        let (relay_config, proxy) = {
            let guard = lock_keep(&self.keep);
            let Some(keep) = guard.as_ref() else {
                return;
            };

            migrate_json_config_to_vault(keep, &self.keep_path);

            let key = self
                .active_group_pubkey_bytes()
                .unwrap_or(keep_core::GLOBAL_RELAY_KEY);
            let relay_config = keep
                .get_relay_config_or_default(&key)
                .unwrap_or_else(|_| keep_core::RelayConfig::with_defaults(key));
            let proxy = keep.get_proxy_config().unwrap_or_default();
            (relay_config, proxy)
        };
        self.apply_relay_config(relay_config);
        self.proxy_enabled = proxy.enabled;
        self.proxy_port = proxy.port;
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
                    s.clear_delete_confirm();
                }
                self.set_toast(friendly_err(e), ToastKind::Error);
            }
        }
    }

    fn handle_create_keyset_validated(
        &mut self,
        name: String,
        threshold: u16,
        total: u16,
    ) -> Task<Message> {
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

    fn handle_copy_npub(&self, npub: String) -> Task<Message> {
        iced::clipboard::write(npub)
    }

    fn handle_generate_export_validated(
        &mut self,
        share: ShareEntry,
        passphrase: Zeroizing<String>,
    ) -> Task<Message> {
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

    fn handle_copy_sensitive(&mut self, data: Zeroizing<String>) -> Task<Message> {
        self.start_clipboard_timer();
        self.copy_feedback_until = Some(Instant::now() + Duration::from_secs(TOAST_DURATION_SECS));
        match &mut self.screen {
            Screen::Export(s) => s.copied = true,
            Screen::ExportNcryptsec(s) => s.copied = true,
            _ => {}
        }
        iced::clipboard::write((*data).clone())
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

    fn handle_import_share(
        &mut self,
        data: Zeroizing<String>,
        passphrase: Zeroizing<String>,
    ) -> Task<Message> {
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

    fn handle_import_nsec(&mut self, data: Zeroizing<String>, name: String) -> Task<Message> {
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
        match result {
            Ok((shares, name)) => {
                self.cached_share_count = shares.len();
                self.refresh_identities(&shares);
                self.set_nsec_keys_screen();
                self.set_toast(
                    format!("'{name}' imported successfully"),
                    ToastKind::Success,
                );
            }
            Err(e) => self.screen.set_loading_error(e),
        }
        Task::none()
    }

    fn handle_import_ncryptsec(
        &mut self,
        data: Zeroizing<String>,
        password: Zeroizing<String>,
        name: String,
    ) -> Task<Message> {
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

    fn handle_go_to_export_ncryptsec(&mut self, pubkey_hex: String) -> Task<Message> {
        let identity = self.identities.iter().find(|i| i.pubkey_hex == pubkey_hex);
        if let Some(id) = identity {
            self.screen = Screen::ExportNcryptsec(Box::new(export_ncryptsec::State::new(
                id.pubkey_hex.clone(),
                id.name.clone(),
                id.npub.clone(),
            )));
        }
        Task::none()
    }

    fn handle_ncryptsec_export_message(&mut self, msg: export_ncryptsec::Message) -> Task<Message> {
        let Screen::ExportNcryptsec(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            export_ncryptsec::Event::GoBack => self.handle_navigation_message(Message::GoBack),
            export_ncryptsec::Event::Generate {
                pubkey_hex,
                password,
            } => self.handle_generate_ncryptsec(pubkey_hex, password),
            export_ncryptsec::Event::CopyToClipboard(t) => self.handle_copy_sensitive(t),
            export_ncryptsec::Event::Reset => {
                self.copy_feedback_until = None;
                if let Screen::ExportNcryptsec(s) = &mut self.screen {
                    s.reset();
                }
                Task::none()
            }
        }
    }

    fn handle_generate_ncryptsec(
        &mut self,
        pubkey_hex: String,
        password: Zeroizing<String>,
    ) -> Task<Message> {
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
                    with_keep_blocking(&keep_arc, "Internal error during export", move |keep| {
                        let ncryptsec = keep
                            .export_ncryptsec(&pubkey_bytes, &password)
                            .map_err(friendly_err)?;
                        Ok(ExportData {
                            bech32: Zeroizing::new(ncryptsec),
                            frames: Vec::new(),
                        })
                    })
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::NcryptsecGenerated,
        )
    }

    fn handle_ncryptsec_generated(&mut self, result: Result<ExportData, String>) -> Task<Message> {
        match result {
            Ok(data) => {
                if let Screen::ExportNcryptsec(s) = &mut self.screen {
                    s.set_result(data.bech32);
                }
            }
            Err(e) => self.screen.set_loading_error(e),
        }
        Task::none()
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

    fn handle_signing_audit_message(
        &mut self,
        msg: crate::screen::signing_audit::Message,
    ) -> Task<Message> {
        let Screen::SigningAudit(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            crate::screen::signing_audit::Event::FilterChanged(caller) => {
                if let Screen::SigningAudit(s) = &mut self.screen {
                    s.selected_caller = caller.clone();
                    s.entries.clear();
                    s.loading = true;
                    s.has_more = false;
                }
                Self::load_audit_page(self.keep.clone(), 0, caller, Message::AuditLoaded)
            }
            crate::screen::signing_audit::Event::LoadMore => {
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
        }
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

                if let Some(key) = parse_hex_key(&pubkey_hex) {
                    let config = {
                        let guard = lock_keep(&self.keep);
                        guard.as_ref().map(|keep| {
                            keep.get_relay_config_or_default(&key)
                                .unwrap_or_else(|_| keep_core::RelayConfig::with_defaults(key))
                        })
                    };
                    if let Some(config) = config {
                        self.apply_relay_config(config);
                    }
                }

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
                    if let Some(pubkey_bytes) = parse_hex_key(&pubkey_hex) {
                        let mut guard = lock_keep(&self.keep);
                        if let Some(keep) = guard.as_mut() {
                            let _ = keep.keyring_mut().set_primary(pubkey_bytes);
                        }
                    }
                }

                self.active_share_hex = Some(pubkey_hex);
                self.identity_switcher_open = false;
                self.delete_identity_confirm = None;

                let shares = self.current_shares();
                match &self.screen {
                    Screen::ShareList(_) => {
                        self.screen = Screen::ShareList(shares::State::new(
                            shares,
                            self.active_share_hex.clone(),
                        ));
                    }
                    Screen::Relay(_) => {
                        self.screen = Screen::Relay(relay::State::new(
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
                    Screen::NsecKeys(_) => {
                        self.set_nsec_keys_screen();
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
                    if let Some(key) = parse_hex_key(&pubkey_hex) {
                        let guard = lock_keep(&self.keep);
                        if let Some(keep) = guard.as_ref() {
                            let _ = keep.delete_relay_config(&key);
                        }
                    }
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

    fn handle_settings_message_new(
        &mut self,
        msg: crate::screen::settings::Message,
    ) -> Task<Message> {
        use crate::screen::settings::Event;
        let Screen::Settings(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            Event::AutoLockChanged(secs) => {
                self.settings.auto_lock_secs = secs;
                if let Screen::Settings(s) = &mut self.screen {
                    s.auto_lock_secs = secs;
                }
            }
            Event::ClipboardClearChanged(secs) => {
                self.settings.clipboard_clear_secs = secs;
                if secs == 0 {
                    self.clipboard_clear_at = None;
                }
                if let Screen::Settings(s) = &mut self.screen {
                    s.clipboard_clear_secs = secs;
                }
            }
            Event::ProxyToggled(enabled) => {
                self.proxy_enabled = enabled;
                let frost_active = matches!(
                    self.frost_status,
                    ConnectionStatus::Connected | ConnectionStatus::Connecting
                );
                let bunker_active = self.bunker.is_some();
                self.save_proxy_config();
                if let Screen::Settings(s) = &mut self.screen {
                    s.proxy_enabled = self.proxy_enabled;
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
                save_settings(&self.keep_path, &self.settings);
                return Task::batch(tasks);
            }
            Event::ProxyPortChanged(port) => {
                self.proxy_port = port;
                self.save_proxy_config();
                if let Screen::Settings(s) = &mut self.screen {
                    s.sync_proxy_port(self.proxy_port);
                }
                return Task::none();
            }
            Event::MinimizeToTrayToggled(v) => {
                self.settings.minimize_to_tray = v;
                if let Screen::Settings(s) = &mut self.screen {
                    s.minimize_to_tray = v;
                }
                if !v && !self.window_visible {
                    self.window_visible = true;
                    save_settings(&self.keep_path, &self.settings);
                    return iced::window::oldest().and_then(|id| {
                        Task::batch([
                            iced::window::set_mode(id, iced::window::Mode::Windowed),
                            iced::window::gain_focus(id),
                        ])
                    });
                }
            }
            Event::StartMinimizedToggled(v) => {
                self.settings.start_minimized = v;
                if let Screen::Settings(s) = &mut self.screen {
                    s.start_minimized = v;
                }
            }
            Event::KillSwitchActivate => {
                return self.handle_kill_switch_activate();
            }
            Event::KillSwitchDeactivate(password) => {
                return self.handle_kill_switch_deactivate(password);
            }
            Event::CertPinClear(hostname) => {
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
                return Task::none();
            }
            Event::BackupExport(passphrase) => {
                return self.handle_backup_export(passphrase);
            }
            Event::RestoreStart => {
                return self.handle_restore_file_pick();
            }
            Event::RestoreSubmit {
                passphrase,
                vault_password,
            } => {
                return self.handle_restore_submit(passphrase, vault_password);
            }
            Event::CertPinClearAll => {
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
                        s.clear_all_pins_done();
                    }
                    self.set_toast("Cleared all certificate pins".into(), ToastKind::Success);
                } else {
                    self.set_toast("Failed to clear pins".into(), ToastKind::Error);
                }
                return Task::none();
            }
        }
        save_settings(&self.keep_path, &self.settings);
        Task::none()
    }

    fn sync_cert_pins_to_screen(&mut self) {
        let entries = self.cert_pin_display_entries();
        if let Screen::Settings(s) = &mut self.screen {
            s.certificate_pins = entries;
        }
    }

    fn handle_cert_pin_message(&mut self, message: Message) -> Task<Message> {
        match message {
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

    fn handle_kill_switch_activate(&mut self) -> Task<Message> {
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
            s.kill_switch_activated();
        }
        self.set_toast(
            "Kill switch activated - all signing blocked".into(),
            ToastKind::Success,
        );
        Task::none()
    }

    fn handle_kill_switch_deactivate(&mut self, password: Zeroizing<String>) -> Task<Message> {
        let keep_arc = self.keep.clone();
        Task::perform(
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
        )
    }

    fn handle_kill_switch_deactivate_result(
        &mut self,
        result: Result<(), String>,
    ) -> Task<Message> {
        match result {
            Ok(()) => {
                {
                    let mut guard = lock_keep(&self.keep);
                    if let Some(keep) = guard.as_mut() {
                        if let Err(e) = keep.set_kill_switch(false) {
                            if let Screen::Settings(s) = &mut self.screen {
                                s.kill_switch_deactivate_failed(friendly_err(e));
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
                    s.kill_switch_deactivated();
                }
                self.set_toast(
                    "Kill switch deactivated - signing re-enabled".into(),
                    ToastKind::Success,
                );
            }
            Err(e) => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.kill_switch_deactivate_failed(e);
                }
            }
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

    fn handle_backup_export(&mut self, passphrase: Zeroizing<String>) -> Task<Message> {
        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                let dialog = rfd::AsyncFileDialog::new()
                    .set_file_name("keep-backup.kbak")
                    .set_title("Save Vault Backup");
                let Some(handle) = dialog.save_file().await else {
                    return Err("Cancelled".into());
                };
                let path = handle.path().to_path_buf();
                let filename = path
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "backup".into());
                let backup_data = tokio::task::spawn_blocking(move || {
                    with_keep_blocking(&keep_arc, "Backup failed", move |keep| {
                        keep_core::backup::create_backup(keep, &passphrase).map_err(friendly_err)
                    })
                })
                .await
                .map_err(|_| "Background task failed".to_string())??;
                tokio::task::spawn_blocking(move || write_private_bytes(&path, &backup_data))
                    .await
                    .map_err(|_| "Background task failed".to_string())?
                    .map_err(|e| format!("Failed to write backup: {e}"))?;
                Ok(filename)
            },
            Message::BackupResult,
        )
    }

    fn handle_backup_result(&mut self, result: Result<String, String>) -> Task<Message> {
        match result {
            Ok(filename) => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.backup_completed();
                }
                self.set_toast(format!("Backup saved to {filename}"), ToastKind::Success);
            }
            Err(ref e) if e == "Cancelled" => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.backup_loading = false;
                }
            }
            Err(e) => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.backup_failed(e.clone());
                }
                self.set_toast(e, ToastKind::Error);
            }
        }
        Task::none()
    }

    fn handle_restore_file_pick(&mut self) -> Task<Message> {
        Task::perform(
            async {
                let dialog = rfd::AsyncFileDialog::new()
                    .add_filter("Keep Backup", &["kbak"])
                    .set_title("Open Vault Backup");
                match dialog.pick_file().await {
                    Some(handle) => {
                        let meta = std::fs::metadata(handle.path())
                            .map_err(|e| format!("Failed to read file: {e}"))?;
                        if meta.len() > keep_core::backup::MAX_BACKUP_SIZE as u64 {
                            return Err(format!(
                                "Backup file too large ({} bytes, max {})",
                                meta.len(),
                                keep_core::backup::MAX_BACKUP_SIZE
                            ));
                        }
                        let name = handle.file_name();
                        let data = handle.read().await;
                        Ok((name, data))
                    }
                    None => Err("Cancelled".to_string()),
                }
            },
            |result: Result<(String, Vec<u8>), String>| match result {
                Ok((name, data)) => Message::RestoreFileLoaded(name, data),
                Err(_) => Message::Settings(crate::screen::settings::Message::RestoreCancel),
            },
        )
    }

    fn handle_restore_submit(
        &mut self,
        passphrase: Zeroizing<String>,
        vault_password: Zeroizing<String>,
    ) -> Task<Message> {
        let file_data = if let Screen::Settings(s) = &self.screen {
            s.restore_file.as_ref().map(|(_, data)| data.clone())
        } else {
            None
        };
        let Some(data) = file_data else {
            return Task::none();
        };
        let keep_path = self.keep_path.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
                    let restore_dir = keep_path.with_file_name(format!("keep-restored-{ts}"));
                    let info = keep_core::backup::restore_backup(
                        &data,
                        &passphrase,
                        &restore_dir,
                        &vault_password,
                    )
                    .map_err(friendly_err)?;
                    Ok(format!(
                        "Restored {} keys, {} shares, {} descriptors to {}",
                        info.key_count,
                        info.share_count,
                        info.descriptor_count,
                        restore_dir.display()
                    ))
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::RestoreResult,
        )
    }

    fn handle_restore_result(&mut self, result: Result<String, String>) -> Task<Message> {
        match result {
            Ok(summary) => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.restore_completed();
                }
                self.set_toast(summary, ToastKind::Success);
            }
            Err(e) => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.restore_failed(e.clone());
                }
                self.set_toast(e, ToastKind::Error);
            }
        }
        Task::none()
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
        };
        let json = serde_json::to_string(&s).unwrap();
        let parsed: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.auto_lock_secs, 60);
        assert_eq!(parsed.clipboard_clear_secs, 10);
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
