// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::{HashMap, VecDeque};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iced::widget::{column, container, text};
use iced::{Background, Element, Length, Subscription, Task};
use keep_core::frost::ShareExport;
use keep_core::relay::{normalize_relay_url, validate_relay_url, MAX_RELAYS};
use keep_core::Keep;
use keep_frost_net::{KfpNode, KfpNodeEvent, PeerStatus, SessionInfo, SigningHooks};
use rand::Rng as _;
use tokio::sync::mpsc;
use tracing::error;
use zeroize::Zeroizing;

use crate::message::{
    ConnectionStatus, ExportData, FrostNodeMsg, Message, PeerEntry, PendingSignRequest,
    ShareIdentity,
};
use crate::screen::create::CreateScreen;
use crate::screen::export::ExportScreen;
use crate::screen::import::ImportScreen;
use crate::screen::relay::RelayScreen;
use crate::screen::shares::{ShareEntry, ShareListScreen};
use crate::screen::unlock::UnlockScreen;
use crate::screen::wallet::{WalletEntry, WalletScreen};
use crate::screen::Screen;

const AUTO_LOCK_SECS: u64 = 300;
const CLIPBOARD_CLEAR_SECS: u64 = 30;
const MIN_PASSWORD_LEN: usize = 8;
pub const MIN_EXPORT_PASSPHRASE_LEN: usize = 15;
const TOAST_DURATION_SECS: u64 = 5;
const SIGNING_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_FROST_EVENT_QUEUE: usize = 1000;
const MAX_PENDING_REQUESTS: usize = 10;
const MAX_REQUESTS_PER_PEER: usize = 3;
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
const RATE_LIMIT_PER_PEER: usize = 30;
const RATE_LIMIT_GLOBAL: usize = 100;
const RECONNECT_BASE_MS: u64 = 200;
const RECONNECT_MAX_MS: u64 = 30_000;
const RECONNECT_MAX_ATTEMPTS: u32 = 10;

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

struct DesktopSigningHooks {
    request_tx: mpsc::Sender<(SessionInfo, mpsc::Sender<bool>)>,
}

impl SigningHooks for DesktopSigningHooks {
    fn pre_sign(&self, session: &SessionInfo) -> keep_frost_net::Result<()> {
        let (response_tx, mut response_rx) = mpsc::channel(1);
        let request_tx = self.request_tx.clone();
        let session = session.clone();

        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async {
                request_tx
                    .send((session, response_tx))
                    .await
                    .map_err(|_| keep_frost_net::FrostNetError::Session("Channel closed".into()))?;

                match tokio::time::timeout(SIGNING_RESPONSE_TIMEOUT, response_rx.recv()).await {
                    Ok(Some(true)) => Ok(()),
                    Ok(Some(false)) => Err(keep_frost_net::FrostNetError::Session(
                        "Request rejected".into(),
                    )),
                    Ok(None) => Err(keep_frost_net::FrostNetError::Session("No response".into())),
                    Err(_) => Err(keep_frost_net::FrostNetError::Session("Timeout".into())),
                }
            })
        })
    }

    fn post_sign(&self, _session: &SessionInfo, _signature: &[u8; 64]) {}
}

struct PendingRequestEntry {
    info: PendingSignRequest,
    response_tx: mpsc::Sender<bool>,
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
    frost_shutdown: Arc<Mutex<Option<mpsc::Sender<()>>>>,
    frost_events: Arc<Mutex<VecDeque<FrostNodeMsg>>>,
    pending_sign_requests: Arc<Mutex<Vec<PendingRequestEntry>>>,
    relay_urls: Vec<String>,
    frost_status: ConnectionStatus,
    frost_peers: Vec<PeerEntry>,
    pending_sign_display: Vec<PendingSignRequest>,
    frost_reconnect_attempts: u32,
    frost_reconnect_at: Option<Instant>,
    frost_last_share: Option<ShareEntry>,
    frost_last_relay_urls: Option<Vec<String>>,
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

fn relay_config_path(keep_path: &std::path::Path) -> PathBuf {
    keep_path.join("relays.json")
}

fn load_relay_urls(keep_path: &std::path::Path) -> Vec<String> {
    let path = relay_config_path(keep_path);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_relay_urls(keep_path: &std::path::Path, urls: &[String]) {
    let path = relay_config_path(keep_path);
    if let Ok(json) = serde_json::to_string_pretty(urls) {
        if let Err(e) = std::fs::write(&path, json) {
            tracing::error!("Failed to save relay config to {}: {e}", path.display());
        }
    }
}

fn push_frost_event(queue: &Mutex<VecDeque<FrostNodeMsg>>, event: FrostNodeMsg) {
    if let Ok(mut q) = queue.lock() {
        if q.len() >= MAX_FROST_EVENT_QUEUE {
            q.pop_front();
        }
        q.push_back(event);
    }
}

fn sanitize_message_preview(msg: &[u8]) -> String {
    const MAX_CHARS: usize = 500;
    const MAX_LINES: usize = 10;
    const MAX_HEX_BYTES: usize = 64;

    match std::str::from_utf8(msg) {
        Ok(s) => {
            let cleaned: String = s
                .chars()
                .filter(|c| !c.is_control() || *c == '\n')
                .collect();
            let mut result = String::new();
            for (i, line) in cleaned.split('\n').enumerate() {
                if i >= MAX_LINES {
                    result.push_str("...");
                    return result;
                }
                if i > 0 {
                    result.push('\n');
                }
                result.push_str(line);
                if result.len() >= MAX_CHARS {
                    let boundary = result
                        .char_indices()
                        .map(|(i, _)| i)
                        .take_while(|&i| i <= MAX_CHARS)
                        .last()
                        .unwrap_or(0);
                    result.truncate(boundary);
                    result.push_str("...");
                    return result;
                }
            }
            result
        }
        Err(_) => {
            let len = msg.len().min(MAX_HEX_BYTES);
            let mut h = hex::encode(&msg[..len]);
            if msg.len() > MAX_HEX_BYTES {
                h.push_str("...");
            }
            h
        }
    }
}

struct FrostNodeSetup {
    node: Arc<KfpNode>,
    connect_rx: tokio::sync::broadcast::Receiver<KfpNodeEvent>,
    run_error_rx: mpsc::Receiver<String>,
}

async fn setup_frost_node(
    keep_arc: Arc<Mutex<Option<Keep>>>,
    keep_path: PathBuf,
    share_entry: ShareEntry,
    relay_urls: Vec<String>,
    frost_events: Arc<Mutex<VecDeque<FrostNodeMsg>>>,
    pending_requests: Arc<Mutex<Vec<PendingRequestEntry>>>,
    frost_shutdown: Arc<Mutex<Option<mpsc::Sender<()>>>>,
) -> Result<FrostNodeSetup, String> {
    let share = tokio::task::spawn_blocking({
        let keep_arc = keep_arc.clone();
        let group_pubkey = share_entry.group_pubkey;
        let identifier = share_entry.identifier;
        move || {
            with_keep_blocking(&keep_arc, "Failed to load share", move |keep| {
                keep.frost_get_share_by_index(&group_pubkey, identifier)
                    .map_err(friendly_err)
            })
        }
    })
    .await
    .map_err(|_| "Background task failed".to_string())??;

    let nonce_store_path = keep_path.join("frost-nonces");
    keep_frost_net::install_default_crypto_provider();
    let node = KfpNode::with_nonce_store_path(share, relay_urls, &nonce_store_path)
        .await
        .map_err(|e| format!("Connection failed: {e}"))?;

    let (request_tx, request_rx) = mpsc::channel(32);
    let hooks = Arc::new(DesktopSigningHooks { request_tx });
    node.set_hooks(hooks);

    let event_rx = node.subscribe();
    let connect_rx = node.subscribe();
    let node = Arc::new(node);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
    let (listener_shutdown_tx, mut listener_shutdown_rx) = mpsc::channel::<()>(1);

    if let Ok(mut guard) = frost_shutdown.lock() {
        *guard = Some(shutdown_tx);
    }

    let (run_error_tx, run_error_rx) = mpsc::channel::<String>(1);
    let run_node = node.clone();
    tokio::spawn(async move {
        tokio::select! {
            result = run_node.run() => {
                if let Err(e) = result {
                    tracing::error!("Node run failed: {e}");
                    let _ = run_error_tx.send(format!("{e}")).await;
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("Node shutdown requested");
            }
        }
        drop(listener_shutdown_tx);
    });

    let listener_events = frost_events;
    let listener_requests = pending_requests;
    let listener_node = node.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = App::frost_event_listener(
                event_rx,
                request_rx,
                listener_events,
                listener_requests,
                listener_node,
            ) => {}
            _ = listener_shutdown_rx.recv() => {}
        }
    });

    Ok(FrostNodeSetup {
        node: node.clone(),
        connect_rx,
        run_error_rx,
    })
}

async fn spawn_frost_node(
    keep_arc: Arc<Mutex<Option<Keep>>>,
    keep_path: PathBuf,
    share_entry: ShareEntry,
    relay_urls: Vec<String>,
    frost_events: Arc<Mutex<VecDeque<FrostNodeMsg>>>,
    pending_requests: Arc<Mutex<Vec<PendingRequestEntry>>>,
    frost_shutdown: Arc<Mutex<Option<mpsc::Sender<()>>>>,
) -> Result<(), String> {
    let setup = setup_frost_node(
        keep_arc,
        keep_path,
        share_entry,
        relay_urls,
        frost_events.clone(),
        pending_requests,
        frost_shutdown,
    )
    .await?;

    let _node = setup.node;
    let mut connect_rx = setup.connect_rx;
    let mut run_error_rx = setup.run_error_rx;

    let connect_timeout = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(connect_timeout);
    loop {
        tokio::select! {
            err = run_error_rx.recv() => {
                let msg = err.unwrap_or_else(|| "Node stopped unexpectedly".into());
                push_frost_event(
                    &frost_events,
                    FrostNodeMsg::StatusChanged(ConnectionStatus::Error(msg.clone())),
                );
                return Err(msg);
            }
            result = connect_rx.recv() => {
                match result {
                    Ok(KfpNodeEvent::PeerDiscovered { .. }) => break,
                    Ok(_) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err("Node stopped unexpectedly".into());
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
            _ = &mut connect_timeout => {
                break;
            }
        }
    }

    Ok(())
}

impl App {
    fn init(keep_path: PathBuf, screen: Screen, relay_urls: Vec<String>) -> Self {
        Self {
            keep: Arc::new(Mutex::new(None)),
            keep_path,
            screen,
            active_share_hex: None,
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
            frost_last_share: None,
            frost_last_relay_urls: None,
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
                    return (Self::init(PathBuf::new(), screen, Vec::new()), Task::none());
                }
            },
        };
        let vault_exists = keep_path.exists();
        let relay_urls = load_relay_urls(&keep_path);
        let screen = Screen::Unlock(UnlockScreen::new(vault_exists));
        (Self::init(keep_path, screen, relay_urls), Task::none())
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

            Message::ImportDataChanged(..)
            | Message::ImportPassphraseChanged(..)
            | Message::ImportShare
            | Message::ImportResult(..) => self.handle_import_message(message),

            Message::CopyNpub(..)
            | Message::CopyDescriptor(..)
            | Message::ToggleWalletDetails(..) => self.handle_wallet_message(message),

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
        }
    }

    fn handle_tick(&mut self) -> Task<Message> {
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
        if self.frost_reconnect_at.is_some_and(|t| now >= t) {
            self.frost_reconnect_at = None;
            self.drain_frost_events();
            return self.handle_reconnect_relay();
        }
        self.drain_frost_events();
        Task::none()
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
                let shares = self.current_shares();
                if !shares.iter().any(|s| s.group_pubkey_hex == hex) {
                    self.set_toast("Share not found".into(), ToastKind::Error);
                    return Task::none();
                }

                let result = {
                    let guard = lock_keep(&self.keep);
                    guard.as_ref().map(|k| k.set_active_share_key(Some(&hex)))
                };
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
            _ => Task::none(),
        }
    }

    fn handle_import_message(&mut self, message: Message) -> Task<Message> {
        match message {
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
            _ => Task::none(),
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
            _ => Task::none(),
        }
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
                    save_relay_urls(&self.keep_path, &self.relay_urls);
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
                        save_relay_urls(&self.keep_path, &self.relay_urls);
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
            Message::ConnectRelayResult(result) => {
                let status = match &result {
                    Ok(()) => {
                        self.frost_reconnect_attempts = 0;
                        self.frost_reconnect_at = None;
                        ConnectionStatus::Connected
                    }
                    Err(e) => {
                        if self.frost_reconnect_attempts < RECONNECT_MAX_ATTEMPTS {
                            let base = RECONNECT_BASE_MS
                                .saturating_mul(1u64 << self.frost_reconnect_attempts.min(15))
                                .min(RECONNECT_MAX_MS);
                            let jitter = rand::rng().random_range(0..base / 4);
                            let delay_ms = base + jitter;
                            self.frost_reconnect_at =
                                Some(Instant::now() + Duration::from_millis(delay_ms));
                            self.frost_reconnect_attempts += 1;
                        }
                        ConnectionStatus::Error(e.clone())
                    }
                };
                self.frost_status = status.clone();
                if let Some(s) = self.relay_screen_mut() {
                    s.status = status;
                }
                Task::none()
            }
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
        let screen = self.screen.view(pending_count);
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

    fn drain_frost_events(&mut self) {
        let events: Vec<FrostNodeMsg> = {
            let Ok(mut queue) = self.frost_events.lock() else {
                return;
            };
            queue.drain(..).collect()
        };

        for event in events {
            self.handle_frost_event(event);
        }
    }

    fn relay_screen_mut(&mut self) -> Option<&mut RelayScreen> {
        if let Screen::Relay(s) = &mut self.screen {
            Some(s)
        } else {
            None
        }
    }

    fn handle_frost_event(&mut self, event: FrostNodeMsg) {
        match event {
            FrostNodeMsg::PeerUpdate(peers) => {
                self.frost_peers = peers.clone();
                if let Some(s) = self.relay_screen_mut() {
                    s.peers = peers;
                }
            }
            FrostNodeMsg::NewSignRequest(req) => {
                self.pending_sign_display.push(req.clone());
                if let Some(s) = self.relay_screen_mut() {
                    s.pending_requests.push(req);
                }
            }
            FrostNodeMsg::SignRequestRemoved(id) => {
                if let Ok(mut guard) = self.pending_sign_requests.lock() {
                    guard.retain(|r| r.info.id != id);
                }
                self.pending_sign_display.retain(|r| r.id != id);
                if let Some(s) = self.relay_screen_mut() {
                    s.pending_requests.retain(|r| r.id != id);
                }
            }
            FrostNodeMsg::StatusChanged(status) => {
                self.frost_status = status.clone();
                if let Some(s) = self.relay_screen_mut() {
                    s.status = status;
                }
            }
        }
    }

    fn handle_connect_relay(&mut self) -> Task<Message> {
        self.handle_disconnect_relay();

        let (share_entry, relay_urls, password) = match &mut self.screen {
            Screen::Relay(s) => {
                let Some(idx) = s.selected_share else {
                    return Task::none();
                };
                let Some(share) = s.shares.get(idx) else {
                    return Task::none();
                };
                if s.relay_urls.is_empty() || s.connect_password.is_empty() {
                    return Task::none();
                }
                let pw = s.connect_password.clone();
                s.connect_password = Zeroizing::new(String::new());
                (share.clone(), s.relay_urls.clone(), pw)
            }
            _ => return Task::none(),
        };

        let pw_result = {
            let guard = lock_keep(&self.keep);
            match guard.as_ref() {
                None => Err("Keep not available".to_string()),
                Some(keep) => keep.verify_password(&password).map_err(friendly_err),
            }
        };
        if let Err(e) = pw_result {
            self.set_toast(e, ToastKind::Error);
            return Task::none();
        }

        self.frost_status = ConnectionStatus::Connecting;
        if let Some(s) = self.relay_screen_mut() {
            s.status = ConnectionStatus::Connecting;
        }
        self.frost_last_share = Some(share_entry.clone());
        self.frost_last_relay_urls = Some(relay_urls.clone());

        Task::perform(
            spawn_frost_node(
                self.keep.clone(),
                self.keep_path.clone(),
                share_entry,
                relay_urls,
                self.frost_events.clone(),
                self.pending_sign_requests.clone(),
                self.frost_shutdown.clone(),
            ),
            Message::ConnectRelayResult,
        )
    }

    fn handle_disconnect_relay(&mut self) {
        if let Ok(mut guard) = self.frost_shutdown.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
        }
        self.frost_status = ConnectionStatus::Disconnected;
        self.frost_peers.clear();
        self.pending_sign_display.clear();
        self.frost_reconnect_attempts = 0;
        self.frost_reconnect_at = None;
        if let Ok(mut guard) = self.pending_sign_requests.lock() {
            guard.clear();
        }
        if let Some(s) = self.relay_screen_mut() {
            s.status = ConnectionStatus::Disconnected;
            s.peers.clear();
            s.pending_requests.clear();
        }
    }

    fn handle_reconnect_relay(&mut self) -> Task<Message> {
        let Some(share_entry) = self.frost_last_share.clone() else {
            return Task::none();
        };
        let Some(relay_urls) = self.frost_last_relay_urls.clone() else {
            return Task::none();
        };
        if lock_keep(&self.keep).is_none() {
            return Task::none();
        }

        if let Ok(mut guard) = self.frost_shutdown.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
        }
        self.frost_peers.clear();
        self.pending_sign_display.clear();
        if let Ok(mut guard) = self.pending_sign_requests.lock() {
            guard.clear();
        }

        self.frost_status = ConnectionStatus::Connecting;
        if let Some(s) = self.relay_screen_mut() {
            s.status = ConnectionStatus::Connecting;
            s.peers.clear();
            s.pending_requests.clear();
        }

        Task::perform(
            spawn_frost_node(
                self.keep.clone(),
                self.keep_path.clone(),
                share_entry,
                relay_urls,
                self.frost_events.clone(),
                self.pending_sign_requests.clone(),
                self.frost_shutdown.clone(),
            ),
            Message::ConnectRelayResult,
        )
    }

    fn respond_to_sign_request(&mut self, id: &str, approve: bool) {
        let response_tx = {
            let Ok(mut guard) = self.pending_sign_requests.lock() else {
                return;
            };
            let Some(idx) = guard.iter().position(|r| r.info.id == id) else {
                return;
            };
            let entry = guard.remove(idx);
            entry.response_tx
        };

        let _ = response_tx.try_send(approve);

        self.pending_sign_display.retain(|r| r.id != id);
        if let Some(s) = self.relay_screen_mut() {
            s.pending_requests.retain(|r| r.id != id);
        }
    }

    fn check_rate_limit(
        global_times: &mut VecDeque<Instant>,
        peer_times_map: &mut HashMap<u16, VecDeque<Instant>>,
        pending_requests: &Mutex<Vec<PendingRequestEntry>>,
        from_peer: u16,
        now: Instant,
        window: Duration,
    ) -> bool {
        let cutoff = now.checked_sub(window).unwrap_or(now);
        while global_times.front().is_some_and(|t| *t < cutoff) {
            global_times.pop_front();
        }
        if global_times.len() >= RATE_LIMIT_GLOBAL {
            return false;
        }

        let peer_times = peer_times_map.entry(from_peer).or_default();
        while peer_times.front().is_some_and(|t| *t < cutoff) {
            peer_times.pop_front();
        }
        if peer_times.len() >= RATE_LIMIT_PER_PEER {
            return false;
        }

        if let Ok(guard) = pending_requests.lock() {
            let peer_pending = guard
                .iter()
                .filter(|r| r.info.from_peer == from_peer)
                .count();
            if peer_pending >= MAX_REQUESTS_PER_PEER {
                return false;
            }
        }

        true
    }

    async fn frost_event_listener(
        mut event_rx: tokio::sync::broadcast::Receiver<KfpNodeEvent>,
        mut request_rx: mpsc::Receiver<(SessionInfo, mpsc::Sender<bool>)>,
        frost_events: Arc<Mutex<VecDeque<FrostNodeMsg>>>,
        pending_requests: Arc<Mutex<Vec<PendingRequestEntry>>>,
        node: Arc<KfpNode>,
    ) {
        let mut global_request_times: VecDeque<Instant> = VecDeque::new();
        let mut peer_request_times: HashMap<u16, VecDeque<Instant>> = HashMap::new();
        let window = Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        loop {
            tokio::select! {
                result = event_rx.recv() => {
                    match result {
                        Ok(KfpNodeEvent::PeerDiscovered { .. })
                        | Ok(KfpNodeEvent::PeerOffline { .. }) => {
                            let peers: Vec<PeerEntry> = node
                                .peer_status()
                                .into_iter()
                                .map(|(share_index, status, name)| PeerEntry {
                                    share_index,
                                    name,
                                    online: status == PeerStatus::Online,
                                })
                                .collect();
                            push_frost_event(&frost_events, FrostNodeMsg::PeerUpdate(peers));
                        }
                        Ok(KfpNodeEvent::SignatureComplete { session_id, .. })
                        | Ok(KfpNodeEvent::SigningFailed { session_id, .. }) => {
                            let id = hex::encode(session_id);
                            if let Ok(mut guard) = pending_requests.lock() {
                                guard.retain(|r| r.info.id != id);
                            }
                            push_frost_event(
                                &frost_events,
                                FrostNodeMsg::SignRequestRemoved(id),
                            );
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                result = request_rx.recv() => {
                    let Some((session, response_tx)) = result else {
                        break;
                    };
                    let from_peer = session.participants.first().copied().unwrap_or(0);
                    let now = Instant::now();

                    if !Self::check_rate_limit(
                        &mut global_request_times,
                        &mut peer_request_times,
                        &pending_requests,
                        from_peer,
                        now,
                        window,
                    ) {
                        let _ = response_tx.try_send(false);
                        continue;
                    }

                    let req = PendingSignRequest {
                        id: hex::encode(session.session_id),
                        message_preview: sanitize_message_preview(&session.message),
                        from_peer,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    };

                    if let Ok(mut guard) = pending_requests.lock() {
                        if guard.len() < MAX_PENDING_REQUESTS {
                            global_request_times.push_back(now);
                            peer_request_times.entry(from_peer).or_default().push_back(now);
                            let entry = PendingRequestEntry {
                                info: req.clone(),
                                response_tx,
                            };
                            guard.push(entry);
                            push_frost_event(
                                &frost_events,
                                FrostNodeMsg::NewSignRequest(req),
                            );
                        } else {
                            let _ = response_tx.try_send(false);
                        }
                    }
                }
            }
        }
    }

    fn do_lock(&mut self) -> Task<Message> {
        self.handle_disconnect_relay();

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

    fn set_share_screen(&mut self, shares: Vec<ShareEntry>) {
        self.resolve_active_share(&shares);
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
            Ok(shares) => self.set_share_screen(shares),
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
                self.set_share_screen(shares);
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
