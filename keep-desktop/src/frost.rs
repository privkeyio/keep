// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keep_frost_net::{KfpNode, KfpNodeEvent, PeerStatus, SessionInfo, SigningHooks};
use rand::Rng as _;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use keep_core::Keep;

use crate::app::{
    friendly_err, lock_keep, with_keep_blocking, App, ToastKind, MAX_PENDING_REQUESTS,
    MAX_REQUESTS_PER_PEER, RATE_LIMIT_GLOBAL, RATE_LIMIT_PER_PEER, RATE_LIMIT_WINDOW_SECS,
    RECONNECT_BASE_MS, RECONNECT_MAX_ATTEMPTS, RECONNECT_MAX_MS, SIGNING_RESPONSE_TIMEOUT,
};
use crate::message::{ConnectionStatus, FrostNodeMsg, Message, PeerEntry, PendingSignRequest};
use crate::screen::relay::RelayScreen;
use crate::screen::shares::ShareEntry;
use crate::screen::Screen;

const MAX_FROST_EVENT_QUEUE: usize = 1000;

pub(crate) async fn verify_relay_certificates(
    relay_urls: &[String],
    certificate_pins: &Mutex<keep_frost_net::CertificatePinSet>,
    keep_path: &std::path::Path,
) -> Result<(), String> {
    for url in relay_urls {
        if url.starts_with("wss://") {
            let mut pins = certificate_pins
                .lock()
                .map_err(|_| "Pin lock poisoned".to_string())?
                .clone();
            keep_frost_net::verify_relay_certificate(url, &mut pins)
                .await
                .map_err(|e| format!("{e}"))?;
            let mut guard = certificate_pins
                .lock()
                .map_err(|_| "Pin lock poisoned".to_string())?;
            for (hostname, hash) in pins.pins() {
                if guard.get_pin(hostname).is_none() {
                    guard.add_pin(hostname.clone(), *hash);
                }
            }
            drop(guard);
            crate::app::save_cert_pins_pub(keep_path, certificate_pins);
        }
    }
    Ok(())
}

pub(crate) fn parse_pin_mismatch(error: &str) -> Option<crate::message::PinMismatchInfo> {
    // Match the format from FrostNetError::CertificatePinMismatch Display:
    // "Certificate pin mismatch for {hostname}: expected {expected}, got {actual}"
    let rest = error.strip_prefix("Certificate pin mismatch for ")?;
    let (hostname, rest) = rest.split_once(": expected ")?;
    let (expected, rest) = rest.split_once(", got ")?;
    let actual = rest.trim();
    if hostname.is_empty() || expected.is_empty() || actual.is_empty() {
        return None;
    }
    Some(crate::message::PinMismatchInfo {
        hostname: hostname.to_string(),
        expected: expected.to_string(),
        actual: actual.to_string(),
    })
}

#[derive(Clone)]
pub(crate) struct NetworkConfig {
    pub proxy: Option<SocketAddr>,
    pub session_timeout: Option<Duration>,
    pub certificate_pins: Arc<Mutex<keep_frost_net::CertificatePinSet>>,
    pub keep_path: std::path::PathBuf,
}

#[derive(Clone)]
pub(crate) struct FrostChannels {
    pub events: Arc<Mutex<VecDeque<FrostNodeMsg>>>,
    pub pending_requests: Arc<Mutex<Vec<PendingRequestEntry>>>,
    pub shutdown: Arc<Mutex<Option<mpsc::Sender<()>>>>,
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
            let mut result = String::new();
            let mut char_count = 0usize;
            let mut line_count = 0usize;
            for ch in s.chars() {
                if ch == '\n' {
                    line_count += 1;
                    if line_count >= MAX_LINES {
                        result.push_str("...");
                        return result;
                    }
                    result.push('\n');
                    continue;
                }
                if ch.is_control() {
                    continue;
                }
                if char_count >= MAX_CHARS {
                    result.push_str("...");
                    return result;
                }
                result.push(ch);
                char_count += 1;
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

pub(crate) struct DesktopSigningHooks {
    pub request_tx: mpsc::Sender<(SessionInfo, mpsc::Sender<bool>)>,
    pub kill_switch: Arc<AtomicBool>,
}

impl SigningHooks for DesktopSigningHooks {
    fn pre_sign(&self, session: &SessionInfo) -> keep_frost_net::Result<()> {
        if self.kill_switch.load(Ordering::Acquire) {
            return Err(keep_frost_net::FrostNetError::Session(
                "Kill switch active".into(),
            ));
        }
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

pub(crate) struct PendingRequestEntry {
    pub info: PendingSignRequest,
    pub response_tx: mpsc::Sender<bool>,
}

pub(crate) struct FrostNodeSetup {
    pub node: Arc<KfpNode>,
    pub connect_rx: tokio::sync::broadcast::Receiver<KfpNodeEvent>,
    pub run_error_rx: mpsc::Receiver<String>,
}

pub(crate) async fn setup_frost_node(
    keep_arc: Arc<Mutex<Option<Keep>>>,
    keep_path: std::path::PathBuf,
    share_entry: ShareEntry,
    relay_urls: Vec<String>,
    ch: FrostChannels,
    net: NetworkConfig,
    kill_switch: Arc<AtomicBool>,
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

    verify_relay_certificates(&relay_urls, &net.certificate_pins, &net.keep_path).await?;

    let nonce_store = keep_frost_net::FileNonceStore::new(&nonce_store_path)
        .map_err(|e| format!("Failed to create nonce store: {e}"))?;
    let node = KfpNode::with_nonce_store(
        share,
        relay_urls,
        Some(Arc::new(nonce_store) as Arc<dyn keep_frost_net::NonceStore>),
        net.proxy,
        net.session_timeout,
    )
    .await
    .map_err(|e| format!("Connection failed: {e}"))?;

    let (request_tx, request_rx) = mpsc::channel(32);
    let hooks = Arc::new(DesktopSigningHooks {
        request_tx,
        kill_switch,
    });
    node.set_hooks(hooks);

    let event_rx = node.subscribe();
    let connect_rx = node.subscribe();
    let node = Arc::new(node);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
    let (listener_shutdown_tx, mut listener_shutdown_rx) = mpsc::channel::<()>(1);

    if let Ok(mut guard) = ch.shutdown.lock() {
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

    let listener_events = ch.events;
    let listener_requests = ch.pending_requests;
    let listener_node = node.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = frost_event_listener(
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
        node,
        connect_rx,
        run_error_rx,
    })
}

pub(crate) async fn spawn_frost_node(
    keep_arc: Arc<Mutex<Option<Keep>>>,
    keep_path: std::path::PathBuf,
    share_entry: ShareEntry,
    relay_urls: Vec<String>,
    ch: FrostChannels,
    net: NetworkConfig,
    kill_switch: Arc<AtomicBool>,
) -> Result<(), String> {
    let frost_events = ch.events.clone();
    let setup = setup_frost_node(
        keep_arc,
        keep_path,
        share_entry,
        relay_urls,
        ch,
        net,
        kill_switch,
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

    let guard = match pending_requests.lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let peer_pending = guard
        .iter()
        .filter(|r| r.info.from_peer == from_peer)
        .count();
    if peer_pending >= MAX_REQUESTS_PER_PEER {
        return false;
    }

    true
}

pub(crate) async fn frost_event_listener(
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
                let from_peer = session.requester;
                let now = Instant::now();

                if !check_rate_limit(
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

impl App {
    pub(crate) fn drain_frost_events(&mut self) {
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

    pub(crate) fn relay_screen_mut(&mut self) -> Option<&mut RelayScreen> {
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
                self.notify_sign_request(&req);
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

    pub(crate) fn handle_connect_relay(&mut self) -> iced::Task<Message> {
        if self.is_kill_switch_active() {
            self.set_toast(
                "Kill switch is active - signing blocked".into(),
                ToastKind::Error,
            );
            return iced::Task::none();
        }
        self.handle_disconnect_relay();

        let (share_entry, relay_urls, password) = match &mut self.screen {
            Screen::Relay(s) => {
                let Some(idx) = s.selected_share else {
                    return iced::Task::none();
                };
                let Some(share) = s.shares.get(idx) else {
                    return iced::Task::none();
                };
                if s.relay_urls.is_empty() || s.connect_password.is_empty() {
                    return iced::Task::none();
                }
                let pw = s.connect_password.clone();
                s.connect_password = Zeroizing::new(String::new());
                (share.clone(), s.relay_urls.clone(), pw)
            }
            _ => return iced::Task::none(),
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
            return iced::Task::none();
        }

        self.frost_status = ConnectionStatus::Connecting;
        if let Some(s) = self.relay_screen_mut() {
            s.status = ConnectionStatus::Connecting;
        }
        self.frost_last_share = Some(share_entry.clone());
        self.frost_last_relay_urls = Some(relay_urls.clone());

        iced::Task::perform(
            spawn_frost_node(
                self.keep.clone(),
                self.keep_path.clone(),
                share_entry,
                relay_urls,
                self.frost_channels(),
                self.network_config(),
                self.kill_switch.clone(),
            ),
            Message::ConnectRelayResult,
        )
    }

    pub(crate) fn handle_disconnect_relay(&mut self) {
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
            for entry in guard.drain(..) {
                let _ = entry.response_tx.try_send(false);
            }
        }
        if let Some(s) = self.relay_screen_mut() {
            s.status = ConnectionStatus::Disconnected;
            s.peers.clear();
            s.pending_requests.clear();
        }
    }

    pub(crate) fn handle_reconnect_relay(&mut self) -> iced::Task<Message> {
        if self.is_kill_switch_active() {
            return iced::Task::none();
        }
        let Some(share_entry) = self.frost_last_share.clone() else {
            return iced::Task::none();
        };
        let Some(relay_urls) = self.frost_last_relay_urls.clone() else {
            return iced::Task::none();
        };
        if lock_keep(&self.keep).is_none() {
            return iced::Task::none();
        }

        if let Ok(mut guard) = self.frost_shutdown.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
        }
        self.frost_peers.clear();
        self.pending_sign_display.clear();
        if let Ok(mut guard) = self.pending_sign_requests.lock() {
            for entry in guard.drain(..) {
                let _ = entry.response_tx.try_send(false);
            }
        }

        self.frost_status = ConnectionStatus::Connecting;
        if let Some(s) = self.relay_screen_mut() {
            s.status = ConnectionStatus::Connecting;
            s.peers.clear();
            s.pending_requests.clear();
        }

        iced::Task::perform(
            spawn_frost_node(
                self.keep.clone(),
                self.keep_path.clone(),
                share_entry,
                relay_urls,
                self.frost_channels(),
                self.network_config(),
                self.kill_switch.clone(),
            ),
            Message::ConnectRelayResult,
        )
    }

    pub(crate) fn respond_to_sign_request(&mut self, id: &str, approve: bool) {
        if approve && self.is_kill_switch_active() {
            self.set_toast(
                "Kill switch is active - signing blocked".into(),
                ToastKind::Error,
            );
            return;
        }
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

    pub(crate) fn handle_connect_relay_result(
        &mut self,
        result: Result<(), String>,
    ) -> iced::Task<Message> {
        let status = match &result {
            Ok(()) => {
                self.frost_reconnect_attempts = 0;
                self.frost_reconnect_at = None;
                ConnectionStatus::Connected
            }
            Err(e) => {
                if let Some(mismatch) = parse_pin_mismatch(e) {
                    self.pin_mismatch = Some(mismatch);
                    self.frost_reconnect_at = None;
                } else if self.frost_reconnect_attempts < RECONNECT_MAX_ATTEMPTS {
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
        iced::Task::none()
    }
}
