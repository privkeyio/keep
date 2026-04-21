// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keep_frost_net::{KfpNode, KfpNodeEvent, PeerStatus, SessionInfo, SigningHooks};
use rand::RngExt as _;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use keep_core::Keep;

use crate::app::{
    friendly_err, lock_keep, with_keep_blocking, ActiveCoordination, App, ToastKind,
    MAX_ACTIVE_COORDINATIONS, MAX_PENDING_REQUESTS, MAX_REQUESTS_PER_PEER, RATE_LIMIT_GLOBAL,
    RATE_LIMIT_PER_PEER, RATE_LIMIT_WINDOW_SECS, RECONNECT_BASE_MS, RECONNECT_MAX_ATTEMPTS,
    RECONNECT_MAX_MS, SIGNING_RESPONSE_TIMEOUT,
};
use crate::message::{
    ConnectionStatus, EventLogEntry, EventLogType, FrostNodeMsg, Message, PeerEntry,
    PendingSignRequest,
};
use crate::screen::relay;
use crate::screen::shares::ShareEntry;
use crate::screen::wallet::{DescriptorProgress, SetupPhase, SetupState, WalletEntry};
use crate::screen::Screen;

const MAX_FROST_EVENT_QUEUE: usize = 1000;

/// Build a `KeepDescriptorLookup` from an `Arc<Mutex<Option<Keep>>>`. Logs a
/// warning and returns no match when the vault is locked, absent, or the
/// mutex is poisoned.
pub(crate) fn descriptor_lookup_for(
    keep: Arc<Mutex<Option<Keep>>>,
) -> keep_frost_net::KeepDescriptorLookup<
    impl Fn() -> Option<Vec<keep_core::wallet::WalletDescriptor>> + Send + Sync + 'static,
> {
    keep_frost_net::KeepDescriptorLookup::new(move || {
        let guard = keep.lock().ok()?;
        let keep = guard.as_ref()?;
        keep.list_wallet_descriptors().ok()
    })
}

pub(crate) async fn verify_relay_certificates(
    relay_urls: &[String],
    certificate_pins: &Mutex<keep_frost_net::CertificatePinSet>,
    keep_path: &std::path::Path,
) -> Result<(), crate::message::ConnectionError> {
    use crate::message::ConnectionError;
    for url in relay_urls.iter().filter(|u| u.starts_with("wss://")) {
        let pins_snapshot = certificate_pins
            .lock()
            .map_err(|_| ConnectionError::Other("Pin lock poisoned".to_string()))?
            .clone();
        let (_hash, new_pin) = keep_frost_net::verify_relay_certificate(url, &pins_snapshot)
            .await
            .map_err(|e| match e {
                keep_frost_net::FrostNetError::CertificatePinMismatch {
                    hostname,
                    expected,
                    actual,
                } => ConnectionError::PinMismatch(crate::message::PinMismatchInfo {
                    hostname,
                    expected,
                    actual,
                }),
                other => ConnectionError::Other(format!("{other}")),
            })?;
        if let Some((hostname, hash)) = new_pin {
            let mut guard = certificate_pins
                .lock()
                .map_err(|_| ConnectionError::Other("Pin lock poisoned".to_string()))?;
            if guard.get_pin(&hostname).is_none() {
                guard.add_pin(hostname, hash);
            }
            let pins_snapshot = guard.clone();
            drop(guard);
            crate::app::save_cert_pins(keep_path, &pins_snapshot);
        }
    }
    Ok(())
}

fn parse_bitcoin_network(net: &str) -> Result<bitcoin::Network, String> {
    net.parse::<bitcoin::Network>().map_err(|e| format!("{e}"))
}

pub(crate) async fn derive_xpub(
    keep_arc: Arc<Mutex<Option<Keep>>>,
    group_pubkey: [u8; 32],
    identifier: u16,
    network: String,
) -> Result<(String, String), String> {
    tokio::task::spawn_blocking(move || {
        with_keep_blocking(&keep_arc, "Failed to derive xpub", move |keep| {
            let share_pkg = keep
                .frost_get_share_by_index(&group_pubkey, identifier)
                .map_err(friendly_err)?;
            let key_package = share_pkg.key_package().map_err(friendly_err)?;
            let signing_share = key_package.signing_share();
            let serialized = Zeroizing::new(signing_share.serialize());
            let signing_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
                serialized
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Invalid signing share length".to_string())?,
            );
            let bitcoin_network = parse_bitcoin_network(&network)?;
            let derivation = keep_bitcoin::AddressDerivation::new(&signing_bytes, bitcoin_network)
                .map_err(|e| format!("{e}"))?;
            let xpub = derivation.account_xpub(0).map_err(|e| format!("{e}"))?;
            let fingerprint = derivation
                .master_fingerprint()
                .map_err(|e| format!("{e}"))?;
            Ok((xpub.to_string(), fingerprint.to_string()))
        })
    })
    .await
    .map_err(|_| "Background task failed".to_string())?
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

fn truncate_peer_string(s: &str) -> &str {
    let max = 200;
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

fn push_frost_event(queue: &Mutex<VecDeque<FrostNodeMsg>>, event: FrostNodeMsg) {
    match queue.lock() {
        Ok(mut q) => {
            if q.len() >= MAX_FROST_EVENT_QUEUE {
                q.pop_front();
            }
            q.push_back(event);
        }
        Err(e) => {
            tracing::warn!("frost event queue mutex poisoned, dropping event: {e}");
        }
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
) -> Result<FrostNodeSetup, crate::message::ConnectionError> {
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

    let node = node.with_descriptor_lookup(Arc::new(descriptor_lookup_for(keep_arc.clone()))
        as Arc<dyn keep_frost_net::PersistedDescriptorLookup>);

    let session_store_path = nonce_store_path.with_file_name("descriptor-sessions.redb");
    let node = match keep_frost_net::FileDescriptorSessionStore::new(&session_store_path) {
        Ok(store) => node.with_descriptor_session_store(
            Arc::new(store) as Arc<dyn keep_frost_net::DescriptorSessionStore>
        ),
        Err(e) => {
            tracing::warn!("Failed to create descriptor session store: {e}");
            node
        }
    };

    let peer_policies = {
        let guard = keep_arc
            .lock()
            .map_err(|_| String::from("Keep mutex poisoned while loading peer policies"))?;
        let keep = guard
            .as_ref()
            .ok_or_else(|| String::from("Keep not available while loading peer policies"))?;
        match keep.get_relay_config(&share_entry.group_pubkey) {
            Ok(Some(config)) => config.peer_policies,
            Ok(None) => {
                tracing::debug!("No peer policies stored for this share");
                Vec::new()
            }
            Err(e) => {
                return Err(format!("Failed to load peer policies: {e}").into());
            }
        }
    };
    for entry in &peer_policies {
        match nostr_sdk::PublicKey::from_hex(&entry.pubkey_hex) {
            Ok(pubkey) => {
                node.set_peer_policy(
                    keep_frost_net::PeerPolicy::new(pubkey)
                        .allow_send(entry.allow_send)
                        .allow_receive(entry.allow_receive),
                );
            }
            Err(e) => {
                tracing::warn!(
                    pubkey_hex = %entry.pubkey_hex,
                    %e,
                    "Skipping invalid peer policy from vault"
                );
            }
        }
    }

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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_frost_node(
    keep_arc: Arc<Mutex<Option<Keep>>>,
    keep_path: std::path::PathBuf,
    share_entry: ShareEntry,
    relay_urls: Vec<String>,
    ch: FrostChannels,
    net: NetworkConfig,
    kill_switch: Arc<AtomicBool>,
    node_out: Arc<Mutex<Option<Arc<KfpNode>>>>,
) -> Result<(), crate::message::ConnectionError> {
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

    let node = setup.node;
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
                return Err(crate::message::ConnectionError::Other(msg));
            }
            result = connect_rx.recv() => {
                match result {
                    Ok(KfpNodeEvent::PeerDiscovered { .. }) => break,
                    Ok(_) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err(crate::message::ConnectionError::Other("Node stopped unexpectedly".into()));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
            _ = &mut connect_timeout => {
                break;
            }
        }
    }

    match node_out.lock() {
        Ok(mut guard) => *guard = Some(node),
        Err(_) => {
            return Err(crate::message::ConnectionError::Other(
                "Node mutex poisoned".into(),
            ));
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

fn push_log(
    frost_events: &Arc<Mutex<VecDeque<FrostNodeMsg>>>,
    now_secs: u64,
    event_type: EventLogType,
    description: String,
) {
    push_frost_event(
        frost_events,
        FrostNodeMsg::EventLog(EventLogEntry {
            timestamp: now_secs,
            event_type,
            description,
        }),
    );
}

fn build_peer_entries(node: &KfpNode) -> Vec<PeerEntry> {
    node.peer_status()
        .into_iter()
        .map(|(share_index, status, name, pubkey)| {
            let policy = node.get_peer_policy(&pubkey);
            PeerEntry {
                share_index,
                name,
                online: status == PeerStatus::Online,
                pubkey_hex: pubkey.to_hex(),
                allow_send: policy.as_ref().is_none_or(|p| p.allow_send),
                allow_receive: policy.as_ref().is_none_or(|p| p.allow_receive),
            }
        })
        .collect()
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
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                macro_rules! log {
                    ($ty:expr, $desc:expr) => {
                        push_log(&frost_events, now_secs, $ty, $desc)
                    };
                }

                match result {
                    Ok(KfpNodeEvent::PeerDiscovered { share_index, ref name }) => {
                        let label = name.as_deref().unwrap_or("Unknown");
                        log!(EventLogType::PeerJoined, format!("Peer #{share_index} ({label}) joined"));
                        let peers = build_peer_entries(&node);
                        push_frost_event(&frost_events, FrostNodeMsg::PeerUpdate(peers));
                    }
                    Ok(KfpNodeEvent::PeerOffline { share_index }) => {
                        log!(EventLogType::PeerLeft, format!("Peer #{share_index} went offline"));
                        let peers = build_peer_entries(&node);
                        push_frost_event(&frost_events, FrostNodeMsg::PeerUpdate(peers));
                    }
                    Ok(KfpNodeEvent::SigningStarted { session_id }) => {
                        log!(EventLogType::SignRequest, format!("Signing started: {}", &hex::encode(session_id)[..8]));
                    }
                    Ok(KfpNodeEvent::SignatureComplete { session_id, .. }) => {
                        log!(EventLogType::SignComplete, format!("Signature complete: {}", &hex::encode(session_id)[..8]));
                        let id = hex::encode(session_id);
                        if let Ok(mut guard) = pending_requests.lock() {
                            guard.retain(|r| r.info.id != id);
                        }
                        push_frost_event(&frost_events, FrostNodeMsg::SignRequestRemoved(id));
                    }
                    Ok(KfpNodeEvent::SigningFailed { session_id, ref error }) => {
                        log!(EventLogType::SignFailed, format!("Signing failed: {}", truncate_peer_string(error)));
                        let id = hex::encode(session_id);
                        if let Ok(mut guard) = pending_requests.lock() {
                            guard.retain(|r| r.info.id != id);
                        }
                        push_frost_event(&frost_events, FrostNodeMsg::SignRequestRemoved(id));
                    }
                    Ok(KfpNodeEvent::EcdhComplete { session_id, .. }) => {
                        log!(EventLogType::EcdhComplete, format!("ECDH complete: {}", &hex::encode(session_id)[..8]));
                    }
                    Ok(KfpNodeEvent::EcdhFailed { session_id, ref error }) => {
                        log!(EventLogType::EcdhFailed, format!("ECDH failed ({}): {}", &hex::encode(session_id)[..8], truncate_peer_string(error)));
                    }
                    Ok(KfpNodeEvent::DescriptorContributionNeeded {
                        session_id,
                        network,
                        initiator_pubkey,
                        ..
                    }) => {
                        log!(EventLogType::Descriptor, format!("Descriptor contribution needed ({network})"));
                        push_frost_event(
                            &frost_events,
                            FrostNodeMsg::DescriptorContributionNeeded {
                                session_id,
                                network,
                                initiator_pubkey,
                            },
                        );
                    }
                    Ok(KfpNodeEvent::DescriptorContributed {
                        session_id,
                        share_index,
                    }) => {
                        log!(EventLogType::Descriptor, format!("Peer #{share_index} contributed to descriptor"));
                        push_frost_event(
                            &frost_events,
                            FrostNodeMsg::DescriptorContributed {
                                session_id,
                                share_index,
                            },
                        );
                    }
                    Ok(KfpNodeEvent::DescriptorReady { session_id }) => {
                        log!(EventLogType::Descriptor, "Descriptor ready for finalization".to_string());
                        push_frost_event(
                            &frost_events,
                            FrostNodeMsg::DescriptorReady { session_id },
                        );
                    }
                    Ok(KfpNodeEvent::DescriptorComplete {
                        session_id,
                        external_descriptor,
                        internal_descriptor,
                        policy_hash,
                        ..
                    }) => {
                        log!(EventLogType::Descriptor, "Descriptor complete".to_string());
                        push_frost_event(
                            &frost_events,
                            FrostNodeMsg::DescriptorComplete {
                                session_id,
                                external_descriptor,
                                internal_descriptor,
                                policy_hash,
                            },
                        );
                    }
                    Ok(KfpNodeEvent::DescriptorAcked {
                        session_id,
                        share_index,
                        ack_count,
                        expected_acks,
                    }) => {
                        log!(EventLogType::Descriptor, format!("Descriptor ack from #{share_index} ({ack_count}/{expected_acks})"));
                        push_frost_event(
                            &frost_events,
                            FrostNodeMsg::DescriptorAcked {
                                session_id,
                                share_index,
                                ack_count,
                                expected_acks,
                            },
                        );
                    }
                    Ok(KfpNodeEvent::DescriptorNacked {
                        session_id,
                        share_index,
                        reason,
                    }) => {
                        log!(EventLogType::Error, format!("Descriptor nack from #{share_index}: {}", truncate_peer_string(&reason)));
                        push_frost_event(
                            &frost_events,
                            FrostNodeMsg::DescriptorNacked {
                                session_id,
                                share_index,
                                reason,
                            },
                        );
                    }
                    Ok(KfpNodeEvent::DescriptorFailed { session_id, error }) => {
                        log!(EventLogType::Error, format!("Descriptor failed: {}", truncate_peer_string(&error)));
                        push_frost_event(
                            &frost_events,
                            FrostNodeMsg::DescriptorFailed { session_id, error },
                        );
                    }
                    Ok(KfpNodeEvent::XpubAnnounced {
                        share_index,
                        recovery_xpubs,
                    }) => {
                        log!(EventLogType::Descriptor, format!("Peer #{share_index} announced {} xpub(s)", recovery_xpubs.len()));
                        push_frost_event(
                            &frost_events,
                            FrostNodeMsg::XpubAnnounced {
                                share_index,
                                recovery_xpubs,
                            },
                        );
                    }
                    Ok(KfpNodeEvent::HealthCheckComplete {
                        responsive,
                        unresponsive,
                        ..
                    }) => {
                        log!(EventLogType::Descriptor, format!(
                            "Health check: {} responsive, {} unresponsive",
                            responsive.len(),
                            unresponsive.len()
                        ));
                        push_frost_event(
                            &frost_events,
                            FrostNodeMsg::HealthCheckComplete {
                                responsive,
                                unresponsive,
                            },
                        );
                    }
                    Ok(KfpNodeEvent::DescriptorProposed { .. }) => {
                        log!(EventLogType::Descriptor, "Descriptor proposed".to_string());
                    }
                    // TODO(WDC-PSBT): expose PSBT coordination to UI (#331)
                    Ok(KfpNodeEvent::PsbtProposed { session_id, tier_index }) => {
                        log!(EventLogType::Descriptor, format!(
                            "PSBT proposed for tier {tier_index}: {}",
                            &hex::encode(session_id)[..8]
                        ));
                    }
                    Ok(KfpNodeEvent::PsbtSignatureNeeded { session_id, tier_index, initiator_pubkey }) => {
                        log!(EventLogType::Descriptor, format!(
                            "PSBT signature required for tier {tier_index} (session {})",
                            &hex::encode(session_id)[..8]
                        ));
                        let snapshot = node.psbt_session_snapshot(&session_id);
                        push_frost_event(
                            &frost_events,
                            FrostNodeMsg::PsbtSignatureNeeded {
                                session_id,
                                tier_index,
                                initiator_pubkey,
                                snapshot,
                            },
                        );
                    }
                    Ok(KfpNodeEvent::PsbtSignatureReceived { session_id, signature_count, threshold, .. }) => {
                        log!(EventLogType::Descriptor, format!(
                            "PSBT signature received ({signature_count}/{threshold}): {}",
                            &hex::encode(session_id)[..8]
                        ));
                        push_frost_event(
                            &frost_events,
                            FrostNodeMsg::PsbtSignatureReceived {
                                session_id,
                                signature_count,
                                threshold,
                            },
                        );
                    }
                    Ok(KfpNodeEvent::PsbtFinalized { session_id, txid }) => {
                        log!(EventLogType::Descriptor, format!(
                            "PSBT finalized: {}",
                            &hex::encode(session_id)[..8]
                        ));
                        push_frost_event(
                            &frost_events,
                            FrostNodeMsg::PsbtFinalized { session_id, txid },
                        );
                    }
                    Ok(KfpNodeEvent::PsbtAborted { session_id, reason }) => {
                        log!(EventLogType::Error, format!(
                            "PSBT aborted ({}): {}",
                            &hex::encode(session_id)[..8],
                            truncate_peer_string(&reason)
                        ));
                        push_frost_event(
                            &frost_events,
                            FrostNodeMsg::PsbtAborted { session_id, reason },
                        );
                    }
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
    pub(crate) fn drain_frost_events(&mut self) -> iced::Task<Message> {
        let events: Vec<FrostNodeMsg> = {
            let Ok(mut queue) = self.frost_events.lock() else {
                return iced::Task::none();
            };
            queue.drain(..).collect()
        };

        let tasks: Vec<iced::Task<Message>> = events
            .into_iter()
            .map(|event| self.handle_frost_event(event))
            .collect();
        iced::Task::batch(tasks)
    }

    pub(crate) fn relay_screen_mut(&mut self) -> Option<&mut relay::State> {
        if let Screen::Relay(s) = &mut self.screen {
            Some(s)
        } else {
            None
        }
    }

    pub(crate) fn get_frost_node(&self) -> Option<Arc<KfpNode>> {
        self.frost_node.lock().ok()?.clone()
    }

    pub(crate) fn update_wallet_setup(
        &mut self,
        session_id: &[u8; 32],
        f: impl FnOnce(&mut SetupState),
    ) {
        if let Screen::Wallet(ws) = &mut self.screen {
            if let Some(setup) = &mut ws.setup {
                if setup.session_id.as_ref() == Some(session_id) {
                    f(setup);
                }
            }
        }
    }

    fn handle_frost_event(&mut self, event: FrostNodeMsg) -> iced::Task<Message> {
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
            FrostNodeMsg::EventLog(entry) => {
                if self.frost_event_log.len() >= crate::screen::relay::MAX_EVENT_LOG {
                    self.frost_event_log.pop_front();
                }
                self.frost_event_log.push_back(entry.clone());
                if let Some(s) = self.relay_screen_mut() {
                    s.push_event(entry);
                }
            }
            FrostNodeMsg::StatusChanged(status) => {
                self.frost_status = status.clone();
                if let Some(s) = self.relay_screen_mut() {
                    s.status = status;
                }
            }
            FrostNodeMsg::DescriptorContributionNeeded {
                session_id,
                network,
                initiator_pubkey,
            } => {
                return self.handle_descriptor_contribution_needed(
                    session_id,
                    network,
                    initiator_pubkey,
                );
            }
            FrostNodeMsg::DescriptorReady { session_id } => {
                let is_initiator = self
                    .active_coordinations
                    .get(&session_id)
                    .is_some_and(|c| c.is_initiator);
                if !is_initiator {
                    return iced::Task::none();
                }
                self.update_wallet_setup(&session_id, |setup| {
                    setup.phase = SetupPhase::Coordinating(DescriptorProgress::Finalizing);
                });
                let Some(node) = self.get_frost_node() else {
                    self.active_coordinations.remove(&session_id);
                    self.update_wallet_setup(&session_id, |setup| {
                        setup.phase = SetupPhase::Coordinating(DescriptorProgress::Failed(
                            "Node unavailable".to_string(),
                        ));
                    });
                    return iced::Task::none();
                };
                return iced::Task::perform(
                    async move {
                        node.build_and_finalize_descriptor(session_id)
                            .await
                            .map_err(|e| format!("{e}"))
                    },
                    move |result| match result {
                        Ok(expected_acks) => Message::WalletDescriptorProgress(
                            DescriptorProgress::WaitingAcks {
                                received: 0,
                                expected: expected_acks,
                            },
                            Some(session_id),
                        ),
                        Err(e) => Message::WalletDescriptorProgress(
                            DescriptorProgress::Failed(e),
                            Some(session_id),
                        ),
                    },
                );
            }
            FrostNodeMsg::DescriptorContributed { session_id, .. } => {
                self.update_wallet_setup(&session_id, |setup| {
                    if let SetupPhase::Coordinating(DescriptorProgress::WaitingContributions {
                        ref mut received,
                        ..
                    }) = setup.phase
                    {
                        *received += 1;
                    }
                });
            }
            FrostNodeMsg::DescriptorAcked {
                session_id,
                ack_count,
                expected_acks,
                ..
            } => {
                self.update_wallet_setup(&session_id, |setup| {
                    setup.phase = SetupPhase::Coordinating(DescriptorProgress::WaitingAcks {
                        received: ack_count,
                        expected: expected_acks,
                    });
                });
            }
            FrostNodeMsg::DescriptorComplete {
                session_id,
                external_descriptor,
                internal_descriptor,
                policy_hash,
            } => {
                self.handle_descriptor_complete(
                    session_id,
                    external_descriptor,
                    internal_descriptor,
                    policy_hash,
                );
            }
            FrostNodeMsg::DescriptorNacked {
                session_id,
                share_index,
                reason,
            } => {
                self.active_coordinations.remove(&session_id);
                let error = format!("Peer {share_index} rejected descriptor: {reason}");
                self.update_wallet_setup(&session_id, |setup| {
                    setup.phase = SetupPhase::Coordinating(DescriptorProgress::Failed(error));
                });
            }
            FrostNodeMsg::DescriptorFailed { session_id, error } => {
                self.active_coordinations.remove(&session_id);
                self.update_wallet_setup(&session_id, |setup| {
                    setup.phase = SetupPhase::Coordinating(DescriptorProgress::Failed(error));
                });
            }
            FrostNodeMsg::XpubAnnounced {
                share_index,
                recovery_xpubs,
            } => {
                tracing::info!(
                    share_index,
                    count = recovery_xpubs.len(),
                    "Received recovery xpub announcement"
                );
                let entry = self.peer_xpubs.entry(share_index).or_default();
                for xpub in recovery_xpubs {
                    if let Some(existing) = entry.iter_mut().find(|x| x.xpub == xpub.xpub) {
                        existing.fingerprint = xpub.fingerprint;
                        existing.label = xpub.label;
                    } else if entry.len() < keep_frost_net::MAX_RECOVERY_XPUBS {
                        entry.push(xpub);
                    }
                }
                if let Screen::Wallet(ws) = &mut self.screen {
                    ws.peer_xpubs = self.peer_xpubs.clone();
                }
            }
            FrostNodeMsg::HealthCheckComplete {
                responsive,
                unresponsive,
            } => {
                tracing::info!(
                    responsive = responsive.len(),
                    unresponsive = unresponsive.len(),
                    "Health check complete"
                );
                if let Some(s) = self.relay_screen_mut() {
                    for peer in &mut s.peers {
                        if responsive.contains(&peer.share_index) {
                            peer.online = true;
                        } else if unresponsive.contains(&peer.share_index) {
                            peer.online = false;
                        }
                    }
                }
            }
            FrostNodeMsg::PsbtSignatureNeeded {
                session_id,
                tier_index,
                initiator_pubkey,
                snapshot,
            } => {
                tracing::info!(
                    session_id = %hex::encode(session_id),
                    tier_index,
                    has_snapshot = snapshot.is_some(),
                    "PSBT signature needed; routing to wallet screen"
                );
                let entry = crate::screen::wallet::PsbtPendingDisplay {
                    session_id,
                    tier_index,
                    initiator_pubkey,
                    snapshot,
                };
                self.pending_psbt_signatures
                    .retain(|e| e.session_id != session_id);
                self.pending_psbt_signatures.push(entry.clone());
                if let Screen::Wallet(ws) = &mut self.screen {
                    ws.pending_psbt_signatures
                        .retain(|e| e.session_id != session_id);
                    ws.pending_psbt_signatures.push(entry);
                }
            }
            FrostNodeMsg::PsbtSignatureReceived {
                session_id,
                signature_count,
                threshold,
            } => {
                if self.active_psbt_spend == Some(session_id) {
                    if let Screen::Wallet(ws) = &mut self.screen {
                        ws.spend_progress(signature_count, threshold);
                    }
                }
            }
            FrostNodeMsg::PsbtFinalized { session_id, txid } => {
                self.pending_psbt_signatures
                    .retain(|e| e.session_id != session_id);
                if let Screen::Wallet(ws) = &mut self.screen {
                    ws.pending_psbt_signatures
                        .retain(|e| e.session_id != session_id);
                }
                if self.active_psbt_spend == Some(session_id) {
                    self.active_psbt_spend = None;
                    if let Screen::Wallet(ws) = &mut self.screen {
                        ws.spend_finalized(txid);
                    }
                }
            }
            FrostNodeMsg::PsbtAborted { session_id, reason } => {
                self.pending_psbt_signatures
                    .retain(|e| e.session_id != session_id);
                if let Screen::Wallet(ws) = &mut self.screen {
                    ws.pending_psbt_signatures
                        .retain(|e| e.session_id != session_id);
                }
                if self.active_psbt_spend == Some(session_id) {
                    self.active_psbt_spend = None;
                    if let Screen::Wallet(ws) = &mut self.screen {
                        ws.spend_failed(reason);
                    }
                }
            }
        }
        iced::Task::none()
    }

    fn handle_descriptor_contribution_needed(
        &mut self,
        session_id: [u8; 32],
        network: String,
        initiator_pubkey: nostr_sdk::PublicKey,
    ) -> iced::Task<Message> {
        let share = match &self.frost_last_share {
            Some(s) => s.clone(),
            None => return iced::Task::none(),
        };
        let Some(node) = self.get_frost_node() else {
            return iced::Task::none();
        };

        if !keep_frost_net::VALID_NETWORKS.contains(&network.as_str()) {
            tracing::warn!(network = %network, "Ignoring descriptor contribution for invalid network");
            return iced::Task::none();
        }

        if self.active_coordinations.len() >= MAX_ACTIVE_COORDINATIONS {
            tracing::warn!("Dropping descriptor contribution: too many active coordinations");
            return iced::Task::none();
        }

        self.active_coordinations.insert(
            session_id,
            ActiveCoordination {
                group_pubkey: share.group_pubkey,
                network: network.clone(),
                is_initiator: false,
            },
        );

        let keep_arc = self.keep.clone();

        iced::Task::perform(
            async move {
                let (xpub_str, fingerprint_str) =
                    derive_xpub(keep_arc, share.group_pubkey, share.identifier, network).await?;

                node.contribute_descriptor(
                    session_id,
                    &initiator_pubkey,
                    &xpub_str,
                    &fingerprint_str,
                )
                .await
                .map_err(|e| format!("{e}"))?;

                Ok::<(), String>(())
            },
            move |result| match result {
                Ok(()) => Message::WalletDescriptorProgress(DescriptorProgress::Contributed, None),
                Err(e) => Message::WalletDescriptorProgress(
                    DescriptorProgress::Failed(e),
                    Some(session_id),
                ),
            },
        )
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
                self.frost_node.clone(),
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
        self.active_coordinations.clear();
        self.frost_reconnect_attempts = 0;
        self.frost_reconnect_at = None;
        if let Ok(mut guard) = self.frost_node.lock() {
            *guard = None;
        }
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
        if let Ok(mut guard) = self.frost_node.lock() {
            *guard = None;
        }
        self.frost_peers.clear();
        self.pending_sign_display.clear();
        self.active_coordinations.clear();
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
                self.frost_node.clone(),
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

    fn handle_descriptor_complete(
        &mut self,
        session_id: [u8; 32],
        external_descriptor: String,
        internal_descriptor: String,
        policy_hash: [u8; 32],
    ) {
        let Some(coord) = self.active_coordinations.remove(&session_id) else {
            return;
        };
        let group_pubkey = coord.group_pubkey;
        let network = coord.network;

        let created_at = chrono::Utc::now().timestamp().max(0) as u64;
        let descriptor = keep_core::WalletDescriptor {
            group_pubkey,
            external_descriptor: external_descriptor.clone(),
            internal_descriptor: internal_descriptor.clone(),
            network: network.clone(),
            created_at,
            device_registrations: Vec::new(),
            policy_hash,
        };

        let store_result = {
            let guard = lock_keep(&self.keep);
            match guard.as_ref() {
                Some(keep) => keep
                    .store_wallet_descriptor(&descriptor)
                    .map_err(friendly_err),
                None => Err("Keep not available".to_string()),
            }
        };

        let progress = match &store_result {
            Ok(()) => DescriptorProgress::Complete,
            Err(e) => DescriptorProgress::Failed(e.clone()),
        };
        self.update_wallet_setup(&session_id, |setup| {
            setup.phase = SetupPhase::Coordinating(progress);
        });

        if store_result.is_ok() {
            if let Screen::Wallet(ws) = &mut self.screen {
                ws.descriptors.push(WalletEntry {
                    group_pubkey,
                    group_hex: hex::encode(group_pubkey),
                    external_descriptor,
                    internal_descriptor,
                    network,
                    created_at,
                });
            }
        }
    }

    pub(crate) fn handle_connect_relay_result(
        &mut self,
        result: Result<(), crate::message::ConnectionError>,
    ) -> iced::Task<Message> {
        let status = match &result {
            Ok(()) => {
                self.frost_reconnect_attempts = 0;
                self.frost_reconnect_at = None;
                ConnectionStatus::Connected
            }
            Err(e @ crate::message::ConnectionError::PinMismatch(mismatch)) => {
                self.pin_mismatch = Some(mismatch.clone());
                self.frost_reconnect_at = None;
                ConnectionStatus::Error(e.to_string())
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
                ConnectionStatus::Error(format!("{e}"))
            }
        };
        self.frost_status = status.clone();
        if let Some(s) = self.relay_screen_mut() {
            s.status = status;
        }
        iced::Task::none()
    }
}
