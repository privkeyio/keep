use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use nostr_sdk::prelude::ToBech32;
use tokio::sync::{broadcast, Mutex};

use keep_core::frost::SharePackage;
use keep_core::keyring::Keyring;
use keep_frost_net::{KfpNode, KfpNodeEvent, SessionInfo, SigningHooks};
use keep_nip46::types::{ApprovalRequest, LogEvent, ServerCallbacks};
use keep_nip46::{NetworkFrostSigner, Permission, Server, ServerConfig};

use crate::state::{BunkerInfo, Event};

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the main thread waits for the bunker thread to report startup
/// before giving up (relay connect + announce + server bind). Bounded so a
/// hung startup surfaces a clear error instead of blocking the daemon forever.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(45);

fn recv_startup<T>(rx: Receiver<Result<T, String>>) -> Result<T, String> {
    match rx.recv_timeout(STARTUP_TIMEOUT) {
        Ok(res) => res,
        Err(RecvTimeoutError::Timeout) => Err(format!(
            "bunker did not start within {}s",
            STARTUP_TIMEOUT.as_secs()
        )),
        Err(RecvTimeoutError::Disconnected) => Err("bunker thread terminated before start".into()),
    }
}

/// Bridges the bunker's NIP-46 client callbacks onto the web event stream.
///
/// `on_log` fans out to every connected browser; `request_approval` parks the
/// signing thread until a `POST /api/approvals/:id` resolves it (or it times
/// out). This gates requests from NIP-46 *clients* that connect to this box.
struct WebCallbacks {
    events: broadcast::Sender<Event>,
    approvals: Arc<StdMutex<HashMap<u64, Sender<bool>>>>,
    /// Kill switch (network-FROST only). When co-signing is off, sign requests
    /// are refused without prompting; `None` for single-key (no kill switch).
    signing_enabled: Option<Arc<AtomicBool>>,
}

/// Random, unguessable approval id (defense-in-depth alongside the auth gate).
/// Masked to 53 bits so the value round-trips losslessly through a JS Number
/// (IEEE-754 double) in the browser client.
fn random_approval_id() -> u64 {
    u64::from_le_bytes(keep_core::crypto::random_bytes()) & ((1u64 << 53) - 1)
}

impl ServerCallbacks for WebCallbacks {
    fn on_log(&self, event: LogEvent) {
        let _ = self.events.send(Event::Log {
            app: event.app,
            action: event.action,
            success: event.success,
            detail: event.detail,
        });
    }

    fn request_approval(&self, request: ApprovalRequest) -> bool {
        // Co-signing is off (kill switch): refuse signing without bothering the
        // operator with a prompt that would only fail at the FROST layer.
        if request.method == "sign_event"
            && self
                .signing_enabled
                .as_ref()
                .is_some_and(|e| !e.load(Ordering::SeqCst))
        {
            let _ = self.events.send(Event::Log {
                app: "frost".into(),
                action: "refused (co-signing disabled)".into(),
                success: false,
                detail: Some("enable co-signing to approve requests".into()),
            });
            return false;
        }
        let id = random_approval_id();
        let (tx, rx) = channel();
        if let Ok(mut map) = self.approvals.lock() {
            map.insert(id, tx);
        }

        let _ = self.events.send(Event::Approval {
            id,
            app: request.app_name,
            method: request.method,
            kind: request.event_kind.map(|k| k.as_u16()),
            preview: request.event_content,
        });

        // `block_in_place` requires a multi-thread runtime; both spawners use
        // `Runtime::new()` (multi-thread), so this is sound. Do not switch them
        // to a current-thread runtime without changing this to `spawn_blocking`.
        let decision = tokio::task::block_in_place(|| await_decision(&rx, APPROVAL_TIMEOUT));
        if let Ok(mut map) = self.approvals.lock() {
            map.remove(&id);
        }
        decision
    }
}

/// Blocks until the browser resolves the request or the timeout fires. Fails
/// closed: a timeout or a dropped sender (no decision) denies. The timeout also
/// backstops the approvals map so it cannot grow unbounded if a request is
/// never resolved via the API.
fn await_decision(rx: &Receiver<bool>, timeout: Duration) -> bool {
    rx.recv_timeout(timeout).unwrap_or(false)
}

fn short_id(id: &[u8; 32]) -> String {
    id[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Policy gate for this node's participation in peer-initiated FROST rounds.
///
/// The always-on co-signer auto-participates within policy rather than
/// prompting a human (the human approval happens on the *initiating* device).
/// `enabled = false` is the kill switch: the node refuses to co-sign. The flag
/// is shared with the API so it can be toggled live (no restart). Every
/// decision is streamed to the web UI for observability.
struct CoSignerPolicy {
    events: broadcast::Sender<Event>,
    enabled: Arc<AtomicBool>,
}

impl SigningHooks for CoSignerPolicy {
    fn pre_sign(&self, session: &SessionInfo) -> keep_frost_net::Result<()> {
        let detail = format!(
            "session {} · threshold {} · {} participants",
            short_id(&session.session_id),
            session.threshold,
            session.participants.len(),
        );
        if self.enabled.load(Ordering::SeqCst) {
            let _ = self.events.send(Event::Log {
                app: "frost".into(),
                action: "co-signing".into(),
                success: true,
                detail: Some(detail),
            });
            Ok(())
        } else {
            let _ = self.events.send(Event::Log {
                app: "frost".into(),
                action: "refused (co-signing disabled)".into(),
                success: false,
                detail: Some(detail),
            });
            Err(keep_frost_net::FrostNetError::PolicyViolation(
                "co-signing disabled".into(),
            ))
        }
    }

    fn post_sign(&self, session: &SessionInfo, _signature: &[u8; 64]) {
        let _ = self.events.send(Event::Log {
            app: "frost".into(),
            action: "co-signed".into(),
            success: true,
            detail: Some(format!("session {}", short_id(&session.session_id))),
        });
    }
}

/// Maps a node lifecycle event to a web activity entry, or `None` for events
/// the co-signer UI doesn't surface here (signing rounds are already reported
/// through the signing hooks above).
fn node_event_to_log(ev: &KfpNodeEvent) -> Option<Event> {
    match ev {
        KfpNodeEvent::PeerDiscovered { share_index, name } => Some(Event::Log {
            app: "frost".into(),
            action: "peer online".into(),
            success: true,
            detail: Some(match name {
                Some(n) => format!("share {share_index} ({n})"),
                None => format!("share {share_index}"),
            }),
        }),
        KfpNodeEvent::PeerOffline { share_index } => Some(Event::Log {
            app: "frost".into(),
            action: "peer offline".into(),
            success: false,
            detail: Some(format!("share {share_index}")),
        }),
        _ => None,
    }
}

/// Parameters for the always-on network-FROST co-signer.
pub struct NetworkConfig {
    pub share: SharePackage,
    pub group_pubkey: [u8; 32],
    pub group_npub: String,
    pub frost_relays: Vec<String>,
    pub bunker_relays: Vec<String>,
    pub enabled: Arc<AtomicBool>,
    /// Persisted NIP-46 secret embedded in the bunker URL and required in the
    /// connect handshake. Clients (Amethyst, etc.) reject a secret-less URL.
    pub bunker_secret: String,
    /// Persisted transport key = the bunker URL's pubkey identity. Stable so the
    /// URL doesn't change across restarts and saved client connections survive.
    pub transport_key: [u8; 32],
}

/// What `spawn_network_frost` reports back once the co-signer is up.
pub struct NetworkHandle {
    pub info: BunkerInfo,
    pub node: Arc<KfpNode>,
}

/// Spawns the always-on network-FROST co-signer: a long-lived `KfpNode` that
/// holds one share and coordinates with peers over the FROST relays, fronted by
/// a NIP-46 bunker on the bunker relays. Runs on a dedicated thread+runtime
/// (the server/node are driven by a non-`Send` event loop, mirroring the CLI).
pub fn spawn_network_frost(
    cfg: NetworkConfig,
    events: broadcast::Sender<Event>,
    approvals: Arc<StdMutex<HashMap<u64, Sender<bool>>>>,
) -> Result<NetworkHandle, String> {
    let (info_tx, info_rx) = channel::<Result<NetworkHandle, String>>();

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = info_tx.send(Err(format!("tokio runtime: {e}")));
                return;
            }
        };
        rt.block_on(async move {
            let threshold = cfg.share.metadata.threshold;
            let total = cfg.share.metadata.total_shares;

            let node = match KfpNode::new(cfg.share, cfg.frost_relays.clone()).await {
                Ok(n) => Arc::new(n),
                Err(e) => {
                    let _ = info_tx.send(Err(format!("frost node: {e}")));
                    return;
                }
            };

            node.set_hooks(Arc::new(CoSignerPolicy {
                events: events.clone(),
                enabled: cfg.enabled.clone(),
            }));

            // Mirror node lifecycle events (peer presence) into the web activity
            // feed so the UI reflects who is online, not just signing rounds.
            let mut node_events = node.subscribe();
            let events_for_feed = events.clone();
            tokio::spawn(async move {
                loop {
                    match node_events.recv().await {
                        Ok(ev) => {
                            if let Some(log) = node_event_to_log(&ev) {
                                let _ = events_for_feed.send(log);
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            });

            if let Err(e) = node.announce().await {
                let _ = info_tx.send(Err(format!("announce: {e}")));
                return;
            }

            let node_for_run = node.clone();
            tokio::spawn(async move {
                if let Err(e) = node_for_run.run().await {
                    tracing::error!(error = %e, "frost node exited");
                }
            });

            let node_for_state = node.clone();
            let signer = NetworkFrostSigner::with_shared_node(cfg.group_pubkey, node);
            // Persisted (not freshly generated) so the bunker URL pubkey is
            // stable across restarts and saved client connections keep working.
            let transport_key = cfg.transport_key;
            let callbacks: Arc<dyn ServerCallbacks> = Arc::new(WebCallbacks {
                events,
                approvals,
                signing_enabled: Some(cfg.enabled.clone()),
            });

            let mut server = match Server::new_network_frost_with_config(
                signer,
                transport_key,
                &cfg.bunker_relays,
                Some(callbacks),
                ServerConfig {
                    // Least privilege for the co-signer: connect handshake +
                    // signing only, not NIP-04/44 encrypt/decrypt.
                    connect_grant: Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT,
                    // Authenticate clients with a stable secret embedded in the
                    // bunker URL. The kill switch is enforced at the FROST policy
                    // layer (CoSignerPolicy) and the approval gate above; we do
                    // not wire ServerConfig.kill_switch because its polarity is
                    // inverted relative to `signing_enabled`.
                    expected_secret: Some(cfg.bunker_secret),
                    ..ServerConfig::default()
                },
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    let _ = info_tx.send(Err(format!("bunker start: {e}")));
                    return;
                }
            };

            let info = BunkerInfo {
                mode: "network-frost".into(),
                url: server.bunker_url(),
                npub: server.pubkey().to_bech32().unwrap_or_default(),
                bunker_relays: cfg.bunker_relays,
                frost_relays: cfg.frost_relays,
                group: Some(cfg.group_npub),
                threshold: Some(format!("{threshold}-of-{total}")),
            };
            let _ = info_tx.send(Ok(NetworkHandle {
                info,
                node: node_for_state,
            }));

            if let Err(e) = server.run().await {
                tracing::error!(error = %e, "bunker exited");
            }
        });
    });

    recv_startup(info_rx)
}

/// Spawns the single-key fallback bunker (no FROST group configured). The vault
/// signs with its primary key directly: convenient, but the full key lives on
/// this one box, so it does not provide threshold security.
pub fn spawn_single_key(
    keyring: Arc<Mutex<Keyring>>,
    relays: Vec<String>,
    bunker_secret: String,
    events: broadcast::Sender<Event>,
    approvals: Arc<StdMutex<HashMap<u64, Sender<bool>>>>,
) -> Result<BunkerInfo, String> {
    let (info_tx, info_rx) = channel::<Result<BunkerInfo, String>>();

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = info_tx.send(Err(format!("tokio runtime: {e}")));
                return;
            }
        };
        rt.block_on(async move {
            let callbacks: Arc<dyn ServerCallbacks> = Arc::new(WebCallbacks {
                events,
                approvals,
                signing_enabled: None,
            });
            let mut server = match Server::new_with_config(
                keyring,
                None,
                None,
                &relays,
                Some(callbacks),
                ServerConfig {
                    // Least privilege for the single-key fallback: connect +
                    // signing only.
                    connect_grant: Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT,
                    // Same secret-in-URL handshake as the network path so
                    // clients can authenticate.
                    expected_secret: Some(bunker_secret),
                    ..ServerConfig::default()
                },
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    let _ = info_tx.send(Err(format!("bunker start: {e}")));
                    return;
                }
            };
            let info = BunkerInfo {
                mode: "single-key".into(),
                url: server.bunker_url(),
                npub: server.pubkey().to_bech32().unwrap_or_default(),
                bunker_relays: relays,
                frost_relays: Vec::new(),
                group: None,
                threshold: None,
            };
            let _ = info_tx.send(Ok(info));

            if let Err(e) = server.run().await {
                tracing::error!(error = %e, "bunker exited");
            }
        });
    });

    recv_startup(info_rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_id_is_js_safe() {
        const MAX_SAFE: u64 = (1u64 << 53) - 1;
        for _ in 0..10_000 {
            assert!(random_approval_id() <= MAX_SAFE);
        }
    }

    fn session() -> SessionInfo {
        SessionInfo {
            session_id: [7u8; 32],
            message: vec![1, 2, 3],
            threshold: 2,
            participants: vec![1, 2, 3],
            requester: 1,
            message_type: String::new(),
        }
    }

    #[test]
    fn pre_sign_respects_kill_switch() {
        let (tx, mut rx) = broadcast::channel(8);
        let enabled = Arc::new(AtomicBool::new(true));
        let policy = CoSignerPolicy {
            events: tx,
            enabled: enabled.clone(),
        };

        assert!(policy.pre_sign(&session()).is_ok());
        enabled.store(false, Ordering::SeqCst);
        assert!(policy.pre_sign(&session()).is_err());

        // Each decision is streamed for observability (co-signing, then refused).
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn await_decision_fails_closed() {
        // Explicit approval and rejection pass through.
        let (tx, rx) = channel();
        tx.send(true).unwrap();
        assert!(await_decision(&rx, Duration::from_secs(1)));
        let (tx, rx) = channel();
        tx.send(false).unwrap();
        assert!(!await_decision(&rx, Duration::from_secs(1)));

        // Timeout with no decision denies.
        let (_tx, rx) = channel::<bool>();
        assert!(!await_decision(&rx, Duration::from_millis(10)));

        // A dropped sender (no decision possible) denies.
        let (tx, rx) = channel::<bool>();
        drop(tx);
        assert!(!await_decision(&rx, Duration::from_secs(1)));
    }
}
