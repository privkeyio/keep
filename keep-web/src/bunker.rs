use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use nostr_sdk::prelude::ToBech32;
use tokio::sync::{broadcast, Mutex};

use keep_core::frost::SharePackage;
use keep_core::keyring::Keyring;
use keep_frost_net::{KfpNode, SessionInfo, SigningHooks};
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
}

/// Random, unguessable approval id (defense-in-depth alongside the auth gate).
fn random_approval_id() -> u64 {
    u64::from_le_bytes(keep_core::crypto::random_bytes())
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
        // `recv_timeout` also doubles as the backstop that drops the channel
        // (and lets the resolver-or-here `remove`) so the approvals map cannot
        // grow unbounded even if a request is never resolved via the API.
        let decision =
            tokio::task::block_in_place(|| rx.recv_timeout(APPROVAL_TIMEOUT).unwrap_or(false));
        if let Ok(mut map) = self.approvals.lock() {
            map.remove(&id);
        }
        decision
    }
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

/// Parameters for the always-on network-FROST co-signer.
pub struct NetworkConfig {
    pub share: SharePackage,
    pub group_pubkey: [u8; 32],
    pub group_npub: String,
    pub frost_relays: Vec<String>,
    pub bunker_relays: Vec<String>,
    pub enabled: Arc<AtomicBool>,
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
                enabled: cfg.enabled,
            }));

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
            let transport_key: [u8; 32] = keep_core::crypto::random_bytes();
            let callbacks: Arc<dyn ServerCallbacks> = Arc::new(WebCallbacks {
                events,
                approvals,
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
                relay: cfg.bunker_relays.first().cloned().unwrap_or_default(),
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
/// signs with its primary key directly — convenient, but the full key lives on
/// this one box, so it does not provide threshold security.
pub fn spawn_single_key(
    keyring: Arc<Mutex<Keyring>>,
    relay: String,
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
            });
            let mut server = match Server::new_with_config(
                keyring,
                None,
                None,
                std::slice::from_ref(&relay),
                Some(callbacks),
                ServerConfig {
                    // Least privilege for the single-key fallback: connect +
                    // signing only.
                    connect_grant: Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT,
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
                relay,
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
