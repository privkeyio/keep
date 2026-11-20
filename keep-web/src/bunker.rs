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
///
/// `None` when the RNG health check trips. Unguessability is the whole point of
/// this value, so the caller refuses the approval rather than falling back to
/// anything predictable.
fn random_approval_id() -> Option<u64> {
    // rng-hygiene: ok - the .ok() converts the health-check failure into None,
    // and the caller refuses the approval on None (see the doc comment above).
    keep_core::crypto::try_random_bytes::<8>()
        .ok()
        .map(|bytes| u64::from_le_bytes(bytes) & ((1u64 << 53) - 1))
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

    fn request_approval(&self, request: ApprovalRequest) -> keep_nip46::types::ApprovalResult {
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
            return false.into();
        }
        // Fail closed: without a sound random id the approval channel would be
        // guessable, so refuse the request the same way a disabled kill switch does.
        let Some(id) = random_approval_id() else {
            let _ = self.events.send(Event::Log {
                app: "frost".into(),
                action: "refused (entropy unavailable)".into(),
                success: false,
                detail: Some("random number generator health check failed".into()),
            });
            return false.into();
        };
        let (tx, rx) = channel();
        if let Ok(mut map) = self.approvals.lock() {
            map.insert(id, tx);
        }

        let http_auth = request.http_auth.map(|d| crate::state::HttpAuth {
            url: d.url,
            method: d.method,
        });
        let _ = self.events.send(Event::Approval {
            id,
            app: request.app_name,
            method: request.method,
            kind: request.event_kind.map(|k| k.as_u16()),
            preview: request.event_content,
            http_auth,
        });

        // `block_in_place` requires a multi-thread runtime; both spawners use
        // `Runtime::new()` (multi-thread), so this is sound. Do not switch them
        // to a current-thread runtime without changing this to `spawn_blocking`.
        let decision = tokio::task::block_in_place(|| await_decision(&rx, APPROVAL_TIMEOUT));
        if let Ok(mut map) = self.approvals.lock() {
            map.remove(&id);
        }
        decision.into()
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

    fn approve_ecdh(&self, _requester: &nostr_sdk::PublicKey) -> keep_frost_net::Result<()> {
        if self.enabled.load(Ordering::SeqCst) {
            return Ok(());
        }
        let _ = self.events.send(Event::Log {
            app: "frost".into(),
            action: "refused ECDH (co-signing disabled)".into(),
            success: false,
            detail: None,
        });
        Err(keep_frost_net::FrostNetError::PolicyViolation(
            "co-signing disabled".into(),
        ))
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
        KfpNodeEvent::PeerVersionMismatch {
            share_index,
            version,
        } => Some(Event::Log {
            app: "frost".into(),
            action: "peer protocol mismatch".into(),
            success: false,
            detail: Some(format!(
                "share {share_index} runs v{version}; every member must run v{}",
                keep_frost_net::KFP_VERSION
            )),
        }),
        KfpNodeEvent::RelayPinRejected { relay_host, reason } => Some(Event::Log {
            app: "frost".into(),
            action: "relay pin rejected".into(),
            success: false,
            detail: Some(format!(
                "Relay {relay_host} refused: {}",
                reason.explanation()
            )),
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
    /// Receives the verifying-share set the node learns from its members when
    /// the share was stored without it, so the caller can store it in the vault.
    pub learned_verifying_shares:
        tokio::sync::mpsc::UnboundedSender<(u16, std::collections::BTreeMap<u16, [u8; 33]>)>,
    /// Vault directory that holds `cert-pins.json`.
    pub pin_dir: std::path::PathBuf,
    /// Refuse a relay that has no recorded pin, and refuse a non-`wss` relay.
    pub require_pinned: bool,
}

/// What `spawn_network_frost` reports back once the co-signer is up.
pub struct NetworkHandle {
    pub info: BunkerInfo,
    pub node: Arc<KfpNode>,
}

/// How often a relay skipped as unreachable at startup is probed again, so it
/// gets its first-use pin from a verified probe once it is back.
const PIN_RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// The pin handle the live handshake enforces, and the relays left once any
/// whose certificate did not match its pin are refused.
struct RelayPins {
    pinning: keep_frost_net::TlsPinning,
    frost_relays: Vec<String>,
    bunker_relays: Vec<String>,
    rejected_hosts: Vec<String>,
}

/// Probe every relay once, record a first-use pin, and return the handle the
/// live handshake enforces. A relay that cannot be reached is skipped so one
/// relay down at startup does not stop the service. The live handshake still
/// enforces its pin, and without strict pinning it is probed again until it
/// answers. A relay whose certificate does not match its pin is refused. A
/// corrupt pin file, a cleartext or unpinned relay while strict pinning is on,
/// or no usable relay left in a set, refuses to start.
async fn relay_pinning(
    pin_dir: &std::path::Path,
    require_pinned: bool,
    frost_relays: &[String],
    bunker_relays: &[String],
) -> Result<RelayPins, String> {
    let store = keep_frost_net::RelayPinStore::open(pin_dir, require_pinned)
        .map_err(|e| format!("certificate pins: {e}"))?;
    let mut relays = frost_relays.to_vec();
    for relay in bunker_relays {
        if !relays.contains(relay) {
            relays.push(relay.clone());
        }
    }
    let skipped = store
        .probe_tolerant(&relays, None)
        .await
        .map_err(|e| format!("certificate pins: {e}"))?;
    let pins = settle_relays(store.pinning(), frost_relays, bunker_relays, &skipped)?;
    for host in &pins.rejected_hosts {
        tracing::error!(relay_host = %host, "relay pin rejected at startup, the relay is not used");
    }
    let unreachable: Vec<String> = skipped
        .into_iter()
        .filter_map(|skip| match skip {
            keep_frost_net::ProbeSkip::Unreachable { relay, .. } => Some(relay),
            keep_frost_net::ProbeSkip::PinMismatch { .. } => None,
        })
        .collect();
    if !require_pinned && !unreachable.is_empty() {
        tokio::spawn(async move {
            if let Err(e) = store
                .pin_when_reachable(unreachable, None, PIN_RETRY_INTERVAL)
                .await
            {
                tracing::error!(error = %e, "stopped probing relays that were unreachable at startup");
            }
        });
    }
    Ok(pins)
}

/// Drop every relay whose certificate did not match its pin from both sets,
/// and refuse a set left with no relay the probe did not skip.
fn settle_relays(
    pinning: keep_frost_net::TlsPinning,
    frost_relays: &[String],
    bunker_relays: &[String],
    skipped: &[keep_frost_net::ProbeSkip],
) -> Result<RelayPins, String> {
    let mut refused: Vec<&str> = Vec::new();
    let mut failed: Vec<&str> = Vec::new();
    let mut rejected_hosts: Vec<String> = Vec::new();
    for skip in skipped {
        match skip {
            keep_frost_net::ProbeSkip::PinMismatch { relay, hostname } => {
                refused.push(relay);
                failed.push(relay);
                if !rejected_hosts.contains(hostname) {
                    rejected_hosts.push(hostname.clone());
                }
            }
            keep_frost_net::ProbeSkip::Unreachable { relay, .. } => failed.push(relay),
        }
    }
    for (name, set) in [("FROST", frost_relays), ("bunker", bunker_relays)] {
        if !set.is_empty() && set.iter().all(|r| failed.contains(&r.as_str())) {
            let reasons: Vec<String> = skipped
                .iter()
                .filter(|skip| match skip {
                    keep_frost_net::ProbeSkip::PinMismatch { relay, .. }
                    | keep_frost_net::ProbeSkip::Unreachable { relay, .. } => set.contains(relay),
                })
                .map(ToString::to_string)
                .collect();
            return Err(format!(
                "certificate pins: no {name} relay passed the certificate probe ({})",
                reasons.join("; ")
            ));
        }
    }
    let keep = |relays: &[String]| -> Vec<String> {
        relays
            .iter()
            .filter(|r| !refused.contains(&r.as_str()))
            .cloned()
            .collect()
    };
    Ok(RelayPins {
        pinning,
        frost_relays: keep(frost_relays),
        bunker_relays: keep(bunker_relays),
        rejected_hosts,
    })
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

            let RelayPins {
                pinning,
                frost_relays,
                bunker_relays,
                rejected_hosts,
            } = match relay_pinning(
                &cfg.pin_dir,
                cfg.require_pinned,
                &cfg.frost_relays,
                &cfg.bunker_relays,
            )
            .await
            {
                Ok(pins) => pins,
                Err(e) => {
                    let _ = info_tx.send(Err(e));
                    return;
                }
            };
            let node =
                match KfpNode::new_pinned(cfg.share, frost_relays.clone(), None, pinning.clone())
                    .await
                {
                    Ok(n) => Arc::new(n),
                    Err(e) => {
                        let _ = info_tx.send(Err(format!("frost node: {e}")));
                        return;
                    }
                };
            for host in &rejected_hosts {
                node.audit_log()
                    .log_relay_pin_rejection(host, keep_frost_net::PinRejection::Mismatch);
            }

            node.set_hooks(Arc::new(CoSignerPolicy {
                events: events.clone(),
                enabled: cfg.enabled.clone(),
            }));

            // Mirror node lifecycle events (peer presence) into the web activity
            // feed so the UI reflects who is online, not just signing rounds.
            let mut node_events = node.subscribe();
            let events_for_feed = events.clone();
            let learned_tx = cfg.learned_verifying_shares.clone();
            tokio::spawn(async move {
                loop {
                    match node_events.recv().await {
                        Ok(KfpNodeEvent::VerifyingSharesLearned {
                            share_index,
                            verifying_shares,
                        }) => {
                            let _ = learned_tx.send((share_index, verifying_shares));
                        }
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
                &bunker_relays,
                Some(callbacks),
                ServerConfig {
                    tls_pinning: Some(pinning),
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
                bunker_relays,
                frost_relays,
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
    pin_dir: std::path::PathBuf,
    require_pinned: bool,
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
            let RelayPins {
                pinning,
                bunker_relays: relays,
                ..
            } = match relay_pinning(&pin_dir, require_pinned, &[], &relays).await {
                Ok(pins) => pins,
                Err(e) => {
                    let _ = info_tx.send(Err(e));
                    return;
                }
            };
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
                    tls_pinning: Some(pinning),
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
    use keep_frost_net::ProbeSkip;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    const DOWN: &str = "wss://relay.keep-probe-test.invalid";
    const DOWN2: &str = "wss://other.keep-probe-test.invalid";

    fn pinning() -> keep_frost_net::TlsPinning {
        keep_frost_net::RelayPinStore::open(tempfile::tempdir().unwrap().path(), false)
            .unwrap()
            .pinning()
    }

    fn mismatch(relay: &str) -> ProbeSkip {
        ProbeSkip::PinMismatch {
            relay: relay.into(),
            hostname: url_host(relay),
        }
    }

    fn down(relay: &str) -> ProbeSkip {
        ProbeSkip::Unreachable {
            relay: relay.into(),
            error: "DNS".into(),
        }
    }

    fn url_host(relay: &str) -> String {
        relay.trim_start_matches("wss://").to_string()
    }

    #[test]
    fn a_mismatched_relay_is_refused_in_both_sets_and_an_unreachable_one_kept() {
        let pins = settle_relays(
            pinning(),
            &strings(&[
                "wss://a.example.com",
                "wss://bad.example.com",
                "wss://down.example.com",
            ]),
            &strings(&["wss://bad.example.com", "wss://c.example.com"]),
            &[
                down("wss://down.example.com"),
                mismatch("wss://bad.example.com"),
            ],
        )
        .expect("each set keeps a usable relay");
        assert_eq!(
            pins.frost_relays,
            strings(&["wss://a.example.com", "wss://down.example.com"])
        );
        assert_eq!(pins.bunker_relays, strings(&["wss://c.example.com"]));
        assert_eq!(pins.rejected_hosts, strings(&["bad.example.com"]));
    }

    #[test]
    fn a_set_emptied_by_a_refusal_in_the_other_set_refuses_to_start() {
        let err = settle_relays(
            pinning(),
            &strings(&["wss://x.example.com"]),
            &strings(&["wss://x.example.com", "wss://w.example.com"]),
            &[mismatch("wss://x.example.com")],
        )
        .err()
        .expect("the FROST set has no relay left");
        assert!(err.contains("no FROST relay passed"), "{err}");
        assert!(err.contains("x.example.com"), "{err}");
    }

    #[test]
    fn a_set_whose_relays_are_all_down_refuses_while_the_other_set_is_fine() {
        let err = settle_relays(
            pinning(),
            &strings(&["wss://a.example.com"]),
            &strings(&["wss://b.example.com", "wss://c.example.com"]),
            &[down("wss://b.example.com"), down("wss://c.example.com")],
        )
        .err()
        .expect("the bunker set has no relay up");
        assert!(err.contains("no bunker relay passed"), "{err}");
    }

    #[tokio::test]
    async fn startup_pinning_skips_an_unreachable_relay() {
        let dir = tempfile::tempdir().unwrap();
        let frost = strings(&[DOWN, "ws://127.0.0.1:2"]);
        let bunker = strings(&["ws://127.0.0.1:3", DOWN]);
        let pins = relay_pinning(dir.path(), false, &frost, &bunker)
            .await
            .expect("one relay down does not stop startup");
        assert_eq!(pins.frost_relays, frost);
        assert_eq!(pins.bunker_relays, bunker);
        assert!(pins.rejected_hosts.is_empty());
        assert!(!dir.path().join("cert-pins.json").exists());
    }

    #[tokio::test]
    async fn startup_pinning_still_refuses_when_every_relay_of_a_set_fails() {
        let dir = tempfile::tempdir().unwrap();
        let err = relay_pinning(
            dir.path(),
            false,
            &strings(&[DOWN]),
            &strings(&["ws://127.0.0.1:3"]),
        )
        .await
        .err()
        .expect("every FROST relay down refuses");
        assert!(err.contains("no FROST relay passed"), "{err}");
        let err = relay_pinning(dir.path(), false, &[], &strings(&[DOWN, DOWN2]))
            .await
            .err()
            .expect("every bunker relay down refuses");
        assert!(err.contains("relay passed the certificate probe"), "{err}");
        assert!(!dir.path().join("cert-pins.json").exists());
    }

    #[tokio::test]
    async fn startup_pinning_still_refuses_a_corrupt_pin_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cert-pins.json"), b"not json").unwrap();
        let err = relay_pinning(dir.path(), false, &strings(&["ws://127.0.0.1:2"]), &[])
            .await
            .err()
            .expect("a corrupt pin file refuses");
        assert!(err.contains("certificate pin store"), "{err}");
        assert_eq!(
            std::fs::read(dir.path().join("cert-pins.json")).unwrap(),
            b"not json"
        );
    }

    #[tokio::test]
    async fn startup_pinning_still_refuses_cleartext_under_strict_pinning() {
        let dir = tempfile::tempdir().unwrap();
        let err = relay_pinning(dir.path(), true, &[], &strings(&["ws://127.0.0.1:2"]))
            .await
            .err()
            .expect("strict pinning refuses a cleartext relay");
        assert!(err.contains("non-wss"), "{err}");
    }

    #[test]
    fn a_relay_pin_rejection_is_an_activity_failure() {
        let event = super::node_event_to_log(&KfpNodeEvent::RelayPinRejected {
            relay_host: "relay.example.com".into(),
            reason: keep_frost_net::PinRejection::Mismatch,
        })
        .expect("a pin rejection is surfaced");
        match event {
            Event::Log {
                app,
                action,
                success,
                detail,
            } => {
                assert_eq!(app, "frost");
                assert_eq!(action, "relay pin rejected");
                assert!(!success);
                let detail = detail.expect("the relay is named");
                assert!(detail.contains("relay.example.com"));
                assert!(detail.contains("does not match"));
            }
            _ => panic!("expected a log event"),
        }
    }

    #[test]
    fn approval_id_is_js_safe() {
        const MAX_SAFE: u64 = (1u64 << 53) - 1;
        for _ in 0..10_000 {
            let id = random_approval_id().expect("healthy RNG yields an approval id");
            assert!(id <= MAX_SAFE);
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
            structured_payload: None,
            derivation_path: Vec::new(),
            taproot_tweak: None,
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
    fn approve_ecdh_respects_kill_switch() {
        let (tx, _rx) = broadcast::channel(8);
        let enabled = Arc::new(AtomicBool::new(true));
        let policy = CoSignerPolicy {
            events: tx,
            enabled: enabled.clone(),
        };
        let peer = nostr_sdk::Keys::generate().public_key();
        assert!(policy.approve_ecdh(&peer).is_ok());
        enabled.store(false, Ordering::SeqCst);
        assert!(policy.approve_ecdh(&peer).is_err());
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
