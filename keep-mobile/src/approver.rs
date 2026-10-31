// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The approver: the phone's side of agent approvals, for keep-android.
//!
//! An agent gateway asks for decisions over Nostr relays (keep-approval's
//! protocol). This pairs the phone with a gateway, receives its requests,
//! runs on each the same checks the gateway runs (keep-approval's own code),
//! and hands what passes to the app through [`ApproverCallbacks`], ready to
//! show. The approver key lives in the Android Keystore and never here:
//! whatever it must sign (a decision, an unfreeze, the pairing), this hands
//! the app a digest, the app has the Keystore sign it behind a strong
//! biometric, and this takes the DER signature back, checks it, and sends
//! the message. The transport key, which only seals messages and signs
//! freezes, is kept in the app's secure storage, so a freeze needs no
//! biometric.
//!
//! Requests waiting for the owner and alerts not yet acknowledged are kept
//! with the pairing, so neither is lost when the app is stopped or killed:
//! after a restart the app reads them back with
//! [`ApproverHandler::waiting_requests`] and [`ApproverHandler::status`].
//! One handler holds a `KeepMobile`'s approver state at a time; the app
//! calls [`ApproverHandler::shutdown`] when done with it.

mod view;

pub use view::{ApprovalField, ApprovalRequest};

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use keep_approval::approver::{
    clock_skew, shown, Alert, AnchorTracker, Refused, RequestGate, FREEZE_RESEND_SECS,
    GATEWAY_TEXT_CHARS,
};
use keep_approval::binding::check_request;
use keep_approval::change::{Change, Scope};
use keep_approval::messages::{
    self as wire, Anchor, Decision, Freeze, FreezeAction, Outcome, OutcomeKind, Pairing, Request,
    SignerKey, Verdict, V1,
};
use keep_approval::pairing::{check_paired, CertChain, PairingUri};
use keep_approval::sig::{self, Alg};
use keep_approval::wrap::{self, Candidate, SeenWraps, TagKey, TWEAK_SECS, WINDOW_PAST_SECS};
use keep_approval::{kind, Hex16, Hex32, Hex33, Hex64};
use nostr_sdk::prelude::{
    Client, Event, Filter, Keys, Kind, PublicKey, RelayPoolNotification, Timestamp,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::KeepMobileError;
use crate::KeepMobile;

const STATE_KEY: &str = "__keep_approver";

/// The most unacknowledged alerts kept; past this the oldest go, counted.
const MAX_ALERTS: usize = 32;

/// The most requests waiting for the owner at once, past which a new one
/// is refused; and the most decided ones kept for their outcomes, past which
/// the oldest go.
const MAX_WAITING: usize = 64;

/// How long a request past its time is kept, no longer decidable, so the
/// gateway's `expired` outcome still reaches the app.
const OUTCOME_GRACE_SECS: u64 = 120;

/// How long after an unfreeze digest is handed out freezes are not resent,
/// so a resend's new counter does not void the unfreeze being signed.
const UNFREEZE_HOLD_SECS: u64 = 60;

/// How far past the stored freeze counter the first freeze or unfreeze after
/// a load signs. Storage can roll back to an earlier copy (a backup, or a
/// write lost to power after it was reported done), which would have this
/// phone sign a counter it already sent, and the gateway refuses an old
/// counter: the owner's freeze would be ignored. This covers a rollback of
/// up to this many counters to a copy saved since the last such jump; a
/// rollback of the write that saved a jump itself is not covered, which
/// storage that only reports a write done once it is durable prevents. It is
/// spent only when a freeze or unfreeze is signed, never by loading alone,
/// so app restarts do not use up the gateway's step limit
/// ([`sig::MAX_COUNTER_STEP`]). An unfreeze whose digest was handed out
/// before the load keeps the counter it was signed for; if a rollback brought
/// it back, the gateway refuses it as old and the scope stays frozen.
const COUNTER_MARGIN: u64 = 1 << 10;
const _: () = assert!(COUNTER_MARGIN < sig::MAX_COUNTER_STEP);

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn invalid(msg: impl Into<String>) -> KeepMobileError {
    KeepMobileError::InvalidInput { msg: msg.into() }
}

/// Text from the gateway or the network, as the owner may be shown it.
fn gateway_text(text: &str) -> String {
    shown(text, GATEWAY_TEXT_CHARS).text
}

/// A request shown to the owner and not yet ended.
#[derive(Clone, Serialize, Deserialize)]
struct Waiting {
    id: Hex32,
    /// The phone's clock when it can no longer be approved.
    until: u64,
    /// The scope an unfreeze request lifts, which its approved outcome
    /// explains.
    unfreeze: Option<Scope>,
    /// The gateway's clock and this phone's differed when it arrived;
    /// measured then, since later the time waited would count as skew.
    #[serde(default)]
    skew: bool,
    /// This phone's decision was sent.
    #[serde(default)]
    decided: bool,
    /// The request while it can be decided; dropped (and wiped) once it is
    /// decided or past its time, keeping only what the outcome needs.
    request: Option<Request>,
}

impl Waiting {
    fn open(&self, local_now: u64) -> Option<&Request> {
        self.request.as_ref().filter(|_| self.until > local_now)
    }
}

/// Keep what the outcomes still need at `local_now`: a request past its
/// time a little longer, without its payload, and a decided one for as long
/// as its outcome can still arrive. Requests that passed their time undecided
/// since the last prune are added to `lapsed`. Whether anything changed.
fn prune(waiting: &mut Vec<Waiting>, local_now: u64, lapsed: &mut Vec<Hex32>) -> bool {
    lapsed.extend(
        waiting
            .iter()
            .filter(|w| w.request.is_some() && w.until <= local_now)
            .map(|w| w.id),
    );
    let before = waiting.len();
    waiting.retain(|w| {
        let grace = if w.decided {
            WINDOW_PAST_SECS
        } else {
            OUTCOME_GRACE_SECS
        };
        w.until.saturating_add(grace) > local_now
    });
    let mut changed = waiting.len() != before;
    for w in waiting.iter_mut() {
        if w.request.is_some() && w.until <= local_now {
            w.request = None;
            changed = true;
        }
    }
    changed
}

/// An unfreeze whose digest was handed out and not yet sent.
#[derive(Clone, Copy, Serialize, Deserialize)]
struct AskedUnfreeze {
    scope: Scope,
    counter: u64,
    epoch: u64,
    /// The phone's clock when the digest was handed out.
    at: u64,
}

/// An alert the owner has not acknowledged.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverAlert {
    /// Counts up across alerts; [`ApproverHandler::acknowledge_alerts`]
    /// takes the last one the owner saw.
    pub seq: u64,
    pub message: String,
}

/// What the phone keeps between runs.
#[derive(Clone, Serialize, Deserialize)]
struct Stored {
    /// The transport key's secret, hex.
    transport: Zeroizing<String>,
    approver: Hex33,
    label: String,
    channel: Hex32,
    relays: Vec<String>,
    /// Whether the gateway answered the pairing with `paired`.
    paired: bool,
    /// The last freeze counter used.
    counter: u64,
    /// The least counter the next freeze or unfreeze signs, set when the
    /// state is loaded: see [`COUNTER_MARGIN`]. Never stored.
    #[serde(skip)]
    counter_floor: u64,
    tracker: AnchorTracker,
    gate: RequestGate,
    #[serde(default)]
    waiting: Vec<Waiting>,
    #[serde(default)]
    alerts: Vec<ApproverAlert>,
    #[serde(default)]
    alert_seq: u64,
    /// Alerts pushed out by [`MAX_ALERTS`] since the owner last
    /// acknowledged.
    #[serde(default)]
    alerts_dropped: u64,
    /// The silence alert was raised and no anchor has come since.
    #[serde(default)]
    silent_reported: bool,
    #[serde(default)]
    unfreeze: Option<AskedUnfreeze>,
}

impl Stored {
    fn keys(&self) -> Result<Keys, KeepMobileError> {
        Keys::parse(&self.transport).map_err(|_| invalid("the stored transport key is damaged"))
    }

    /// Move to the next freeze counter, past the floor set at load.
    fn next_counter(&mut self) {
        self.counter = self.counter.max(self.counter_floor).saturating_add(1);
    }

    fn fingerprint(&self) -> Result<String, KeepMobileError> {
        Ok(sig::fingerprint(
            &sig::xonly(&self.keys()?),
            &self.approver.0,
        ))
    }

    /// Raise `message`, unless the same alert is still unacknowledged.
    fn alert(&mut self, message: String, fx: &mut Effects) {
        if self.alerts.iter().any(|a| a.message == message) {
            return;
        }
        if self.alerts.len() == MAX_ALERTS {
            self.alerts.remove(0);
            self.alerts_dropped += 1;
        }
        self.alert_seq += 1;
        let alert = ApproverAlert {
            seq: self.alert_seq,
            message,
        };
        self.alerts.push(alert.clone());
        fx.events.push(ApproverEvent::Alert {
            seq: alert.seq,
            message: alert.message,
        });
    }
}

/// A pairing begun, waiting for the approver key's signature.
struct Begun {
    stored: Stored,
    secret: Zeroizing<[u8; 32]>,
    digest: [u8; 32],
}

/// The transport key and the one candidate a gateway's message is opened
/// against, derived once per pairing rather than for every wrap.
struct Session {
    keys: Keys,
    candidates: [Candidate<()>; 1],
}

impl Session {
    fn new(stored: &Stored) -> Option<Self> {
        let keys = stored.keys().ok()?;
        let tag_key = TagKey::device(&keys, &stored.channel.0).ok()?;
        Some(Self {
            keys,
            candidates: [Candidate::Peer {
                id: (),
                tag_key,
                sender: stored.channel.0,
            }],
        })
    }
}

#[derive(Default)]
struct Inner {
    stored: Option<Stored>,
    session: Option<Session>,
    begun: Option<Begun>,
    seen: SeenWraps,
}

impl Inner {
    fn set(&mut self, stored: Option<Stored>) {
        self.session = stored.as_ref().and_then(Session::new);
        self.stored = stored;
    }
}

/// What a pairing needs the approver key to sign.
#[derive(uniffi::Record, Clone, Debug)]
pub struct PairingStart {
    /// The fingerprint the gateway's terminal shows; the owner compares them.
    pub fingerprint: String,
    /// The digest for the Keystore to sign with `SHA256withECDSA`.
    pub digest: Vec<u8>,
}

/// The approver's state, for the app's screens.
#[derive(uniffi::Record, Clone, Debug)]
pub struct ApproverStatus {
    pub paired: bool,
    /// A pairing was sent and the gateway has not answered.
    pub pairing: bool,
    pub running: bool,
    pub label: Option<String>,
    pub fingerprint: Option<String>,
    pub relays: Vec<String>,
    /// Why the approver could not serve its relays at the last attempt, a
    /// start or a move to the gateway's new relays, until one succeeds or it
    /// stops. A start with no network succeeds and connects once the network
    /// is back; relays that never answer raise the silence alert instead.
    pub last_error: Option<String>,
    /// The gateway's freeze epoch, from the latest anchor kept.
    pub epoch: Option<u64>,
    pub all_frozen: bool,
    pub frozen_credentials: Vec<String>,
    /// No anchor for an hour: the gateway is down, cut off, or withheld.
    pub silent: bool,
    /// Alerts the owner has not acknowledged, oldest first.
    pub alerts: Vec<ApproverAlert>,
    /// Older unacknowledged alerts pushed out to keep the list bounded,
    /// which the app states.
    pub alerts_dropped: u64,
}

/// Something to show the owner.
#[derive(uniffi::Enum, Clone, Debug)]
pub enum ApproverEvent {
    Paired {
        fingerprint: String,
    },
    PairingRefused {
        reason: String,
        /// The gateway refused, and the pairing is forgotten on this phone,
        /// so the approver key made for it can go. Otherwise an answer failed
        /// its checks and the pairing still waits for the gateway.
        ended: bool,
    },
    Request {
        request: ApprovalRequest,
    },
    /// A request that failed a check, never offered for approval.
    RequestRefused {
        reason: String,
    },
    /// A request shown to the owner passed its time undecided and can no
    /// longer be decided here. The gateway's `expired` outcome may follow.
    RequestExpired {
        request_id: String,
    },
    Outcome {
        request_id: String,
        /// `approved`, `denied`, `expired` or `canceled`.
        outcome: String,
    },
    /// A newer anchor was kept: the gateway's freeze state now.
    Anchor {
        epoch: u64,
        all_frozen: bool,
        frozen_credentials: Vec<String>,
        audit_seq: u64,
    },
    /// Something the owner must see, prominently. It also stays in
    /// [`ApproverStatus::alerts`] until acknowledged.
    Alert {
        seq: u64,
        message: String,
    },
}

#[uniffi::export(with_foreign)]
pub trait ApproverCallbacks: Send + Sync {
    fn on_event(&self, event: ApproverEvent);
}

fn alert_text(alert: &Alert) -> String {
    let scope = |s: &Scope| match s {
        Scope::All => "every agent".to_string(),
        Scope::Credential(id) => format!("credential {}", id.to_hex()),
    };
    match alert {
        Alert::AuditCountWentBack { from, to } => format!(
            "The gateway's audit log went back from {from} to {to} entries: it was rolled back or cut."
        ),
        Alert::AuditHeadChanged { seq } => {
            format!("The gateway's audit log was rewritten at entry {seq}.")
        }
        Alert::PrevWentBack { kept, prev } => format!(
            "The gateway was put back to an earlier copy: its last anchor was at {prev} entries, after {kept} were seen."
        ),
        Alert::PrevHeadChanged { seq } => {
            format!("The gateway's audit log was rewritten before entry {seq}.")
        }
        Alert::PrevMissing => "The gateway's record of the anchors it sent is gone.".into(),
        Alert::WalletCountWentBack { wallet, from, to } => format!(
            "A wallet ledger ({}) went back from {from} to {to} spends.",
            gateway_text(wallet)
        ),
        Alert::WalletMissing { wallet } => {
            format!("A wallet ledger ({}) is gone.", gateway_text(wallet))
        }
        Alert::EpochWentBack { from, to } => {
            format!("The gateway's freeze epoch went back from {from} to {to}.")
        }
        Alert::OwnFreezeNotShown { scope: s } => format!(
            "The freeze of {} sent from this phone has not shown at the gateway: a relay may be withholding it.",
            scope(s)
        ),
        Alert::FreezeCleared { scope: s } => format!(
            "The freeze of {} was lifted, and no unfreeze explains it.",
            scope(s)
        ),
    }
}

const SILENT_ALERT: &str =
    "No word from the gateway for an hour: it is down, cut off, or its messages are withheld.";

fn scope_arg(credential: Option<String>) -> Result<Scope, KeepMobileError> {
    match credential {
        None => Ok(Scope::All),
        Some(id) => Hex16::parse(&id)
            .map(Scope::Credential)
            .map_err(|_| invalid("a credential id is 32 lowercase hex characters")),
    }
}

fn request_id_arg(id: &str) -> Result<Hex32, KeepMobileError> {
    Hex32::parse(id).map_err(|_| invalid("a request id is 64 lowercase hex characters"))
}

fn verdict(approve: bool) -> Verdict {
    if approve {
        Verdict::Approve
    } else {
        Verdict::Deny
    }
}

/// A signature from the Keystore, checked against the approver key over
/// `digest` before anything is sent.
fn checked_signature(
    der: &[u8],
    approver: &Hex33,
    digest: &[u8; 32],
) -> Result<Hex64, KeepMobileError> {
    let sig = sig::p256_from_der(der).map_err(|e| invalid(e.to_string()))?;
    sig::verify_p256(&approver.0, digest, &sig).map_err(|_| {
        invalid(
            "the signature does not verify under this phone's approver key for what was asked: \
             sign the digest for this request again, and if a fingerprint or face was enrolled \
             since pairing, the key was replaced and the phone must be paired again",
        )
    })?;
    Ok(sig)
}

/// The change an unfreeze request carries.
fn unfreeze_scope(request: &Request) -> Option<Scope> {
    match Change::parse(request.payload.get("change")?) {
        Ok(Change::Unfreeze { scope, .. }) => Some(scope),
        _ => None,
    }
}

/// A freeze of `scope` signed by the transport key with the next counter.
fn signed_freeze(
    stored: &mut Stored,
    scope: Scope,
    epoch: u64,
    local_now: u64,
) -> Result<String, KeepMobileError> {
    let keys = stored.keys()?;
    stored.next_counter();
    let freeze = sig::freeze(&keys, &stored.channel.0, stored.counter, epoch, scope);
    stored.tracker.freeze_sent(scope, epoch, local_now);
    Ok(wire::to_text(&freeze))
}

/// The gateway's relays, held to the rules every other relay here is: `wss://`,
/// and not an internal address, which the pinned transport would refuse anyway
/// with an error that does not say why. Internal addresses pass only where the
/// transport lets them through too, in test builds.
fn checked_relays(relays: &[String]) -> Result<(), KeepMobileError> {
    let validate = if keep_core::relay::ALLOW_INTERNAL_HOSTS {
        keep_core::relay::validate_relay_url_allow_internal
    } else {
        keep_core::relay::validate_relay_url
    };
    relays
        .iter()
        .try_for_each(|r| validate(r).map_err(|msg| KeepMobileError::InvalidRelayUrl { msg }))
}

fn no_relay() -> KeepMobileError {
    KeepMobileError::NetworkError {
        msg: "no relay accepted the message".into(),
    }
}

/// What happens after a state change, outside the lock.
#[derive(Default)]
struct Effects {
    events: Vec<ApproverEvent>,
    send: Vec<(u16, String)>,
    reconnect: Option<Vec<String>>,
    /// Stop serving: the pairing is gone.
    halt: bool,
}

struct Running {
    client: Client,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Running {
    fn end(self, runtime: &tokio::runtime::Runtime) {
        for task in self.tasks {
            task.abort();
        }
        let client = self.client;
        runtime.spawn(async move { client.shutdown().await });
    }
}

/// A strong reference a task takes for a while. The handler owns the
/// `KeepMobile` whose runtime runs the task, and a runtime dropped inside
/// itself panics; so when this is the last reference, however the task
/// ends, the handler is let go on a thread of its own.
struct Held(Option<Arc<ApproverHandler>>);

impl Held {
    fn upgrade(weak: &Weak<ApproverHandler>) -> Option<Self> {
        weak.upgrade().map(|a| Held(Some(a)))
    }

    fn of(handler: &Arc<ApproverHandler>) -> Self {
        Held(Some(handler.clone()))
    }
}

impl std::ops::Deref for Held {
    type Target = Arc<ApproverHandler>;

    fn deref(&self) -> &Self::Target {
        // Only `drop` takes it out.
        self.0.as_ref().unwrap_or_else(|| unreachable!())
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(last) = self.0.take().and_then(Arc::into_inner) {
            std::thread::spawn(move || drop(last));
        }
    }
}

#[derive(uniffi::Object)]
pub struct ApproverHandler {
    mobile: Arc<KeepMobile>,
    inner: Mutex<Inner>,
    running: Mutex<Option<Running>>,
    /// Serializes start, stop, shutdown, forget and reconnects.
    lifecycle: Mutex<()>,
    /// Counts stops, so a reconnect scheduled before one does not undo it.
    generation: AtomicU64,
    /// Closed, or dropped: the `KeepMobile`'s approver slot is given back.
    closed: AtomicBool,
    callbacks: Mutex<Option<Arc<dyn ApproverCallbacks>>>,
    /// See [`ApproverStatus::last_error`].
    last_error: Mutex<Option<String>>,
}

impl Drop for ApproverHandler {
    fn drop(&mut self) {
        if let Some(running) = self
            .running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            running.end(&self.mobile.runtime);
        }
        self.release();
    }
}

impl ApproverHandler {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Give back the `KeepMobile`'s approver slot, once.
    fn release(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.mobile.approver_live.store(false, Ordering::SeqCst);
        }
    }

    fn open_check(&self) -> Result<(), KeepMobileError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(invalid("this approver was closed"));
        }
        Ok(())
    }

    fn persist(&self, stored: &Stored) -> Result<(), KeepMobileError> {
        let data = serde_json::to_vec(stored)
            .map_err(|e| KeepMobileError::Serialization { msg: e.to_string() })?;
        self.mobile.storage.store_share_by_key(
            STATE_KEY.into(),
            data,
            crate::persistence::storage_metadata("approver"),
        )
    }

    fn persist_or_log(&self, stored: &Stored) {
        if let Err(e) = self.persist(stored) {
            tracing::error!(error = %e, "the approver state could not be kept");
        }
    }

    fn emit(&self, events: Vec<ApproverEvent>) {
        let callbacks = self
            .callbacks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(cb) = callbacks {
            for event in events {
                cb.on_event(event);
            }
        }
    }

    /// `content` of `kind`, sealed to the gateway.
    fn sealed(&self, kind: u16, content: &str) -> Result<Event, KeepMobileError> {
        let (keys, channel) = {
            let inner = self.lock();
            let stored = inner.stored.as_ref().ok_or_else(|| invalid("not paired"))?;
            (stored.keys()?, stored.channel.0)
        };
        let tag = TagKey::device(&keys, &channel).map_err(|e| invalid(e.to_string()))?;
        wrap::wrap(&keys, &channel, &tag, kind, content, now()).map_err(|e| invalid(e.to_string()))
    }

    fn client(&self) -> Result<Client, KeepMobileError> {
        self.running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|r| r.client.clone())
            .ok_or_else(|| KeepMobileError::NetworkError {
                msg: "the approver is not running".into(),
            })
    }

    /// Send `event` from a call the app made, on its own thread: done only
    /// when a relay took it.
    fn send_now(&self, event: Event) -> Result<(), KeepMobileError> {
        let client = self.client()?;
        self.mobile.runtime.block_on(async move {
            let output = client
                .send_event(&event)
                .await
                .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?;
            if output.success.is_empty() {
                return Err(no_relay());
            }
            Ok(())
        })
    }

    /// Stop serving. Callers hold `lifecycle`.
    fn halt(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = None;
        if let Some(running) = self
            .running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            running.end(&self.mobile.runtime);
        }
    }

    /// Connect to `relays` and serve what arrives for the transport key, in
    /// place of what ran before once the new socket is set up, so a failure
    /// leaves the old one serving. Callers hold `lifecycle`.
    ///
    /// The socket goes through the configured proxy and the pinned transport,
    /// like every other relay socket here: it carries the pairing and every
    /// approval. The relays are probed first, which learns a pin on first use.
    /// Unless pinning is strict that probe is best effort, since an approver
    /// started offline has to come up when the network does: the handshake
    /// still enforces every recorded pin, and a mismatch stops it here. Relays
    /// that never connect are reported by the gateway-silence alert.
    fn run(self: &Arc<Self>, relays: Vec<String>, keys: Keys) -> Result<(), KeepMobileError> {
        let result = self.serve(relays, keys);
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) =
            result.as_ref().err().map(|e| e.to_string());
        result
    }

    fn serve(self: &Arc<Self>, relays: Vec<String>, keys: Keys) -> Result<(), KeepMobileError> {
        checked_relays(&relays)?;
        let transport = keys.public_key();
        let proxy = self.mobile.configured_proxy()?;
        if proxy.is_some() && self.mobile.get_strict_cert_pinning()? {
            // The pinned transport cannot pin a socket the proxy opens, and
            // refuses every one under strict pinning: the approver would
            // report running while carrying nothing.
            return Err(KeepMobileError::InvalidInput {
                msg: "Strict certificate pinning cannot pin relays reached through the proxy; turn one of them off".into(),
            });
        }
        let (relays, pinning) = {
            let _cert = self
                .mobile
                .cert_pin_lock
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let relays = match self
                .mobile
                .runtime
                .block_on(self.mobile.verify_and_pin_relays(&relays, proxy))
            {
                Ok(verified) => verified,
                Err(e @ KeepMobileError::CertificatePinMismatch { .. }) => return Err(e),
                Err(e) if self.mobile.get_strict_cert_pinning()? => return Err(e),
                Err(e) => {
                    tracing::warn!(error = %e, "approver relays not probed; connecting to them anyway");
                    relays
                }
            };
            (relays, self.mobile.live_pinning()?)
        };
        let client = keep_frost_net::build_client(&keys, proxy, Some(pinning))
            .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?;
        let weak = Arc::downgrade(self);
        // What these tasks deliver is dropped once a stop or start follows.
        let generation = self.generation.load(Ordering::SeqCst);
        // Wraps carry a creation time up to `TWEAK_SECS` early, and are kept
        // for the past window: anything older can no longer be opened.
        let since = Timestamp::from_secs(now().saturating_sub(TWEAK_SECS + WINDOW_PAST_SECS));
        let tasks = self.mobile.runtime.block_on(async {
            for relay in &relays {
                client
                    .add_relay(relay)
                    .await
                    .map_err(|e| KeepMobileError::InvalidRelayUrl { msg: e.to_string() })?;
            }
            client.connect().await;
            client
                .subscribe(
                    Filter::new()
                        .kind(Kind::GiftWrap)
                        .pubkey(transport)
                        .since(since),
                    None,
                )
                .await
                .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?;
            let mut events = client.notifications();
            let listen_weak = weak.clone();
            let listen = tokio::spawn(async move {
                loop {
                    match events.recv().await {
                        Ok(RelayPoolNotification::Event { event, .. }) => {
                            let Some(this) = Held::upgrade(&listen_weak) else {
                                break;
                            };
                            // Storage and the app's callbacks block; keep
                            // them off the runtime's workers.
                            let r = Held::of(&this);
                            if let Ok(fx) =
                                tokio::task::spawn_blocking(move || r.received(&event)).await
                            {
                                this.deliver(fx, generation).await;
                            }
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(dropped = n, "the approver fell behind its relays");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
            let tick = tokio::spawn(async move {
                let mut every = tokio::time::interval(Duration::from_secs(FREEZE_RESEND_SECS));
                loop {
                    every.tick().await;
                    let Some(this) = Held::upgrade(&weak) else {
                        break;
                    };
                    let t = Held::of(&this);
                    if let Ok(fx) = tokio::task::spawn_blocking(move || t.tick_at(now())).await {
                        this.deliver(fx, generation).await;
                    }
                }
            });
            Ok::<_, KeepMobileError>(vec![listen, tick])
        })?;
        let old = self
            .running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(Running { client, tasks });
        if let Some(old) = old {
            old.end(&self.mobile.runtime);
        }
        Ok(())
    }

    fn received(&self, event: &Event) -> Effects {
        let mut inner = self.lock();
        let Inner { session, seen, .. } = &mut *inner;
        let Some(session) = session.as_ref() else {
            return Effects::default();
        };
        let Ok(opened) = wrap::open(&session.keys, event, &session.candidates, seen, now()) else {
            return Effects::default();
        };
        let (kind, content) = (opened.kind, opened.content.to_string());
        self.handle(&mut inner, kind, &content, now())
    }

    /// Send what `fx` holds and tell the app, from the tasks `run` started
    /// at `generation`. A reconnect or a halt runs on a thread of its own,
    /// since it replaces the tasks this runs in.
    async fn deliver(self: &Arc<Self>, fx: Effects, generation: u64) {
        if let Ok(client) = self.client() {
            for (kind, content) in fx.send {
                match self.sealed(kind, &content) {
                    Ok(event) => match client.send_event(&event).await {
                        Ok(output) if output.success.is_empty() => {
                            tracing::warn!("no relay accepted an approver message");
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "an approver message was not sent"),
                    },
                    Err(e) => tracing::warn!(error = %e, "an approver message was not sealed"),
                }
            }
        }
        if !fx.events.is_empty() {
            let this = Held::of(self);
            let events = fx.events;
            let _ = tokio::task::spawn_blocking(move || this.emit(events)).await;
        }
        if fx.halt || fx.reconnect.is_some() {
            let this = self.clone();
            let reconnect = fx.reconnect;
            std::thread::spawn(move || {
                let _lifecycle = this.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
                // A stop or start since then wins.
                if this.generation.load(Ordering::SeqCst) != generation {
                    return;
                }
                match reconnect {
                    Some(relays) => this.move_relays(relays),
                    None => this.halt(),
                }
            });
        }
    }

    /// Serve `relays` in place of the relays running now. Not halted first: a
    /// failure leaves the old socket serving, and with it the silence alert,
    /// rather than an approver that stopped and told no one. Callers hold
    /// `lifecycle`.
    fn move_relays(self: &Arc<Self>, relays: Vec<String>) {
        let keys = self.lock().session.as_ref().map(|s| s.keys.clone());
        let Some(keys) = keys else { return };
        match self.run(relays.clone(), keys) {
            Ok(()) => {
                let mut inner = self.lock();
                if let Some(stored) = inner.stored.as_mut() {
                    stored.relays = relays;
                    self.persist_or_log(stored);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "the approver could not move to the gateway's new relays");
            }
        }
    }

    /// After the pairing to `channel` from `transport` was sent, or not:
    /// undo it if no relay took it, unless the gateway answered `paired`
    /// anyway, which stands.
    fn settle_pairing(
        &self,
        sent: Result<(), KeepMobileError>,
        channel: [u8; 32],
        transport: PublicKey,
        digest: [u8; 32],
    ) -> Result<(), KeepMobileError> {
        let mut inner = self.lock();
        let ours = |s: &Stored| {
            s.channel.0 == channel && s.keys().ok().map(|k| k.public_key()) == Some(transport)
        };
        let answered = inner.stored.as_ref().is_some_and(|s| ours(s) && s.paired);
        if let Err(e) = sent {
            if !answered {
                if inner.stored.as_ref().is_some_and(ours) {
                    inner.set(None);
                    let _ = self.mobile.storage.delete_share_by_key(STATE_KEY.into());
                }
                drop(inner);
                self.halt();
                return Err(e);
            }
        }
        // A pairing begun again meanwhile is left alone.
        if inner.begun.as_ref().is_some_and(|b| b.digest == digest) {
            inner.begun = None;
        }
        Ok(())
    }

    /// Take one message from the gateway, at the phone's `local_now`.
    fn handle(&self, inner: &mut Inner, kind: u16, content: &str, local_now: u64) -> Effects {
        let mut fx = Effects::default();
        let mut forget = false;
        let Some(stored) = inner.stored.as_mut() else {
            return fx;
        };
        match kind {
            kind::PAIRING if !stored.paired => match wire::parse::<Pairing>(content) {
                Ok(Pairing::Refused { reason, .. }) => {
                    fx.events.push(ApproverEvent::PairingRefused {
                        reason: gateway_text(&reason),
                        ended: true,
                    });
                    forget = true;
                }
                Ok(message) => {
                    let Ok(keys) = stored.keys() else {
                        return fx;
                    };
                    match check_paired(&message, &sig::xonly(&keys), &stored.approver.0) {
                        Ok(paired) => {
                            stored.paired = true;
                            if !paired.relays.is_empty() && paired.relays != stored.relays {
                                // Kept once the approver is serving them, by
                                // `move_relays`, so a move that fails leaves
                                // stored what still runs.
                                match checked_relays(&paired.relays) {
                                    Ok(()) => fx.reconnect = Some(paired.relays.clone()),
                                    Err(e) => tracing::warn!(
                                        error = %e,
                                        "keeping the approver's relays: the gateway named relays it cannot use"
                                    ),
                                }
                            }
                            stored
                                .tracker
                                .baseline(&paired.anchor, &paired.frozen, local_now);
                            self.persist_or_log(stored);
                            fx.events.push(ApproverEvent::Paired {
                                fingerprint: stored.fingerprint().unwrap_or_default(),
                            });
                        }
                        Err(e) => fx.events.push(ApproverEvent::PairingRefused {
                            reason: gateway_text(&e.to_string()),
                            ended: false,
                        }),
                    }
                }
                Err(e) => fx.events.push(ApproverEvent::PairingRefused {
                    reason: gateway_text(&e.to_string()),
                    ended: false,
                }),
            },
            kind::REQUEST if stored.paired => {
                let request: Request = match wire::parse(content) {
                    Ok(r) => r,
                    Err(e) => {
                        fx.events.push(ApproverEvent::RequestRefused {
                            reason: gateway_text(&e.to_string()),
                        });
                        return fx;
                    }
                };
                let checked = match check_request(&request, &stored.channel.0) {
                    Ok(c) => c,
                    Err(e) => {
                        fx.events.push(ApproverEvent::RequestRefused {
                            reason: gateway_text(&e.to_string()),
                        });
                        return fx;
                    }
                };
                match stored.gate.admit(&request, &stored.tracker, local_now) {
                    Ok(()) => {}
                    Err(Refused::Full) => {
                        fx.events.push(ApproverEvent::RequestRefused {
                            reason: Refused::Full.to_string(),
                        });
                        return fx;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "a request not shown");
                        return fx;
                    }
                }
                // Observed once admitted, shown or not, so the tracker's time,
                // which the gate lets ids go by, keeps up with every request.
                for alert in
                    stored
                        .tracker
                        .observe(request.created_at, &request.anchor, None, local_now)
                {
                    stored.alert(alert_text(&alert), &mut fx);
                }
                let mut lapsed = Vec::new();
                prune(&mut stored.waiting, local_now, &mut lapsed);
                fx.events.extend(lapsed_events(lapsed));
                if stored
                    .waiting
                    .iter()
                    .filter(|w| w.open(local_now).is_some())
                    .count()
                    >= MAX_WAITING
                {
                    self.persist_or_log(stored);
                    fx.events.push(ApproverEvent::RequestRefused {
                        reason: "too many requests are waiting: decide some first".into(),
                    });
                    return fx;
                }
                let skew = clock_skew(request.created_at, local_now);
                let view = view::view(&request, &checked, skew, request.deadline_secs);
                stored.waiting.push(Waiting {
                    id: request.request_id,
                    until: local_now.saturating_add(request.deadline_secs),
                    unfreeze: unfreeze_scope(&request),
                    skew,
                    decided: false,
                    request: Some(request),
                });
                self.persist_or_log(stored);
                fx.events.push(ApproverEvent::Request { request: view });
            }
            kind::OUTCOME if stored.paired => {
                let Ok(outcome) = wire::parse::<Outcome>(content) else {
                    return fx;
                };
                // Only for a request this phone showed and still keeps, so a
                // replay, which finds it gone, counts once.
                let Some(i) = stored
                    .waiting
                    .iter()
                    .position(|w| w.id == outcome.request_id)
                else {
                    return fx;
                };
                let waiting = stored.waiting.remove(i);
                if outcome.outcome == OutcomeKind::Approved {
                    if let Some(scope) = waiting.unfreeze {
                        stored
                            .tracker
                            .unfreeze_seen(outcome.request_id, scope, local_now);
                    }
                }
                self.persist_or_log(stored);
                fx.events.push(ApproverEvent::Outcome {
                    request_id: outcome.request_id.to_hex(),
                    outcome: match outcome.outcome {
                        OutcomeKind::Approved => "approved",
                        OutcomeKind::Denied => "denied",
                        OutcomeKind::Expired => "expired",
                        OutcomeKind::Canceled => "canceled",
                    }
                    .into(),
                });
            }
            kind::ANCHOR if stored.paired => {
                let Ok(anchor) = wire::parse::<Anchor>(content) else {
                    return fx;
                };
                let before = stored.tracker.kept().map(|(at, a)| (at, a.seq));
                let alerts = stored.tracker.observe(
                    anchor.at,
                    &anchor.anchor,
                    Some(&anchor.frozen),
                    local_now,
                );
                // An anchor no later than the one kept, a relay's replay or
                // a wrap arriving late, changes nothing and is not shown.
                if stored.tracker.kept().map(|(at, a)| (at, a.seq)) == before {
                    return fx;
                }
                for alert in alerts {
                    stored.alert(alert_text(&alert), &mut fx);
                }
                stored.silent_reported = false;
                self.persist_or_log(stored);
                fx.events.push(anchor_event(&stored.tracker));
            }
            _ => {}
        }
        if forget {
            inner.set(None);
            let _ = self.mobile.storage.delete_share_by_key(STATE_KEY.into());
            fx.halt = true;
        }
        fx
    }

    /// Every [`FREEZE_RESEND_SECS`], at the phone's `local_now`: due
    /// alerts, the silence alert (once per silence), freezes no anchor has
    /// shown yet sent again, and requests past their time dropped. Saves
    /// only what changed, and sends a freeze only once its counter is saved,
    /// so no counter is used twice across a restart.
    fn tick_at(&self, local_now: u64) -> Effects {
        let mut inner = self.lock();
        let mut fx = Effects::default();
        let Some(stored) = inner.stored.as_mut() else {
            return fx;
        };
        if !stored.paired {
            return fx;
        }
        let mut lapsed = Vec::new();
        let mut changed = prune(&mut stored.waiting, local_now, &mut lapsed);
        fx.events.extend(lapsed_events(lapsed));
        for alert in stored.tracker.due_alerts(local_now) {
            stored.alert(alert_text(&alert), &mut fx);
            changed = true;
        }
        let silent = stored.tracker.silent(local_now);
        if silent != stored.silent_reported {
            if silent {
                stored.alert(SILENT_ALERT.into(), &mut fx);
            }
            stored.silent_reported = silent;
            changed = true;
        }
        let unfreezing = stored
            .unfreeze
            .is_some_and(|a| local_now.saturating_sub(a.at) < UNFREEZE_HOLD_SECS);
        if !unfreezing {
            let epoch = stored.tracker.epoch().unwrap_or(0);
            for scope in stored.tracker.freezes_to_resend() {
                if let Ok(content) = signed_freeze(stored, scope, epoch, local_now) {
                    fx.send.push((kind::FREEZE, content));
                    changed = true;
                }
            }
        }
        if changed {
            if let Err(e) = self.persist(stored) {
                tracing::error!(error = %e, "the approver state could not be kept");
                fx.send.clear();
            }
        }
        fx
    }
}

/// Refuse to begin a pairing over one paired or waiting for the gateway.
fn not_pairing(inner: &Inner) -> Result<(), KeepMobileError> {
    match inner.stored.as_ref() {
        Some(s) if s.paired => Err(invalid("already paired: remove this pairing first")),
        Some(_) => Err(invalid(
            "a pairing is waiting for the gateway's answer: cancel it first",
        )),
        None => Ok(()),
    }
}

fn lapsed_events(lapsed: Vec<Hex32>) -> impl Iterator<Item = ApproverEvent> {
    lapsed.into_iter().map(|id| ApproverEvent::RequestExpired {
        request_id: id.to_hex(),
    })
}

fn anchor_event(tracker: &AnchorTracker) -> ApproverEvent {
    let frozen = tracker.frozen();
    ApproverEvent::Anchor {
        epoch: frozen.map_or(0, |f| f.epoch),
        all_frozen: frozen.is_some_and(|f| f.all),
        frozen_credentials: frozen
            .map(|f| f.credentials.iter().map(|c| c.to_hex()).collect())
            .unwrap_or_default(),
        audit_seq: tracker.kept().map_or(0, |(_, a)| a.seq),
    }
}

#[uniffi::export]
impl ApproverHandler {
    /// The approver for `mobile`, with any pairing kept from an earlier
    /// run. One at a time per `KeepMobile`: shut the last one down first.
    #[uniffi::constructor]
    pub fn new(mobile: Arc<KeepMobile>) -> Result<Arc<Self>, KeepMobileError> {
        if mobile.approver_live.swap(true, Ordering::SeqCst) {
            return Err(KeepMobileError::InitializationFailed {
                msg: "an approver is already open for this KeepMobile".into(),
            });
        }
        let stored = match mobile.storage.load_share_by_key(STATE_KEY.into()) {
            Ok(data) => match serde_json::from_slice::<Stored>(&Zeroizing::new(data)) {
                Ok(mut stored) => {
                    stored.counter_floor = stored.counter.saturating_add(COUNTER_MARGIN);
                    Some(stored)
                }
                Err(e) => {
                    mobile.approver_live.store(false, Ordering::SeqCst);
                    return Err(KeepMobileError::StorageError {
                        msg: format!("the approver state cannot be read: {e}"),
                    });
                }
            },
            Err(KeepMobileError::StorageNotFound) => None,
            Err(e) => {
                mobile.approver_live.store(false, Ordering::SeqCst);
                return Err(e);
            }
        };
        let mut inner = Inner::default();
        inner.set(stored);
        Ok(Arc::new(Self {
            mobile,
            inner: Mutex::new(inner),
            running: Mutex::new(None),
            lifecycle: Mutex::new(()),
            generation: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            callbacks: Mutex::new(None),
            last_error: Mutex::new(None),
        }))
    }

    pub fn status(&self) -> ApproverStatus {
        let running = self
            .running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
        let last_error = self
            .last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let inner = self.lock();
        let Some(stored) = inner.stored.as_ref() else {
            return ApproverStatus {
                paired: false,
                pairing: false,
                running,
                label: None,
                fingerprint: None,
                relays: Vec::new(),
                last_error,
                epoch: None,
                all_frozen: false,
                frozen_credentials: Vec::new(),
                silent: false,
                alerts: Vec::new(),
                alerts_dropped: 0,
            };
        };
        let frozen = stored.tracker.frozen();
        ApproverStatus {
            paired: stored.paired,
            pairing: !stored.paired,
            running,
            label: Some(stored.label.clone()),
            fingerprint: stored.fingerprint().ok(),
            relays: stored.relays.clone(),
            last_error,
            epoch: stored.tracker.epoch(),
            all_frozen: frozen.is_some_and(|f| f.all),
            frozen_credentials: frozen
                .map(|f| f.credentials.iter().map(|c| c.to_hex()).collect())
                .unwrap_or_default(),
            silent: stored.tracker.silent(now()),
            alerts: stored.alerts.clone(),
            alerts_dropped: stored.alerts_dropped,
        }
    }

    /// The owner has seen the alerts up to and including `through_seq`
    /// (the last [`ApproverAlert::seq`] shown); any raised since stay.
    pub fn acknowledge_alerts(&self, through_seq: u64) -> Result<(), KeepMobileError> {
        let mut inner = self.lock();
        let stored = inner.stored.as_mut().ok_or_else(|| invalid("not paired"))?;
        stored.alerts.retain(|a| a.seq > through_seq);
        stored.alerts_dropped = 0;
        self.persist(stored)
    }

    /// The requests still waiting for the owner, with the time each has
    /// left, as when they arrived: after a restart, the app shows these.
    pub fn waiting_requests(&self) -> Vec<ApprovalRequest> {
        let inner = self.lock();
        let Some(stored) = inner.stored.as_ref() else {
            return Vec::new();
        };
        let local_now = now();
        stored
            .waiting
            .iter()
            .filter_map(|w| {
                let request = w.open(local_now)?;
                let checked = check_request(request, &stored.channel.0).ok()?;
                Some(view::view(request, &checked, w.skew, w.until - local_now))
            })
            .collect()
    }

    /// The attestation challenge for the pairing code `uri`, to make the
    /// approver key with (`setAttestationChallenge`) before pairing begins.
    /// Refused while paired or while a pairing waits for the gateway, so a
    /// new approver key is never made over the one in use.
    pub fn pairing_attestation_challenge(&self, uri: String) -> Result<Vec<u8>, KeepMobileError> {
        self.open_check()?;
        not_pairing(&self.lock())?;
        let uri = PairingUri::parse(&uri).map_err(|e| invalid(e.to_string()))?;
        Ok(sig::pair_attestation_challenge(&uri.secret, &uri.gateway).to_vec())
    }

    /// Begin pairing with the gateway whose pairing code is `uri`, with the
    /// Keystore's approver key `approver_key` (33 bytes, compressed P-256)
    /// and the phone's `label`. The owner compares the fingerprint with the
    /// gateway's terminal; the app then has the Keystore sign the digest
    /// and calls [`Self::finish_pairing`].
    pub fn begin_pairing(
        &self,
        uri: String,
        approver_key: Vec<u8>,
        label: String,
    ) -> Result<PairingStart, KeepMobileError> {
        self.open_check()?;
        let mut inner = self.lock();
        not_pairing(&inner)?;
        let uri = PairingUri::parse(&uri).map_err(|e| invalid(e.to_string()))?;
        checked_relays(&uri.relays)?;
        keep_approval::change::check_label(&label, "label").map_err(|e| invalid(e.to_string()))?;
        let approver = Hex33(
            approver_key
                .as_slice()
                .try_into()
                .map_err(|_| invalid("an approver key is 33 bytes, compressed P-256"))?,
        );
        let keys = Keys::generate();
        let transport = sig::xonly(&keys);
        let digest = sig::pair_approver_digest(&uri.gateway, &transport, &approver.0);
        let stored = Stored {
            transport: Zeroizing::new(keys.secret_key().to_secret_hex()),
            approver,
            label,
            channel: Hex32(uri.gateway),
            relays: uri.relays.clone(),
            paired: false,
            counter: 0,
            counter_floor: 0,
            tracker: AnchorTracker::default(),
            gate: RequestGate::default(),
            waiting: Vec::new(),
            alerts: Vec::new(),
            alert_seq: 0,
            alerts_dropped: 0,
            silent_reported: false,
            unfreeze: None,
        };
        let start = PairingStart {
            fingerprint: sig::fingerprint(&transport, &approver.0),
            digest: digest.to_vec(),
        };
        inner.begun = Some(Begun {
            stored,
            secret: uri.secret.clone(),
            digest,
        });
        Ok(start)
    }

    /// Send the pairing, signed by the approver key (`signature`, DER, as
    /// the Keystore returns it) and with its attestation (`attestation`,
    /// the certificates `getCertificateChain` returns, DER, leaf first), and
    /// wait for the gateway's answer. If it cannot be sent, the pairing
    /// begun stays, to finish again.
    pub fn finish_pairing(
        self: Arc<Self>,
        signature: Vec<u8>,
        attestation: Vec<Vec<u8>>,
        callbacks: Arc<dyn ApproverCallbacks>,
    ) -> Result<(), KeepMobileError> {
        let _lifecycle = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        self.open_check()?;
        let attestation = CertChain::new(attestation).map_err(|e| invalid(e.to_string()))?;
        let (pair, relays, keys, channel, secret, digest) = {
            let mut inner = self.lock();
            if inner.stored.as_ref().is_some_and(|s| s.paired) {
                return Err(invalid("already paired: remove this pairing first"));
            }
            let begun = inner
                .begun
                .as_ref()
                .ok_or_else(|| invalid("no pairing was begun"))?;
            let sig = checked_signature(&signature, &begun.stored.approver, &begun.digest)?;
            let keys = begun.stored.keys()?;
            let transport = sig::xonly(&keys);
            let channel = begun.stored.channel.0;
            let a = begun.stored.approver.0;
            let pair = Pairing::Pair {
                v: V1,
                label: begun.stored.label.clone(),
                alg: Alg::P256,
                approver: begun.stored.approver,
                proof: sig::pair_proof(&begun.secret, &channel, &transport, &a),
                approver_sig: sig,
                attestation,
            };
            let stored = begun.stored.clone();
            let secret = begun.secret.clone();
            let digest = begun.digest;
            self.persist(&stored)?;
            let relays = stored.relays.clone();
            inner.set(Some(stored));
            (pair, relays, keys, channel, secret, digest)
        };
        *self.callbacks.lock().unwrap_or_else(|e| e.into_inner()) = Some(callbacks);
        self.halt();
        let sent = self.run(relays, keys.clone()).and_then(|()| {
            let tag = TagKey::pairing_phone(&secret);
            let event = wrap::wrap(
                &keys,
                &channel,
                &tag,
                kind::PAIRING,
                &wire::to_text(&pair),
                now(),
            )
            .map_err(|e| invalid(e.to_string()))?;
            self.send_now(event)
        });
        self.settle_pairing(sent, channel, keys.public_key(), digest)
    }

    /// Start serving a pairing kept from an earlier run. Requests that
    /// waited across the restart are read with [`Self::waiting_requests`].
    pub fn start(
        self: Arc<Self>,
        callbacks: Arc<dyn ApproverCallbacks>,
    ) -> Result<(), KeepMobileError> {
        let _lifecycle = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        self.open_check()?;
        let (relays, keys) = {
            let inner = self.lock();
            let stored = inner.stored.as_ref().ok_or_else(|| invalid("not paired"))?;
            (stored.relays.clone(), stored.keys()?)
        };
        *self.callbacks.lock().unwrap_or_else(|e| e.into_inner()) = Some(callbacks);
        self.halt();
        self.run(relays, keys)
    }

    pub fn stop(&self) {
        let _lifecycle = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        self.halt();
    }

    /// Stop serving, let go of the callbacks, and give the `KeepMobile`'s
    /// approver slot back, so a new handler can open. The pairing stays
    /// stored; this handler can do nothing more.
    pub fn shutdown(&self) {
        let _lifecycle = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        self.halt();
        *self.callbacks.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self.lock() = Inner::default();
        self.release();
    }

    /// Forget the pairing on this phone. The gateway keeps the device until
    /// it is removed there.
    pub fn forget(&self) -> Result<(), KeepMobileError> {
        let _lifecycle = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        self.open_check()?;
        self.halt();
        *self.lock() = Inner::default();
        match self.mobile.storage.delete_share_by_key(STATE_KEY.into()) {
            Ok(()) | Err(KeepMobileError::StorageNotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// The digest the approver key signs to approve or deny request
    /// `request_id`, while it can still be decided.
    pub fn decision_digest(
        &self,
        request_id: String,
        approve: bool,
    ) -> Result<Vec<u8>, KeepMobileError> {
        let id = request_id_arg(&request_id)?;
        let inner = self.lock();
        let stored = inner.stored.as_ref().ok_or_else(|| invalid("not paired"))?;
        let local_now = now();
        let request = stored
            .waiting
            .iter()
            .filter(|w| w.id == id)
            .find_map(|w| w.open(local_now))
            .ok_or_else(|| invalid("that request is no longer waiting"))?;
        Ok(sig::decision_digest(
            &stored.channel.0,
            &stored.approver.0,
            &request.request_hash.0,
            verdict(approve),
        )
        .to_vec())
    }

    /// Send the decision on request `request_id` that the Keystore signed
    /// (`signature`, DER) over [`Self::decision_digest`]'s digest.
    pub fn send_decision(
        &self,
        request_id: String,
        approve: bool,
        signature: Vec<u8>,
    ) -> Result<(), KeepMobileError> {
        let id = request_id_arg(&request_id)?;
        let verdict = verdict(approve);
        let decision = {
            let inner = self.lock();
            let stored = inner.stored.as_ref().ok_or_else(|| invalid("not paired"))?;
            let request = stored
                .waiting
                .iter()
                .filter(|w| w.id == id)
                .find_map(|w| w.open(now()))
                .ok_or_else(|| invalid("that request is no longer waiting"))?;
            let request_hash = request.request_hash;
            let digest = sig::decision_digest(
                &stored.channel.0,
                &stored.approver.0,
                &request_hash.0,
                verdict,
            );
            Decision {
                v: V1,
                request_id: id,
                request_hash,
                decision: verdict,
                sig: checked_signature(&signature, &stored.approver, &digest)?,
            }
        };
        self.send_now(self.sealed(kind::DECISION, &wire::to_text(&decision))?)?;
        // Decided only once a relay took it, so a failed send can be tried
        // again. Its payload goes; what its outcome needs stays.
        let mut inner = self.lock();
        if let Some(stored) = inner.stored.as_mut() {
            if let Some(w) = stored.waiting.iter_mut().find(|w| w.id == id) {
                w.decided = true;
                w.request = None;
            }
            if stored.waiting.iter().filter(|w| w.decided).count() > MAX_WAITING {
                if let Some(i) = stored.waiting.iter().position(|w| w.decided) {
                    stored.waiting.remove(i);
                }
            }
            self.persist_or_log(stored);
        }
        Ok(())
    }

    /// Freeze one credential (its id), or every agent (`None`). Signed by
    /// the transport key: no biometric, so stopping an agent is never slower
    /// than letting it go. Sent again until an anchor shows it.
    pub fn freeze(&self, credential: Option<String>) -> Result<(), KeepMobileError> {
        let scope = scope_arg(credential)?;
        let content = {
            let mut inner = self.lock();
            let stored = inner
                .stored
                .as_mut()
                .filter(|s| s.paired)
                .ok_or_else(|| invalid("not paired"))?;
            let epoch = stored.tracker.epoch().unwrap_or(0);
            let content = signed_freeze(stored, scope, epoch, now())?;
            self.persist(stored)?;
            content
        };
        self.send_now(self.sealed(kind::FREEZE, &content)?)
    }

    /// The digest the approver key signs to unfreeze one credential, or
    /// every agent, at the gateway's current epoch.
    pub fn unfreeze_digest(&self, credential: Option<String>) -> Result<Vec<u8>, KeepMobileError> {
        let scope = scope_arg(credential)?;
        let mut inner = self.lock();
        let stored = inner
            .stored
            .as_mut()
            .filter(|s| s.paired)
            .ok_or_else(|| invalid("not paired"))?;
        let epoch = stored.tracker.epoch().unwrap_or(0);
        stored.next_counter();
        let asked = AskedUnfreeze {
            scope,
            counter: stored.counter,
            epoch,
            at: now(),
        };
        stored.unfreeze = Some(asked);
        self.persist(stored)?;
        Ok(unfreeze_digest(stored, asked).to_vec())
    }

    /// Send the unfreeze of the same credential (or every agent) that the
    /// Keystore signed (`signature`, DER) over [`Self::unfreeze_digest`]'s
    /// digest.
    pub fn send_unfreeze(
        &self,
        credential: Option<String>,
        signature: Vec<u8>,
    ) -> Result<(), KeepMobileError> {
        let scope = scope_arg(credential)?;
        let freeze = {
            let mut inner = self.lock();
            let stored = inner.stored.as_mut().ok_or_else(|| invalid("not paired"))?;
            let asked = stored
                .unfreeze
                .filter(|a| a.scope == scope)
                .ok_or_else(|| invalid("no unfreeze of that scope was asked for"))?;
            // A freeze signed since carries a higher counter, so the gateway
            // would refuse this one as old.
            if stored.counter != asked.counter {
                stored.unfreeze = None;
                self.persist_or_log(stored);
                return Err(invalid(
                    "a freeze was sent while this unfreeze was being signed: ask for the \
                     unfreeze digest again",
                ));
            }
            let digest = unfreeze_digest(stored, asked);
            Freeze {
                v: V1,
                action: FreezeAction::Unfreeze,
                scope,
                counter: asked.counter,
                epoch: asked.epoch,
                signer: SignerKey::Approver(stored.approver),
                sig: checked_signature(&signature, &stored.approver, &digest)?,
            }
        };
        self.send_now(self.sealed(kind::FREEZE, &wire::to_text(&freeze))?)?;
        let mut inner = self.lock();
        if let Some(stored) = inner.stored.as_mut() {
            stored.unfreeze = None;
            self.persist_or_log(stored);
        }
        Ok(())
    }
}

fn unfreeze_digest(stored: &Stored, asked: AskedUnfreeze) -> [u8; 32] {
    sig::freeze_digest(
        &stored.channel.0,
        &SignerKey::Approver(stored.approver),
        asked.counter,
        asked.epoch,
        FreezeAction::Unfreeze,
        asked.scope,
    )
}

#[cfg(test)]
mod tests;
