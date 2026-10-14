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

mod view;

pub use view::{ApprovalField, ApprovalRequest};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use keep_approval::approver::{clock_skew, Alert, AnchorTracker, RequestGate, FREEZE_RESEND_SECS};
use keep_approval::binding::check_request;
use keep_approval::change::{Change, Scope};
use keep_approval::messages::{
    self as wire, Anchor, Decision, Freeze, FreezeAction, Outcome, OutcomeKind, Pairing, Request,
    SignerKey, Verdict, V1,
};
use keep_approval::pairing::{check_paired, PairingUri};
use keep_approval::sig::{self, Alg};
use keep_approval::wrap::{self, Candidate, SeenWraps, TagKey};
use keep_approval::{kind, Hex16, Hex32, Hex33, Hex64};
use nostr_sdk::prelude::{Client, Event, Filter, Keys, Kind, PublicKey, RelayPoolNotification};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::KeepMobileError;
use crate::KeepMobile;

const STATE_KEY: &str = "__keep_approver";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn invalid(msg: impl Into<String>) -> KeepMobileError {
    KeepMobileError::InvalidInput { msg: msg.into() }
}

/// What the phone keeps between runs.
#[derive(Serialize, Deserialize)]
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
    tracker: AnchorTracker,
    gate: RequestGate,
}

impl Stored {
    fn keys(&self) -> Result<Keys, KeepMobileError> {
        Keys::parse(&self.transport).map_err(|_| invalid("the stored transport key is damaged"))
    }

    fn fingerprint(&self) -> Result<String, KeepMobileError> {
        Ok(sig::fingerprint(
            &sig::xonly(&self.keys()?),
            &self.approver.0,
        ))
    }
}

/// A pairing begun, waiting for the approver key's signature.
struct Begun {
    stored: Stored,
    secret: Zeroizing<[u8; 32]>,
    digest: [u8; 32],
}

/// An approver signature asked for and not yet given.
enum Asked {
    Decision {
        request_id: Hex32,
        request_hash: Hex32,
        verdict: Verdict,
    },
    Unfreeze {
        scope: Scope,
        counter: u64,
        epoch: u64,
    },
}

struct Waiting {
    request: Request,
    /// The phone's clock when the request can no longer be approved.
    until: u64,
}

#[derive(Default)]
struct Inner {
    stored: Option<Stored>,
    begun: Option<Begun>,
    asked: Option<([u8; 32], Asked)>,
    waiting: HashMap<Hex32, Waiting>,
    seen: SeenWraps,
    silent_reported: bool,
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
    /// The gateway's freeze epoch, from the latest anchor.
    pub epoch: Option<u64>,
    pub all_frozen: bool,
    pub frozen_credentials: Vec<String>,
    /// No anchor for an hour: the gateway is down, cut off, or withheld.
    pub silent: bool,
}

/// Something to show the owner.
#[derive(uniffi::Enum, Clone, Debug)]
pub enum ApproverEvent {
    Paired {
        fingerprint: String,
    },
    PairingRefused {
        reason: String,
    },
    Request {
        request: ApprovalRequest,
    },
    /// A request that failed a check, never offered for approval.
    RequestRefused {
        reason: String,
    },
    Outcome {
        request_id: String,
        /// `approved`, `denied`, `expired` or `canceled`.
        outcome: String,
    },
    Anchor {
        epoch: u64,
        all_frozen: bool,
        frozen_credentials: Vec<String>,
        audit_seq: u64,
    },
    /// Something the owner must see, prominently.
    Alert {
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
            "A wallet ledger ({wallet}) went back from {from} to {to} spends."
        ),
        Alert::WalletMissing { wallet } => format!("A wallet ledger ({wallet}) is gone."),
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

/// A signature from the Keystore, checked against the approver key over
/// `digest`, so a key the Keystore replaced (a new biometric enrolled) is
/// found here rather than refused at the gateway.
fn checked_signature(
    der: &[u8],
    approver: &Hex33,
    digest: &[u8; 32],
) -> Result<Hex64, KeepMobileError> {
    let sig = sig::p256_from_der(der).map_err(|e| invalid(e.to_string()))?;
    sig::verify_p256(&approver.0, digest, &sig)
        .map_err(|_| invalid("the signature is not the approver key's: re-pair this phone"))?;
    Ok(sig)
}

/// What the network side does after a state change, outside the lock.
#[derive(Default)]
struct Effects {
    events: Vec<ApproverEvent>,
    send: Vec<(u16, String)>,
    reconnect: Option<Vec<String>>,
}

struct Running {
    client: Client,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

#[derive(uniffi::Object)]
pub struct ApproverHandler {
    mobile: Arc<KeepMobile>,
    inner: Arc<Mutex<Inner>>,
    running: Mutex<Option<Running>>,
    callbacks: Mutex<Option<Arc<dyn ApproverCallbacks>>>,
}

impl ApproverHandler {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn persist(&self, stored: &Stored) -> Result<(), KeepMobileError> {
        let data = Zeroizing::new(
            serde_json::to_vec(stored)
                .map_err(|e| KeepMobileError::Serialization { msg: e.to_string() })?,
        );
        self.mobile.storage.store_share_by_key(
            STATE_KEY.into(),
            data.to_vec(),
            crate::persistence::storage_metadata("approver"),
        )
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

    /// Send `event` from a call the app made, on its own thread.
    fn send_now(&self, event: Event) -> Result<(), KeepMobileError> {
        let client = self.client()?;
        self.mobile.runtime.block_on(async move {
            client
                .send_event(&event)
                .await
                .map(|_| ())
                .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })
        })
    }

    /// Connect to `relays` and serve what arrives for the transport key.
    fn run(
        self: &Arc<Self>,
        relays: Vec<String>,
        transport: PublicKey,
    ) -> Result<(), KeepMobileError> {
        self.halt();
        let client = Client::default();
        let this = self.clone();
        let tasks = self.mobile.runtime.block_on(async {
            for relay in &relays {
                client
                    .add_relay(relay)
                    .await
                    .map_err(|e| KeepMobileError::InvalidRelayUrl { msg: e.to_string() })?;
            }
            client.connect().await;
            client
                .subscribe(Filter::new().kind(Kind::GiftWrap).pubkey(transport), None)
                .await
                .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?;
            let mut events = client.notifications();
            let receiver = this.clone();
            let listen = tokio::spawn(async move {
                loop {
                    match events.recv().await {
                        Ok(RelayPoolNotification::Event { event, .. }) => {
                            // Storage and the app's callbacks block; keep
                            // them off the runtime's workers.
                            let r = receiver.clone();
                            if let Ok(fx) =
                                tokio::task::spawn_blocking(move || r.received(&event)).await
                            {
                                receiver.deliver(fx).await;
                            }
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
            let ticker = this.clone();
            let tick = tokio::spawn(async move {
                let mut every = tokio::time::interval(Duration::from_secs(FREEZE_RESEND_SECS));
                loop {
                    every.tick().await;
                    let t = ticker.clone();
                    if let Ok(fx) = tokio::task::spawn_blocking(move || t.tick()).await {
                        ticker.deliver(fx).await;
                    }
                }
            });
            Ok::<_, KeepMobileError>(vec![listen, tick])
        })?;
        *self.running.lock().unwrap_or_else(|e| e.into_inner()) = Some(Running { client, tasks });
        Ok(())
    }

    fn halt(&self) {
        let running = self
            .running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(running) = running {
            for task in running.tasks {
                task.abort();
            }
            let client = running.client;
            self.mobile
                .runtime
                .spawn(async move { client.shutdown().await });
        }
    }

    fn received(&self, event: &Event) -> Effects {
        let mut inner = self.lock();
        let Inner { stored, seen, .. } = &mut *inner;
        let Some(stored) = stored.as_ref() else {
            return Effects::default();
        };
        let Ok(keys) = stored.keys() else {
            return Effects::default();
        };
        let Ok(tag_key) = TagKey::device(&keys, &stored.channel.0) else {
            return Effects::default();
        };
        let candidates = [Candidate::Peer {
            id: (),
            tag_key,
            sender: stored.channel.0,
        }];
        let Ok(opened) = wrap::open(&keys, event, &candidates, seen, now()) else {
            return Effects::default();
        };
        let (kind, content) = (opened.kind, opened.content.to_string());
        self.handle(&mut inner, kind, &content, now())
    }

    /// Send what `fx` holds and tell the app, from the runtime: messages are
    /// sent with the running client, the app is called on a blocking thread,
    /// and a reconnect runs on a thread of its own, since it replaces the
    /// tasks this runs in.
    async fn deliver(self: &Arc<Self>, fx: Effects) {
        if let Ok(client) = self.client() {
            for (kind, content) in fx.send {
                match self.sealed(kind, &content) {
                    Ok(event) => {
                        if let Err(e) = client.send_event(&event).await {
                            tracing::warn!(error = %e, "an approver message was not sent");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "an approver message was not sealed"),
                }
            }
        }
        if !fx.events.is_empty() {
            let this = self.clone();
            let events = fx.events;
            let _ = tokio::task::spawn_blocking(move || this.emit(events)).await;
        }
        if let Some(relays) = fx.reconnect {
            let this = self.clone();
            std::thread::spawn(move || {
                let transport = this
                    .lock()
                    .stored
                    .as_ref()
                    .and_then(|s| s.keys().ok())
                    .map(|k| k.public_key());
                if let Some(transport) = transport {
                    if let Err(e) = this.run(relays, transport) {
                        tracing::warn!(error = %e, "the approver could not reconnect");
                    }
                }
            });
        }
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
                        reason: keep_approval::approver::shown(
                            &reason,
                            keep_approval::approver::GATEWAY_TEXT_CHARS,
                        )
                        .text,
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
                                stored.relays = paired.relays.clone();
                                fx.reconnect = Some(stored.relays.clone());
                            }
                            stored
                                .tracker
                                .baseline(&paired.anchor, &paired.frozen, local_now);
                            if let Err(e) = self.persist(stored) {
                                tracing::error!(error = %e, "the pairing could not be kept");
                            }
                            fx.events.push(ApproverEvent::Paired {
                                fingerprint: stored.fingerprint().unwrap_or_default(),
                            });
                        }
                        Err(e) => fx.events.push(ApproverEvent::PairingRefused {
                            reason: e.to_string(),
                        }),
                    }
                }
                Err(e) => fx.events.push(ApproverEvent::PairingRefused {
                    reason: e.to_string(),
                }),
            },
            kind::REQUEST if stored.paired => {
                let request: Request = match wire::parse(content) {
                    Ok(r) => r,
                    Err(e) => {
                        fx.events.push(ApproverEvent::RequestRefused {
                            reason: e.to_string(),
                        });
                        return fx;
                    }
                };
                let checked = match check_request(&request, &stored.channel.0) {
                    Ok(c) => c,
                    Err(e) => {
                        fx.events.push(ApproverEvent::RequestRefused {
                            reason: e.to_string(),
                        });
                        return fx;
                    }
                };
                if let Err(e) = stored.gate.admit(&request, &stored.tracker, local_now) {
                    tracing::debug!(error = %e, "a request not shown");
                    return fx;
                }
                for alert in
                    stored
                        .tracker
                        .observe(request.created_at, &request.anchor, None, local_now)
                {
                    fx.events.push(ApproverEvent::Alert {
                        message: alert_text(&alert),
                    });
                }
                let shown = view::view(
                    &request,
                    &checked,
                    clock_skew(request.created_at, local_now),
                );
                inner.waiting.insert(
                    request.request_id,
                    Waiting {
                        until: local_now.saturating_add(request.deadline_secs),
                        request,
                    },
                );
                if let Err(e) = self.persist(stored) {
                    tracing::error!(error = %e, "the approver state could not be kept");
                }
                fx.events.push(ApproverEvent::Request { request: shown });
            }
            kind::OUTCOME if stored.paired => {
                let Ok(outcome) = wire::parse::<Outcome>(content) else {
                    return fx;
                };
                if !stored.tracker.outcome_seen(outcome.request_id, local_now) {
                    return fx;
                }
                if let Some(waiting) = inner.waiting.remove(&outcome.request_id) {
                    if outcome.outcome == OutcomeKind::Approved {
                        if let Some(Change::Unfreeze { scope, .. }) =
                            unfreeze_change(&waiting.request)
                        {
                            stored
                                .tracker
                                .unfreeze_seen(outcome.request_id, scope, local_now);
                        }
                    }
                }
                if let Err(e) = self.persist(stored) {
                    tracing::error!(error = %e, "the approver state could not be kept");
                }
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
                for alert in stored.tracker.observe(
                    anchor.at,
                    &anchor.anchor,
                    Some(&anchor.frozen),
                    local_now,
                ) {
                    fx.events.push(ApproverEvent::Alert {
                        message: alert_text(&alert),
                    });
                }
                inner.silent_reported = false;
                if let Err(e) = self.persist(stored) {
                    tracing::error!(error = %e, "the approver state could not be kept");
                }
                fx.events.push(ApproverEvent::Anchor {
                    epoch: anchor.frozen.epoch,
                    all_frozen: anchor.frozen.all,
                    frozen_credentials: anchor
                        .frozen
                        .credentials
                        .iter()
                        .map(|c| c.to_hex())
                        .collect(),
                    audit_seq: anchor.anchor.seq,
                });
            }
            _ => {}
        }
        if forget {
            inner.stored = None;
            let _ = self.mobile.storage.delete_share_by_key(STATE_KEY.into());
        }
        fx
    }

    /// Every [`FREEZE_RESEND_SECS`]: due alerts, the silence alert, freezes
    /// no anchor has shown yet sent again, and requests past their time
    /// dropped.
    fn tick(&self) -> Effects {
        let local_now = now();
        {
            let mut inner = self.lock();
            let mut fx = Effects::default();
            inner.waiting.retain(|_, w| w.until > local_now);
            let silent_reported = inner.silent_reported;
            let Some(stored) = inner.stored.as_mut() else {
                return fx;
            };
            if !stored.paired {
                return fx;
            }
            for alert in stored.tracker.due_alerts(local_now) {
                fx.events.push(ApproverEvent::Alert {
                    message: alert_text(&alert),
                });
            }
            let silent = stored.tracker.silent(local_now);
            if silent && !silent_reported {
                fx.events.push(ApproverEvent::Alert {
                    message: "No word from the gateway for an hour: it is down, cut off, or its messages are withheld.".into(),
                });
            }
            let epoch = stored.tracker.epoch().unwrap_or(0);
            for scope in stored.tracker.freezes_to_resend() {
                if let Ok(content) = signed_freeze(stored, scope, epoch) {
                    fx.send.push((kind::FREEZE, content));
                }
            }
            if let Err(e) = self.persist(stored) {
                tracing::error!(error = %e, "the approver state could not be kept");
            }
            inner.silent_reported = silent;
            fx
        }
    }
}

/// The change an unfreeze request carries.
fn unfreeze_change(request: &Request) -> Option<Change> {
    let change = request.payload.get("change")?;
    match Change::parse(change) {
        Ok(c @ Change::Unfreeze { .. }) => Some(c),
        _ => None,
    }
}

/// A freeze of `scope` signed by the transport key with the next counter.
fn signed_freeze(stored: &mut Stored, scope: Scope, epoch: u64) -> Result<String, KeepMobileError> {
    let keys = stored.keys()?;
    stored.counter += 1;
    let freeze = sig::freeze(&keys, &stored.channel.0, stored.counter, epoch, scope);
    stored.tracker.freeze_sent(scope, epoch, now());
    Ok(wire::to_text(&freeze))
}

#[uniffi::export]
impl ApproverHandler {
    #[uniffi::constructor]
    pub fn new(mobile: Arc<KeepMobile>) -> Arc<Self> {
        let stored = mobile
            .storage
            .load_share_by_key(STATE_KEY.into())
            .ok()
            .and_then(|data| serde_json::from_slice::<Stored>(&Zeroizing::new(data)).ok());
        Arc::new(Self {
            mobile,
            inner: Arc::new(Mutex::new(Inner {
                stored,
                ..Inner::default()
            })),
            running: Mutex::new(None),
            callbacks: Mutex::new(None),
        })
    }

    pub fn status(&self) -> ApproverStatus {
        let inner = self.lock();
        let running = self
            .running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
        let Some(stored) = inner.stored.as_ref() else {
            return ApproverStatus {
                paired: false,
                pairing: false,
                running,
                label: None,
                fingerprint: None,
                relays: Vec::new(),
                epoch: None,
                all_frozen: false,
                frozen_credentials: Vec::new(),
                silent: false,
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
            epoch: stored.tracker.epoch(),
            all_frozen: frozen.is_some_and(|f| f.all),
            frozen_credentials: frozen
                .map(|f| f.credentials.iter().map(|c| c.to_hex()).collect())
                .unwrap_or_default(),
            silent: stored.tracker.silent(now()),
        }
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
        let mut inner = self.lock();
        if inner.stored.as_ref().is_some_and(|s| s.paired) {
            return Err(invalid("already paired: remove this pairing first"));
        }
        let uri = PairingUri::parse(&uri).map_err(|e| invalid(e.to_string()))?;
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
            tracker: AnchorTracker::default(),
            gate: RequestGate::default(),
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
    /// the Keystore returns it), and wait for the gateway's answer.
    pub fn finish_pairing(
        self: Arc<Self>,
        signature: Vec<u8>,
        callbacks: Arc<dyn ApproverCallbacks>,
    ) -> Result<(), KeepMobileError> {
        let (pair, relays, keys, channel, secret) = {
            let mut inner = self.lock();
            let begun = inner
                .begun
                .take()
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
            };
            self.persist(&begun.stored)?;
            let relays = begun.stored.relays.clone();
            inner.stored = Some(begun.stored);
            (pair, relays, keys, channel, begun.secret)
        };
        *self.callbacks.lock().unwrap_or_else(|e| e.into_inner()) = Some(callbacks);
        self.run(relays, keys.public_key())?;
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
    }

    /// Start serving a pairing kept from an earlier run.
    pub fn start(
        self: Arc<Self>,
        callbacks: Arc<dyn ApproverCallbacks>,
    ) -> Result<(), KeepMobileError> {
        let (relays, transport) = {
            let inner = self.lock();
            let stored = inner.stored.as_ref().ok_or_else(|| invalid("not paired"))?;
            (stored.relays.clone(), stored.keys()?.public_key())
        };
        *self.callbacks.lock().unwrap_or_else(|e| e.into_inner()) = Some(callbacks);
        self.run(relays, transport)
    }

    pub fn stop(&self) {
        self.halt();
    }

    /// Forget the pairing on this phone. The gateway keeps the device until
    /// it is removed there.
    pub fn forget(&self) -> Result<(), KeepMobileError> {
        self.halt();
        let mut inner = self.lock();
        *inner = Inner::default();
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
        let mut inner = self.lock();
        let local_now = now();
        let waiting = inner
            .waiting
            .get(&id)
            .filter(|w| w.until > local_now)
            .ok_or_else(|| invalid("that request is no longer waiting"))?;
        let request_hash = waiting.request.request_hash;
        let stored = inner.stored.as_ref().ok_or_else(|| invalid("not paired"))?;
        let verdict = if approve {
            Verdict::Approve
        } else {
            Verdict::Deny
        };
        let digest = sig::decision_digest(
            &stored.channel.0,
            &stored.approver.0,
            &request_hash.0,
            verdict,
        );
        inner.asked = Some((
            digest,
            Asked::Decision {
                request_id: id,
                request_hash,
                verdict,
            },
        ));
        Ok(digest.to_vec())
    }

    /// Send the decision the Keystore signed (`signature`, DER) after
    /// [`Self::decision_digest`].
    pub fn send_decision(&self, signature: Vec<u8>) -> Result<(), KeepMobileError> {
        let decision = {
            let mut inner = self.lock();
            let (digest, asked) = inner
                .asked
                .take()
                .ok_or_else(|| invalid("no decision was asked for"))?;
            let Asked::Decision {
                request_id,
                request_hash,
                verdict,
            } = asked
            else {
                return Err(invalid("the signature asked for is not a decision"));
            };
            if inner
                .waiting
                .get(&request_id)
                .is_none_or(|w| w.until <= now())
            {
                return Err(invalid("that request is no longer waiting"));
            }
            let stored = inner.stored.as_ref().ok_or_else(|| invalid("not paired"))?;
            let sig = checked_signature(&signature, &stored.approver, &digest)?;
            Decision {
                v: V1,
                request_id,
                request_hash,
                decision: verdict,
                sig,
            }
        };
        // Taken off the waiting list only once sent, so a failed send can be
        // tried again.
        self.send_now(self.sealed(kind::DECISION, &wire::to_text(&decision))?)?;
        self.lock().waiting.remove(&decision.request_id);
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
            let content = signed_freeze(stored, scope, epoch)?;
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
        stored.counter += 1;
        let counter = stored.counter;
        let signer = SignerKey::Approver(stored.approver);
        let digest = sig::freeze_digest(
            &stored.channel.0,
            &signer,
            counter,
            epoch,
            FreezeAction::Unfreeze,
            scope,
        );
        self.persist(stored)?;
        inner.asked = Some((
            digest,
            Asked::Unfreeze {
                scope,
                counter,
                epoch,
            },
        ));
        Ok(digest.to_vec())
    }

    /// Send the unfreeze the Keystore signed (`signature`, DER) after
    /// [`Self::unfreeze_digest`].
    pub fn send_unfreeze(&self, signature: Vec<u8>) -> Result<(), KeepMobileError> {
        let freeze = {
            let mut inner = self.lock();
            let (digest, asked) = inner
                .asked
                .take()
                .ok_or_else(|| invalid("no unfreeze was asked for"))?;
            let Asked::Unfreeze {
                scope,
                counter,
                epoch,
            } = asked
            else {
                return Err(invalid("the signature asked for is not an unfreeze"));
            };
            let stored = inner.stored.as_ref().ok_or_else(|| invalid("not paired"))?;
            let sig = checked_signature(&signature, &stored.approver, &digest)?;
            Freeze {
                v: V1,
                action: FreezeAction::Unfreeze,
                scope,
                counter,
                epoch,
                signer: SignerKey::Approver(stored.approver),
                sig,
            }
        };
        self.send_now(self.sealed(kind::FREEZE, &wire::to_text(&freeze))?)
    }
}

#[cfg(test)]
mod tests;
