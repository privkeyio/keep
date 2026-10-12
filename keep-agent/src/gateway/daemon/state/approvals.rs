// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Approvals over Nostr, the gateway's side: requests parked for the
//! approver devices, their decisions, freezes from the devices, anchors,
//! pairing, and management changes that need an approver.
//!
//! Everything here runs under the state lock, like every other decision,
//! except opening wraps, which [`Inbox`] does before the lock is taken.
//! A parked request holds no lock and no thread: the agent's connection
//! waits on a oneshot channel the decision, the deadline, a freeze or a
//! cancellation answers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use keep_approval::binding::UnsignedEventFields;
use keep_approval::change::{Change, Decimal, Scope};
use keep_approval::messages::{
    self as wire, Anchor, AnchorState, Budget, CredentialRef, Decision as SignedDecision, Freeze,
    FreezeAction, Frozen, Outcome, OutcomeKind, Pairing, Reason, Verdict, WalletAnchor, V1,
};
use keep_approval::pairing::PairingUri;
use keep_approval::sig::{self, Device};
use keep_approval::wrap::{self, Opened, TagKey};
use keep_approval::{kind, Hex16, Hex32};
use keep_core::audit::AuditEventType;
use nostr_sdk::prelude::{Event, Keys};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use super::{
    decode_ledger, line, load_credential, tool_result, wallet_key, Refusal, State, LEDGER_NETWORKS,
};
use crate::approval::{Approval, ParkRequest, Parked, ParkedObject};
use crate::error::{AgentError, Result};
use crate::gateway::daemon::approvals::{
    Inbox, RelayLink, Source, Store, StoredDevice, ANCHOR_EVERY_SECS, MAX_PARKED, OUTBOX_CAPACITY,
    PAIRING_SECS,
};
use crate::gateway::GrantedCredential;
use crate::policy::{evaluate_approved, ApprovalReason, Budgets, Decision, Grant, Ledger};

/// What a request that waits for an approver hands its connection: the
/// line to write once it is decided, and the request to cancel if the
/// connection goes away first.
pub struct Pending {
    pub request_id: Option<[u8; 32]>,
    pub reply: oneshot::Receiver<Zeroizing<String>>,
}

/// An agent request that needs an approval, ready to park.
pub(crate) struct ParkAsk {
    pub object: ParkedObject,
    pub reason: Reason,
    pub budget: Option<Budget>,
}

/// Who waits for a parked request, and what its approval does.
enum Waiter {
    Agent {
        credential: [u8; 16],
        id: Value,
        tool: &'static str,
        reply: oneshot::Sender<Zeroizing<String>>,
    },
    Admin {
        conn: u64,
        reply: oneshot::Sender<Zeroizing<String>>,
        effect: Effect,
    },
}

/// What an approved management change does beyond its change object.
enum Effect {
    /// Issue the credential with this grant, whose change grant the change
    /// carries.
    Issue {
        grant: Grant,
    },
    Unfreeze,
    /// Register the paired device, then tell it so.
    AddApprover,
    RemoveApprover,
}

struct Waiting {
    parked: Parked,
    /// On the budget clock.
    deadline: u64,
    waiter: Waiter,
}

/// How a parked request ended.
enum End {
    Denied { device: Device, sig: String },
    Expired,
    Canceled(&'static str),
}

enum PairState {
    /// Waiting for the phone's `pair`.
    Waiting,
    /// The phone's keys, waiting for the operator to confirm the fingerprint.
    Confirming { device: Device },
}

struct PairingSession {
    secret: Zeroizing<[u8; 32]>,
    label: String,
    conn: u64,
    /// On the budget clock.
    expires: u64,
    state: PairState,
    /// The waiting admin command, told when the phone's keys arrive.
    reply: Option<oneshot::Sender<Zeroizing<String>>>,
}

/// The approval side of a running gateway with its channel key.
pub(crate) struct Approvals {
    channel: Keys,
    channel_pub: [u8; 32],
    relays: Vec<String>,
    deadline_secs: u64,
    store: Store,
    pairing: Option<PairingSession>,
    parked: HashMap<[u8; 32], Waiting>,
    outbox: mpsc::Sender<Event>,
    link: Option<RelayLink>,
    inbox: Arc<Mutex<Inbox>>,
    /// When the next anchor is due, on the budget clock.
    next_anchor: u64,
    /// Owner entries that could not be written yet; retried until they are,
    /// since a freeze never waits on the log.
    owed: Vec<(AuditEventType, String)>,
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn admin_ok(result: Value) -> Zeroizing<String> {
    line(&json!({ "ok": true, "result": result }))
}

fn admin_err(message: &str) -> Zeroizing<String> {
    line(&json!({ "ok": false, "error": message }))
}

impl State {
    /// Set up approvals with the channel key, if one was loaded, after the
    /// state starts. Refuses to go on when an approver is registered and the
    /// key is missing or is not the one the approvers paired with, when the
    /// key is a key in the vault, or when the relays or deadline are not
    /// usable. Without a key and without approvers, approvals stay off and
    /// every request that needs one is refused, as before.
    pub fn configure_approvals(
        &mut self,
        channel: Option<Keys>,
        relays: Vec<String>,
        deadline_secs: u64,
    ) -> Result<()> {
        let store = Store::load(&self.keep)?;
        let registered = !store.devices.is_empty();
        let Some(channel) = channel else {
            if registered {
                return Err(AgentError::Other(
                    "approver devices are registered, so the gateway needs its channel-key \
                     credential to start: load it in the unit, or run `keep gateway approver \
                     reset` and pair again"
                        .into(),
                ));
            }
            self.reserved = store.reserved(None);
            return Ok(());
        };
        let channel_pub = channel.public_key().to_bytes();
        if registered && store.channel != Some(Hex32(channel_pub)) {
            return Err(AgentError::Other(
                "the channel key is not the one the approver devices were paired with: load \
                 that key, or run `keep gateway approver reset` and pair again"
                    .into(),
            ));
        }
        if self.keep.keyring().get(&channel_pub).is_some() {
            return Err(AgentError::Other(
                "the channel key is a key in the vault; generate one with `keep gateway \
                 channel-key new`"
                    .into(),
            ));
        }
        if relays.is_empty() {
            return Err(AgentError::Other(
                "approvals need at least one relay: pass --approval-relay".into(),
            ));
        }
        for relay in &relays {
            keep_approval::pairing::check_relay(relay)
                .map_err(|e| AgentError::Other(format!("relay {relay:?}: {e}")))?;
        }
        if !keep_approval::binding::DEADLINE_SECS.contains(&deadline_secs) {
            return Err(AgentError::Other(format!(
                "the approval deadline is {} to {} seconds",
                keep_approval::binding::DEADLINE_SECS.start(),
                keep_approval::binding::DEADLINE_SECS.end()
            )));
        }
        let (outbox, receiver) = mpsc::channel(OUTBOX_CAPACITY);
        let mut inbox = Inbox::new(channel.clone());
        inbox.expect(&store.devices, None);
        let inbox = Arc::new(Mutex::new(inbox));
        self.reserved = store.reserved(Some(channel_pub));
        self.approvals = Some(Approvals {
            link: Some(RelayLink {
                outbox: receiver,
                inbox: inbox.clone(),
                relays: relays.clone(),
                channel: channel_pub,
            }),
            channel,
            channel_pub,
            relays,
            deadline_secs,
            store,
            pairing: None,
            parked: HashMap::new(),
            outbox,
            inbox,
            next_anchor: self.clock.now(),
            owed: Vec::new(),
        });
        tracing::info!(
            channel = %hex(&channel_pub),
            approvers = self.approvals.as_ref().map_or(0, |a| a.store.devices.len()),
            "approvals over Nostr are set up"
        );
        Ok(())
    }

    /// What the relay connection needs, taken once by the server.
    pub fn take_relay_link(&mut self) -> Option<RelayLink> {
        self.approvals.as_mut().and_then(|a| a.link.take())
    }

    /// Whether requests that need an approval are sent to approvers: the
    /// channel key is loaded and a device is registered.
    pub fn approvals_active(&self) -> bool {
        self.approvals
            .as_ref()
            .is_some_and(|a| !a.store.devices.is_empty())
    }

    /// Approvals as `status` reports them.
    pub(crate) fn approval_status(&self) -> Value {
        match self.approvals.as_ref() {
            None => json!({ "configured": false }),
            Some(a) => json!({
                "configured": true,
                "channel": hex(&a.channel_pub),
                "approvers": a.store.devices.len(),
                "deadline_secs": a.deadline_secs,
                "relays": a.relays,
                "parked": a.parked.len(),
                "epoch": a.store.epoch,
                "pairing": a.pairing.is_some(),
            }),
        }
    }

    /// Refuse an id no credential has.
    pub(crate) fn load_known(&self, id: &[u8; 16]) -> Result<()> {
        match load_credential(&self.keep, id)? {
            Some(_) => Ok(()),
            None => Err(AgentError::Other(format!(
                "no agent credential {}",
                hex(id)
            ))),
        }
    }

    /// The approval deadline, when approvals are active.
    pub(crate) fn approval_deadline(&self) -> Option<u64> {
        self.approvals_active()
            .then(|| self.approvals.as_ref().map(|a| a.deadline_secs))
            .flatten()
    }

    fn refresh_expected(&mut self) {
        let Some(a) = self.approvals.as_mut() else {
            return;
        };
        let secret = a.pairing.as_ref().map(|p| *p.secret);
        if let Ok(mut inbox) = a.inbox.lock() {
            inbox.expect(&a.store.devices, secret.as_ref());
        }
        self.reserved = a.store.reserved(Some(a.channel_pub));
    }

    /// Wrap `content` of `kind` for the device with transport key `to` and
    /// queue it for the relays.
    fn send_to(&mut self, to: &[u8; 32], kind: u16, content: &str) {
        let now = self.clock.calendar();
        let Some(a) = self.approvals.as_ref() else {
            return;
        };
        let sent = TagKey::for_peer(&a.channel, to)
            .and_then(|tag| wrap::wrap(&a.channel, to, &tag, kind, content, now));
        match sent {
            Ok(event) => {
                if let Err(e) = a.outbox.try_send(event) {
                    tracing::warn!(error = %e, "a message to an approver was dropped: the relay queue is full");
                }
            }
            Err(e) => tracing::error!(error = %e, "a message to an approver could not be wrapped"),
        }
    }

    fn send_all(&mut self, kind: u16, content: &str) {
        let devices: Vec<[u8; 32]> = self
            .approvals
            .as_ref()
            .map(|a| a.store.devices.iter().map(|d| d.transport.0).collect())
            .unwrap_or_default();
        for to in devices {
            self.send_to(&to, kind, content);
        }
    }

    /// The audit log's and the wallet ledgers' anchor, now.
    fn anchor_state(&self) -> Result<AnchorState> {
        let (seq, head) = self.keep.audit_anchor()?;
        let now = self.clock.now();
        let mut wallets = Vec::new();
        for slot in self.keep.keyring().list() {
            for network in LEDGER_NETWORKS {
                let key = wallet_key(&slot.pubkey, network);
                let Some(bytes) = self.keep.load_agent_ledger(&key)? else {
                    continue;
                };
                let ledger: Ledger = decode_ledger(Some(&bytes))?;
                let prefix = if network == keep_bitcoin::Network::Bitcoin {
                    "main"
                } else {
                    "test"
                };
                wallets.push(WalletAnchor {
                    wallet: format!("{prefix}:{}", hex(&slot.pubkey)),
                    seq: ledger.seq(),
                    spent: ledger.spent(now),
                    window: self.settings.wallet_budget_sats,
                });
            }
        }
        wallets.sort_by(|a, b| a.wallet.cmp(&b.wallet));
        Ok(AnchorState {
            seq,
            head: Hex32(head),
            wallets,
        })
    }

    /// What is frozen, and the freeze epoch.
    fn frozen_state(&self) -> Result<Frozen> {
        let mut credentials = Vec::new();
        for id in self.keep.agent_credential_ids()? {
            if let Ok(Some(c)) = load_credential(&self.keep, &id) {
                if c.frozen {
                    credentials.push(Hex16(id));
                }
            }
        }
        credentials.sort();
        Ok(Frozen {
            epoch: self.approvals.as_ref().map_or(0, |a| a.store.epoch),
            all: self.keep.agent_freeze()?,
            credentials,
        })
    }

    /// Send an anchor to `to`, or to every device, and record the audit
    /// log's place in the vault, so the anchor and the vault agree.
    fn send_anchor(&mut self, to: Option<[u8; 32]>) {
        let anchor = match (self.anchor_state(), self.frozen_state()) {
            (Ok(anchor), Ok(frozen)) => Anchor {
                v: V1,
                at: self.clock.calendar(),
                anchor,
                frozen,
            },
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "the anchor cannot be taken");
                return;
            }
        };
        if let Err(e) = self.keep.audit_checkpoint() {
            tracing::warn!(error = %e, "the audit log's place could not be recorded");
        }
        let text = wire::to_text(&anchor);
        match to {
            Some(to) => self.send_to(&to, kind::ANCHOR, &text),
            None => self.send_all(kind::ANCHOR, &text),
        }
    }

    /// Write an owner entry now, or owe it and retry until it is written.
    fn owner_entry(&mut self, event: AuditEventType, reason: String) {
        if let Err(e) = self.keep.record_owner_event(event, &reason) {
            tracing::error!(error = %e, %event, "an approval entry could not be written yet; retrying");
            if let Some(a) = self.approvals.as_mut() {
                a.owed.push((event, reason));
            }
        }
    }

    /// Run the approval timers: expire parked requests and a pairing session
    /// past their time, count freezes an audit budget made, retry owed
    /// entries, and send the anchor every 15 minutes.
    pub fn approval_tick(&mut self) {
        for id in self.audit.take_frozen() {
            self.after_freeze(Scope::Credential(Hex16(id)), "an audit budget");
        }
        let now = self.clock.now();
        let Some(a) = self.approvals.as_mut() else {
            return;
        };
        let expired: Vec<[u8; 32]> = a
            .parked
            .iter()
            .filter(|(_, w)| now >= w.deadline)
            .map(|(id, _)| *id)
            .collect();
        if a.pairing.as_ref().is_some_and(|p| now >= p.expires) {
            if let Some(mut session) = a.pairing.take() {
                if let Some(reply) = session.reply.take() {
                    let _ = reply.send(admin_err("the pairing session expired"));
                }
            }
            self.refresh_expected();
        }
        for id in expired {
            self.end(id, End::Expired);
        }
        let Some(a) = self.approvals.as_mut() else {
            return;
        };
        let owed = std::mem::take(&mut a.owed);
        for (event, reason) in owed {
            self.owner_entry(event, reason);
        }
        let Some(a) = self.approvals.as_mut() else {
            return;
        };
        if !a.store.devices.is_empty() && now >= a.next_anchor {
            a.next_anchor = now.saturating_add(ANCHOR_EVERY_SECS);
            self.send_anchor(None);
        }
    }

    /// Handle a message opened from a wrap.
    pub fn approval_message(&mut self, opened: Opened<Source>) {
        if self.closed {
            return;
        }
        match (opened.from, opened.kind) {
            (Source::Device(transport), kind::DECISION) => {
                self.on_decision(&transport, &opened.content)
            }
            (Source::Device(transport), kind::FREEZE) => {
                self.on_freeze(&transport, &opened.content)
            }
            (Source::Pairing, kind::PAIRING) => self.on_pair(&opened.sender, &opened.content),
            (from, kind) => tracing::debug!(?from, kind, "an approval message nobody takes"),
        }
    }

    fn device(&self, transport: &[u8; 32]) -> Option<StoredDevice> {
        self.approvals
            .as_ref()
            .and_then(|a| a.store.device(transport).cloned())
    }

    // Parking.

    /// Park an agent request for the approvers: build it from exactly what
    /// will be signed, record it, send it to every device, and hand the
    /// connection the reply to wait on.
    pub(super) fn park_agent(
        &mut self,
        granted: &GrantedCredential,
        id: Value,
        tool: &'static str,
        ask: ParkAsk,
        now: u64,
    ) -> std::result::Result<Pending, Refusal> {
        let cid = granted.credential.id;
        let pending_for = |a: &Approvals| {
            a.parked
                .values()
                .any(|w| matches!(w.waiter, Waiter::Agent { credential, .. } if credential == cid))
        };
        let Some(a) = self.approvals.as_ref() else {
            return Err(Refusal::Internal("approvals are not set up".into()));
        };
        if pending_for(a) {
            return Err(Refusal::refused_approval(
                "an approval for this credential is already pending",
            ));
        }
        if a.parked.len() >= MAX_PARKED {
            return Err(Refusal::refused_approval(
                "too many requests are waiting for an approval; try again later",
            ));
        }
        let credential = CredentialRef {
            id: Hex16(cid),
            name: granted.credential.name.clone(),
            uid: granted.credential.uid,
        };
        let info = self
            .park_info(Some(credential), ask.reason, ask.budget)
            .map_err(|e| Refusal::Internal(e.to_string()))?;
        let channel = self
            .approvals
            .as_ref()
            .map(|a| a.channel_pub)
            .unwrap_or_default();
        let parked = Parked::new(ask.object, info, &channel).map_err(|e| match e {
            AgentError::PolicyDenied(m) => Refusal::refused_approval(&m),
            e => Refusal::Internal(e.to_string()),
        })?;
        let detail = format!(
            "request {} hash {} reason {}",
            hex(&parked.request_id()),
            hex(&parked.hash()),
            reason_text(&parked.request().reason)
        );
        self.audit
            .record_approval_requested(&mut self.keep, &cid, tool, &detail, now)
            .map_err(super::withheld)?;
        let (reply, receiver) = oneshot::channel();
        let request_id = parked.request_id();
        self.dispatch(
            parked,
            Waiter::Agent {
                credential: cid,
                id,
                tool,
                reply,
            },
        );
        Ok(Pending {
            request_id: Some(request_id),
            reply: receiver,
        })
    }

    /// The fields of a new request besides its object.
    fn park_info(
        &self,
        credential: Option<CredentialRef>,
        reason: Reason,
        budget: Option<Budget>,
    ) -> Result<ParkRequest> {
        let deadline_secs = self
            .approvals
            .as_ref()
            .map_or(keep_approval::binding::DEFAULT_DEADLINE_SECS, |a| {
                a.deadline_secs
            });
        Ok(ParkRequest {
            request_id: keep_core::entropy::try_random_bytes()
                .map_err(|e| AgentError::Other(e.to_string()))?,
            created_at: self.clock.calendar(),
            deadline_secs,
            credential,
            reason,
            budget,
            anchor: self.anchor_state()?,
        })
    }

    /// Send a parked request to every device and wait for it.
    fn dispatch(&mut self, parked: Parked, waiter: Waiter) {
        let now = self.clock.now();
        let text = wire::to_text(parked.request());
        self.send_all(kind::REQUEST, &text);
        if let Some(a) = self.approvals.as_mut() {
            let deadline = now.saturating_add(a.deadline_secs);
            a.parked.insert(
                parked.request_id(),
                Waiting {
                    parked,
                    deadline,
                    waiter,
                },
            );
        }
    }

    /// Cancel parked request `id` whose waiter went away.
    pub fn cancel_parked(&mut self, id: [u8; 32]) {
        if self
            .approvals
            .as_ref()
            .is_some_and(|a| a.parked.contains_key(&id))
        {
            self.end(id, End::Canceled("canceled: the request was withdrawn"));
        }
    }

    /// Cancel the parked request of credential `cid` whose JSON-RPC id is
    /// `request`, as the agent's `notifications/cancelled` asks.
    pub(crate) fn cancel_agent_request(&mut self, cid: &[u8; 16], request: &Value) {
        let found = self.approvals.as_ref().and_then(|a| {
            a.parked.iter().find_map(|(id, w)| match &w.waiter {
                Waiter::Agent {
                    credential,
                    id: rpc,
                    ..
                } if credential == cid && rpc == request => Some(*id),
                _ => None,
            })
        });
        if let Some(id) = found {
            self.end(id, End::Canceled("canceled: the request was withdrawn"));
        }
    }

    /// Cancel every parked request `covered` matches, saying `why`.
    fn cancel_where(&mut self, why: &'static str, covered: impl Fn(Option<[u8; 16]>) -> bool) {
        let ids: Vec<[u8; 32]> = self
            .approvals
            .as_ref()
            .map(|a| {
                a.parked
                    .iter()
                    .filter(|(_, w)| covered(w.parked.credential()))
                    .map(|(id, _)| *id)
                    .collect()
            })
            .unwrap_or_default();
        for id in ids {
            self.end(id, End::Canceled(why));
        }
    }

    /// Cancel the parked requests of credential `cid`, revoked or deleted.
    pub(crate) fn cancel_revoked(&mut self, cid: &[u8; 16]) {
        self.cancel_where("canceled: revoked", |c| c == Some(*cid));
    }

    /// Cancel every parked request and the pairing session, as the gateway
    /// stops.
    pub(crate) fn cancel_all(&mut self, why: &'static str) {
        self.cancel_where(why, |_| true);
        if let Some(a) = self.approvals.as_mut() {
            if let Some(mut session) = a.pairing.take() {
                if let Some(reply) = session.reply.take() {
                    let _ = reply.send(admin_err(why));
                }
            }
        }
    }

    /// End parked request `id` other than by an approval: record it, tell
    /// every device, and answer whoever waits.
    fn end(&mut self, id: [u8; 32], end: End) {
        let Some(waiting) = self.approvals.as_mut().and_then(|a| a.parked.remove(&id)) else {
            return;
        };
        let deadline = self.approvals.as_ref().map_or(0, |a| a.deadline_secs);
        let (outcome, by, what) = match &end {
            End::Denied { device, sig } => (
                OutcomeKind::Denied,
                Some(device.approver),
                format!(
                    "denied by transport {} approver {} sig {sig}",
                    hex(&device.transport),
                    hex(&device.approver)
                ),
            ),
            End::Expired => (OutcomeKind::Expired, None, "expired".to_string()),
            End::Canceled(why) => (OutcomeKind::Canceled, None, (*why).to_string()),
        };
        self.owner_entry(
            AuditEventType::AgentApprovalDecided,
            format!(
                "request {} hash {} {what}",
                hex(&id),
                hex(&waiting.parked.hash())
            ),
        );
        self.send_outcome(id, outcome, by);
        let message = match &end {
            End::Denied { .. } => "denied by the approver".to_string(),
            End::Expired => format!("no approval within {deadline} seconds"),
            End::Canceled(why) => (*why).to_string(),
        };
        match waiting.waiter {
            Waiter::Agent {
                credential,
                id,
                reply,
                ..
            } => {
                let _ = reply.send(self.reply_agent(id, &message));
                if matches!(end, End::Denied { .. }) {
                    self.note_denial(credential);
                }
            }
            Waiter::Admin { reply, .. } => {
                let _ = reply.send(admin_err(&message));
            }
        }
    }

    fn reply_agent(&self, id: Value, message: &str) -> Zeroizing<String> {
        tool_result(id, &Value::String(message.into()), true)
    }

    fn send_outcome(&mut self, id: [u8; 32], outcome: OutcomeKind, by: Option<[u8; 32]>) {
        let text = wire::to_text(&Outcome {
            v: V1,
            request_id: Hex32(id),
            outcome,
            by: by.map(Hex32),
        });
        self.send_all(kind::OUTCOME, &text);
    }

    /// Count a denial of credential `cid`; three within a day freeze it,
    /// which only an approved unfreeze clears.
    fn note_denial(&mut self, cid: [u8; 16]) {
        let now = self.clock.now();
        let Some(a) = self.approvals.as_mut() else {
            return;
        };
        let freeze = a.store.note_denial(cid, now);
        let saved = a.store.clone().save(&mut self.keep);
        if let Err(e) = saved {
            tracing::error!(error = %e, "a denial could not be recorded");
        }
        if freeze {
            if let Err(e) = self.freeze(Scope::Credential(Hex16(cid)), "three denials in a day") {
                tracing::error!(error = %e, "a credential denied three times could not be frozen");
            }
        }
    }

    // Decisions.

    fn on_decision(&mut self, transport: &[u8; 32], content: &str) {
        let decision: SignedDecision = match wire::parse(content) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "a decision does not parse");
                return;
            }
        };
        let Some(device) = self.device(transport).map(|d| d.device()) else {
            return;
        };
        let now = self.clock.now();
        let id = decision.request_id.0;
        let Some(a) = self.approvals.as_ref() else {
            return;
        };
        let channel = a.channel_pub;
        let Some(waiting) = a.parked.get(&id) else {
            tracing::info!(request = %hex(&id), "a decision for a request that is not parked, ignored");
            return;
        };
        if now >= waiting.deadline {
            return;
        }
        let verdict = match sig::check_decision(
            &decision,
            &channel,
            &device,
            &id,
            &waiting.parked.hash(),
        ) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(request = %hex(&id), error = %e, "a decision did not verify, ignored");
                return;
            }
        };
        match verdict {
            Verdict::Deny => self.end(
                id,
                End::Denied {
                    device,
                    sig: decision.sig.to_hex(),
                },
            ),
            Verdict::Approve => {
                let Some(waiting) = self.approvals.as_mut().and_then(|a| a.parked.remove(&id))
                else {
                    return;
                };
                match Approval::verify(&decision, &channel, &device, waiting.parked) {
                    Ok(approval) => self.approved(approval, waiting.waiter),
                    Err((_, why)) => {
                        tracing::error!(%why, "a verified decision did not verify again")
                    }
                }
            }
        }
    }

    /// Carry out an approval and answer whoever waits; the approval is
    /// recorded and announced as it is carried out.
    fn approved(&mut self, approval: Approval, waiter: Waiter) {
        match waiter {
            Waiter::Agent {
                credential,
                id: rpc,
                tool,
                reply,
            } => {
                let line = self.carry_out_agent(approval, credential, rpc, tool);
                let _ = reply.send(line);
            }
            Waiter::Admin { reply, effect, .. } => {
                let line = self.carry_out_management(approval, effect);
                let _ = reply.send(line);
            }
        }
    }

    fn decided_entry(&mut self, approved: &crate::approval::Approved, what: &str) {
        let d = approved.device();
        self.owner_entry(
            AuditEventType::AgentApprovalDecided,
            format!(
                "request {} hash {} {what} by transport {} approver {} sig {}",
                hex(&approved.parked().request_id()),
                hex(&approved.parked().hash()),
                hex(&d.transport),
                hex(&d.approver),
                approved.signature().to_hex()
            ),
        );
        self.send_outcome(
            approved.parked().request_id(),
            OutcomeKind::Approved,
            Some(d.approver),
        );
    }

    /// Carry out an approved agent request: check its credential again,
    /// evaluate it again with the approval, sign exactly what was parked,
    /// record the signature, and answer.
    fn carry_out_agent(
        &mut self,
        approval: Approval,
        cid: [u8; 16],
        rpc: Value,
        tool: &'static str,
    ) -> Zeroizing<String> {
        let now = self.clock.now();
        let calendar = self.clock.calendar();
        let usable = match load_credential(&self.keep, &cid) {
            Ok(Some(c)) => {
                let all_frozen = self.keep.agent_freeze().unwrap_or(true);
                match c.check_usable(c.uid, calendar, all_frozen) {
                    Ok(()) => {
                        GrantedCredential::new(c, &self.reserved).map_err(|_| "canceled: revoked")
                    }
                    Err(keep_core::agent::AgentRefusal::Frozen) => Err("canceled: frozen"),
                    Err(_) => Err("canceled: revoked"),
                }
            }
            _ => Err("canceled: revoked"),
        };
        let granted = match usable {
            Ok(g) => g,
            Err(why) => {
                self.owner_entry(
                    AuditEventType::AgentApprovalDecided,
                    format!(
                        "request {} hash {} approved but {why}",
                        hex(&approval.parked().request_id()),
                        hex(&approval.parked().hash())
                    ),
                );
                self.send_outcome(approval.parked().request_id(), OutcomeKind::Canceled, None);
                return tool_result(rpc, &Value::String(why.into()), true);
            }
        };
        let served = match approval.parked().object() {
            ParkedObject::NostrEvent(_) => self.approved_event(&granted, approval, now),
            ParkedObject::Psbt { .. } => self.approved_psbt(&granted, approval, now),
            ParkedObject::Management(_) => Err(Refusal::Internal(
                "a management change waited as an agent request".into(),
            )),
        };
        self.answer_tool(&granted, rpc, tool, served, now)
    }

    /// Evaluate and sign an approved event exactly as it was parked.
    fn approved_event(
        &mut self,
        granted: &GrantedCredential,
        approval: Approval,
        now: u64,
    ) -> super::Served {
        let (mut c, mut w) = (Ledger::default(), Ledger::default());
        let mut budgets = Budgets {
            credential: &mut c,
            wallet: &mut w,
            wallet_window_sats: 0,
        };
        let (decision, approved) = evaluate_approved(approval, &granted.grant, &mut budgets, now);
        match decision {
            Decision::Allow => {}
            Decision::Deny(reason) => return Err(Refusal::deny(reason)),
            other => {
                return Err(Refusal::Internal(format!(
                    "an approved event was decided {other:?}"
                )))
            }
        }
        let ParkedObject::NostrEvent(fields) = approved.parked().object() else {
            return Err(Refusal::Internal("not an event".into()));
        };
        let event = self.sign_fields(fields)?;
        let context = format!(
            "sign_nostr_event kind {} id {} approved request {}",
            fields.kind,
            event.id,
            hex(&approved.parked().request_id())
        );
        self.decided_entry(&approved, "approved");
        self.audit
            .record_signature(
                &mut self.keep,
                &granted.credential.id,
                &fields.pubkey.0,
                event.id.as_bytes(),
                &context,
                now,
            )
            .map_err(super::withheld)?;
        serde_json::to_value(&event).map_err(|e| Refusal::Internal(e.to_string()))
    }

    /// Sign `fields` with its key, refusing unless the event is exactly the
    /// one the approver was shown.
    fn sign_fields(
        &self,
        fields: &UnsignedEventFields,
    ) -> std::result::Result<nostr_sdk::prelude::Event, Refusal> {
        use nostr_sdk::prelude::{EventBuilder, Kind, SecretKey, Tag, Timestamp};
        let secret = self.secret(&fields.pubkey.0)?;
        let keys = SecretKey::from_slice(secret.as_slice())
            .map(Keys::new)
            .map_err(|e| Refusal::Internal(format!("vault key: {e}")))?;
        drop(secret);
        let tags = fields
            .tags
            .iter()
            .map(|t| Tag::parse(t.clone()).map_err(|e| Refusal::Internal(e.to_string())))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let event = EventBuilder::new(Kind::from(fields.kind), &fields.content)
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(fields.created_at))
            .sign_with_keys(&keys)
            .map_err(|e| Refusal::Internal(format!("sign: {e}")))?;
        let expected = fields
            .event_id()
            .map_err(|e| Refusal::Internal(e.to_string()))?;
        if event.id.to_bytes() != expected || event.pubkey.to_bytes() != fields.pubkey.0 {
            return Err(Refusal::Internal(
                "the signed event is not the one approved".into(),
            ));
        }
        Ok(event)
    }

    /// Evaluate an approved spend again, reserve it, and sign the PSBT
    /// unchanged.
    fn approved_psbt(
        &mut self,
        granted: &GrantedCredential,
        approval: Approval,
        now: u64,
    ) -> super::Served {
        let ParkedObject::Psbt { key, analysis, .. } = approval.parked().object() else {
            return Err(Refusal::Internal("not a PSBT".into()));
        };
        let key = *key;
        let network = analysis.network;
        let cid = granted.credential.id;
        let wallet = wallet_key(&key, network);
        let wallet_window_sats = self.settings.wallet_budget_sats;
        let mut outcome = None;
        let mut approval = Some(approval);
        self.keep
            .update_agent_ledgers(&[&cid, &wallet], |current| {
                let mut credential = decode_ledger(current[0].as_ref().map(|v| v.as_slice()))?;
                let mut wallet = decode_ledger(current[1].as_ref().map(|v| v.as_slice()))?;
                let mut budgets = Budgets {
                    credential: &mut credential,
                    wallet: &mut wallet,
                    wallet_window_sats,
                };
                if let Some(approval) = approval.take() {
                    outcome = Some(evaluate_approved(
                        approval,
                        &granted.grant,
                        &mut budgets,
                        now,
                    ));
                }
                Ok(vec![
                    super::encode_ledger(&credential)?,
                    super::encode_ledger(&wallet)?,
                ])
            })
            .map_err(|e| Refusal::Internal(format!("the budget ledgers cannot be updated: {e}")))?;
        let Some((decision, approved)) = outcome else {
            return Err(Refusal::Internal("no decision".into()));
        };
        let reservation = match decision {
            Decision::Allow => None,
            Decision::Spend(r) => Some(r),
            Decision::Deny(reason) => return Err(Refusal::deny(reason)),
            Decision::RequireApproval(_) => {
                return Err(Refusal::Internal(
                    "an approved spend asked for an approval again".into(),
                ))
            }
        };
        let ParkedObject::Psbt { psbt, .. } = approved.parked().object() else {
            return Err(Refusal::Internal("not a PSBT".into()));
        };
        let mut psbt = (**psbt).clone();
        let signed = self.sign_psbt_exactly(&key, network, &mut psbt);
        let signed = signed.and_then(|count| {
            let txid = psbt.unsigned_tx.compute_txid();
            let context = format!(
                "sign_bitcoin_psbt txid {txid} inputs {count} approved request {}",
                hex(&approved.parked().request_id())
            );
            self.decided_entry(&approved, "approved");
            self.audit
                .record_signature(&mut self.keep, &cid, &key, txid.as_ref(), &context, now)
                .map_err(super::withheld)?;
            Ok(count)
        });
        match signed {
            Ok(count) => {
                let ParkedObject::Psbt { analysis, .. } = approved.parked().object() else {
                    return Err(Refusal::Internal("not a PSBT".into()));
                };
                Ok(json!({
                    "signed_psbt": keep_bitcoin::psbt::serialize_psbt_base64(&psbt),
                    "inputs_signed": count,
                    "fee_sats": analysis.fee_sats,
                    "leaving_wallet_sats": analysis.leaving_wallet_sats(),
                    "network": network.to_string()
                }))
            }
            Err(refusal) => {
                if let Some(reservation) = reservation {
                    self.release(&cid, &wallet, reservation);
                }
                Err(refusal)
            }
        }
    }

    /// Sign `psbt` with `key`'s wallet on `network`, refusing unless the
    /// inputs signed are those the approver was shown.
    fn sign_psbt_exactly(
        &self,
        key: &[u8; 32],
        network: keep_bitcoin::Network,
        psbt: &mut keep_bitcoin::bitcoin::Psbt,
    ) -> std::result::Result<usize, Refusal> {
        let mut secret = self.secret(key)?;
        let signer = keep_bitcoin::BitcoinSigner::new(&mut secret, network)
            .map_err(|e| Refusal::Internal(e.to_string()))?;
        drop(secret);
        let count = signer
            .sign_psbt(psbt)
            .map_err(|e| Refusal::Internal(format!("sign: {e}")))?;
        if count == 0 {
            return Err(Refusal::Internal(
                "no input of the approved PSBT was signed".into(),
            ));
        }
        Ok(count)
    }

    // Freezes.

    /// Freeze `scope` now, from `source`: the epoch moves first, so an
    /// unfreeze held back from before can never undo this freeze, then the
    /// freeze takes effect, then it is recorded; parked requests it covers
    /// are canceled and every device is shown the new state.
    pub(crate) fn freeze(&mut self, scope: Scope, source: &str) -> Result<()> {
        if let Err(e) = self.bump_epoch(None) {
            tracing::error!(error = %e, "the freeze epoch could not be moved");
        }
        let applied = match scope {
            Scope::All => self.keep.set_agent_freeze(true),
            Scope::Credential(id) => self.keep.set_agent_credential_frozen(&id.0, true),
        };
        if let Err(e) = applied {
            tracing::error!(error = %e, source, "a freeze could not be applied");
            return Err(e.into());
        }
        self.after_freeze(scope, source);
        Ok(())
    }

    /// Clear the freeze of `scope` from the admin socket, with no approver
    /// registered to ask: the epoch still moves.
    pub(crate) fn unfreeze_now(&mut self, scope: Scope) -> Result<()> {
        let epoch = self.approvals.as_ref().map_or(0, |a| a.store.epoch);
        self.unfreeze(scope, epoch, None)?;
        if self.approvals_active() {
            self.send_anchor(None);
        }
        Ok(())
    }

    /// What follows a freeze already applied: parked requests canceled and
    /// the anchor.
    fn after_freeze(&mut self, scope: Scope, source: &str) {
        tracing::warn!(?scope, source, "agents frozen");
        match scope {
            Scope::All => self.cancel_where("canceled: frozen", |_| true),
            Scope::Credential(id) => self.cancel_where("canceled: frozen", |c| c == Some(id.0)),
        }
        if self.approvals_active() {
            self.send_anchor(None);
        }
    }

    /// Move the freeze epoch on, and the counter of the device it came from.
    fn bump_epoch(&mut self, counter: Option<([u8; 32], u64)>) -> Result<u64> {
        let Some(a) = self.approvals.as_mut() else {
            return Ok(0);
        };
        let mut store = a.store.clone();
        store.epoch = store.epoch.saturating_add(1);
        if let Some((transport, counter)) = counter {
            if let Some(d) = store
                .devices
                .iter_mut()
                .find(|d| d.transport.0 == transport)
            {
                d.counter = counter;
            }
        }
        store.save(&mut self.keep)?;
        let epoch = store.epoch;
        if let Some(a) = self.approvals.as_mut() {
            a.store = store;
        }
        Ok(epoch)
    }

    /// Clear the freeze of `scope` if `epoch` is still current: the epoch
    /// moves first, then the freeze is cleared, which needs its entry
    /// written.
    fn unfreeze(
        &mut self,
        scope: Scope,
        epoch: u64,
        counter: Option<([u8; 32], u64)>,
    ) -> Result<()> {
        let current = self.approvals.as_ref().map_or(0, |a| a.store.epoch);
        if epoch != current {
            return Err(AgentError::Other(format!(
                "the freeze epoch moved from {epoch} to {current}: something froze or unfroze since"
            )));
        }
        self.bump_epoch(counter)?;
        match scope {
            Scope::All => self.keep.set_agent_freeze(false)?,
            Scope::Credential(id) => {
                self.keep.set_agent_credential_frozen(&id.0, false)?;
                self.audit.reset(&id.0);
                if let Some(a) = self.approvals.as_mut() {
                    a.store.denials.remove(&id);
                }
            }
        }
        Ok(())
    }

    fn on_freeze(&mut self, transport: &[u8; 32], content: &str) {
        let freeze: Freeze = match wire::parse(content) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "a freeze does not parse");
                return;
            }
        };
        let Some(stored) = self.device(transport) else {
            return;
        };
        let device = stored.device();
        let Some(channel) = self.approvals.as_ref().map(|a| a.channel_pub) else {
            return;
        };
        if let Err(e) = sig::check_freeze(&freeze, &channel, &device) {
            tracing::warn!(error = %e, "a freeze did not verify, ignored");
            return;
        }
        // A replayed or reordered message, or one for a credential that does
        // not exist, is refused with the current state.
        let known = match freeze.scope {
            Scope::All => true,
            Scope::Credential(id) => matches!(load_credential(&self.keep, &id.0), Ok(Some(_))),
        };
        if freeze.counter <= stored.counter || !known {
            tracing::info!(
                counter = freeze.counter,
                "a freeze or unfreeze refused: old counter or unknown credential"
            );
            self.send_anchor(Some(*transport));
            return;
        }
        let what = match freeze.action {
            FreezeAction::Freeze => "freeze",
            FreezeAction::Unfreeze => "unfreeze",
        };
        let entry = format!(
            "{what} {} from transport {} signed by {} counter {} epoch {} sig {}",
            scope_text(&freeze.scope),
            hex(transport),
            freeze.signer.to_hex(),
            freeze.counter,
            freeze.epoch,
            freeze.sig.to_hex()
        );
        match freeze.action {
            FreezeAction::Freeze => {
                if let Err(e) = self.bump_epoch(Some((*transport, freeze.counter))) {
                    tracing::error!(error = %e, "the freeze epoch could not be moved");
                }
                let applied = match freeze.scope {
                    Scope::All => self.keep.set_agent_freeze(true),
                    Scope::Credential(id) => self.keep.set_agent_credential_frozen(&id.0, true),
                };
                if let Err(e) = applied {
                    tracing::error!(error = %e, "a freeze from an approver could not be applied");
                    self.send_anchor(Some(*transport));
                    return;
                }
                self.owner_entry(AuditEventType::AgentApproverFreeze, entry);
                self.after_freeze(freeze.scope, "an approver device");
            }
            FreezeAction::Unfreeze => {
                match self.unfreeze(
                    freeze.scope,
                    freeze.epoch,
                    Some((*transport, freeze.counter)),
                ) {
                    Ok(()) => {
                        self.owner_entry(AuditEventType::AgentApproverFreeze, entry);
                        self.send_anchor(None);
                    }
                    Err(e) => {
                        tracing::info!(error = %e, "an unfreeze from an approver refused");
                        self.send_anchor(Some(*transport));
                    }
                }
            }
        }
    }

    // Pairing.

    /// Open a pairing session for a device labeled `label`, for the admin
    /// connection `conn` of `uid`: root for the first device, root or the
    /// admin uid for a later one, which an existing device must then
    /// approve. Answers with the pairing URI, then, once the phone's keys
    /// arrive, with their fingerprint.
    pub(crate) fn pair(
        &mut self,
        uid: u32,
        conn: u64,
        label: &str,
    ) -> (Zeroizing<String>, Option<Pending>) {
        let now = self.clock.now();
        let Some(a) = self.approvals.as_ref() else {
            return (
                admin_err(
                    "approvals are not set up: load the channel-key credential and name the relays",
                ),
                None,
            );
        };
        if a.store.devices.is_empty() && uid != 0 {
            return (
                admin_err("only root may pair the first approver device"),
                None,
            );
        }
        if let Err(e) = keep_approval::change::check_label(label, "label") {
            return (admin_err(&e.to_string()), None);
        }
        if a.pairing.as_ref().is_some_and(|p| now < p.expires) {
            return (admin_err("a pairing session is already open"), None);
        }
        let secret = match keep_core::entropy::try_random_bytes::<32>() {
            Ok(s) => Zeroizing::new(s),
            Err(e) => return (admin_err(&e.to_string()), None),
        };
        let uri = PairingUri {
            gateway: a.channel_pub,
            secret: secret.clone(),
            relays: a.relays.clone(),
        }
        .to_uri();
        let uri = match uri {
            Ok(u) => u,
            Err(e) => return (admin_err(&e.to_string()), None),
        };
        let (reply, receiver) = oneshot::channel();
        if let Some(a) = self.approvals.as_mut() {
            a.pairing = Some(PairingSession {
                secret,
                label: label.to_string(),
                conn,
                expires: now.saturating_add(PAIRING_SECS),
                state: PairState::Waiting,
                reply: Some(reply),
            });
        }
        self.refresh_expected();
        (
            admin_ok(json!({ "uri": uri, "expires_in": PAIRING_SECS })),
            Some(Pending {
                request_id: None,
                reply: receiver,
            }),
        )
    }

    /// The registration rules: two different keys, neither the channel key,
    /// a key in the vault, or a registered device's key.
    fn registrable(&self, device: &Device) -> std::result::Result<(), &'static str> {
        let Some(a) = self.approvals.as_ref() else {
            return Err("approvals are not set up");
        };
        let keys = [device.transport, device.approver];
        if device.transport == device.approver {
            return Err("the device's two keys are the same");
        }
        if keys.contains(&a.channel_pub) {
            return Err("a device key is the channel key");
        }
        if keys.iter().any(|k| self.keep.keyring().get(k).is_some()) {
            return Err("a device key is a key in the vault");
        }
        if a.store
            .devices
            .iter()
            .any(|d| keys.contains(&d.transport.0) || keys.contains(&d.approver.0))
        {
            return Err("a device key is already registered");
        }
        Ok(())
    }

    fn on_pair(&mut self, transport: &[u8; 32], content: &str) {
        let now = self.clock.now();
        let Some(a) = self.approvals.as_mut() else {
            return;
        };
        let Some(session) = a.pairing.as_mut() else {
            return;
        };
        if now >= session.expires || !matches!(session.state, PairState::Waiting) {
            return;
        }
        // The first `pair` uses the session up, whatever it holds, so a
        // racer who saw the code shows up on the host and the real phone is
        // refused.
        let channel = a.channel_pub;
        let secret = *session.secret;
        let checked = match wire::parse::<Pairing>(content) {
            Ok(Pairing::Pair {
                label,
                approver,
                proof,
                approver_sig,
                ..
            }) => sig::check_pair(
                &channel,
                &secret,
                transport,
                &approver,
                &proof,
                &approver_sig,
            )
            .map_err(|e| e.to_string())
            .and_then(|device| {
                keep_approval::change::check_label(&label, "label")
                    .map(|()| (device, label))
                    .map_err(|e| e.to_string())
            }),
            Ok(_) => Err("not a pair message".to_string()),
            Err(e) => Err(e.to_string()),
        };
        let checked = checked.and_then(|(device, label)| {
            self.registrable(&device)
                .map(|()| (device, label))
                .map_err(str::to_string)
        });
        let Some(session) = self.approvals.as_mut().and_then(|a| a.pairing.as_mut()) else {
            return;
        };
        let reply = session.reply.take();
        match checked {
            Ok((device, phone_label)) => {
                let fingerprint = sig::fingerprint(&device.transport, &device.approver);
                session.state = PairState::Confirming { device };
                if let Some(reply) = reply {
                    let _ = reply.send(line(&json!({
                        "ok": true,
                        "result": {
                            "fingerprint": fingerprint,
                            "phone_label": phone_label,
                            "transport": hex(&device.transport),
                            "approver": hex(&device.approver),
                        }
                    })));
                }
            }
            Err(why) => {
                self.approvals.as_mut().map(|a| a.pairing.take());
                self.refresh_expected();
                self.refuse_pair(transport, &why);
                if let Some(reply) = reply {
                    let _ = reply.send(admin_err(&format!("pairing refused: {why}")));
                }
            }
        }
    }

    fn refuse_pair(&mut self, transport: &[u8; 32], why: &str) {
        let text = wire::to_text(&Pairing::Refused {
            v: V1,
            reason: why.to_string(),
        });
        // Not a registered device: tagged with the channel key and the
        // phone's transport key, as `paired` is.
        self.send_to(transport, kind::PAIRING, &text);
    }

    /// The operator confirmed the fingerprint on admin connection `conn`:
    /// register the first device now, or ask an existing device to approve
    /// a later one.
    pub(crate) fn confirm_pair(
        &mut self,
        conn: u64,
        confirmed: bool,
    ) -> (Zeroizing<String>, Option<Pending>) {
        let Some(a) = self.approvals.as_mut() else {
            return (admin_err("approvals are not set up"), None);
        };
        let Some(session) = a.pairing.take_if(|s| s.conn == conn) else {
            return (
                admin_err("no pairing session is waiting on this connection"),
                None,
            );
        };
        self.refresh_expected();
        let PairState::Confirming { device } = session.state else {
            return (admin_err("the phone has not paired yet"), None);
        };
        if !confirmed {
            self.refuse_pair(&device.transport, "the operator rejected the fingerprint");
            return (admin_ok(json!({ "rejected": true })), None);
        }
        if let Err(why) = self.registrable(&device) {
            self.refuse_pair(&device.transport, why);
            return (admin_err(why), None);
        }
        let first = self
            .approvals
            .as_ref()
            .is_some_and(|a| a.store.devices.is_empty());
        if first {
            return match self.register(device, &session.label) {
                Ok(fingerprint) => (admin_ok(json!({ "registered": fingerprint })), None),
                Err(e) => {
                    self.refuse_pair(
                        &device.transport,
                        "the gateway could not register the device",
                    );
                    (admin_err(&e.to_string()), None)
                }
            };
        }
        let change = Change::AddApprover {
            transport: Hex32(device.transport),
            approver: Hex32(device.approver),
            label: session.label.clone(),
            fingerprint: sig::fingerprint(&device.transport, &device.approver),
        };
        self.park_management(conn, change, Effect::AddApprover)
    }

    /// Register `device` labeled `label`, record it, and tell it so.
    fn register(&mut self, device: Device, label: &str) -> Result<String> {
        let Some(a) = self.approvals.as_ref() else {
            return Err(AgentError::Other("approvals are not set up".into()));
        };
        let mut store = a.store.clone();
        store.channel = Some(Hex32(a.channel_pub));
        store.devices.push(StoredDevice {
            transport: Hex32(device.transport),
            approver: Hex32(device.approver),
            label: label.to_string(),
            counter: 0,
        });
        let fingerprint = sig::fingerprint(&device.transport, &device.approver);
        self.keep.record_owner_event(
            AuditEventType::AgentApproverAdded,
            &format!(
                "label \"{label}\" transport {} approver {} fingerprint {fingerprint}",
                hex(&device.transport),
                hex(&device.approver)
            ),
        )?;
        store.save(&mut self.keep)?;
        if let Some(a) = self.approvals.as_mut() {
            a.store = store;
            a.next_anchor = 0;
        }
        self.refresh_expected();
        let paired = match (self.anchor_state(), self.frozen_state()) {
            (Ok(anchor), Ok(frozen)) => Pairing::Paired {
                v: V1,
                transport: Hex32(device.transport),
                approver: Hex32(device.approver),
                relays: self
                    .approvals
                    .as_ref()
                    .map(|a| a.relays.clone())
                    .unwrap_or_default(),
                deadline_secs: self.approvals.as_ref().map_or(0, |a| a.deadline_secs),
                anchor,
                frozen,
            },
            (Err(e), _) | (_, Err(e)) => return Err(e),
        };
        self.send_to(&device.transport, kind::PAIRING, &wire::to_text(&paired));
        tracing::info!(%fingerprint, "approver device registered");
        Ok(fingerprint)
    }

    /// Remove `device`, record it, and stop expecting its messages.
    fn unregister(&mut self, transport: &[u8; 32]) -> Result<()> {
        let Some(a) = self.approvals.as_ref() else {
            return Err(AgentError::Other("approvals are not set up".into()));
        };
        let mut store = a.store.clone();
        let Some(i) = store
            .devices
            .iter()
            .position(|d| d.transport.0 == *transport)
        else {
            return Err(AgentError::Other("no such approver device".into()));
        };
        let removed = store.devices.remove(i);
        if store.devices.is_empty() {
            store.channel = None;
        }
        self.keep.record_owner_event(
            AuditEventType::AgentApproverRemoved,
            &format!(
                "label \"{}\" transport {} approver {}",
                removed.label,
                removed.transport.to_hex(),
                removed.approver.to_hex()
            ),
        )?;
        store.save(&mut self.keep)?;
        if let Some(a) = self.approvals.as_mut() {
            a.store = store;
        }
        self.refresh_expected();
        if !self.approvals_active() {
            // No approver is left to answer.
            self.cancel_all("canceled: no approver device is registered");
        }
        Ok(())
    }

    /// The registered devices.
    pub(crate) fn approvers(&self) -> Value {
        let devices = self
            .approvals
            .as_ref()
            .map(|a| a.store.devices.clone())
            .or_else(|| Store::load(&self.keep).ok().map(|s| s.devices))
            .unwrap_or_default();
        Value::Array(
            devices
                .iter()
                .map(|d| {
                    json!({
                        "label": d.label,
                        "fingerprint": d.fingerprint(),
                        "transport": d.transport.to_hex(),
                        "approver": d.approver.to_hex(),
                    })
                })
                .collect(),
        )
    }

    /// Remove every approver device: root only, recorded, and the channel
    /// key forgotten, so the next start may use another.
    pub(crate) fn reset_approvers(&mut self) -> Result<Value> {
        let removed = reset_store(&mut self.keep)?;
        if let Some(a) = self.approvals.as_mut() {
            a.store = Store::load(&self.keep)?;
        }
        self.refresh_expected();
        self.cancel_all("canceled: the approver devices were reset");
        Ok(json!({ "removed": removed }))
    }

    // Management.

    /// Whether changes that give agents more power wait for an approver.
    pub(crate) fn management_needs_approval(&self) -> bool {
        self.approvals_active()
    }

    /// Ask the approvers for `change`, for admin connection `conn`.
    fn park_management(
        &mut self,
        conn: u64,
        change: Change,
        effect: Effect,
    ) -> (Zeroizing<String>, Option<Pending>) {
        let Some(a) = self.approvals.as_ref() else {
            return (admin_err("approvals are not set up"), None);
        };
        if a.parked.len() >= MAX_PARKED {
            return (
                admin_err("too many requests are waiting for an approval"),
                None,
            );
        }
        let channel = a.channel_pub;
        let credential = match &change {
            Change::IssueCredential { id, name, uid, .. } => Some(CredentialRef {
                id: *id,
                name: name.clone(),
                uid: u32::try_from(uid.0).unwrap_or(u32::MAX),
            }),
            Change::Unfreeze {
                scope: Scope::Credential(id),
                ..
            } => match load_credential(&self.keep, &id.0) {
                Ok(Some(c)) => Some(CredentialRef {
                    id: *id,
                    name: c.name,
                    uid: c.uid,
                }),
                _ => return (admin_err("no such credential"), None),
            },
            _ => None,
        };
        let info = match self.park_info(credential, Reason::Management, None) {
            Ok(i) => i,
            Err(e) => return (admin_err(&e.to_string()), None),
        };
        let parked = match Parked::new(ParkedObject::Management(change), info, &channel) {
            Ok(p) => p,
            Err(e) => return (admin_err(&e.to_string()), None),
        };
        if let Err(e) = self.keep.record_owner_event(
            AuditEventType::AgentApprovalRequested,
            &format!(
                "management request {} hash {}",
                hex(&parked.request_id()),
                hex(&parked.hash())
            ),
        ) {
            return (admin_err(&e.to_string()), None);
        }
        let request_id = parked.request_id();
        let (reply, receiver) = oneshot::channel();
        self.dispatch(
            parked,
            Waiter::Admin {
                conn,
                reply,
                effect,
            },
        );
        (
            line(&json!({ "ok": true, "pending": hex(&request_id) })),
            Some(Pending {
                request_id: Some(request_id),
                reply: receiver,
            }),
        )
    }

    /// Ask the approvers to issue a credential. Its id and times are fixed
    /// now, so the approved change is exactly what is issued.
    pub(crate) fn park_issue(
        &mut self,
        conn: u64,
        name: &str,
        uid: u32,
        grant: Grant,
        ttl: u64,
    ) -> (Zeroizing<String>, Option<Pending>) {
        let now = self.clock.calendar();
        let id: [u8; 16] = match keep_core::entropy::try_random_bytes() {
            Ok(id) => id,
            Err(e) => return (admin_err(&e.to_string()), None),
        };
        // Everything issuing checks, before an approver is asked.
        if let Err(e) = keep_core::agent::AgentCredential::issue_with_id(
            id,
            name,
            uid,
            serde_json::to_vec(&grant).unwrap_or_default(),
            now,
            ttl,
        ) {
            return (admin_err(&e.to_string()), None);
        }
        let change = Change::IssueCredential {
            id: Hex16(id),
            name: name.to_string(),
            uid: Decimal(u64::from(uid)),
            created_at: Decimal(now),
            expires_at: Decimal(now.saturating_add(ttl)),
            grant: crate::gateway::daemon::approvals::change_grant(&grant),
        };
        self.park_management(conn, change, Effect::Issue { grant })
    }

    /// Ask the approvers to unfreeze `scope` at the current epoch.
    pub(crate) fn park_unfreeze(
        &mut self,
        conn: u64,
        scope: Scope,
    ) -> (Zeroizing<String>, Option<Pending>) {
        let epoch = self.approvals.as_ref().map_or(0, |a| a.store.epoch);
        let change = Change::Unfreeze {
            scope,
            epoch: Decimal(epoch),
        };
        self.park_management(conn, change, Effect::Unfreeze)
    }

    /// Ask the approvers to remove the device with transport key `transport`.
    pub(crate) fn park_remove(
        &mut self,
        conn: u64,
        transport: &[u8; 32],
    ) -> (Zeroizing<String>, Option<Pending>) {
        let Some(d) = self.device(transport) else {
            return (admin_err("no such approver device"), None);
        };
        let change = Change::RemoveApprover {
            transport: d.transport,
            approver: d.approver,
        };
        self.park_management(conn, change, Effect::RemoveApprover)
    }

    /// Carry out an approved management change and answer the admin.
    fn carry_out_management(&mut self, approval: Approval, effect: Effect) -> Zeroizing<String> {
        let approved = match approval.into_management() {
            Ok(a) => a,
            Err(_) => return admin_err("an agent request waited as a management change"),
        };
        let ParkedObject::Management(change) = approved.parked().object() else {
            return admin_err("not a management change");
        };
        let change = change.clone();
        self.decided_entry(&approved, "approved");
        let done: Result<Zeroizing<String>> = match (change, effect) {
            (
                Change::IssueCredential {
                    id,
                    name,
                    uid,
                    created_at,
                    expires_at,
                    ..
                },
                Effect::Issue { grant },
            ) => self.issue_approved(
                id.0,
                &name,
                uid.0 as u32,
                grant,
                created_at.0,
                expires_at.0.saturating_sub(created_at.0),
            ),
            (Change::Unfreeze { scope, epoch }, Effect::Unfreeze) => {
                self.unfreeze(scope, epoch.0, None).map(|()| {
                    self.send_anchor(None);
                    admin_ok(json!({ "unfrozen": scope_text(&scope) }))
                })
            }
            (
                Change::AddApprover {
                    transport,
                    approver,
                    label,
                    ..
                },
                Effect::AddApprover,
            ) => {
                let device = Device {
                    transport: transport.0,
                    approver: approver.0,
                };
                match self.registrable(&device) {
                    Ok(()) => self
                        .register(device, &label)
                        .map(|f| admin_ok(json!({ "registered": f }))),
                    Err(why) => Err(AgentError::Other(why.into())),
                }
            }
            (Change::RemoveApprover { transport, .. }, Effect::RemoveApprover) => self
                .unregister(&transport.0)
                .map(|()| admin_ok(json!({ "removed": transport.to_hex() }))),
            _ => Err(AgentError::Other(
                "the approved change does not match the request".into(),
            )),
        };
        done.unwrap_or_else(|e| admin_err(&e.to_string()))
    }

    /// Cancel what admin connection `conn` was waiting for, once it is gone:
    /// an `issue_credential` is never approved with nobody to receive the
    /// token.
    pub fn admin_gone(&mut self, conn: u64) {
        let ids: Vec<[u8; 32]> = self
            .approvals
            .as_ref()
            .map(|a| {
                a.parked
                    .iter()
                    .filter(|(_, w)| matches!(w.waiter, Waiter::Admin { conn: c, .. } if c == conn))
                    .map(|(id, _)| *id)
                    .collect()
            })
            .unwrap_or_default();
        for id in ids {
            self.end(id, End::Canceled("canceled: the admin command went away"));
        }
        let gone = self
            .approvals
            .as_mut()
            .and_then(|a| a.pairing.take_if(|s| s.conn == conn));
        if gone.is_some() {
            self.refresh_expected();
        }
    }
}

/// Remove every approver device from the vault's store and record each:
/// what `keep gateway approver reset` does, with the gateway running or not.
/// Returns how many were removed.
pub fn reset_store(keep: &mut keep_core::Keep) -> Result<usize> {
    let mut store = Store::load(keep)?;
    let removed = std::mem::take(&mut store.devices);
    for d in &removed {
        keep.record_owner_event(
            AuditEventType::AgentApproverRemoved,
            &format!(
                "reset: label \"{}\" transport {} approver {}",
                d.label,
                d.transport.to_hex(),
                d.approver.to_hex()
            ),
        )?;
    }
    store.channel = None;
    store.save(keep)?;
    Ok(removed.len())
}

fn scope_text(scope: &Scope) -> String {
    match scope {
        Scope::All => "all".into(),
        Scope::Credential(id) => format!("credential {}", id.to_hex()),
    }
}

fn reason_text(reason: &Reason) -> String {
    match reason {
        Reason::Kind { kind } => format!("kind {kind}"),
        Reason::EncryptToOwnKey => "encrypt_to_own_key".into(),
        Reason::DecryptOwnPayload => "decrypt_own_payload".into(),
        Reason::AboveThreshold {
            requested,
            spent,
            threshold,
        } => format!("above_threshold requested {requested} spent {spent} threshold {threshold}"),
        Reason::Management => "management".into(),
    }
}

/// The wire reason for an approval reason the policy gave.
pub(crate) fn wire_reason(reason: &ApprovalReason) -> Reason {
    match *reason {
        ApprovalReason::Kind(kind) => Reason::Kind { kind },
        ApprovalReason::EncryptToOwnKey => Reason::EncryptToOwnKey,
        ApprovalReason::DecryptOwnPayload => Reason::DecryptOwnPayload,
        ApprovalReason::AboveThreshold {
            requested,
            spent,
            threshold,
        } => Reason::AboveThreshold {
            requested,
            spent,
            threshold,
        },
    }
}
