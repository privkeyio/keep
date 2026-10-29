// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Approvals over Nostr, end to end through the gateway's state: an
//! in-process phone with its transport and approver keys pairs, receives
//! requests, decides, freezes and unfreezes, with every message a real gift
//! wrap passed through the gateway's outbox and inbox as the relay helper
//! would carry it.

use keep_approval::binding::check_request;
use keep_approval::change::Scope;
use keep_approval::messages::{
    self as wire, Anchor, Freeze, FreezeAction, Outcome, OutcomeKind, Pairing, Request, SignerKey,
    Verdict, V1,
};
use keep_approval::pairing::{CertChain, PairingUri};
use keep_approval::sig::{self, ApproverSigningKey};
use keep_approval::test_attestation;
use keep_approval::wrap::{self, Candidate, SeenWraps, TagKey};
use keep_approval::{kind, Hex16, Hex32, Hex33, Hex64};
use keep_core::audit::AuditEventType;
use nostr_sdk::prelude::{Event, Keys, SecretKey};
use serde_json::{json, Value};

use super::approvals::{RelayLink, Store, MANAGEMENT_RESERVED, MAX_PARKED};
use super::state::Pending;
use super::tests::{bitcoin_grant, nostr_grant, psbt, Gw, AGENT, OTHER, T0};
use crate::policy::Grant;

pub(super) const RELAY: &str = "wss://relay.example.com";

pub(super) fn channel() -> Keys {
    Keys::new(SecretKey::from_slice(&[0x42; 32]).unwrap())
}

/// An approver phone: its two keys, what it has opened, and its counter.
pub(super) struct Phone {
    pub(super) transport: Keys,
    pub(super) approver: ApproverSigningKey,
    pub(super) channel: [u8; 32],
    seen: SeenWraps,
    counter: u64,
}

/// A fresh P-256 approver key.
pub(super) fn approver_key() -> ApproverSigningKey {
    loop {
        if let Ok(key) = ApproverSigningKey::from_slice(&rand::random::<[u8; 32]>()) {
            return key;
        }
    }
}

/// The key a freeze or unfreeze is signed with in a test.
pub(super) enum Signer {
    Transport(Keys),
    Approver(ApproverSigningKey),
}

impl Phone {
    pub(super) fn new() -> Self {
        Self {
            transport: Keys::generate(),
            approver: approver_key(),
            channel: channel().public_key().to_bytes(),
            seen: SeenWraps::default(),
            counter: 0,
        }
    }

    pub(super) fn t(&self) -> [u8; 32] {
        sig::xonly(&self.transport)
    }

    pub(super) fn a(&self) -> [u8; 33] {
        sig::approver_key(&self.approver)
    }

    /// A wrap of `content` to the gateway, sealed by the transport key and
    /// tagged for the channel key.
    pub(super) fn wrap(&self, kind: u16, content: &str, now: u64) -> Event {
        let tag = TagKey::device(&self.transport, &self.channel).unwrap();
        wrap::wrap(&self.transport, &self.channel, &tag, kind, content, now).unwrap()
    }

    /// What the gateway sent this phone, opened, in order.
    pub(super) fn open(&mut self, events: &[Event], now: u64) -> Vec<(u16, String)> {
        let candidates = [Candidate::Peer {
            id: (),
            tag_key: TagKey::device(&self.transport, &self.channel).unwrap(),
            sender: self.channel,
        }];
        events
            .iter()
            .filter_map(|e| wrap::open(&self.transport, e, &candidates, &mut self.seen, now).ok())
            .map(|o| (o.kind, o.content.to_string()))
            .collect()
    }

    /// A pairing wrap of `message` for the session with `secret`.
    pub(super) fn pairing_wrap(&self, secret: &[u8; 32], message: &Pairing, now: u64) -> Event {
        self.pairing_wrap_text(secret, &wire::to_text(message), now)
    }

    /// A pairing wrap of `text` for the session with `secret`.
    pub(super) fn pairing_wrap_text(&self, secret: &[u8; 32], text: &str, now: u64) -> Event {
        let tag = TagKey::pairing_phone(secret);
        wrap::wrap(
            &self.transport,
            &self.channel,
            &tag,
            kind::PAIRING,
            text,
            now,
        )
        .unwrap()
    }

    /// The `pair` message for a pairing session with `secret`.
    pub(super) fn pair(&self, secret: &[u8; 32], now: u64) -> Event {
        let message = sig::pair(
            &self.t(),
            &self.approver,
            &self.channel,
            secret,
            "My phone",
            self.attestation(secret),
        );
        self.pairing_wrap(secret, &message, now)
    }

    /// The approver key's attestation for the pairing session with
    /// `secret`, under the test root.
    pub(super) fn attestation(&self, secret: &[u8; 32]) -> keep_approval::pairing::CertChain {
        keep_approval::test_attestation::chain(
            &self.a(),
            &sig::pair_attestation_challenge(secret, &self.channel),
        )
    }

    /// A decision on `request`, signed by `signer`.
    pub(super) fn decide_as(
        &self,
        signer: &ApproverSigningKey,
        request: &Request,
        verdict: Verdict,
    ) -> String {
        wire::to_text(&sig::decision(
            signer,
            &self.channel,
            request.request_id,
            request.request_hash,
            verdict,
        ))
    }

    pub(super) fn decide(&self, request: &Request, verdict: Verdict) -> String {
        self.decide_as(&self.approver, request, verdict)
    }

    /// A freeze or unfreeze with the next counter, signed by `signer`,
    /// whichever action it is.
    pub(super) fn freeze_as(
        &mut self,
        signer: &Signer,
        action: FreezeAction,
        scope: Scope,
        epoch: u64,
    ) -> String {
        self.counter += 1;
        self.freeze_with_counter(signer, action, scope, epoch, self.counter)
    }

    /// A freeze or unfreeze with `counter`, signed by `signer`.
    pub(super) fn freeze_with_counter(
        &self,
        signer: &Signer,
        action: FreezeAction,
        scope: Scope,
        epoch: u64,
        counter: u64,
    ) -> String {
        let key = match signer {
            Signer::Transport(k) => SignerKey::Transport(Hex32(sig::xonly(k))),
            Signer::Approver(k) => SignerKey::Approver(Hex33(sig::approver_key(k))),
        };
        let digest = sig::freeze_digest(&self.channel, &key, counter, epoch, action, scope);
        let sig = match signer {
            Signer::Transport(k) => sig::sign_bip340(k, &digest),
            Signer::Approver(k) => sig::sign_p256(k, &digest),
        };
        wire::to_text(&Freeze {
            v: V1,
            action,
            scope,
            counter,
            epoch,
            signer: key,
            sig,
        })
    }

    pub(super) fn freeze(&mut self, scope: Scope, epoch: u64) -> String {
        let t = Signer::Transport(self.transport.clone());
        self.freeze_as(&t, FreezeAction::Freeze, scope, epoch)
    }

    pub(super) fn unfreeze(&mut self, scope: Scope, epoch: u64) -> String {
        let a = Signer::Approver(self.approver.clone());
        self.freeze_as(&a, FreezeAction::Unfreeze, scope, epoch)
    }
}

/// A gateway with approvals set up, and the link a relay helper would use.
struct Ap {
    gw: Gw,
    link: RelayLink,
    next_conn: u64,
}

impl Ap {
    fn new() -> Self {
        let mut gw = Gw::new();
        gw.state
            .configure_approvals(Some(channel()), vec![RELAY.into()], 120)
            .unwrap();
        let link = gw.state.take_relay_link().unwrap();
        Self {
            gw,
            link,
            next_conn: 1,
        }
    }

    fn now(&self) -> u64 {
        self.gw.state.calendar()
    }

    /// Every wrap the gateway queued since the last call.
    fn sent(&mut self) -> Vec<Event> {
        let mut events = Vec::new();
        while let Some(e) = self.link.outbox.try_pop() {
            events.push(e);
        }
        events
    }

    /// Deliver a wrap as the relay helper would: opened outside the state
    /// lock, handled under it. Whether it opened.
    fn deliver(&mut self, event: &Event) -> bool {
        let now = self.now();
        let opened = self.link.inbox.lock().unwrap().open(event, now);
        match opened {
            Some(o) => {
                self.gw.state.approval_message(o);
                true
            }
            None => false,
        }
    }

    fn deliver_from(&mut self, phone: &Phone, kind: u16, content: &str) -> bool {
        let event = phone.wrap(kind, content, self.now());
        self.deliver(&event)
    }

    /// What `phone` received since the last call.
    fn received(&mut self, phone: &mut Phone) -> Vec<(u16, String)> {
        let now = self.now();
        let events = self.sent();
        phone.open(&events, now)
    }

    fn admin_from(&mut self, uid: u32, conn: u64, request: Value) -> (Value, Option<Pending>) {
        let (line, pending) =
            self.gw
                .state
                .admin_request_from(uid, conn, request.to_string().as_bytes());
        (serde_json::from_str(&line).unwrap(), pending)
    }

    fn conn(&mut self) -> u64 {
        self.next_conn += 1;
        self.next_conn
    }

    /// Pair `phone` as root: the first device is registered on confirm.
    fn pair_first(&mut self, phone: &mut Phone) {
        let conn = self.conn();
        let (answer, pending) =
            self.admin_from(0, conn, json!({ "op": "approver_pair", "label": "Phone" }));
        assert_eq!(answer["ok"], json!(true), "{answer}");
        let uri = PairingUri::parse(answer["result"]["uri"].as_str().unwrap()).unwrap();
        assert_eq!(uri.gateway, phone.channel);
        assert_eq!(uri.relays, [RELAY]);
        let event = phone.pair(&uri.secret, self.now());
        assert!(self.deliver(&event));
        let shown = reply(pending.unwrap());
        assert_eq!(
            shown["result"]["fingerprint"],
            json!(sig::fingerprint(&phone.t(), &phone.a()))
        );
        let (answer, _) = self.admin_from(0, conn, json!({ "op": "approver_confirm" }));
        assert_eq!(answer["ok"], json!(true), "{answer}");
        let got = self.received(phone);
        let paired = got.iter().find(|(k, _)| *k == kind::PAIRING).unwrap();
        assert!(matches!(
            wire::parse::<Pairing>(&paired.1).unwrap(),
            Pairing::Paired { transport, .. } if transport.0 == phone.t()
        ));
    }

    /// Issue a credential directly (no approver registered yet) with `grant`.
    fn issue(&mut self, grant: &Grant) -> (String, String) {
        self.gw.issue(grant, AGENT)
    }

    /// Ask for a tool call by `token`, which parks; the pending reply.
    fn park(&mut self, token: &str, rpc: u64, tool: &str, args: Value) -> Pending {
        let line = json!({
            "token": token,
            "message": {
                "jsonrpc": "2.0", "id": rpc, "method": "tools/call",
                "params": { "name": tool, "arguments": args }
            }
        })
        .to_string();
        let answer = self.gw.state.agent_request(AGENT, line.as_bytes());
        assert!(answer.line.is_none(), "answered at once: {:?}", answer.line);
        answer.pending.expect("parked")
    }

    /// The requests `phone` received, checked as the phone checks them.
    fn requests(&mut self, phone: &mut Phone) -> Vec<Request> {
        let channel = phone.channel;
        self.received(phone)
            .into_iter()
            .filter(|(k, _)| *k == kind::REQUEST)
            .map(|(_, text)| {
                let request: Request = wire::parse(&text).unwrap();
                check_request(&request, &channel).unwrap();
                request
            })
            .collect()
    }

    fn epoch(&self) -> u64 {
        self.gw.state.keep().agent_freeze_epoch().unwrap()
    }

    fn store(&self) -> Store {
        Store::load(self.gw.state.keep()).unwrap()
    }

    /// Whether credential `id` (hex) is frozen itself.
    fn frozen(&mut self, id: &str) -> bool {
        let listed = self.gw.admin_ok(json!({ "op": "list" }));
        listed
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == json!(id))
            .unwrap()["frozen"]
            .as_bool()
            .unwrap()
    }

    /// The outcomes `phone` received since the last call.
    fn outcomes(&mut self, phone: &mut Phone) -> Vec<Outcome> {
        self.received(phone)
            .into_iter()
            .filter(|(k, _)| *k == kind::OUTCOME)
            .map(|(_, t)| wire::parse(&t).unwrap())
            .collect()
    }

    /// Pair `second` as root once `first` approves adding it.
    fn add_device(&mut self, first: &mut Phone, second: &mut Phone) {
        let conn = self.conn();
        let (answer, pending) =
            self.admin_from(0, conn, json!({ "op": "approver_pair", "label": "Tablet" }));
        let uri = PairingUri::parse(answer["result"]["uri"].as_str().unwrap()).unwrap();
        assert!(self.deliver(&second.pair(&uri.secret, self.now())));
        let _ = reply(pending.unwrap());
        let (_, pending) = self.admin_from(0, conn, json!({ "op": "approver_confirm" }));
        let request = self.requests(first).pop().unwrap();
        self.deliver_from(
            first,
            kind::DECISION,
            &first.decide(&request, Verdict::Approve),
        );
        assert_eq!(reply(pending.unwrap())["ok"], json!(true));
        let _ = self.received(second);
    }
}

/// The line a pending request was answered with, parsed.
fn reply(mut pending: Pending) -> Value {
    let line = pending.reply.try_recv().expect("answered");
    serde_json::from_str(&line).unwrap()
}

fn unanswered(pending: &mut Pending) -> bool {
    matches!(
        pending.reply.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    )
}

/// A tool result's text and whether it is an error.
fn tool_text(answer: &Value) -> (String, bool) {
    let result = &answer["result"];
    (
        result["content"][0]["text"].as_str().unwrap().to_string(),
        result["isError"].as_bool().unwrap(),
    )
}

fn kind0() -> Value {
    json!({ "kind": 0, "content": "{\"name\":\"agent\"}" })
}

/// One approver set up, and a credential that may sign kind 0 (which needs
/// an approval).
fn paired() -> (Ap, Phone, String, String) {
    let mut ap = Ap::new();
    let (id, token) = ap.issue(&nostr_grant(ap.gw.key));
    let mut phone = Phone::new();
    ap.pair_first(&mut phone);
    (ap, phone, id, token)
}

#[test]
fn an_approved_event_is_signed_exactly_as_the_phone_saw_it() {
    let (mut ap, mut phone, id, token) = paired();
    let mut pending = ap.park(&token, 9, "sign_nostr_event", kind0());
    let request = ap.requests(&mut phone).pop().expect("a request");
    assert_eq!(request.credential.as_ref().unwrap().id.to_hex(), id);
    assert_eq!(request.deadline_secs, 120);
    assert!(unanswered(&mut pending));
    let requested = ap.gw.reasons(AuditEventType::AgentApprovalRequested);
    assert!(requested
        .iter()
        .any(|r| r.contains(&request.request_hash.to_hex())));

    assert!(ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve)
    ));
    let answer = reply(pending);
    let (text, error) = tool_text(&answer);
    assert!(!error, "{text}");
    assert_eq!(answer["id"], json!(9));
    let event: Event = serde_json::from_str(&text).unwrap();
    event.verify().unwrap();
    let payload = &request.payload["event"];
    assert_eq!(event.content, payload["content"].as_str().unwrap());
    assert_eq!(
        event.created_at.as_secs(),
        payload["created_at"].as_u64().unwrap()
    );
    assert_eq!(event.pubkey.to_bytes(), ap.gw.key);
    // Recorded with the decision's signature, and announced to every phone.
    let decided = ap.gw.reasons(AuditEventType::AgentApprovalDecided);
    assert!(decided.iter().any(|r| r.contains("approved")
        && r.contains(&hex::encode(phone.a()))
        && r.contains(&request.request_hash.to_hex())));
    let outcome = ap
        .received(&mut phone)
        .into_iter()
        .find(|(k, _)| *k == kind::OUTCOME)
        .unwrap();
    let outcome: Outcome = wire::parse(&outcome.1).unwrap();
    assert_eq!(outcome.outcome, OutcomeKind::Approved);
    assert_eq!(outcome.by, Some(Hex33(phone.a())));
    // The same decision again is for a consumed request: ignored.
    assert!(ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve)
    ));
    assert_eq!(
        ap.gw.reasons(AuditEventType::AgentApprovalDecided).len(),
        decided.len()
    );
}

#[test]
fn a_denial_answers_the_agent_and_three_in_a_day_freeze_the_credential() {
    let (mut ap, mut phone, id, token) = paired();
    for round in 0..3 {
        let pending = ap.park(&token, round, "sign_nostr_event", kind0());
        let request = ap.requests(&mut phone).pop().unwrap();
        ap.deliver_from(
            &phone,
            kind::DECISION,
            &phone.decide(&request, Verdict::Deny),
        );
        let (text, error) = tool_text(&reply(pending));
        assert!(error);
        assert_eq!(text, "denied by the approver");
    }
    let listed = ap.gw.admin_ok(json!({ "op": "list" }));
    let credential = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == json!(id))
        .unwrap();
    assert_eq!(credential["frozen"], json!(true));
    // The freeze moved the epoch and every phone was shown it.
    assert_eq!(ap.epoch(), 1);
    let anchor = ap
        .received(&mut phone)
        .into_iter()
        .rfind(|(k, _)| *k == kind::ANCHOR)
        .unwrap();
    let anchor: Anchor = wire::parse(&anchor.1).unwrap();
    assert_eq!(anchor.frozen.epoch, 1);
    assert_eq!(anchor.frozen.credentials.len(), 1);
    // Only an approved unfreeze clears it: the admin socket asks the phone.
    let conn = ap.conn();
    let (answer, pending) = ap.admin_from(0, conn, json!({ "op": "unfreeze", "id": id }));
    assert_eq!(answer["ok"], json!(true));
    assert!(answer["pending"].is_string(), "{answer}");
    let request = ap.requests(&mut phone).pop().unwrap();
    assert_eq!(request.op, keep_approval::binding::Op::Management);
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let answer = reply(pending.unwrap());
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!(ap.epoch(), 2);
    let mut pending = ap.park(&token, 7, "sign_nostr_event", kind0());
    assert!(unanswered(&mut pending), "served again after the unfreeze");
}

#[test]
fn the_deadline_expires_a_request_on_the_budget_clock() {
    let (mut ap, mut phone, _, token) = paired();
    let mut pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.gw.boot.advance(119);
    ap.gw.state.approval_tick();
    assert!(unanswered(&mut pending));
    // Moving the wall clock changes nothing.
    ap.gw.boot.set_wall(T0 + 10_000);
    ap.gw.state.approval_tick();
    assert!(unanswered(&mut pending));
    ap.gw.boot.advance(1);
    ap.gw.state.approval_tick();
    let (text, error) = tool_text(&reply(pending));
    assert!(error);
    assert_eq!(text, "no approval within 120 seconds");
    // A decision after the deadline finds nothing parked.
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let outcomes: Vec<Outcome> = ap
        .received(&mut phone)
        .into_iter()
        .filter(|(k, _)| *k == kind::OUTCOME)
        .map(|(_, t)| wire::parse(&t).unwrap())
        .collect();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].outcome, OutcomeKind::Expired);
}

#[test]
fn one_request_waits_per_credential_and_agents_leave_room_for_management() {
    let agents = MAX_PARKED - MANAGEMENT_RESERVED;
    let mut ap = Ap::new();
    let mut tokens = Vec::new();
    for _ in 0..=agents {
        tokens.push(ap.issue(&nostr_grant(ap.gw.key)).1);
    }
    let mut phone = Phone::new();
    ap.pair_first(&mut phone);
    let _first = ap.park(&tokens[0], 1, "sign_nostr_event", kind0());
    let again = ap.gw.tool(&tokens[0], "sign_nostr_event", kind0());
    assert_eq!(
        again,
        (
            json!("an approval for this credential is already pending"),
            true
        )
    );
    let mut parked = Vec::new();
    for token in &tokens[1..agents] {
        parked.push(ap.park(token, 1, "sign_nostr_event", kind0()));
    }
    let (text, error) = ap.gw.tool(&tokens[agents], "sign_nostr_event", kind0());
    assert!(error);
    assert!(
        text.as_str().unwrap().contains("too many requests"),
        "{text}"
    );
    // The owner can still ask for an unfreeze, twice over.
    for _ in 0..MANAGEMENT_RESERVED {
        let conn = ap.conn();
        let (answer, pending) = ap.admin_from(0, conn, json!({ "op": "unfreeze_all" }));
        assert!(pending.is_some(), "{answer}");
    }
}

#[test]
fn a_freeze_cancels_what_it_covers_and_takes_effect_from_the_phone() {
    let (mut ap, mut phone, id, token) = paired();
    let pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let _ = ap.requests(&mut phone);
    let cid = Hex16(<[u8; 16]>::try_from(hex::decode(&id).unwrap()).unwrap());
    let freeze = phone.freeze(Scope::Credential(cid), 0);
    ap.deliver_from(&phone, kind::FREEZE, &freeze);
    let (text, error) = tool_text(&reply(pending));
    assert!(error);
    assert_eq!(text, "canceled: frozen");
    assert_eq!(ap.epoch(), 1);
    assert_eq!(ap.store().devices[0].counter, 1);
    let got = ap.received(&mut phone);
    let anchor: Anchor =
        wire::parse(&got.iter().rfind(|(k, _)| *k == kind::ANCHOR).unwrap().1).unwrap();
    assert_eq!(anchor.frozen.credentials, [cid]);
    let entries = ap.gw.reasons(AuditEventType::AgentApproverFreeze);
    assert!(entries[0].contains("freeze") && entries[0].contains(&hex::encode(phone.t())));
    // The same message replayed: an old counter, refused, answered with an
    // anchor to that phone.
    ap.deliver_from(&phone, kind::FREEZE, &freeze);
    assert_eq!(ap.gw.reasons(AuditEventType::AgentApproverFreeze).len(), 1);
    assert!(ap
        .received(&mut phone)
        .iter()
        .any(|(k, _)| *k == kind::ANCHOR));
}

#[test]
fn each_action_has_one_signer() {
    let (mut ap, mut phone, _, token) = paired();
    // A freeze signed by the approver key, an unfreeze by the transport key.
    let a = Signer::Approver(phone.approver.clone());
    let t = Signer::Transport(phone.transport.clone());
    let bad_freeze = phone.freeze_as(&a, FreezeAction::Freeze, Scope::All, 0);
    ap.deliver_from(&phone, kind::FREEZE, &bad_freeze);
    assert_eq!(ap.epoch(), 0);
    let bad_unfreeze = phone.freeze_as(&t, FreezeAction::Unfreeze, Scope::All, 0);
    ap.deliver_from(&phone, kind::FREEZE, &bad_unfreeze);
    assert_eq!(ap.epoch(), 0);
    // A decision carrying the approver key's signature over an unfreeze: a
    // signature over one digest never verifies over another.
    let mut pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let request = ap.requests(&mut phone).pop().unwrap();
    let unfreeze: Freeze =
        wire::parse(&phone.freeze_as(&a, FreezeAction::Unfreeze, Scope::All, 0)).unwrap();
    let mut borrowed: keep_approval::messages::Decision =
        wire::parse(&phone.decide(&request, Verdict::Approve)).unwrap();
    borrowed.sig = unfreeze.sig;
    ap.deliver_from(&phone, kind::DECISION, &wire::to_text(&borrowed));
    assert!(unanswered(&mut pending));
    // Nor does the transport key's signature over a freeze.
    let freeze: Freeze =
        wire::parse(&phone.freeze_as(&t, FreezeAction::Freeze, Scope::All, 0)).unwrap();
    borrowed.sig = freeze.sig;
    ap.deliver_from(&phone, kind::DECISION, &wire::to_text(&borrowed));
    assert!(unanswered(&mut pending));
    // A decision sealed by this phone but signed by another device's key.
    let other = Phone::new();
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide_as(&other.approver, &request, Verdict::Approve),
    );
    assert!(unanswered(&mut pending));
    // A decision from a phone nobody registered: its wraps are not even
    // opened.
    assert!(!ap.deliver_from(
        &other,
        kind::DECISION,
        &other.decide(&request, Verdict::Approve)
    ));
    assert!(unanswered(&mut pending));
    // A decision naming another request's hash under a valid signature.
    let mut renamed = request.clone();
    renamed.request_hash = Hex32([9; 32]);
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&renamed, Verdict::Approve),
    );
    assert!(unanswered(&mut pending));
    // The real one decides.
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Deny),
    );
    assert_eq!(tool_text(&reply(pending)).0, "denied by the approver");
}

#[test]
fn an_unfreeze_from_an_old_epoch_is_refused_and_the_retry_is_taken() {
    let (mut ap, mut phone, _, _) = paired();
    let freeze = phone.freeze(Scope::All, 0);
    ap.deliver_from(&phone, kind::FREEZE, &freeze);
    assert!(ap.gw.state.keep().agent_freeze().unwrap());
    // An unfreeze naming the epoch before the freeze.
    let stale = phone.unfreeze(Scope::All, 0);
    ap.deliver_from(&phone, kind::FREEZE, &stale);
    assert!(ap.gw.state.keep().agent_freeze().unwrap());
    let anchor: Anchor = wire::parse(
        &ap.received(&mut phone)
            .into_iter()
            .rfind(|(k, _)| *k == kind::ANCHOR)
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(anchor.frozen.epoch, 1);
    // Retried with the epoch from that anchor.
    let retry = phone.unfreeze(Scope::All, anchor.frozen.epoch);
    ap.deliver_from(&phone, kind::FREEZE, &retry);
    assert!(!ap.gw.state.keep().agent_freeze().unwrap());
    assert_eq!(ap.epoch(), 2);
    // Replayed later, after another freeze: refused.
    let refreeze = phone.freeze(Scope::All, 2);
    ap.deliver_from(&phone, kind::FREEZE, &refreeze);
    ap.deliver_from(&phone, kind::FREEZE, &retry);
    assert!(ap.gw.state.keep().agent_freeze().unwrap());
}

#[test]
fn pairing_needs_both_proofs_and_two_keys() {
    let mut ap = Ap::new();
    let try_pair = |ap: &mut Ap, build: &dyn Fn(&Phone, &[u8; 32], u64) -> Event| {
        let conn = ap.conn();
        let (answer, pending) =
            ap.admin_from(0, conn, json!({ "op": "approver_pair", "label": "Phone" }));
        let uri = PairingUri::parse(answer["result"]["uri"].as_str().unwrap()).unwrap();
        let phone = Phone::new();
        let event = build(&phone, &uri.secret, ap.now());
        ap.deliver(&event);
        reply(pending.unwrap())
    };
    // No approver signature: one by another key.
    let shown = try_pair(&mut ap, &|phone, secret, now| {
        let mut message = sig::pair(
            &phone.t(),
            &phone.approver,
            &phone.channel,
            secret,
            "x",
            phone.attestation(secret),
        );
        if let Pairing::Pair { approver_sig, .. } = &mut message {
            *approver_sig = sig::sign_p256(
                &approver_key(),
                &sig::pair_approver_digest(&phone.channel, &phone.t(), &phone.a()),
            );
        }
        phone.pairing_wrap(secret, &message, now)
    });
    assert_eq!(shown["ok"], json!(false), "{shown}");
    // A signature over other keys.
    let shown = try_pair(&mut ap, &|phone, secret, now| {
        let mut message = sig::pair(
            &phone.t(),
            &phone.approver,
            &phone.channel,
            secret,
            "x",
            phone.attestation(secret),
        );
        if let Pairing::Pair { approver_sig, .. } = &mut message {
            *approver_sig = sig::sign_p256(
                &phone.approver,
                &sig::pair_approver_digest(&phone.channel, &[9; 32], &phone.a()),
            );
        }
        phone.pairing_wrap(secret, &message, now)
    });
    assert_eq!(shown["ok"], json!(false));
    // A proof by another session's secret.
    let shown = try_pair(&mut ap, &|phone, secret, now| {
        let message = sig::pair(
            &phone.t(),
            &phone.approver,
            &phone.channel,
            &[7; 32],
            "x",
            phone.attestation(secret),
        );
        phone.pairing_wrap(secret, &message, now)
    });
    assert_eq!(shown["ok"], json!(false));
    // No attestation, one made for another session, and one made for the
    // secret and channel the wrong way round.
    type MakeChain = dyn Fn(&Phone, &[u8; 32]) -> CertChain;
    let chains: [&MakeChain; 3] = [
        &|_, _| CertChain(vec![vec![0x30, 0x00]]),
        &|phone, _| phone.attestation(&[7; 32]),
        &|phone, secret| {
            test_attestation::chain(
                &phone.a(),
                &sig::pair_attestation_challenge(&phone.channel, secret),
            )
        },
    ];
    for chain in chains {
        let shown = try_pair(&mut ap, &|phone, secret, now| {
            let message = sig::pair(
                &phone.t(),
                &phone.approver,
                &phone.channel,
                secret,
                "x",
                chain(phone, secret),
            );
            phone.pairing_wrap(secret, &message, now)
        });
        assert_eq!(shown["ok"], json!(false), "{shown}");
        assert!(
            shown["error"].as_str().unwrap().contains("attestation"),
            "{shown}"
        );
    }
    assert!(ap.store().devices.is_empty());
    // An approver key of another type is not even opened as a `pair`: the
    // session goes on waiting.
    let conn = ap.conn();
    let (answer, pending) = ap.admin_from(0, conn, json!({ "op": "approver_pair", "label": "x" }));
    let uri = PairingUri::parse(answer["result"]["uri"].as_str().unwrap()).unwrap();
    let phone = Phone::new();
    let message = sig::pair(
        &phone.t(),
        &phone.approver,
        &phone.channel,
        &uri.secret,
        "x",
        phone.attestation(&uri.secret),
    );
    let text = wire::to_text(&message).replace("\"p256\"", "\"bip340\"");
    assert!(!ap.deliver(&phone.pairing_wrap_text(&uri.secret, &text, ap.now())));
    assert!(unanswered(&mut pending.unwrap()));
    ap.gw.state.admin_gone(conn);
    assert!(ap.store().devices.is_empty());
    // Only root pairs the first device.
    let conn = ap.conn();
    let (answer, _) = ap.admin_from(1500, conn, json!({ "op": "approver_pair", "label": "x" }));
    assert_eq!(answer["ok"], json!(false));
}

/// The pairing session is used up by the first `pair`: someone who saw the
/// code and pairs first shows up on the host, and the real phone is refused.
#[test]
fn a_racer_uses_up_the_session_and_the_operator_rejects_it() {
    let mut ap = Ap::new();
    let conn = ap.conn();
    let (answer, pending) =
        ap.admin_from(0, conn, json!({ "op": "approver_pair", "label": "Phone" }));
    let uri = PairingUri::parse(answer["result"]["uri"].as_str().unwrap()).unwrap();
    let racer = Phone::new();
    let real = Phone::new();
    let event = racer.pair(&uri.secret, ap.now());
    assert!(ap.deliver(&event));
    let shown = reply(pending.unwrap());
    assert_eq!(
        shown["result"]["fingerprint"],
        json!(sig::fingerprint(&racer.t(), &racer.a()))
    );
    let mut real = real;
    let event = real.pair(&uri.secret, ap.now());
    assert!(ap.deliver(&event));
    // The real phone is told the code was used, so its owner knows.
    let got = ap.received(&mut real);
    assert!(
        got.iter().any(|(k, t)| *k == kind::PAIRING
            && matches!(
                wire::parse::<Pairing>(t).unwrap(),
                Pairing::Refused { reason, .. } if reason.contains("already used")
            )),
        "{got:?}"
    );
    let (answer, _) = ap.admin_from(0, conn, json!({ "op": "approver_reject" }));
    assert_eq!(answer["ok"], json!(true));
    assert!(ap.store().devices.is_empty());
}

#[test]
fn untagged_and_wrongly_tagged_wraps_are_dropped_and_a_freeze_gets_through_a_flood() {
    let (mut ap, mut phone, _, _) = paired();
    let stranger = Keys::generate();
    let channel_pub = phone.channel;
    let now = ap.now();
    for i in 0..200 {
        // Tagged for another pair of keys, or carrying no tag at all.
        let tag = TagKey::device(&stranger, &channel_pub).unwrap();
        let event = wrap::wrap(
            &stranger,
            &channel_pub,
            &tag,
            kind::FREEZE,
            &format!("{i}"),
            now,
        )
        .unwrap();
        let event = if i % 2 == 0 {
            event
        } else {
            use nostr_sdk::prelude::{EventBuilder, Kind, PublicKey, Tag};
            EventBuilder::new(Kind::GiftWrap, event.content.clone())
                .tag(Tag::public_key(
                    PublicKey::from_slice(&channel_pub).unwrap(),
                ))
                .sign_with_keys(&Keys::generate())
                .unwrap()
        };
        assert!(!ap.deliver(&event));
    }
    let freeze = phone.freeze(Scope::All, 0);
    assert!(ap.deliver_from(&phone, kind::FREEZE, &freeze));
    assert!(ap.gw.state.keep().agent_freeze().unwrap());
    let _ = ap.received(&mut phone);
}

#[test]
fn a_freeze_and_an_approval_work_with_the_agents_audit_budget_used_up() {
    let mut gw = Gw::with(super::state::Settings {
        audit_budgets: (3, 3),
        ..super::tests::settings()
    });
    gw.state
        .configure_approvals(Some(channel()), vec![RELAY.into()], 120)
        .unwrap();
    let link = gw.state.take_relay_link().unwrap();
    let mut ap = Ap {
        gw,
        link,
        next_conn: 1,
    };
    let (_, token) = ap.issue(&nostr_grant(ap.gw.key));
    let mut phone = Phone::new();
    ap.pair_first(&mut phone);
    // The agents' budget is spent on its requests.
    let mut used_up = false;
    for _ in 0..6 {
        let answer = ap.gw.rpc(
            &token,
            "tools/call",
            json!({ "name": "get_nostr_pubkey", "arguments": {} }),
        );
        used_up |= answer.get("error").is_some();
    }
    assert!(used_up, "the agents' budget was not used up");
    // A freeze from the phone still takes effect and is recorded.
    let freeze = phone.freeze(Scope::All, 0);
    ap.deliver_from(&phone, kind::FREEZE, &freeze);
    assert!(ap.gw.state.keep().agent_freeze().unwrap());
    assert_eq!(ap.gw.reasons(AuditEventType::AgentApproverFreeze).len(), 1);
    // The budget's own freeze of the credential moved the epoch too.
    assert_eq!(ap.epoch(), 2);
    // A management change is still decided on the phone, applied and
    // recorded.
    let conn = ap.conn();
    let (_, pending) = ap.admin_from(0, conn, json!({ "op": "unfreeze_all" }));
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    assert_eq!(reply(pending.unwrap())["ok"], json!(true));
    assert!(!ap.gw.state.keep().agent_freeze().unwrap());
    assert!(ap
        .gw
        .reasons(AuditEventType::AgentApprovalDecided)
        .iter()
        .any(|r| r.contains("approved and applied") && r.contains(&request.request_hash.to_hex())));
}

#[test]
fn the_agent_withdraws_a_request_with_notifications_cancelled() {
    let (mut ap, mut phone, _, token) = paired();
    let pending = ap.park(&token, 42, "sign_nostr_event", kind0());
    let request = ap.requests(&mut phone).pop().unwrap();
    // Another id withdraws nothing.
    ap.gw.send(
        AGENT,
        &token,
        json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": 41 } }),
    );
    let mut pending = pending;
    assert!(unanswered(&mut pending));
    ap.gw.send(
        AGENT,
        &token,
        json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": 42 } }),
    );
    let (text, error) = tool_text(&reply(pending));
    assert!(error && text.starts_with("canceled"), "{text}");
    let outcome = ap
        .received(&mut phone)
        .into_iter()
        .find(|(k, _)| *k == kind::OUTCOME)
        .unwrap();
    let outcome: Outcome = wire::parse(&outcome.1).unwrap();
    assert_eq!(outcome.request_id, request.request_id);
    assert_eq!(outcome.outcome, OutcomeKind::Canceled);
    // A connection gone away withdraws its request the same way.
    let pending = ap.park(&token, 43, "sign_nostr_event", kind0());
    ap.gw.state.cancel_parked(pending.request_id.unwrap());
    assert!(reply(pending)["result"]["isError"].as_bool().unwrap());
}

#[test]
fn issuing_with_an_approver_waits_for_one_and_hands_the_token_back() {
    let (mut ap, mut phone, _, _) = paired();
    let conn = ap.conn();
    let grant = nostr_grant(ap.gw.key);
    let (answer, pending) = ap.admin_from(
        0,
        conn,
        json!({ "op": "issue", "name": "approved agent", "uid": OTHER, "grant": grant, "ttl_secs": 3600 }),
    );
    assert!(answer["pending"].is_string(), "{answer}");
    let request = ap.requests(&mut phone).pop().unwrap();
    let change = keep_approval::change::Change::parse(&request.payload["change"]).unwrap();
    let keep_approval::change::Change::IssueCredential {
        id,
        expires_at,
        created_at,
        ..
    } = change
    else {
        panic!("not an issue change");
    };
    assert_eq!(expires_at.0 - created_at.0, 3600);
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let answer = reply(pending.unwrap());
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!(answer["result"]["id"], json!(id.to_hex()));
    assert!(answer["token"].as_str().unwrap().starts_with("keep_agt_"));
    // A denied one issues nothing.
    let conn = ap.conn();
    let (_, pending) = ap.admin_from(
        0,
        conn,
        json!({ "op": "issue", "name": "denied agent", "uid": OTHER, "grant": nostr_grant(ap.gw.key) }),
    );
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Deny),
    );
    let answer = reply(pending.unwrap());
    assert_eq!(answer["ok"], json!(false));
    let names: Vec<Value> = ap
        .gw
        .admin_ok(json!({ "op": "list" }))
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].clone())
        .collect();
    assert!(!names.contains(&json!("denied agent")));
    // The admin command gone, its request is canceled, so a token never
    // goes to nobody.
    let conn = ap.conn();
    let (_, pending) = ap.admin_from(
        0,
        conn,
        json!({ "op": "issue", "name": "abandoned", "uid": OTHER, "grant": nostr_grant(ap.gw.key) }),
    );
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.gw.state.admin_gone(conn);
    assert_eq!(reply(pending.unwrap())["ok"], json!(false));
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let names: Vec<Value> = ap
        .gw
        .admin_ok(json!({ "op": "list" }))
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].clone())
        .collect();
    assert!(!names.contains(&json!("abandoned")));
}

#[test]
fn a_second_device_is_added_with_the_first_ones_approval_and_removed_the_same_way() {
    let (mut ap, mut first, _, _) = paired();
    let mut second = Phone::new();
    let conn = ap.conn();
    let (answer, pending) = ap.admin_from(
        1500,
        conn,
        json!({ "op": "approver_pair", "label": "Tablet" }),
    );
    assert_eq!(answer["ok"], json!(true), "{answer}");
    let uri = PairingUri::parse(answer["result"]["uri"].as_str().unwrap()).unwrap();
    let event = second.pair(&uri.secret, ap.now());
    ap.deliver(&event);
    let _ = reply(pending.unwrap());
    let (answer, pending) = ap.admin_from(1500, conn, json!({ "op": "approver_confirm" }));
    assert!(answer["pending"].is_string(), "{answer}");
    let request = ap.requests(&mut first).pop().unwrap();
    let change = keep_approval::change::Change::parse(&request.payload["change"]).unwrap();
    assert!(
        matches!(change, keep_approval::change::Change::AddApprover { transport, .. } if transport.0 == second.t())
    );
    ap.deliver_from(
        &first,
        kind::DECISION,
        &first.decide(&request, Verdict::Approve),
    );
    assert_eq!(reply(pending.unwrap())["ok"], json!(true));
    assert_eq!(ap.store().devices.len(), 2);
    assert!(ap
        .received(&mut second)
        .iter()
        .any(|(k, t)| *k == kind::PAIRING && t.contains("paired")));
    // A grant may no longer name either of its keys.
    let mut grant = nostr_grant(ap.gw.key);
    grant.nip44_peers.insert(second.t());
    let answer = ap
        .gw
        .admin(json!({ "op": "issue", "name": "x", "uid": OTHER, "grant": grant }));
    assert_eq!(answer["ok"], json!(false), "{answer}");

    // Removing the first, approved by the second.
    let conn = ap.conn();
    let (_, pending) = ap.admin_from(
        0,
        conn,
        json!({ "op": "approver_remove", "transport": hex::encode(first.t()) }),
    );
    let request = ap.requests(&mut second).pop().unwrap();
    ap.deliver_from(
        &second,
        kind::DECISION,
        &second.decide(&request, Verdict::Approve),
    );
    assert_eq!(reply(pending.unwrap())["ok"], json!(true));
    assert_eq!(ap.store().devices.len(), 1);
    // The removed device's messages are no longer opened.
    let freeze = first.freeze(Scope::All, 0);
    assert!(!ap.deliver_from(&first, kind::FREEZE, &freeze));
    assert_eq!(ap.gw.reasons(AuditEventType::AgentApproverRemoved).len(), 1);
}

#[test]
fn a_spend_above_the_threshold_is_approved_with_its_budget_context() {
    let mut ap = Ap::new();
    let mut grant = bitcoin_grant(ap.gw.key);
    grant.bitcoin.as_mut().unwrap().approval_above_sats = Some(5_000);
    let (_, token) = ap.issue(&grant);
    let mut phone = Phone::new();
    ap.pair_first(&mut phone);
    let pending = ap.park(
        &token,
        3,
        "sign_bitcoin_psbt",
        json!({ "psbt": psbt(10_000, 50_000, 500) }),
    );
    let request = ap.requests(&mut phone).pop().unwrap();
    let checked = check_request(&request, &phone.channel).unwrap();
    let view = checked.psbt.unwrap();
    assert_eq!(view.fee, 500);
    assert_eq!(view.leaving_wallet, 10_500);
    assert!(
        view.outputs[1].change_path.is_some(),
        "the change is shown with its path"
    );
    let budget = request.budget.unwrap();
    assert_eq!(budget.credential_window, 50_000);
    assert_eq!(budget.wallet_window, 100_000);
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let answer = reply(pending);
    let (text, error) = tool_text(&answer);
    assert!(!error, "{text}");
    let signed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(signed["inputs_signed"], json!(1));
    // Reserved in both ledgers, whose counts the next anchor carries.
    let wallet = super::state::wallet_key(&ap.gw.key, super::tests::NETWORK);
    assert_eq!(ap.gw.spent(&wallet), 10_500);
    ap.gw.boot.advance(super::approvals::ANCHOR_EVERY_SECS);
    ap.gw.state.approval_tick();
    let anchor: Anchor = wire::parse(
        &ap.received(&mut phone)
            .into_iter()
            .rfind(|(k, _)| *k == kind::ANCHOR)
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(anchor.anchor.wallets.len(), 1);
    assert_eq!(anchor.anchor.wallets[0].seq, 1);
    assert_eq!(anchor.anchor.wallets[0].spent, 10_500);
    assert!(anchor.anchor.wallets[0]
        .wallet
        .as_str()
        .starts_with("test:"));
    let (seq, head) = ap.gw.state.keep().audit_anchor().unwrap();
    assert!(anchor.anchor.seq <= seq);
    assert_ne!(head, [0; 32]);
}

#[test]
fn the_protocol_kinds_are_denied_even_with_an_approver() {
    let (mut ap, _, _, token) = paired();
    let mut grant = nostr_grant(ap.gw.key);
    grant.event_kinds.insert(24_251);
    let answer = ap
        .gw
        .admin(json!({ "op": "issue", "name": "x", "uid": OTHER, "grant": grant }));
    assert_eq!(answer["ok"], json!(false), "{answer}");
    for kind in 24_250..=24_255 {
        let (text, error) = ap.gw.tool(
            &token,
            "sign_nostr_event",
            json!({ "kind": kind, "content": "" }),
        );
        assert!(error);
        assert!(
            text.as_str().unwrap().contains("approval protocol"),
            "{text}"
        );
    }
}

#[test]
fn a_request_too_large_to_approve_is_refused_at_once() {
    let (mut ap, _, _, token) = paired();
    let big = "x".repeat(keep_approval::wrap::MAX_RUMOR_BYTES);
    let (text, error) = ap.gw.tool(
        &token,
        "sign_nostr_event",
        json!({ "kind": 0, "content": big }),
    );
    assert!(error);
    assert_eq!(text, json!("the request is too large to approve"));
}

#[test]
fn start_refuses_a_missing_or_different_channel_key_once_an_approver_is_registered() {
    let (ap, _, _, _) = paired();
    let Ap { gw, .. } = ap;
    let mut gw = gw.restart(super::tests::BOOT, T0 + 100).unwrap();
    let err = gw.state.configure_approvals(None, vec![], 120).unwrap_err();
    assert!(err.to_string().contains("channel-key"), "{err}");
    let err = gw
        .state
        .configure_approvals(Some(Keys::generate()), vec![RELAY.into()], 120)
        .unwrap_err();
    assert!(err.to_string().contains("not the one"), "{err}");
    gw.state
        .configure_approvals(Some(channel()), vec![RELAY.into()], 120)
        .unwrap();
    assert!(gw.state.approvals_active());
    // Root's reset removes every device, so the next start may differ.
    let answer = gw.state.admin_request(br#"{"op":"approver_reset"}"#);
    assert!(answer.contains("\"removed\":1"), "{}", &*answer);
    assert!(!gw.state.approvals_active());
}

#[test]
fn a_channel_key_in_the_vault_or_unusable_settings_are_refused() {
    let mut gw = Gw::new();
    let in_vault = Keys::new(SecretKey::from_slice(&super::tests::SECRET).unwrap());
    let err = gw
        .state
        .configure_approvals(Some(in_vault), vec![RELAY.into()], 120)
        .unwrap_err();
    assert!(err.to_string().contains("in the vault"), "{err}");
    for (relays, deadline) in [
        (vec![], 120),
        (vec!["https://relay.example.com".to_string()], 120),
        (vec![RELAY.to_string()], 29),
        (vec![RELAY.to_string()], 121),
    ] {
        assert!(gw
            .state
            .configure_approvals(Some(channel()), relays, deadline)
            .is_err());
    }
    // Without a key and without approvers, approvals stay off.
    gw.state.configure_approvals(None, vec![], 120).unwrap();
    assert!(!gw.state.approvals_active());
}

#[test]
fn without_an_approver_a_request_that_needs_one_is_refused_as_before() {
    let mut ap = Ap::new();
    let (_, token) = ap.issue(&nostr_grant(ap.gw.key));
    let (text, error) = ap.gw.tool(&token, "sign_nostr_event", kind0());
    assert!(error);
    assert!(text.as_str().unwrap().contains("needs approval"), "{text}");
    // Management goes over the admin socket alone.
    let answer = ap.gw.admin(json!({ "op": "freeze_all" }));
    assert_eq!(answer["ok"], json!(true));
    let answer = ap.gw.admin(json!({ "op": "unfreeze_all" }));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    let _ = Hex64([0; 64]);
}

#[test]
fn a_credential_revoked_or_expired_while_it_waits_signs_nothing() {
    let (mut ap, mut phone, id, token) = paired();
    let pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let _ = ap.requests(&mut phone);
    ap.gw.admin_ok(json!({ "op": "revoke", "id": id }));
    let (text, error) = tool_text(&reply(pending));
    assert!(error);
    assert_eq!(text, "canceled: revoked");

    // One that expires while its approver decides is refused at approval.
    let grant = nostr_grant(ap.gw.key);
    let conn = ap.conn();
    let (_, issuing) = ap.admin_from(
        0,
        conn,
        json!({ "op": "issue", "name": "short", "uid": AGENT, "grant": grant, "ttl_secs": 60 }),
    );
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let short = reply(issuing.unwrap())["token"]
        .as_str()
        .unwrap()
        .to_string();
    let pending = ap.park(&short, 2, "sign_nostr_event", kind0());
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.gw.boot.advance(61);
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let (text, error) = tool_text(&reply(pending));
    assert!(error);
    assert_eq!(text, "canceled: revoked");
    assert!(ap.gw.entries(AuditEventType::Sign).iter().all(|e| !e
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("approved request")));
}

#[test]
fn a_device_whose_key_is_a_vault_key_or_already_registered_is_refused() {
    let (mut ap, first, _, _) = paired();
    let pair_with = |ap: &mut Ap, phone: &Phone| {
        let conn = ap.conn();
        let (answer, pending) =
            ap.admin_from(0, conn, json!({ "op": "approver_pair", "label": "x" }));
        let uri = PairingUri::parse(answer["result"]["uri"].as_str().unwrap()).unwrap();
        let event = phone.pair(&uri.secret, ap.now());
        ap.deliver(&event);
        reply(pending.unwrap())
    };
    // The vault's own key as the transport key.
    let mut vaulted = Phone::new();
    vaulted.transport = Keys::new(SecretKey::from_slice(&super::tests::SECRET).unwrap());
    let shown = pair_with(&mut ap, &vaulted);
    assert_eq!(shown["ok"], json!(false));
    assert!(
        shown["error"].as_str().unwrap().contains("in the vault"),
        "{shown}"
    );
    // A key another device holds, either one.
    let mut copy = Phone::new();
    copy.approver = first.approver.clone();
    let shown = pair_with(&mut ap, &copy);
    assert_eq!(shown["ok"], json!(false));
    assert!(
        shown["error"]
            .as_str()
            .unwrap()
            .contains("already registered"),
        "{shown}"
    );
    let mut copy = Phone::new();
    copy.transport = first.transport.clone();
    let shown = pair_with(&mut ap, &copy);
    assert_eq!(shown["ok"], json!(false));
    // The channel key as the transport key.
    let mut channelled = Phone::new();
    channelled.transport = channel();
    let shown = pair_with(&mut ap, &channelled);
    assert_eq!(shown["ok"], json!(false));
    assert_eq!(ap.store().devices.len(), 1);
}

/// A pairing session lasts ten minutes and one phone.
#[test]
fn a_pairing_session_expires_and_is_used_once() {
    let mut ap = Ap::new();
    let conn = ap.conn();
    let (answer, pending) = ap.admin_from(0, conn, json!({ "op": "approver_pair", "label": "x" }));
    let uri = PairingUri::parse(answer["result"]["uri"].as_str().unwrap()).unwrap();
    ap.gw.boot.advance(super::approvals::PAIRING_SECS);
    ap.gw.state.approval_tick();
    assert_eq!(reply(pending.unwrap())["ok"], json!(false));
    let phone = Phone::new();
    let event = phone.pair(&uri.secret, ap.now());
    assert!(
        !ap.deliver(&event),
        "an expired session's pair is not even opened"
    );
    // Another connection cannot confirm someone else's session.
    let conn = ap.conn();
    let (answer, _) = ap.admin_from(0, conn, json!({ "op": "approver_pair", "label": "x" }));
    let uri = PairingUri::parse(answer["result"]["uri"].as_str().unwrap()).unwrap();
    let event = phone.pair(&uri.secret, ap.now());
    assert!(ap.deliver(&event));
    let other = ap.conn();
    let (answer, _) = ap.admin_from(0, other, json!({ "op": "approver_confirm" }));
    assert_eq!(answer["ok"], json!(false));
    let (answer, _) = ap.admin_from(0, conn, json!({ "op": "approver_confirm" }));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!(ap.store().devices.len(), 1);
}

/// The gateway's deadline counts, not the timer: a decision that arrives
/// past it, before the timer has run, decides nothing.
#[test]
fn a_decision_past_the_deadline_decides_nothing() {
    let (mut ap, mut phone, _, token) = paired();
    let pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.gw.boot.advance(120);
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    ap.gw.state.approval_tick();
    let (text, error) = tool_text(&reply(pending));
    assert!(error);
    assert_eq!(text, "no approval within 120 seconds");
}

/// Only the credential that asked may withdraw its request.
#[test]
fn another_credential_cannot_withdraw_a_request() {
    let (mut ap, mut phone, _, token) = paired();
    let mut pending = ap.park(&token, 5, "sign_nostr_event", kind0());
    let _ = ap.requests(&mut phone);
    // A second credential, issued with the phone's approval.
    let conn = ap.conn();
    let (_, issuing) = ap.admin_from(
        0,
        conn,
        json!({ "op": "issue", "name": "other", "uid": AGENT, "grant": nostr_grant(ap.gw.key) }),
    );
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let other_token = reply(issuing.unwrap())["token"]
        .as_str()
        .unwrap()
        .to_string();
    ap.gw.send(
        AGENT,
        &other_token,
        json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": 5 } }),
    );
    assert!(unanswered(&mut pending));
}

/// Management changes count against the same cap of 16 waiting requests.
#[test]
fn a_management_change_is_refused_once_sixteen_requests_wait() {
    let agents = MAX_PARKED - MANAGEMENT_RESERVED;
    let mut ap = Ap::new();
    let mut tokens = Vec::new();
    for _ in 0..agents {
        tokens.push(ap.issue(&nostr_grant(ap.gw.key)).1);
    }
    let mut phone = Phone::new();
    ap.pair_first(&mut phone);
    let _parked: Vec<Pending> = tokens
        .iter()
        .map(|token| ap.park(token, 1, "sign_nostr_event", kind0()))
        .collect();
    let mut waiting = Vec::new();
    for _ in 0..MANAGEMENT_RESERVED {
        let conn = ap.conn();
        let (_, pending) = ap.admin_from(0, conn, json!({ "op": "unfreeze_all" }));
        waiting.push(pending.unwrap());
    }
    let _ = ap.requests(&mut phone);
    let conn = ap.conn();
    let (answer, pending) = ap.admin_from(
        0,
        conn,
        json!({ "op": "issue", "name": "late", "uid": AGENT, "grant": nostr_grant(ap.gw.key) }),
    );
    assert!(pending.is_none());
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert!(
        answer["error"]
            .as_str()
            .unwrap()
            .contains("too many requests are waiting"),
        "{answer}"
    );
    assert!(ap.requests(&mut phone).is_empty());
}

/// A freeze of the whole gateway cancels every waiting request: agents'
/// and management changes alike.
#[test]
fn a_freeze_of_everything_cancels_every_waiting_request() {
    let (mut ap, mut phone, _id, token) = paired();
    let agent = ap.park(&token, 1, "sign_nostr_event", kind0());
    let conn = ap.conn();
    let (answer, issue) = ap.admin_from(
        0,
        conn,
        json!({ "op": "issue", "name": "second", "uid": OTHER, "grant": nostr_grant(ap.gw.key) }),
    );
    assert!(answer["pending"].is_string(), "{answer}");
    assert_eq!(ap.requests(&mut phone).len(), 2);
    let freeze = phone.freeze(Scope::All, 0);
    ap.deliver_from(&phone, kind::FREEZE, &freeze);
    assert_eq!(tool_text(&reply(agent)), ("canceled: frozen".into(), true));
    let answer = reply(issue.unwrap());
    assert_eq!(answer["error"], json!("canceled: frozen"), "{answer}");
    let outcomes: Vec<Outcome> = ap
        .received(&mut phone)
        .into_iter()
        .filter(|(k, _)| *k == kind::OUTCOME)
        .map(|(_, t)| wire::parse(&t).unwrap())
        .collect();
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes.iter().all(|o| o.outcome == OutcomeKind::Canceled));
}

/// A freeze of a credential the gateway does not have is refused: no
/// epoch, no counter, no entry.
#[test]
fn a_freeze_of_an_unknown_credential_is_refused() {
    let (mut ap, mut phone, _id, _token) = paired();
    let freeze = phone.freeze(Scope::Credential(Hex16([9; 16])), 0);
    ap.deliver_from(&phone, kind::FREEZE, &freeze);
    assert_eq!(ap.epoch(), 0);
    assert_eq!(ap.store().devices[0].counter, 0);
    assert!(ap
        .gw
        .reasons(AuditEventType::AgentApproverFreeze)
        .is_empty());
}

/// A credential its audit budget froze has its waiting request canceled on
/// the next tick, and the phone is shown the freeze.
#[test]
fn a_freeze_by_the_audit_budget_cancels_the_waiting_request() {
    let mut gw = Gw::with(super::state::Settings {
        audit_budgets: (4, 1000),
        ..super::tests::settings()
    });
    gw.state
        .configure_approvals(Some(channel()), vec![RELAY.into()], 120)
        .unwrap();
    let link = gw.state.take_relay_link().unwrap();
    let mut ap = Ap {
        gw,
        link,
        next_conn: 1,
    };
    let (id, token) = ap.issue(&nostr_grant(ap.gw.key));
    let mut phone = Phone::new();
    ap.pair_first(&mut phone);
    let mut pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let _ = ap.requests(&mut phone);
    let mut frozen = false;
    for _ in 0..8 {
        let answer = ap.gw.rpc(
            &token,
            "tools/call",
            json!({ "name": "get_nostr_pubkey", "arguments": {} }),
        );
        frozen |= answer.get("error").is_some();
    }
    assert!(frozen, "the credential's audit budget was not used up");
    assert!(unanswered(&mut pending));
    ap.gw.state.approval_tick();
    assert_eq!(
        tool_text(&reply(pending)),
        ("canceled: frozen".into(), true)
    );
    let got = ap.received(&mut phone);
    let anchor: Anchor =
        wire::parse(&got.iter().rfind(|(k, _)| *k == kind::ANCHOR).unwrap().1).unwrap();
    let cid = <[u8; 16]>::try_from(hex::decode(&id).unwrap()).unwrap();
    assert_eq!(anchor.frozen.credentials, [Hex16(cid)]);
    // The budget's freeze moved the epoch, so an unfreeze signed before it
    // and held back until now is refused.
    assert_eq!(ap.epoch(), 1);
    assert_eq!(anchor.frozen.epoch, 1);
    let held_back = phone.unfreeze(Scope::Credential(Hex16(cid)), 0);
    ap.deliver_from(&phone, kind::FREEZE, &held_back);
    assert!(ap.frozen(&id));
    assert_eq!(ap.epoch(), 1);
}

/// A request is recorded before the phone is asked: when its entry cannot
/// be written, it is withheld and the phone hears nothing.
#[test]
fn a_request_whose_entry_cannot_be_written_is_never_sent() {
    let mut gw = Gw::with(super::state::Settings {
        audit_budgets: (1, 1000),
        ..super::tests::settings()
    });
    gw.state
        .configure_approvals(Some(channel()), vec![RELAY.into()], 120)
        .unwrap();
    let link = gw.state.take_relay_link().unwrap();
    let mut ap = Ap {
        gw,
        link,
        next_conn: 1,
    };
    let (_, token) = ap.issue(&nostr_grant(ap.gw.key));
    let mut phone = Phone::new();
    ap.pair_first(&mut phone);
    // The one entry of the day: a served request.
    let (_, error) = ap.gw.tool(&token, "get_nostr_pubkey", json!({}));
    assert!(!error);
    let answer = ap.gw.rpc(
        &token,
        "tools/call",
        json!({ "name": "sign_nostr_event", "arguments": kind0() }),
    );
    assert!(answer.get("error").is_some(), "{answer}");
    assert!(ap.requests(&mut phone).is_empty());
    assert!(ap
        .gw
        .reasons(AuditEventType::AgentApprovalRequested)
        .is_empty());
}

/// An approval is evaluated again against the credential as it is when the
/// decision comes: a grant that no longer allows the request signs nothing.
#[test]
fn an_approved_request_the_grant_no_longer_allows_signs_nothing() {
    let (mut ap, mut phone, id, token) = paired();
    let pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let request = ap.requests(&mut phone).remove(0);
    // The credential's grant changes under the waiting request: the same
    // id, now without kind 0.
    let cid = <[u8; 16]>::try_from(hex::decode(&id).unwrap()).unwrap();
    let mut narrower = nostr_grant(ap.gw.key);
    narrower.event_kinds.remove(&0);
    let keep = ap.gw.state.keep_mut();
    keep.delete_agent_credential(&cid).unwrap();
    keep.issue_agent_credential_with_id(
        cid,
        "agent",
        AGENT,
        serde_json::to_vec(&narrower).unwrap(),
        T0,
        86_400,
    )
    .unwrap();
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let (text, error) = tool_text(&reply(pending));
    assert!(error);
    assert!(text.starts_with("denied"), "{text}");
    assert!(!ap
        .gw
        .state
        .keep()
        .audit_read_all()
        .unwrap()
        .iter()
        .any(|e| e
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("approved request"))));
}

/// Stop `gw`, run `between` with its vault closed, and start it again with
/// approvals at wall time `wall`.
fn reopen(gw: Gw, wall: u64, between: impl FnOnce(&std::path::Path)) -> Ap {
    let path = gw.path();
    let Gw {
        dir,
        boot,
        mut state,
        key,
    } = gw;
    state.shut_down();
    drop(state);
    between(&path);
    let (keep, _) = super::tests::vault(dir.path());
    boot.set_wall(wall);
    let mut state =
        super::tests::start(keep, super::tests::settings(), &boot, super::tests::BOOT).unwrap();
    state
        .configure_approvals(Some(channel()), vec![RELAY.into()], 120)
        .unwrap();
    let link = state.take_relay_link().unwrap();
    Ap {
        gw: Gw {
            dir,
            boot,
            state,
            key,
        },
        link,
        next_conn: 1,
    }
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A vault put back to an earlier copy, audit log and ledgers with it, is
/// consistent on the host; only the phone, which kept a later anchor, sees
/// the counts go back.
#[test]
fn a_vault_put_back_to_an_earlier_copy_shows_on_the_phone() {
    use keep_approval::approver::{Alert, AnchorTracker};
    let (ap, mut phone, _id, token) = paired();
    let backup = tempfile::tempdir().unwrap();
    let wall = ap.gw.state.calendar();
    // The copy, taken with the gateway stopped.
    let mut ap = reopen(ap.gw, wall + 10, |path| copy_dir(path, backup.path()));
    // Served after the copy: the audit log grows.
    for _ in 0..3 {
        let (_, error) = ap.gw.tool(&token, "get_nostr_pubkey", json!({}));
        assert!(!error);
    }
    ap.gw.state.approval_tick();
    let anchors = |ap: &mut Ap, phone: &mut Phone| -> Vec<Anchor> {
        ap.received(phone)
            .into_iter()
            .filter(|(k, _)| *k == kind::ANCHOR)
            .map(|(_, t)| wire::parse(&t).unwrap())
            .collect()
    };
    let later = anchors(&mut ap, &mut phone).pop().expect("an anchor");
    let mut tracker = AnchorTracker::default();
    assert!(tracker
        .observe(later.at, &later.anchor, Some(&later.frozen), 0)
        .is_empty());
    // The earlier copy put back, and the gateway started on it.
    let mut ap = reopen(ap.gw, wall + 30, |path| {
        std::fs::remove_dir_all(path).unwrap();
        copy_dir(backup.path(), path);
    });
    ap.gw.state.approval_tick();
    let restored = anchors(&mut ap, &mut phone).pop().expect("an anchor");
    assert!(restored.at > later.at);
    assert!(restored.anchor.seq < later.anchor.seq);
    let alerts = tracker.observe(restored.at, &restored.anchor, Some(&restored.frozen), 1);
    assert!(
        alerts
            .iter()
            .any(|a| matches!(a, Alert::AuditCountWentBack { .. })),
        "{alerts:?}"
    );
}

/// A pairing session takes a plain label, is the only one open, and turns
/// away a phone that answers once it expired, even before the timer runs.
#[test]
fn a_pairing_session_needs_a_plain_label_is_alone_and_ends_on_time() {
    let mut ap = Ap::new();
    let conn = ap.conn();
    for label in ["Phone\u{202e}enohp", "", &"x".repeat(65)] {
        let (answer, pending) =
            ap.admin_from(0, conn, json!({ "op": "approver_pair", "label": label }));
        assert_eq!(answer["ok"], json!(false), "{label:?}: {answer}");
        assert!(pending.is_none());
    }
    let (answer, pending) =
        ap.admin_from(0, conn, json!({ "op": "approver_pair", "label": "Phone" }));
    let mut pending = pending.unwrap();
    let uri = PairingUri::parse(answer["result"]["uri"].as_str().unwrap()).unwrap();
    let other = ap.conn();
    let (answer, second) = ap.admin_from(
        0,
        other,
        json!({ "op": "approver_pair", "label": "Tablet" }),
    );
    assert_eq!(
        answer["error"],
        json!("a pairing session is already open"),
        "{answer}"
    );
    assert!(second.is_none());
    ap.gw.boot.advance(super::approvals::PAIRING_SECS);
    let phone = Phone::new();
    let event = phone.pair(&uri.secret, ap.now());
    ap.deliver(&event);
    assert!(unanswered(&mut pending), "a late phone was shown");
    ap.gw.state.approval_tick();
    assert_eq!(reply(pending)["ok"], json!(false));
    assert!(ap.store().devices.is_empty());
}

/// Once a phone has answered a pairing session, another phone's answer is
/// ignored: the operator confirms the phone they were shown.
#[test]
fn a_pairing_session_takes_the_first_phone_only() {
    let mut ap = Ap::new();
    let conn = ap.conn();
    let (answer, pending) =
        ap.admin_from(0, conn, json!({ "op": "approver_pair", "label": "Phone" }));
    let uri = PairingUri::parse(answer["result"]["uri"].as_str().unwrap()).unwrap();
    let (first, second) = (Phone::new(), Phone::new());
    assert!(ap.deliver(&first.pair(&uri.secret, ap.now())));
    let shown = reply(pending.unwrap());
    assert_eq!(
        shown["result"]["fingerprint"],
        json!(sig::fingerprint(&first.t(), &first.a()))
    );
    ap.deliver(&second.pair(&uri.secret, ap.now()));
    let (answer, _) = ap.admin_from(0, conn, json!({ "op": "approver_confirm" }));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    let devices = ap.store().devices;
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].transport.0, first.t());
}

/// Only root resets the approver devices.
#[test]
fn only_root_resets_the_approvers() {
    let (mut ap, _phone, _, _) = paired();
    let conn = ap.conn();
    let (answer, pending) = ap.admin_from(1500, conn, json!({ "op": "approver_reset" }));
    assert!(pending.is_none());
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert_eq!(ap.store().devices.len(), 1);
    let (answer, _) = ap.admin_from(0, conn, json!({ "op": "approver_reset" }));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert!(ap.store().devices.is_empty());
}

/// A device added with an approval is checked again when the approval
/// comes: the same phone paired twice while the first waited is registered
/// once.
#[test]
fn an_added_device_is_checked_again_when_approved() {
    let (mut ap, mut first, _, _) = paired();
    let second = Phone::new();
    let mut waiting = Vec::new();
    for _ in 0..2 {
        let conn = ap.conn();
        let (answer, pending) =
            ap.admin_from(0, conn, json!({ "op": "approver_pair", "label": "Tablet" }));
        let uri = PairingUri::parse(answer["result"]["uri"].as_str().unwrap()).unwrap();
        assert!(ap.deliver(&second.pair(&uri.secret, ap.now())));
        let _ = reply(pending.unwrap());
        let (answer, pending) = ap.admin_from(0, conn, json!({ "op": "approver_confirm" }));
        assert!(answer["pending"].is_string(), "{answer}");
        waiting.push(pending.unwrap());
    }
    let requests = ap.requests(&mut first);
    assert_eq!(requests.len(), 2);
    for request in &requests {
        ap.deliver_from(
            &first,
            kind::DECISION,
            &first.decide(request, Verdict::Approve),
        );
    }
    let answers: Vec<Value> = waiting.into_iter().map(reply).collect();
    assert_eq!(answers[0]["ok"], json!(true), "{}", answers[0]);
    assert_eq!(answers[1]["ok"], json!(false), "{}", answers[1]);
    assert_eq!(ap.store().devices.len(), 2);
    // The addition approved but not carried out is refused to the phone.
    let mut second = second;
    assert!(refused(&mut ap, &mut second));
}

fn cid_of(id: &str) -> [u8; 16] {
    <[u8; 16]>::try_from(hex::decode(id).unwrap()).unwrap()
}

/// A gateway with approvals and `budgets` (per credential, for the
/// gateway), one approver paired, and a credential that may sign kind 0.
fn paired_with_budgets(budgets: (u32, u32)) -> (Ap, Phone, String, String) {
    let mut gw = Gw::with(super::state::Settings {
        audit_budgets: budgets,
        ..super::tests::settings()
    });
    gw.state
        .configure_approvals(Some(channel()), vec![RELAY.into()], 120)
        .unwrap();
    let link = gw.state.take_relay_link().unwrap();
    let mut ap = Ap {
        gw,
        link,
        next_conn: 1,
    };
    let (id, token) = ap.issue(&nostr_grant(ap.gw.key));
    let mut phone = Phone::new();
    ap.pair_first(&mut phone);
    (ap, phone, id, token)
}

/// A freeze the vault cannot write applies nothing, neither the freeze nor
/// the epoch nor the device's counter, so the phone's retry of the same
/// message is taken; what it covers is canceled all the same.
#[test]
fn a_freeze_that_cannot_be_written_applies_nothing_and_its_retry_is_taken() {
    let (mut ap, mut phone, _id, token) = paired();
    let pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let _ = ap.requests(&mut phone);
    let freeze = phone.freeze(Scope::All, 0);
    ap.gw.state.keep_mut().lock();
    ap.deliver_from(&phone, kind::FREEZE, &freeze);
    assert_eq!(
        tool_text(&reply(pending)),
        ("canceled: frozen".into(), true)
    );
    ap.gw.state.keep_mut().unlock("testpass").unwrap();
    assert!(!ap.gw.state.keep().agent_freeze().unwrap());
    assert_eq!(ap.epoch(), 0);
    assert_eq!(ap.store().devices[0].counter, 0);
    ap.deliver_from(&phone, kind::FREEZE, &freeze);
    assert!(ap.gw.state.keep().agent_freeze().unwrap());
    assert_eq!(ap.epoch(), 1);
    assert_eq!(ap.store().devices[0].counter, 1);
}

/// An unfreeze of a credential drops its denials in the same write, so
/// they do not come back after a restart and freeze it again early.
#[test]
fn an_unfreeze_drops_the_credentials_denials_for_good() {
    let (mut ap, mut phone, id, token) = paired();
    for round in 0..2 {
        let pending = ap.park(&token, round, "sign_nostr_event", kind0());
        let request = ap.requests(&mut phone).pop().unwrap();
        ap.deliver_from(
            &phone,
            kind::DECISION,
            &phone.decide(&request, Verdict::Deny),
        );
        let _ = reply(pending);
    }
    assert_eq!(ap.store().denials.len(), 1);
    let cid = Hex16(cid_of(&id));
    let freeze = phone.freeze(Scope::Credential(cid), 0);
    ap.deliver_from(&phone, kind::FREEZE, &freeze);
    let unfreeze = phone.unfreeze(Scope::Credential(cid), 1);
    ap.deliver_from(&phone, kind::FREEZE, &unfreeze);
    assert!(!ap.frozen(&id));
    assert!(ap.store().denials.is_empty());
    // After a restart one more denial is one, not the third.
    let wall = ap.now();
    let mut ap = reopen(ap.gw, wall + 10, |_| {});
    let pending = ap.park(&token, 9, "sign_nostr_event", kind0());
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Deny),
    );
    let _ = reply(pending);
    assert!(!ap.frozen(&id));
}

/// An approval whose signature cannot be recorded (the gateway's audit
/// budget spent) signs nothing, is recorded as not carried out, and is
/// announced canceled, not approved.
#[test]
fn an_approval_whose_signature_cannot_be_recorded_is_announced_canceled() {
    let (mut ap, mut phone, _id, token) = paired_with_budgets((1_000, 3));
    let pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let request = ap.requests(&mut phone).pop().unwrap();
    for _ in 0..2 {
        let (_, error) = ap.gw.tool(&token, "get_nostr_pubkey", json!({}));
        assert!(!error);
    }
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let answer = reply(pending);
    let refused =
        answer.get("error").is_some() || answer["result"]["isError"].as_bool() == Some(true);
    assert!(refused, "{answer}");
    let outcomes = ap.outcomes(&mut phone);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].request_id, request.request_id);
    assert_eq!(outcomes[0].outcome, OutcomeKind::Canceled);
    assert_eq!(outcomes[0].by, None);
    let decided = ap.gw.reasons(AuditEventType::AgentApprovalDecided);
    assert!(
        decided
            .iter()
            .any(|r| r.contains("approved but not carried out")
                && r.contains(&request.request_hash.to_hex())),
        "{decided:?}"
    );
    assert!(!decided.iter().any(|r| r.contains("approved and signed")));
    assert!(ap.gw.entries(AuditEventType::Sign).iter().all(|e| !e
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("approved request")));
}

/// An unfreeze approved after something froze again names an epoch gone:
/// nothing is unfrozen, the approval is recorded as not carried out and
/// announced canceled, and the admin is told.
#[test]
fn an_unfreeze_approved_after_the_epoch_moved_is_recorded_as_not_carried_out() {
    let (mut ap, mut phone, id, _token) = paired();
    let freeze = phone.freeze(Scope::All, 0);
    ap.deliver_from(&phone, kind::FREEZE, &freeze);
    let conn = ap.conn();
    let (_, pending) = ap.admin_from(0, conn, json!({ "op": "unfreeze_all" }));
    let request = ap.requests(&mut phone).pop().unwrap();
    // Another freeze moves the epoch before the approval comes.
    let refreeze = phone.freeze(Scope::Credential(Hex16(cid_of(&id))), 1);
    ap.deliver_from(&phone, kind::FREEZE, &refreeze);
    assert_eq!(ap.epoch(), 2);
    let _ = ap.received(&mut phone);
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let answer = reply(pending.unwrap());
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert!(ap.gw.state.keep().agent_freeze().unwrap());
    let outcomes = ap.outcomes(&mut phone);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].outcome, OutcomeKind::Canceled);
    assert_eq!(outcomes[0].by, None);
    let decided = ap.gw.reasons(AuditEventType::AgentApprovalDecided);
    assert!(
        decided
            .iter()
            .any(|r| r.contains("approved but not carried out")
                && r.contains(&request.request_hash.to_hex())),
        "{decided:?}"
    );
}

/// An approval that fails its second check (which nothing but the test
/// hook can cause) carries out nothing: the agent gets an internal error,
/// the entry says why, and the phones are told it was canceled.
#[test]
fn an_approval_that_fails_its_second_check_carries_out_nothing() {
    let (mut ap, mut phone, _id, token) = paired();
    let pending = ap.park(&token, 4, "sign_nostr_event", kind0());
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.gw.state.fail_reverify_for_testing();
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let answer = reply(pending);
    assert_eq!(answer["error"]["code"], json!(-32603), "{answer}");
    let outcomes = ap.outcomes(&mut phone);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].outcome, OutcomeKind::Canceled);
    assert!(ap
        .gw
        .reasons(AuditEventType::AgentApprovalDecided)
        .iter()
        .any(|r| r.contains("did not verify again")));
    assert!(ap.gw.entries(AuditEventType::Sign).iter().all(|e| !e
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("approved request")));
}

/// An owner entry the log cannot take is kept in the vault and written
/// once it can be, even after a restart.
#[test]
fn an_owed_owner_entry_survives_a_restart_and_is_written() {
    let (mut ap, mut phone, _id, _token) = paired();
    ap.gw.break_log(true);
    let freeze = phone.freeze(Scope::All, 0);
    ap.deliver_from(&phone, kind::FREEZE, &freeze);
    assert!(ap.gw.state.keep().agent_freeze().unwrap());
    assert_eq!(ap.store().owed.len(), 1);
    let wall = ap.now();
    let mut ap = reopen(ap.gw, wall + 10, |path| {
        let log = path.join("audit.log");
        std::fs::remove_dir(&log).unwrap();
        std::fs::rename(log.with_extension("bak"), &log).unwrap();
    });
    assert!(ap
        .gw
        .reasons(AuditEventType::AgentApproverFreeze)
        .is_empty());
    ap.gw.state.approval_tick();
    let entries = ap.gw.reasons(AuditEventType::AgentApproverFreeze);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].starts_with("freeze all"), "{}", entries[0]);
    assert!(ap.store().owed.is_empty());
}

/// A reset with no approver registered is recorded too.
#[test]
fn a_reset_with_no_approver_is_recorded() {
    let mut ap = Ap::new();
    let conn = ap.conn();
    let (answer, _) = ap.admin_from(0, conn, json!({ "op": "approver_reset" }));
    assert_eq!(answer["result"]["removed"], json!(0), "{answer}");
    assert_eq!(
        ap.gw.reasons(AuditEventType::AgentApproverRemoved),
        ["reset: no approver device was registered"]
    );
}

/// A management change sent to the approvers is recorded with its type and
/// the credential it is about.
#[test]
fn a_management_request_is_recorded_with_its_type_and_credential() {
    let (mut ap, mut phone, id, _token) = paired();
    let conn = ap.conn();
    let (_, _unfreeze) = ap.admin_from(0, conn, json!({ "op": "unfreeze", "id": id }));
    let conn = ap.conn();
    let (_, _issue) = ap.admin_from(
        0,
        conn,
        json!({ "op": "issue", "name": "new", "uid": OTHER, "grant": nostr_grant(ap.gw.key) }),
    );
    let requests = ap.requests(&mut phone);
    let issued = keep_approval::change::Change::parse(&requests[1].payload["change"]).unwrap();
    let keep_approval::change::Change::IssueCredential { id: new_id, .. } = issued else {
        panic!("not an issue change");
    };
    let requested = ap.gw.reasons(AuditEventType::AgentApprovalRequested);
    assert!(
        requested[0].ends_with(&format!("type unfreeze credential {id}")),
        "{requested:?}"
    );
    assert!(
        requested[1].ends_with(&format!(
            "type issue_credential credential {}",
            new_id.to_hex()
        )),
        "{requested:?}"
    );
}

/// The agent's own requests that expire or that it withdraws are charged to
/// its audit budget: spending it that way freezes it like any other entry.
#[test]
fn expired_and_withdrawn_requests_count_against_the_agents_audit_budget() {
    let (mut ap, mut phone, id, token) = paired_with_budgets((3, 1_000));
    let mut pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let _ = ap.requests(&mut phone);
    ap.gw.boot.advance(120);
    ap.gw.state.approval_tick();
    assert!(!unanswered(&mut pending));
    let decided = |ap: &Ap| -> Vec<keep_core::audit::AuditEntry> {
        ap.gw.entries(AuditEventType::AgentApprovalDecided)
    };
    let expired = decided(&ap);
    assert_eq!(expired.len(), 1);
    let text = expired[0].reason.clone().unwrap_or_default();
    assert!(
        text.starts_with(&format!("agent {id} approval expired")) && text.contains("expired"),
        "{text}"
    );
    assert!(!ap.frozen(&id));
    // The withdrawal finds the budget used up: the credential is frozen,
    // and the end is still written, as the owner's.
    let pending = ap.park(&token, 2, "sign_nostr_event", kind0());
    ap.gw.state.cancel_parked(pending.request_id.unwrap());
    assert!(ap.frozen(&id), "the withdrawal was not charged");
    assert_eq!(ap.epoch(), 1);
    let ended = decided(&ap);
    assert_eq!(ended.len(), 2);
    let text = ended[1].reason.clone().unwrap_or_default();
    assert!(
        text.starts_with(&format!("agent {id} approval withdrawn: request ")),
        "{text}"
    );
}

/// A freeze of everything, from the device being removed or any other,
/// leaves a waiting `remove_approver` in place, so a stolen phone cannot
/// hold off its own removal.
#[test]
fn a_freeze_of_everything_leaves_a_waiting_removal_of_an_approver() {
    let (mut ap, mut first, _, _) = paired();
    let mut second = Phone::new();
    ap.add_device(&mut first, &mut second);
    let conn = ap.conn();
    let (_, mut pending) = ap.admin_from(
        0,
        conn,
        json!({ "op": "approver_remove", "transport": hex::encode(first.t()) }),
    );
    let request = ap.requests(&mut second).pop().unwrap();
    for _ in 0..3 {
        let freeze = first.freeze(Scope::All, ap.epoch());
        ap.deliver_from(&first, kind::FREEZE, &freeze);
    }
    assert!(ap.gw.state.keep().agent_freeze().unwrap());
    assert!(unanswered(pending.as_mut().unwrap()));
    ap.deliver_from(
        &second,
        kind::DECISION,
        &second.decide(&request, Verdict::Approve),
    );
    assert_eq!(reply(pending.unwrap())["ok"], json!(true));
    let devices = ap.store().devices;
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].transport.0, second.t());
}

/// The grant an approved `issue_credential` issues is the one its approver
/// was shown, or nothing is issued.
#[test]
fn an_issue_whose_grant_is_not_the_one_shown_issues_nothing() {
    let (mut ap, mut phone, _, _) = paired();
    let conn = ap.conn();
    let (_, pending) = ap.admin_from(
        0,
        conn,
        json!({ "op": "issue", "name": "swapped", "uid": OTHER, "grant": nostr_grant(ap.gw.key) }),
    );
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.gw.state.change_waiting_grants_for_testing(|g| {
        g.event_kinds.insert(30_023);
    });
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let answer = reply(pending.unwrap());
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert!(answer["error"]
        .as_str()
        .unwrap()
        .contains("not the one approved"));
    let listed = ap.gw.admin_ok(json!({ "op": "list" }));
    assert!(!listed
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == json!("swapped")));
    assert_eq!(ap.outcomes(&mut phone)[0].outcome, OutcomeKind::Canceled);
}

/// A decision counts only under the approver key of the device whose
/// transport key sealed it, even when the signing key is another registered
/// device's.
#[test]
fn a_decision_counts_only_under_the_sealing_devices_approver_key() {
    let (mut ap, mut first, _, token) = paired();
    let mut second = Phone::new();
    ap.add_device(&mut first, &mut second);
    let mut pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let request = ap.requests(&mut first).pop().unwrap();
    ap.deliver_from(
        &first,
        kind::DECISION,
        &first.decide_as(&second.approver, &request, Verdict::Approve),
    );
    ap.deliver_from(
        &second,
        kind::DECISION,
        &second.decide_as(&first.approver, &request, Verdict::Approve),
    );
    assert!(unanswered(&mut pending));
    ap.deliver_from(
        &second,
        kind::DECISION,
        &second.decide(&request, Verdict::Approve),
    );
    assert!(!tool_text(&reply(pending)).1);
}

/// An unfreeze of everything clears the gateway-wide freeze only: a
/// credential frozen on its own stays frozen.
#[test]
fn an_unfreeze_of_everything_leaves_credential_freezes_in_place() {
    let (mut ap, mut phone, id, token) = paired();
    let cid = Hex16(cid_of(&id));
    for (scope, epoch) in [(Scope::Credential(cid), 0), (Scope::All, 1)] {
        let freeze = phone.freeze(scope, epoch);
        ap.deliver_from(&phone, kind::FREEZE, &freeze);
    }
    let unfreeze = phone.unfreeze(Scope::All, 2);
    ap.deliver_from(&phone, kind::FREEZE, &unfreeze);
    assert!(!ap.gw.state.keep().agent_freeze().unwrap());
    assert!(ap.frozen(&id));
    let answer = ap.gw.rpc(
        &token,
        "tools/call",
        json!({ "name": "get_nostr_pubkey", "arguments": {} }),
    );
    assert!(answer.get("error").is_some(), "{answer}");
}

/// The last approver may be removed through `remove_approver`, approved by
/// itself: approvals are then off, and requests that need one are refused
/// as before.
#[test]
fn the_last_approver_approves_its_own_removal() {
    let (mut ap, mut phone, _, token) = paired();
    let conn = ap.conn();
    let (_, pending) = ap.admin_from(
        0,
        conn,
        json!({ "op": "approver_remove", "transport": hex::encode(phone.t()) }),
    );
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    assert_eq!(reply(pending.unwrap())["ok"], json!(true));
    let store = ap.store();
    assert!(store.devices.is_empty());
    assert_eq!(store.channel, None);
    assert!(!ap.gw.state.approvals_active());
    let (text, error) = ap.gw.tool(&token, "sign_nostr_event", kind0());
    assert!(error);
    assert!(text.as_str().unwrap().contains("needs approval"), "{text}");
}

/// With two approvers, the one being removed may approve its own removal.
#[test]
fn a_device_approves_its_own_removal() {
    let (mut ap, mut first, _, _) = paired();
    let mut second = Phone::new();
    ap.add_device(&mut first, &mut second);
    let conn = ap.conn();
    let (_, pending) = ap.admin_from(
        0,
        conn,
        json!({ "op": "approver_remove", "transport": hex::encode(first.t()) }),
    );
    let request = ap.requests(&mut first).pop().unwrap();
    ap.deliver_from(
        &first,
        kind::DECISION,
        &first.decide(&request, Verdict::Approve),
    );
    assert_eq!(reply(pending.unwrap())["ok"], json!(true));
    let devices = ap.store().devices;
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].transport.0, second.t());
}

/// An approval is checked against the gateway-wide freeze as it is when
/// the decision comes, however that freeze was set.
#[test]
fn an_approval_after_a_freeze_of_everything_signs_nothing() {
    let (mut ap, mut phone, _, token) = paired();
    let pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.gw.state.keep_mut().set_agent_freeze(true).unwrap();
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    assert_eq!(
        tool_text(&reply(pending)),
        ("canceled: frozen".into(), true)
    );
}

/// An approval is checked against the keys reserved when the decision
/// comes: a grant that names a device registered since signs nothing.
#[test]
fn an_approval_for_a_grant_naming_a_key_reserved_since_signs_nothing() {
    let mut ap = Ap::new();
    let mut first = Phone::new();
    let mut second = Phone::new();
    let mut grant = nostr_grant(ap.gw.key);
    grant.nip44_peers.insert(second.t());
    let (_, token) = ap.issue(&grant);
    ap.pair_first(&mut first);
    let pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let request = ap.requests(&mut first).pop().unwrap();
    ap.add_device(&mut first, &mut second);
    ap.deliver_from(
        &first,
        kind::DECISION,
        &first.decide(&request, Verdict::Approve),
    );
    assert_eq!(
        tool_text(&reply(pending)),
        ("canceled: revoked".into(), true)
    );
}

/// An agent at its request limit can still withdraw what it asked for: the
/// cancellation is not counted against the limit, so the parked request
/// cannot go on to be approved and signed.
#[test]
fn an_agent_at_its_request_limit_still_withdraws_a_request() {
    let mut ap = Ap::new();
    let mut grant = nostr_grant(ap.gw.key);
    grant.limits.per_minute = 2;
    let (_, token) = ap.issue(&grant);
    let mut phone = Phone::new();
    ap.pair_first(&mut phone);
    let mut pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let limited = ap.gw.rpc(&token, "ping", json!({}));
    assert!(limited.get("result").is_some(), "{limited}");
    let limited = ap.gw.rpc(&token, "ping", json!({}));
    assert_eq!(limited["error"]["code"], json!(-32002), "{limited}");
    assert!(unanswered(&mut pending));
    ap.gw.send(
        AGENT,
        &token,
        json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": 1 } }),
    );
    let (text, error) = tool_text(&reply(pending));
    assert!(error && text.starts_with("canceled"), "{text}");
}

/// Deleting a frozen credential clears its freeze like an unfreeze: the
/// epoch moves and the anchors list it, so no phone takes the freeze
/// vanishing for a rollback.
#[test]
fn deleting_a_frozen_credential_is_explained_to_the_phones() {
    use keep_approval::approver::{AnchorTracker, CLEARED_GRACE_SECS};
    let (mut ap, mut phone, id, _token) = paired();
    let cid = Hex16(cid_of(&id));
    let freeze = phone.freeze(Scope::Credential(cid), 0);
    ap.deliver_from(&phone, kind::FREEZE, &freeze);
    assert_eq!(ap.epoch(), 1);
    let anchors = |ap: &mut Ap, phone: &mut Phone| -> Vec<Anchor> {
        ap.received(phone)
            .into_iter()
            .filter(|(k, _)| *k == kind::ANCHOR)
            .map(|(_, t)| wire::parse(&t).unwrap())
            .collect()
    };
    let frozen = anchors(&mut ap, &mut phone).pop().expect("an anchor");
    assert_eq!(frozen.frozen.credentials, [cid]);
    let mut tracker = AnchorTracker::default();
    assert!(tracker
        .observe(frozen.at, &frozen.anchor, Some(&frozen.frozen), 0)
        .is_empty());
    ap.gw.boot.advance(1);
    let conn = ap.conn();
    let (answer, _) = ap.admin_from(0, conn, json!({ "op": "delete", "id": id }));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!(ap.epoch(), 2);
    let after = anchors(&mut ap, &mut phone).pop().expect("an anchor");
    assert!(after.frozen.credentials.is_empty());
    assert!(after
        .frozen
        .unfrozen
        .iter()
        .any(|u| u.scope == Scope::Credential(cid) && u.epoch == 2));
    assert!(tracker
        .observe(after.at, &after.anchor, Some(&after.frozen), 10)
        .is_empty());
    assert!(tracker.due_alerts(10 + CLEARED_GRACE_SECS).is_empty());
}

/// An agent its uid's request limit refuses can still withdraw its parked
/// request with its token: the cancellation is neither refused by that limit
/// nor counted against it. Anything else past the limit is refused and
/// counted, at most one credential row read and never every credential
/// checked: another uid naming the request's id, the right uid with another
/// token, a cancellation of nothing, and one on a line too long (which the
/// bridge never sends).
#[test]
fn an_agent_at_its_uids_request_limit_still_withdraws_a_request() {
    let mut gw = Gw::with(super::state::Settings {
        uid_limits: crate::policy::RequestLimits {
            per_minute: 3,
            per_hour: 1_000,
            per_day: 10_000,
        },
        ..super::tests::settings()
    });
    gw.state
        .configure_approvals(Some(channel()), vec![RELAY.into()], 120)
        .unwrap();
    let link = gw.state.take_relay_link().unwrap();
    let mut ap = Ap {
        gw,
        link,
        next_conn: 1,
    };
    let (_, token) = ap.issue(&nostr_grant(ap.gw.key));
    let (_, other) = ap.gw.issue(&nostr_grant(ap.gw.key), OTHER);
    let mut phone = Phone::new();
    ap.pair_first(&mut phone);
    let mut pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    for uid_token in [&token, &other] {
        for _ in 0..3 {
            let line = json!({ "token": uid_token, "message": { "jsonrpc": "2.0", "id": 7, "method": "ping" } });
            let uid = if uid_token == &token { AGENT } else { OTHER };
            ap.gw.raw(uid, &line.to_string());
        }
    }
    let limited = ap.gw.rpc(&token, "ping", json!({}));
    assert_eq!(
        limited["error"]["code"],
        json!(super::state::REFUSED_CODE),
        "{limited}"
    );
    let cancel = |token: &str, id: u64| {
        json!({ "token": token, "message": {
            "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": id }
        }})
        .to_string()
    };
    // Refused, unanswered as a notification is, and not authenticated, so
    // a connection's refusals in a row still count it.
    let refused = |ap: &mut Ap, uid: u32, line: &str| {
        assert_eq!(ap.gw.raw(uid, line), (None, false), "{line}");
    };
    refused(&mut ap, OTHER, &cancel(&other, 1));
    refused(&mut ap, AGENT, &cancel(&token, 9));
    assert_eq!(
        ap.gw.state.withdrawal_checks,
        (0, 0),
        "no credential was read"
    );
    refused(&mut ap, AGENT, &cancel(&other, 1));
    refused(&mut ap, AGENT, &cancel("nope", 1));
    assert_eq!(ap.gw.state.withdrawal_checks, (1, 0), "one row, no scan");
    let long = json!({ "token": token, "message": {
        "jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": { "requestId": 1, "reason": "x".repeat(5_000) }
    }})
    .to_string();
    // Too long to be taken for one, so refused as any line is.
    let (answer, authenticated) = ap.gw.raw(AGENT, &long);
    assert_eq!(
        answer.unwrap()["error"]["code"],
        json!(super::state::REFUSED_CODE)
    );
    assert!(!authenticated);
    assert!(unanswered(&mut pending));

    assert_eq!(ap.gw.raw(AGENT, &cancel(&token, 1)), (None, true));
    assert_eq!(ap.gw.state.withdrawal_checks, (2, 1));
    let (text, error) = tool_text(&reply(pending));
    assert!(error && text.starts_with("canceled"), "{text}");
}

/// A revoke or a delete that fails still cancels what the credential waits
/// for, so nothing of it can be approved and signed afterwards.
#[test]
fn a_failed_revoke_or_delete_still_cancels_what_the_credential_waits_for() {
    for op in ["revoke", "delete"] {
        let (mut ap, _phone, id, token) = paired();
        let mut pending = ap.park(&token, 1, "sign_nostr_event", kind0());
        assert!(unanswered(&mut pending));
        ap.gw.state.keep_mut().lock();
        let answer = ap.gw.admin(json!({ "op": op, "id": id }));
        assert_eq!(answer["ok"], json!(false), "{op}: {answer}");
        let (text, error) = tool_text(&reply(pending));
        assert!(error && text.starts_with("canceled"), "{op}: {text}");
    }
}

/// The last anchor `phone` received since the last call.
fn last_anchor(ap: &mut Ap, phone: &mut Phone) -> Option<Anchor> {
    ap.received(phone)
        .into_iter()
        .rfind(|(k, _)| *k == kind::ANCHOR)
        .map(|(_, t)| wire::parse(&t).unwrap())
}

/// A credential row that cannot be read stops neither pairing nor the
/// anchors: it is shown frozen, since it serves no agent.
#[test]
fn an_unreadable_credential_is_shown_frozen_and_anchors_go_on() {
    let mut ap = Ap::new();
    let (id, _) = ap.issue(&nostr_grant(ap.gw.key));
    let bad = [0xee; 16];
    ap.gw
        .state
        .keep()
        .misplace_agent_credential_for_testing(&cid_of(&id), &bad)
        .unwrap();
    let mut phone = Phone::new();
    ap.pair_first(&mut phone);
    ap.gw.boot.advance(super::approvals::ANCHOR_EVERY_SECS);
    ap.gw.state.approval_tick();
    let anchor = last_anchor(&mut ap, &mut phone).expect("an anchor");
    assert_eq!(anchor.frozen.credentials, [Hex16(bad)]);
}

/// With approvals off, a freeze from the admin socket keeps the approval
/// state the vault holds, and owed entries are still written.
#[test]
fn with_approvals_off_a_freeze_keeps_the_approval_state_and_owed_entries_are_written() {
    use crate::approval::OwedEntry;
    use keep_approval::messages::LogPoint;
    let mut gw = Gw::new();
    let store = Store {
        owed: vec![OwedEntry {
            event: AuditEventType::AgentApproverRemoved,
            reason: "owed from before".into(),
            more: 0,
        }],
        last_anchor: Some(LogPoint {
            seq: 5,
            head: Hex32([3; 32]),
        }),
        denials: [(Hex16([4; 16]), vec![1])].into(),
        ..Store::default()
    };
    store.save(gw.state.keep_mut()).unwrap();
    gw.admin_ok(json!({ "op": "freeze_all" }));
    assert_eq!(Store::load(gw.state.keep()).unwrap(), store);
    gw.state.approval_tick();
    let after = Store::load(gw.state.keep()).unwrap();
    assert!(after.owed.is_empty());
    assert_eq!(after.last_anchor, store.last_anchor);
    assert_eq!(after.denials, store.denials);
    assert_eq!(
        gw.reasons(AuditEventType::AgentApproverRemoved),
        ["owed from before"]
    );
}

/// A device is registered once it is saved, though its entry has to wait
/// for the log: the entry is kept owed with it and written later.
#[test]
fn a_device_is_registered_though_its_entry_waits_for_the_log() {
    let mut ap = Ap::new();
    let mut phone = Phone::new();
    // Nothing owed yet: the timer stops looking until something is.
    ap.gw.state.approval_tick();
    ap.gw.break_log(true);
    ap.pair_first(&mut phone);
    let store = ap.store();
    assert_eq!(store.devices.len(), 1);
    assert_eq!(store.owed.len(), 1);
    ap.gw.break_log(false);
    ap.gw.state.approval_tick();
    assert_eq!(ap.gw.reasons(AuditEventType::AgentApproverAdded).len(), 1);
    assert!(ap.store().owed.is_empty());
}

/// A removal and a reset are made though their entries have to wait for
/// the log.
#[test]
fn a_removal_and_a_reset_are_made_though_their_entries_wait_for_the_log() {
    let (mut ap, mut phone, _, _) = paired();
    let conn = ap.conn();
    let (_, pending) = ap.admin_from(
        0,
        conn,
        json!({ "op": "approver_remove", "transport": hex::encode(phone.t()) }),
    );
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.gw.break_log(true);
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    assert_eq!(reply(pending.unwrap())["ok"], json!(true));
    assert!(ap.store().devices.is_empty());
    let (answer, _) = ap.admin_from(0, conn, json!({ "op": "approver_reset" }));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    ap.gw.break_log(false);
    ap.gw.state.approval_tick();
    let removed = ap.gw.reasons(AuditEventType::AgentApproverRemoved);
    assert_eq!(removed.len(), 2, "{removed:?}");
    assert!(removed[0].starts_with("label "));
    assert!(removed[1].starts_with("reset: no approver"));
    assert!(ap.store().owed.is_empty());
}

/// A freeze already in effect is not recorded again, though it moves the
/// epoch and saves the counter, and is answered with the state; past the
/// rate, a device's freezes are dropped until the minute is over.
#[test]
fn a_freeze_already_in_effect_is_not_recorded_again_and_a_flood_is_cut_off() {
    use super::approvals::FREEZES_PER_MINUTE;
    let (mut ap, mut phone, _, _) = paired();
    let freeze = phone.freeze(Scope::All, 0);
    ap.deliver_from(&phone, kind::FREEZE, &freeze);
    assert_eq!(ap.epoch(), 1);
    let _ = ap.received(&mut phone);
    for _ in 1..FREEZES_PER_MINUTE {
        let again = phone.freeze(Scope::All, 1);
        ap.deliver_from(&phone, kind::FREEZE, &again);
    }
    assert_eq!(ap.gw.reasons(AuditEventType::AgentApproverFreeze).len(), 1);
    assert_eq!(ap.epoch(), u64::from(FREEZES_PER_MINUTE));
    assert_eq!(ap.store().devices[0].counter, u64::from(FREEZES_PER_MINUTE));
    let anchors = ap
        .received(&mut phone)
        .iter()
        .filter(|(k, _)| *k == kind::ANCHOR)
        .count();
    assert_eq!(anchors as u32, FREEZES_PER_MINUTE - 1);
    let over = phone.freeze(Scope::All, 1);
    ap.deliver_from(&phone, kind::FREEZE, &over);
    assert!(last_anchor(&mut ap, &mut phone).is_none());
    ap.gw.boot.advance(60);
    let later = phone.freeze(Scope::All, 1);
    ap.deliver_from(&phone, kind::FREEZE, &later);
    assert!(last_anchor(&mut ap, &mut phone).is_some());
}

/// A phone whose addition is denied is told it was refused.
#[test]
fn a_phone_whose_addition_is_denied_is_told_it_was_refused() {
    let (mut ap, mut first, _, _) = paired();
    let mut second = Phone::new();
    let conn = ap.conn();
    let (answer, pending) =
        ap.admin_from(0, conn, json!({ "op": "approver_pair", "label": "Tablet" }));
    let uri = PairingUri::parse(answer["result"]["uri"].as_str().unwrap()).unwrap();
    assert!(ap.deliver(&second.pair(&uri.secret, ap.now())));
    let _ = reply(pending.unwrap());
    let (_, pending) = ap.admin_from(0, conn, json!({ "op": "approver_confirm" }));
    let request = ap.requests(&mut first).pop().unwrap();
    ap.deliver_from(
        &first,
        kind::DECISION,
        &first.decide(&request, Verdict::Deny),
    );
    assert_eq!(reply(pending.unwrap())["ok"], json!(false));
    assert!(refused(&mut ap, &mut second));
    assert_eq!(ap.store().devices.len(), 1);
}

/// Whether `phone` was sent a pairing `refused` since the last call.
fn refused(ap: &mut Ap, phone: &mut Phone) -> bool {
    ap.received(phone).iter().any(|(k, t)| {
        *k == kind::PAIRING && matches!(wire::parse::<Pairing>(t), Ok(Pairing::Refused { .. }))
    })
}

/// An approved issue is checked again when it is carried out: a key
/// deleted from the vault while it waited is not issued.
#[test]
fn an_approved_issue_of_a_key_deleted_meanwhile_issues_nothing() {
    let (mut ap, mut phone, _, _) = paired();
    let conn = ap.conn();
    let (_, pending) = ap.admin_from(
        0,
        conn,
        json!({ "op": "issue", "name": "late", "uid": OTHER, "grant": nostr_grant(ap.gw.key) }),
    );
    let request = ap.requests(&mut phone).pop().unwrap();
    let key = ap.gw.key;
    ap.gw.state.keep_mut().delete_key(&key).unwrap();
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let answer = reply(pending.unwrap());
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert!(
        answer["error"]
            .as_str()
            .unwrap()
            .contains("not in the vault"),
        "{answer}"
    );
}

/// A credential row that cannot be read can be deleted, as a frozen one:
/// the epoch moves and the phones are told why the freeze went.
#[test]
fn an_unreadable_credential_can_be_deleted() {
    let (mut ap, mut phone, id, _) = paired();
    let bad = [0xee; 16];
    ap.gw
        .state
        .keep()
        .misplace_agent_credential_for_testing(&cid_of(&id), &bad)
        .unwrap();
    let _ = ap.received(&mut phone);
    let answer = ap
        .gw
        .admin(json!({ "op": "delete", "id": hex::encode(bad) }));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!(ap.epoch(), 1);
    let anchor = last_anchor(&mut ap, &mut phone).expect("an anchor");
    assert!(anchor
        .frozen
        .unfrozen
        .iter()
        .any(|u| u.scope == Scope::Credential(Hex16(bad))));
    assert!(!anchor.frozen.credentials.contains(&Hex16(bad)));
}

/// A freeze of what is frozen already still moves the epoch and saves the
/// device's counter, so an unfreeze signed before it, by that device or
/// another, and held back until after it, is refused.
#[test]
fn a_held_back_unfreeze_is_refused_after_a_repeat_freeze() {
    let (mut ap, mut first, _, _) = paired();
    let mut second = Phone::new();
    ap.add_device(&mut first, &mut second);
    let freeze = first.freeze(Scope::All, 0);
    ap.deliver_from(&first, kind::FREEZE, &freeze);
    assert_eq!(ap.epoch(), 1);
    let held_first = first.unfreeze(Scope::All, 1);
    let held_second = second.unfreeze(Scope::All, 1);
    let again = first.freeze(Scope::All, 1);
    ap.deliver_from(&first, kind::FREEZE, &again);
    assert_eq!(ap.epoch(), 2);
    assert_eq!(ap.store().device(&first.t()).unwrap().counter, 3);
    assert_eq!(ap.gw.reasons(AuditEventType::AgentApproverFreeze).len(), 1);
    ap.deliver_from(&second, kind::FREEZE, &held_second);
    assert!(ap.gw.state.keep().agent_freeze().unwrap());
    ap.deliver_from(&first, kind::FREEZE, &held_first);
    assert!(ap.gw.state.keep().agent_freeze().unwrap());
}

/// A reset forgets the devices in the gateway as well as in the vault: the
/// removed phone's messages are no longer opened, and no later save brings
/// it back.
#[test]
fn a_reset_forgets_the_devices_in_the_running_gateway() {
    let (mut ap, mut phone, _, _) = paired();
    let (answer, _) = ap.admin_from(0, 7, json!({ "op": "approver_reset" }));
    assert_eq!(answer["result"]["removed"], json!(1), "{answer}");
    let freeze = phone.freeze(Scope::All, 0);
    assert!(!ap.deliver_from(&phone, kind::FREEZE, &freeze));
    ap.gw.admin_ok(json!({ "op": "freeze_all" }));
    assert!(ap.store().devices.is_empty());
    let _ = ap.received(&mut phone);
}

/// A frozen credential is deleted though the epoch cannot be read: the
/// vault seeds a new one, and the phones are told the freeze went with it.
#[test]
fn a_frozen_credential_is_deleted_though_the_epoch_cannot_be_read() {
    let (mut ap, mut phone, id, _) = paired();
    let cid = Hex16(cid_of(&id));
    let freeze = phone.freeze(Scope::Credential(cid), 0);
    ap.deliver_from(&phone, kind::FREEZE, &freeze);
    ap.gw
        .state
        .keep()
        .corrupt_agent_freeze_epoch_for_testing()
        .unwrap();
    let _ = ap.received(&mut phone);
    let answer = ap.gw.admin(json!({ "op": "delete", "id": id }));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    let seeded = ap.epoch();
    let unfrozen = ap.store().recent_unfreezes(ap.now());
    assert!(
        unfrozen
            .iter()
            .any(|u| u.scope == Scope::Credential(cid) && u.epoch == seeded),
        "{unfrozen:?} {seeded}"
    );
    let anchor = last_anchor(&mut ap, &mut phone).expect("an anchor");
    assert_eq!(anchor.frozen.epoch, seeded);
}

/// A grant's secrets go to the approver named, with their rules, and the
/// credential is issued only while each is still the secret it was shown.
#[test]
fn issuing_with_secrets_shows_them_and_checks_them_again_when_approved() {
    use super::tests::{secret_entry, secrets_grant, store_secret};
    use keep_core::secret::SecretKind;
    let (mut ap, mut phone, _, _) = paired();
    let id = store_secret(&mut ap.gw, "deploy token", SecretKind::ApiToken);
    let grant = secrets_grant(vec![secret_entry(json!({ "name": "deploy token" }), "/v1")]);

    let conn = ap.conn();
    let (answer, pending) = ap.admin_from(
        0,
        conn,
        json!({ "op": "issue", "name": "deployer", "uid": OTHER, "grant": grant.clone() }),
    );
    assert!(answer["pending"].is_string(), "{answer}");
    let request = ap.requests(&mut phone).pop().unwrap();
    let keep_approval::change::Change::IssueCredential { grant: shown, .. } =
        keep_approval::change::Change::parse(&request.payload["change"]).unwrap()
    else {
        panic!("not an issue change");
    };
    assert_eq!(shown.operations, ["http_request"]);
    assert_eq!(shown.secrets.len(), 1);
    assert_eq!(shown.secrets[0].secret, Hex32(id));
    assert_eq!(shown.secrets[0].name, "deploy token");
    assert_eq!(shown.secrets[0].kind, "api_token");
    assert_eq!(shown.secrets[0].http[0].path_prefix, "/v1");
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let answer = reply(pending.unwrap());
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!(
        answer["result"]["grant"]["secrets"][0]["secret"],
        json!(hex::encode(id))
    );

    // Renamed while waiting: not the secret the approver saw, so not issued.
    let conn = ap.conn();
    let (_, pending) = ap.admin_from(
        0,
        conn,
        json!({ "op": "issue", "name": "renamed", "uid": OTHER, "grant": grant }),
    );
    let request = ap.requests(&mut phone).pop().unwrap();
    let mut record = ap.gw.state.keep().load_secret(&id).unwrap();
    record.name = "something else".into();
    ap.gw.state.keep_mut().store_secret(&record).unwrap();
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    let answer = reply(pending.unwrap());
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert!(
        answer["error"]
            .as_str()
            .unwrap()
            .contains("not the one approved"),
        "{answer}"
    );

    // Deleted while waiting: the same.
    let conn = ap.conn();
    let grant = secrets_grant(vec![secret_entry(json!(hex::encode(id)), "/v1")]);
    let (_, pending) = ap.admin_from(
        0,
        conn,
        json!({ "op": "issue", "name": "deleted", "uid": OTHER, "grant": grant }),
    );
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.gw.state.keep_mut().delete_secret(&id).unwrap();
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide(&request, Verdict::Approve),
    );
    assert_eq!(reply(pending.unwrap())["ok"], json!(false));
    let names: Vec<Value> = ap
        .gw
        .admin_ok(json!({ "op": "list" }))
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].clone())
        .collect();
    assert!(names.contains(&json!("deployer")));
    assert!(!names.contains(&json!("renamed")) && !names.contains(&json!("deleted")));
}
