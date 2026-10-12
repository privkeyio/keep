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
    self as wire, Anchor, Decision, Freeze, FreezeAction, Outcome, OutcomeKind, Pairing, Request,
    Verdict, V1,
};
use keep_approval::pairing::PairingUri;
use keep_approval::sig;
use keep_approval::wrap::{self, Candidate, SeenWraps, TagKey};
use keep_approval::{kind, Hex16, Hex32, Hex64};
use keep_core::audit::AuditEventType;
use nostr_sdk::prelude::{Event, Keys, SecretKey};
use serde_json::{json, Value};

use super::approvals::{RelayLink, Store, MAX_PARKED};
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
    pub(super) approver: Keys,
    pub(super) channel: [u8; 32],
    seen: SeenWraps,
    counter: u64,
}

impl Phone {
    pub(super) fn new() -> Self {
        Self {
            transport: Keys::generate(),
            approver: Keys::generate(),
            channel: channel().public_key().to_bytes(),
            seen: SeenWraps::default(),
            counter: 0,
        }
    }

    pub(super) fn t(&self) -> [u8; 32] {
        sig::xonly(&self.transport)
    }

    pub(super) fn a(&self) -> [u8; 32] {
        sig::xonly(&self.approver)
    }

    /// A wrap of `content` to the gateway, sealed by the transport key and
    /// tagged for the channel key.
    pub(super) fn wrap(&self, kind: u16, content: &str, now: u64) -> Event {
        let tag = TagKey::for_peer(&self.transport, &self.channel).unwrap();
        wrap::wrap(&self.transport, &self.channel, &tag, kind, content, now).unwrap()
    }

    /// What the gateway sent this phone, opened, in order.
    pub(super) fn open(&mut self, events: &[Event], now: u64) -> Vec<(u16, String)> {
        let candidates = [Candidate {
            id: (),
            tag_key: TagKey::for_peer(&self.transport, &self.channel).unwrap(),
            sender: Some(self.channel),
        }];
        events
            .iter()
            .filter_map(|e| wrap::open(&self.transport, e, &candidates, &mut self.seen, now).ok())
            .map(|o| (o.kind, o.content))
            .collect()
    }

    /// The `pair` message for a pairing session with `secret`.
    pub(super) fn pair(&self, secret: &[u8; 32], now: u64) -> Event {
        let (t, a) = (self.t(), self.a());
        let message = Pairing::Pair {
            v: V1,
            label: "My phone".into(),
            approver: Hex32(a),
            proof: sig::pair_proof(secret, &self.channel, &t, &a),
            approver_sig: sig::sign(
                &self.approver,
                &sig::pair_approver_digest(&self.channel, &t, &a),
            ),
        };
        let tag = TagKey::for_pairing(secret);
        wrap::wrap(
            &self.transport,
            &self.channel,
            &tag,
            kind::PAIRING,
            &wire::to_text(&message),
            now,
        )
        .unwrap()
    }

    /// A decision on `request`, signed by `signer`.
    pub(super) fn decide_as(&self, signer: &Keys, request: &Request, verdict: Verdict) -> String {
        let digest = sig::decision_digest(
            &self.channel,
            &sig::xonly(signer),
            &request.request_hash.0,
            verdict,
        );
        wire::to_text(&Decision {
            v: V1,
            request_id: request.request_id,
            request_hash: request.request_hash,
            decision: verdict,
            sig: sig::sign(signer, &digest),
        })
    }

    pub(super) fn decide(&self, request: &Request, verdict: Verdict) -> String {
        self.decide_as(&self.approver, request, verdict)
    }

    /// A freeze or unfreeze with the next counter, signed by `signer`.
    pub(super) fn freeze_as(
        &mut self,
        signer: &Keys,
        action: FreezeAction,
        scope: Scope,
        epoch: u64,
    ) -> String {
        self.counter += 1;
        let digest = sig::freeze_digest(
            &self.channel,
            &sig::xonly(signer),
            self.counter,
            epoch,
            action,
            scope,
        );
        wire::to_text(&Freeze {
            v: V1,
            action,
            scope,
            counter: self.counter,
            epoch,
            signer: Hex32(sig::xonly(signer)),
            sig: sig::sign(signer, &digest),
        })
    }

    pub(super) fn freeze(&mut self, scope: Scope, epoch: u64) -> String {
        let t = self.transport.clone();
        self.freeze_as(&t, FreezeAction::Freeze, scope, epoch)
    }

    pub(super) fn unfreeze(&mut self, scope: Scope, epoch: u64) -> String {
        let a = self.approver.clone();
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
        while let Ok(e) = self.link.outbox.try_recv() {
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

    fn store(&self) -> Store {
        Store::load(self.gw.state.keep()).unwrap()
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
    assert_eq!(outcome.by, Some(Hex32(phone.a())));
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
    let store = ap.store();
    assert_eq!(store.epoch, 1);
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
    assert_eq!(ap.store().epoch, 2);
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
fn one_request_waits_per_credential_and_sixteen_in_all() {
    let mut ap = Ap::new();
    let mut tokens = Vec::new();
    for _ in 0..=MAX_PARKED {
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
    for token in &tokens[1..MAX_PARKED] {
        parked.push(ap.park(token, 1, "sign_nostr_event", kind0()));
    }
    let (text, error) = ap.gw.tool(&tokens[MAX_PARKED], "sign_nostr_event", kind0());
    assert!(error);
    assert!(
        text.as_str().unwrap().contains("too many requests"),
        "{text}"
    );
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
    assert_eq!(ap.store().epoch, 1);
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
    let a = phone.approver.clone();
    let t = phone.transport.clone();
    let bad_freeze = phone.freeze_as(&a, FreezeAction::Freeze, Scope::All, 0);
    ap.deliver_from(&phone, kind::FREEZE, &bad_freeze);
    assert_eq!(ap.store().epoch, 0);
    let bad_unfreeze = phone.freeze_as(&t, FreezeAction::Unfreeze, Scope::All, 0);
    ap.deliver_from(&phone, kind::FREEZE, &bad_unfreeze);
    assert_eq!(ap.store().epoch, 0);
    // A decision signed by the transport key.
    let mut pending = ap.park(&token, 1, "sign_nostr_event", kind0());
    let request = ap.requests(&mut phone).pop().unwrap();
    ap.deliver_from(
        &phone,
        kind::DECISION,
        &phone.decide_as(&t, &request, Verdict::Approve),
    );
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
    assert_eq!(ap.store().epoch, 2);
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
        let (t, a) = (phone.t(), phone.a());
        let message = Pairing::Pair {
            v: V1,
            label: "x".into(),
            approver: Hex32(a),
            proof: sig::pair_proof(secret, &phone.channel, &t, &a),
            approver_sig: sig::sign(
                &Keys::generate(),
                &sig::pair_approver_digest(&phone.channel, &t, &a),
            ),
        };
        let tag = TagKey::for_pairing(secret);
        wrap::wrap(
            &phone.transport,
            &phone.channel,
            &tag,
            kind::PAIRING,
            &wire::to_text(&message),
            now,
        )
        .unwrap()
    });
    assert_eq!(shown["ok"], json!(false), "{shown}");
    // A signature over other keys.
    let shown = try_pair(&mut ap, &|phone, secret, now| {
        let (t, a) = (phone.t(), phone.a());
        let message = Pairing::Pair {
            v: V1,
            label: "x".into(),
            approver: Hex32(a),
            proof: sig::pair_proof(secret, &phone.channel, &t, &a),
            approver_sig: sig::sign(
                &phone.approver,
                &sig::pair_approver_digest(&phone.channel, &[9; 32], &a),
            ),
        };
        let tag = TagKey::for_pairing(secret);
        wrap::wrap(
            &phone.transport,
            &phone.channel,
            &tag,
            kind::PAIRING,
            &wire::to_text(&message),
            now,
        )
        .unwrap()
    });
    assert_eq!(shown["ok"], json!(false));
    // The same key twice.
    let shown = try_pair(&mut ap, &|phone, secret, now| {
        let t = phone.t();
        let message = Pairing::Pair {
            v: V1,
            label: "x".into(),
            approver: Hex32(t),
            proof: sig::pair_proof(secret, &phone.channel, &t, &t),
            approver_sig: sig::sign(
                &phone.transport,
                &sig::pair_approver_digest(&phone.channel, &t, &t),
            ),
        };
        let tag = TagKey::for_pairing(secret);
        wrap::wrap(
            &phone.transport,
            &phone.channel,
            &tag,
            kind::PAIRING,
            &wire::to_text(&message),
            now,
        )
        .unwrap()
    });
    assert_eq!(shown["ok"], json!(false));
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
    let event = real.pair(&uri.secret, ap.now());
    ap.deliver(&event);
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
        let tag = TagKey::for_peer(&stranger, &channel_pub).unwrap();
        let event = wrap::wrap(
            &stranger,
            &channel_pub,
            &tag,
            kind::FREEZE,
            &format!("{i}"),
            now,
        )
        .unwrap();
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
    // A management change is still approved and recorded.
    let unfreeze = phone.unfreeze(Scope::All, 1);
    ap.deliver_from(&phone, kind::FREEZE, &unfreeze);
    assert!(!ap.gw.state.keep().agent_freeze().unwrap());
    assert_eq!(ap.gw.reasons(AuditEventType::AgentApproverFreeze).len(), 2);
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
    grant.nip44_peers.insert(second.a());
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
    assert!(anchor.anchor.wallets[0].wallet.starts_with("test:"));
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
    // The vault's own key as the approver key.
    let mut vaulted = Phone::new();
    vaulted.approver = Keys::new(SecretKey::from_slice(&super::tests::SECRET).unwrap());
    let shown = pair_with(&mut ap, &vaulted);
    assert_eq!(shown["ok"], json!(false));
    assert!(
        shown["error"].as_str().unwrap().contains("in the vault"),
        "{shown}"
    );
    // A key another device holds.
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
    // The channel key as a device key.
    let mut channelled = Phone::new();
    channelled.approver = channel();
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
