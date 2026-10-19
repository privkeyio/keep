// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap as Map;
use std::sync::atomic::AtomicBool;

use keep_approval::approver::{CLEARED_GRACE_SECS, FREEZE_SHOWN_SECS, SILENCE_SECS};
use keep_approval::binding::{
    Nip44DecryptPayload, NostrPayload, Payload, RequestDraft, UnsignedEventFields,
};
use keep_approval::change::Decimal;
use keep_approval::messages::{AnchorState, CredentialRef, Frozen, Reason};
use p256::ecdsa::signature::Signer;

use super::*;
use crate::storage::{SecureStorage, ShareMetadataInfo};

/// Start a `MockRelay`, retrying a start that lost the race for its port.
///
/// `nostr-relay-builder` picks a random free port by binding a probe listener
/// and dropping it before binding the address for real, so two starts racing in
/// this binary's parallel tests can pick the same port and the loser gets
/// `AddrInUse`. Each attempt is a fresh `MockRelay`, which is what draws a new
/// port: the chosen port is memoized per relay. Binding port 0 instead is not
/// an option, because the relay reports the address it was given, so its URL
/// would say port 0.
async fn start_mock_relay() -> nostr_relay_builder::MockRelay {
    let mut last = None;
    for _ in 0..8 {
        match nostr_relay_builder::MockRelay::run().await {
            Ok(relay) => return relay,
            Err(e) => last = Some(e),
        }
    }
    panic!("mock relay start: {}", last.expect("a failure to report"));
}

#[derive(Default)]
struct Memory(Mutex<Map<String, Vec<u8>>>, AtomicBool);

impl SecureStorage for Memory {
    fn store_share(&self, _: Vec<u8>, _: ShareMetadataInfo) -> Result<(), KeepMobileError> {
        Ok(())
    }
    fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
        Err(KeepMobileError::StorageNotFound)
    }
    fn has_share(&self) -> bool {
        false
    }
    fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
        None
    }
    fn delete_share(&self) -> Result<(), KeepMobileError> {
        Ok(())
    }
    fn store_share_by_key(
        &self,
        key: String,
        data: Vec<u8>,
        _: ShareMetadataInfo,
    ) -> Result<(), KeepMobileError> {
        if self.1.load(Ordering::SeqCst) {
            return Err(KeepMobileError::StorageError { msg: "full".into() });
        }
        self.0.lock().unwrap().insert(key, data);
        Ok(())
    }
    fn load_share_by_key(&self, key: String) -> Result<Vec<u8>, KeepMobileError> {
        self.0
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .ok_or(KeepMobileError::StorageNotFound)
    }
    fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
        Vec::new()
    }
    fn delete_share_by_key(&self, key: String) -> Result<(), KeepMobileError> {
        self.0.lock().unwrap().remove(&key);
        Ok(())
    }
    fn get_active_share_key(&self) -> Option<String> {
        None
    }
    fn set_active_share_key(&self, _: Option<String>) -> Result<(), KeepMobileError> {
        Ok(())
    }
}

struct Phone {
    handler: Arc<ApproverHandler>,
    mobile: Arc<KeepMobile>,
    memory: Arc<Memory>,
    channel: Keys,
    approver: p256::ecdsa::SigningKey,
}

/// A handler paired with a gateway whose channel key is `channel`.
fn paired() -> Phone {
    let memory = Arc::new(Memory::default());
    let storage: Arc<dyn SecureStorage> = memory.clone();
    let mobile = Arc::new(KeepMobile::new(storage).unwrap());
    let channel = Keys::generate();
    let approver = p256::ecdsa::SigningKey::from_slice(&[5u8; 32]).unwrap();
    let key: [u8; 33] = approver
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let stored = Stored {
        transport: Zeroizing::new(Keys::generate().secret_key().to_secret_hex()),
        approver: Hex33(key),
        label: "phone".into(),
        channel: Hex32(sig::xonly(&channel)),
        relays: vec!["wss://relay.example".into()],
        paired: true,
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
    let handler = ApproverHandler::new(mobile.clone()).unwrap();
    handler.persist(&stored).unwrap();
    handler.lock().set(Some(stored));
    Phone {
        handler,
        mobile,
        memory,
        channel,
        approver,
    }
}

fn anchor(seq: u64) -> AnchorState {
    AnchorState {
        seq,
        head: Hex32([seq as u8; 32]),
        prev: None,
        wallets: vec![],
    }
}

impl Phone {
    /// The app stopped and started again: a new handler on the same storage.
    fn reopen(self) -> Phone {
        let Phone {
            handler,
            mobile,
            memory,
            channel,
            approver,
        } = self;
        drop(handler);
        Phone {
            handler: ApproverHandler::new(mobile.clone()).unwrap(),
            mobile,
            memory,
            channel,
            approver,
        }
    }

    fn stored<T>(&self, f: impl FnOnce(&mut Stored) -> T) -> T {
        f(self.handler.lock().stored.as_mut().unwrap())
    }

    fn channel(&self) -> [u8; 32] {
        sig::xonly(&self.channel)
    }

    fn request(&self, id: u8, content: &str, seq: u64) -> Request {
        let key = self.channel();
        RequestDraft {
            request_id: [id; 32],
            created_at: now(),
            deadline_secs: 120,
            credential: Some(CredentialRef {
                id: Hex16([0x22; 16]),
                name: "writer".into(),
                uid: 1001,
            }),
            key: Some(key),
            network: None,
            reason: Reason::Kind { kind: 0 },
            payload: Payload::Nostr(NostrPayload {
                event: UnsignedEventFields {
                    pubkey: Hex32(key),
                    created_at: now(),
                    kind: 0,
                    tags: vec![vec!["p".into(), "aa".repeat(32)]],
                    content: content.into(),
                },
            }),
            budget: None,
            anchor: anchor(seq),
        }
        .finish(&key)
        .unwrap()
        .0
    }

    fn take(&self, kind: u16, content: &str) -> Vec<ApproverEvent> {
        let mut inner = self.handler.lock();
        self.handler.handle(&mut inner, kind, content, now()).events
    }

    fn sign(&self, digest: &[u8], high_s: bool) -> Vec<u8> {
        let sig: p256::ecdsa::Signature = self.approver.sign(digest);
        let sig = if high_s {
            let (r, s) = sig.split_scalars();
            p256::ecdsa::Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap()
        } else {
            sig
        };
        sig.to_der().as_bytes().to_vec()
    }
}

fn shown_request(events: &[ApproverEvent]) -> Option<&ApprovalRequest> {
    events.iter().find_map(|e| match e {
        ApproverEvent::Request { request } => Some(request),
        _ => None,
    })
}

#[test]
fn a_checked_request_is_shown_once_with_the_agents_words_apart() {
    let phone = paired();
    let request = phone.request(1, "hello\u{202e}world", 10);
    let text = wire::to_text(&request);
    let events = phone.take(kind::REQUEST, &text);
    let shown = shown_request(&events).expect("shown");
    assert_eq!(shown.op, "sign_nostr_event");
    assert_eq!(shown.credential.as_deref(), Some("writer"));
    assert!(shown.reason.contains("kind 0"));
    let content = shown.fields.iter().find(|f| f.label == "content").unwrap();
    assert!(content.by_agent);
    assert_eq!(content.value, "helloworld", "the bidi override removed");
    assert_eq!(content.removed, 1);
    let tag = shown.fields.iter().find(|f| f.label == "tag 0").unwrap();
    assert!(tag.by_agent);
    assert_eq!(tag.value, format!("[\"p\",\"{}\"]", "aa".repeat(32)));
    assert!(
        !shown
            .fields
            .iter()
            .find(|f| f.label == "kind")
            .unwrap()
            .by_agent
    );
    assert!(
        shown_request(&phone.take(kind::REQUEST, &text)).is_none(),
        "a replay is not shown again"
    );
}

#[test]
fn a_request_that_fails_a_check_is_refused_never_shown() {
    let phone = paired();
    let mut request = phone.request(2, "x", 10);
    request.request_hash = Hex32([9; 32]);
    let events = phone.take(kind::REQUEST, &wire::to_text(&request));
    assert!(shown_request(&events).is_none());
    assert!(events
        .iter()
        .any(|e| matches!(e, ApproverEvent::RequestRefused { .. })));
    // From another gateway: its hash binds another channel.
    let other = paired();
    let foreign = other.request(3, "x", 10);
    let events = phone.take(kind::REQUEST, &wire::to_text(&foreign));
    assert!(shown_request(&events).is_none());
    assert!(phone
        .take(kind::REQUEST, "not json")
        .iter()
        .any(|e| matches!(e, ApproverEvent::RequestRefused { .. })));
}

#[test]
fn a_decision_is_signed_only_for_a_waiting_request_by_the_approver_key() {
    let phone = paired();
    let request = phone.request(4, "x", 10);
    phone.take(kind::REQUEST, &wire::to_text(&request));
    let id = request.request_id.to_hex();
    assert!(phone
        .handler
        .decision_digest("00".repeat(32), true)
        .is_err());
    let digest = phone.handler.decision_digest(id, true).unwrap();
    let approver = phone.handler.lock().stored.as_ref().unwrap().approver;
    let digest32: [u8; 32] = digest.clone().try_into().unwrap();
    assert_eq!(
        digest32,
        sig::decision_digest(
            &phone.channel(),
            &approver.0,
            &request.request_hash.0,
            Verdict::Approve
        )
    );
    // A Keystore signature verifies whichever s it carries.
    for high_s in [false, true] {
        let raw = checked_signature(&phone.sign(&digest, high_s), &approver, &digest32).unwrap();
        sig::verify_p256(&approver.0, &digest32, &raw).unwrap();
    }
    // Another key's signature is found here, not at the gateway.
    let other = p256::ecdsa::SigningKey::from_slice(&[6u8; 32]).unwrap();
    let wrong: p256::ecdsa::Signature = other.sign(&digest);
    assert!(checked_signature(wrong.to_der().as_bytes(), &approver, &digest32).is_err());
    // Not running: nothing is sent, and the request still waits.
    let id = request.request_id.to_hex();
    assert!(phone
        .handler
        .send_decision(id.clone(), true, phone.sign(&digest, false))
        .is_err());
    assert_eq!(phone.handler.waiting_requests().len(), 1);
    // Signed for the other verdict: refused here.
    let deny = phone.handler.decision_digest(id.clone(), false).unwrap();
    let err = phone
        .handler
        .send_decision(id, true, phone.sign(&deny, false))
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("sign the digest for this request again"));
}

#[test]
fn a_decision_names_a_request_that_is_waiting() {
    let phone = paired();
    let request = phone.request(11, "x", 10);
    phone.take(kind::REQUEST, &wire::to_text(&request));
    let digest = phone
        .handler
        .decision_digest(request.request_id.to_hex(), true)
        .unwrap();
    let signature = phone.sign(&digest, false);
    for id in ["00".repeat(32), "nope".into(), "AB".repeat(32)] {
        assert!(phone.handler.decision_digest(id.clone(), true).is_err());
        assert!(phone
            .handler
            .send_decision(id, true, signature.clone())
            .is_err());
    }
    phone.stored(|s| {
        s.waiting[0].decided = true;
        s.waiting[0].request = None;
    });
    assert!(
        phone
            .handler
            .decision_digest(request.request_id.to_hex(), true)
            .is_err(),
        "decided once"
    );
    assert!(phone.handler.waiting_requests().is_empty());
}

#[test]
fn a_request_past_its_time_cannot_be_decided() {
    let phone = paired();
    let request = phone.request(5, "x", 10);
    phone.take(kind::REQUEST, &wire::to_text(&request));
    phone.stored(|s| s.waiting[0].until = now() - 1);
    assert!(phone
        .handler
        .decision_digest(request.request_id.to_hex(), true)
        .is_err());
}

#[test]
fn an_outcome_ends_a_request_once() {
    let phone = paired();
    let request = phone.request(6, "x", 10);
    phone.take(kind::REQUEST, &wire::to_text(&request));
    let outcome = wire::to_text(&Outcome {
        v: V1,
        request_id: request.request_id,
        outcome: OutcomeKind::Denied,
        by: None,
    });
    let events = phone.take(kind::OUTCOME, &outcome);
    assert!(matches!(
        &events[..],
        [ApproverEvent::Outcome { outcome, .. }] if outcome == "denied"
    ));
    assert!(phone.stored(|s| s.waiting.is_empty()));
    assert!(
        phone.take(kind::OUTCOME, &outcome).is_empty(),
        "a replay counts once"
    );
}

#[test]
fn anchors_are_tracked_and_a_rollback_alerts() {
    let phone = paired();
    let anchor_at = |at: u64, seq: u64, epoch: u64, all: bool| {
        wire::to_text(&Anchor {
            v: V1,
            at,
            anchor: anchor(seq),
            frozen: Frozen {
                epoch,
                all,
                credentials: vec![],
                unfrozen: vec![],
            },
        })
    };
    let t = now();
    let events = phone.take(kind::ANCHOR, &anchor_at(t, 100, 3, true));
    assert!(events.iter().any(|e| matches!(
        e,
        ApproverEvent::Anchor {
            epoch: 3,
            all_frozen: true,
            audit_seq: 100,
            ..
        }
    )));
    let status = phone.handler.status();
    assert_eq!(status.epoch, Some(3));
    assert!(status.all_frozen);
    let events = phone.take(kind::ANCHOR, &anchor_at(t + 60, 90, 3, true));
    assert!(
        events.iter().any(
            |e| matches!(e, ApproverEvent::Alert { message, .. } if message.contains("went back"))
        ),
        "{events:?}"
    );
}

#[test]
fn a_refused_pairing_forgets_the_phones_state() {
    let phone = paired();
    phone.handler.lock().stored.as_mut().unwrap().paired = false;
    // A pairing sent and not yet answered shows no request.
    assert!(phone
        .take(kind::REQUEST, &wire::to_text(&phone.request(10, "x", 10)))
        .is_empty());
    let refused = wire::to_text(&Pairing::Refused {
        v: V1,
        reason: "no\u{0}pe".into(),
    });
    let events = phone.take(kind::PAIRING, &refused);
    assert!(matches!(
        &events[..],
        [ApproverEvent::PairingRefused { reason }] if reason == "nope"
    ));
    assert!(phone.handler.lock().stored.is_none());
    // Requests are ignored until paired.
    assert!(phone
        .take(kind::REQUEST, &wire::to_text(&phone.request(7, "x", 10)))
        .is_empty());
}

#[test]
fn the_pairing_is_kept_across_runs() {
    let phone = paired();
    let request = phone.request(8, "x", 10);
    phone.take(kind::REQUEST, &wire::to_text(&request));
    assert!(
        ApproverHandler::new(phone.mobile.clone()).is_err(),
        "one handler at a time"
    );
    phone.stored(|s| {
        s.waiting[0].until = now() + 30;
        phone.handler.persist(s).unwrap();
    });
    let phone = phone.reopen();
    let status = phone.handler.status();
    assert!(status.paired);
    assert_eq!(status.label.as_deref(), Some("phone"));
    // The request still waits, with the time it has left.
    let waiting = phone.handler.waiting_requests();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].request_id, request.request_id.to_hex());
    assert!((29..=30).contains(&waiting[0].seconds_left));
    phone
        .handler
        .decision_digest(request.request_id.to_hex(), true)
        .unwrap();
    // The request gate came back too: the same request is not shown again.
    assert!(shown_request(&phone.take(kind::REQUEST, &wire::to_text(&request))).is_none());
    phone.handler.forget().unwrap();
    let phone = phone.reopen();
    assert!(!phone.handler.status().paired);
    assert!(phone.handler.waiting_requests().is_empty());
}

#[test]
fn a_decrypt_request_warns_the_plaintext_reaches_the_agent() {
    let phone = paired();
    let key = phone.channel();
    let peer = sig::xonly(&Keys::generate());
    let (request, _) = RequestDraft {
        request_id: [9; 32],
        created_at: now(),
        deadline_secs: 120,
        credential: Some(CredentialRef {
            id: Hex16([0x22; 16]),
            name: "writer".into(),
            uid: 1001,
        }),
        key: Some(key),
        network: None,
        reason: Reason::DecryptOwnPayload,
        payload: Payload::Nip44Decrypt(Nip44DecryptPayload {
            peer: Hex32(peer),
            ciphertext_sha256: Hex32([1; 32]),
            plaintext: "secret plan".into(),
        }),
        budget: None,
        anchor: anchor(10),
    }
    .finish(&key)
    .unwrap();
    let events = phone.take(kind::REQUEST, &wire::to_text(&request));
    let shown = shown_request(&events).unwrap();
    assert!(shown.warnings.iter().any(|w| w.contains("model provider")));
    assert!(shown
        .fields
        .iter()
        .any(|f| f.label == "plaintext" && f.by_agent && f.value == "secret plan"));
}

#[test]
fn pairing_begins_with_the_gateways_code_and_checks_the_approver_signature() {
    let storage: Arc<dyn SecureStorage> = Arc::new(Memory::default());
    let handler = ApproverHandler::new(Arc::new(KeepMobile::new(storage).unwrap())).unwrap();
    let channel = Keys::generate();
    let uri = PairingUri {
        gateway: sig::xonly(&channel),
        secret: Zeroizing::new([3u8; 32]),
        relays: vec!["ws://127.0.0.1:1".into()],
    }
    .to_uri()
    .unwrap();
    let approver = p256::ecdsa::SigningKey::from_slice(&[5u8; 32]).unwrap();
    let key = approver
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    assert!(handler
        .begin_pairing(uri.to_string(), key[..32].to_vec(), "phone".into())
        .is_err());
    assert!(handler
        .begin_pairing(uri.to_string(), key.clone(), "bad\u{202e}label".into())
        .is_err());
    assert!(handler
        .begin_pairing("keep-approver:v1?nope".into(), key.clone(), "phone".into())
        .is_err());
    let start = handler
        .begin_pairing(uri.to_string(), key, "phone".into())
        .unwrap();
    let transport = {
        let inner = handler.lock();
        sig::xonly(&inner.begun.as_ref().unwrap().stored.keys().unwrap())
    };
    let a: [u8; 33] = approver
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    assert_eq!(start.fingerprint, sig::fingerprint(&transport, &a));
    assert_eq!(
        start.digest,
        sig::pair_approver_digest(&sig::xonly(&channel), &transport, &a)
    );
    // A signature by another key is refused before anything is sent.
    let other = p256::ecdsa::SigningKey::from_slice(&[6u8; 32]).unwrap();
    let wrong: p256::ecdsa::Signature = other.sign(&start.digest);
    assert!(handler
        .clone()
        .finish_pairing(wrong.to_der().as_bytes().to_vec(), Arc::new(Nobody))
        .unwrap_err()
        .to_string()
        .contains("does not verify"));
    assert!(!handler.status().pairing, "nothing kept");
    // The pairing begun stays, so the right signature can follow; one no
    // relay takes leaves nothing stored and the pairing still begun.
    let right: p256::ecdsa::Signature = approver.sign(&start.digest);
    let right = right.to_der().as_bytes().to_vec();
    assert!(handler
        .clone()
        .finish_pairing(right.clone(), Arc::new(Nobody))
        .is_err());
    assert!(!handler.status().pairing);
    assert!(!handler.status().running);
    assert!(handler.lock().begun.is_some());
    // Paired meanwhile: never overwritten.
    let phone = paired();
    let begun = handler.lock().begun.take();
    phone.handler.lock().begun = begun;
    assert!(phone
        .handler
        .clone()
        .finish_pairing(right, Arc::new(Nobody))
        .unwrap_err()
        .to_string()
        .contains("already paired"));
    assert!(phone.handler.status().paired);
}

fn anchor_text(at: u64, seq: u64, epoch: u64, all: bool) -> String {
    wire::to_text(&Anchor {
        v: V1,
        at,
        anchor: anchor(seq),
        frozen: Frozen {
            epoch,
            all,
            credentials: vec![],
            unfrozen: vec![],
        },
    })
}

fn alerts(events: &[ApproverEvent]) -> Vec<&str> {
    events
        .iter()
        .filter_map(|e| match e {
            ApproverEvent::Alert { message, .. } => Some(message.as_str()),
            _ => None,
        })
        .collect()
}

#[test]
fn an_anchor_not_newer_than_the_one_kept_is_not_shown() {
    let phone = paired();
    let t = now();
    assert_eq!(
        phone
            .take(kind::ANCHOR, &anchor_text(t, 100, 3, false))
            .len(),
        1
    );
    assert!(
        phone
            .take(kind::ANCHOR, &anchor_text(t, 100, 3, false))
            .is_empty(),
        "a replay"
    );
    assert!(
        phone
            .take(kind::ANCHOR, &anchor_text(t - 60, 50, 1, true))
            .is_empty(),
        "an old anchor arriving late"
    );
    let status = phone.handler.status();
    assert_eq!(status.epoch, Some(3));
    assert!(!status.all_frozen);
    assert!(status.alerts.is_empty());
}

#[test]
fn alerts_stay_until_acknowledged_and_survive_a_restart() {
    let phone = paired();
    let t = now();
    phone.take(kind::ANCHOR, &anchor_text(t, 100, 3, false));
    let events = phone.take(kind::ANCHOR, &anchor_text(t + 60, 90, 3, false));
    assert_eq!(alerts(&events).len(), 2, "{events:?}");
    let phone = phone.reopen();
    let kept = phone.handler.status().alerts;
    assert_eq!(
        kept.iter().map(|a| a.message.as_str()).collect::<Vec<_>>(),
        alerts(&events)
    );
    // One raised after the owner looked stays.
    let mut fx = Effects::default();
    phone.stored(|s| s.alert("later".into(), &mut fx));
    phone.handler.acknowledge_alerts(kept[1].seq).unwrap();
    let left = phone.handler.status().alerts;
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].message, "later");
    phone.handler.acknowledge_alerts(left[0].seq).unwrap();
    assert!(phone.handler.status().alerts.is_empty());
    let phone = phone.reopen();
    assert!(phone.handler.status().alerts.is_empty());
}

#[test]
fn alerts_kept_are_bounded() {
    let phone = paired();
    let mut fx = Effects::default();
    phone.stored(|s| {
        for i in 0..MAX_ALERTS + 5 {
            s.alert(format!("alert {i}"), &mut fx);
        }
    });
    let status = phone.handler.status();
    assert_eq!(status.alerts.len(), MAX_ALERTS);
    assert_eq!(status.alerts[0].message, "alert 5", "the oldest go");
    assert_eq!(status.alerts_dropped, 5, "counted");
    // The same alert, still unacknowledged, is not raised again.
    let mut fx = Effects::default();
    phone.stored(|s| s.alert(format!("alert {}", MAX_ALERTS + 4), &mut fx));
    assert!(fx.events.is_empty());
    assert_eq!(phone.handler.status().alerts_dropped, 5);
    phone.handler.acknowledge_alerts(0).unwrap();
    assert_eq!(phone.handler.status().alerts_dropped, 0);
}

#[test]
fn a_freeze_is_resent_until_shown_and_alerts_once_when_it_is_not() {
    let phone = paired();
    let t = now();
    phone.take(kind::ANCHOR, &anchor_text(t, 100, 3, false));
    // Not running: not sent now, but kept to resend.
    assert!(phone.handler.freeze(None).is_err());
    assert_eq!(phone.stored(|s| s.counter), 1);
    let fx = phone.handler.tick_at(t + 15);
    assert_eq!(fx.send.len(), 1);
    let (k, content) = &fx.send[0];
    assert_eq!(*k, kind::FREEZE);
    let freeze: Freeze = wire::parse(content).unwrap();
    assert_eq!(freeze.action, FreezeAction::Freeze);
    assert_eq!(freeze.scope, Scope::All);
    assert_eq!((freeze.counter, freeze.epoch), (2, 3));
    assert!(alerts(&fx.events).is_empty());
    let fx = phone.handler.tick_at(t + FREEZE_SHOWN_SECS);
    let shown = alerts(&fx.events);
    assert_eq!(shown.len(), 1);
    assert!(shown[0].contains("has not shown at the gateway"));
    assert!(alerts(&phone.handler.tick_at(t + FREEZE_SHOWN_SECS + 15).events).is_empty());
    // An anchor showing it ends the resends.
    phone.take(kind::ANCHOR, &anchor_text(t + 1, 101, 4, true));
    assert!(phone.handler.tick_at(t + 200).send.is_empty());
}

#[test]
fn silence_alerts_once_until_an_anchor_arrives() {
    let phone = paired();
    let t = now();
    phone.take(kind::ANCHOR, &anchor_text(t, 100, 3, false));
    assert!(alerts(&phone.handler.tick_at(t + 60).events).is_empty());
    let fx = phone.handler.tick_at(t + SILENCE_SECS);
    assert_eq!(alerts(&fx.events), vec![SILENT_ALERT]);
    assert!(alerts(&phone.handler.tick_at(t + SILENCE_SECS + 15).events).is_empty());
    assert!(phone
        .handler
        .status()
        .alerts
        .iter()
        .any(|a| a.message == SILENT_ALERT));
    // Restarted while still silent: not raised again.
    let phone = phone.reopen();
    assert!(alerts(&phone.handler.tick_at(t + SILENCE_SECS + 30).events).is_empty());
    let seq = phone.handler.status().alerts[0].seq;
    phone.handler.acknowledge_alerts(seq).unwrap();
    let phone = phone.reopen();
    assert!(alerts(&phone.handler.tick_at(t + SILENCE_SECS + 45).events).is_empty());
    // An anchor ends the silence; the next one alerts again.
    phone.take(kind::ANCHOR, &anchor_text(t + 1, 101, 3, false));
    let later = now() + SILENCE_SECS;
    assert_eq!(
        alerts(&phone.handler.tick_at(later).events),
        vec![SILENT_ALERT]
    );
}

#[test]
fn a_tick_drops_requests_past_their_time_and_saves_only_changes() {
    let phone = paired();
    let request = phone.request(12, "x", 10);
    phone.take(kind::REQUEST, &wire::to_text(&request));
    phone
        .mobile
        .storage
        .delete_share_by_key(STATE_KEY.into())
        .unwrap();
    phone.handler.tick_at(now() + 1);
    assert!(
        phone
            .mobile
            .storage
            .load_share_by_key(STATE_KEY.into())
            .is_err(),
        "nothing changed, nothing saved"
    );
    // Past its time: no longer decidable, but kept a while for the
    // gateway's `expired` outcome.
    phone.handler.tick_at(now() + 121);
    assert!(phone.stored(|s| s.waiting.len() == 1 && !s.waiting[0].decided));
    assert!(
        phone.stored(|s| s.waiting[0].request.is_none()),
        "its payload goes"
    );
    phone.handler.tick_at(now() + 120 + OUTCOME_GRACE_SECS + 1);
    assert!(phone.stored(|s| s.waiting.is_empty()));
    assert!(phone
        .mobile
        .storage
        .load_share_by_key(STATE_KEY.into())
        .is_ok());
}

#[test]
fn too_many_waiting_requests_are_refused() {
    let phone = paired();
    for i in 0..MAX_WAITING {
        let r = phone.request(0, "x", 10);
        let mut r = r;
        r.request_id = Hex32([i as u8; 32]);
        phone.stored(|s| {
            s.waiting.push(Waiting {
                id: r.request_id,
                until: now() + 100,
                unfreeze: None,
                skew: false,
                decided: false,
                request: Some(r),
            })
        });
    }
    let events = phone.take(kind::REQUEST, &wire::to_text(&phone.request(200, "x", 10)));
    assert!(shown_request(&events).is_none());
    assert!(events.iter().any(
        |e| matches!(e, ApproverEvent::RequestRefused { reason } if reason.contains("too many"))
    ));
    // A relay replaying it is dropped by the gate, not refused again.
    assert!(phone
        .take(kind::REQUEST, &wire::to_text(&phone.request(200, "x", 10)))
        .is_empty());
    // Refused, but its time was observed.
    assert!(phone.stored(|s| s.tracker.latest_gateway_time()) > 0);
    // Nor does one past its time, kept only for its outcome.
    phone.stored(|s| s.waiting[1].until = now() - 1);
    let events = phone.take(kind::REQUEST, &wire::to_text(&phone.request(202, "x", 10)));
    assert!(
        shown_request(&events).is_some(),
        "an expired one does not count"
    );
    phone.stored(|s| {
        s.waiting[0].decided = true;
        s.waiting[0].request = None;
    });
    let events = phone.take(kind::REQUEST, &wire::to_text(&phone.request(201, "x", 10)));
    assert!(
        shown_request(&events).is_some(),
        "a decided one does not count"
    );
}

#[test]
fn an_unfreeze_is_signed_for_what_was_asked() {
    let phone = paired();
    let t = now();
    phone.take(kind::ANCHOR, &anchor_text(t, 100, 3, true));
    let credential = "22".repeat(16);
    assert!(phone.handler.unfreeze_digest(Some("zz".into())).is_err());
    let digest = phone
        .handler
        .unfreeze_digest(Some(credential.clone()))
        .unwrap();
    let approver = phone.stored(|s| s.approver);
    assert_eq!(
        digest,
        sig::freeze_digest(
            &phone.channel(),
            &SignerKey::Approver(approver),
            1,
            3,
            FreezeAction::Unfreeze,
            Scope::Credential(Hex16([0x22; 16])),
        )
    );
    let signature = phone.sign(&digest, true);
    assert!(
        phone
            .handler
            .send_unfreeze(None, signature.clone())
            .unwrap_err()
            .to_string()
            .contains("no unfreeze of that scope"),
        "another scope"
    );
    let wrong = phone.sign(&[0u8; 32], false);
    assert!(phone
        .handler
        .send_unfreeze(Some(credential.clone()), wrong)
        .unwrap_err()
        .to_string()
        .contains("does not verify"));
    // Verified, but not running: still asked, so it can be sent again.
    let err = phone
        .handler
        .send_unfreeze(Some(credential.clone()), signature)
        .unwrap_err();
    assert!(matches!(err, KeepMobileError::NetworkError { .. }), "{err}");
    assert!(phone.stored(|s| s.unfreeze.is_some()));
    // The asked unfreeze survives a restart; a freeze after it counts on.
    let phone = phone.reopen();
    assert!(phone.stored(|s| s.unfreeze.is_some()));
    // Still sendable: loading did not move the counter it was signed for.
    let err = phone
        .handler
        .send_unfreeze(Some(credential.clone()), phone.sign(&digest, false))
        .unwrap_err();
    assert!(matches!(err, KeepMobileError::NetworkError { .. }), "{err}");
    // A freeze signed meanwhile voids it: its counter is now old.
    assert!(phone.handler.freeze(Some(credential.clone())).is_err());
    assert_eq!(phone.stored(|s| s.counter), 1 + COUNTER_MARGIN + 1);
    let signature = phone.sign(&digest, false);
    assert!(phone
        .handler
        .send_unfreeze(Some(credential), signature)
        .unwrap_err()
        .to_string()
        .contains("ask for the unfreeze digest again"));
    assert!(phone.stored(|s| s.unfreeze.is_none()));
}

#[test]
fn freezes_are_not_resent_while_an_unfreeze_is_signed() {
    let phone = paired();
    let t = now();
    phone.take(kind::ANCHOR, &anchor_text(t, 100, 3, false));
    assert!(phone.handler.freeze(None).is_err());
    phone.handler.unfreeze_digest(None).unwrap();
    let asked = phone.stored(|s| s.unfreeze.unwrap().at);
    assert!(phone.handler.tick_at(asked + 15).send.is_empty());
    assert_eq!(phone.stored(|s| s.counter), 2);
    assert_eq!(
        phone.handler.tick_at(asked + UNFREEZE_HOLD_SECS).send.len(),
        1
    );
}

#[test]
fn a_freeze_is_resent_only_once_its_counter_is_saved() {
    let phone = paired();
    let t = now();
    phone.take(kind::ANCHOR, &anchor_text(t, 100, 3, false));
    assert!(phone.handler.freeze(None).is_err());
    phone.memory.1.store(true, Ordering::SeqCst);
    assert!(phone.handler.tick_at(t + 15).send.is_empty());
    assert!(phone.handler.freeze(None).is_err(), "nor sent unsaved");
    phone.memory.1.store(false, Ordering::SeqCst);
    let fx = phone.handler.tick_at(t + 30);
    assert_eq!(fx.send.len(), 1);
    let freeze: Freeze = wire::parse(&fx.send[0].1).unwrap();
    let phone = phone.reopen();
    assert_eq!(phone.stored(|s| s.counter), freeze.counter);
}

/// An approved unfreeze request this phone decided explains the freeze it
/// lifts, so no alert follows.
#[test]
fn a_decided_unfreeze_explains_the_freeze_it_clears() {
    for decided_outcome in [true, false] {
        let phone = paired();
        let t = now();
        phone.take(kind::ANCHOR, &anchor_text(t, 100, 3, true));
        let channel = phone.channel();
        let (request, _) = RequestDraft {
            request_id: [13; 32],
            created_at: now(),
            deadline_secs: 120,
            credential: None,
            key: None,
            network: None,
            reason: Reason::Management,
            payload: Payload::Management(Change::Unfreeze {
                scope: Scope::All,
                epoch: Decimal(3),
            }),
            budget: None,
            anchor: anchor(100),
        }
        .finish(&channel)
        .unwrap();
        let events = phone.take(kind::REQUEST, &wire::to_text(&request));
        assert!(shown_request(&events).is_some(), "{events:?}");
        phone.stored(|s| {
            s.waiting[0].decided = true;
            s.waiting[0].request = None;
        });
        if decided_outcome {
            phone.take(
                kind::OUTCOME,
                &wire::to_text(&Outcome {
                    v: V1,
                    request_id: request.request_id,
                    outcome: OutcomeKind::Approved,
                    by: None,
                }),
            );
        }
        phone.take(kind::ANCHOR, &anchor_text(t + 1, 101, 4, false));
        let fx = phone.handler.tick_at(now() + CLEARED_GRACE_SECS + 1);
        let cleared = alerts(&fx.events)
            .iter()
            .any(|a| a.contains("no unfreeze explains it"));
        assert_eq!(cleared, !decided_outcome, "{:?}", fx.events);
    }
}

#[test]
fn an_outcome_for_a_request_never_shown_is_ignored() {
    let phone = paired();
    let before = phone.stored(|s| serde_json::to_vec(&s.tracker).unwrap());
    let outcome = wire::to_text(&Outcome {
        v: V1,
        request_id: Hex32([0x77; 32]),
        outcome: OutcomeKind::Approved,
        by: None,
    });
    assert!(phone.take(kind::OUTCOME, &outcome).is_empty());
    assert_eq!(
        phone.stored(|s| serde_json::to_vec(&s.tracker).unwrap()),
        before
    );
}

struct Nobody;

impl ApproverCallbacks for Nobody {
    fn on_event(&self, _: ApproverEvent) {}
}

fn serve(phone: &Phone, relay: String) {
    phone.stored(|s| s.relays = vec![relay]);
    phone.handler.clone().start(Arc::new(Nobody)).unwrap();
}

#[test]
fn a_decision_is_decided_once_a_relay_takes_it_and_its_payload_goes() {
    let phone = paired();
    let relay = phone.mobile.runtime.block_on(start_mock_relay());
    let url = phone.mobile.runtime.block_on(relay.url()).to_string();
    serve(&phone, url);
    let request = phone.request(14, "x", 10);
    phone.take(kind::REQUEST, &wire::to_text(&request));
    let id = request.request_id.to_hex();
    let digest = phone.handler.decision_digest(id.clone(), true).unwrap();
    phone
        .handler
        .send_decision(id.clone(), true, phone.sign(&digest, false))
        .unwrap();
    assert!(phone.handler.waiting_requests().is_empty());
    assert!(phone.handler.decision_digest(id, true).is_err());
    let phone = phone.reopen();
    assert!(
        phone.stored(|s| s.waiting.len() == 1
            && s.waiting[0].decided
            && s.waiting[0].request.is_none()),
        "kept for its outcome, without the request"
    );
    let stored = phone.memory.0.lock().unwrap()[STATE_KEY].clone();
    let text = String::from_utf8(stored).unwrap();
    assert!(!text.contains("\"payload\""), "{text}");
}

#[test]
fn a_decision_no_relay_takes_is_not_decided() {
    let phone = paired();
    serve(&phone, "ws://127.0.0.1:1".into());
    let request = phone.request(15, "x", 10);
    phone.take(kind::REQUEST, &wire::to_text(&request));
    let id = request.request_id.to_hex();
    let digest = phone.handler.decision_digest(id.clone(), true).unwrap();
    let err = phone
        .handler
        .send_decision(id, true, phone.sign(&digest, false))
        .unwrap_err();
    assert!(matches!(err, KeepMobileError::NetworkError { .. }), "{err}");
    assert_eq!(phone.handler.waiting_requests().len(), 1);
    phone.handler.stop();
    assert!(!phone.handler.status().running);
}

#[test]
fn shutdown_gives_the_slot_back_and_ends_the_handler() {
    let phone = paired();
    assert!(ApproverHandler::new(phone.mobile.clone()).is_err());
    phone.handler.shutdown();
    assert!(!phone.handler.status().paired);
    assert!(phone.handler.clone().start(Arc::new(Nobody)).is_err());
    assert!(phone.handler.forget().is_err());
    assert!(phone
        .handler
        .begin_pairing("keep-approver:v1?x".into(), vec![2; 33], "phone".into())
        .unwrap_err()
        .to_string()
        .contains("closed"));
    let next = ApproverHandler::new(phone.mobile.clone()).unwrap();
    assert!(next.status().paired, "the pairing stays stored");
    // The closed one dropping does not free the new one's slot.
    let Phone {
        handler, mobile, ..
    } = phone;
    drop(handler);
    assert!(ApproverHandler::new(mobile.clone()).is_err());
    drop(next);
    assert!(ApproverHandler::new(mobile).is_ok());
}

#[test]
fn a_pairing_a_relay_takes_waits_for_the_gateway() {
    let storage: Arc<dyn SecureStorage> = Arc::new(Memory::default());
    let mobile = Arc::new(KeepMobile::new(storage).unwrap());
    let relay = mobile.runtime.block_on(start_mock_relay());
    let url = mobile.runtime.block_on(relay.url()).to_string();
    let handler = ApproverHandler::new(mobile).unwrap();
    let uri = PairingUri {
        gateway: sig::xonly(&Keys::generate()),
        secret: Zeroizing::new([3u8; 32]),
        relays: vec![url],
    }
    .to_uri()
    .unwrap();
    let approver = p256::ecdsa::SigningKey::from_slice(&[5u8; 32]).unwrap();
    let key = approver
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let start = handler
        .begin_pairing(uri.to_string(), key, "phone".into())
        .unwrap();
    let signature: p256::ecdsa::Signature = approver.sign(&start.digest);
    handler
        .clone()
        .finish_pairing(signature.to_der().as_bytes().to_vec(), Arc::new(Nobody))
        .unwrap();
    let status = handler.status();
    assert!(status.pairing && status.running && !status.paired);
    assert!(handler.lock().begun.is_none(), "sent once");
    assert!(handler
        .clone()
        .finish_pairing(vec![], Arc::new(Nobody))
        .unwrap_err()
        .to_string()
        .contains("no pairing was begun"));
    handler.shutdown();
}

#[test]
fn an_expired_outcome_after_the_deadline_still_reaches_the_app() {
    let phone = paired();
    let request = phone.request(16, "x", 10);
    phone.take(kind::REQUEST, &wire::to_text(&request));
    phone.stored(|s| s.waiting[0].until = now() - 30);
    phone.handler.tick_at(now());
    assert!(phone
        .handler
        .decision_digest(request.request_id.to_hex(), true)
        .is_err());
    let events = phone.take(
        kind::OUTCOME,
        &wire::to_text(&Outcome {
            v: V1,
            request_id: request.request_id,
            outcome: OutcomeKind::Expired,
            by: None,
        }),
    );
    assert!(matches!(
        &events[..],
        [ApproverEvent::Outcome { outcome, .. }] if outcome == "expired"
    ));
}

#[test]
fn a_pairing_the_gateway_answered_stands_though_no_relay_confirmed_it() {
    let phone = paired();
    let (channel, transport) = phone.stored(|s| (s.channel.0, s.keys().unwrap().public_key()));
    let digest = [9u8; 32];
    phone
        .handler
        .settle_pairing(Err(no_relay()), channel, transport, digest)
        .unwrap();
    assert!(phone.handler.status().paired);
    // Unanswered: undone, and nothing stored.
    phone.stored(|s| s.paired = false);
    assert!(phone
        .handler
        .settle_pairing(Err(no_relay()), channel, transport, digest)
        .is_err());
    assert!(phone.handler.lock().stored.is_none());
    assert!(phone.memory.0.lock().unwrap().get(STATE_KEY).is_none());
}

#[test]
fn settling_a_pairing_leaves_another_alone() {
    let phone = paired();
    let other = Keys::generate().public_key();
    let (channel, transport) = phone.stored(|s| (s.channel.0, s.keys().unwrap().public_key()));
    phone.stored(|s| s.paired = false);
    // A failed send for another pairing does not undo this one.
    assert!(phone
        .handler
        .settle_pairing(Err(no_relay()), channel, other, [9; 32])
        .is_err());
    assert!(phone.handler.lock().stored.is_some());
    // A pairing begun again meanwhile keeps its own begun.
    let begun = phone.handler.lock().stored.clone().map(|stored| Begun {
        stored,
        secret: Zeroizing::new([1; 32]),
        digest: [7; 32],
    });
    phone.handler.lock().begun = begun;
    phone
        .handler
        .settle_pairing(Ok(()), channel, transport, [9; 32])
        .unwrap();
    assert!(phone.handler.lock().begun.is_some());
    phone
        .handler
        .settle_pairing(Ok(()), channel, transport, [7; 32])
        .unwrap();
    assert!(phone.handler.lock().begun.is_none());
}

#[test]
fn the_skew_warning_is_measured_when_a_request_arrives() {
    let phone = paired();
    let request = phone.request(17, "x", 10);
    phone.take(kind::REQUEST, &wire::to_text(&request));
    let skewed = |p: &Phone| {
        p.handler.waiting_requests()[0]
            .warnings
            .iter()
            .any(|w| w.contains("clock"))
    };
    assert!(!skewed(&phone));
    // Read back long after it was created: still no skew.
    phone.stored(|s| {
        if let Some(r) = s.waiting[0].request.as_mut() {
            r.created_at -= 1_000;
        }
    });
    assert!(!skewed(&phone));
    phone.stored(|s| s.waiting[0].skew = true);
    assert!(skewed(&phone));
}

#[test]
fn a_full_request_gate_is_told_to_the_app() {
    let phone = paired();
    let mut admitted = 0;
    let mut n: u32 = 0;
    phone.stored(|s| {
        while admitted < keep_approval::approver::MAX_SEEN_REQUESTS {
            let mut r = phone.request(0, "x", 10);
            r.request_id.0[..4].copy_from_slice(&n.to_le_bytes());
            n += 1;
            if s.gate.admit(&r, &s.tracker, now()).is_ok() {
                admitted += 1;
            }
        }
    });
    let events = phone.take(kind::REQUEST, &wire::to_text(&phone.request(203, "x", 10)));
    assert!(shown_request(&events).is_none());
    assert!(events.iter().any(
        |e| matches!(e, ApproverEvent::RequestRefused { reason } if reason.contains("open at once"))
    ));
}

#[test]
fn a_decided_request_waits_for_its_outcome_past_its_time() {
    let phone = paired();
    let request = phone.request(18, "x", 10);
    phone.take(kind::REQUEST, &wire::to_text(&request));
    phone.stored(|s| {
        s.waiting[0].decided = true;
        s.waiting[0].request = None;
    });
    phone.handler.tick_at(now() + 120 + OUTCOME_GRACE_SECS + 60);
    assert!(phone.stored(|s| s.waiting.len() == 1));
    phone.handler.tick_at(now() + 120 + WINDOW_PAST_SECS + 1);
    assert!(phone.stored(|s| s.waiting.is_empty()));
}

#[test]
fn the_first_counter_after_a_load_skips_past_a_rollback() {
    let saved = |p: &Phone| -> u64 {
        let data = p.memory.0.lock().unwrap()[STATE_KEY].clone();
        serde_json::from_slice::<Stored>(&data).unwrap().counter
    };
    let phone = paired();
    assert!(phone.handler.freeze(None).is_err());
    assert_eq!(saved(&phone), 1);
    // Loading alone spends nothing, however often, even when the state is
    // saved again without signing anything.
    let phone = phone.reopen().reopen().reopen();
    assert_eq!(saved(&phone), 1);
    phone.handler.acknowledge_alerts(0).unwrap();
    let phone = phone.reopen();
    assert_eq!(saved(&phone), 1);
    assert!(phone.handler.freeze(None).is_err());
    assert_eq!(saved(&phone), 1 + COUNTER_MARGIN + 1);
    assert!(phone.handler.freeze(None).is_err());
    assert_eq!(saved(&phone), 1 + COUNTER_MARGIN + 2, "then by one");
    // Freezes sent after that load, then storage rolled back a few writes:
    // the next load signs past every counter sent since.
    let sent = phone.stored(|s| s.counter);
    for _ in 0..5 {
        assert!(phone.handler.freeze(None).is_err());
    }
    let last = sent + 5;
    assert_eq!(saved(&phone), last);
    phone.stored(|s| {
        s.counter = sent;
        phone.handler.persist(s).unwrap();
    });
    let phone = phone.reopen();
    phone.handler.unfreeze_digest(None).unwrap();
    let asked = phone.stored(|s| s.unfreeze.unwrap().counter);
    assert_eq!(asked, sent + COUNTER_MARGIN + 1);
    assert!(asked > last);
    // At the boundary: a rollback of exactly the margin is still covered.
    let base = phone.stored(|s| s.counter);
    for _ in 0..COUNTER_MARGIN {
        assert!(phone.handler.freeze(None).is_err());
    }
    let last = base + COUNTER_MARGIN;
    phone.stored(|s| {
        s.counter = base;
        phone.handler.persist(s).unwrap();
    });
    let phone = phone.reopen();
    assert!(phone.handler.freeze(None).is_err());
    assert!(saved(&phone) > last);
}

// The approver's relay socket enforces pins inside the handshake like every
// other relay socket here: under strict pinning a relay it cannot pin carries
// nothing, where the same decision over the same relay goes through when
// pinning is lenient (`a_decision_is_decided_once_a_relay_takes_it_...`).
#[test]
fn under_strict_pinning_a_relay_that_cannot_be_pinned_carries_no_decision() {
    let phone = paired();
    phone.mobile.set_strict_cert_pinning(true).unwrap();
    let relay = phone.mobile.runtime.block_on(start_mock_relay());
    let url = phone.mobile.runtime.block_on(relay.url()).to_string();
    serve(&phone, url);
    let request = phone.request(17, "x", 10);
    phone.take(kind::REQUEST, &wire::to_text(&request));
    let id = request.request_id.to_hex();
    let digest = phone.handler.decision_digest(id.clone(), true).unwrap();
    let err = phone
        .handler
        .send_decision(id, true, phone.sign(&digest, false))
        .unwrap_err();
    assert!(matches!(err, KeepMobileError::NetworkError { .. }), "{err}");
    assert_eq!(phone.handler.waiting_requests().len(), 1);
    phone.handler.stop();
}

// With the proxy on, both the probe that learns a relay's pin and the live
// socket that carries the pairing and approvals go through it, rather than
// connecting from this phone's own address. The live socket retries only every
// ten seconds, so two greetings well inside that are the probe's and its own.
#[test]
fn the_approver_reaches_its_relays_through_the_proxy() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (greetings, seen) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut first = [0u8; 1];
            if std::io::Read::read_exact(&mut stream, &mut first).is_ok()
                && greetings.send(first[0]).is_err()
            {
                return;
            }
        }
    });

    let phone = paired();
    phone
        .mobile
        .save_proxy_config(crate::ProxyConfigInfo {
            enabled: true,
            port,
        })
        .unwrap();
    let started = std::time::Instant::now();
    phone.handler.clone().start(Arc::new(Nobody)).unwrap();

    for which in ["the probe", "the live socket"] {
        let left = Duration::from_secs(6).saturating_sub(started.elapsed());
        let first = seen
            .recv_timeout(left)
            .unwrap_or_else(|_| panic!("{which} did not go through the proxy"));
        assert_eq!(first, 0x05, "{which} opens with a SOCKS5 greeting");
    }
    phone.handler.stop();
}

// Strict pinning cannot pin a socket the proxy opens, so the approver refuses
// the pair outright rather than report running and carry nothing.
#[test]
fn strict_pinning_with_the_proxy_is_refused() {
    let phone = paired();
    phone.mobile.set_strict_cert_pinning(true).unwrap();
    phone
        .mobile
        .save_proxy_config(crate::ProxyConfigInfo {
            enabled: true,
            port: 9050,
        })
        .unwrap();
    let err = phone.handler.clone().start(Arc::new(Nobody)).unwrap_err();
    assert!(
        err.to_string().contains("Strict certificate pinning"),
        "{err}"
    );
    assert!(!phone.handler.status().running);
}

// The pairing's relays were never probed by an approver before, so they have no
// pin: one started offline still comes up, and connects when the network does.
// Under strict pinning the same start is refused.
#[test]
fn an_approver_started_offline_comes_up_unless_pinning_is_strict() {
    let phone = paired();
    phone.handler.clone().start(Arc::new(Nobody)).unwrap();
    assert!(phone.handler.status().running);
    phone.handler.stop();

    phone.mobile.set_strict_cert_pinning(true).unwrap();
    assert!(phone.handler.clone().start(Arc::new(Nobody)).is_err());
    assert!(!phone.handler.status().running);
}

// The gateway's relays are held to the rules every other relay here is, with
// an error that says so, whether they come from a pairing code or were kept
// from an earlier run.
#[test]
fn relays_another_socket_would_refuse_are_refused() {
    let phone = paired();
    let uri = PairingUri {
        gateway: sig::xonly(&Keys::generate()),
        secret: Zeroizing::new([3u8; 32]),
        relays: vec!["wss://user@relay.example".into()],
    }
    .to_uri();
    if let Ok(uri) = uri {
        let fresh = ApproverHandler::new(Arc::new(
            KeepMobile::new(Arc::new(Memory::default())).unwrap(),
        ))
        .unwrap();
        let err = fresh
            .begin_pairing(uri.to_string(), vec![2; 33], "phone".into())
            .unwrap_err();
        assert!(
            matches!(err, KeepMobileError::InvalidRelayUrl { .. }),
            "{err}"
        );
    }
    phone.stored(|s| s.relays = vec!["wss://user@relay.example".into()]);
    let err = phone.handler.clone().start(Arc::new(Nobody)).unwrap_err();
    assert!(
        matches!(err, KeepMobileError::InvalidRelayUrl { .. }),
        "{err}"
    );
}

// A move to relays the approver cannot use leaves it serving the old ones, so
// approvals still go and the silence alert still runs, rather than stopping
// with no word to anyone.
#[test]
fn a_failed_move_to_new_relays_keeps_the_old_ones_serving() {
    let phone = paired();
    let relay = phone.mobile.runtime.block_on(start_mock_relay());
    let url = phone.mobile.runtime.block_on(relay.url()).to_string();
    serve(&phone, url);
    phone
        .handler
        .move_relays(vec!["https://relay.example".into()]);
    assert!(phone.handler.status().running);
    let request = phone.request(18, "x", 10);
    phone.take(kind::REQUEST, &wire::to_text(&request));
    let id = request.request_id.to_hex();
    let digest = phone.handler.decision_digest(id.clone(), true).unwrap();
    phone
        .handler
        .send_decision(id, true, phone.sign(&digest, false))
        .expect("the old relay still carries the decision");
    phone.handler.stop();
}
