// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap as Map;

use keep_approval::binding::{
    Nip44DecryptPayload, NostrPayload, Payload, RequestDraft, UnsignedEventFields,
};
use keep_approval::messages::{AnchorState, CredentialRef, Frozen, Reason};
use p256::ecdsa::signature::Signer;

use super::*;
use crate::storage::{SecureStorage, ShareMetadataInfo};

#[derive(Default)]
struct Memory(Mutex<Map<String, Vec<u8>>>);

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
    channel: Keys,
    approver: p256::ecdsa::SigningKey,
}

/// A handler paired with a gateway whose channel key is `channel`.
fn paired() -> Phone {
    let storage: Arc<dyn SecureStorage> = Arc::new(Memory::default());
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
        tracker: AnchorTracker::default(),
        gate: RequestGate::default(),
    };
    let handler = ApproverHandler::new(mobile.clone());
    handler.lock().stored = Some(stored);
    Phone {
        handler,
        mobile,
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
    assert!(shown
        .fields
        .iter()
        .any(|f| f.label == "tag 0" && f.by_agent));
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
    assert!(phone
        .handler
        .send_decision(phone.sign(&digest, false))
        .is_err());
    assert!(phone
        .handler
        .lock()
        .waiting
        .contains_key(&request.request_id));
    assert!(
        phone.handler.send_decision(vec![]).is_err(),
        "nothing asked"
    );
}

#[test]
fn a_request_past_its_time_cannot_be_decided() {
    let phone = paired();
    let request = phone.request(5, "x", 10);
    phone.take(kind::REQUEST, &wire::to_text(&request));
    phone
        .handler
        .lock()
        .waiting
        .get_mut(&request.request_id)
        .unwrap()
        .until = now() - 1;
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
    assert!(phone.handler.lock().waiting.is_empty());
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
            |e| matches!(e, ApproverEvent::Alert { message } if message.contains("went back"))
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
    let again = ApproverHandler::new(phone.mobile.clone());
    let status = again.status();
    assert!(status.paired);
    assert_eq!(status.label.as_deref(), Some("phone"));
    // The request gate came back too: the same request is not shown again.
    let mut inner = again.lock();
    let events = again
        .handle(&mut inner, kind::REQUEST, &wire::to_text(&request), now())
        .events;
    assert!(shown_request(&events).is_none());
    drop(inner);
    again.forget().unwrap();
    assert!(!ApproverHandler::new(phone.mobile.clone()).status().paired);
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
    let handler = ApproverHandler::new(Arc::new(KeepMobile::new(storage).unwrap()));
    let channel = Keys::generate();
    let uri = PairingUri {
        gateway: sig::xonly(&channel),
        secret: Zeroizing::new([3u8; 32]),
        relays: vec!["wss://relay.example".into()],
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
    struct Nobody;
    impl ApproverCallbacks for Nobody {
        fn on_event(&self, _: ApproverEvent) {}
    }
    assert!(handler
        .clone()
        .finish_pairing(wrong.to_der().as_bytes().to_vec(), Arc::new(Nobody))
        .is_err());
    assert!(!handler.status().pairing, "nothing kept");
}
