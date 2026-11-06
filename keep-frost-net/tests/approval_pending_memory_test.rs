// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! A co-signer whose approval waits on a human, over the in-process bus with
//! paused time: the round stays open up to the approval cap and no further,
//! the co-signer keeps answering while its prompt is open, and nothing is
//! committed for an approval that comes too late or is withdrawn.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use keep_core::frost::{ThresholdConfig, TrustedDealer};
use keep_frost_net::test_support::{MemoryBus, MemoryTransport};
use keep_frost_net::{
    Approval, CosignTransport, FrostNetError, KfpNode, KfpNodeEvent, SessionInfo, SigningHooks,
    KFP_EVENT_KIND,
};
use nostr_sdk::prelude::*;
use tokio::time::{timeout, Instant};

const DIGEST: [u8; 32] = [42u8; 32];

/// A co-signer whose human answers `approve` after `after`, behind a kill
/// switch checked in `pre_sign`.
struct PromptHooks {
    after: Duration,
    approve: bool,
    prompts: AtomicUsize,
    permitted: AtomicBool,
}

impl PromptHooks {
    fn new(after: Duration, approve: bool) -> Arc<Self> {
        Arc::new(Self {
            after,
            approve,
            prompts: AtomicUsize::new(0),
            permitted: AtomicBool::new(true),
        })
    }
}

impl SigningHooks for PromptHooks {
    fn pre_sign(&self, _session: &SessionInfo) -> keep_frost_net::Result<()> {
        if self.permitted.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(FrostNetError::PolicyViolation(
                "co-signing is disabled".into(),
            ))
        }
    }

    fn post_sign(&self, _session: &SessionInfo, _signature: &[u8; 64]) {}

    fn begin_approval(&self, _session: &SessionInfo, _deadline: std::time::Instant) -> Approval {
        self.prompts.fetch_add(1, Ordering::SeqCst);
        let (after, approve) = (self.after, self.approve);
        Approval::Pending(Box::pin(async move {
            tokio::time::sleep(after).await;
            if approve {
                Ok(())
            } else {
                Err(FrostNetError::PolicyViolation("denied".into()))
            }
        }))
    }
}

/// A co-signer that only implements `pre_sign`, as every hook did before
/// `begin_approval` existed.
#[derive(Default)]
struct LegacyHooks {
    calls: AtomicUsize,
}

impl SigningHooks for LegacyHooks {
    fn pre_sign(&self, _session: &SessionInfo) -> keep_frost_net::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn post_sign(&self, _session: &SessionInfo, _signature: &[u8; 64]) {}
}

/// A 2-of-2 group on one bus: a co-signer (share 1) and a requester (share 2)
/// that have discovered each other.
struct Group {
    bus: MemoryBus,
    cosigner: Arc<KfpNode>,
    requester: Arc<KfpNode>,
    cosigner_transport: Arc<MemoryTransport>,
    requester_rx: tokio::sync::broadcast::Receiver<KfpNodeEvent>,
    verifying_key: [u8; 33],
    shutdowns: Vec<tokio::sync::mpsc::Sender<()>>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Group {
    async fn start(hooks: Arc<dyn SigningHooks>, interactive: bool) -> Self {
        let dealer = TrustedDealer::new(ThresholdConfig::new(2, 2).unwrap());
        let (mut shares, pubkey_pkg) = dealer.generate("approval-pending").unwrap();
        let bus = MemoryBus::new();
        let cosigner_transport = bus.transport();
        let requester_transport = bus.transport();
        if interactive {
            for t in [&cosigner_transport, &requester_transport] {
                t.refuse_if(|ev| tagged(ev, "nonce_commitment"));
            }
        }
        let mut cosigner = KfpNode::with_transport(
            shares.remove(0),
            cosigner_transport.clone() as Arc<dyn CosignTransport>,
            None,
            None,
        )
        .unwrap();
        let mut requester = KfpNode::with_transport(
            shares.remove(0),
            requester_transport as Arc<dyn CosignTransport>,
            None,
            None,
        )
        .unwrap();
        cosigner.set_hooks(hooks);

        let mut cosigner_rx = cosigner.subscribe();
        let requester_rx = requester.subscribe();
        let shutdowns = [
            cosigner.take_shutdown_handle(),
            requester.take_shutdown_handle(),
        ]
        .into_iter()
        .flatten()
        .collect();
        let cosigner = Arc::new(cosigner);
        let requester = Arc::new(requester);
        let handles = [&cosigner, &requester]
            .into_iter()
            .map(|n| {
                let n = Arc::clone(n);
                tokio::spawn(async move {
                    let _ = n.run().await;
                })
            })
            .collect();

        let mut group = Self {
            bus,
            cosigner,
            requester,
            cosigner_transport,
            requester_rx,
            verifying_key: pubkey_pkg
                .verifying_key()
                .serialize()
                .unwrap()
                .try_into()
                .unwrap(),
            shutdowns,
            handles,
        };
        wait_for(&mut group.requester_rx, |e| {
            matches!(e, KfpNodeEvent::PeerDiscovered { .. })
        })
        .await;
        wait_for(&mut cosigner_rx, |e| {
            matches!(e, KfpNodeEvent::PeerDiscovered { .. })
        })
        .await;
        group
    }

    fn request(&self) -> tokio::task::JoinHandle<keep_frost_net::Result<[u8; 64]>> {
        let requester = Arc::clone(&self.requester);
        tokio::spawn(async move {
            requester
                .request_signature(DIGEST.to_vec(), "nostr-event")
                .await
        })
    }

    /// Events the co-signer published tagged `kind`.
    async fn cosigner_sent(&self, kind: &str) -> Vec<Event> {
        self.published_by(self.cosigner.pubkey(), kind).await
    }

    async fn published_by(&self, author: PublicKey, kind: &str) -> Vec<Event> {
        self.cosigner_transport
            .fetch_events(
                Filter::new()
                    .author(author)
                    .kind(Kind::Custom(KFP_EVENT_KIND)),
                Duration::from_secs(1),
            )
            .await
            .unwrap()
            .into_iter()
            .filter(|e| tagged(e, kind))
            .collect()
    }

    /// Publish `event` again, as a relay redelivering it would.
    async fn redeliver(&self, event: &Event) {
        self.bus.transport().send_event(event).await.unwrap();
    }

    fn verifies(&self, signature: &[u8; 64]) -> bool {
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&self.verifying_key[1..33])
            .expect("x-only group key");
        let msg = bitcoin::secp256k1::Message::from_digest(DIGEST);
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(signature).unwrap();
        secp.verify_schnorr(&sig, &msg, &key).is_ok()
    }

    async fn stop(self) {
        for tx in self.shutdowns {
            let _ = tx.try_send(());
        }
        for h in self.handles {
            let _ = timeout(Duration::from_secs(2), h).await;
        }
    }
}

fn tagged(event: &Event, kind: &str) -> bool {
    event.tags.iter().any(|t| {
        t.as_slice().first().map(String::as_str) == Some("t")
            && t.as_slice().get(1).map(String::as_str) == Some(kind)
    })
}

async fn wait_for(
    rx: &mut tokio::sync::broadcast::Receiver<KfpNodeEvent>,
    pred: impl Fn(&KfpNodeEvent) -> bool,
) {
    timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(e) = rx.recv().await {
                if pred(&e) {
                    return;
                }
            }
        }
    })
    .await
    .expect("the awaited event never arrived");
}

async fn approved_after_signs(after: Duration, interactive: bool) {
    let hooks = PromptHooks::new(after, true);
    let group = Group::start(hooks.clone(), interactive).await;

    let started = Instant::now();
    let signature = timeout(Duration::from_secs(120), group.request())
        .await
        .expect("the request returns")
        .unwrap()
        .expect("an approval inside the cap is signed");
    let elapsed = started.elapsed();

    assert!(group.verifies(&signature), "the signature verifies");
    assert!(
        elapsed >= after,
        "signed only after the approval: {elapsed:?}"
    );
    assert_eq!(hooks.prompts.load(Ordering::SeqCst), 1);
    assert_eq!(group.cosigner_sent("sign_approval_pending").await.len(), 1);
    group.stop().await;
}

/// An approval twenty seconds in, past the plain round timeout, is still
/// signed because the co-signer told the requester to keep the round open.
#[tokio::test(start_paused = true)]
async fn an_approval_after_twenty_seconds_is_signed() {
    approved_after_signs(Duration::from_secs(20), false).await;
}

/// The same with no pooled nonces, so the co-signer's commitment is what is
/// missing while it waits rather than its share.
#[tokio::test(start_paused = true)]
async fn an_approval_after_twenty_seconds_is_signed_interactively() {
    approved_after_signs(Duration::from_secs(20), true).await;
}

/// On the real clock, which sessions expire by: thirty-two seconds in, past
/// the requester's own session timeout and the reap after it, the round is
/// still there to finish.
#[tokio::test]
async fn an_approval_past_the_session_reap_is_signed() {
    approved_after_signs(Duration::from_secs(32), true).await;
}

/// Without the pending report the requester gives up at the plain round
/// timeout, so the twenty-second approval is wasted.
#[tokio::test(start_paused = true)]
async fn without_the_pending_report_the_round_times_out() {
    let hooks = PromptHooks::new(Duration::from_secs(20), true);
    let group = Group::start(hooks.clone(), false).await;
    group
        .cosigner_transport
        .refuse_if(|ev| tagged(ev, "sign_approval_pending"));

    let result = timeout(Duration::from_secs(120), group.request())
        .await
        .expect("the request returns")
        .unwrap();
    assert!(
        matches!(result, Err(FrostNetError::Timeout(_))),
        "{result:?}"
    );
    group.stop().await;
}

/// An approval after the co-signer's deadline is not acted on: the round
/// fails and the co-signer never commits.
#[tokio::test(start_paused = true)]
async fn an_approval_after_the_cap_is_not_signed() {
    let hooks = PromptHooks::new(Duration::from_secs(70), true);
    let group = Group::start(hooks.clone(), true).await;

    let result = timeout(Duration::from_secs(180), group.request())
        .await
        .expect("the request returns")
        .unwrap();
    assert!(result.is_err(), "{result:?}");
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(group.cosigner_sent("commitment").await.is_empty());
    assert!(group.cosigner_sent("signature_share").await.is_empty());
    group.stop().await;
}

/// Repeating the pending report cannot hold the round open past the cap
/// measured from its start.
#[tokio::test(start_paused = true)]
async fn repeated_pending_reports_do_not_extend_past_the_cap() {
    let hooks = PromptHooks::new(Duration::from_secs(600), true);
    let group = Group::start(hooks.clone(), false).await;
    // Keep the co-signer's refusal at its own deadline from ending the round,
    // so only the requester's cap does.
    group.cosigner_transport.refuse_if(|ev| tagged(ev, "error"));

    let started = Instant::now();
    let request = group.request();
    let mut rx = group.requester.subscribe();
    wait_for(&mut rx, |e| {
        matches!(e, KfpNodeEvent::CosignerApprovalPending { .. })
    })
    .await;
    let report = group
        .cosigner_sent("sign_approval_pending")
        .await
        .pop()
        .expect("the co-signer reported its pending approval");
    let redelivery = async {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            group.redeliver(&report).await;
        }
    };
    let result = tokio::select! {
        r = request => r.unwrap(),
        _ = redelivery => unreachable!(),
    };
    let elapsed = started.elapsed();

    assert!(
        matches!(result, Err(FrostNetError::Timeout(_))),
        "{result:?}"
    );
    assert!(
        elapsed >= keep_frost_net::APPROVAL_ROUND_HARD_CAP
            && elapsed < keep_frost_net::APPROVAL_ROUND_HARD_CAP + Duration::from_secs(2),
        "the round ends at the cap: {elapsed:?}"
    );
    group.stop().await;
}

/// The co-signer keeps answering pings while its prompt is open.
#[tokio::test(start_paused = true)]
async fn a_ping_is_answered_while_a_prompt_is_open() {
    let hooks = PromptHooks::new(Duration::from_secs(30), true);
    let mut group = Group::start(hooks.clone(), false).await;

    let request = group.request();
    wait_for(&mut group.requester_rx, |e| {
        matches!(e, KfpNodeEvent::CosignerApprovalPending { .. })
    })
    .await;
    let responsive = group
        .requester
        .ping_peers(Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(responsive, vec![1]);
    assert_eq!(hooks.prompts.load(Ordering::SeqCst), 1);

    let signature = request.await.unwrap().expect("still signed after the ping");
    assert!(group.verifies(&signature));
    group.stop().await;
}

/// A redelivered copy of a request whose approval is pending opens no second
/// prompt and yields one commitment.
#[tokio::test(start_paused = true)]
async fn a_duplicate_request_gives_one_prompt_and_one_commitment() {
    let hooks = PromptHooks::new(Duration::from_secs(20), true);
    let mut group = Group::start(hooks.clone(), true).await;

    let request = group.request();
    wait_for(&mut group.requester_rx, |e| {
        matches!(e, KfpNodeEvent::CosignerApprovalPending { .. })
    })
    .await;
    let copy = group
        .published_by(group.requester.pubkey(), "sign_request")
        .await
        .pop()
        .expect("the request is on the bus");
    group.redeliver(&copy).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(hooks.prompts.load(Ordering::SeqCst), 1);

    let signature = request.await.unwrap().expect("signed once approved");
    assert!(group.verifies(&signature));
    assert_eq!(hooks.prompts.load(Ordering::SeqCst), 1);
    assert_eq!(group.cosigner_sent("commitment").await.len(), 1);
    group.stop().await;
}

/// The kill switch flipped while the prompt is open refuses the approved
/// request: no commitment, no signature.
#[tokio::test(start_paused = true)]
async fn the_kill_switch_flipped_during_a_prompt_refuses() {
    let hooks = PromptHooks::new(Duration::from_secs(20), true);
    let mut group = Group::start(hooks.clone(), true).await;

    let request = group.request();
    wait_for(&mut group.requester_rx, |e| {
        matches!(e, KfpNodeEvent::CosignerApprovalPending { .. })
    })
    .await;
    hooks.permitted.store(false, Ordering::SeqCst);

    let result = timeout(Duration::from_secs(120), request)
        .await
        .expect("the request returns")
        .unwrap();
    assert!(result.is_err(), "{result:?}");
    assert!(group.cosigner_sent("commitment").await.is_empty());
    assert!(group.cosigner_sent("signature_share").await.is_empty());
    group.stop().await;
}

/// A denied prompt refuses: no commitment, no signature.
#[tokio::test(start_paused = true)]
async fn a_denied_prompt_refuses() {
    let hooks = PromptHooks::new(Duration::from_secs(5), false);
    let group = Group::start(hooks.clone(), true).await;

    let result = timeout(Duration::from_secs(120), group.request())
        .await
        .expect("the request returns")
        .unwrap();
    assert!(result.is_err(), "{result:?}");
    assert!(group.cosigner_sent("commitment").await.is_empty());
    group.stop().await;
}

/// A hook that only implements `pre_sign` is asked once and signs at once,
/// with no pending report.
#[tokio::test(start_paused = true)]
async fn a_legacy_hook_behaves_as_before() {
    let hooks = Arc::new(LegacyHooks::default());
    let group = Group::start(hooks.clone(), false).await;

    let started = Instant::now();
    let signature = timeout(Duration::from_secs(60), group.request())
        .await
        .expect("the request returns")
        .unwrap()
        .expect("signed");
    assert!(group.verifies(&signature));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(hooks.calls.load(Ordering::SeqCst), 1);
    assert!(group
        .cosigner_sent("sign_approval_pending")
        .await
        .is_empty());
    group.stop().await;
}

/// A kill switch already on refuses in `pre_sign`, so the prompt is never
/// opened.
#[tokio::test(start_paused = true)]
async fn a_refusing_pre_sign_never_opens_a_prompt() {
    let hooks = PromptHooks::new(Duration::from_secs(5), true);
    hooks.permitted.store(false, Ordering::SeqCst);
    let group = Group::start(hooks.clone(), true).await;

    let result = timeout(Duration::from_secs(120), group.request())
        .await
        .expect("the request returns")
        .unwrap();
    assert!(result.is_err(), "{result:?}");
    assert_eq!(hooks.prompts.load(Ordering::SeqCst), 0);
    assert!(group.cosigner_sent("commitment").await.is_empty());
    group.stop().await;
}

/// A request a human denied is not shown again when a copy is redelivered.
#[tokio::test(start_paused = true)]
async fn a_denied_request_is_not_prompted_again() {
    let hooks = PromptHooks::new(Duration::from_secs(5), false);
    let group = Group::start(hooks.clone(), true).await;

    let result = timeout(Duration::from_secs(120), group.request())
        .await
        .expect("the request returns")
        .unwrap();
    assert!(result.is_err(), "{result:?}");
    assert_eq!(hooks.prompts.load(Ordering::SeqCst), 1);

    let copy = group
        .published_by(group.requester.pubkey(), "sign_request")
        .await
        .pop()
        .expect("the request is on the bus");
    group.redeliver(&copy).await;
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(hooks.prompts.load(Ordering::SeqCst), 1);
    assert!(group.cosigner_sent("commitment").await.is_empty());
    group.stop().await;
}

/// On the real clock: in a 3-of-3 round without pooled nonces, a co-signer
/// that commits at once keeps its session until a second co-signer approves
/// thirty-two seconds in, past the plain session timeout and the reap after
/// it, so the round still completes.
#[tokio::test]
async fn an_instant_co_signer_waits_for_a_slow_approval() {
    let dealer = TrustedDealer::new(ThresholdConfig::new(3, 3).unwrap());
    let (shares, pubkey_pkg) = dealer.generate("approval-pending-3").unwrap();
    let bus = MemoryBus::new();
    let transports: Vec<_> = (0..3).map(|_| bus.transport()).collect();
    for t in &transports {
        t.refuse_if(|ev| tagged(ev, "nonce_commitment"));
    }
    let mut nodes: Vec<KfpNode> = shares
        .into_iter()
        .zip(&transports)
        .map(|(share, t)| {
            KfpNode::with_transport(share, t.clone() as Arc<dyn CosignTransport>, None, None)
                .unwrap()
        })
        .collect();
    let slow = PromptHooks::new(Duration::from_secs(32), true);
    nodes[1].set_hooks(slow.clone());
    let mut rxs: Vec<_> = nodes.iter().map(|n| n.subscribe()).collect();
    let shutdowns: Vec<_> = nodes
        .iter_mut()
        .filter_map(|n| n.take_shutdown_handle())
        .collect();
    let nodes: Vec<Arc<KfpNode>> = nodes.into_iter().map(Arc::new).collect();
    let handles: Vec<_> = nodes
        .iter()
        .map(|n| {
            let n = Arc::clone(n);
            tokio::spawn(async move {
                let _ = n.run().await;
            })
        })
        .collect();
    for rx in &mut rxs {
        for _ in 0..2 {
            wait_for(rx, |e| matches!(e, KfpNodeEvent::PeerDiscovered { .. })).await;
        }
    }

    let result = timeout(
        Duration::from_secs(90),
        nodes[2].request_signature(DIGEST.to_vec(), "nostr-event"),
    )
    .await
    .expect("the request returns");

    for tx in shutdowns {
        let _ = tx.try_send(());
    }
    for h in handles {
        let _ = timeout(Duration::from_secs(2), h).await;
    }

    let signature = result.expect("signed once the slow co-signer approves");
    assert_eq!(slow.prompts.load(Ordering::SeqCst), 1);
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let vk = pubkey_pkg.verifying_key().serialize().unwrap();
    let key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&vk[1..33]).unwrap();
    let msg = bitcoin::secp256k1::Message::from_digest(DIGEST);
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&signature).unwrap();
    secp.verify_schnorr(&sig, &msg, &key)
        .expect("the signature verifies under the group key");
}
