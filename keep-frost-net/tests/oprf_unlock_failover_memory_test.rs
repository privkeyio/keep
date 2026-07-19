// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Deterministic OPRF-unlock failover over the in-process `MemoryTransport`. In
//! a 2-of-3, one holder is persistently silent: its default approval hook DENIES,
//! so it clears attestation and rate limit but returns no partial, which from the
//! box is indistinguishable from unreachable. The box samples `threshold-1 = 1`
//! holder at random; when it lands on the silent one it must exclude it and
//! re-sample the live holder WITHIN the same unlock rather than failing the boot
//! closed. This is the geo-distributed flaky-holder case for the passphrase-
//! recovery path. A short session timeout keeps each failover round quick.
//!
//! Every iteration derives a key (immediately when the live holder is sampled,
//! else after one failover round), so the test is deterministically green; a
//! regression that drops failover fails any iteration that samples the silent
//! holder. Counterpart of the MockRelay
//! `test_oprf_unlock_fails_over_when_one_holder_silent` (#790).

use std::sync::Arc;
use std::time::Duration;

use keep_core::frost::{ThresholdConfig, TrustedDealer};
use keep_frost_net::test_support::MemoryBus;
use keep_frost_net::{AttestationStatus, CosignTransport, KfpNode, KfpNodeEvent};
use tokio::time::timeout;

const OPRF_INPUT: &[u8] = b"keep-node-vault-v1";

/// Holder-side hook that approves every OPRF evaluation (the oracle defaults to
/// DENY, so the live holder must opt in; the silent holder keeps the default).
struct ApproveOprfHooks;

impl keep_frost_net::SigningHooks for ApproveOprfHooks {
    fn pre_sign(&self, _session: &keep_frost_net::SessionInfo) -> keep_frost_net::Result<()> {
        Ok(())
    }
    fn post_sign(&self, _session: &keep_frost_net::SessionInfo, _signature: &[u8; 64]) {}
    fn approve_oprf_eval(
        &self,
        _requester_share_index: u16,
        _session_id: [u8; 32],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        Box::pin(async { true })
    }
}

/// Split one OPRF key 2-of-3; `KeyShare` at index `i` is the vsss share for
/// FROST identifier `i + 1`.
fn split_oprf_key_2of3() -> Vec<keep_core::oprf::threshold::KeyShare> {
    use k256::elliptic_curve::rand_core::OsRng;
    use k256::Scalar;
    let mut rng = OsRng;
    let secret = <Scalar as k256::elliptic_curve::Field>::random(&mut rng);
    keep_core::oprf::threshold::split_key(&secret, 2, 3, rng).expect("split oprf key")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oprf_unlock_fails_over_when_one_holder_silent_over_memory_transport() {
    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("mem-oprf-failover").unwrap();
    let share1 = shares.remove(0); // FROST id 1 = box
    let share2 = shares.remove(0); // FROST id 2 = silent holder
    let share3 = shares.remove(0); // FROST id 3 = live holder

    let oprf = split_oprf_key_2of3();

    // Short session timeout so a failover round costs ~3s, not the default.
    let short = Some(Duration::from_secs(3));
    let bus = MemoryBus::new();
    let mk = |share, timeout| {
        KfpNode::with_transport(
            share,
            bus.transport() as Arc<dyn CosignTransport>,
            None,
            timeout,
        )
        .expect("node")
    };

    let mut node1 = mk(share1, short);
    node1.set_oprf_key_share(oprf[0]);
    // node2 keeps the DEFAULT approval hook, which DENIES: it clears every prior
    // gate but returns no partial, so from the box it is silent.
    let mut node2 = mk(share2, short);
    node2.set_oprf_key_share(oprf[1]);
    let mut node3 = mk(share3, short);
    node3.set_oprf_key_share(oprf[2]);
    node3.set_hooks(Arc::new(ApproveOprfHooks));

    let mut rx1 = node1.subscribe();
    let _s1 = node1.take_shutdown_handle();
    let _s2 = node2.take_shutdown_handle();
    let _s3 = node3.take_shutdown_handle();

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let node3 = Arc::new(node3);
    let n1r = Arc::clone(&node1);
    let n2r = Arc::clone(&node2);
    let n3r = Arc::clone(&node3);
    let _h1 = tokio::spawn(async move {
        let _ = n1r.run().await;
    });
    let _h2 = tokio::spawn(async move {
        let _ = n2r.run().await;
    });
    let _h3 = tokio::spawn(async move {
        let _ = n3r.run().await;
    });

    // The box must discover BOTH holders so either can be sampled.
    let discovery = timeout(Duration::from_secs(30), async {
        let mut discovered = 0u32;
        while discovered < 2 {
            if let Ok(KfpNodeEvent::PeerDiscovered { .. }) = rx1.recv().await {
                discovered += 1;
            }
        }
    })
    .await;
    assert!(discovery.is_ok(), "box must discover both holders");
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut first_key: Option<[u8; 32]> = None;
    for i in 0..6 {
        // Re-assert the box as Verified on both holders before each unlock; a
        // periodic re-announce can otherwise reset attestation between rounds.
        node2.test_set_peer_attestation(1, AttestationStatus::Verified);
        node3.test_set_peer_attestation(1, AttestationStatus::Verified);

        let key = timeout(
            Duration::from_secs(30),
            node1.request_oprf_unlock(OPRF_INPUT, "vault0", 1),
        )
        .await
        .unwrap_or_else(|_| panic!("unlock iteration {i} timed out"))
        .unwrap_or_else(|e| {
            panic!("unlock iteration {i} failed (a failover regression fails closed here): {e}")
        });
        assert_eq!(key.len(), 32, "iteration {i}: LUKS key must be 32 bytes");
        let bytes: [u8; 32] = *key;
        match first_key {
            None => first_key = Some(bytes),
            Some(k0) => assert_eq!(
                k0, bytes,
                "iteration {i}: every unlock must derive the same key regardless of which holder answered"
            ),
        }
    }
}
