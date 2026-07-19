// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Deterministic health-check-then-sign coverage over the in-process
//! `MemoryTransport`. `health_check` pings every co-signer and waits for pongs;
//! this is the regression guard for the ping/pong self-deadlock (handle_ping /
//! handle_pong once took a `peers.read()` guard across a `peers.write()` in the
//! same task). Over the in-process bus the pongs return immediately, so the
//! check is deterministic and fast rather than relay-timing-bound, and signing
//! must still complete afterward. Counterpart of the MockRelay
//! `test_health_check_then_sign_no_deadlock` (#790).

use std::sync::Arc;
use std::time::Duration;

use keep_core::frost::{ThresholdConfig, TrustedDealer};
use keep_frost_net::test_support::MemoryBus;
use keep_frost_net::{CosignTransport, KfpNode, KfpNodeEvent};
use tokio::time::timeout;

fn spawn_run(node: Arc<KfpNode>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = node.run().await;
    })
}

#[tokio::test]
async fn health_check_then_sign_completes_over_memory_transport() {
    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("mem-health").unwrap();
    let share1 = shares.remove(0);
    let share2 = shares.remove(0);
    let share3 = shares.remove(0);

    let bus = MemoryBus::new();
    let mk = |share| {
        KfpNode::with_transport(
            share,
            bus.transport() as Arc<dyn CosignTransport>,
            None,
            None,
        )
        .expect("node")
    };
    let mut node1 = mk(share1);
    let mut node2 = mk(share2);
    let mut node3 = mk(share3);

    let mut rx3 = node3.subscribe();
    let _s1 = node1.take_shutdown_handle();
    let _s2 = node2.take_shutdown_handle();
    let _s3 = node3.take_shutdown_handle();

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let node3 = Arc::new(node3);
    let _h1 = spawn_run(Arc::clone(&node1));
    let _h2 = spawn_run(Arc::clone(&node2));
    let _h3 = spawn_run(Arc::clone(&node3));

    // node3 must see both co-signers.
    let discovered = timeout(Duration::from_secs(30), async {
        let mut n = 0u32;
        while n < 2 {
            if let Ok(KfpNodeEvent::PeerDiscovered { .. }) = rx3.recv().await {
                n += 1;
            }
        }
    })
    .await;
    assert!(discovered.is_ok(), "node3 must discover both co-signers");

    // Let the reciprocal announces flush so both peers are ready to pong.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The deadlock regression: health_check must RETURN (bounded), and over the
    // in-process bus both co-signers answer the liveness ping. The ping window is
    // short because pongs are delivered instantly on the in-process bus (the
    // window is a max wait, so it bounds the test rather than gating on a relay).
    let health = timeout(
        Duration::from_secs(10),
        node3.health_check(Duration::from_secs(2)),
    )
    .await
    .expect("health_check deadlocked (did not return)")
    .expect("health_check returned an error");
    assert_eq!(
        health.responsive.len(),
        2,
        "both co-signers should answer the liveness ping"
    );

    // Signing after the ping round-trip must still complete.
    let sign_result = timeout(
        Duration::from_secs(30),
        node3.request_signature(b"health-then-sign".to_vec(), "raw"),
    )
    .await;
    match sign_result {
        Ok(Ok(sig)) => assert_eq!(sig.len(), 64),
        Ok(Err(e)) => panic!("signing after health check failed: {e:?}"),
        Err(_) => panic!("signing after health check timed out"),
    }
}
