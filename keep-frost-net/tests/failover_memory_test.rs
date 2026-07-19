// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Deterministic in-process `MemoryTransport` counterpart of the MockRelay test
//! `test_failover_when_cosigner_dropped_mid_session` (in `multinode_test.rs`),
//! covering the issue #412 fast-failover acceptance over the memory bus (#790).
//!
//! A co-signer dropped mid-session must fail over to the surviving co-signer
//! FAST: the pre-round liveness ping excludes the freshly-dropped peer (still
//! "online" by its recent announce) up front, so signing goes straight to the
//! live peer instead of burning a full doomed round timeout.

use std::sync::Arc;
use std::time::Duration;

use keep_core::frost::{ThresholdConfig, TrustedDealer};
use keep_frost_net::test_support::MemoryBus;
use keep_frost_net::{CosignTransport, KfpNode, KfpNodeEvent};
use tokio::sync::mpsc;
use tokio::time::timeout;

async fn graceful_shutdown(
    shutdown_tx: Option<mpsc::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
) {
    if let Some(tx) = shutdown_tx {
        let _ = tx.try_send(());
    }
    let _ = timeout(Duration::from_secs(2), handle).await;
}

/// Issue #412 acceptance over the in-process bus: after a warm-up all-online
/// signature, co-signer node2 is taken offline (its transport stays registered
/// on the bus but its run loop stops, so it no longer pongs). node3's next
/// `request_signature` must fail over to node1 and return a 64-byte signature
/// quickly, because the pre-round liveness ping excludes the dead node2 before
/// committing to a round.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failover_completes_fast_when_cosigner_dropped_over_memory_transport() {
    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pubkey_pkg) = dealer.generate("mem-failover").unwrap();
    let share1 = shares.remove(0);
    let share2 = shares.remove(0);
    let share3 = shares.remove(0);

    let bus = MemoryBus::new();
    let mut node1 = KfpNode::with_transport(
        share1,
        bus.transport() as Arc<dyn CosignTransport>,
        None,
        None,
    )
    .expect("node1");
    let mut node2 = KfpNode::with_transport(
        share2,
        bus.transport() as Arc<dyn CosignTransport>,
        None,
        None,
    )
    .expect("node2");
    let mut node3 = KfpNode::with_transport(
        share3,
        bus.transport() as Arc<dyn CosignTransport>,
        None,
        None,
    )
    .expect("node3");

    let mut rx3 = node3.subscribe();
    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();
    let shutdown3 = node3.take_shutdown_handle();

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let node3 = Arc::new(node3);
    let node1_for_run = Arc::clone(&node1);
    let node2_for_run = Arc::clone(&node2);
    let node3_for_run = Arc::clone(&node3);

    let node1_handle = tokio::spawn(async move {
        let _ = node1_for_run.run().await;
    });
    let node2_handle = tokio::spawn(async move {
        let _ = node2_for_run.run().await;
    });
    let node3_handle = tokio::spawn(async move {
        let _ = node3_for_run.run().await;
    });

    let mut peers_discovered = 0u32;
    let discovery = timeout(Duration::from_secs(30), async {
        while peers_discovered < 2 {
            if let Ok(KfpNodeEvent::PeerDiscovered { .. }) = rx3.recv().await {
                peers_discovered += 1;
            }
        }
    })
    .await;
    if discovery.is_err() {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        graceful_shutdown(shutdown3, node3_handle).await;
        panic!("Peer discovery timed out: only {peers_discovered} peers discovered");
    }

    // Warm up with one all-online signature first. This mirrors the issue #412
    // scenario (repeated signing after approvals) and ensures the ping path is
    // warm so the liveness pong is prompt.
    let warmup = timeout(Duration::from_secs(30), async {
        node3.request_signature(b"warmup".to_vec(), "raw").await
    })
    .await;
    if !matches!(warmup, Ok(Ok(_))) {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        graceful_shutdown(shutdown3, node3_handle).await;
        panic!("Warm-up signing failed: {warmup:?}");
    }

    // Take co-signer node2 offline. Its transport stays registered on the bus,
    // so it remains "online" in node3's peer table for up to offline_threshold;
    // without the pre-ping node3 may still select it and burn a full round
    // timeout. node1 remains live.
    graceful_shutdown(shutdown2, node2_handle).await;

    let started = std::time::Instant::now();
    let sign_result = timeout(Duration::from_secs(30), async {
        node3.request_signature(b"failover".to_vec(), "raw").await
    })
    .await;
    let elapsed = started.elapsed();

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown3, node3_handle).await;

    match sign_result {
        Ok(Ok(signature)) => assert_eq!(signature.len(), 64),
        Ok(Err(e)) => panic!("Failover signing failed: {e:?}"),
        Err(_) => panic!("Failover signing timed out after 30s"),
    }
    // Observed elapsed over the in-process bus is a stable ~3.05s (the pre-ping
    // budget + one live round); the 12s bound, matching the MockRelay
    // counterpart, is comfortably above that but far below the ~15s a single
    // doomed round would cost without the pre-ping excluding the dead co-signer.
    assert!(
        elapsed < Duration::from_secs(12),
        "failover took {elapsed:?}, expected a few seconds (pre-ping should exclude the dead co-signer up front)"
    );
}
