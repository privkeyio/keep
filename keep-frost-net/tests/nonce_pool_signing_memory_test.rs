// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Deterministic nonce-pool signing robustness over the in-process
//! `MemoryTransport`. FROST nonce handling is the protocol's sharpest edge: a
//! reused round-1 commitment leaks the secret share, so these two tests pin the
//! single-use accounting and the consecutive-round churn that guard it.
//!
//! * `repeated_signing_completes_over_memory_transport` drives six signs in a row
//!   on a persistent initiator; each must complete, proving per-round session and
//!   nonce state is cleaned up rather than leaking or colliding across rounds
//!   (the stale_nonce / "Unknown identifier" regression).
//! * `nonce_pre_exchange_signing_over_memory_transport` pre-exchanges round-1
//!   commitments into the signer's pool, then asserts exactly ONE pooled
//!   commitment was consumed across the selected peers, proving pre-committed
//!   nonces are single-use.
//!
//! Counterparts of the MockRelay `test_repeated_signing` and
//! `test_signing_flow_with_nonce_pre_exchange` (#790).

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

async fn await_discovery(rx3: &mut tokio::sync::broadcast::Receiver<KfpNodeEvent>) {
    let discovered = timeout(Duration::from_secs(30), async {
        let mut n = 0u32;
        while n < 2 {
            if let Ok(KfpNodeEvent::PeerDiscovered { .. }) = rx3.recv().await {
                n += 1;
            }
        }
    })
    .await;
    assert!(discovered.is_ok(), "signer must discover both co-signers");
}

#[tokio::test]
async fn repeated_signing_completes_over_memory_transport() {
    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("mem-repeat-signing").unwrap();
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
    let mut node1 = mk(shares.remove(0));
    let mut node2 = mk(shares.remove(0));
    let mut node3 = mk(shares.remove(0));

    let mut rx3 = node3.subscribe();
    // Hold the shutdown handles for the whole test: they own the shutdown sender,
    // and dropping them makes each node's run() see all-senders-dropped and exit.
    let _s1 = node1.take_shutdown_handle();
    let _s2 = node2.take_shutdown_handle();
    let _s3 = node3.take_shutdown_handle();

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let node3 = Arc::new(node3);
    let _h1 = spawn_run(Arc::clone(&node1));
    let _h2 = spawn_run(Arc::clone(&node2));
    let _h3 = spawn_run(Arc::clone(&node3));

    await_discovery(&mut rx3).await;

    let mut failures = Vec::new();
    for i in 0..6u32 {
        let msg = format!("repeat-sign-{i}").into_bytes();
        match timeout(Duration::from_secs(30), node3.request_signature(msg, "raw")).await {
            Ok(Ok(sig)) => assert_eq!(sig.len(), 64),
            Ok(Err(e)) => failures.push(format!("sign {i}: {e:?}")),
            Err(_) => failures.push(format!("sign {i}: timeout")),
        }
    }
    assert!(
        failures.is_empty(),
        "repeated signing failures: {failures:#?}"
    );
}

#[tokio::test]
async fn nonce_pre_exchange_signing_over_memory_transport() {
    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("mem-nonce-pre-exchange").unwrap();
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
    let mut node1 = mk(shares.remove(0));
    let mut node2 = mk(shares.remove(0));
    let mut node3 = mk(shares.remove(0));

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

    await_discovery(&mut rx3).await;

    // The co-signers must also see the signer so their pre-exchange broadcasts
    // reach it.
    let peers_ready = timeout(Duration::from_secs(30), async {
        loop {
            if node1.online_peers() >= 2 && node2.online_peers() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        peers_ready.is_ok(),
        "co-signers did not discover the signer"
    );

    // Each peer pre-exchanges round-1 commitments into the signer's pool.
    node1.replenish_nonce_pool().await.expect("node1 replenish");
    node2.replenish_nonce_pool().await.expect("node2 replenish");

    let pool_ready = timeout(Duration::from_secs(20), async {
        loop {
            if node3.nonce_pool_peer_available(1) > 0 && node3.nonce_pool_peer_available(2) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        pool_ready.is_ok(),
        "pre-exchanged commitments did not reach the signer"
    );

    let before_1 = node3.nonce_pool_peer_available(1);
    let before_2 = node3.nonce_pool_peer_available(2);

    let sign_result = timeout(
        Duration::from_secs(30),
        node3.request_signature(b"pre-exchanged nonce signing".to_vec(), "raw"),
    )
    .await;

    let after_1 = node3.nonce_pool_peer_available(1);
    let after_2 = node3.nonce_pool_peer_available(2);

    match sign_result {
        Ok(Ok(sig)) => assert_eq!(sig.len(), 64),
        Ok(Err(e)) => panic!("signing failed: {e:?}"),
        Err(_) => panic!("signing timed out"),
    }

    // A 2-of-3 round selects exactly one peer besides the requester, so exactly
    // one pooled commitment must have been consumed (single-use).
    let consumed = (before_1 - after_1) + (before_2 - after_2);
    assert_eq!(
        consumed, 1,
        "expected exactly one pooled commitment consumed across selected peers"
    );
}
