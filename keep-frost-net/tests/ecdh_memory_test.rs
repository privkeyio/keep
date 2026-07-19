// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Deterministic multi-peer ECDH coordination tests over the in-process
//! `MemoryTransport` (no relay, no network timing). These cover the requester
//! orchestration and responder delivery paths that the single-node `ecdh.rs`
//! unit tests cannot reach (#543), by driving real `request_ecdh` sessions
//! between real `KfpNode`s wired to a shared in-process bus.

use std::sync::Arc;
use std::time::Duration;

use keep_core::frost::{ThresholdConfig, TrustedDealer};
use keep_frost_net::test_support::MemoryBus;
use keep_frost_net::{AttestationStatus, CosignTransport, KfpNode, KfpNodeEvent};
use tokio::time::timeout;

/// Spawn `node.run()` and return the join handle.
fn spawn_run(node: Arc<KfpNode>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = node.run().await;
    })
}

/// Wait until both nodes have discovered at least one peer (drives announce
/// delivery over the in-process bus). Returns whether discovery completed.
async fn await_mutual_discovery(
    rx1: &mut tokio::sync::broadcast::Receiver<KfpNodeEvent>,
    rx2: &mut tokio::sync::broadcast::Receiver<KfpNodeEvent>,
) -> bool {
    let mut n1 = 0u32;
    let mut n2 = 0u32;
    timeout(Duration::from_secs(30), async {
        loop {
            tokio::select! {
                Ok(KfpNodeEvent::PeerDiscovered { .. }) = rx1.recv() => n1 += 1,
                Ok(KfpNodeEvent::PeerDiscovered { .. }) = rx2.recv() => n2 += 1,
            }
            if n1 >= 1 && n2 >= 1 {
                return;
            }
        }
    })
    .await
    .is_ok()
}

/// A 2-of-3 group drives `request_ecdh` to completion over the in-process bus,
/// and the shared secret matches an independent recipient-side computation.
/// This exercises the full responder pipeline (handle_ecdh_request ->
/// handle_ecdh_share -> handle_ecdh_complete) and the requester completion arm
/// deterministically, with no relay.
#[tokio::test]
async fn ecdh_completes_over_memory_transport() {
    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, pubkey_pkg) = dealer.generate("mem-ecdh").unwrap();
    let share1 = shares.remove(0);
    let share2 = shares.remove(0);

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

    let mut rx1 = node1.subscribe();
    let mut rx2 = node2.subscribe();
    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let h1 = spawn_run(Arc::clone(&node1));
    let h2 = spawn_run(Arc::clone(&node2));

    let discovered = await_mutual_discovery(&mut rx1, &mut rx2).await;
    assert!(
        discovered,
        "peers must discover each other over the memory bus"
    );

    // Arbitrary external recipient (a syntactically valid compressed point).
    let recipient_secret = bitcoin::secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let recipient_pubkey: [u8; 33] = recipient_secret.public_key(&secp).serialize();

    // The ECDH oracle requires the requester to be fresh-Verified; these nodes
    // run without an attestation policy, so mark the requester (share index 1)
    // Verified on the responder after the reciprocal announces have flushed.
    tokio::time::sleep(Duration::from_millis(500)).await;
    node2.test_set_peer_attestation(1, AttestationStatus::Verified);

    let request_result = timeout(
        Duration::from_secs(30),
        node1.request_ecdh(&recipient_pubkey),
    )
    .await;

    if let Some(tx) = shutdown1 {
        let _ = tx.try_send(());
    }
    if let Some(tx) = shutdown2 {
        let _ = tx.try_send(());
    }
    let _ = timeout(Duration::from_secs(2), h1).await;
    let _ = timeout(Duration::from_secs(2), h2).await;

    let shared_secret = match request_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => panic!("request_ecdh failed: {e}"),
        Err(_) => panic!("request_ecdh timed out over the memory bus"),
    };

    // Independent recipient-side oracle: cosigners aggregate to the x-coordinate
    // of recipient_pubkey * group_secret, which by ECDH symmetry equals the
    // x-coordinate of group_pubkey * recipient_secret. Derived without touching
    // request_ecdh, so it is a genuine oracle.
    let vk_bytes = pubkey_pkg.verifying_key().serialize().unwrap();
    let group_point = bitcoin::secp256k1::PublicKey::from_slice(vk_bytes.as_slice())
        .expect("group verifying key is a valid compressed point");
    let recipient_scalar = bitcoin::secp256k1::Scalar::from_be_bytes([7u8; 32])
        .expect("recipient secret is a valid scalar");
    let shared_point = group_point
        .mul_tweak(&secp, &recipient_scalar)
        .expect("ECDH point multiplication");
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&shared_point.serialize()[1..33]);

    assert_eq!(
        shared_secret.as_slice(),
        expected.as_slice(),
        "ECDH shared secret must match the independently computed recipient-side value"
    );
}

/// With no cosigner available, `request_ecdh` must fail fast on the
/// no-eligible-peer guard (which runs before the coordination wait) rather than
/// block or falsely succeed. Drives the requester's early-terminator path
/// deterministically over the in-process bus.
#[tokio::test]
async fn ecdh_fails_fast_with_no_eligible_cosigner_over_memory_transport() {
    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("mem-ecdh-nopeer").unwrap();
    let share1 = shares.remove(0);

    let bus = MemoryBus::new();
    let mut node1 = KfpNode::with_transport(
        share1,
        bus.transport() as Arc<dyn CosignTransport>,
        None,
        None,
    )
    .expect("node1");
    let shutdown1 = node1.take_shutdown_handle();
    let node1 = Arc::new(node1);
    let h1 = spawn_run(Arc::clone(&node1));

    // Let run() subscribe; no peer ever announces, so a 2-of-3 request has no
    // eligible cosigner and `select_eligible_peers` must reject up front.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let recipient_secret = bitcoin::secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let recipient_pubkey: [u8; 33] = recipient_secret.public_key(&secp).serialize();

    // A bound well under request_ecdh's 30s coordination timeout: the failure
    // must come from the up-front eligible-peer check, not a wait timeout.
    let result = timeout(
        Duration::from_secs(5),
        node1.request_ecdh(&recipient_pubkey),
    )
    .await;

    if let Some(tx) = shutdown1 {
        let _ = tx.try_send(());
    }
    let _ = timeout(Duration::from_secs(2), h1).await;

    match result {
        Ok(Ok(_)) => panic!("request_ecdh must not succeed with no eligible cosigner"),
        Ok(Err(_)) => {} // expected: rejected on the no-eligible-peer guard
        Err(_) => {
            panic!("request_ecdh did not fail fast on the no-eligible-peer guard (blocked)")
        }
    }
}
