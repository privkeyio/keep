// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Deterministic in-process-`MemoryTransport` counterpart of the MockRelay test
//! `test_oprf_enroll_distributes_share_and_completes`. A 2-of-3 dealer at FROST
//! id 1 ships the holder at FROST id 2 its OPRF secret key share over a shared
//! in-process bus (no relay, no network timing); the holder, seeing the dealer
//! as `Verified`, takes durable custody (emits `OprfShareReceived`) and acks, so
//! the dealer's `distribute_oprf_shares` completes. Covers the OPRF enrollment
//! coordination path deterministically (#790).

use std::sync::Arc;
use std::time::Duration;

use keep_core::frost::{ThresholdConfig, TrustedDealer};
use keep_frost_net::test_support::MemoryBus;
use keep_frost_net::{AttestationStatus, CosignTransport, KfpNode, KfpNodeEvent};
use tokio::sync::mpsc;
use tokio::time::timeout;
use zeroize::Zeroizing;

async fn graceful_shutdown(
    shutdown_tx: Option<mpsc::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
) {
    if let Some(tx) = shutdown_tx {
        let _ = tx.try_send(());
    }
    let _ = timeout(Duration::from_secs(2), handle).await;
}

/// Split one OPRF key 2-of-3. `KeyShare` at index `i` is the vsss share for
/// FROST identifier `i + 1`.
fn split_oprf_key_2of3() -> Vec<keep_core::oprf::threshold::KeyShare> {
    use k256::elliptic_curve::rand_core::OsRng;
    use k256::Scalar;
    let mut rng = OsRng;
    let secret = <Scalar as k256::elliptic_curve::Field>::random(&mut rng);
    keep_core::oprf::threshold::split_key(&secret, 2, 3, rng).expect("split oprf key")
}

/// Happy path: a 2-of-3 group where the dealer (id 1) distributes the holder's
/// (id 2) OPRF secret key share over the in-process bus. The holder, seeing the
/// dealer as `Verified`, takes custody (emits `OprfShareReceived` with a share
/// that round-trips through `deserialize_key_share` and equals what was sent)
/// and acks, so the dealer's `distribute_oprf_shares` completes.
#[tokio::test]
async fn oprf_enroll_distributes_share_over_memory_transport() {
    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, _pkg) = dealer.generate("test-oprf-enroll").unwrap();
    let share1 = shares.remove(0); // FROST id 1 = dealer (box)
    let share2 = shares.remove(0); // FROST id 2 = holder

    let oprf = split_oprf_key_2of3();
    // The remote target (holder id 2) gets the vsss share at index 2 (oprf[1]).
    // The dealer keeps its own share (oprf[0]) sealed locally; it is NOT sent.
    let target_bytes = keep_core::oprf::threshold::serialize_key_share(&oprf[1]).to_vec();

    let bus = MemoryBus::new();
    let mut node1 = KfpNode::with_transport(
        share1,
        bus.transport() as Arc<dyn CosignTransport>,
        None,
        None,
    )
    .expect("dealer node");
    let mut node2 = KfpNode::with_transport(
        share2,
        bus.transport() as Arc<dyn CosignTransport>,
        None,
        None,
    )
    .expect("holder node");
    // Pin the box (FROST id 1) as the designated dealer (fail-closed default).
    node2.set_expected_oprf_dealer(1);

    let mut rx1 = node1.subscribe();
    let mut rx2 = node2.subscribe();
    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let node1_run = Arc::clone(&node1);
    let node2_run = Arc::clone(&node2);
    let node1_handle = tokio::spawn(async move {
        let _ = node1_run.run().await;
    });
    let node2_handle = tokio::spawn(async move {
        let _ = node2_run.run().await;
    });

    let mut n1 = 0u32;
    let mut n2 = 0u32;
    let discovery = timeout(Duration::from_secs(30), async {
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
    .await;
    if discovery.is_err() {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        panic!("Peer discovery timed out: node1={n1}, node2={n2}");
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    // The holder must see the dealer as Verified to take custody of a share.
    node2.test_set_peer_attestation(1, AttestationStatus::Verified);

    // Watch the holder for OprfShareReceived (rx2 already subscribed, so the
    // event is buffered even if it arrives before we await).
    let recv_task = tokio::spawn(async move {
        loop {
            match rx2.recv().await {
                Ok(KfpNodeEvent::OprfShareReceived {
                    dealer_index,
                    threshold,
                    total,
                    share,
                    seal_ack,
                }) => {
                    // Confirm durable custody so the holder acks the dealer.
                    if let Some(tx) = seal_ack.lock().unwrap().take() {
                        let _ = tx.send(true);
                    }
                    return Some((dealer_index, threshold, total, share));
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(_) => return None,
            }
        }
    });

    let dist = timeout(
        Duration::from_secs(30),
        node1.distribute_oprf_shares(vec![(2u16, Zeroizing::new(target_bytes.clone()))], 2, 3),
    )
    .await;

    let received = timeout(Duration::from_secs(5), recv_task).await;

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown2, node2_handle).await;

    match dist {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("distribute_oprf_shares failed: {e}"),
        Err(_) => panic!("distribute_oprf_shares timed out (no ack)"),
    }

    let received = received
        .expect("holder OprfShareReceived wait timed out")
        .expect("holder recv task panicked")
        .expect("holder must emit OprfShareReceived");
    let (dealer_index, threshold, total, share) = received;
    assert_eq!(dealer_index, 1, "share came from the dealer at index 1");
    assert_eq!(threshold, 2);
    assert_eq!(total, 3);
    assert_eq!(
        share.as_slice(),
        target_bytes.as_slice(),
        "the received share must equal exactly what the dealer sent"
    );
    keep_core::oprf::threshold::deserialize_key_share(&share)
        .expect("the received share must be a valid OPRF key share");
}
