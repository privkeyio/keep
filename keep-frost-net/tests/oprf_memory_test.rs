// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Deterministic multi-peer threshold-OPRF unlock over the in-process
//! `MemoryTransport` (no relay, no network timing). Drives a real
//! `request_oprf_unlock` between a box and one holder on a shared in-process
//! bus, through every #621 gate (attestation + approval hook + OPRF share), and
//! asserts the derived LUKS key is stable across two independent runs -- the
//! defining property of the OPRF (a deterministic PRF of input/key/volume/epoch)
//! that a length check alone cannot catch. Covers the threshold-OPRF
//! coordination path deterministically (#790/#800).

use std::sync::Arc;
use std::time::Duration;

use keep_core::frost::{ThresholdConfig, TrustedDealer};
use keep_frost_net::test_support::MemoryBus;
use keep_frost_net::{AttestationStatus, CosignTransport, KfpNode, KfpNodeEvent};
use tokio::time::timeout;

const OPRF_INPUT: &[u8] = b"keep-node-vault-v1";

/// Holder-side hook that approves every OPRF evaluation (the oracle defaults to
/// DENY, so the happy path must opt in).
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

/// The box and one holder (both carrying an OPRF share) complete an OPRF unlock
/// over the in-process bus, and a second independent run derives the identical
/// LUKS key.
#[tokio::test]
async fn oprf_unlock_completes_and_is_stable_over_memory_transport() {
    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("mem-oprf-unlock").unwrap();
    let share1 = shares.remove(0); // FROST id 1 = box
    let share2 = shares.remove(0); // FROST id 2 = holder
    let oprf = split_oprf_key_2of3();

    let bus = MemoryBus::new();
    let mut node1 = KfpNode::with_transport(
        share1,
        bus.transport() as Arc<dyn CosignTransport>,
        None,
        None,
    )
    .expect("box node");
    node1.set_oprf_key_share(oprf[0]);
    let mut node2 = KfpNode::with_transport(
        share2,
        bus.transport() as Arc<dyn CosignTransport>,
        None,
        None,
    )
    .expect("holder node");
    node2.set_oprf_key_share(oprf[1]);
    node2.set_hooks(Arc::new(ApproveOprfHooks));

    let mut rx1 = node1.subscribe();
    let mut rx2 = node2.subscribe();
    let _shutdown1 = node1.take_shutdown_handle();
    let _shutdown2 = node2.take_shutdown_handle();

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let n1r = Arc::clone(&node1);
    let n2r = Arc::clone(&node2);
    let _h1 = tokio::spawn(async move {
        let _ = n1r.run().await;
    });
    let _h2 = tokio::spawn(async move {
        let _ = n2r.run().await;
    });

    // Both must discover the other before the box can select the holder.
    let discovery = timeout(Duration::from_secs(30), async {
        let mut n1 = 0u32;
        let mut n2 = 0u32;
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
    assert!(discovery.is_ok(), "box and holder must discover each other");

    // Let reciprocal announces flush, then mark the box Verified on the holder
    // (re-announces are 20s apart, covering the sub-second request window).
    tokio::time::sleep(Duration::from_millis(500)).await;
    node2.test_set_peer_attestation(1, AttestationStatus::Verified);

    let key1 = timeout(
        Duration::from_secs(30),
        node1.request_oprf_unlock(OPRF_INPUT, "vault0", 1),
    )
    .await
    .expect("first unlock timed out")
    .expect("first unlock failed");
    assert_eq!(key1.len(), 32, "derived LUKS key must be 32 bytes");

    // Second independent run (fresh blind) must derive the SAME key: the OPRF is
    // a deterministic PRF of (input, key, volume, epoch), and finalize strips the
    // per-attempt blinding. This is the real oracle a length check misses.
    node2.test_set_peer_attestation(1, AttestationStatus::Verified);
    let key2 = timeout(
        Duration::from_secs(30),
        node1.request_oprf_unlock(OPRF_INPUT, "vault0", 1),
    )
    .await
    .expect("second unlock timed out")
    .expect("second unlock failed");

    assert_eq!(
        key1.as_slice(),
        key2.as_slice(),
        "two OPRF unlocks of the same input/volume/epoch must derive the identical LUKS key"
    );
}
