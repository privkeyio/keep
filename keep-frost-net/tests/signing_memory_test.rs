// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Deterministic multi-peer FROST signing over the in-process `MemoryTransport`
//! (no relay, no network timing). Drives a real 2-of-3 `request_signature`
//! session between three `KfpNode`s on a shared in-process bus and verifies the
//! aggregated BIP-340 signature against the group public key (a genuine
//! cryptographic oracle, not just a length check), covering the coordinator ->
//! commitment -> signature-share -> aggregate path deterministically (#790).

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

/// A 2-of-3 group signs a 32-byte digest over the in-process bus, and the
/// aggregated signature verifies as a valid BIP-340 signature under the group
/// public key.
#[tokio::test]
async fn signing_completes_and_verifies_over_memory_transport() {
    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, pubkey_pkg) = dealer.generate("mem-sign").unwrap();
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
    let h1 = spawn_run(Arc::clone(&node1));
    let h2 = spawn_run(Arc::clone(&node2));
    let h3 = spawn_run(Arc::clone(&node3));

    // The requester (node3) must see both cosigners before requesting.
    let discovered = timeout(Duration::from_secs(30), async {
        let mut peers = 0u32;
        while peers < 2 {
            if let Ok(KfpNodeEvent::PeerDiscovered { .. }) = rx3.recv().await {
                peers += 1;
            }
        }
    })
    .await;
    assert!(discovered.is_ok(), "node3 must discover both cosigners");

    // A 32-byte digest: for the "raw" path this is the message signed directly,
    // so the aggregated BIP-340 signature verifies over exactly these bytes.
    let digest = [42u8; 32];
    let sign_result = timeout(
        Duration::from_secs(30),
        node3.request_signature(digest.to_vec(), "raw"),
    )
    .await;

    for tx in [shutdown1, shutdown2, shutdown3].into_iter().flatten() {
        let _ = tx.try_send(());
    }
    let _ = timeout(Duration::from_secs(2), h1).await;
    let _ = timeout(Duration::from_secs(2), h2).await;
    let _ = timeout(Duration::from_secs(2), h3).await;

    let signature = match sign_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => panic!("request_signature failed: {e:?}"),
        Err(_) => panic!("request_signature timed out over the memory bus"),
    };
    assert_eq!(signature.len(), 64);

    // Cryptographic oracle: the aggregated signature must be a valid BIP-340
    // signature over the digest under the group x-only public key.
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let vk = pubkey_pkg.verifying_key().serialize().unwrap();
    let group_xonly = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&vk[1..33])
        .expect("group verifying key is a valid x-only point");
    let msg = bitcoin::secp256k1::Message::from_digest(digest);
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&signature)
        .expect("aggregated signature is 64 bytes");
    secp.verify_schnorr(&sig, &msg, &group_xonly)
        .expect("aggregated FROST signature must verify under the group public key");
}
