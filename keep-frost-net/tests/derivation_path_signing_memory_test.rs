// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Deterministic BIP-32 derived-key signing over the in-process
//! `MemoryTransport`. This is the real HD-wallet spending path: a co-signer
//! requests a signature at a derivation path, and every node applies the same
//! BIP-32 tweak to its share before the FROST round so the aggregate signs under
//! the derived child key, not the parent group key. The oracle is strict on both
//! sides: the resulting signature MUST verify under the derived child pubkey and
//! MUST NOT verify under the parent group pubkey, proving the tweak was actually
//! applied (a missing tweak would sign under the parent and silently spend from
//! the wrong key). Counterpart of the MockRelay
//! `test_full_signing_flow_at_derivation_path` (#790).

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
async fn derivation_path_signing_completes_over_memory_transport() {
    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("mem-bip32-signing").unwrap();
    let group_pubkey: [u8; 32] = *shares[0].group_pubkey();
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

    // 32-byte digest so it fits `Message::from_digest_slice` for BIP-340.
    let message = [0x33u8; 32].to_vec();
    let derivation_path = vec![0u32, 5u32];

    let sign_result = timeout(
        Duration::from_secs(30),
        node3.request_signature_at_path(message.clone(), "raw", None, derivation_path.clone()),
    )
    .await;

    let sig_bytes = match sign_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => panic!("BIP-32 signing failed: {e:?}"),
        Err(_) => panic!("BIP-32 signing timed out"),
    };

    let composite =
        keep_core::frost::bip32_signing::derive_child(&group_pubkey, &derivation_path).unwrap();

    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    let secp = Secp256k1::verification_only();
    let sig = Signature::from_slice(&sig_bytes).unwrap();
    let child_xonly = XOnlyPublicKey::from_slice(&composite.child_pubkey).unwrap();
    let msg = Message::from_digest_slice(&message).unwrap();
    secp.verify_schnorr(&sig, &msg, &child_xonly)
        .expect("aggregate signature must verify under the derived child pubkey");

    let group_xonly = XOnlyPublicKey::from_slice(&group_pubkey).unwrap();
    assert!(
        secp.verify_schnorr(&sig, &msg, &group_xonly).is_err(),
        "child-derived signature MUST NOT verify under the parent group pubkey"
    );
}
