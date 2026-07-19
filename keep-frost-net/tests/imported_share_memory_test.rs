// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Deterministic regression coverage over the in-process `MemoryTransport`: a
//! share imported from an encrypted transport export carries only its OWN
//! verifying share, so its `pubkey_package` is incomplete. When such a share
//! initiates signing, the initiator must reconstruct the full package from the
//! co-signers' announced verifying shares; before that fix the round failed on
//! the initiator with "Aggregation failed: Unknown identifier". Counterpart of
//! the MockRelay `test_imported_share_can_initiate_signing` (#790).

use std::sync::Arc;
use std::time::Duration;

use keep_core::frost::{ShareExport, ThresholdConfig, TrustedDealer};
use keep_frost_net::test_support::MemoryBus;
use keep_frost_net::{CosignTransport, KfpNode, KfpNodeEvent};
use tokio::time::timeout;

fn spawn_run(node: Arc<KfpNode>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = node.run().await;
    })
}

#[tokio::test]
async fn imported_share_can_initiate_signing_over_memory_transport() {
    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("mem-import-signing").unwrap();
    let share1 = shares.remove(0);
    let share2 = shares.remove(0);
    let share3 = shares.remove(0);

    // Round-trip the initiator's share through an encrypted export, exactly as an
    // operator importing into a fresh box would; the imported share's
    // pubkey_package holds only its own verifying share.
    let export = ShareExport::from_share(&share3, "pw").expect("export share3");
    let share3 = export.to_share("pw", "imported").expect("import share3");

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

    // The imported initiator must reconstruct the full pubkey package from the
    // peers' announced verifying shares and produce a valid 64-byte signature.
    let sign_result = timeout(
        Duration::from_secs(30),
        node3.request_signature(b"imported-share signing".to_vec(), "raw"),
    )
    .await;
    match sign_result {
        Ok(Ok(sig)) => assert_eq!(sig.len(), 64),
        Ok(Err(e)) => panic!("signing with imported share failed: {e:?}"),
        Err(_) => panic!("signing with imported share timed out"),
    }
}
