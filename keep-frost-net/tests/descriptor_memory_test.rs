// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Deterministic wallet-descriptor coordination (WDC) over the in-process
//! `MemoryTransport` (no relay, no network timing). This is the memory-bus
//! counterpart of `test_descriptor_coordination_flow` in `multinode_test.rs`:
//! two real `KfpNode`s wired to a shared in-process bus drive a full
//! `request_descriptor` -> `contribute_descriptor` -> `finalize_descriptor`
//! session, and an independent descriptor reconstruction acts as the oracle that
//! the `DescriptorComplete` payload delivered to the responder carries exactly
//! the descriptor the requester finalized (#790).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use keep_bitcoin::recovery::{RecoveryConfig, RecoveryTier as BitcoinRecoveryTier, SpendingTier};
use keep_bitcoin::{xpub_to_x_only, DescriptorExport, Network};
use keep_core::frost::{ThresholdConfig, TrustedDealer};
use keep_frost_net::test_support::MemoryBus;
use keep_frost_net::{
    derive_policy_hash, CosignTransport, KeySlot, KfpNode, KfpNodeEvent, PolicyTier, WalletPolicy,
    XpubContribution,
};
use tokio::time::timeout;

fn spawn_run(node: Arc<KfpNode>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = node.run().await;
    })
}

/// A 2-of-3 group completes the WDC descriptor-coordination flow over the
/// in-process bus. The `DescriptorComplete` delivered to the responder (node2)
/// must carry the same external/internal descriptor that the requester (node1)
/// finalized, verified against an independent reconstruction of the descriptor
/// from the same contributions and recovery policy.
#[tokio::test]
async fn descriptor_coordination_completes_over_memory_transport() {
    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pubkey_pkg) = dealer.generate("mem-descriptor").unwrap();
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

    let node1_pubkey = node1.pubkey();
    let group_pubkey = *node1.group_pubkey();

    let (xpub1_str, fp1) = node1
        .derive_account_xpub("signet")
        .expect("derive_account_xpub node1");
    let (xpub2_str, fp2) = node2
        .derive_account_xpub("signet")
        .expect("derive_account_xpub node2");

    let mut rx1 = node1.subscribe();
    let mut rx2 = node2.subscribe();

    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let node1_handle = spawn_run(Arc::clone(&node1));
    let node2_handle = spawn_run(Arc::clone(&node2));

    let mut node1_peers = 0u32;
    let mut node2_peers = 0u32;
    let discovery = timeout(Duration::from_secs(30), async {
        loop {
            tokio::select! {
                Ok(KfpNodeEvent::PeerDiscovered { .. }) = rx1.recv() => {
                    node1_peers += 1;
                }
                Ok(KfpNodeEvent::PeerDiscovered { .. }) = rx2.recv() => {
                    node2_peers += 1;
                }
            }
            if node1_peers >= 1 && node2_peers >= 1 {
                return;
            }
        }
    })
    .await;

    if discovery.is_err() {
        for tx in [shutdown1, shutdown2].into_iter().flatten() {
            let _ = tx.try_send(());
        }
        panic!("Peer discovery timed out: node1={node1_peers}, node2={node2_peers}");
    }

    let policy = WalletPolicy {
        recovery_tiers: vec![PolicyTier {
            threshold: 1,
            key_slots: vec![
                KeySlot::Participant { share_index: 1 },
                KeySlot::Participant { share_index: 2 },
            ],
            timelock_months: 6,
        }],
        version: 1,
    };

    let session_id = node1
        .request_descriptor(policy.clone(), "signet", &xpub1_str, &fp1)
        .await
        .expect("request_descriptor failed");

    let contribution_needed = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(KfpNodeEvent::DescriptorContributionNeeded {
                session_id: sid, ..
            }) = rx2.recv().await
            {
                return sid;
            }
        }
    })
    .await
    .expect("Timed out waiting for DescriptorContributionNeeded on node2");

    assert_eq!(contribution_needed, session_id);

    node2
        .contribute_descriptor(session_id, &node1_pubkey, &xpub2_str, &fp2)
        .await
        .expect("contribute_descriptor failed");

    let ready = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(KfpNodeEvent::DescriptorReady { session_id: sid }) = rx1.recv().await {
                return sid;
            }
        }
    })
    .await
    .expect("Timed out waiting for DescriptorReady on node1");

    assert_eq!(ready, session_id);

    let policy_hash = derive_policy_hash(&policy);

    let mut contributions = BTreeMap::new();
    contributions.insert(
        1,
        XpubContribution {
            account_xpub: xpub1_str.clone(),
            fingerprint: fp1.to_string(),
        },
    );
    contributions.insert(
        2,
        XpubContribution {
            account_xpub: xpub2_str.clone(),
            fingerprint: fp2.to_string(),
        },
    );

    let key1 = xpub_to_x_only(&xpub1_str, Network::Signet).unwrap();
    let key2 = xpub_to_x_only(&xpub2_str, Network::Signet).unwrap();

    let recovery_config = RecoveryConfig {
        primary: SpendingTier {
            keys: vec![group_pubkey],
            threshold: 1,
        },
        recovery_tiers: vec![BitcoinRecoveryTier {
            keys: vec![key1, key2],
            threshold: 1,
            timelock_months: 6,
        }],
        network: Network::Signet,
    };

    let export =
        DescriptorExport::from_frost_wallet(&group_pubkey, Some(&recovery_config), Network::Signet)
            .expect("descriptor export failed");
    let external_desc = export.external_descriptor().to_string();
    let internal_desc = export
        .internal_descriptor()
        .expect("internal descriptor failed");

    let finalize_result = node1
        .finalize_descriptor(session_id, &external_desc, &internal_desc, policy_hash)
        .await;
    finalize_result.expect("finalize_descriptor failed");

    let node2_complete = timeout(Duration::from_secs(30), async {
        loop {
            match rx2.recv().await {
                Ok(KfpNodeEvent::DescriptorComplete {
                    session_id: sid,
                    external_descriptor,
                    internal_descriptor,
                    ..
                }) => {
                    return Ok((sid, external_descriptor, internal_descriptor));
                }
                Ok(KfpNodeEvent::DescriptorFailed {
                    session_id: sid,
                    error,
                }) => {
                    return Err(format!(
                        "DescriptorFailed session={} error={error}",
                        hex::encode(&sid[..8])
                    ));
                }
                Ok(KfpNodeEvent::DescriptorNacked {
                    session_id: sid,
                    share_index,
                    reason,
                }) => {
                    return Err(format!(
                        "DescriptorNacked session={} share={share_index} reason={reason}",
                        hex::encode(&sid[..8])
                    ));
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return Err(
                        "Event channel closed while waiting for DescriptorComplete".to_string()
                    );
                }
            }
        }
    })
    .await
    .expect("Timed out waiting for DescriptorComplete on node2")
    .expect("Descriptor coordination failed on node2");

    assert_eq!(node2_complete.0, session_id);
    assert_eq!(node2_complete.1, external_desc);
    assert_eq!(node2_complete.2, internal_desc);

    let node1_complete = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(KfpNodeEvent::DescriptorComplete {
                session_id: sid,
                external_descriptor,
                internal_descriptor,
                ..
            }) = rx1.recv().await
            {
                return (sid, external_descriptor, internal_descriptor);
            }
        }
    })
    .await
    .expect("Timed out waiting for DescriptorComplete on node1 (all ACKs)");

    assert_eq!(node1_complete.0, session_id);
    assert_eq!(node1_complete.1, external_desc);
    assert_eq!(node1_complete.2, internal_desc);

    for tx in [shutdown1, shutdown2].into_iter().flatten() {
        let _ = tx.try_send(());
    }
    let _ = timeout(Duration::from_secs(2), node1_handle).await;
    let _ = timeout(Duration::from_secs(2), node2_handle).await;
}
