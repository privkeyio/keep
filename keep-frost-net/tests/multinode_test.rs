// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]

use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

use k256::schnorr::SigningKey;
use keep_core::frost::{ThresholdConfig, TrustedDealer};
use keep_frost_net::{
    AnnouncePayload, KeySlot, KfpMessage, KfpNode, KfpNodeEvent, PolicyTier, SessionManager,
    SessionState, SignRequestPayload, WalletPolicy,
};
use nostr_relay_builder::prelude::*;

async fn graceful_shutdown(
    shutdown_tx: Option<mpsc::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
) {
    if let Some(tx) = shutdown_tx {
        let _ = tx.try_send(());
    }
    let _ = timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn test_node_creation_and_announcement() {
    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, _pubkey_pkg) = dealer.generate("test-multinode").unwrap();

    let share1 = shares.remove(0);
    let share2 = shares.remove(0);

    let node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("Failed to create node 1");

    let node2 = KfpNode::new(share2, vec![relay])
        .await
        .expect("Failed to create node 2");

    assert_eq!(node1.share_index(), 1);
    assert_eq!(node2.share_index(), 2);

    node1.announce().await.expect("Node 1 announce failed");
    node2.announce().await.expect("Node 2 announce failed");
}

#[tokio::test]
async fn test_peer_discovery_with_running_nodes() {
    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, _pubkey_pkg) = dealer.generate("test-discovery").unwrap();

    let share1 = shares.remove(0);
    let share2 = shares.remove(0);

    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("Failed to create node 1");

    let mut node2 = KfpNode::new(share2, vec![relay])
        .await
        .expect("Failed to create node 2");

    let mut rx1 = node1.subscribe();

    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();

    let node2_handle = tokio::spawn(async move {
        let _ = node2.run().await;
    });

    let node1_handle = tokio::spawn(async move {
        let _ = node1.run().await;
    });

    // Allow more time for CI environments which may be slower
    let discovery_result = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(keep_frost_net::KfpNodeEvent::PeerDiscovered { share_index, .. }) =
                rx1.recv().await
            {
                // Node 1 should discover Node 2, not itself
                assert_eq!(share_index, 2, "Node 1 should discover Node 2");
                return true;
            }
        }
    })
    .await;

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown2, node2_handle).await;

    assert!(discovery_result.is_ok(), "Peer discovery timed out");
}

#[tokio::test]
async fn test_frost_protocol_message_flow() {
    // Generate real cryptographic keys for proof
    let signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();

    let mut signing_share = [0u8; 32];
    signing_share.copy_from_slice(&signing_key.to_bytes());

    let mut verifying_share = [0u8; 33];
    verifying_share[0] = 0x02;
    verifying_share[1..33].copy_from_slice(&verifying_key.to_bytes());

    let group_pubkey = [1u8; 32];
    let share_index = 1u16;
    let timestamp = chrono::Utc::now().timestamp() as u64;

    // Create real proof signature
    let proof_signature = keep_frost_net::proof::sign_proof(
        &signing_share,
        &group_pubkey,
        share_index,
        &verifying_share,
        timestamp,
    )
    .expect("Failed to sign proof");

    let announce = AnnouncePayload::new(
        group_pubkey,
        share_index,
        verifying_share,
        proof_signature,
        timestamp,
    )
    .with_name("Test Node");

    let msg = KfpMessage::Announce(announce.clone());
    let json = msg.to_json().unwrap();

    assert!(json.contains("announce"));
    assert!(json.contains("Test Node"));

    let parsed = KfpMessage::from_json(&json).unwrap();
    assert_eq!(parsed.message_type(), "announce");

    // Verify the proof in the parsed message
    if let KfpMessage::Announce(payload) = &parsed {
        keep_frost_net::proof::verify_proof(
            &payload.verifying_share,
            &payload.proof_signature,
            &payload.group_pubkey,
            payload.share_index,
            payload.timestamp,
        )
        .expect("Proof verification should succeed");
    }

    let sign_req = SignRequestPayload::new(
        [2u8; 32],
        [3u8; 32],
        b"test message".to_vec(),
        "raw",
        vec![1, 2],
    );
    let msg = KfpMessage::SignRequest(sign_req);
    let json = msg.to_json().unwrap();

    assert!(json.contains("sign_request"));

    let parsed = KfpMessage::from_json(&json).unwrap();
    assert_eq!(parsed.message_type(), "sign_request");
    assert!(parsed.session_id().is_some());
    assert!(parsed.group_pubkey().is_some());
}

#[tokio::test]
async fn test_proof_verification_with_real_keys() {
    // Test valid proof creation and verification
    let signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();

    let mut signing_share = [0u8; 32];
    signing_share.copy_from_slice(&signing_key.to_bytes());

    let mut verifying_share = [0u8; 33];
    verifying_share[0] = 0x02;
    verifying_share[1..33].copy_from_slice(&verifying_key.to_bytes());

    let group_pubkey = [42u8; 32];
    let share_index = 5u16;
    let timestamp = chrono::Utc::now().timestamp() as u64;

    let signature = keep_frost_net::proof::sign_proof(
        &signing_share,
        &group_pubkey,
        share_index,
        &verifying_share,
        timestamp,
    )
    .expect("Signing should succeed");

    // Valid verification
    keep_frost_net::proof::verify_proof(
        &verifying_share,
        &signature,
        &group_pubkey,
        share_index,
        timestamp,
    )
    .expect("Verification should succeed");

    // Test with wrong share index (should fail)
    let wrong_index_result = keep_frost_net::proof::verify_proof(
        &verifying_share,
        &signature,
        &group_pubkey,
        share_index + 1, // Wrong index
        timestamp,
    );
    assert!(wrong_index_result.is_err(), "Wrong share index should fail");

    // Test with wrong group pubkey (should fail)
    let wrong_group_result = keep_frost_net::proof::verify_proof(
        &verifying_share,
        &signature,
        &[99u8; 32], // Wrong group pubkey
        share_index,
        timestamp,
    );
    assert!(
        wrong_group_result.is_err(),
        "Wrong group pubkey should fail"
    );

    // Test with mismatched verifying share (should fail)
    let other_signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
    let other_verifying_key = other_signing_key.verifying_key();
    let mut wrong_verifying_share = [0u8; 33];
    wrong_verifying_share[0] = 0x02;
    wrong_verifying_share[1..33].copy_from_slice(&other_verifying_key.to_bytes());

    let wrong_share_result = keep_frost_net::proof::verify_proof(
        &wrong_verifying_share,
        &signature,
        &group_pubkey,
        share_index,
        timestamp,
    );
    assert!(
        wrong_share_result.is_err(),
        "Mismatched verifying share should fail"
    );
}

#[tokio::test]
async fn test_session_management() {
    use keep_frost_net::derive_session_id;

    let mut manager = SessionManager::new();

    let message = b"test message".to_vec();
    let participants = vec![1, 2, 3];
    let threshold = 2;
    let session_id = derive_session_id(&message, &participants, threshold);

    let session = manager
        .create_session(session_id, message.clone(), threshold, participants.clone())
        .unwrap();

    assert_eq!(session.state(), SessionState::AwaitingCommitments);
    assert_eq!(session.commitments_needed(), 2);
    assert!(session.is_participant(1));
    assert!(session.is_participant(2));
    assert!(!session.is_participant(4));

    // Attempting to create with different participants should fail (session ID mismatch)
    let result = manager.create_session(session_id, message.clone(), threshold, vec![1, 2]);
    let err = result
        .err()
        .expect("should fail with mismatched participants");
    assert!(err.to_string().contains("mismatch"));

    // Attempting to create duplicate session with same params should fail
    let result = manager.create_session(session_id, message.clone(), threshold, participants);
    let err = result.err().expect("should fail with duplicate session");
    assert!(err.to_string().contains("already active"));

    manager.complete_session(&session_id);
    assert!(manager.is_replay(&session_id));
}

#[tokio::test]
async fn test_full_signing_flow() {
    use std::sync::Arc;

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, _pubkey_pkg) = dealer.generate("test-signing").unwrap();

    let share1 = shares.remove(0);
    let share2 = shares.remove(0);
    let share3 = shares.remove(0);

    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("Failed to create node 1");

    let mut node2 = KfpNode::new(share2, vec![relay.clone()])
        .await
        .expect("Failed to create node 2");

    let mut node3 = KfpNode::new(share3, vec![relay])
        .await
        .expect("Failed to create node 3");

    // Subscribe to node3 events BEFORE taking shutdown handle
    let mut rx3 = node3.subscribe();

    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();
    let shutdown3 = node3.take_shutdown_handle();

    let node3 = Arc::new(node3);
    let node3_for_run = Arc::clone(&node3);

    // Start all nodes
    let node1_handle = tokio::spawn(async move {
        let _ = node1.run().await;
    });

    let node2_handle = tokio::spawn(async move {
        let _ = node2.run().await;
    });

    let node3_handle = tokio::spawn(async move {
        let _ = node3_for_run.run().await;
    });

    // Wait for node3 to discover at least 2 peers via events
    let mut peers_discovered = 0u32;
    let discovery_timeout = timeout(Duration::from_secs(45), async {
        while peers_discovered < 2 {
            if let Ok(keep_frost_net::KfpNodeEvent::PeerDiscovered { .. }) = rx3.recv().await {
                peers_discovered += 1;
            }
        }
    })
    .await;

    if discovery_timeout.is_err() {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        graceful_shutdown(shutdown3, node3_handle).await;
        panic!("Peer discovery timed out: only {peers_discovered} peers discovered");
    }

    let message = b"Hello, FROST!".to_vec();
    // Allow more time for signing in CI environments
    let sign_result = timeout(Duration::from_secs(60), async {
        node3.request_signature(message, "raw").await
    })
    .await;

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown2, node2_handle).await;
    graceful_shutdown(shutdown3, node3_handle).await;

    match sign_result {
        Ok(Ok(signature)) => {
            assert_eq!(signature.len(), 64);
        }
        Ok(Err(e)) => {
            panic!("Signing failed: {e:?}");
        }
        Err(_) => {
            panic!("Signing timed out after 60 seconds");
        }
    }
}

/// Regression for the ping/pong self-deadlock: `handle_ping`/`handle_pong`
/// previously held a `peers.read()` guard across a `peers.write()` in the same
/// task, which deadlocks the non-reentrant lock once ping traffic flows. Calling
/// `health_check` (which pings every peer) while the node loop is running, then
/// signing, must both complete rather than hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_health_check_then_sign_no_deadlock() {
    use std::sync::Arc;

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pubkey_pkg) = dealer.generate("test-health").unwrap();
    let share1 = shares.remove(0);
    let share2 = shares.remove(0);
    let share3 = shares.remove(0);

    let mut node1 = KfpNode::new(share1, vec![relay.clone()]).await.unwrap();
    let mut node2 = KfpNode::new(share2, vec![relay.clone()]).await.unwrap();
    let mut node3 = KfpNode::new(share3, vec![relay]).await.unwrap();

    let mut rx3 = node3.subscribe();
    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();
    let shutdown3 = node3.take_shutdown_handle();

    let node3 = Arc::new(node3);
    let node3_for_run = Arc::clone(&node3);

    let node1_handle = tokio::spawn(async move {
        let _ = node1.run().await;
    });
    let node2_handle = tokio::spawn(async move {
        let _ = node2.run().await;
    });
    let node3_handle = tokio::spawn(async move {
        let _ = node3_for_run.run().await;
    });

    let mut peers_discovered = 0u32;
    let discovery = timeout(Duration::from_secs(45), async {
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

    // The deadlock manifested here: before the fix this never returned.
    let health = timeout(
        Duration::from_secs(15),
        node3.health_check(Duration::from_secs(2)),
    )
    .await;

    // Signing after the ping round-trip must also still complete.
    let sign_result = timeout(Duration::from_secs(60), async {
        node3
            .request_signature(b"health-then-sign".to_vec(), "raw")
            .await
    })
    .await;

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown2, node2_handle).await;
    graceful_shutdown(shutdown3, node3_handle).await;

    let health = health
        .expect("health_check deadlocked (did not return within 15s)")
        .expect("health_check returned an error");
    assert_eq!(
        health.responsive.len(),
        2,
        "both co-signers should answer the liveness ping"
    );
    match sign_result {
        Ok(Ok(signature)) => assert_eq!(signature.len(), 64),
        Ok(Err(e)) => panic!("Signing after health check failed: {e:?}"),
        Err(_) => panic!("Signing after health check timed out"),
    }
}

/// Issue #412 acceptance: a co-signer taken offline mid-session must fail over
/// to the surviving co-signer within a few seconds, not tens of seconds. The
/// pre-round liveness ping excludes the freshly-dropped peer (still "online" by
/// its recent announce) before committing, so signing goes straight to the live
/// peer. The 12s bound is comfortably above the ~3s ping budget + one round, but
/// below the ~15s a single doomed round would cost without the pre-ping.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_failover_when_cosigner_dropped_mid_session() {
    use std::sync::Arc;

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pubkey_pkg) = dealer.generate("test-failover").unwrap();
    let share1 = shares.remove(0);
    let share2 = shares.remove(0);
    let share3 = shares.remove(0);

    let mut node1 = KfpNode::new(share1, vec![relay.clone()]).await.unwrap();
    let mut node2 = KfpNode::new(share2, vec![relay.clone()]).await.unwrap();
    let mut node3 = KfpNode::new(share3, vec![relay]).await.unwrap();

    let mut rx3 = node3.subscribe();
    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();
    let shutdown3 = node3.take_shutdown_handle();

    let node3 = Arc::new(node3);
    let node3_for_run = Arc::clone(&node3);

    let node1_handle = tokio::spawn(async move {
        let _ = node1.run().await;
    });
    let node2_handle = tokio::spawn(async move {
        let _ = node2.run().await;
    });
    let node3_handle = tokio::spawn(async move {
        let _ = node3_for_run.run().await;
    });

    let mut peers_discovered = 0u32;
    let discovery = timeout(Duration::from_secs(45), async {
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
    // scenario (repeated signing after approvals) and ensures the relay
    // connections/ping path are warm so the liveness pong is prompt.
    let warmup = timeout(Duration::from_secs(60), async {
        node3.request_signature(b"warmup".to_vec(), "raw").await
    })
    .await;
    if !matches!(warmup, Ok(Ok(_))) {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        graceful_shutdown(shutdown3, node3_handle).await;
        panic!("Warm-up signing failed: {warmup:?}");
    }

    // Take co-signer node2 offline. It stays "online" in node3's peer table for
    // up to offline_threshold, so without the pre-ping node3 may still select it
    // and burn a full round timeout. node1 remains live.
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
    assert!(
        elapsed < Duration::from_secs(12),
        "failover took {elapsed:?}, expected a few seconds (pre-ping should exclude the dead co-signer up front)"
    );
}

/// Regression: a share imported from a transport export carries only its own
/// verifying share, so its `pubkey_package` is missing the co-signers' shares
/// that `frost::aggregate` needs. The initiator must reconstruct the full
/// package from peers' announced verifying shares; before that fix this signing
/// round failed on the initiator with "Aggregation failed: Unknown identifier".
///
/// Like the other full signing-flow tests it spins up three nodes on a shared
/// in-process MockRelay and is timing-sensitive under parallel suite load (the
/// extra Argon2 export/import here makes it the most sensitive).
#[tokio::test]
async fn test_imported_share_can_initiate_signing() {
    use keep_core::frost::ShareExport;
    use std::sync::Arc;

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, _pubkey_pkg) = dealer.generate("test-import-signing").unwrap();

    let share1 = shares.remove(0);
    let share2 = shares.remove(0);
    let share3 = shares.remove(0);

    // Round-trip the initiator's share through an encrypted export, exactly as
    // an operator importing into a fresh StartOS box would. The resulting share
    // has an incomplete pubkey_package (only its own verifying share).
    let export = ShareExport::from_share(&share3, "pw").expect("export share3");
    let share3 = export.to_share("pw", "imported").expect("import share3");

    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("Failed to create node 1");
    let mut node2 = KfpNode::new(share2, vec![relay.clone()])
        .await
        .expect("Failed to create node 2");
    let mut node3 = KfpNode::new(share3, vec![relay])
        .await
        .expect("Failed to create node 3");

    let mut rx3 = node3.subscribe();

    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();
    let shutdown3 = node3.take_shutdown_handle();

    let node3 = Arc::new(node3);
    let node3_for_run = Arc::clone(&node3);

    let node1_handle = tokio::spawn(async move {
        let _ = node1.run().await;
    });
    let node2_handle = tokio::spawn(async move {
        let _ = node2.run().await;
    });
    let node3_handle = tokio::spawn(async move {
        let _ = node3_for_run.run().await;
    });

    let mut peers_discovered = 0u32;
    let discovery_timeout = timeout(Duration::from_secs(45), async {
        while peers_discovered < 2 {
            if let Ok(keep_frost_net::KfpNodeEvent::PeerDiscovered { .. }) = rx3.recv().await {
                peers_discovered += 1;
            }
        }
    })
    .await;

    if discovery_timeout.is_err() {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        graceful_shutdown(shutdown3, node3_handle).await;
        panic!("Peer discovery timed out: only {peers_discovered} peers discovered");
    }

    let sign_result = timeout(Duration::from_secs(60), async {
        node3
            .request_signature(b"imported-share signing".to_vec(), "raw")
            .await
    })
    .await;

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown2, node2_handle).await;
    graceful_shutdown(shutdown3, node3_handle).await;

    match sign_result {
        Ok(Ok(signature)) => assert_eq!(signature.len(), 64),
        Ok(Err(e)) => panic!("Signing with imported share failed: {e:?}"),
        Err(_) => panic!("Signing with imported share timed out"),
    }
}

#[tokio::test]
async fn test_descriptor_coordination_flow() {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use keep_bitcoin::recovery::{
        RecoveryConfig, RecoveryTier as BitcoinRecoveryTier, SpendingTier,
    };
    use keep_bitcoin::{xpub_to_x_only, DescriptorExport, Network};
    use keep_frost_net::{derive_policy_hash, XpubContribution};

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, _pubkey_pkg) = dealer.generate("test-descriptor").unwrap();

    let share1 = shares.remove(0);
    let share2 = shares.remove(0);

    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("Failed to create node 1");

    let mut node2 = KfpNode::new(share2, vec![relay])
        .await
        .expect("Failed to create node 2");

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
    let node1_for_run = Arc::clone(&node1);
    let node2_for_run = Arc::clone(&node2);

    let node1_handle = tokio::spawn(async move {
        let _ = node1_for_run.run().await;
    });

    let node2_handle = tokio::spawn(async move {
        let _ = node2_for_run.run().await;
    });

    let mut node1_peers = 0u32;
    let mut node2_peers = 0u32;
    let discovery = timeout(Duration::from_secs(45), async {
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
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
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

    let contribution_needed = timeout(Duration::from_secs(15), async {
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

    let ready = timeout(Duration::from_secs(15), async {
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

    let node1_complete = timeout(Duration::from_secs(15), async {
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

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown2, node2_handle).await;
}

/// In-process `PersistedDescriptorLookup` backed by a single `WalletDescriptor`
/// for use by the recovery-tier PSBT integration test.
struct StaticDescriptorLookup {
    descriptor: keep_core::wallet::WalletDescriptor,
}

impl keep_frost_net::PersistedDescriptorLookup for StaticDescriptorLookup {
    fn find_by_hash(&self, group: &[u8; 32], hash: &[u8; 32]) -> bool {
        &self.descriptor.group_pubkey == group && &self.descriptor.canonical_hash() == hash
    }
    fn network_for(&self, group: &[u8; 32], hash: &[u8; 32]) -> Option<String> {
        if self.find_by_hash(group, hash) {
            Some(self.descriptor.network.clone())
        } else {
            None
        }
    }
    fn latest_version_for(
        &self,
        group: &[u8; 32],
    ) -> std::result::Result<Option<u32>, keep_frost_net::DescriptorLookupUnavailable> {
        if &self.descriptor.group_pubkey == group {
            Ok(Some(self.descriptor.version))
        } else {
            Ok(None)
        }
    }
}

#[tokio::test]
async fn test_psbt_recovery_spend_end_to_end() {
    use std::sync::Arc;

    use bitcoin::bip32::Xpub;
    use bitcoin::hashes::Hash as _;
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{LeafVersion, Signature as TaprootSignature, TapLeafHash};
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, Network, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
    };
    use keep_bitcoin::recovery::{
        RecoveryConfig, RecoveryTier as BitcoinRecoveryTier, SpendingTier,
    };
    use keep_bitcoin::{
        merge_tap_script_sig, script_spend_sighashes, DescriptorExport, RecoveryTxBuilder,
    };
    use keep_frost_net::{SignerId, WalletPolicy};

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, _pubkey_pkg) = dealer.generate("test-psbt-recovery").unwrap();

    let share1 = shares.remove(0);
    let share2 = shares.remove(0);

    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("Failed to create node 1 (initiator)");

    let mut node2 = KfpNode::new(share2, vec![relay])
        .await
        .expect("Failed to create node 2 (responder)");

    let group_pubkey = *node1.group_pubkey();

    // Responder controls a known external xpub. We derive it from a fixed seed
    // so the test has access to the secret key for inline signing in lieu of a
    // live NIP-46 signer; the responder's `KfpNode` only sees the xpub +
    // fingerprint.
    let secp = Secp256k1::new();
    let responder_xpriv =
        bitcoin::bip32::Xpriv::new_master(Network::Signet, &[7u8; 32]).expect("xpriv master");
    let responder_xpub = Xpub::from_priv(&secp, &responder_xpriv);
    let responder_xpub_str = responder_xpub.to_string();
    let responder_fp = responder_xpub
        .fingerprint()
        .to_string()
        .to_ascii_lowercase();
    let responder_xonly_bytes = responder_xpub.to_x_only_pub().serialize();
    let responder_xonly =
        XOnlyPublicKey::from_slice(&responder_xonly_bytes).expect("xonly from slice");
    let responder_sk = responder_xpriv.private_key.secret_bytes();

    // Build a recovery config with a single recovery tier holding ONE external
    // key (threshold 1). Single-signer keeps the test deterministic and lets
    // the initiator auto-finalize as soon as the responder contributes.
    let recovery_config = RecoveryConfig {
        primary: SpendingTier {
            keys: vec![group_pubkey],
            threshold: 1,
        },
        recovery_tiers: vec![BitcoinRecoveryTier {
            keys: vec![responder_xonly_bytes],
            threshold: 1,
            timelock_months: 6,
        }],
        network: Network::Signet,
    };
    let recovery_output = recovery_config.build().expect("build recovery output");
    let builder = RecoveryTxBuilder::new(recovery_output.clone());

    let policy = WalletPolicy {
        recovery_tiers: vec![keep_frost_net::PolicyTier {
            threshold: 1,
            key_slots: vec![keep_frost_net::KeySlot::External {
                xpub: responder_xpub_str.clone(),
                fingerprint: responder_fp.clone(),
            }],
            timelock_months: 6,
        }],
        version: 1,
    };
    let policy_hash = keep_frost_net::derive_policy_hash(&policy);

    let export =
        DescriptorExport::from_frost_wallet(&group_pubkey, Some(&recovery_config), Network::Signet)
            .expect("descriptor export");
    let external_desc = export.external_descriptor().to_string();
    let internal_desc = export.internal_descriptor().expect("internal descriptor");

    let policy_value = serde_json::to_value(&policy).ok();
    let wallet_descriptor = keep_core::wallet::WalletDescriptor {
        group_pubkey,
        external_descriptor: external_desc.clone(),
        internal_descriptor: internal_desc.clone(),
        network: "signet".to_string(),
        created_at: 0,
        device_registrations: Vec::new(),
        policy_hash,
        version: 1,
        previous_descriptor_hash: None,
        policy: policy_value,
    };
    let descriptor_hash = wallet_descriptor.canonical_hash();
    let lookup: Arc<dyn keep_frost_net::PersistedDescriptorLookup> =
        Arc::new(StaticDescriptorLookup {
            descriptor: wallet_descriptor.clone(),
        });

    node1 = node1.with_descriptor_lookup(lookup.clone());
    node2 = node2.with_descriptor_lookup(lookup);

    let node1_pubkey = node1.pubkey();

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

    // Both nodes announce so they discover each other; node2 also announces
    // its external recovery xpub so the initiator can target it by fingerprint.
    node1.announce().await.expect("node1 announce");
    node2.announce().await.expect("node2 announce");

    let discovery = timeout(Duration::from_secs(45), async {
        let mut n1 = 0u32;
        let mut n2 = 0u32;
        loop {
            tokio::select! {
                ev = rx1.recv() => {
                    if let Ok(KfpNodeEvent::PeerDiscovered { .. }) = ev {
                        n1 += 1;
                    }
                }
                ev = rx2.recv() => {
                    if let Ok(KfpNodeEvent::PeerDiscovered { .. }) = ev {
                        n2 += 1;
                    }
                }
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
        panic!("peer discovery timed out");
    }

    // After mutual peer discovery, announce the responder's external xpub so
    // the initiator can target it by fingerprint when proposing.
    node2
        .announce_xpubs(vec![keep_frost_net::AnnouncedXpub {
            xpub: responder_xpub_str.clone(),
            fingerprint: responder_fp.clone(),
            label: Some("test-responder".into()),
        }])
        .await
        .expect("node2 announce_xpubs");

    // Wait for node1 to ingest node2's XpubAnnounce so target_peers filtering
    // by fingerprint succeeds when we propose.
    let xpub_seen = timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(KfpNodeEvent::XpubAnnounced { share_index, .. }) = rx1.recv().await {
                if share_index == 2 {
                    return;
                }
            }
        }
    })
    .await;
    if xpub_seen.is_err() {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        panic!("did not receive responder's XpubAnnounce");
    }

    // The XpubAnnounced event only signals the announce was ingested; under load
    // the peer's stored xpub may lag the event observer. Poll node1's peer view
    // until the responder fingerprint is present so target_peers filtering by
    // fingerprint deterministically succeeds before we propose.
    let xpub_stored = timeout(Duration::from_secs(15), async {
        loop {
            if node1
                .get_peer_recovery_xpubs(2)
                .map(|xpubs| xpubs.iter().any(|x| x.fingerprint == responder_fp))
                .unwrap_or(false)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if xpub_stored.is_err() {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        panic!("node1 did not store responder's recovery xpub");
    }

    // Build an unsigned recovery-spend PSBT for a 1-input/1-output tx against
    // a synthetic UTXO that uses our recovery address as the prev script.
    let utxo = OutPoint {
        txid: bitcoin::Txid::all_zeros(),
        vout: 0,
    };
    let utxo_value: u64 = 100_000;
    let fee: u64 = 1_000;
    let dest_kp = Keypair::from_seckey_slice(&secp, &[9u8; 32]).expect("dest keypair");
    let dest_xonly = dest_kp.x_only_public_key().0;
    let dest_script = ScriptBuf::new_p2tr(&secp, dest_xonly, None);

    let unsigned_psbt = builder
        .build_recovery_psbt(0, utxo, utxo_value, &dest_script, fee)
        .expect("build_recovery_psbt");
    let unsigned_bytes = unsigned_psbt.serialize();

    // Initiator proposes the PSBT, expecting the responder's fingerprint to
    // contribute the script-spend signature.
    let session_id = node1
        .request_psbt_spend(
            descriptor_hash,
            0,
            unsigned_bytes.clone(),
            fee,
            1,
            Vec::new(),
            vec![responder_fp.clone()],
            Vec::new(),
            Vec::new(),
            Some(60),
        )
        .await
        .expect("request_psbt_spend");

    // Responder side: receive PsbtSignatureNeeded, then perform the same chain
    // the production approve path runs: compute sighash, sign (in lieu of
    // NIP-46), merge, contribute.
    let need = timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(KfpNodeEvent::PsbtSignatureNeeded {
                session_id: sid,
                initiator_pubkey,
                ..
            }) = rx2.recv().await
            {
                if sid == session_id {
                    return initiator_pubkey;
                }
            }
        }
    })
    .await
    .expect("PsbtSignatureNeeded on responder");
    assert_eq!(need, node1_pubkey);

    let proposal_bytes = node2
        .psbt_session_proposal_psbt(&session_id)
        .expect("responder has proposal psbt");
    let mut responder_psbt = Psbt::deserialize(&proposal_bytes).expect("decode proposal");
    let sighashes = script_spend_sighashes(&responder_psbt).expect("compute sighashes");
    assert_eq!(sighashes.len(), 1);

    // In-process "NIP-46 signer": sign the sighash directly with the known
    // secret key. This stands in for a real bunker round-trip.
    let kp = Keypair::from_seckey_slice(&secp, &responder_sk).expect("responder kp");
    let msg = bitcoin::secp256k1::Message::from_digest(sighashes[0].sighash);
    let aux = [0u8; 32];
    let schnorr_sig = secp.sign_schnorr_with_aux_rand(&msg, &kp, &aux);
    let schnorr_bytes: [u8; 64] = schnorr_sig.serialize();
    merge_tap_script_sig(
        &mut responder_psbt,
        sighashes[0].input_index,
        responder_xonly,
        sighashes[0].leaf_hash,
        &sighashes[0].sighash,
        schnorr_bytes,
    )
    .expect("merge sig");
    let merged_bytes = responder_psbt.serialize();

    node2
        .contribute_psbt_signature(
            session_id,
            &need,
            SignerId::Fingerprint(responder_fp.clone()),
            merged_bytes,
        )
        .await
        .expect("contribute_psbt_signature");

    // Initiator auto-finalizes once threshold (1) is met. Wait for the event
    // and validate the produced PSBT's witness verifies on the prevout.
    let finalized = timeout(Duration::from_secs(15), async {
        loop {
            match rx1.recv().await {
                Ok(KfpNodeEvent::PsbtFinalized {
                    session_id: sid, ..
                }) if sid == session_id => {
                    return;
                }
                Ok(KfpNodeEvent::PsbtAborted {
                    session_id: sid,
                    reason,
                }) if sid == session_id => {
                    panic!("session aborted: {reason}");
                }
                Ok(_) => {}
                Err(_) => panic!("event channel closed"),
            }
        }
    })
    .await;
    if finalized.is_err() {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        panic!("did not receive PsbtFinalized");
    }

    // Independently reconstruct the same merged PSBT and finalize it via the
    // RecoveryTxBuilder so we can verify the script-spend signature is valid
    // and produces a well-formed witness for the recovery tier.
    let mut verify_psbt = Psbt::deserialize(&unsigned_bytes).expect("decode unsigned");
    let verify_sighashes = script_spend_sighashes(&verify_psbt).expect("verify sighashes");
    let v_msg = bitcoin::secp256k1::Message::from_digest(verify_sighashes[0].sighash);
    let v_sig = secp.sign_schnorr_with_aux_rand(&v_msg, &kp, &aux);
    verify_psbt.inputs[0].tap_script_sigs.insert(
        (responder_xonly, verify_sighashes[0].leaf_hash),
        TaprootSignature {
            signature: v_sig,
            sighash_type: TapSighashType::Default,
        },
    );

    let final_tx = builder
        .finalize_recovery(&mut verify_psbt, 0)
        .expect("finalize_recovery");
    assert!(!final_tx.input[0].witness.is_empty());

    // Verify the schnorr signature against the sighash using the prevout.
    let prevout = TxOut {
        value: Amount::from_sat(utxo_value),
        script_pubkey: recovery_output.address.script_pubkey(),
    };
    let mut cache = SighashCache::new(&final_tx);
    let leaf_hash =
        TapLeafHash::from_script(&recovery_output.tiers[0].script, LeafVersion::TapScript);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::Default,
        )
        .expect("verify sighash");
    let verify_msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
    secp.verify_schnorr(&v_sig, &verify_msg, &responder_xonly)
        .expect("schnorr verify");

    // Sanity: ensure the unused stack-cells / script / control-block are at
    // the expected witness positions for a 1-of-1 recovery tier.
    let witness = &final_tx.input[0].witness;
    assert!(witness.len() >= 3, "witness should have sig + script + cb");

    // Silence unused locals.
    let _ = (
        &external_desc,
        &internal_desc,
        Version::TWO,
        LockTime::ZERO,
        TxIn {
            previous_output: utxo,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        },
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        },
    );

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown2, node2_handle).await;
}

#[tokio::test]
async fn test_request_descriptor_fails_with_no_peers() {
    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, _pubkey_pkg) = dealer.generate("test-no-peers").unwrap();

    let share1 = shares.remove(0);

    let node1 = KfpNode::new(share1, vec![relay])
        .await
        .expect("Failed to create node");

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

    let result = node1
        .request_descriptor(policy, "signet", "tpub_test", "aabbccdd")
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("No online peers"),
        "Expected 'No online peers' error, got: {err}"
    );
}

#[tokio::test]
async fn test_signing_flow_with_nonce_pre_exchange() {
    use std::sync::Arc;

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, _pubkey_pkg) = dealer.generate("test-nonce-pre-exchange").unwrap();

    let share1 = shares.remove(0);
    let share2 = shares.remove(0);
    let share3 = shares.remove(0);

    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("Failed to create node 1");
    let mut node2 = KfpNode::new(share2, vec![relay.clone()])
        .await
        .expect("Failed to create node 2");
    let mut node3 = KfpNode::new(share3, vec![relay])
        .await
        .expect("Failed to create node 3");

    let mut rx3 = node3.subscribe();

    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();
    let shutdown3 = node3.take_shutdown_handle();

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let node3 = Arc::new(node3);

    let n1 = Arc::clone(&node1);
    let n2 = Arc::clone(&node2);
    let n3 = Arc::clone(&node3);

    let node1_handle = tokio::spawn(async move {
        let _ = n1.run().await;
    });
    let node2_handle = tokio::spawn(async move {
        let _ = n2.run().await;
    });
    let node3_handle = tokio::spawn(async move {
        let _ = n3.run().await;
    });

    let mut peers_discovered = 0u32;
    let discovery_timeout = timeout(Duration::from_secs(45), async {
        while peers_discovered < 2 {
            if let Ok(KfpNodeEvent::PeerDiscovered { .. }) = rx3.recv().await {
                peers_discovered += 1;
            }
        }
    })
    .await;

    if discovery_timeout.is_err() {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        graceful_shutdown(shutdown3, node3_handle).await;
        panic!("Peer discovery timed out: only {peers_discovered} peers discovered");
    }

    // Wait until node1 and node2 have also discovered node3, so their
    // broadcasts will reach the signer.
    let peers_ready = timeout(Duration::from_secs(45), async {
        loop {
            if node1.online_peers() >= 2 && node2.online_peers() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;

    if peers_ready.is_err() {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        graceful_shutdown(shutdown3, node3_handle).await;
        panic!("node1/node2 did not discover all peers");
    }

    // Each peer pre-exchanges round-1 commitments. node3 (the signer) needs
    // pooled commitments from node1 and node2.
    node1.replenish_nonce_pool().await.expect("node1 replenish");
    node2.replenish_nonce_pool().await.expect("node2 replenish");

    // Allow the broadcast NonceCommitment events to propagate to node3.
    let pool_ready = timeout(Duration::from_secs(20), async {
        loop {
            if node3.nonce_pool_peer_available(1) > 0 && node3.nonce_pool_peer_available(2) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;

    if pool_ready.is_err() {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        graceful_shutdown(shutdown3, node3_handle).await;
        panic!("Pre-exchanged commitments did not propagate to signer");
    }

    let before_1 = node3.nonce_pool_peer_available(1);
    let before_2 = node3.nonce_pool_peer_available(2);

    let message = b"pre-exchanged nonce signing".to_vec();
    let sign_result = timeout(Duration::from_secs(60), async {
        node3.request_signature(message, "raw").await
    })
    .await;

    // The signer should have consumed exactly one pooled commitment per peer.
    let after_1 = node3.nonce_pool_peer_available(1);
    let after_2 = node3.nonce_pool_peer_available(2);

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown2, node2_handle).await;
    graceful_shutdown(shutdown3, node3_handle).await;

    match sign_result {
        Ok(Ok(signature)) => assert_eq!(signature.len(), 64),
        Ok(Err(e)) => panic!("Signing failed: {e:?}"),
        Err(_) => panic!("Signing timed out after 60 seconds"),
    }

    // A 2-of-3 signing selects exactly one peer besides the requester, so
    // exactly one pooled commitment must have been consumed (single-use).
    let consumed = (before_1 - after_1) + (before_2 - after_2);
    assert_eq!(
        consumed, 1,
        "expected exactly one pooled commitment consumed across selected peers"
    );
}

// Reproduces consecutive-signing robustness bugs (stale_nonce / Unknown
// identifier): a persistent initiator must complete many signs in a row as the
// pre-exchanged nonce pool churns.
#[tokio::test]
async fn test_repeated_signing() {
    use std::sync::Arc;

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, _pubkey_pkg) = dealer.generate("repeat-signing").unwrap();
    let share1 = shares.remove(0);
    let share2 = shares.remove(0);
    let share3 = shares.remove(0);

    let mut node1 = KfpNode::new(share1, vec![relay.clone()]).await.unwrap();
    let mut node2 = KfpNode::new(share2, vec![relay.clone()]).await.unwrap();
    let mut node3 = KfpNode::new(share3, vec![relay]).await.unwrap();

    let mut rx3 = node3.subscribe();
    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();
    let shutdown3 = node3.take_shutdown_handle();

    let node3 = Arc::new(node3);
    let node3_for_run = Arc::clone(&node3);
    let h1 = tokio::spawn(async move {
        let _ = node1.run().await;
    });
    let h2 = tokio::spawn(async move {
        let _ = node2.run().await;
    });
    let h3 = tokio::spawn(async move {
        let _ = node3_for_run.run().await;
    });

    let mut peers_discovered = 0u32;
    let discovered = timeout(Duration::from_secs(45), async {
        while peers_discovered < 2 {
            if let Ok(keep_frost_net::KfpNodeEvent::PeerDiscovered { .. }) = rx3.recv().await {
                peers_discovered += 1;
            }
        }
    })
    .await;
    if discovered.is_err() {
        graceful_shutdown(shutdown1, h1).await;
        graceful_shutdown(shutdown2, h2).await;
        graceful_shutdown(shutdown3, h3).await;
        panic!("peer discovery timed out: only {peers_discovered} peers discovered");
    }

    let mut failures = Vec::new();
    for i in 0..6u32 {
        let msg = format!("repeat-sign-{i}").into_bytes();
        match timeout(Duration::from_secs(30), node3.request_signature(msg, "raw")).await {
            Ok(Ok(sig)) => assert_eq!(sig.len(), 64),
            Ok(Err(e)) => failures.push(format!("sign {i}: {e:?}")),
            Err(_) => failures.push(format!("sign {i}: timeout")),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    graceful_shutdown(shutdown1, h1).await;
    graceful_shutdown(shutdown2, h2).await;
    graceful_shutdown(shutdown3, h3).await;

    assert!(
        failures.is_empty(),
        "repeated signing failures: {failures:#?}"
    );
}

/// ECDH multi-peer integration test (closes #543's request/share/complete handler gaps).
///
/// Drives a 2-of-3 group through `request_ecdh` end-to-end on a MockRelay
/// with two live nodes: the requester (node1) and one cosigner (node2).
/// This exercises the full responder pipeline (`handle_ecdh_request` ->
/// `handle_ecdh_share` -> `handle_ecdh_complete`) and the requester-side
/// completion path, killing the mutations in `node/ecdh.rs` that the unit
/// tests in PR #544 couldn't reach.
///
#[tokio::test]
async fn test_ecdh_request_completes_with_one_cosigner() {
    use std::sync::Arc;

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, pubkey_pkg) = dealer.generate("test-ecdh").unwrap();

    let share1 = shares.remove(0);
    let share2 = shares.remove(0);

    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("Failed to create node 1");
    let mut node2 = KfpNode::new(share2, vec![relay])
        .await
        .expect("Failed to create node 2");

    let mut rx1 = node1.subscribe();
    let mut rx2 = node2.subscribe();

    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let node1_for_run = Arc::clone(&node1);
    let node2_for_run = Arc::clone(&node2);

    let node1_handle = tokio::spawn(async move {
        let _ = node1_for_run.run().await;
    });
    let node2_handle = tokio::spawn(async move {
        let _ = node2_for_run.run().await;
    });

    // Wait for peer discovery: both nodes must see the other before the
    // request_ecdh call, or `select_eligible_peers` fails with no eligible
    // cosigner.
    let mut node1_peers = 0u32;
    let mut node2_peers = 0u32;
    let discovery = timeout(Duration::from_secs(45), async {
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
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        panic!("Peer discovery timed out: node1={node1_peers}, node2={node2_peers}");
    }

    // An arbitrary external recipient. ECDH completes regardless of
    // recipient identity; PR #544 covers crypto correctness, so here we
    // just need a syntactically valid compressed point.
    let recipient_secret = bitcoin::secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let recipient_pubkey: [u8; 33] = recipient_secret.public_key(&secp).serialize();

    let request_result = timeout(
        Duration::from_secs(45),
        node1.request_ecdh(&recipient_pubkey),
    )
    .await;

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown2, node2_handle).await;

    let shared_secret = match request_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => panic!("request_ecdh failed: {e}"),
        Err(_) => panic!("request_ecdh timed out: multi-peer ECDH coordination did not complete"),
    };

    // Independent recipient-side oracle. The cosigners aggregate to the
    // x-coordinate of `recipient_pubkey * group_secret`; by ECDH symmetry that
    // equals the x-coordinate of `group_pubkey * recipient_secret`, which the
    // x-coordinate makes invariant to taproot's even-Y parity. Deriving it from
    // the dealer's group pubkey and the known recipient secret never touches the
    // request_ecdh path, so this is a genuine oracle rather than a circular check.
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
