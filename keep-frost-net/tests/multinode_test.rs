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

    // node3 having discovered both peers does not guarantee they have processed
    // node3's announce yet; let the reciprocal announces flush so both are ready
    // to answer node3's ping before we measure responsiveness.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // The deadlock manifested here: before the fix this never returned. The ping
    // window is generous so a loaded (e.g. macOS CI) runner still collects both
    // pongs; the point of the test is that health_check returns at all.
    let health = timeout(
        Duration::from_secs(20),
        node3.health_check(Duration::from_secs(8)),
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

    // The ECDH oracle now requires the requester to be fresh-Verified (matching
    // the OPRF/enroll oracles). These nodes run without an attestation policy,
    // so mark the requester (share index 1) Verified on the responder, exactly
    // as the OPRF round-trip test does. Let the post-discovery reciprocal
    // announces flush first (a re-announce would reset the status); re-announces
    // are then 20s apart, covering the sub-second request window.
    tokio::time::sleep(Duration::from_secs(1)).await;
    node2.test_set_peer_attestation(1, keep_frost_net::AttestationStatus::Verified);

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

/// Persisted-descriptor lookup that knows two version-linked descriptors for
/// the same group (OLD as version 1, NEW as version 2 with
/// `previous_descriptor_hash` pointing back to OLD). Used by the migration
/// sweep test to satisfy both the proposer's `find_by_hash`/`external_for`
/// checks (covering both OLD and NEW) and the responder's `successor_for`
/// chain check from `validate_migration_sweep_destination`.
struct DualDescriptorLookup {
    old: keep_core::wallet::WalletDescriptor,
    new: keep_core::wallet::WalletDescriptor,
}

impl keep_frost_net::PersistedDescriptorLookup for DualDescriptorLookup {
    fn find_by_hash(&self, group: &[u8; 32], hash: &[u8; 32]) -> bool {
        if &self.old.group_pubkey != group {
            return false;
        }
        hash == &self.old.canonical_hash() || hash == &self.new.canonical_hash()
    }

    fn network_for(&self, group: &[u8; 32], hash: &[u8; 32]) -> Option<String> {
        if &self.old.group_pubkey != group {
            return None;
        }
        if hash == &self.old.canonical_hash() {
            return Some(self.old.network.clone());
        }
        if hash == &self.new.canonical_hash() {
            return Some(self.new.network.clone());
        }
        None
    }

    fn external_for(&self, group: &[u8; 32], hash: &[u8; 32]) -> Option<String> {
        if &self.old.group_pubkey != group {
            return None;
        }
        if hash == &self.old.canonical_hash() {
            return Some(self.old.external_descriptor.clone());
        }
        if hash == &self.new.canonical_hash() {
            return Some(self.new.external_descriptor.clone());
        }
        None
    }

    fn latest_version_for(
        &self,
        group: &[u8; 32],
    ) -> std::result::Result<Option<u32>, keep_frost_net::DescriptorLookupUnavailable> {
        if &self.old.group_pubkey == group {
            Ok(Some(self.new.version))
        } else {
            Ok(None)
        }
    }

    fn successor_for(&self, group: &[u8; 32], hash: &[u8; 32]) -> keep_frost_net::SuccessorLookup {
        if &self.old.group_pubkey != group {
            return keep_frost_net::SuccessorLookup::Unavailable;
        }
        let old_hash = self.old.canonical_hash();
        let new_hash = self.new.canonical_hash();
        if hash == &old_hash {
            keep_frost_net::SuccessorLookup::Found {
                external_descriptor: self.new.external_descriptor.clone(),
                network: self.new.network.clone(),
            }
        } else if hash == &new_hash {
            keep_frost_net::SuccessorLookup::Tip
        } else {
            keep_frost_net::SuccessorLookup::Unavailable
        }
    }
}

/// Drives `request_descriptor_migration_sweep` end to end on two nodes over a
/// MockRelay, covering the previously-untested coordination path:
///   - `request_descriptor_migration_sweep` (proposer-side build + broadcast)
///   - `handle_psbt_propose` (responder-side `validate_migration_sweep_destination`
///     successor-chain check)
///   - `handle_psbt_sign` -> aggregation -> `handle_psbt_finalize` (responder
///     and proposer finalization)
///
/// A `Complete` migration session is injected directly into node1's session
/// manager (the protocol-correct way to reach that state is descriptor
/// coordination + ack, which is covered by `test_descriptor_coordination_flow`
/// and would just duplicate setup here). The descriptor lookup is a
/// `DualDescriptorLookup` so OLD and NEW resolve correctly on both nodes.
#[tokio::test]
async fn test_psbt_migration_sweep_end_to_end() {
    use std::sync::Arc;

    use bitcoin::bip32::Xpub;
    use bitcoin::hashes::Hash as _;
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{LeafVersion, TapLeafHash};
    use bitcoin::{Amount, Network, OutPoint, TxOut, XOnlyPublicKey};
    use keep_bitcoin::recovery::{
        RecoveryConfig, RecoveryTier as BitcoinRecoveryTier, SpendingTier,
    };
    use keep_bitcoin::{
        merge_tap_script_sig, script_spend_sighashes, DescriptorExport, RecoveryTxBuilder,
        SweepUtxo,
    };
    use keep_frost_net::{DescriptorSession, FinalizedDescriptor, SignerId, WalletPolicy};

    let mock_relay = MockRelay::run().await.expect("MockRelay start");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-psbt-sweep").unwrap();
    let share1 = shares.remove(0);
    let share2 = shares.remove(0);

    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("node1 create");
    let mut node2 = KfpNode::new(share2, vec![relay])
        .await
        .expect("node2 create");
    let group_pubkey = *node1.group_pubkey();

    // Responder external key — known secret enables inline sighash signing
    // in lieu of a NIP-46 round-trip (same pattern as the recovery-spend test).
    let secp = Secp256k1::new();
    let responder_xpriv =
        bitcoin::bip32::Xpriv::new_master(Network::Signet, &[7u8; 32]).expect("xpriv");
    let responder_xpub = Xpub::from_priv(&secp, &responder_xpriv);
    let responder_xpub_str = responder_xpub.to_string();
    let responder_fp = responder_xpub
        .fingerprint()
        .to_string()
        .to_ascii_lowercase();
    let responder_xonly_bytes = responder_xpub.to_x_only_pub().serialize();
    let responder_xonly = XOnlyPublicKey::from_slice(&responder_xonly_bytes).expect("xonly");
    let responder_sk = responder_xpriv.private_key.secret_bytes();

    // OLD and NEW share the same recovery shape (one external key, 1-of-1
    // tier, 6-month timelock). The migration is "cosmetic" but exercises the
    // full sweep coordination — the production threat model the test verifies
    // is the proposer-side build + responder-side validation, not a
    // semantically interesting policy change.
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

    // OLD descriptor: version 1, no previous.
    let old_descriptor = keep_core::wallet::WalletDescriptor {
        group_pubkey,
        external_descriptor: external_desc.clone(),
        internal_descriptor: internal_desc.clone(),
        network: "signet".to_string(),
        created_at: 0,
        device_registrations: Vec::new(),
        policy_hash,
        version: 1,
        previous_descriptor_hash: None,
        policy: policy_value.clone(),
    };
    let old_descriptor_hash = old_descriptor.canonical_hash();

    // NEW descriptor: version 2, previous_descriptor_hash = OLD's hash. Same
    // external/internal strings work here (the sweep cares about the version
    // chain, not the descriptor content).
    let new_descriptor = keep_core::wallet::WalletDescriptor {
        group_pubkey,
        external_descriptor: external_desc.clone(),
        internal_descriptor: internal_desc.clone(),
        network: "signet".to_string(),
        created_at: 0,
        device_registrations: Vec::new(),
        policy_hash,
        version: 2,
        previous_descriptor_hash: Some(old_descriptor_hash),
        policy: policy_value,
    };

    let lookup: Arc<dyn keep_frost_net::PersistedDescriptorLookup> =
        Arc::new(DualDescriptorLookup {
            old: old_descriptor,
            new: new_descriptor.clone(),
        });
    node1 = node1.with_descriptor_lookup(lookup.clone());
    node2 = node2.with_descriptor_lookup(lookup);

    // Inject a Complete migration session for the NEW descriptor on node1.
    // request_descriptor_migration_sweep reads the session for the finalized
    // descriptor's external/internal/policy_hash/network and version.
    let migration_session_id = [0xAA; 32];
    {
        let finalized = FinalizedDescriptor {
            external: external_desc.clone(),
            internal: internal_desc.clone(),
            policy_hash,
        };
        let mut policy_v2 = policy.clone();
        policy_v2.version = 2;
        let session = DescriptorSession::test_completed(
            migration_session_id,
            group_pubkey,
            policy_v2,
            "signet".to_string(),
            finalized,
        );
        node1.test_inject_descriptor_session(session);
    }

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

    node2
        .announce_xpubs(vec![keep_frost_net::AnnouncedXpub {
            xpub: responder_xpub_str.clone(),
            fingerprint: responder_fp.clone(),
            label: Some("test-sweep-responder".into()),
        }])
        .await
        .expect("node2 announce_xpubs");

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

    // Sweep two synthetic UTXOs under the OLD recovery output.
    let utxos = vec![
        SweepUtxo {
            outpoint: OutPoint {
                txid: bitcoin::Txid::all_zeros(),
                vout: 0,
            },
            value_sats: 75_000,
        },
        SweepUtxo {
            outpoint: OutPoint {
                txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(
                    [0x11; 32],
                )),
                vout: 1,
            },
            value_sats: 30_000,
        },
    ];
    let total_in: u64 = utxos.iter().map(|u| u.value_sats).sum();
    let fee_sats: u64 = 1_500;

    let session_id = node1
        .request_descriptor_migration_sweep(
            migration_session_id,
            old_descriptor_hash,
            &recovery_output,
            0,
            utxos.clone(),
            fee_sats,
            1,
            Vec::new(),
            vec![responder_fp.clone()],
            Some(60),
        )
        .await
        .expect("request_descriptor_migration_sweep");

    // Responder side: receive PsbtSignatureNeeded, sign the sighashes, contribute.
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
    assert_eq!(sighashes.len(), utxos.len(), "one sighash per swept input");

    let responder_kp = Keypair::from_seckey_slice(&secp, &responder_sk).expect("responder keypair");
    let aux = [0u8; 32];

    for sh in &sighashes {
        let msg = bitcoin::secp256k1::Message::from_digest(sh.sighash);
        let schnorr_sig = secp.sign_schnorr_with_aux_rand(&msg, &responder_kp, &aux);
        let schnorr_bytes: [u8; 64] = schnorr_sig.serialize();
        merge_tap_script_sig(
            &mut responder_psbt,
            sh.input_index,
            responder_xonly,
            sh.leaf_hash,
            &sh.sighash,
            schnorr_bytes,
        )
        .expect("merge sig");
    }
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

    let finalized = timeout(Duration::from_secs(15), async {
        loop {
            match rx1.recv().await {
                Ok(KfpNodeEvent::PsbtFinalized {
                    session_id: sid, ..
                }) if sid == session_id => return,
                Ok(KfpNodeEvent::PsbtAborted {
                    session_id: sid,
                    reason,
                }) if sid == session_id => panic!("sweep aborted: {reason}"),
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

    // Independently rebuild the same proposal PSBT and verify each input's
    // schnorr signature against the swept recovery prevouts. Asserts the
    // proposer-side build wired the right tap_scripts + control_block for
    // every input (sighash recomputation must match what the responder
    // signed) and that the destination addresses the NEW descriptor.
    let new_dest_script =
        keep_bitcoin::descriptor_address(&new_descriptor.external_descriptor, Network::Signet)
            .expect("derive new dest")
            .script_pubkey();
    let verify_psbt = builder
        .build_sweep_psbt(0, &utxos, &new_dest_script, fee_sats)
        .expect("build_sweep_psbt");

    let verify_sighashes = script_spend_sighashes(&verify_psbt).expect("verify sighashes");
    assert_eq!(verify_sighashes.len(), utxos.len(), "one sighash per input");

    let prevouts: Vec<TxOut> = utxos
        .iter()
        .map(|u| TxOut {
            value: Amount::from_sat(u.value_sats),
            script_pubkey: recovery_output.address.script_pubkey(),
        })
        .collect();
    let mut cache = SighashCache::new(&verify_psbt.unsigned_tx);
    let leaf_hash =
        TapLeafHash::from_script(&recovery_output.tiers[0].script, LeafVersion::TapScript);
    for (idx, sh) in verify_sighashes.iter().enumerate() {
        // Sighash recomputed from the rebuilt PSBT must match what the
        // responder signed: same value if and only if the proposer used the
        // same inputs + destination + recovery output.
        let recomputed = cache
            .taproot_script_spend_signature_hash(
                idx,
                &Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            )
            .expect("recompute sighash");
        assert_eq!(
            recomputed.to_byte_array(),
            sh.sighash,
            "input {idx}: recomputed sighash must match the proposer's"
        );

        // Cross-check the responder's real proposal sighash (derived from the
        // protocol's proposal PSBT) against the locally rebuilt one.
        assert_eq!(
            sighashes[idx].input_index, sh.input_index,
            "input {idx}: proposal/rebuild input index must align"
        );
        assert_eq!(
            sighashes[idx].sighash, sh.sighash,
            "input {idx}: responder's real proposal sighash must match the rebuilt one"
        );

        // Verify the responder's actual contributed signature, not a re-signed
        // copy. Pulls the schnorr sig the responder merged into the proposal
        // PSBT before contributing; re-signing here would tautologically pass
        // regardless of whether the PSBT coordination produced a valid sig.
        let v_msg = bitcoin::secp256k1::Message::from_digest(sh.sighash);
        let contributed_sig = responder_psbt.inputs[sh.input_index]
            .tap_script_sigs
            .get(&(responder_xonly, sh.leaf_hash))
            .unwrap_or_else(|| {
                panic!(
                    "input {idx}: PSBT is missing the responder's tap_script_sig \
                     for (xonly={responder_xonly:?}, leaf={:?}); \
                     PSBT merging or storage regression",
                    sh.leaf_hash
                )
            });
        secp.verify_schnorr(&contributed_sig.signature, &v_msg, &responder_xonly)
            .expect("responder's contributed sweep signature MUST verify under BIP-340");
    }

    // The proposer-side build produced exactly the right output shape: one
    // output paying the NEW descriptor address with the swept-amount minus
    // fee.
    assert_eq!(verify_psbt.unsigned_tx.output.len(), 1);
    assert_eq!(
        verify_psbt.unsigned_tx.output[0].script_pubkey, new_dest_script,
        "sweep MUST pay the NEW descriptor address"
    );
    assert_eq!(
        verify_psbt.unsigned_tx.output[0].value.to_sat(),
        total_in - fee_sats,
        "sweep output value = sum(inputs) - fee"
    );

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown2, node2_handle).await;
}

// ---------------------------------------------------------------------------
// Threshold-OPRF unlock session tests.
//
// These mirror the ECDH harness above: a 2-of-3 FROST group on a MockRelay
// where the "box" (initiator) gathers holder partial evaluations and derives a
// LUKS key locally. The OPRF oracle defaults CLOSED (security fixes #621), so a
// happy-path holder MUST (a) install a SigningHooks impl whose
// `approve_oprf_eval` returns true and (b) see the box peer as
// `AttestationStatus::Verified`. The negative-path tests drive the holder
// handler directly to assert each gate rejects without producing a share.
// ---------------------------------------------------------------------------

const OPRF_INPUT: &[u8] = b"keep-node-vault-v1";

/// Holder-side hook that approves every OPRF evaluation. Required for the happy
/// path because `approve_oprf_eval` defaults to DENY.
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

/// Split one OPRF key 2-of-3. `KeyShare` at index `i` is the vsss share for
/// FROST identifier `i + 1`.
fn split_oprf_key_2of3() -> Vec<keep_core::oprf::threshold::KeyShare> {
    use k256::elliptic_curve::rand_core::OsRng;
    use k256::Scalar;
    let mut rng = OsRng;
    let secret = <Scalar as k256::elliptic_curve::Field>::random(&mut rng);
    keep_core::oprf::threshold::split_key(&secret, 2, 3, rng).expect("split oprf key")
}

/// Happy path: a 2-of-3 group with the box (id 1) and one holder (id 2) online,
/// both carrying an OPRF share. The holder approves evaluations and sees the box
/// as Verified, so `request_oprf_unlock` collects the holder's partial, reaches
/// quorum, and derives a 32-byte LUKS key. Two independent runs (fresh blinds)
/// must derive the SAME key, since finalize strips the per-attempt blinding.
#[tokio::test]
async fn test_oprf_unlock_completes_with_one_holder() {
    use std::sync::Arc;

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, _pkg) = dealer.generate("test-oprf-unlock").unwrap();
    let share1 = shares.remove(0); // FROST id 1 = box
    let share2 = shares.remove(0); // FROST id 2 = holder

    let oprf = split_oprf_key_2of3();

    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("Failed to create box node");
    node1.set_oprf_key_share(oprf[0]); // box holds vsss index 1
    let mut node2 = KfpNode::new(share2, vec![relay])
        .await
        .expect("Failed to create holder node");
    node2.set_oprf_key_share(oprf[1]); // holder holds vsss index 2
    node2.set_hooks(Arc::new(ApproveOprfHooks));

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
    let discovery = timeout(Duration::from_secs(45), async {
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

    // Let the reciprocal announces flush, then mark the box Verified on the
    // holder. Re-announces are 20s apart, so this stays Verified for the brief
    // window the (sub-second) request occupies.
    tokio::time::sleep(Duration::from_secs(1)).await;
    node2.test_set_peer_attestation(1, keep_frost_net::AttestationStatus::Verified);

    let key1 = match timeout(
        Duration::from_secs(45),
        node1.request_oprf_unlock(OPRF_INPUT, "vault0", 1),
    )
    .await
    {
        Ok(Ok(k)) => k,
        Ok(Err(e)) => {
            graceful_shutdown(shutdown1, node1_handle).await;
            graceful_shutdown(shutdown2, node2_handle).await;
            panic!("request_oprf_unlock failed: {e}");
        }
        Err(_) => {
            graceful_shutdown(shutdown1, node1_handle).await;
            graceful_shutdown(shutdown2, node2_handle).await;
            panic!("request_oprf_unlock timed out");
        }
    };
    assert_eq!(key1.len(), 32, "derived LUKS key must be 32 bytes");

    // Second independent run (fresh blind) must derive the same key: the OPRF
    // output is a deterministic PRF of (input, key, volume, epoch).
    node2.test_set_peer_attestation(1, keep_frost_net::AttestationStatus::Verified);
    let key2 = match timeout(
        Duration::from_secs(45),
        node1.request_oprf_unlock(OPRF_INPUT, "vault0", 1),
    )
    .await
    {
        Ok(Ok(k)) => k,
        Ok(Err(e)) => {
            graceful_shutdown(shutdown1, node1_handle).await;
            graceful_shutdown(shutdown2, node2_handle).await;
            panic!("second request_oprf_unlock failed: {e}");
        }
        Err(_) => {
            graceful_shutdown(shutdown1, node1_handle).await;
            graceful_shutdown(shutdown2, node2_handle).await;
            panic!("second request_oprf_unlock timed out");
        }
    };

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown2, node2_handle).await;

    assert_eq!(
        *key1, *key2,
        "two independent unlock runs must derive the same LUKS key (PRF determinism)"
    );
}

/// Build a well-formed OPRF eval request for `holder` from a synthetic box at
/// FROST share index 1, returning the box pubkey, the request payload (with a
/// real blinded element), and the raw blinded bytes for box-side partials.
fn make_oprf_request(
    holder: &KfpNode,
) -> (
    nostr_sdk::PublicKey,
    keep_frost_net::OprfEvalRequestPayload,
    Vec<u8>,
) {
    let box_pubkey = nostr_sdk::Keys::generate().public_key();
    let (_client, blinded) = keep_core::oprf::unlock::blind(OPRF_INPUT).expect("blind");
    let blinded_arr: [u8; 33] = blinded.as_slice().try_into().expect("33-byte blinded");
    let payload = keep_frost_net::OprfEvalRequestPayload::new(
        [0x01u8; 32],
        *holder.group_pubkey(),
        blinded_arr,
        vec![1, 2, 3],
        1,
    );
    (box_pubkey, payload, blinded)
}

/// Gate (approval declined): a Verified, in-budget requester whose evaluation
/// the holder's hook declines (the default DENY hook) gets NO partial. The
/// handler returns `Ok(())` (declined, not errored) and emits `OprfEvalRequested`
/// (proving every prior gate passed, so the decline is the hook), but produces
/// no share, so a box with only its own partial never reaches quorum.
#[tokio::test]
async fn test_oprf_eval_declined_by_hook_sends_no_share() {
    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-oprf-decline").unwrap();
    let _ = shares.remove(0); // id 1 (box is synthetic)
    let holder_share = shares.remove(0); // id 2 = holder

    let oprf = split_oprf_key_2of3();
    let mut holder = KfpNode::new(holder_share, vec![relay])
        .await
        .expect("holder");
    holder.set_oprf_key_share(oprf[1]);
    // No approving hook installed: the default NoOpHooks denies every eval.

    let (box_pubkey, payload, blinded) = make_oprf_request(&holder);
    holder.test_inject_peer(
        keep_frost_net::Peer::new(box_pubkey, 1)
            .with_attestation_status(keep_frost_net::AttestationStatus::Verified),
    );

    let mut rx = holder.subscribe();
    let result = holder
        .test_handle_oprf_eval_request(box_pubkey, payload)
        .await;
    assert!(
        result.is_ok(),
        "a declined eval must return Ok(()), got {result:?}"
    );

    // The holder accepted the request (passed every gate) and only then declined
    // at the hook.
    let requested = rx.try_recv();
    assert!(
        matches!(
            requested,
            Ok(KfpNodeEvent::OprfEvalRequested {
                requester_index: 1,
                ..
            })
        ),
        "holder must emit OprfEvalRequested before the hook declines, got {requested:?}"
    );

    // No share was produced, so a box holding only its own partial cannot reach
    // the 2-of-3 quorum.
    let (client, _) = keep_core::oprf::unlock::blind(OPRF_INPUT).expect("blind");
    let box_partial = keep_core::oprf::unlock::evaluate(&oprf[0], &blinded).expect("box partial");
    let mut session = keep_frost_net::OprfUnlockSession::new(
        [0x01u8; 32],
        client,
        2,
        vec![1, 2, 3],
        "vault0".into(),
        1,
    );
    session
        .add_partial(1, box_partial.to_vec())
        .expect("add box partial");
    assert!(
        !session.has_quorum(),
        "box must not reach quorum without the holder's declined partial"
    );
}

/// Gate (attestation): a requester whose peer is NOT `Verified` (default
/// `NotProvided`) is rejected with `UntrustedPeer` before any partial is
/// produced, and the holder emits no `OprfEvalRequested`.
#[tokio::test]
async fn test_oprf_eval_rejects_unattested_requester() {
    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-oprf-unattested").unwrap();
    let _ = shares.remove(0);
    let holder_share = shares.remove(0);

    let oprf = split_oprf_key_2of3();
    let mut holder = KfpNode::new(holder_share, vec![relay])
        .await
        .expect("holder");
    holder.set_oprf_key_share(oprf[1]);
    holder.set_hooks(std::sync::Arc::new(ApproveOprfHooks));

    let (box_pubkey, payload, _blinded) = make_oprf_request(&holder);
    // Inject the requester with the DEFAULT attestation status (NotProvided).
    holder.test_inject_peer(keep_frost_net::Peer::new(box_pubkey, 1));

    let mut rx = holder.subscribe();
    let result = holder
        .test_handle_oprf_eval_request(box_pubkey, payload)
        .await;
    assert!(
        matches!(result, Err(keep_frost_net::FrostNetError::UntrustedPeer(_))),
        "an unattested requester must be rejected with UntrustedPeer, got {result:?}"
    );
    assert!(
        rx.try_recv().is_err(),
        "no OprfEvalRequested may be emitted for a rejected unattested requester"
    );
}

/// Gate (rate limit): from one Verified + approved requester, the first
/// `MAX_OPRF_EVALS_PER_WINDOW` evaluations succeed; the next is refused with
/// `RateLimited`. The limiter keys on the requester pubkey, so distinct
/// session_ids share one budget.
#[tokio::test]
async fn test_oprf_eval_rate_limited_after_budget() {
    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-oprf-ratelimit").unwrap();
    let _ = shares.remove(0);
    let holder_share = shares.remove(0);

    let oprf = split_oprf_key_2of3();
    let mut holder = KfpNode::new(holder_share, vec![relay])
        .await
        .expect("holder");
    holder.set_oprf_key_share(oprf[1]);
    holder.set_hooks(std::sync::Arc::new(ApproveOprfHooks));

    let (box_pubkey, base_payload, _blinded) = make_oprf_request(&holder);
    holder.test_inject_peer(
        keep_frost_net::Peer::new(box_pubkey, 1)
            .with_attestation_status(keep_frost_net::AttestationStatus::Verified),
    );

    for i in 0..keep_frost_net::MAX_OPRF_EVALS_PER_WINDOW {
        let mut payload = base_payload.clone();
        payload.session_id = [i as u8; 32];
        let r = holder
            .test_handle_oprf_eval_request(box_pubkey, payload)
            .await;
        assert!(r.is_ok(), "eval {i} within budget must succeed, got {r:?}");
    }

    let mut over = base_payload.clone();
    over.session_id = [0xFFu8; 32];
    let result = holder.test_handle_oprf_eval_request(box_pubkey, over).await;
    assert!(
        matches!(result, Err(keep_frost_net::FrostNetError::RateLimited(_))),
        "exceeding the per-window budget must be rejected with RateLimited, got {result:?}"
    );
}

/// Gate (replay): a request whose `created_at` predates the replay window is
/// rejected with `ReplayDetected` before any peer/attestation check, and no
/// share is produced.
#[tokio::test]
async fn test_oprf_eval_rejects_replayed_request() {
    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-oprf-replay").unwrap();
    let _ = shares.remove(0);
    let holder_share = shares.remove(0);

    let oprf = split_oprf_key_2of3();
    let mut holder = KfpNode::new(holder_share, vec![relay])
        .await
        .expect("holder");
    holder.set_oprf_key_share(oprf[1]);

    let (box_pubkey, mut payload, _blinded) = make_oprf_request(&holder);
    // Backdate well past the default 300s replay window.
    payload.created_at = nostr_sdk::Timestamp::now().as_secs() - 400;

    let result = holder
        .test_handle_oprf_eval_request(box_pubkey, payload)
        .await;
    assert!(
        matches!(
            result,
            Err(keep_frost_net::FrostNetError::ReplayDetected(_))
        ),
        "a stale request must be rejected with ReplayDetected, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Trusted-dealer OPRF enrollment tests.
//
// The "box" (dealer) has already split an OPRF secret and now ships each remote
// holder that holder's secret key share, collecting an ack from each. Like the
// eval oracle, taking custody of a key share is gated on STRICT (`Verified`)
// attestation of the dealer.
// ---------------------------------------------------------------------------

/// Happy path: a 2-of-3 group where the dealer (id 1) distributes the holder's
/// (id 2) OPRF secret key share. The holder, seeing the dealer as `Verified`,
/// takes custody (emits `OprfShareReceived` with a share that round-trips
/// through `deserialize_key_share` and equals what was sent) and acks, so the
/// dealer's `distribute_oprf_shares` completes.
#[tokio::test]
async fn test_oprf_enroll_distributes_share_and_completes() {
    use std::sync::Arc;
    use zeroize::Zeroizing;

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, _pkg) = dealer.generate("test-oprf-enroll").unwrap();
    let share1 = shares.remove(0); // FROST id 1 = dealer (box)
    let share2 = shares.remove(0); // FROST id 2 = holder

    let oprf = split_oprf_key_2of3();
    // The remote target (holder id 2) gets the vsss share at index 2 (oprf[1]).
    // The dealer keeps its own share (oprf[0]) sealed locally; it is NOT sent.
    let target_bytes = keep_core::oprf::threshold::serialize_key_share(&oprf[1]).to_vec();

    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("dealer node");
    let mut node2 = KfpNode::new(share2, vec![relay])
        .await
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
    let discovery = timeout(Duration::from_secs(45), async {
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
    node2.test_set_peer_attestation(1, keep_frost_net::AttestationStatus::Verified);

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
        Duration::from_secs(45),
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

/// Build a well-formed OPRF enrollment for `holder` (FROST id 2) from a synthetic
/// dealer at share index 1, returning the dealer pubkey and the payload.
fn make_oprf_enroll(holder: &KfpNode) -> (nostr_sdk::PublicKey, keep_frost_net::OprfEnrollPayload) {
    let dealer_pubkey = nostr_sdk::Keys::generate().public_key();
    let oprf = split_oprf_key_2of3();
    let share = keep_core::oprf::threshold::serialize_key_share(&oprf[1]).to_vec();
    let payload = keep_frost_net::OprfEnrollPayload::new(
        [0x01u8; 32],
        *holder.group_pubkey(),
        1, // dealer_index
        2, // target_index = holder FROST id 2
        2, // threshold
        3, // total
        zeroize::Zeroizing::new(share),
    );
    (dealer_pubkey, payload)
}

/// Gate (attestation): a dealer whose peer is NOT `Verified` (default
/// `NotProvided`) is rejected with `UntrustedPeer` before the share is taken
/// into custody, and the holder emits no `OprfShareReceived` (and sends no ack).
#[tokio::test]
async fn test_oprf_enroll_rejects_unattested_dealer() {
    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-oprf-enroll-unattested").unwrap();
    let _ = shares.remove(0); // id 1 (dealer is synthetic)
    let holder_share = shares.remove(0); // id 2 = holder

    // Allow unpinned enrollment so the attestation gate (not the dealer pin) is what rejects.
    let holder = KfpNode::new(holder_share, vec![relay])
        .await
        .expect("holder")
        .allow_unpinned_oprf_dealer(true);

    let (dealer_pubkey, payload) = make_oprf_enroll(&holder);
    // Inject the dealer with the DEFAULT attestation status (NotProvided).
    holder.test_inject_peer(keep_frost_net::Peer::new(dealer_pubkey, 1));

    let mut rx = holder.subscribe();
    let result = holder.test_handle_oprf_enroll(dealer_pubkey, payload).await;
    assert!(
        matches!(result, Err(keep_frost_net::FrostNetError::UntrustedPeer(_))),
        "an unattested dealer must be rejected with UntrustedPeer, got {result:?}"
    );
    assert!(
        rx.try_recv().is_err(),
        "no OprfShareReceived may be emitted for a rejected unattested dealer"
    );
}

/// With a designated dealer pinned, an enrollment from a different index is refused even when the
/// sender is attested (defense in depth against a compromised-but-attested group member).
#[tokio::test]
async fn test_oprf_enroll_rejects_non_designated_dealer() {
    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-oprf-enroll-pin").unwrap();
    let _ = shares.remove(0); // id 1
    let holder_share = shares.remove(0); // id 2 = holder

    let mut holder = KfpNode::new(holder_share, vec![relay])
        .await
        .expect("holder");
    // Pin the designated dealer to index 2; the enrollment below arrives from index 1.
    holder.set_expected_oprf_dealer(2);

    let (dealer_pubkey, payload) = make_oprf_enroll(&holder); // dealer_index = 1
    holder.test_inject_peer(keep_frost_net::Peer::new(dealer_pubkey, 1));
    // Attest the sender, so the pin (not attestation) is what rejects it.
    holder.test_set_peer_attestation(1, keep_frost_net::AttestationStatus::Verified);

    let mut rx = holder.subscribe();
    let result = holder.test_handle_oprf_enroll(dealer_pubkey, payload).await;
    assert!(
        matches!(result, Err(keep_frost_net::FrostNetError::UntrustedPeer(_))),
        "a non-designated dealer must be rejected even when attested, got {result:?}"
    );
    assert!(
        rx.try_recv().is_err(),
        "no OprfShareReceived may be emitted for a non-designated dealer"
    );
}

/// Durable custody is fail-closed: if a subscriber takes the seal-ack sender but drops it without
/// confirming a seal, the holder withholds the ack rather than confirm custody it did not take.
/// This drives the `Ok(Err(_))` arm directly (the dropped sender resolves the receiver to Err),
/// distinct from the timeout arm that fires when no subscriber touches the sender at all.
#[tokio::test]
async fn test_oprf_enroll_withholds_ack_when_seal_sender_dropped() {
    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-oprf-enroll-seal-drop").unwrap();
    let _ = shares.remove(0); // id 1 = dealer
    let holder_share = shares.remove(0); // id 2 = holder

    let holder = KfpNode::new(holder_share, vec![relay])
        .await
        .expect("holder");

    let (dealer_pubkey, payload) = make_oprf_enroll(&holder); // dealer_index = 1
                                                              // Pin the dealer (fail-closed default refuses enrollment with no pin), inject and attest it, so
                                                              // every gate passes and the handler reaches the seal step.
    let mut holder = holder;
    holder.set_expected_oprf_dealer(1);
    holder.test_inject_peer(keep_frost_net::Peer::new(dealer_pubkey, 1));
    holder.test_set_peer_attestation(1, keep_frost_net::AttestationStatus::Verified);

    let holder = std::sync::Arc::new(holder);
    let mut rx = holder.subscribe();
    let h = std::sync::Arc::clone(&holder);
    let handle =
        tokio::spawn(async move { h.test_handle_oprf_enroll(dealer_pubkey, payload).await });

    // Take the seal sender out of the shared Option and drop it without confirming a seal. take()
    // moves the sender out, so the broadcast ring buffer's retained clone no longer keeps it alive
    // and the holder's receiver resolves to Err. Bounded so the test cannot hang.
    let took = timeout(Duration::from_secs(10), async {
        loop {
            match rx.recv().await {
                Ok(KfpNodeEvent::OprfShareReceived { seal_ack, .. }) => {
                    let _ = seal_ack.lock().unwrap().take();
                    return true;
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(_) => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        took,
        "handler must emit OprfShareReceived so a subscriber can take custody"
    );

    let result = timeout(Duration::from_secs(20), handle)
        .await
        .expect("handler did not return in time")
        .expect("handler task panicked");
    match result {
        Err(keep_frost_net::FrostNetError::Session(msg)) => {
            assert!(
                msg.contains("No subscriber sealed"),
                "expected the dropped-seal failure, got: {msg}"
            );
        }
        other => panic!("dropping the seal sender must withhold the ack, got {other:?}"),
    }
}

/// Durable custody: with the share addressed, attested, and pinned but NO subscriber to take
/// custody (seal) it, `handle_oprf_enroll` returns Err and sends no ack. A non-empty subscriber
/// count is not enough; here there are zero receivers, so the broadcast send fails outright.
#[tokio::test]
async fn test_oprf_enroll_no_subscriber_refuses_ack() {
    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-oprf-enroll-no-sub").unwrap();
    let _ = shares.remove(0); // id 1
    let holder_share = shares.remove(0); // id 2 = holder

    let mut holder = KfpNode::new(holder_share, vec![relay])
        .await
        .expect("holder");
    holder.set_expected_oprf_dealer(1);

    let (dealer_pubkey, payload) = make_oprf_enroll(&holder);
    holder.test_inject_peer(keep_frost_net::Peer::new(dealer_pubkey, 1));
    holder.test_set_peer_attestation(1, keep_frost_net::AttestationStatus::Verified);

    // Deliberately do NOT subscribe: nothing will take custody of the share.
    let result = holder.test_handle_oprf_enroll(dealer_pubkey, payload).await;
    assert!(
        matches!(result, Err(keep_frost_net::FrostNetError::Session(_))),
        "with no subscriber to seal the share the holder must refuse to ack, got {result:?}"
    );
}

/// Replay window: an enrollment whose `created_at` is far in the past is rejected with
/// `ReplayDetected` at the replay gate, before any custody is taken.
#[tokio::test]
async fn test_oprf_enroll_rejects_stale_created_at() {
    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-oprf-enroll-stale").unwrap();
    let _ = shares.remove(0); // id 1
    let holder_share = shares.remove(0); // id 2 = holder

    let holder = KfpNode::new(holder_share, vec![relay])
        .await
        .expect("holder");

    let (dealer_pubkey, mut payload) = make_oprf_enroll(&holder);
    payload.created_at = nostr_sdk::Timestamp::now().as_secs() - 400;

    let mut rx = holder.subscribe();
    let result = holder.test_handle_oprf_enroll(dealer_pubkey, payload).await;
    assert!(
        matches!(
            result,
            Err(keep_frost_net::FrostNetError::ReplayDetected(_))
        ),
        "a stale enrollment must be rejected with ReplayDetected, got {result:?}"
    );
    assert!(
        rx.try_recv().is_err(),
        "no OprfShareReceived may be emitted for a replayed enrollment"
    );
}

/// Build a dealer node (FROST id 1) over a mock relay. The relay handle is returned so the caller
/// keeps it alive for the node's lifetime.
async fn make_dealer_node() -> (KfpNode, MockRelay) {
    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();
    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-oprf-distribute").unwrap();
    let share1 = shares.remove(0); // id 1 = dealer
    let node = KfpNode::new(share1, vec![relay])
        .await
        .expect("dealer node");
    (node, mock_relay)
}

/// Dealer-side `distribute_oprf_shares` rejects every malformed round up front, before any share
/// leaves the box: bad threshold/total bounds, empty input, the dealer's own index, a zero index,
/// a malformed share, and an unannounced target.
#[tokio::test]
async fn test_distribute_oprf_shares_early_validations() {
    use zeroize::Zeroizing;

    let (node, _relay) = make_dealer_node().await;
    let valid = || {
        Zeroizing::new(
            keep_core::oprf::threshold::serialize_key_share(&split_oprf_key_2of3()[1]).to_vec(),
        )
    };

    // Empty input.
    assert!(node.distribute_oprf_shares(vec![], 2, 3).await.is_err());

    // threshold < 2.
    assert!(node
        .distribute_oprf_shares(vec![(2u16, valid())], 1, 3)
        .await
        .is_err());

    // threshold > total.
    assert!(node
        .distribute_oprf_shares(vec![(2u16, valid())], 3, 2)
        .await
        .is_err());

    // total exceeds MAX_PARTICIPANTS.
    assert!(node
        .distribute_oprf_shares(vec![(2u16, valid())], 2, 256)
        .await
        .is_err());

    // Zero target index.
    assert!(node
        .distribute_oprf_shares(vec![(0u16, valid())], 2, 3)
        .await
        .is_err());

    // The dealer's own index (1) must never be distributed.
    assert!(node
        .distribute_oprf_shares(vec![(1u16, valid())], 2, 3)
        .await
        .is_err());

    // A malformed share aborts the whole round.
    assert!(node
        .distribute_oprf_shares(vec![(2u16, Zeroizing::new(vec![0u8; 8]))], 2, 3)
        .await
        .is_err());

    // An unannounced target peer.
    let result = node
        .distribute_oprf_shares(vec![(2u16, valid())], 2, 3)
        .await;
    assert!(
        matches!(result, Err(keep_frost_net::FrostNetError::UntrustedPeer(_))),
        "an unannounced target must be rejected with UntrustedPeer, got {result:?}"
    );
}

/// A duplicate target index is rejected even when the peer is announced and sendable.
#[tokio::test]
async fn test_distribute_oprf_shares_rejects_duplicate_target() {
    use zeroize::Zeroizing;

    let (node, _relay) = make_dealer_node().await;
    let peer2 = nostr_sdk::Keys::generate().public_key();
    node.test_inject_peer(keep_frost_net::Peer::new(peer2, 2));

    let valid = || {
        Zeroizing::new(
            keep_core::oprf::threshold::serialize_key_share(&split_oprf_key_2of3()[1]).to_vec(),
        )
    };

    let result = node
        .distribute_oprf_shares(vec![(2u16, valid()), (2u16, valid())], 2, 3)
        .await;
    assert!(result.is_err(), "a duplicate target index must be rejected");
}

/// Cross-attestation downgrade guard: on a node that REQUIRES attestation (an enclave PCR policy
/// set, but no TPM policy), a peer presenting unappraisable TPM-quote evidence must be appraised
/// `Failed`, NOT `NotConfigured` (which would admit it, more permissively than presenting no
/// evidence). A node with no attestation policy at all stays permissive (`NotConfigured`).
#[tokio::test]
async fn test_unappraisable_tpm_evidence_is_failed_not_downgraded() {
    use keep_frost_net::{AttestationStatus, ExpectedPcrs, TpmQuoteEvidence};

    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-tpm-downgrade").unwrap();
    let _ = shares.remove(0);
    let required_share = shares.remove(0); // id 2
    let permissive_share = shares.remove(0); // id 3

    // Junk evidence that nonetheless satisfies `validate()`.
    let junk = TpmQuoteEvidence {
        attest: vec![0xff; 16],
        signature: vec![0u8; 64],
        ak_sec1: {
            let mut v = vec![0u8; 65];
            v[0] = 0x04;
            v
        },
        pcr_values: vec!["00".repeat(32)],
    };
    let payload = AnnouncePayload::new([1u8; 32], 2, [2u8; 33], [3u8; 64], 1_700_000_000)
        .with_tpm_attestation(junk);

    // A node that requires attestation (enclave PCRs) but has NO TPM policy: the cross-type
    // evidence is unappraisable -> Failed (the downgrade is refused).
    let mut required = KfpNode::new(required_share, vec![relay.clone()])
        .await
        .expect("required node");
    required.set_expected_pcrs(ExpectedPcrs::new([1u8; 48], [2u8; 48], [3u8; 48]));
    let status = required.test_attestation_status(&payload);
    assert!(
        matches!(status, AttestationStatus::Failed(_)),
        "unappraisable TPM evidence on an attestation-requiring node must be Failed, got {status:?}"
    );

    // A node with no attestation policy at all stays permissive.
    let permissive = KfpNode::new(permissive_share, vec![relay])
        .await
        .expect("permissive node");
    assert_eq!(
        permissive.test_attestation_status(&payload),
        AttestationStatus::NotConfigured,
        "a node enforcing no attestation must report NotConfigured, not reject"
    );
}

/// A test [`AnnounceAttestor`] that records the nonces it is asked to quote and
/// returns either canned evidence or a failure, without needing a TPM.
struct RecordingAttestor {
    nonces: std::sync::Arc<std::sync::Mutex<Vec<[u8; 32]>>>,
    succeed: bool,
}

impl keep_frost_net::AnnounceAttestor for RecordingAttestor {
    fn ak_sec1(&self) -> Vec<u8> {
        let mut v = vec![0u8; 65];
        v[0] = 0x04;
        v
    }

    fn request_quote(
        &self,
        nonce: [u8; 32],
    ) -> tokio::sync::oneshot::Receiver<keep_frost_net::Result<keep_frost_net::TpmQuoteEvidence>>
    {
        self.nonces.lock().unwrap().push(nonce);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let result = if self.succeed {
            Ok(keep_frost_net::TpmQuoteEvidence {
                attest: vec![0xff; 16],
                signature: vec![0u8; 64],
                ak_sec1: self.ak_sec1(),
                pcr_values: vec!["00".repeat(32)],
            })
        } else {
            Err(keep_frost_net::FrostNetError::Attestation(
                "mock quote failure".into(),
            ))
        };
        let _ = tx.send(result);
        rx
    }
}

/// The announce path must bind the TPM quote's nonce to THIS announce: the nonce
/// the attestor is asked to quote must be `derive_announce_attestation_nonce`
/// over the node's group, share index, and the announce's own timestamp.
#[tokio::test]
async fn test_announce_binds_tpm_quote_nonce_to_announce() {
    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-announce-quote").unwrap();
    let share = shares.remove(0);

    let nonces = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut node = KfpNode::new(share, vec![relay]).await.expect("node");
    node.set_announce_attestor(std::sync::Arc::new(RecordingAttestor {
        nonces: nonces.clone(),
        succeed: true,
    }));

    let group = *node.group_pubkey();
    let idx = node.share_index();

    let t0 = chrono::Utc::now().timestamp() as u64;
    node.announce().await.expect("announce");
    let t1 = chrono::Utc::now().timestamp() as u64;

    let recorded = nonces.lock().unwrap().clone();
    assert_eq!(
        recorded.len(),
        1,
        "the attestor must be asked for exactly one quote per announce"
    );
    // The exact second is the node's own `Timestamp::now()`; it lies within the
    // bracket we measured around the call.
    let candidates: Vec<[u8; 32]> = (t0..=t1 + 1)
        .map(|ts| keep_frost_net::derive_announce_attestation_nonce(&group, idx, ts))
        .collect();
    assert!(
        candidates.contains(&recorded[0]),
        "the quote nonce must be bound to the announce's group, share, and timestamp"
    );
}

/// If a node is configured to attest but quoting fails, the announce must fail
/// closed (a configured-but-unattested announce would be rejected by any peer
/// that pins a policy, so emitting it is pointless and masks the failure).
#[tokio::test]
async fn test_announce_fails_closed_when_quote_fails() {
    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-announce-quote-fail").unwrap();
    let share = shares.remove(0);

    let nonces = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut node = KfpNode::new(share, vec![relay]).await.expect("node");
    node.set_announce_attestor(std::sync::Arc::new(RecordingAttestor {
        nonces,
        succeed: false,
    }));

    let err = node
        .announce()
        .await
        .expect_err("announce must fail closed when the configured attestor cannot quote");
    assert!(
        matches!(err, keep_frost_net::FrostNetError::Attestation(_)),
        "the failure must be the attestation fail-closed path, got {err:?}"
    );
}

// ===== keep-4zhi: end-to-end threshold-OPRF unlock with REAL attestation =====
//
// The unlock/enroll tests above inject `Verified` via `test_set_peer_attestation`.
// These instead drive attestation through the real path: the box attaches a TPM
// quote to its announce, and the holder appraises it against a pinned policy,
// reaching `Verified` on its own before answering the box's OPRF evaluation.
// This is the protocol capstone for the 3-node deployment.

use keep_frost_net::test_support::{build_signed_quote, one_pcr_selection};

/// A test announce attestor that signs a valid quote for each announce nonce,
/// the in-process stand-in for `TpmQuoteService` (proven against swtpm elsewhere).
struct ValidQuoteAttestor {
    sk: p256::ecdsa::SigningKey,
    ak_sec1: Vec<u8>,
    pcr_value: [u8; 32],
}

impl ValidQuoteAttestor {
    fn new() -> Self {
        let sk = p256::ecdsa::SigningKey::from_slice(&[0x77u8; 32]).unwrap();
        let ak_sec1 = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self {
            sk,
            ak_sec1,
            pcr_value: [0x11u8; 32],
        }
    }

    /// The verifier policy a peer pins to verify quotes from this attestor.
    fn policy(&self, box_index: u16) -> keep_frost_net::TpmAttestationPolicy {
        let mut pinned = std::collections::HashMap::new();
        pinned.insert(box_index, self.ak_sec1.clone());
        keep_frost_net::TpmAttestationPolicy::new(one_pcr_selection(), vec![self.pcr_value], pinned)
    }
}

impl keep_frost_net::AnnounceAttestor for ValidQuoteAttestor {
    fn ak_sec1(&self) -> Vec<u8> {
        self.ak_sec1.clone()
    }
    fn request_quote(
        &self,
        nonce: [u8; 32],
    ) -> tokio::sync::oneshot::Receiver<keep_frost_net::Result<keep_frost_net::TpmQuoteEvidence>>
    {
        let (attest, signature) =
            build_signed_quote(&nonce, &one_pcr_selection(), &self.pcr_value, &self.sk);
        let ev = keep_frost_net::TpmQuoteEvidence {
            attest,
            signature,
            ak_sec1: self.ak_sec1.clone(),
            pcr_values: vec![hex::encode(self.pcr_value)],
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = tx.send(Ok(ev));
        rx
    }
}

/// Happy path: the box attaches a real TPM quote to its announce; the holder
/// pins the box's AK and reaches `Verified` on its own (no injection), then
/// answers the box's evaluation. A 2-of-3 unlock derives the 32-byte key.
#[tokio::test]
async fn test_oprf_unlock_with_real_tpm_attestation_2of3() {
    use std::sync::Arc;

    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-oprf-attest-ok").unwrap();
    let share1 = shares.remove(0); // box id 1
    let share2 = shares.remove(0); // holder id 2
    let oprf = split_oprf_key_2of3();

    let attestor = Arc::new(ValidQuoteAttestor::new());
    let policy = attestor.policy(1);

    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("box");
    node1.set_oprf_key_share(oprf[0]);
    node1.set_announce_attestor(attestor); // box self-attests on every announce

    let mut node2 = KfpNode::new(share2, vec![relay]).await.expect("holder");
    node2.set_oprf_key_share(oprf[1]);
    node2.set_hooks(Arc::new(ApproveOprfHooks));
    node2.set_tpm_attestation_policy(policy); // holder verifies the box

    let mut rx1 = node1.subscribe();
    let mut rx2 = node2.subscribe();
    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();
    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let r1 = Arc::clone(&node1);
    let r2 = Arc::clone(&node2);
    let h1 = tokio::spawn(async move {
        let _ = r1.run().await;
    });
    let h2 = tokio::spawn(async move {
        let _ = r2.run().await;
    });

    // Mutual discovery: the holder discovering the box means it processed AND
    // verified the box's quote, so the box is `Verified` with no injection.
    let (mut n1, mut n2) = (0u32, 0u32);
    let discovery = timeout(Duration::from_secs(45), async {
        loop {
            // Match the full `recv()` result: a closed stream (a crashed node)
            // must surface as a legible error, not a `select!` "all branches
            // disabled" panic that hides which node died. A lagged stream is
            // transient and ignored, matching the original tolerant behaviour.
            use tokio::sync::broadcast::error::RecvError;
            tokio::select! {
                ev = rx1.recv() => match ev {
                    Ok(KfpNodeEvent::PeerDiscovered { .. }) => n1 += 1,
                    Ok(_) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => return Err("box event stream closed".to_string()),
                },
                ev = rx2.recv() => match ev {
                    Ok(KfpNodeEvent::PeerDiscovered { .. }) => n2 += 1,
                    Ok(_) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => return Err("holder event stream closed".to_string()),
                },
            }
            if n1 >= 1 && n2 >= 1 {
                return Ok(());
            }
        }
    })
    .await;
    let discovery_failure = match discovery {
        Ok(Ok(())) => None,
        Ok(Err(msg)) => Some(msg),
        Err(_) => Some(format!("discovery timed out: n1={n1}, n2={n2}")),
    };
    if let Some(msg) = discovery_failure {
        graceful_shutdown(shutdown1, h1).await;
        graceful_shutdown(shutdown2, h2).await;
        panic!("{msg}");
    }

    let result = timeout(
        Duration::from_secs(45),
        node1.request_oprf_unlock(OPRF_INPUT, "vault0", 1),
    )
    .await;
    graceful_shutdown(shutdown1, h1).await;
    graceful_shutdown(shutdown2, h2).await;
    match result {
        Ok(Ok(key)) => assert_eq!(key.len(), 32, "derived LUKS key must be 32 bytes"),
        Ok(Err(e)) => panic!("unlock failed despite valid attestation: {e}"),
        Err(_) => panic!("unlock timed out despite valid attestation"),
    }
}

/// Negative: the box attaches NO quote, so the holder (which requires
/// attestation) refuses to answer. With the holder out, the box is alone below
/// threshold and the unlock cannot complete: the gate, reached naturally,
/// prevents a single share from opening the volume.
#[tokio::test]
async fn test_oprf_unlock_blocked_when_box_unattested() {
    use std::sync::Arc;

    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-oprf-attest-blocked").unwrap();
    let share1 = shares.remove(0); // box id 1
    let share2 = shares.remove(0); // holder id 2
    let oprf = split_oprf_key_2of3();

    // The holder pins a policy but the box presents NO attestor, so it never
    // reaches Verified at the holder.
    let policy = ValidQuoteAttestor::new().policy(1);

    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("box");
    node1.set_oprf_key_share(oprf[0]); // box: no announce attestor

    let mut node2 = KfpNode::new(share2, vec![relay]).await.expect("holder");
    node2.set_oprf_key_share(oprf[1]);
    node2.set_hooks(Arc::new(ApproveOprfHooks));
    node2.set_tpm_attestation_policy(policy);

    let mut rx1 = node1.subscribe();
    let mut rx2 = node2.subscribe();
    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();
    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let r1 = Arc::clone(&node1);
    let r2 = Arc::clone(&node2);
    let h1 = tokio::spawn(async move {
        let _ = r1.run().await;
    });
    let h2 = tokio::spawn(async move {
        let _ = r2.run().await;
    });

    // The box (no policy) discovers the holder; the holder rejects the box's
    // unattested announce, so we only wait on the box side.
    let discovered = timeout(Duration::from_secs(45), async {
        loop {
            if let Ok(KfpNodeEvent::PeerDiscovered { .. }) = rx1.recv().await {
                return;
            }
        }
    })
    .await;
    if discovered.is_err() {
        graceful_shutdown(shutdown1, h1).await;
        graceful_shutdown(shutdown2, h2).await;
        panic!("box never discovered the holder");
    }

    // Watch the holder's stream: it must NEVER discover the unattested box
    // (share index 1). That is the gate firing, and it attributes the blocked
    // unlock to attestation rejection rather than to an incidental timeout or a
    // dropped relay message. The flag is read after the unlock window closes.
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::broadcast::error::RecvError;
    let holder_admitted_box = Arc::new(AtomicBool::new(false));
    // A lagged stream means a dropped event could have hidden a bypass, so we
    // fail safe rather than let the assertion pass on incomplete evidence.
    let watcher_lagged = Arc::new(AtomicBool::new(false));
    let admitted = Arc::clone(&holder_admitted_box);
    let lagged = Arc::clone(&watcher_lagged);
    let watcher = tokio::spawn(async move {
        loop {
            match rx2.recv().await {
                Ok(KfpNodeEvent::PeerDiscovered { share_index: 1, .. }) => {
                    admitted.store(true, Ordering::SeqCst);
                }
                Ok(_) => {}
                Err(RecvError::Lagged(_)) => lagged.store(true, Ordering::SeqCst),
                Err(RecvError::Closed) => break,
            }
        }
    });

    // The holder never sends a partial, so the box stays below threshold; this
    // window only needs to be long enough to be sure it will not succeed.
    let result = timeout(
        Duration::from_secs(12),
        node1.request_oprf_unlock(OPRF_INPUT, "vault0", 1),
    )
    .await;
    watcher.abort();
    let _ = watcher.await; // join the aborted task so its flag write is visible
    graceful_shutdown(shutdown1, h1).await;
    graceful_shutdown(shutdown2, h2).await;
    assert!(
        !watcher_lagged.load(Ordering::SeqCst),
        "holder event watcher lagged: cannot prove the attestation gate held"
    );
    assert!(
        !holder_admitted_box.load(Ordering::SeqCst),
        "holder must never discover the unattested box: the attestation gate was bypassed"
    );
    assert!(
        !matches!(result, Ok(Ok(_))),
        "unlock must NOT succeed when the box is unattested (gate bypassed)"
    );
}

/// A valid attestor whose quote arrives after a delay (still within the
/// announce timeout), to exercise the slow-quote path. `quote_starts` counts
/// each `request_quote` so a test can wait until a particular quote (e.g. the
/// reciprocal one) is genuinely in flight before probing.
struct SlowQuoteAttestor {
    inner: ValidQuoteAttestor,
    delay: Duration,
    quote_starts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl keep_frost_net::AnnounceAttestor for SlowQuoteAttestor {
    fn ak_sec1(&self) -> Vec<u8> {
        self.inner.ak_sec1.clone()
    }
    fn request_quote(
        &self,
        nonce: [u8; 32],
    ) -> tokio::sync::oneshot::Receiver<keep_frost_net::Result<keep_frost_net::TpmQuoteEvidence>>
    {
        self.quote_starts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (attest, signature) = build_signed_quote(
            &nonce,
            &one_pcr_selection(),
            &self.inner.pcr_value,
            &self.inner.sk,
        );
        let ev = keep_frost_net::TpmQuoteEvidence {
            attest,
            signature,
            ak_sec1: self.inner.ak_sec1.clone(),
            pcr_values: vec![hex::encode(self.inner.pcr_value)],
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let delay = self.delay;
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = tx.send(Ok(ev));
        });
        rx
    }
}

/// Regression test for keep-w7t2: a slow TPM quote must not stall the node's
/// event loop. node1 has a valid but slow (4.5s, under the 5s announce timeout)
/// attestor; after it discovers node2 it spawns a slow reciprocal announce. Its
/// loop must keep serving, so a liveness ping still gets a prompt pong well
/// inside the quote window. (Passes for the spawned-announce fix; the old
/// inline-await code would leave node1 unresponsive for the whole quote.)
#[tokio::test]
async fn test_slow_announce_quote_does_not_block_event_loop() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-slow-announce").unwrap();
    let share1 = shares.remove(0); // node1: slow attestor
    let share2 = shares.remove(0); // node2: normal

    let quote_starts = Arc::new(AtomicUsize::new(0));
    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("node1");
    node1.set_announce_attestor(Arc::new(SlowQuoteAttestor {
        inner: ValidQuoteAttestor::new(),
        delay: Duration::from_millis(4500),
        quote_starts: Arc::clone(&quote_starts),
    }));
    let mut node2 = KfpNode::new(share2, vec![relay]).await.expect("node2");

    let mut rx2 = node2.subscribe();
    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();
    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let r1 = Arc::clone(&node1);
    let r2 = Arc::clone(&node2);
    let h1 = tokio::spawn(async move {
        let _ = r1.run().await;
    });
    let h2 = tokio::spawn(async move {
        let _ = r2.run().await;
    });

    // node1's startup announce is sync and waits for its slow quote, so node2
    // discovers it only after that; node1 then spawns a slow reciprocal announce
    // on seeing node2. The generous timeout covers the ~4.5s startup quote.
    let discovered = timeout(Duration::from_secs(45), async {
        loop {
            if let Ok(KfpNodeEvent::PeerDiscovered { share_index, .. }) = rx2.recv().await {
                if share_index == 1 {
                    return;
                }
            }
        }
    })
    .await;
    if discovered.is_err() {
        graceful_shutdown(shutdown1, h1).await;
        graceful_shutdown(shutdown2, h2).await;
        panic!("node2 never discovered node1");
    }

    // Wait until node1's RECIPROCAL quote is actually in flight before probing:
    // the first quote is its startup announce; the second is the reciprocal it
    // spawns on seeing node2. Probing only after `quote_starts >= 2` guarantees a
    // slow announce is genuinely outstanding (otherwise the ping could race ahead
    // of the reciprocal and pass even on the old blocking code).
    let reciprocal_started = timeout(Duration::from_secs(10), async {
        while quote_starts.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    if reciprocal_started.is_err() {
        graceful_shutdown(shutdown1, h1).await;
        graceful_shutdown(shutdown2, h2).await;
        panic!("node1's reciprocal announce quote never started");
    }

    // node1 is mid slow reciprocal announce now; its loop must still pong within
    // a window shorter than the 4.5s quote, proving it is not blocked on it.
    let health = timeout(
        Duration::from_secs(10),
        node2.health_check(Duration::from_secs(3)),
    )
    .await
    .expect("health_check did not return")
    .expect("health_check error");

    graceful_shutdown(shutdown1, h1).await;
    graceful_shutdown(shutdown2, h2).await;

    assert!(
        health.responsive.contains(&1),
        "node1 must answer a ping while a slow announce is in flight (responsive={:?})",
        health.responsive
    );
}

/// A valid attestor with a configurable quote delay that records both the peak
/// number of concurrent quotes and the TOTAL number of quotes started. The
/// single-flight test asserts on the total: while one background announce is
/// awaiting its quote, further reciprocal announces must be suppressed (not
/// merely serialized), so exactly one reciprocal quote is issued.
struct ConcurrentQuoteProbe {
    inner: ValidQuoteAttestor,
    delay: Duration,
    in_flight: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    max_in_flight: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    total_starts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl keep_frost_net::AnnounceAttestor for ConcurrentQuoteProbe {
    fn ak_sec1(&self) -> Vec<u8> {
        self.inner.ak_sec1.clone()
    }
    fn request_quote(
        &self,
        nonce: [u8; 32],
    ) -> tokio::sync::oneshot::Receiver<keep_frost_net::Result<keep_frost_net::TpmQuoteEvidence>>
    {
        use std::sync::atomic::Ordering;
        self.total_starts.fetch_add(1, Ordering::SeqCst);
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        let (attest, signature) = build_signed_quote(
            &nonce,
            &one_pcr_selection(),
            &self.inner.pcr_value,
            &self.inner.sk,
        );
        let ev = keep_frost_net::TpmQuoteEvidence {
            attest,
            signature,
            ak_sec1: self.inner.ak_sec1.clone(),
            pcr_values: vec![hex::encode(self.inner.pcr_value)],
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let delay = self.delay;
        let in_flight = std::sync::Arc::clone(&self.in_flight);
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = tx.send(Ok(ev));
            in_flight.fetch_sub(1, Ordering::SeqCst);
        });
        rx
    }
}

/// Single-flight regression: while one slow background announce is in flight, a
/// second `spawn_announce` must be skipped rather than starting a concurrent
/// quote. node1 carries a slow attestor that records the peak number of in-flight
/// quotes; node2 and node3 come online only after node1 is past its synchronous
/// startup announce, so the reciprocal announces node1 attempts on discovering
/// them fall inside one slow-quote window. The recorded peak must stay at one.
#[tokio::test]
async fn test_single_flight_suppresses_concurrent_announce_quotes() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let mock_relay = MockRelay::run().await.expect("relay");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-single-flight").unwrap();
    let share1 = shares.remove(0);
    let share2 = shares.remove(0);
    let share3 = shares.remove(0);

    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let total_starts = Arc::new(AtomicUsize::new(0));

    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("node1");
    node1.set_announce_attestor(Arc::new(ConcurrentQuoteProbe {
        inner: ValidQuoteAttestor::new(),
        delay: Duration::from_millis(4500),
        in_flight: Arc::clone(&in_flight),
        max_in_flight: Arc::clone(&max_in_flight),
        total_starts: Arc::clone(&total_starts),
    }));

    let mut rx1 = node1.subscribe();
    let shutdown1 = node1.take_shutdown_handle();
    let node1 = Arc::new(node1);
    let r1 = Arc::clone(&node1);
    let h1 = tokio::spawn(async move {
        let _ = r1.run().await;
    });

    // Hold node2/node3 back until node1 is past its ~4.5s synchronous startup
    // announce and into its loop, so the peers are discovered (and reciprocated)
    // only while a single slow background announce can already be in flight. This
    // keeps the startup announce from overlapping a reciprocal spawn, isolating
    // the single-flight guard as the only thing bounding concurrency.
    tokio::time::sleep(Duration::from_secs(7)).await;

    let mut node2 = KfpNode::new(share2, vec![relay.clone()])
        .await
        .expect("node2");
    let mut node3 = KfpNode::new(share3, vec![relay]).await.expect("node3");
    let shutdown2 = node2.take_shutdown_handle();
    let shutdown3 = node3.take_shutdown_handle();
    let node2 = Arc::new(node2);
    let node3 = Arc::new(node3);
    let r2 = Arc::clone(&node2);
    let r3 = Arc::clone(&node3);
    let h2 = tokio::spawn(async move {
        let _ = r2.run().await;
    });
    let h3 = tokio::spawn(async move {
        let _ = r3.run().await;
    });

    // Wait until node1 has discovered both peers; each new-peer discovery drives a
    // reciprocal spawn_announce, so this guarantees the suppression path is hit.
    let mut seen2 = false;
    let mut seen3 = false;
    let discovered = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(KfpNodeEvent::PeerDiscovered { share_index, .. }) = rx1.recv().await {
                if share_index == 2 {
                    seen2 = true;
                }
                if share_index == 3 {
                    seen3 = true;
                }
                if seen2 && seen3 {
                    return;
                }
            }
        }
    })
    .await;

    // Give the reciprocal spawns time to reach request_quote before sampling.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let peak = max_in_flight.load(Ordering::SeqCst);
    let total = total_starts.load(Ordering::SeqCst);

    graceful_shutdown(shutdown1, h1).await;
    graceful_shutdown(shutdown2, h2).await;
    graceful_shutdown(shutdown3, h3).await;

    assert!(
        discovered.is_ok(),
        "node1 must discover both peers to exercise the suppression path"
    );
    assert!(
        peak <= 1,
        "single-flight must keep at most one background announce quote in flight (peak={peak})"
    );
    // The startup announce issues exactly one quote; discovering two peers within
    // one slow-quote window must add exactly one reciprocal quote (the second is
    // suppressed, not serialized). Total == 2 verifies suppression, which `peak`
    // alone cannot (two sequential reciprocal quotes would also keep peak at 1).
    assert_eq!(
        total, 2,
        "expected 1 startup + 1 reciprocal quote (second reciprocal suppressed), got {total}"
    );
}

/// #487 PR3: end-to-end multinode signing under a BIP-32 unhardened
/// derivation path. Every co-signer independently computes the composite
/// tweak from the request's `derivation_path`, applies it to its
/// KeyPackage before round1/round2, and aggregates under the tweaked
/// PublicKeyPackage. The resulting BIP-340 signature MUST verify under the
/// derived child pubkey and MUST NOT verify under the parent group pubkey.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_full_signing_flow_at_derivation_path() {
    use std::sync::Arc;

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay = mock_relay.url().await.to_string();

    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, _pubkey_pkg) = dealer.generate("test-bip32-signing").unwrap();
    let group_pubkey: [u8; 32] = *shares[0].group_pubkey();

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

    // 32-byte digest so it fits `Message::from_digest_slice` for BIP-340.
    let message = [0x33u8; 32].to_vec();
    let derivation_path = vec![0u32, 5u32];

    let sign_result = timeout(Duration::from_secs(60), async {
        node3
            .request_signature_at_path(message.clone(), "raw", None, derivation_path.clone())
            .await
    })
    .await;

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown2, node2_handle).await;
    graceful_shutdown(shutdown3, node3_handle).await;

    let sig_bytes = match sign_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => panic!("BIP-32 signing failed: {e:?}"),
        Err(_) => panic!("BIP-32 signing timed out after 60 seconds"),
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

/// Migration-sweep responder-side guards exercised through the real node
/// methods and the real `DualDescriptorLookup.successor_for` wiring (#551,
/// #414/#502). Deterministic: no relay run loop or peer discovery is needed
/// because every assertion here fails (or passes) before any broadcast.
///
///   - `validate_migration_sweep_destination` refuses a sweep paying an attacker
///     script, and (the core of the #414 gate) refuses one paying the superseded
///     OLD `/0/0` address, while accepting the re-derived NEW `/0/0` address. OLD
///     and NEW are genuinely distinct descriptors, so this proves the successor
///     chain resolves to NEW rather than silently reusing OLD.
///   - `request_descriptor_migration_sweep` refuses a fee above 1/4 of the swept
///     input value (#502) and a sweep whose `old_recovery` does not match the
///     descriptor identified by `old_descriptor_hash`.
#[tokio::test]
async fn test_migration_sweep_destination_and_fee_guards() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin::{Network, OutPoint};
    use keep_bitcoin::recovery::{
        RecoveryConfig, RecoveryTier as BitcoinRecoveryTier, SpendingTier,
    };
    use keep_bitcoin::{DescriptorExport, SweepUtxo};
    use keep_frost_net::{DescriptorSession, FinalizedDescriptor, WalletPolicy};

    let mock_relay = MockRelay::run().await.expect("MockRelay start");
    let relay = mock_relay.url().await.to_string();

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-sweep-guards").unwrap();
    let share1 = shares.remove(0);
    let share2 = shares.remove(0);

    let mut node1 = KfpNode::new(share1, vec![relay.clone()])
        .await
        .expect("node1 create");
    let node2 = KfpNode::new(share2, vec![relay])
        .await
        .expect("node2 create");
    let group_pubkey = *node1.group_pubkey();

    let secp = Secp256k1::new();
    let responder_xpriv =
        bitcoin::bip32::Xpriv::new_master(Network::Signet, &[7u8; 32]).expect("xpriv");
    let responder_xpub = bitcoin::bip32::Xpub::from_priv(&secp, &responder_xpriv);
    let responder_xpub_str = responder_xpub.to_string();
    let responder_fp = responder_xpub
        .fingerprint()
        .to_string()
        .to_ascii_lowercase();
    let responder_xonly_bytes = responder_xpub.to_x_only_pub().serialize();

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

    // The NEW descriptor must derive a GENUINELY distinct /0/0 address from OLD,
    // so the destination-rebind gate (#414) is actually exercised. A different
    // recovery key yields a different taproot output, hence a different external
    // descriptor and a different /0/0 script. Without this, OLD and NEW would
    // share an address and a regression that re-derived the destination from the
    // OLD/session descriptor instead of the resolved NEW successor would pass
    // unnoticed.
    let new_responder_xpub = bitcoin::bip32::Xpub::from_priv(
        &secp,
        &bitcoin::bip32::Xpriv::new_master(Network::Signet, &[9u8; 32]).expect("new xpriv"),
    );
    let new_recovery_config = RecoveryConfig {
        primary: SpendingTier {
            keys: vec![group_pubkey],
            threshold: 1,
        },
        recovery_tiers: vec![BitcoinRecoveryTier {
            keys: vec![new_responder_xpub.to_x_only_pub().serialize()],
            threshold: 1,
            timelock_months: 6,
        }],
        network: Network::Signet,
    };
    let new_export = DescriptorExport::from_frost_wallet(
        &group_pubkey,
        Some(&new_recovery_config),
        Network::Signet,
    )
    .expect("new descriptor export");
    let new_external_desc = new_export.external_descriptor().to_string();
    let new_internal_desc = new_export
        .internal_descriptor()
        .expect("new internal descriptor");
    assert_ne!(new_external_desc, external_desc);

    let old_descriptor = keep_core::wallet::WalletDescriptor {
        group_pubkey,
        external_descriptor: external_desc.clone(),
        internal_descriptor: internal_desc.clone(),
        network: "signet".to_string(),
        created_at: 0,
        device_registrations: Vec::new(),
        policy_hash,
        version: 1,
        previous_descriptor_hash: None,
        policy: policy_value.clone(),
    };
    let old_descriptor_hash = old_descriptor.canonical_hash();

    let new_descriptor = keep_core::wallet::WalletDescriptor {
        group_pubkey,
        external_descriptor: new_external_desc.clone(),
        internal_descriptor: new_internal_desc.clone(),
        network: "signet".to_string(),
        created_at: 0,
        device_registrations: Vec::new(),
        policy_hash,
        version: 2,
        previous_descriptor_hash: Some(old_descriptor_hash),
        policy: policy_value,
    };

    let lookup: std::sync::Arc<dyn keep_frost_net::PersistedDescriptorLookup> =
        std::sync::Arc::new(DualDescriptorLookup {
            old: old_descriptor,
            new: new_descriptor,
        });
    node1 = node1.with_descriptor_lookup(lookup.clone());
    let node2 = node2.with_descriptor_lookup(lookup);

    let migration_session_id = [0xAA; 32];
    {
        // The finalized session descriptor must match the NEW lookup entry
        // (same external/internal/policy_hash/version) so the proposer's
        // `find_by_hash` version-link check resolves.
        let finalized = FinalizedDescriptor {
            external: new_external_desc.clone(),
            internal: new_internal_desc.clone(),
            policy_hash,
        };
        let mut policy_v2 = policy.clone();
        policy_v2.version = 2;
        let session = DescriptorSession::test_completed(
            migration_session_id,
            group_pubkey,
            policy_v2,
            "signet".to_string(),
            finalized,
        );
        node1.test_inject_descriptor_session(session);
    }

    // The correctly re-derived NEW /0/0 destination the sweep must pay, and the
    // superseded OLD /0/0 address a correct rebind gate must refuse. These are
    // genuinely distinct scripts (NEW is built from a different recovery key),
    // so paying OLD is a concrete regression the gate has to catch.
    let expected_script =
        keep_bitcoin::descriptor_address_at_index(&new_external_desc, Network::Signet, 0)
            .expect("derive NEW successor address")
            .script_pubkey();
    let old_script = keep_bitcoin::descriptor_address_at_index(&external_desc, Network::Signet, 0)
        .expect("derive OLD address")
        .script_pubkey();
    assert_ne!(old_script, expected_script);

    let one_output_tx = |script: bitcoin::ScriptBuf| bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(50_000),
            script_pubkey: script,
        }],
    };

    // #414: a sweep paying an attacker script (not the re-derived successor) is
    // refused by the real node method resolving the real descriptor chain.
    let attacker_kp = Keypair::from_seckey_slice(&secp, &[0x42; 32]).unwrap();
    let (attacker_xonly, _) = attacker_kp.x_only_public_key();
    let attacker_script = bitcoin::ScriptBuf::new_p2tr(&secp, attacker_xonly, None);
    assert_ne!(attacker_script, expected_script);
    let err = node2
        .validate_migration_sweep_destination(&old_descriptor_hash, &one_output_tx(attacker_script))
        .expect_err("attacker-scripted sweep must be refused");
    assert!(
        err.contains("does not pay the persisted NEW descriptor address"),
        "expected destination-rebind refusal, got: {err}"
    );

    // #414 core property: a sweep paying the superseded OLD /0/0 address must be
    // refused. Because the resolved NEW successor address is genuinely distinct
    // from OLD, this fails only if the gate actually routes to the NEW address; a
    // regression re-deriving the destination from the OLD/session descriptor
    // would accept this and be caught here.
    let err = node2
        .validate_migration_sweep_destination(&old_descriptor_hash, &one_output_tx(old_script))
        .expect_err("sweep paying the superseded OLD address must be refused");
    assert!(
        err.contains("does not pay the persisted NEW descriptor address"),
        "expected destination-rebind refusal for OLD address, got: {err}"
    );

    // #414: the correctly re-derived NEW successor address is accepted, proving
    // the successor_for -> address derivation wiring resolves the version chain
    // to the NEW descriptor (not OLD).
    node2
        .validate_migration_sweep_destination(&old_descriptor_hash, &one_output_tx(expected_script))
        .expect("correctly-derived successor destination must be accepted");

    let utxos = vec![
        SweepUtxo {
            outpoint: OutPoint {
                txid: bitcoin::Txid::all_zeros(),
                vout: 0,
            },
            value_sats: 75_000,
        },
        SweepUtxo {
            outpoint: OutPoint {
                txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(
                    [0x11; 32],
                )),
                vout: 1,
            },
            value_sats: 30_000,
        },
    ];
    let total_in: u64 = utxos.iter().map(|u| u.value_sats).sum();

    // #502: a fee above 1/4 of total input is refused before any build/broadcast.
    let griefing_fee = total_in / 3;
    let err = node1
        .request_descriptor_migration_sweep(
            migration_session_id,
            old_descriptor_hash,
            &recovery_output,
            0,
            utxos.clone(),
            griefing_fee,
            1,
            Vec::new(),
            vec![responder_fp.clone()],
            Some(60),
        )
        .await
        .expect_err("fee above 1/4 of input must be refused");
    assert!(
        err.to_string().contains("exceeds 1/4 of total input"),
        "expected fee-cap refusal, got: {err}"
    );

    // An `old_recovery` output that does not match `old_descriptor_hash` must be
    // refused so a proposer cannot sweep coins from an unrelated recovery output.
    let other_config = RecoveryConfig {
        primary: SpendingTier {
            keys: vec![group_pubkey],
            threshold: 1,
        },
        recovery_tiers: vec![BitcoinRecoveryTier {
            keys: vec![bitcoin::bip32::Xpub::from_priv(
                &secp,
                &bitcoin::bip32::Xpriv::new_master(Network::Signet, &[8u8; 32]).unwrap(),
            )
            .to_x_only_pub()
            .serialize()],
            threshold: 1,
            timelock_months: 6,
        }],
        network: Network::Signet,
    };
    let other_recovery = other_config.build().expect("build other recovery output");
    assert_ne!(
        other_recovery.address.script_pubkey(),
        recovery_output.address.script_pubkey()
    );
    let err = node1
        .request_descriptor_migration_sweep(
            migration_session_id,
            old_descriptor_hash,
            &other_recovery,
            0,
            utxos,
            1_500,
            1,
            Vec::new(),
            vec![responder_fp],
            Some(60),
        )
        .await
        .expect_err("mismatched old_recovery must be refused");
    assert!(
        err.to_string()
            .contains("old_recovery output does not match the descriptor"),
        "expected old_recovery-binding refusal, got: {err}"
    );
}
