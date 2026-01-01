#![forbid(unsafe_code)]

use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

use k256::schnorr::SigningKey;
use keep_core::frost::{ThresholdConfig, TrustedDealer};
use keep_frost_net::{
    AnnouncePayload, KfpMessage, KfpNode, SessionManager, SessionState, SignRequestPayload,
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

    let discovery_result = timeout(Duration::from_secs(15), async {
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

    tokio::time::sleep(Duration::from_secs(3)).await;

    let message = b"Hello, FROST!".to_vec();
    let sign_result = timeout(Duration::from_secs(30), async {
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
            panic!("Signing failed: {:?}", e);
        }
        Err(_) => {
            panic!("Signing timed out after 30 seconds");
        }
    }
}
