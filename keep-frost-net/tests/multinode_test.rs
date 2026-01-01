#![forbid(unsafe_code)]

use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

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
    let announce =
        AnnouncePayload::new([1u8; 32], 1, [2u8; 33], [3u8; 64], 1234567890).with_name("Test Node");
    let msg = KfpMessage::Announce(announce);
    let json = msg.to_json().unwrap();

    assert!(json.contains("announce"));
    assert!(json.contains("Test Node"));

    let parsed = KfpMessage::from_json(&json).unwrap();
    assert_eq!(parsed.message_type(), "announce");

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
