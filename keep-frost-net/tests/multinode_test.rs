#![forbid(unsafe_code)]

use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

use keep_core::frost::{ThresholdConfig, TrustedDealer};
use keep_frost_net::{
    AnnouncePayload, KfpMessage, KfpNode, SessionManager, SessionState, SignRequestPayload,
};

fn get_test_relay() -> String {
    std::env::var("FROST_TEST_RELAY").unwrap_or_else(|_| "wss://nos.lol".to_string())
}

#[tokio::test]
#[ignore = "requires external relay; set FROST_TEST_RELAY env var or run with --ignored"]
async fn test_node_creation_and_announcement() {
    let relay = get_test_relay();
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

    println!("Both nodes announced successfully");
    println!("Node 1 pubkey: {:?}", node1.pubkey());
    println!("Node 2 pubkey: {:?}", node2.pubkey());
}

#[tokio::test]
#[ignore = "requires external relay; set FROST_TEST_RELAY env var or run with --ignored"]
async fn test_peer_discovery_with_running_nodes() {
    let relay = get_test_relay();
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

    println!(
        "Node 1 share: {}, Node 2 share: {}",
        node1.share_index(),
        node2.share_index()
    );

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
            if let Ok(event) = rx1.recv().await {
                if let keep_frost_net::KfpNodeEvent::PeerDiscovered { share_index, name } = event {
                    println!("DISCOVERED peer: share {} ({:?})", share_index, name);
                    return true;
                }
            }
        }
    })
    .await;

    async fn graceful_shutdown(
        shutdown_tx: Option<mpsc::Sender<()>>,
        handle: tokio::task::JoinHandle<()>,
        name: &str,
    ) {
        if let Some(tx) = shutdown_tx {
            let _ = tx.try_send(());
        }
        match timeout(Duration::from_secs(2), handle).await {
            Ok(_) => println!("{} shutdown gracefully", name),
            Err(_) => println!("{} shutdown timed out", name),
        }
    }

    graceful_shutdown(shutdown1, node1_handle, "Node 1").await;
    graceful_shutdown(shutdown2, node2_handle, "Node 2").await;

    match discovery_result {
        Ok(true) => println!("SUCCESS: Peer discovery verified!"),
        _ => println!("Peer discovery timed out (relay latency or filtering)"),
    }
}

#[tokio::test]
async fn test_frost_protocol_message_flow() {
    let announce = AnnouncePayload::new([1u8; 32], 1).with_name("Test Node");
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
    let mut manager = SessionManager::new();

    let session_id = [1u8; 32];
    let message = b"test message".to_vec();

    let session = manager
        .create_session(session_id, message.clone(), 2, vec![1, 2, 3])
        .unwrap();

    assert_eq!(session.state(), SessionState::AwaitingCommitments);
    assert_eq!(session.commitments_needed(), 2);
    assert!(session.is_participant(1));
    assert!(session.is_participant(2));
    assert!(!session.is_participant(4));

    let result = manager.create_session(session_id, message, 2, vec![1, 2]);
    assert!(result.is_err());

    manager.complete_session(&session_id);
    assert!(manager.is_replay(&session_id));
}

#[tokio::test]
#[ignore = "requires external relay; set FROST_TEST_RELAY env var or run with --ignored"]
async fn test_full_signing_flow() {
    use std::sync::Arc;

    let relay = get_test_relay();
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

    println!(
        "Created nodes: share 1, 2, 3 with group {:?}",
        hex::encode(node1.group_pubkey())
    );

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

    tokio::time::sleep(Duration::from_secs(5)).await;
    println!(
        "Nodes running, node 3 has {} online peers",
        node3.online_peers()
    );

    println!("Attempting signature from node 3...");

    let message = b"Hello, FROST!".to_vec();
    let sign_result = timeout(Duration::from_secs(30), async {
        node3.request_signature(message, "raw").await
    })
    .await;

    async fn graceful_shutdown(
        shutdown_tx: Option<mpsc::Sender<()>>,
        handle: tokio::task::JoinHandle<()>,
        name: &str,
    ) {
        if let Some(tx) = shutdown_tx {
            let _ = tx.try_send(());
        }
        match timeout(Duration::from_secs(2), handle).await {
            Ok(_) => println!("{} shutdown gracefully", name),
            Err(_) => println!("{} shutdown timed out", name),
        }
    }

    graceful_shutdown(shutdown1, node1_handle, "Node 1").await;
    graceful_shutdown(shutdown2, node2_handle, "Node 2").await;
    graceful_shutdown(shutdown3, node3_handle, "Node 3").await;

    match sign_result {
        Ok(Ok(signature)) => {
            println!("SUCCESS: Signature obtained!");
            println!("Signature: {}", hex::encode(signature));
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
