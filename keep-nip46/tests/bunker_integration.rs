use std::sync::Arc;
use std::time::Duration;

use nostr_sdk::prelude::*;
use tokio::sync::Mutex;

use keep_core::keyring::Keyring;
use keep_core::keys::{KeyType, NostrKeypair};
use keep_nip46::{Server, ServerConfig};

fn extract_bunker_secret(bunker_url: &str) -> Option<String> {
    let url = url::Url::parse(bunker_url).ok()?;
    url.query_pairs()
        .find(|(k, _)| k == "secret")
        .map(|(_, v)| v.to_string())
}

fn setup_keyring() -> (Arc<Mutex<Keyring>>, PublicKey) {
    let mut keyring = Keyring::new();
    let keypair = NostrKeypair::generate().unwrap();
    let pubkey_bytes = *keypair.public_bytes();
    keyring
        .load_key(
            *keypair.public_bytes(),
            *keypair.secret_bytes(),
            KeyType::Nostr,
            "test".to_string(),
        )
        .unwrap();
    let pubkey = PublicKey::from_slice(&pubkey_bytes).unwrap();
    (Arc::new(Mutex::new(keyring)), pubkey)
}

#[tokio::test]
async fn test_bunker_e2e_connect_and_sign() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let relay_url = "wss://relay.damus.io".to_string();

    let (keyring, signer_pubkey) = setup_keyring();
    let mut server = Server::new_with_config(
        keyring,
        None,
        None,
        std::slice::from_ref(&relay_url),
        None,
        ServerConfig {
            auto_approve: true,
            ..Default::default()
        },
    )
    .await
    .expect("server creation failed");

    let bunker_url = server.bunker_url();
    assert!(bunker_url.starts_with("bunker://"));
    assert!(bunker_url.contains("relay="));
    assert!(
        bunker_url.contains("secret="),
        "headless bunker URL must include secret"
    );

    let bunker_secret = extract_bunker_secret(&bunker_url).expect("bunker URL must have secret");

    let server_pubkey = server.pubkey();
    let server_handler = server.handler();

    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    let client_keys = Keys::generate();
    let client = Client::new(client_keys.clone());
    client.add_relay(relay_url).await.unwrap();
    client.connect().await;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Send connect request with bunker secret
    let connect_req = serde_json::json!({
        "id": "req-1",
        "method": "connect",
        "params": [signer_pubkey.to_hex(), bunker_secret]
    });
    let connect_json = serde_json::to_string(&connect_req).unwrap();

    let encrypted = nip44::encrypt(
        client_keys.secret_key(),
        &server_pubkey,
        &connect_json,
        nip44::Version::V2,
    )
    .unwrap();

    let connect_event = EventBuilder::new(Kind::NostrConnect, &encrypted)
        .tag(Tag::public_key(server_pubkey))
        .sign_with_keys(&client_keys)
        .unwrap();

    client.send_event(&connect_event).await.unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify the client connected
    let clients = server_handler.list_clients().await;
    assert!(
        !clients.is_empty(),
        "no clients connected to bunker after connect request"
    );
    assert_eq!(clients[0].pubkey, client_keys.public_key());

    // Send get_public_key request
    let gpk_req = serde_json::json!({
        "id": "req-2",
        "method": "get_public_key",
        "params": []
    });
    let gpk_json = serde_json::to_string(&gpk_req).unwrap();

    let encrypted = nip44::encrypt(
        client_keys.secret_key(),
        &server_pubkey,
        &gpk_json,
        nip44::Version::V2,
    )
    .unwrap();

    let gpk_event = EventBuilder::new(Kind::NostrConnect, &encrypted)
        .tag(Tag::public_key(server_pubkey))
        .sign_with_keys(&client_keys)
        .unwrap();

    client.send_event(&gpk_event).await.unwrap();

    // Send sign_event request (kind 1 text note)
    let sign_req = serde_json::json!({
        "id": "req-3",
        "method": "sign_event",
        "params": [serde_json::to_string(&serde_json::json!({
            "kind": 1,
            "content": "Hello from NIP-46 integration test",
            "tags": [],
            "created_at": Timestamp::now().as_secs()
        })).unwrap()]
    });
    let sign_json = serde_json::to_string(&sign_req).unwrap();

    let encrypted = nip44::encrypt(
        client_keys.secret_key(),
        &server_pubkey,
        &sign_json,
        nip44::Version::V2,
    )
    .unwrap();

    let sign_event = EventBuilder::new(Kind::NostrConnect, &encrypted)
        .tag(Tag::public_key(server_pubkey))
        .sign_with_keys(&client_keys)
        .unwrap();

    client.send_event(&sign_event).await.unwrap();

    // Wait for relay to deliver responses - retry a few times
    let mut request_count = 0;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let apps = server_handler.list_clients().await;
        if let Some(app) = apps.first() {
            request_count = app.request_count;
            if request_count > 0 {
                break;
            }
        }
    }

    // Cleanup
    server_handle.abort();
    client.disconnect().await;

    println!("NIP-46 bunker integration test passed!");
    println!("  - Server started with bunker URL: {bunker_url}");
    println!(
        "  - Client connected successfully ({} clients)",
        clients.len()
    );
    println!("  - get_public_key and sign_event requests sent");
    println!("  - {request_count} request(s) recorded via relay round-trip");
}

#[tokio::test]
async fn test_bunker_rejects_without_auto_approve() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let relay_url = "wss://relay.damus.io".to_string();
    let (keyring, _signer_pubkey) = setup_keyring();

    // auto_approve: false, no callbacks = rejects by default
    let server = Server::new_with_config(
        keyring,
        None,
        None,
        std::slice::from_ref(&relay_url),
        None,
        ServerConfig {
            auto_approve: false,
            ..Default::default()
        },
    )
    .await
    .expect("server creation failed");

    let handler = server.handler();

    // Directly test the handler without relay round-trip
    let app_pubkey = Keys::generate().public_key();
    let result = handler.handle_connect(app_pubkey, None, None, None).await;

    // Should be rejected (no callbacks, auto_approve=false)
    assert!(
        result.is_err(),
        "connect should be rejected without callbacks or auto_approve"
    );

    println!("Rejection test passed: connect properly denied without auto_approve");
}

#[tokio::test]
async fn test_bunker_permission_scoping() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let relay_url = "wss://relay.damus.io".to_string();
    let (keyring, signer_pubkey) = setup_keyring();

    let server = Server::new_with_config(
        keyring,
        None,
        None,
        std::slice::from_ref(&relay_url),
        None,
        ServerConfig {
            auto_approve: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let bunker_secret = extract_bunker_secret(&server.bunker_url());
    let handler = server.handler();
    let app_pubkey = Keys::generate().public_key();

    // Connect requesting only get_public_key (with bunker secret)
    let result = handler
        .handle_connect(
            app_pubkey,
            Some(signer_pubkey),
            bunker_secret,
            Some("get_public_key".to_string()),
        )
        .await;
    assert!(result.is_ok(), "connect with valid perms should succeed");

    // get_public_key should work
    let pk_result = handler.handle_get_public_key(app_pubkey).await;
    assert!(pk_result.is_ok(), "get_public_key should be allowed");
    assert_eq!(pk_result.unwrap(), signer_pubkey);

    // sign_event should be denied (not requested)
    let unsigned = UnsignedEvent::new(
        signer_pubkey,
        Timestamp::now(),
        Kind::TextNote,
        vec![],
        "test",
    );
    let sign_result = handler.handle_sign_event(app_pubkey, unsigned).await;
    assert!(
        sign_result.is_err(),
        "sign_event should be denied when only get_public_key requested"
    );

    println!("Permission scoping test passed:");
    println!("  - get_public_key: allowed");
    println!("  - sign_event: correctly denied");
}
