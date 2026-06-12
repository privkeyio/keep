use std::sync::Arc;
use std::time::Duration;

use nostr_relay_builder::prelude::*;
use nostr_sdk::prelude::*;
use tokio::sync::Mutex;

use keep_core::keyring::Keyring;
use keep_core::keys::{KeyType, NostrKeypair};
use keep_nip46::types::{ApprovalRequest, ApprovalResult, LogEvent, ServerCallbacks};
use keep_nip46::{Server, ServerConfig};

/// Test-only `ServerCallbacks` that approves every request. Used by tests
/// that need the connect handshake to succeed (and the per-method approval
/// gate to fire) WITHOUT enabling `auto_approve: true`, which would override
/// the client's requested permissions with `Permission::ALL`.
struct AlwaysApprove;
impl ServerCallbacks for AlwaysApprove {
    fn on_log(&self, _event: LogEvent) {}
    fn request_approval(&self, _request: ApprovalRequest) -> ApprovalResult {
        ApprovalResult::approved_once()
    }
}

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

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay_url = mock_relay.url().await.to_string();

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

    tokio::time::sleep(Duration::from_secs(1)).await;

    let client_keys = Keys::generate();
    let client = Client::new(client_keys.clone());
    client.add_relay(relay_url).await.unwrap();
    client.connect().await;

    tokio::time::sleep(Duration::from_secs(1)).await;

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

    tokio::time::sleep(Duration::from_secs(2)).await;

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

    // Cleanup
    server_handle.abort();
    client.disconnect().await;
}

#[tokio::test]
async fn test_bunker_rejects_without_auto_approve() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay_url = mock_relay.url().await.to_string();
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
}

#[tokio::test]
async fn test_bunker_permission_scoping() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay_url = mock_relay.url().await.to_string();
    let (keyring, signer_pubkey) = setup_keyring();

    // `auto_approve: false` here, with an `AlwaysApprove` callback. This
    // exercises the real per-permission scoping path: the client's requested
    // permissions are honored as-is, not silently widened to `Permission::ALL`
    // by `auto_approve` (see #444 / `handler.rs:351`). The callback lets the
    // connect handshake succeed in a test that has no human in the loop.
    let server = Server::new_with_config(
        keyring,
        None,
        None,
        std::slice::from_ref(&relay_url),
        Some(Arc::new(AlwaysApprove)),
        ServerConfig {
            auto_approve: false,
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
}

// === #435: validate the signature on the returned event ===
//
// The existing `test_bunker_e2e_connect_and_sign` sends a `sign_event`
// request over the relay but never waits for the response nor validates
// the returned signed event. That's #435's headline gap: until a NIP-46
// round-trip is verified end-to-end, "keep is a Nostr signer" is only
// asserted at the bunker URL boundary.
//
// This test drives the full handshake (connect, sign_event), waits for
// the sign_event response, decrypts it, and parses the signed event into
// a `nostr_sdk::Event`. `Event::verify` recomputes the event id from its
// content and checks the BIP-340 schnorr signature and pubkey binding, so
// a regression that emits an unsigned event, signs with the wrong key, or
// returns a self-consistent (id, sig) pair over the wrong content/kind
// fails this test. It also asserts the returned content and kind match the
// request and that the signer pubkey is the bunker's.

/// Build a NIP-46 request event addressed to `server_pubkey`, encrypted
/// under `client_keys` with NIP-44 v2.
fn build_nip46_request(client_keys: &Keys, server_pubkey: &PublicKey, request_json: &str) -> Event {
    let encrypted = nip44::encrypt(
        client_keys.secret_key(),
        server_pubkey,
        request_json,
        nip44::Version::V2,
    )
    .expect("nip44 encrypt");
    EventBuilder::new(Kind::NostrConnect, &encrypted)
        .tag(Tag::public_key(*server_pubkey))
        .sign_with_keys(client_keys)
        .expect("sign nip46 request")
}

/// Wait up to `timeout` for a NIP-46 response from `server_pubkey` whose
/// JSON id matches `expected_id`. The caller must create `notifications`
/// (via `client.notifications()`) BEFORE sending the request, so a response
/// landing between send and recv cannot be dropped.
async fn await_nip46_response(
    notifications: &mut tokio::sync::broadcast::Receiver<RelayPoolNotification>,
    client_keys: &Keys,
    server_pubkey: &PublicKey,
    expected_id: &str,
    timeout: Duration,
) -> Option<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.checked_duration_since(tokio::time::Instant::now())?;
        let event = match tokio::time::timeout(remaining, notifications.recv()).await {
            Ok(Ok(RelayPoolNotification::Event { event, .. })) => event,
            _ => continue,
        };
        if event.kind != Kind::NostrConnect || event.pubkey != *server_pubkey {
            continue;
        }
        let decrypted = match nip44::decrypt(
            client_keys.secret_key(),
            server_pubkey,
            event.content.as_str(),
        ) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let json: serde_json::Value = match serde_json::from_str(&decrypted) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if json.get("id").and_then(|v| v.as_str()) != Some(expected_id) {
            continue;
        }
        return Some(json);
    }
}

#[tokio::test]
async fn test_bunker_e2e_returned_event_signature_verifies() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mock_relay = MockRelay::run().await.expect("MockRelay start");
    let relay_url = mock_relay.url().await.to_string();

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
    .expect("server creation");

    let bunker_url = server.bunker_url();
    let bunker_secret = extract_bunker_secret(&bunker_url).expect("bunker secret");
    let server_pubkey = server.pubkey();
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let client_keys = Keys::generate();
    let client = Client::new(client_keys.clone());
    client.add_relay(relay_url).await.unwrap();
    client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Subscribe BEFORE any request so no response can beat the filter.
    client
        .subscribe(
            Filter::new()
                .kind(Kind::NostrConnect)
                .author(server_pubkey)
                .pubkey(client_keys.public_key()),
            None,
        )
        .await
        .expect("subscribe to bunker responses");
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 1. connect handshake, wait for ack before signing.
    let connect_req = serde_json::json!({
        "id": "req-connect",
        "method": "connect",
        "params": [signer_pubkey.to_hex(), bunker_secret],
    });
    let mut notifications = client.notifications();
    client
        .send_event(&build_nip46_request(
            &client_keys,
            &server_pubkey,
            &serde_json::to_string(&connect_req).unwrap(),
        ))
        .await
        .unwrap();
    let connect_resp = await_nip46_response(
        &mut notifications,
        &client_keys,
        &server_pubkey,
        "req-connect",
        Duration::from_secs(10),
    )
    .await
    .expect("connect must respond before sign_event");
    assert_eq!(
        connect_resp.get("result").and_then(|v| v.as_str()),
        Some("ack"),
        "connect must succeed with ack, got: {connect_resp}"
    );

    // 2. sign_event request, kind 1 text note.
    let request_content = "round-trip signature verification (#435)";
    let unsigned = serde_json::json!({
        "kind": 1,
        "content": request_content,
        "tags": [],
        "created_at": Timestamp::now().as_secs(),
    });
    let sign_req = serde_json::json!({
        "id": "req-sign",
        "method": "sign_event",
        "params": [serde_json::to_string(&unsigned).unwrap()],
    });
    client
        .send_event(&build_nip46_request(
            &client_keys,
            &server_pubkey,
            &serde_json::to_string(&sign_req).unwrap(),
        ))
        .await
        .unwrap();
    let response = await_nip46_response(
        &mut notifications,
        &client_keys,
        &server_pubkey,
        "req-sign",
        Duration::from_secs(10),
    )
    .await
    .expect("sign_event must respond");

    // NIP-46 response shape: { id, result, error }. `result` is the
    // JSON-stringified signed event.
    let result_str = response
        .get("result")
        .and_then(|v| v.as_str())
        .expect("sign_event response must include `result`");
    let signed_event =
        Event::from_json(result_str).expect("`result` is a JSON-stringified signed event");

    // `verify` recomputes the id from the event content and checks the
    // BIP-340 schnorr signature plus pubkey binding, so a self-consistent
    // (id, sig) pair over the wrong content cannot pass.
    signed_event
        .verify()
        .expect("returned NIP-46 signed event MUST verify (id, sig, pubkey)");

    assert_eq!(
        signed_event.pubkey, signer_pubkey,
        "returned event MUST be signed under the bunker's signer pubkey"
    );
    assert_eq!(
        signed_event.content, request_content,
        "returned event MUST carry the requested content"
    );
    assert_eq!(
        signed_event.kind,
        Kind::TextNote,
        "returned event MUST be the requested kind 1"
    );

    server_handle.abort();
    client.disconnect().await;
}

// === #553: NIP-46 dispatch_request match-arm coverage ===
//
// Each of these tests drives one NIP-46 method through `dispatch_request`
// over the relay, killing the match-arm-deletion mutation for that
// method. The existing #435 e2e covers `connect` + `sign_event` only.

/// Holds everything an NIP-46 method test needs after the connect handshake.
/// `_mock_relay` MUST stay alive for the entire test — dropping it shuts
/// down the relay and any in-flight method calls hang on the 10s timeout.
struct ConnectedBunker {
    client: Client,
    client_keys: Keys,
    server_pubkey: PublicKey,
    signer_pubkey: PublicKey,
    server_handle: tokio::task::JoinHandle<()>,
    notifications: tokio::sync::broadcast::Receiver<RelayPoolNotification>,
    _mock_relay: MockRelay,
}

async fn bunker_with_connected_client() -> ConnectedBunker {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mock_relay = MockRelay::run().await.expect("MockRelay start");
    let relay_url = mock_relay.url().await.to_string();

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
    .expect("server creation");

    let bunker_url = server.bunker_url();
    let bunker_secret = extract_bunker_secret(&bunker_url).expect("bunker secret");
    let server_pubkey = server.pubkey();
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_secs(1)).await;

    let client_keys = Keys::generate();
    let client = Client::new(client_keys.clone());
    client.add_relay(relay_url).await.unwrap();
    client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    client
        .subscribe(
            Filter::new()
                .kind(Kind::NostrConnect)
                .author(server_pubkey)
                .pubkey(client_keys.public_key()),
            None,
        )
        .await
        .expect("subscribe to bunker responses");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut notifications = client.notifications();

    let connect_req = serde_json::json!({
        "id": "req-connect",
        "method": "connect",
        "params": [signer_pubkey.to_hex(), bunker_secret],
    });
    client
        .send_event(&build_nip46_request(
            &client_keys,
            &server_pubkey,
            &serde_json::to_string(&connect_req).unwrap(),
        ))
        .await
        .unwrap();
    let connect_resp = await_nip46_response(
        &mut notifications,
        &client_keys,
        &server_pubkey,
        "req-connect",
        Duration::from_secs(10),
    )
    .await
    .expect("connect must respond");
    assert_eq!(
        connect_resp.get("result").and_then(|v| v.as_str()),
        Some("ack"),
        "connect must succeed with ack, got: {connect_resp}"
    );

    ConnectedBunker {
        client,
        client_keys,
        server_pubkey,
        signer_pubkey,
        server_handle,
        notifications,
        _mock_relay: mock_relay,
    }
}

async fn send_and_await(
    cb: &mut ConnectedBunker,
    id: &str,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let req = serde_json::json!({ "id": id, "method": method, "params": params });
    cb.client
        .send_event(&build_nip46_request(
            &cb.client_keys,
            &cb.server_pubkey,
            &serde_json::to_string(&req).unwrap(),
        ))
        .await
        .unwrap();
    await_nip46_response(
        &mut cb.notifications,
        &cb.client_keys,
        &cb.server_pubkey,
        id,
        Duration::from_secs(10),
    )
    .await
    .unwrap_or_else(|| panic!("{method} must respond"))
}

#[tokio::test]
async fn test_dispatch_get_public_key_returns_signer_pubkey() {
    let mut cb = bunker_with_connected_client().await;

    let resp = send_and_await(&mut cb, "req-gpk", "get_public_key", serde_json::json!([])).await;
    let result = resp
        .get("result")
        .and_then(|v| v.as_str())
        .expect("get_public_key result must be a string");

    assert_eq!(
        result,
        cb.signer_pubkey.to_hex(),
        "get_public_key MUST return the bunker's signer pubkey verbatim"
    );

    cb.server_handle.abort();
    cb.client.disconnect().await;
}

#[tokio::test]
async fn test_dispatch_ping_returns_pong() {
    let mut cb = bunker_with_connected_client().await;

    let resp = send_and_await(&mut cb, "req-ping", "ping", serde_json::json!([])).await;
    let result = resp
        .get("result")
        .and_then(|v| v.as_str())
        .expect("ping result must be a string");
    assert_eq!(
        result, "pong",
        "ping MUST return the literal string \"pong\""
    );

    cb.server_handle.abort();
    cb.client.disconnect().await;
}

#[tokio::test]
async fn test_dispatch_nip44_encrypt_decrypt_roundtrip() {
    let mut cb = bunker_with_connected_client().await;

    let third_party = Keys::generate();
    let plaintext = "secret message for #553 nip44 coverage";

    let enc = send_and_await(
        &mut cb,
        "req-nip44-enc",
        "nip44_encrypt",
        serde_json::json!([third_party.public_key().to_hex(), plaintext]),
    )
    .await;
    let ciphertext = enc
        .get("result")
        .and_then(|v| v.as_str())
        .expect("nip44_encrypt result must be a ciphertext string")
        .to_string();
    assert!(!ciphertext.is_empty(), "nip44 ciphertext MUST be non-empty");
    // Independently decrypt with the third party's key against the signer
    // pubkey. This proves the bunker encrypted to the REQUESTED recipient,
    // not to a fixed or its own key: a bunker-internal symmetric round-trip
    // alone can't catch a peer-pubkey-binding regression.
    let independent = nip44::decrypt(third_party.secret_key(), &cb.signer_pubkey, &ciphertext)
        .expect("nip44 ciphertext must decrypt for the requested peer");
    assert_eq!(
        independent, plaintext,
        "nip44 ciphertext MUST be addressed to the requested peer pubkey"
    );

    let dec = send_and_await(
        &mut cb,
        "req-nip44-dec",
        "nip44_decrypt",
        serde_json::json!([third_party.public_key().to_hex(), ciphertext]),
    )
    .await;
    let decrypted = dec
        .get("result")
        .and_then(|v| v.as_str())
        .expect("nip44_decrypt result must be a plaintext string");
    assert_eq!(
        decrypted, plaintext,
        "nip44 decrypt MUST round-trip to the original plaintext"
    );

    cb.server_handle.abort();
    cb.client.disconnect().await;
}

#[tokio::test]
async fn test_dispatch_nip04_encrypt_decrypt_roundtrip() {
    let mut cb = bunker_with_connected_client().await;

    let third_party = Keys::generate();
    let plaintext = "legacy nip04 coverage for #553";

    let enc = send_and_await(
        &mut cb,
        "req-nip04-enc",
        "nip04_encrypt",
        serde_json::json!([third_party.public_key().to_hex(), plaintext]),
    )
    .await;
    let ciphertext = enc
        .get("result")
        .and_then(|v| v.as_str())
        .expect("nip04_encrypt result must be a ciphertext string")
        .to_string();
    assert!(!ciphertext.is_empty(), "nip04 ciphertext MUST be non-empty");
    // Independently decrypt with the third party's key against the signer
    // pubkey to prove the bunker encrypted to the REQUESTED recipient.
    let independent = nip04::decrypt(third_party.secret_key(), &cb.signer_pubkey, &ciphertext)
        .expect("nip04 ciphertext must decrypt for the requested peer");
    assert_eq!(
        independent, plaintext,
        "nip04 ciphertext MUST be addressed to the requested peer pubkey"
    );

    let dec = send_and_await(
        &mut cb,
        "req-nip04-dec",
        "nip04_decrypt",
        serde_json::json!([third_party.public_key().to_hex(), ciphertext]),
    )
    .await;
    let decrypted = dec
        .get("result")
        .and_then(|v| v.as_str())
        .expect("nip04_decrypt result must be a plaintext string");
    assert_eq!(
        decrypted, plaintext,
        "nip04 decrypt MUST round-trip to the original plaintext"
    );

    cb.server_handle.abort();
    cb.client.disconnect().await;
}
