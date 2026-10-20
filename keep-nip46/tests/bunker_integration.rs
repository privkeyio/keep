mod common;

use std::sync::Arc;
use std::time::Duration;

use nostr_relay_builder::prelude::*;
use nostr_sdk::prelude::*;

use common::{extract_bunker_secret, setup_keyring};
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

#[tokio::test]
async fn test_bunker_e2e_connect_and_sign() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mock_relay = common::start_mock_relay().await;
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

    let mock_relay = common::start_mock_relay().await;
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

    let mock_relay = common::start_mock_relay().await;
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

    let mock_relay = common::start_mock_relay().await;
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

async fn bunker_with_connected_client(transport: Option<[u8; 32]>) -> ConnectedBunker {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mock_relay = common::start_mock_relay().await;
    let relay_url = mock_relay.url().await.to_string();

    let (keyring, signer_pubkey) = setup_keyring();
    let mut server = Server::new_with_config(
        keyring,
        None,
        transport,
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
        "params": [server_pubkey.to_hex(), bunker_secret],
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
    let mut cb = bunker_with_connected_client(None).await;

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
    let mut cb = bunker_with_connected_client(None).await;

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
    let mut cb = bunker_with_connected_client(None).await;

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
    let mut cb = bunker_with_connected_client(None).await;

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

/// Refuses every prompt and records which method asked, so a test can tell a
/// request the user was asked about from one the bunker answered on its own.
struct RecordingRefuser(std::sync::Mutex<Vec<String>>);
impl ServerCallbacks for RecordingRefuser {
    fn on_log(&self, _event: LogEvent) {}
    fn request_approval(&self, request: ApprovalRequest) -> ApprovalResult {
        self.0.lock().unwrap().push(request.method);
        ApprovalResult::rejected()
    }
}

// A client holding the connect secret names the kinds it wants signed on
// connect. Over the relay, each of those kinds must still reach the prompt,
// and what the client asks for beyond the connect grant is refused outright.
#[tokio::test]
async fn test_e2e_kinds_named_on_connect_still_prompt() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mock_relay = common::start_mock_relay().await;
    let relay_url = mock_relay.url().await.to_string();
    let (keyring, signer_pubkey) = setup_keyring();
    let prompts = Arc::new(RecordingRefuser(std::sync::Mutex::new(Vec::new())));
    let mut server = Server::new_with_config(
        keyring,
        None,
        None,
        std::slice::from_ref(&relay_url),
        Some(prompts.clone()),
        ServerConfig {
            connect_grant: keep_nip46::Permission::GET_PUBLIC_KEY
                | keep_nip46::Permission::SIGN_EVENT,
            expected_secret: Some("e2e-connect-secret".into()),
            ..Default::default()
        },
    )
    .await
    .expect("server creation");
    let bunker_secret = extract_bunker_secret(&server.bunker_url()).expect("bunker secret");
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

    let ask = |id: &str, method: &str, params: serde_json::Value| {
        let request = serde_json::json!({ "id": id, "method": method, "params": params });
        build_nip46_request(
            &client_keys,
            &server_pubkey,
            &serde_json::to_string(&request).unwrap(),
        )
    };
    let unsigned = |kind: u16| {
        serde_json::to_string(&serde_json::json!({
            "kind": kind,
            "content": "e2e",
            "tags": [],
            "created_at": Timestamp::now().as_secs(),
        }))
        .unwrap()
    };

    let mut responses = Vec::new();
    let mut requests = vec![(
        "connect".to_string(),
        ask(
            "connect",
            "connect",
            serde_json::json!([
                signer_pubkey.to_hex(),
                bunker_secret,
                "sign_event:0,sign_event:1,sign_event:3,nip44_decrypt"
            ]),
        ),
    )];
    for kind in [0u16, 1, 3, 7] {
        let id = format!("sign-{kind}");
        requests.push((
            id.clone(),
            ask(&id, "sign_event", serde_json::json!([unsigned(kind)])),
        ));
    }
    requests.push((
        "decrypt".to_string(),
        ask(
            "decrypt",
            "nip44_decrypt",
            serde_json::json!([Keys::generate().public_key().to_hex(), "AAAA"]),
        ),
    ));
    for (id, event) in requests {
        client.send_event(&event).await.unwrap();
        let response = await_nip46_response(
            &mut notifications,
            &client_keys,
            &server_pubkey,
            &id,
            Duration::from_secs(10),
        )
        .await
        .unwrap_or_else(|| panic!("{id} must respond"));
        responses.push((id, response));
    }

    let result = |id: &str| {
        responses
            .iter()
            .find(|(r, _)| r == id)
            .and_then(|(_, response)| response.get("result").and_then(|v| v.as_str()))
            .filter(|r| !r.is_empty())
            .map(str::to_owned)
    };
    assert_eq!(result("connect").as_deref(), Some("ack"));
    for kind in [0, 1, 3] {
        assert!(
            result(&format!("sign-{kind}")).is_none(),
            "kind {kind} was named on connect and must not be signed unprompted"
        );
    }
    let reaction = Event::from_json(result("sign-7").expect("kind 7 is signed by default"))
        .expect("signed reaction");
    reaction.verify().expect("the reaction verifies");
    assert!(
        result("decrypt").is_none(),
        "decryption is outside the connect grant"
    );
    assert_eq!(
        *prompts.0.lock().unwrap(),
        vec!["sign_event"; 3],
        "each named kind was prompted, and nothing else was"
    );

    server_handle.abort();
    client.disconnect().await;
}

// A grant row saved before kinds were vetted may hold kinds a client chose
// for itself. A known client needs no connect to sign, so over the relay a
// bunker restored from such a row must not sign those kinds unprompted: with
// them dropped the row holds no grant, so the client is not restored at all
// and has to connect again. A row saved since keeps signing them.
#[tokio::test]
async fn test_e2e_unvetted_restored_kinds_are_not_signed_unprompted() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    for vetted in [false, true] {
        let mock_relay = common::start_mock_relay().await;
        let relay_url = mock_relay.url().await.to_string();
        let (keyring, _) = setup_keyring();
        let client_keys = Keys::generate();
        let row = keep_core::relay::StoredBunkerPermission {
            pubkey_hex: client_keys.public_key().to_hex(),
            name: "restored".into(),
            permissions: (keep_nip46::Permission::GET_PUBLIC_KEY
                | keep_nip46::Permission::SIGN_EVENT)
                .bits(),
            auto_approve_kinds: vec![1],
            duration: keep_core::relay::StoredPermissionDuration::Forever,
            connected_at: 0,
            timed_kind_grants: Vec::new(),
            explicitly_remembered: Some(true),
            kinds_vetted: vetted,
        };
        let prompts = Arc::new(RecordingRefuser(std::sync::Mutex::new(Vec::new())));
        let mut server = Server::new_with_config(
            keyring,
            None,
            None,
            std::slice::from_ref(&relay_url),
            Some(prompts.clone()),
            ServerConfig {
                pre_grants: keep_nip46::PreGrantedApp::from_stored(&row)
                    .into_iter()
                    .collect(),
                expected_secret: Some("e2e-connect-secret".into()),
                ..Default::default()
            },
        )
        .await
        .expect("server creation");
        let server_pubkey = server.pubkey();
        let server_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(Duration::from_secs(1)).await;

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

        let unsigned = serde_json::json!({
            "kind": 1,
            "content": "restored",
            "tags": [],
            "created_at": Timestamp::now().as_secs(),
        });
        let request = serde_json::json!({
            "id": "sign",
            "method": "sign_event",
            "params": [serde_json::to_string(&unsigned).unwrap()],
        });
        client
            .send_event(&build_nip46_request(
                &client_keys,
                &server_pubkey,
                &serde_json::to_string(&request).unwrap(),
            ))
            .await
            .unwrap();
        let response = await_nip46_response(
            &mut notifications,
            &client_keys,
            &server_pubkey,
            "sign",
            Duration::from_secs(10),
        )
        .await
        .expect("sign_event must respond");
        let signed = response
            .get("result")
            .and_then(|v| v.as_str())
            .filter(|r| !r.is_empty())
            .is_some();
        assert_eq!(signed, vetted, "vetted={vetted}: {response}");
        if !vetted {
            assert!(
                response.get("error").and_then(|v| v.as_str()).is_some(),
                "an unrestored client is refused: {response}"
            );
        }
        assert!(prompts.0.lock().unwrap().is_empty());

        server_handle.abort();
        client.disconnect().await;
    }
}

// A single-key bunker with its own transport secret serves under a bunker
// pubkey that is not its signing key. The event it returns must be signed for
// the signing key, and verify.
#[tokio::test]
async fn test_e2e_keyring_bunker_with_transport_key_signs_valid_events() {
    let transport = Keys::generate();
    let mut cb = bunker_with_connected_client(Some(transport.secret_key().secret_bytes())).await;
    assert_eq!(cb.server_pubkey, transport.public_key());
    assert_ne!(cb.server_pubkey, cb.signer_pubkey);

    let unsigned = serde_json::json!({
        "kind": 1,
        "content": "signed for the signing key",
        "tags": [],
        "created_at": Timestamp::now().as_secs(),
    });
    let resp = send_and_await(
        &mut cb,
        "req-sign",
        "sign_event",
        serde_json::json!([serde_json::to_string(&unsigned).unwrap()]),
    )
    .await;
    let signed = Event::from_json(
        resp.get("result")
            .and_then(|v| v.as_str())
            .expect("sign_event returns the event"),
    )
    .expect("a signed event");
    signed.verify().expect("the returned event verifies");
    assert_eq!(signed.pubkey, cb.signer_pubkey);
    assert_eq!(signed.content, "signed for the signing key");

    cb.server_handle.abort();
    cb.client.disconnect().await;
}

/// A server on `relay_url` serving under `transport`, returning its pubkey,
/// handler and the task running it.
async fn serve_on(
    relay_url: &str,
    transport: [u8; 32],
) -> (
    PublicKey,
    Arc<keep_nip46::SignerHandler>,
    tokio::task::JoinHandle<()>,
) {
    let (keyring, _) = setup_keyring();
    let mut server = Server::new_with_config(
        keyring,
        None,
        Some(transport),
        &[relay_url.to_string()],
        None,
        ServerConfig {
            expected_secret: Some("replay-secret".into()),
            ..Default::default()
        },
    )
    .await
    .expect("server creation");
    let pubkey = server.pubkey();
    let handler = server.handler();
    let task = tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    (pubkey, handler, task)
}

/// A NIP-46 request from `client_keys` to `server_pubkey`, dated `created_at`.
fn dated_request(
    client_keys: &Keys,
    server_pubkey: &PublicKey,
    request: &serde_json::Value,
    created_at: Timestamp,
) -> Event {
    let encrypted = nip44::encrypt(
        client_keys.secret_key(),
        server_pubkey,
        request.to_string(),
        nip44::Version::V2,
    )
    .unwrap();
    EventBuilder::new(Kind::NostrConnect, &encrypted)
        .tag(Tag::public_key(*server_pubkey))
        .custom_created_at(created_at)
        .sign_with_keys(client_keys)
        .unwrap()
}

// A relay that keeps NIP-46 events replays them to every new subscription, so
// a bunker that restarts is handed requests from before it started, among them
// connects carrying a secret that was valid then. One dated before the start
// is not handled, nor is one dated far ahead, which would otherwise come back
// on every restart until its date; one from a client whose clock runs a little
// behind is.
#[tokio::test]
async fn test_e2e_requests_dated_outside_the_run_are_not_handled() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mock_relay = common::start_mock_relay().await;
    let relay_url = mock_relay.url().await.to_string();
    let (server_pubkey, handler, task) =
        serve_on(&relay_url, Keys::generate().secret_key().secret_bytes()).await;

    let client_keys = Keys::generate();
    let client = Client::new(client_keys.clone());
    client.add_relay(relay_url).await.unwrap();
    client.connect().await;
    client
        .subscribe(
            Filter::new()
                .kind(Kind::NostrConnect)
                .author(server_pubkey)
                .pubkey(client_keys.public_key()),
            None,
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut notifications = client.notifications();

    // Requests are handled in the order they arrive, so a pong after a request
    // proves that request was processed.
    let mut ping = async |id: &str, created_at: Timestamp| {
        let request = serde_json::json!({ "id": id, "method": "ping", "params": [] });
        client
            .send_event(&dated_request(
                &client_keys,
                &server_pubkey,
                &request,
                created_at,
            ))
            .await
            .unwrap();
        await_nip46_response(
            &mut notifications,
            &client_keys,
            &server_pubkey,
            id,
            Duration::from_secs(10),
        )
        .await
    };
    assert!(
        ping("before", Timestamp::now()).await.is_some(),
        "the bunker serves"
    );

    let replayed = serde_json::json!({
        "id": "replayed",
        "method": "connect",
        "params": [server_pubkey.to_hex(), "replay-secret"],
    });
    for created_at in [
        Timestamp::now() - Duration::from_secs(600),
        Timestamp::now() + Duration::from_secs(600),
    ] {
        client
            .send_event(&dated_request(
                &client_keys,
                &server_pubkey,
                &replayed,
                created_at,
            ))
            .await
            .unwrap();
    }
    assert!(
        ping("after", Timestamp::now() - Duration::from_secs(10))
            .await
            .is_some(),
        "a client whose clock runs a little behind is answered"
    );
    assert!(
        handler.list_clients().await.is_empty(),
        "a connect dated outside the bunker's run does not register the client"
    );

    task.abort();
    client.disconnect().await;
}
