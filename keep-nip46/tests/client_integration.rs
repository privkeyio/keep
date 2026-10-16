mod common;

use std::time::Duration;

use nostr_relay_builder::prelude::*;
use nostr_sdk::prelude::Keys;

use common::setup_keyring;
use keep_core::error::{KeepError, NetworkError};
use keep_nip46::{generate_bunker_url, Nip46Client, Server, ServerConfig};

/// The outbound client is the direction where Keep dials someone else's
/// bunker, and that socket carries sighashes and signing requests. Strict
/// pinning has nothing to pin on a cleartext socket, so the connect must fail
/// rather than return a client that silently carries nothing: `connect` only
/// spawns attempts and `subscribe` queues against an empty pool, so both
/// resolve `Ok` while every socket is being refused.
///
/// The lenient connect against the same relay is the timing witness: it proves
/// the refusal is attributable to `require_pinned` and not to a relay this test
/// could never reach.
#[tokio::test]
async fn strict_pinning_refuses_an_outbound_client_relay_it_cannot_pin() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mock_relay = MockRelay::run().await.expect("mock relay");
    let relay_url = mock_relay.url().await.to_string();
    let signer = Keys::generate().public_key();

    let pinning = |require_pinned| {
        keep_frost_net::TlsPinning::new(
            std::sync::Arc::new(std::sync::Mutex::new(
                keep_frost_net::CertificatePinSet::default(),
            )),
            require_pinned,
        )
    };

    let lenient = Nip46Client::connect_with(
        signer,
        vec![relay_url.clone()],
        None,
        None,
        Some(pinning(false)),
    )
    .await
    .expect("lenient pinning must reach the mock relay, or the refusal below proves nothing");
    lenient.disconnect().await;

    let err = Nip46Client::connect_with(
        signer,
        vec![relay_url.clone()],
        None,
        None,
        Some(pinning(true)),
    )
    .await
    .err()
    .expect("strict pinning cannot pin a cleartext socket, so the connect must fail");
    let err = err.to_string();
    assert!(
        err.contains("Timed out waiting for relay connection"),
        "the failure must be the refused socket, not a rejected URL or an empty relay list: {err}"
    );
}

/// The wait above is gated on pinning being installed, and that gate is
/// load-bearing for a caller that passes none: `keep-cli` has no pin store, and
/// it must keep the old behavior of returning a client without waiting for a
/// relay. Mirrors `an_unpinned_bunker_starts_without_a_reachable_relay` on the
/// serving side.
#[tokio::test]
async fn an_unpinned_outbound_client_connects_without_a_reachable_relay() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    // Nothing is listening on port 1, so no relay can ever reach `Connected`.
    let client = Nip46Client::connect_with(
        Keys::generate().public_key(),
        vec!["ws://127.0.0.1:1".to_string()],
        None,
        None,
        None,
    )
    .await
    .expect("an unpinned client must not wait for a relay");
    client.disconnect().await;
}

#[tokio::test]
async fn test_nip46_client_rejects_unknown_method() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mock_relay = MockRelay::run().await.expect("mock relay");
    let relay_url = mock_relay.url().await.to_string();

    let (keyring, _signer_pubkey) = setup_keyring();
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
    let bunker_secret = url::Url::parse(&bunker_url).ok().and_then(|u| {
        u.query_pairs()
            .find(|(k, _)| k == "secret")
            .map(|(_, v)| v.to_string())
    });
    let server_pubkey = server.pubkey();

    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_secs(1)).await;

    let client = Nip46Client::connect_with(
        server_pubkey,
        vec![relay_url.clone()],
        bunker_secret,
        None,
        None,
    )
    .await
    .expect("client connect");
    client.connect().await.expect("connect handshake");

    // The keep-nip46 server does not implement register_wallet, so it should
    // respond with an "Unknown method" error. Verify the client surfaces it as
    // a typed NetworkError::Response with a non-empty message.
    let err = client
        .register_wallet("test-wallet", "tr([deadbeef]xpub6.../<0;1>/*)")
        .await
        .expect_err("register_wallet should error against a non-hardware signer");
    match err {
        KeepError::NetworkErr(NetworkError::Response { message, .. }) => {
            assert!(!message.is_empty(), "empty response error message");
            assert!(
                message.contains("register_wallet rejected") || message.contains("Unknown method"),
                "unexpected response error: {message}"
            );
        }
        other => panic!("expected NetworkError::Response, got {other:?}"),
    }

    client.disconnect().await;
    server_handle.abort();
}

#[tokio::test]
async fn test_nip46_client_parses_bunker_url() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let bad = Nip46Client::connect_to("not-a-bunker-url", None, None).await;
    assert!(bad.is_err(), "invalid URL must be rejected");

    let mock_relay = MockRelay::run().await.expect("mock relay");
    let relay_url = mock_relay.url().await.to_string();
    let keys = Keys::generate();
    let url = generate_bunker_url(&keys.public_key(), &[relay_url], Some("topsecretbunker12"));

    let client = Nip46Client::connect_to(&url, None, None)
        .await
        .expect("well-formed bunker URL connects");
    client.disconnect().await;
}

// Simulates a remote hardware signer that accepts register_wallet and replies
// with a deterministic HMAC so we can exercise the full happy-path client flow.
async fn run_stub_signer(
    signer_keys: Keys,
    relay_url: String,
    hmac_hex: String,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    use nostr_sdk::prelude::{
        nip44, Client, EventBuilder, Filter, Kind, RelayPoolNotification, Tag, Timestamp,
    };

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    let handle = tokio::spawn(async move {
        let client = Client::new(signer_keys.clone());
        client.add_relay(relay_url.as_str()).await.unwrap();
        client.connect().await;
        let filter = Filter::new()
            .kind(Kind::NostrConnect)
            .pubkey(signer_keys.public_key());
        client.subscribe(filter, None).await.unwrap();
        let _ = ready_tx.send(());

        let mut notifications = client.notifications();
        while let Ok(notif) = notifications.recv().await {
            let RelayPoolNotification::Event { event, .. } = notif else {
                continue;
            };
            if event.kind != Kind::NostrConnect {
                continue;
            }
            let app_pubkey = event.pubkey;
            let Ok(plaintext) =
                nip44::decrypt(signer_keys.secret_key(), &app_pubkey, &event.content)
            else {
                continue;
            };
            let Ok(request): Result<serde_json::Value, _> = serde_json::from_str(&plaintext) else {
                continue;
            };
            let id = request
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");

            let response = match method {
                "connect" => serde_json::json!({"id": id, "result": "ack"}),
                "register_wallet" => serde_json::json!({"id": id, "result": hmac_hex}),
                _ => serde_json::json!({"id": id, "error": "Unknown method"}),
            };

            let body = serde_json::to_string(&response).unwrap();
            let ct = nip44::encrypt(
                signer_keys.secret_key(),
                &app_pubkey,
                &body,
                nip44::Version::V2,
            )
            .unwrap();
            let ev = EventBuilder::new(Kind::NostrConnect, ct)
                .custom_created_at(Timestamp::now())
                .tag(Tag::public_key(app_pubkey))
                .sign_with_keys(&signer_keys)
                .unwrap();
            let _ = client.send_event(&ev).await;
        }
    });

    (handle, ready_rx)
}

#[tokio::test]
async fn test_nip46_client_register_wallet_returns_hmac() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mock_relay = MockRelay::run().await.expect("mock relay");
    let relay_url = mock_relay.url().await.to_string();

    let signer_keys = Keys::generate();
    let signer_pubkey = signer_keys.public_key();
    let hmac_hex = "deadbeef".repeat(8);

    let (signer_handle, signer_ready) =
        run_stub_signer(signer_keys, relay_url.clone(), hmac_hex.clone()).await;
    signer_ready.await.expect("stub signer ready");

    let client = Nip46Client::connect_with(signer_pubkey, vec![relay_url], None, None, None)
        .await
        .expect("client connect");
    client.connect().await.expect("connect handshake");

    let resp = client
        .register_wallet("treasury", "tr([deadbeef]xpub6.../<0;1>/*)")
        .await
        .expect("register_wallet succeeds");

    let decoded = resp.hmac.expect("hmac returned");
    assert_eq!(hex::encode(decoded.as_slice()), hmac_hex);

    client.disconnect().await;
    signer_handle.abort();
}

// Pure register_wallet argument validation (empty/overlong name, empty or
// single-path descriptor, multipath order) is covered hermetically by the
// `validate_register_wallet_args_*` unit tests in `client.rs`. Those need no
// relay, so the former MockRelay-dependent empty-name integration test (which
// could fail on a port conflict or a rustls-provider install race unrelated to
// the validation under test) was removed as redundant and flaky.
