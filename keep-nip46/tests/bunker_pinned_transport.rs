// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! The bunker's relay socket carries remote-signing requests, so the SPKI pin
//! has to be enforced on that socket's own TLS handshake and not only on the
//! pre-flight probe the callers run first. These tests cover the two ends of
//! that: the transport is actually installed on the bunker client and still
//! serves traffic, and under strict pinning a socket that cannot be pinned
//! carries nothing.

use std::sync::Arc;
use std::time::Duration;

use nostr_relay_builder::prelude::*;
use nostr_sdk::prelude::*;
use tokio::sync::Mutex;

use keep_core::keyring::Keyring;
use keep_core::keys::{KeyType, NostrKeypair};
use keep_frost_net::{
    install_default_crypto_provider, verify_relay_certificate, CertificatePinSet, SpkiHash,
    TlsPinning,
};
use keep_nip46::{Server, ServerConfig};

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
    (
        Arc::new(Mutex::new(keyring)),
        PublicKey::from_slice(&pubkey_bytes).unwrap(),
    )
}

fn pinning(require_pinned: bool) -> TlsPinning {
    TlsPinning::new(
        Arc::new(std::sync::Mutex::new(CertificatePinSet::default())),
        require_pinned,
    )
}

/// Drive the NIP-46 connect handshake over a local mock relay.
async fn connect_handshake_reaches_bunker(config: ServerConfig) -> bool {
    install_default_crypto_provider();
    let mock_relay = MockRelay::run().await.expect("Failed to start mock relay");
    let relay_url = mock_relay.url().await.to_string();
    connect_handshake_reaches_bunker_on(&relay_url, config).await
}

/// Drive the NIP-46 connect handshake from a plain client and report whether
/// the bunker registered it, which is only possible if the bunker's own relay
/// socket carried the event.
async fn connect_handshake_reaches_bunker_on(relay_url: &str, config: ServerConfig) -> bool {
    install_default_crypto_provider();
    let relay_url = relay_url.to_string();

    let (keyring, signer_pubkey) = setup_keyring();
    let mut server = Server::new_with_config(
        keyring,
        None,
        None,
        std::slice::from_ref(&relay_url),
        None,
        config,
    )
    .await
    .expect("server creation failed");

    let bunker_secret = url::Url::parse(&server.bunker_url())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "secret")
        .map(|(_, v)| v.to_string())
        .expect("headless bunker URL must include secret");

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

    let connect_json = serde_json::json!({
        "id": "req-1",
        "method": "connect",
        "params": [signer_pubkey.to_hex(), bunker_secret]
    })
    .to_string();
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
    let connected = !server_handler.list_clients().await.is_empty();

    server_handle.abort();
    client.disconnect().await;
    connected
}

/// Installing the pinning transport must not cost the bunker its relay: with
/// pinning lenient the socket behaves exactly as the default transport did, so
/// the handshake still lands.
#[tokio::test]
async fn a_pinned_bunker_still_serves_its_relay() {
    let reached = connect_handshake_reaches_bunker(ServerConfig {
        auto_approve: true,
        tls_pinning: Some(pinning(false)),
        ..Default::default()
    })
    .await;

    assert!(
        reached,
        "pinned bunker transport dropped the connect handshake"
    );
}

/// Strict pinning has nothing to pin on a cleartext socket, so the bunker must
/// refuse it rather than serve signing requests over an unauthenticated
/// channel. Failing here means the strict toggle is cosmetic on this path.
#[tokio::test]
async fn strict_pinning_refuses_an_unpinnable_bunker_relay() {
    let reached = connect_handshake_reaches_bunker(ServerConfig {
        auto_approve: true,
        tls_pinning: Some(pinning(true)),
        ..Default::default()
    })
    .await;

    assert!(
        !reached,
        "strict pinning served the bunker over a relay socket it could not pin"
    );
}

/// The unpinned default is what every caller that sets no pinning gets, so it
/// has to keep working: this is the control for the two tests above.
#[tokio::test]
async fn an_unpinned_bunker_is_unchanged() {
    let reached = connect_handshake_reaches_bunker(ServerConfig {
        auto_approve: true,
        ..Default::default()
    })
    .await;

    assert!(reached, "default bunker transport dropped the handshake");
}

/// Live-relay checks, `#[ignore]`d like the rest of the TLS pinning tests
/// because they cross the real internet:
///
/// ```sh
/// cargo test -p keep-nip46 --test bunker_pinned_transport -- --ignored
/// ```
///
/// The mock-relay tests above run over cleartext, so they cannot show the pin
/// being checked at all. These do: remote-signing traffic crosses a socket
/// whose TLS handshake ran the pinning verifier against a real certificate,
/// and a wrong pin stops that socket from ever coming up.
const LIVE_RELAY: &str = "wss://relay.damus.io";
const LIVE_RELAY_HOST: &str = "relay.damus.io";

/// The end-to-end shape the product runs: the callers' pre-flight probe learns
/// the pin, then the bunker's own data socket enforces that value in strict
/// mode. A disagreement between the two would reject the relay the probe had
/// just accepted.
#[tokio::test]
#[ignore = "requires network access to a public relay"]
async fn a_bunker_enforces_a_probe_learned_pin_on_its_live_socket() {
    install_default_crypto_provider();

    let empty = CertificatePinSet::new();
    let (_observed, learned) = verify_relay_certificate(LIVE_RELAY, &empty, false)
        .await
        .expect("probe should trust the relay on first use");
    let (host, hash) = learned.expect("probe should surface a pin to record");
    assert_eq!(host, LIVE_RELAY_HOST);

    let mut provisioned = CertificatePinSet::new();
    provisioned.add_pin(host, hash);

    let reached = connect_handshake_reaches_bunker_on(
        LIVE_RELAY,
        ServerConfig {
            auto_approve: true,
            tls_pinning: Some(TlsPinning::new(
                Arc::new(std::sync::Mutex::new(provisioned)),
                true,
            )),
            ..Default::default()
        },
    )
    .await;

    assert!(
        reached,
        "strict pinning rejected the pin the probe had just learned from {LIVE_RELAY}"
    );
}

/// A wrong pin must stop the bunker's relay socket from coming up, which is
/// exactly the case a pre-flight probe cannot cover on the connection that
/// carries signing requests.
#[tokio::test]
#[ignore = "requires network access to a public relay"]
async fn a_mismatched_pin_blocks_the_live_bunker_socket() {
    install_default_crypto_provider();

    let mut wrong = CertificatePinSet::new();
    wrong.add_pin(LIVE_RELAY_HOST.to_string(), [0x42u8; 32] as SpkiHash);

    let reached = connect_handshake_reaches_bunker_on(
        LIVE_RELAY,
        ServerConfig {
            auto_approve: true,
            tls_pinning: Some(TlsPinning::new(
                Arc::new(std::sync::Mutex::new(wrong)),
                true,
            )),
            ..Default::default()
        },
    )
    .await;

    assert!(
        !reached,
        "the bunker served a relay whose certificate does not match the pin"
    );
}
