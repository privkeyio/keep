// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! The bunker's relay socket carries remote-signing requests, so the SPKI pin
//! has to be enforced on that socket's own TLS handshake and not only on the
//! pre-flight probe the callers run first.
//!
//! Every negative case here asserts that `Server::start` returns an error,
//! never that a client merely failed to show up within some window. An
//! absence-after-a-sleep assertion would pass on a slow runner even if the
//! pinning field were ignored outright, which is the one way these tests could
//! quietly stop testing anything.

mod common;

use std::sync::Arc;
use std::time::Duration;

use nostr_relay_builder::prelude::*;
use nostr_sdk::prelude::*;

use keep_frost_net::{
    install_default_crypto_provider, verify_relay_certificate, CertificatePinSet, SpkiHash,
    TlsPinning,
};
use keep_nip46::{Server, ServerConfig};

use common::{extract_bunker_secret, send_connect_request, setup_keyring};

/// A relay of this test's own, like every other relay test in the workspace.
/// Sharing one across the binary does not work: `MockRelay::run` spawns its
/// accept loop on the runtime that happens to win the race to build it, and
/// each `#[tokio::test]` owns its own runtime, so the relay stops serving the
/// moment that first test ends and every later test times out against a socket
/// nobody is listening on. The returned guard has to stay bound for the whole
/// test.
async fn mock_relay() -> (MockRelay, String) {
    install_default_crypto_provider();
    let mock = common::start_mock_relay().await;
    let url = mock.url().await.to_string();
    (mock, url)
}

fn pinning(require_pinned: bool) -> TlsPinning {
    TlsPinning::new(
        Arc::new(std::sync::Mutex::new(CertificatePinSet::default())),
        require_pinned,
    )
}

fn config(tls_pinning: Option<TlsPinning>) -> ServerConfig {
    ServerConfig {
        auto_approve: true,
        tls_pinning,
        ..Default::default()
    }
}

/// Build a bunker against `relay_url` and try to start it. `Err` means the
/// relay socket never came up, which under strict pinning is the refusal this
/// file is about.
async fn try_start(
    relay_url: &str,
    config: ServerConfig,
) -> Result<(), keep_core::error::KeepError> {
    install_default_crypto_provider();
    let (keyring, _) = setup_keyring();
    let mut server = Server::new_with_config(
        keyring,
        None,
        None,
        std::slice::from_ref(&relay_url.to_string()),
        None,
        config,
    )
    .await?;
    server.start().await
}

/// Start a bunker, drive a real NIP-46 connect handshake at it, and report
/// whether the bunker registered the client. That is only possible if the
/// bunker's own relay socket carried the event, so it is the positive proof
/// that installing the transport did not cost the bunker its relay.
///
/// `Err` carries why it did not land. The bunker's own `start` waits for a
/// relay to reach `Connected` and gives up, so a bunker that exited early and
/// a handshake that never arrived are two different failures with the same
/// symptom; swallowing `run`'s error would hide exactly the one worth reading.
async fn connect_handshake_reaches_bunker(
    relay_url: &str,
    config: ServerConfig,
) -> Result<(), String> {
    install_default_crypto_provider();
    let (keyring, signer_pubkey) = setup_keyring();
    let relay_url = relay_url.to_string();
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

    let bunker_secret =
        extract_bunker_secret(&server.bunker_url()).expect("headless bunker URL must have secret");
    let server_pubkey = server.pubkey();
    let server_handler = server.handler();
    let (exited_tx, mut exited) = tokio::sync::oneshot::channel();
    let server_handle = tokio::spawn(async move {
        if let Err(e) = server.run().await {
            let _ = exited_tx.send(e.to_string());
        }
    });

    let client_keys = Keys::generate();
    let client = Client::new(client_keys.clone());
    client.add_relay(relay_url).await.unwrap();
    client.connect().await;
    // The client's own socket has to be up before anything is sent, or every
    // send below is accepted by nobody and silently reports success.
    keep_frost_net::wait_for_any_relay(&client, Duration::from_secs(30))
        .await
        .map_err(|e| format!("the test client never reached the relay: {e}"))?;

    // Bounded poll rather than a fixed sleep, so the positive case is fast and
    // its deadline is explicit. The deadline has to clear the bunker's own
    // wait-for-a-relay bound with room to spare, or a loaded runner fails this
    // on the bunker still coming up rather than on anything this file tests.
    let reached = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if let Ok(why) = exited.try_recv() {
                return Err(format!("the bunker exited instead of serving: {why}"));
            }
            send_connect_request(
                &client,
                &client_keys,
                server_pubkey,
                signer_pubkey,
                &bunker_secret,
            )
            .await?;
            for _ in 0..10 {
                if !server_handler.list_clients().await.is_empty() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    })
    .await
    .unwrap_or_else(|_| Err("no client registered before the deadline".to_string()));

    server_handle.abort();
    client.disconnect().await;
    reached
}

/// Installing the pinning transport must not cost the bunker its relay: with
/// pinning lenient the socket behaves as the default transport did, so a real
/// connect handshake still lands.
#[tokio::test]
async fn a_pinned_bunker_still_serves_its_relay() {
    let (_relay, url) = mock_relay().await;
    let url = url.as_str();

    if let Err(why) = connect_handshake_reaches_bunker(url, config(Some(pinning(false)))).await {
        panic!("pinned bunker transport dropped the connect handshake: {why}");
    }
}

/// Strict pinning has nothing to pin on a cleartext socket, so the bunker must
/// refuse to start rather than publish a URL and serve signing requests over an
/// unauthenticated channel.
///
/// The lenient start against the same relay is the timing witness: it proves
/// the refusal below is attributable to `require_pinned` and not to a relay
/// that was simply never reachable from this test.
#[tokio::test]
async fn strict_pinning_refuses_a_bunker_relay_it_cannot_pin() {
    let (_relay, url) = mock_relay().await;
    let url = url.as_str();

    try_start(url, config(Some(pinning(false))))
        .await
        .expect("lenient pinning should start against the mock relay");

    let err = try_start(url, config(Some(pinning(true))))
        .await
        .expect_err("strict pinning started a bunker over a socket it cannot pin");
    println!("strict pinning refused the bunker start: {err}");
}

/// The unpinned default is what every caller that sets no pinning gets, and the
/// always-on bunkers in keep-cli and keep-web depend on it starting without
/// waiting for a relay. This is the control for the two tests above.
#[tokio::test]
async fn an_unpinned_bunker_is_unchanged() {
    let (_relay, url) = mock_relay().await;
    let url = url.as_str();

    if let Err(why) = connect_handshake_reaches_bunker(url, config(None)).await {
        panic!("default bunker transport dropped the handshake: {why}");
    }
}

/// An unpinned bunker must still start when no relay is reachable at all, since
/// the pool reconnects in the background and the always-on deployments rely on
/// that. This pins down the gate on the new start-time wait: it must apply only
/// where pinning is installed.
#[tokio::test]
async fn an_unpinned_bunker_starts_without_a_reachable_relay() {
    install_default_crypto_provider();

    try_start("ws://127.0.0.1:1", config(None))
        .await
        .expect("an unpinned bunker must start even with no relay reachable");
}

/// Live-relay checks, `#[ignore]`d like the rest of the TLS pinning tests
/// because they cross the real internet:
///
/// ```sh
/// cargo test -p keep-nip46 --test bunker_pinned_transport -- --ignored
/// ```
///
/// The mock-relay tests above run over cleartext, so they cannot show a pin
/// value being checked at all. These do: remote-signing traffic crosses a
/// socket whose TLS handshake ran the pinning verifier against a real
/// certificate, and a wrong pin stops that socket from coming up.
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
    let (_observed, learned) = verify_relay_certificate(LIVE_RELAY, &empty, false, None)
        .await
        .expect("probe should trust the relay on first use");
    let (host, hash) = learned.expect("probe should surface a pin to record");
    assert_eq!(host, LIVE_RELAY_HOST);

    let mut provisioned = CertificatePinSet::new();
    provisioned.add_pin(host, hash);
    let strict = TlsPinning::new(Arc::new(std::sync::Mutex::new(provisioned)), true);

    if let Err(why) = connect_handshake_reaches_bunker(LIVE_RELAY, config(Some(strict))).await {
        panic!(
            "strict pinning rejected the pin the probe had just learned from {LIVE_RELAY}: {why}"
        );
    }
}

/// A wrong pin must stop the bunker's relay socket from coming up, which is
/// exactly the case a pre-flight probe cannot cover on the connection that
/// carries signing requests. Asserted as a start failure, not as absence.
#[tokio::test]
#[ignore = "requires network access to a public relay"]
async fn a_mismatched_pin_blocks_the_live_bunker_socket() {
    install_default_crypto_provider();

    let mut wrong = CertificatePinSet::new();
    wrong.add_pin(LIVE_RELAY_HOST.to_string(), [0x42u8; 32] as SpkiHash);
    let strict = TlsPinning::new(Arc::new(std::sync::Mutex::new(wrong)), true);

    let err = try_start(LIVE_RELAY, config(Some(strict)))
        .await
        .expect_err("the bunker started against a relay whose certificate does not match the pin");
    println!("mismatched pin refused the bunker start: {err}");
}
