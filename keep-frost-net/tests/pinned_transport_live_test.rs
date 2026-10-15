// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! Live-relay checks for the SPKI-pinned transport.
//!
//! These hit a public relay over the real internet, so they are `#[ignore]`d
//! like the other TLS pinning tests and are run explicitly:
//!
//! ```sh
//! cargo test -p keep-frost-net --test pinned_transport_live_test -- --ignored
//! ```
//!
//! What they establish, which no offline test can: relay traffic actually flows
//! over a socket whose handshake ran our pinning verifier, a pin the pre-flight
//! probe learned is then enforced on that socket, and a wrong pin stops the
//! socket from ever coming up. Those are the claims the data-channel pin rests
//! on. They also pin down the read-only contract: the live handshake must never
//! write a pin into the shared set.

use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use keep_frost_net::{
    install_default_crypto_provider, verify_relay_certificate, CertificatePinSet,
    PinnedWebSocketTransport, SpkiHash, TlsPinning,
};
use nostr_sdk::prelude::*;

const RELAY: &str = "wss://relay.damus.io";
const RELAY_HOST: &str = "relay.damus.io";

static SETUP: Once = Once::new();

fn setup() {
    SETUP.call_once(install_default_crypto_provider);
}

fn pinned_client(pins: Arc<Mutex<CertificatePinSet>>, require_pinned: bool) -> Client {
    let transport = PinnedWebSocketTransport::new(TlsPinning::new(pins, require_pinned))
        .expect("build pinned transport");
    Client::builder()
        .signer(Keys::generate())
        .websocket_transport(transport)
        .build()
}

/// Bounded wait for the relay to report `Connected`.
async fn reaches_connected(client: &Client, within: Duration) -> bool {
    tokio::time::timeout(within, async {
        loop {
            let connected = client
                .relays()
                .await
                .values()
                .any(|r| matches!(r.status(), RelayStatus::Connected));
            if connected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .is_ok()
}

/// The connection comes up through our verifier and real events flow over it,
/// and with no pin on record the handshake accepts on CA validation alone
/// WITHOUT recording anything into the shared set.
#[tokio::test]
#[ignore = "requires network access to a public relay"]
async fn pinned_transport_connects_without_recording_a_pin() {
    setup();

    let pins = Arc::new(Mutex::new(CertificatePinSet::new()));
    let client = pinned_client(pins.clone(), false);
    client.add_relay(RELAY).await.expect("add relay");
    client.connect().await;

    assert!(
        reaches_connected(&client, Duration::from_secs(20)).await,
        "pinned transport never reached Connected against {RELAY}"
    );

    // Traffic over the pinned socket, not just a handshake: ask the relay for a
    // few events and require the request itself to succeed.
    let events = client
        .fetch_events(
            Filter::new().kind(Kind::TextNote).limit(1),
            Duration::from_secs(15),
        )
        .await
        .expect("fetch events over the pinned connection");
    println!("fetched {} event(s) over the pinned socket", events.len());

    // The read-only contract, over a real handshake: learning a pin belongs to
    // the probe, so a live connection must leave the set exactly as it found it.
    // This is what stops a reconnect from re-adding a pin the user cleared.
    let recorded = {
        let guard = pins.lock().unwrap();
        guard.get_pins(RELAY_HOST).to_vec()
    };
    assert!(
        recorded.is_empty(),
        "the live handshake recorded {recorded:?}; it must only ever enforce pins"
    );

    client.disconnect().await;
}

/// The pin the pre-flight probe learns is the one the live socket enforces.
///
/// This is the end-to-end shape the product actually runs: the probe learns and
/// persists under the caller's lock, then the data socket enforces that value in
/// strict mode. If the two keyed or hashed a certificate differently, strict
/// mode here would reject the relay the probe had just accepted.
#[tokio::test]
#[ignore = "requires network access to a public relay"]
async fn a_pin_learned_by_the_probe_is_enforced_on_the_live_socket() {
    setup();

    // Learn the pin the way the shipped callers do: on the pre-flight probe.
    let empty = CertificatePinSet::new();
    let (observed, learned) = verify_relay_certificate(RELAY, &empty, false, None)
        .await
        .expect("probe should trust the relay on first use");
    let (host, hash) = learned.expect("probe should surface a pin to record");
    assert_eq!(host, RELAY_HOST);
    assert_eq!(hash, observed);

    // Re-connect in strict mode against exactly that pin.
    let mut provisioned = CertificatePinSet::new();
    provisioned.add_pin(host, hash);
    let strict = pinned_client(Arc::new(Mutex::new(provisioned)), true);
    strict.add_relay(RELAY).await.expect("add relay");
    strict.connect().await;
    assert!(
        reaches_connected(&strict, Duration::from_secs(20)).await,
        "strict mode rejected the pin the probe had just learned from the same relay"
    );

    strict.disconnect().await;
}

/// A wrong pin must stop the data socket from ever coming up. This is the case
/// the pre-flight probe cannot cover on the connection that carries data.
#[tokio::test]
#[ignore = "requires network access to a public relay"]
async fn a_mismatched_pin_blocks_the_live_connection() {
    setup();

    let mut wrong = CertificatePinSet::new();
    wrong.add_pin(RELAY_HOST.to_string(), [0x42u8; 32] as SpkiHash);

    let client = pinned_client(Arc::new(Mutex::new(wrong)), true);
    client.add_relay(RELAY).await.expect("add relay");
    client.connect().await;

    // Generous window: the point is that it never connects, so this must not
    // pass merely by being checked too early.
    assert!(
        !reaches_connected(&client, Duration::from_secs(15)).await,
        "a relay presenting a certificate that does not match the pin was accepted"
    );

    client.disconnect().await;
}
