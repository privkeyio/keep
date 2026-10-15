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
//! over a socket whose handshake ran our pinning verifier, and a wrong pin stops
//! that socket from ever coming up. Those are the two claims the data-channel
//! pin rests on.

use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use keep_frost_net::{
    install_default_crypto_provider, CertificatePinSet, PinnedWebSocketTransport, SpkiHash,
    TlsPinning,
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

/// Trust-on-first-use over the live socket: the connection comes up, real
/// events flow, and the pin recorded is the one from that very handshake.
#[tokio::test]
#[ignore = "requires network access to a public relay"]
async fn pinned_transport_connects_and_records_the_live_pin() {
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

    let recorded = {
        let guard = pins.lock().unwrap();
        guard.get_pins(RELAY_HOST).to_vec()
    };
    assert_eq!(
        recorded.len(),
        1,
        "exactly one pin should have been recorded for {RELAY_HOST}, got {recorded:?}"
    );

    client.disconnect().await;
}

/// The pin recorded on a live handshake is accepted by a later strict-mode
/// connection, so trust-on-first-use and enforcement agree on the same value.
#[tokio::test]
#[ignore = "requires network access to a public relay"]
async fn a_pin_learned_live_is_accepted_in_strict_mode() {
    setup();

    // Learn the pin.
    let learned = Arc::new(Mutex::new(CertificatePinSet::new()));
    let first = pinned_client(learned.clone(), false);
    first.add_relay(RELAY).await.expect("add relay");
    first.connect().await;
    assert!(
        reaches_connected(&first, Duration::from_secs(20)).await,
        "first (trust-on-first-use) connection never came up"
    );
    first.disconnect().await;

    let hashes = {
        let guard = learned.lock().unwrap();
        guard.get_pins(RELAY_HOST).to_vec()
    };
    assert!(!hashes.is_empty(), "no pin was learned to re-use");

    // Re-connect in strict mode against exactly that pin.
    let mut provisioned = CertificatePinSet::new();
    for hash in hashes {
        provisioned.add_pin(RELAY_HOST.to_string(), hash);
    }
    let strict = pinned_client(Arc::new(Mutex::new(provisioned)), true);
    strict.add_relay(RELAY).await.expect("add relay");
    strict.connect().await;
    assert!(
        reaches_connected(&strict, Duration::from_secs(20)).await,
        "strict mode rejected the pin it had just learned from the same relay"
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
