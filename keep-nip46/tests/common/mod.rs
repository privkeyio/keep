// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! Shared fixtures for the NIP-46 integration tests. Each test binary includes
//! this with `mod common;`, so not every binary uses every item.
#![allow(dead_code)]

use std::sync::Arc;

use nostr_sdk::prelude::*;
use tokio::sync::Mutex;

use keep_core::keyring::Keyring;
use keep_core::keys::{KeyType, NostrKeypair};

/// A keyring holding one freshly generated Nostr key, plus that key's pubkey.
pub fn setup_keyring() -> (Arc<Mutex<Keyring>>, PublicKey) {
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

/// Pull the `secret` query parameter out of a `bunker://` URL.
pub fn extract_bunker_secret(bunker_url: &str) -> Option<String> {
    let url = url::Url::parse(bunker_url).ok()?;
    url.query_pairs()
        .find(|(k, _)| k == "secret")
        .map(|(_, v)| v.to_string())
}

/// Send the NIP-46 `connect` request to a running bunker from a plain client.
///
/// `Err` when no relay took the event. `Client::send_event` resolves to `Ok`
/// even when every relay refused it, so a client whose socket is not up yet
/// sends into nothing and reports success; a caller polling for the effect
/// would then wait out its whole deadline with nothing on the wire.
pub async fn send_connect_request(
    client: &Client,
    client_keys: &Keys,
    server_pubkey: PublicKey,
    signer_pubkey: PublicKey,
    bunker_secret: &str,
) -> Result<(), String> {
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
    let event = EventBuilder::new(Kind::NostrConnect, &encrypted)
        .tag(Tag::public_key(server_pubkey))
        .sign_with_keys(client_keys)
        .unwrap();
    let output = client
        .send_event(&event)
        .await
        .map_err(|e| format!("send connect: {e}"))?;
    if output.success.is_empty() {
        let why: Vec<String> = output
            .failed
            .iter()
            .map(|(url, reason)| format!("{url}: {reason}"))
            .collect();
        return Err(format!(
            "no relay accepted the connect request ({})",
            if why.is_empty() {
                "no connected relays".to_string()
            } else {
                why.join("; ")
            }
        ));
    }
    Ok(())
}

/// Start a `MockRelay`, retrying a start that lost the race for its port.
///
/// `nostr-relay-builder` picks a random free port by binding a probe listener
/// and dropping it before binding the address for real, so two starts racing in
/// this binary's parallel tests can pick the same port and the loser gets
/// `AddrInUse`. Each attempt is a fresh `MockRelay`, which is what draws a new
/// port: the chosen port is memoized per relay. Binding port 0 instead is not
/// an option, because the relay reports the address it was given, so its URL
/// would say port 0.
pub async fn start_mock_relay() -> nostr_relay_builder::MockRelay {
    let mut last = None;
    for _ in 0..8 {
        match nostr_relay_builder::MockRelay::run().await {
            Ok(relay) => return relay,
            Err(e) => last = Some(e),
        }
    }
    panic!("mock relay start: {}", last.expect("a failure to report"));
}
