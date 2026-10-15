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
pub async fn send_connect_request(
    client: &Client,
    client_keys: &Keys,
    server_pubkey: PublicKey,
    signer_pubkey: PublicKey,
    bunker_secret: &str,
) {
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
    client.send_event(&event).await.unwrap();
}
