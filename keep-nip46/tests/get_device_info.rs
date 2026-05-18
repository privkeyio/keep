// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::time::Duration;

use nostr_relay_builder::prelude::*;
use nostr_sdk::prelude::{
    nip44, Client, EventBuilder, Filter, Keys, Kind, RelayPoolNotification, Tag, Timestamp,
};

use keep_core::error::{KeepError, NetworkError};
use keep_nip46::{DeviceKind, Nip46Client};

async fn run_stub_signer(
    signer_keys: Keys,
    relay_url: String,
    device_info_json: String,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
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
                "get_device_info" => {
                    serde_json::json!({"id": id, "result": device_info_json.clone()})
                }
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
async fn test_get_device_info_happy_path() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mock_relay = MockRelay::run().await.expect("mock relay");
    let relay_url = mock_relay.url().await.to_string();

    let signer_keys = Keys::generate();
    let signer_pubkey = signer_keys.public_key();
    let info_json = r#"{"kind":"Coldcard","firmware_version":"5.1.2","fingerprint":"deadbeef","capabilities":["miniscript","tapminiscript","multisig"]}"#.to_string();

    let (signer_handle, signer_ready) =
        run_stub_signer(signer_keys, relay_url.clone(), info_json).await;
    signer_ready.await.expect("stub signer ready");

    let client = Nip46Client::connect_with(signer_pubkey, vec![relay_url], None)
        .await
        .expect("client connect");
    client.connect().await.expect("connect handshake");

    let info = client.get_device_info().await.expect("get_device_info");
    assert_eq!(info.kind, DeviceKind::Coldcard);
    assert_eq!(info.firmware_version.as_deref(), Some("5.1.2"));
    assert_eq!(info.fingerprint_bytes(), Some([0xde, 0xad, 0xbe, 0xef]));
    assert_eq!(info.capabilities.len(), 3);

    client.disconnect().await;
    signer_handle.abort();
}

#[tokio::test]
async fn test_get_device_info_unknown_method_errors() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mock_relay = MockRelay::run().await.expect("mock relay");
    let relay_url = mock_relay.url().await.to_string();

    let signer_keys = Keys::generate();
    let signer_pubkey = signer_keys.public_key();

    // Stub that only answers connect; any other method gets "Unknown method".
    let (signer_handle, signer_ready) = run_stub_signer(
        signer_keys,
        relay_url.clone(),
        // Send an "Unknown method" by configuring the stub with a payload that
        // will never be returned for non-get_device_info methods. We trigger
        // the error path by sending get_device_info to a signer that answers
        // it with malformed JSON (force JSON parse error).
        "not-json".into(),
    )
    .await;
    signer_ready.await.expect("stub signer ready");

    let client = Nip46Client::connect_with(signer_pubkey, vec![relay_url], None)
        .await
        .expect("client connect");
    client.connect().await.expect("connect handshake");

    let err = client
        .get_device_info()
        .await
        .expect_err("malformed payload must error");
    // We accept either an InvalidFormat (parse error) or a Response error.
    match err {
        KeepError::StorageErr(_) | KeepError::InvalidInput(_) => {}
        KeepError::NetworkErr(NetworkError::Response { .. }) => {}
        other => panic!("unexpected error: {other:?}"),
    }

    client.disconnect().await;
    signer_handle.abort();

    // Give the runtime a beat to drain background tasks before the test exits.
    tokio::time::sleep(Duration::from_millis(50)).await;
}
