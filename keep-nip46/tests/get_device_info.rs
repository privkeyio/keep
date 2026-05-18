// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use nostr_relay_builder::prelude::*;
use nostr_sdk::prelude::{
    nip44, Client, EventBuilder, Filter, Keys, Kind, RelayPoolNotification, Tag, Timestamp,
};

use keep_core::error::{KeepError, NetworkError};
use keep_nip46::{DeviceKind, Nip46Client, MAX_DEVICE_INFO_JSON_LEN};

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
    let _ = signer_handle.await;
}

#[tokio::test]
async fn test_get_device_info_malformed_payload_errors() {
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
    let _ = signer_handle.await;
}

/// Stub that returns a NIP-46-level error for `get_device_info`, exercising
/// the `response.error` branch in the client.
async fn run_unknown_method_signer(
    signer_keys: Keys,
    relay_url: String,
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
async fn test_get_device_info_unknown_method_errors() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mock_relay = MockRelay::run().await.expect("mock relay");
    let relay_url = mock_relay.url().await.to_string();

    let signer_keys = Keys::generate();
    let signer_pubkey = signer_keys.public_key();

    let (signer_handle, signer_ready) =
        run_unknown_method_signer(signer_keys, relay_url.clone()).await;
    signer_ready.await.expect("stub signer ready");

    let client = Nip46Client::connect_with(signer_pubkey, vec![relay_url], None)
        .await
        .expect("client connect");
    client.connect().await.expect("connect handshake");

    let err = client
        .get_device_info()
        .await
        .expect_err("unknown method must error");
    match err {
        KeepError::NetworkErr(NetworkError::Response { .. }) => {}
        other => panic!("unexpected error: {other:?}"),
    }

    client.disconnect().await;
    signer_handle.abort();
    let _ = signer_handle.await;
}

async fn expect_error_for_payload(payload: String) -> KeepError {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let mock_relay = MockRelay::run().await.expect("mock relay");
    let relay_url = mock_relay.url().await.to_string();
    let signer_keys = Keys::generate();
    let signer_pubkey = signer_keys.public_key();
    let (handle, ready) = run_stub_signer(signer_keys, relay_url.clone(), payload).await;
    ready.await.expect("ready");

    let client = Nip46Client::connect_with(signer_pubkey, vec![relay_url], None)
        .await
        .expect("connect");
    client.connect().await.expect("handshake");
    let err = client.get_device_info().await.expect_err("must error");

    client.disconnect().await;
    handle.abort();
    let _ = handle.await;
    err
}

#[tokio::test]
async fn test_get_device_info_rejects_oversize_json() {
    let big_cap = "a".repeat(32);
    let mut caps = String::from("[");
    for i in 0..(MAX_DEVICE_INFO_JSON_LEN / 35) {
        if i > 0 {
            caps.push(',');
        }
        caps.push_str(&format!("\"{big_cap}\""));
    }
    caps.push(']');
    let payload =
        format!(r#"{{"kind":"Coldcard","fingerprint":"deadbeef","capabilities":{caps}}}"#);
    assert!(payload.len() > MAX_DEVICE_INFO_JSON_LEN);
    let err = expect_error_for_payload(payload).await;
    match err {
        KeepError::InvalidInput(msg) => assert!(msg.contains("payload exceeds")),
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn test_get_device_info_rejects_oversize_capability_label() {
    let big_cap = "x".repeat(33);
    let payload =
        format!(r#"{{"kind":"Ledger","fingerprint":"00112233","capabilities":["{big_cap}"]}}"#);
    let err = expect_error_for_payload(payload).await;
    match err {
        KeepError::InvalidInput(msg) => assert!(msg.contains("capability label")),
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn test_get_device_info_rejects_too_many_capabilities() {
    let caps: Vec<String> = (0..33).map(|i| format!("\"c{i}\"")).collect();
    let payload = format!(
        r#"{{"kind":"Jade","fingerprint":"00112233","capabilities":[{}]}}"#,
        caps.join(",")
    );
    let err = expect_error_for_payload(payload).await;
    match err {
        KeepError::InvalidInput(msg) => assert!(msg.contains("capabilities list")),
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn test_get_device_info_rejects_oversize_other_label() {
    let label = "z".repeat(33);
    let payload =
        format!(r#"{{"kind":{{"Other":"{label}"}},"fingerprint":"deadbeef","capabilities":[]}}"#);
    let err = expect_error_for_payload(payload).await;
    match err {
        KeepError::InvalidInput(msg) => assert!(msg.contains("'Other' label")),
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn test_get_device_info_rejects_control_chars_in_other() {
    let payload =
        r#"{"kind":{"Other":"Cold\ncard"},"fingerprint":"deadbeef","capabilities":[]}"#.to_string();
    let err = expect_error_for_payload(payload).await;
    match err {
        KeepError::InvalidInput(msg) => assert!(msg.contains("control")),
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn test_get_device_info_normalizes_other_to_known_kind() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let mock_relay = MockRelay::run().await.expect("mock relay");
    let relay_url = mock_relay.url().await.to_string();
    let signer_keys = Keys::generate();
    let signer_pubkey = signer_keys.public_key();
    let payload =
        r#"{"kind":{"Other":"Coldcard"},"fingerprint":"deadbeef","capabilities":[]}"#.to_string();
    let (handle, ready) = run_stub_signer(signer_keys, relay_url.clone(), payload).await;
    ready.await.expect("ready");

    let client = Nip46Client::connect_with(signer_pubkey, vec![relay_url], None)
        .await
        .expect("connect");
    client.connect().await.expect("handshake");
    let info = client.get_device_info().await.expect("ok");
    assert_eq!(info.kind, DeviceKind::Coldcard);

    client.disconnect().await;
    handle.abort();
    let _ = handle.await;
}
