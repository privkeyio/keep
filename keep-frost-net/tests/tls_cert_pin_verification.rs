// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::collections::HashMap;

use keep_frost_net::{
    install_default_crypto_provider, verify_relay_certificate, CertificatePinSet, FrostNetError,
    SpkiHash,
};

const TEST_RELAY: &str = "wss://relay.damus.io";
const TEST_HOSTNAME: &str = "relay.damus.io";

fn setup() {
    install_default_crypto_provider();
}

async fn fetch_pin() -> SpkiHash {
    let pins = CertificatePinSet::new();
    let (hash, _) = verify_relay_certificate(TEST_RELAY, &pins)
        .await
        .expect("should connect");
    hash
}

#[tokio::test]
#[ignore]
async fn test_tofu_returns_new_pin() {
    setup();
    let pins = CertificatePinSet::new();
    let (hash, new_pin) = verify_relay_certificate(TEST_RELAY, &pins)
        .await
        .expect("TOFU connection should succeed");

    assert_ne!(hash, [0u8; 32]);
    let (hostname, pin_hash) = new_pin.expect("should return new pin for unknown host");
    assert_eq!(hostname, TEST_HOSTNAME);
    assert_eq!(pin_hash, hash);
}

#[tokio::test]
#[ignore]
async fn test_pin_persistence_reconnect() {
    setup();
    let hash = fetch_pin().await;

    let mut pins = CertificatePinSet::new();
    pins.add_pin(TEST_HOSTNAME.into(), hash);

    let serialized: HashMap<String, String> = pins
        .pins()
        .iter()
        .map(|(k, v)| (k.clone(), hex::encode(v)))
        .collect();
    let json = serde_json::to_string(&serialized).expect("serialize");

    let deserialized: HashMap<String, String> = serde_json::from_str(&json).expect("deserialize");
    let mut restored_pins = CertificatePinSet::new();
    for (hostname, hex_hash) in deserialized {
        let bytes = hex::decode(&hex_hash).expect("hex decode");
        let h: [u8; 32] = bytes.try_into().expect("32 bytes");
        restored_pins.add_pin(hostname, h);
    }

    let (verified_hash, new_pin) = verify_relay_certificate(TEST_RELAY, &restored_pins)
        .await
        .expect("reconnect with persisted pin should pass");

    assert_eq!(verified_hash, hash);
    assert!(new_pin.is_none());
}

#[tokio::test]
#[ignore]
async fn test_mismatch_detection() {
    setup();
    let actual_hash = fetch_pin().await;

    let mut pins = CertificatePinSet::new();
    let wrong_hash = [0xBB; 32];
    pins.add_pin(TEST_HOSTNAME.into(), wrong_hash);

    let err = verify_relay_certificate(TEST_RELAY, &pins)
        .await
        .expect_err("should fail with wrong pin");

    match &err {
        FrostNetError::CertificatePinMismatch {
            hostname,
            expected,
            actual,
        } => {
            assert_eq!(hostname, TEST_HOSTNAME);
            assert_eq!(expected, &hex::encode(wrong_hash));
            assert_eq!(actual, &hex::encode(actual_hash));
        }
        other => panic!("expected CertificatePinMismatch, got: {other}"),
    }
}

#[tokio::test]
#[ignore]
async fn test_clear_and_repin() {
    setup();
    let original_hash = fetch_pin().await;

    let mut pins = CertificatePinSet::new();
    pins.add_pin(TEST_HOSTNAME.into(), original_hash);
    pins.remove_pin(TEST_HOSTNAME);
    assert!(pins.get_pin(TEST_HOSTNAME).is_none());

    let (new_hash, new_pin) = verify_relay_certificate(TEST_RELAY, &pins)
        .await
        .expect("cleared pin should allow TOFU");

    assert_eq!(new_hash, original_hash);
    let (hostname, _) = new_pin.expect("should return new pin after clearing");
    assert_eq!(hostname, TEST_HOSTNAME);
}

#[tokio::test]
#[ignore]
async fn test_pin_set_empty_all() {
    setup();
    let mut pins = CertificatePinSet::new();
    pins.add_pin("relay1.example.com".into(), [0x11; 32]);
    pins.add_pin("relay2.example.com".into(), [0x22; 32]);
    pins.add_pin("relay3.example.com".into(), [0x33; 32]);
    assert_eq!(pins.pins().len(), 3);

    let hostnames: Vec<String> = pins.pins().keys().cloned().collect();
    for h in hostnames {
        pins.remove_pin(&h);
    }
    assert!(pins.is_empty());
}

#[tokio::test]
#[ignore]
async fn test_lock_unlock_cycle() {
    setup();
    let hash = fetch_pin().await;

    let mut pins = CertificatePinSet::new();
    pins.add_pin(TEST_HOSTNAME.into(), hash);

    let serialized: HashMap<String, String> = pins
        .pins()
        .iter()
        .map(|(k, v)| (k.clone(), hex::encode(v)))
        .collect();
    let json = serde_json::to_string(&serialized).expect("serialize");

    drop(pins);

    let deserialized: HashMap<String, String> = serde_json::from_str(&json).expect("deserialize");
    let mut restored = CertificatePinSet::new();
    for (hostname, hex_hash) in deserialized {
        let bytes = hex::decode(&hex_hash).expect("hex decode");
        let h: [u8; 32] = bytes.try_into().expect("32 bytes");
        restored.add_pin(hostname, h);
    }

    let (verified, new_pin) = verify_relay_certificate(TEST_RELAY, &restored)
        .await
        .expect("should verify after lock/unlock");

    assert_eq!(verified, hash);
    assert!(new_pin.is_none());
}
