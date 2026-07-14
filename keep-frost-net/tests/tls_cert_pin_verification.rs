// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]

use std::sync::Once;

use keep_frost_net::{
    install_default_crypto_provider, verify_relay_certificate, CertificatePinSet, FrostNetError,
    SpkiHash,
};

const TEST_RELAY: &str = "wss://relay.damus.io";
const TEST_HOSTNAME: &str = "relay.damus.io";

static SETUP: Once = Once::new();

fn setup() {
    SETUP.call_once(install_default_crypto_provider);
}

async fn fetch_pin() -> SpkiHash {
    setup();
    let pins = CertificatePinSet::new();
    let (hash, _) = verify_relay_certificate(TEST_RELAY, &pins, false)
        .await
        .expect("should connect");
    hash
}

fn roundtrip_pins(original: &CertificatePinSet) -> CertificatePinSet {
    let json = serde_json::to_vec(&original.to_hex_map()).expect("serialize");
    let (restored, malformed) = CertificatePinSet::from_json_bytes(&json).expect("deserialize");
    assert!(malformed.is_empty());
    restored
}

#[tokio::test]
#[ignore]
async fn test_tofu_returns_new_pin() {
    setup();
    let pins = CertificatePinSet::new();
    let (hash, new_pin) = verify_relay_certificate(TEST_RELAY, &pins, false)
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

    let restored_pins = roundtrip_pins(&pins);

    let (verified_hash, new_pin) = verify_relay_certificate(TEST_RELAY, &restored_pins, false)
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

    let err = verify_relay_certificate(TEST_RELAY, &pins, false)
        .await
        .expect_err("should fail with wrong pin");

    match &err {
        FrostNetError::CertificatePinMismatch {
            hostname,
            expected,
            actual,
        } => {
            assert_eq!(hostname, TEST_HOSTNAME);
            assert_eq!(expected, "***");
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
    assert!(!pins.is_pinned(TEST_HOSTNAME));

    let (new_hash, new_pin) = verify_relay_certificate(TEST_RELAY, &pins, false)
        .await
        .expect("cleared pin should allow TOFU");

    assert_eq!(new_hash, original_hash);
    let (hostname, _) = new_pin.expect("should return new pin after clearing");
    assert_eq!(hostname, TEST_HOSTNAME);
}

#[test]
fn test_pin_set_empty_all() {
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

    let restored = roundtrip_pins(&pins);
    drop(pins);

    let (verified, new_pin) = verify_relay_certificate(TEST_RELAY, &restored, false)
        .await
        .expect("should verify after lock/unlock");

    assert_eq!(verified, hash);
    assert!(new_pin.is_none());
}
