// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use keep_frost_net::{install_default_crypto_provider, verify_relay_certificate, CertificatePinSet};

#[tokio::test]
#[ignore] // requires network
async fn test_cert_pin_trust_on_first_use() {
    install_default_crypto_provider();
    let pins = CertificatePinSet::new();
    let result = verify_relay_certificate("wss://relay.damus.io", &pins).await;

    let (hash, new_pin) = result.expect("Should connect and get certificate hash");
    assert_ne!(hash, [0u8; 32], "Hash should not be all zeros");

    let (hostname, pin_hash) = new_pin.expect("Should return new pin for unknown host");
    assert_eq!(hostname, "relay.damus.io");
    assert_eq!(pin_hash, hash);
}

#[tokio::test]
#[ignore] // requires network
async fn test_cert_pin_verification_passes() {
    install_default_crypto_provider();
    let pins = CertificatePinSet::new();
    let (hash, _) = verify_relay_certificate("wss://relay.damus.io", &pins)
        .await
        .expect("First connection should succeed");

    let mut pins = CertificatePinSet::new();
    pins.add_pin("relay.damus.io".into(), hash);

    let (verified_hash, new_pin) = verify_relay_certificate("wss://relay.damus.io", &pins)
        .await
        .expect("Pinned verification should pass");

    assert_eq!(verified_hash, hash);
    assert!(new_pin.is_none(), "Should not return new pin when pin exists and matches");
}

#[tokio::test]
#[ignore] // requires network
async fn test_cert_pin_mismatch_rejects() {
    install_default_crypto_provider();
    let mut pins = CertificatePinSet::new();
    pins.add_pin("relay.damus.io".into(), [0xAA; 32]);

    let result = verify_relay_certificate("wss://relay.damus.io", &pins).await;
    assert!(result.is_err(), "Should fail with wrong pin");

    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("pin mismatch"),
        "Error should mention pin mismatch: {err_str}"
    );
}

#[tokio::test]
#[ignore] // requires network
async fn test_cert_pin_rejects_non_tls() {
    install_default_crypto_provider();
    let pins = CertificatePinSet::new();
    let result = verify_relay_certificate("ws://relay.damus.io", &pins).await;
    assert!(result.is_err(), "Should reject non-wss URL");
}

#[tokio::test]
#[ignore] // requires network
async fn test_cert_pin_multiple_relays() {
    install_default_crypto_provider();
    let pins = CertificatePinSet::new();

    let (hash1, _) = verify_relay_certificate("wss://relay.damus.io", &pins)
        .await
        .expect("damus relay");

    let (hash2, _) = verify_relay_certificate("wss://relay.primal.net", &pins)
        .await
        .expect("primal relay");

    assert_ne!(hash1, hash2, "Different relays should have different cert hashes");
    assert_ne!(hash1, [0u8; 32]);
    assert_ne!(hash2, [0u8; 32]);
}
