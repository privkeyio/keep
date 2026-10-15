// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]

use keep_frost_net::{
    install_default_crypto_provider, verify_relay_certificate, CertificatePinSet,
};

// The probe is a second TCP connection to the relay, so it has to take the same
// SOCKS proxy the live sockets take, and it has to hand the relay name to the
// proxy instead of resolving it here. Both are observable offline from which
// error comes back for a host that cannot resolve: a direct probe reports the
// local DNS failure, a proxied one never looks the name up and fails at the
// SOCKS handshake instead.
#[tokio::test]
async fn a_configured_proxy_reaches_the_pin_probe() {
    install_default_crypto_provider();
    let pins = CertificatePinSet::new();

    let direct = verify_relay_certificate("wss://relay.invalid", &pins, false, None)
        .await
        .expect_err("a .invalid host has nothing to connect to");
    let direct = direct.to_string();
    assert!(!direct.contains("SOCKS connect"), "{direct}");

    // Nothing listens on port 1, so the SOCKS handshake cannot complete.
    let proxied = verify_relay_certificate(
        "wss://relay.invalid",
        &pins,
        false,
        Some("127.0.0.1:1".parse().unwrap()),
    )
    .await
    .expect_err("the proxy is dead");
    let proxied = proxied.to_string();
    assert!(
        proxied.contains("SOCKS connect"),
        "the probe resolved and dialed the relay itself instead of going through the proxy: {proxied}"
    );
}

#[tokio::test]
#[ignore] // requires network
async fn test_cert_pin_trust_on_first_use() {
    install_default_crypto_provider();
    let pins = CertificatePinSet::new();
    let result = verify_relay_certificate("wss://relay.damus.io", &pins, false, None).await;

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
    let (hash, _) = verify_relay_certificate("wss://relay.damus.io", &pins, false, None)
        .await
        .expect("First connection should succeed");

    let mut pins = CertificatePinSet::new();
    pins.add_pin("relay.damus.io".into(), hash);

    let (verified_hash, new_pin) =
        verify_relay_certificate("wss://relay.damus.io", &pins, false, None)
            .await
            .expect("Pinned verification should pass");

    assert_eq!(verified_hash, hash);
    assert!(
        new_pin.is_none(),
        "Should not return new pin when pin exists and matches"
    );
}

#[tokio::test]
#[ignore] // requires network
async fn test_cert_pin_mismatch_rejects() {
    install_default_crypto_provider();
    let mut pins = CertificatePinSet::new();
    pins.add_pin("relay.damus.io".into(), [0xAA; 32]);

    let result = verify_relay_certificate("wss://relay.damus.io", &pins, false, None).await;
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
    let result = verify_relay_certificate("ws://relay.damus.io", &pins, false, None).await;
    assert!(result.is_err(), "Should reject non-wss URL");
}

#[tokio::test]
#[ignore] // requires network
async fn test_cert_pin_multiple_relays() {
    install_default_crypto_provider();
    let pins = CertificatePinSet::new();

    let (hash1, _) = verify_relay_certificate("wss://relay.damus.io", &pins, false, None)
        .await
        .expect("damus relay");

    let (hash2, _) = verify_relay_certificate("wss://relay.primal.net", &pins, false, None)
        .await
        .expect("primal relay");

    assert_ne!(
        hash1, hash2,
        "Different relays should have different cert hashes"
    );
    assert_ne!(hash1, [0u8; 32]);
    assert_ne!(hash2, [0u8; 32]);
}
