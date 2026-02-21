// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;

use keep_frost_net::{CertificatePinSet, SpkiHash};

fn load_cert_pins(keep_path: &Path) -> CertificatePinSet {
    let path = keep_path.join("cert-pins.json");
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return CertificatePinSet::new();
    };
    let map: HashMap<String, String> = serde_json::from_str(&contents).unwrap_or_default();
    let mut pins = CertificatePinSet::new();
    for (hostname, hex_hash) in map {
        let Ok(bytes) = hex::decode(&hex_hash) else {
            continue;
        };
        let Ok(hash) = <[u8; 32]>::try_from(bytes.as_slice()) else {
            continue;
        };
        pins.add_pin(hostname, hash);
    }
    pins
}

fn save_cert_pins(keep_path: &Path, pins: &CertificatePinSet) {
    let path = keep_path.join("cert-pins.json");
    let map: HashMap<&String, String> = pins
        .pins()
        .iter()
        .map(|(k, v)| (k, hex::encode(v)))
        .collect();
    let json = serde_json::to_string_pretty(&map).expect("serialize");
    std::fs::write(&path, &json).expect("write cert-pins.json");
}

#[test]
fn test_cert_pins_file_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut pins = CertificatePinSet::new();
    pins.add_pin("relay.damus.io".into(), [0x42; 32]);
    pins.add_pin("relay.primal.net".into(), [0xAB; 32]);

    save_cert_pins(dir.path(), &pins);

    let loaded = load_cert_pins(dir.path());
    assert_eq!(loaded.pins().len(), 2);
    assert_eq!(loaded.get_pin("relay.damus.io"), Some(&[0x42u8; 32]));
    assert_eq!(loaded.get_pin("relay.primal.net"), Some(&[0xABu8; 32]));
}

#[test]
fn test_cert_pins_file_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let loaded = load_cert_pins(dir.path());
    assert!(loaded.is_empty());
}

#[test]
fn test_cert_pins_file_display() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hash: SpkiHash = [0xDE; 32];

    let mut pins = CertificatePinSet::new();
    pins.add_pin("relay.damus.io".into(), hash);
    save_cert_pins(dir.path(), &pins);

    let contents =
        std::fs::read_to_string(dir.path().join("cert-pins.json")).expect("read");
    let map: HashMap<String, String> = serde_json::from_str(&contents).expect("parse");

    assert_eq!(map.len(), 1);
    let stored_hex = map.get("relay.damus.io").expect("key exists");
    assert_eq!(stored_hex, &hex::encode(hash));
}

#[test]
fn test_inject_bad_pin() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut pins = CertificatePinSet::new();
    pins.add_pin("relay.damus.io".into(), [0x42; 32]);
    save_cert_pins(dir.path(), &pins);

    let path = dir.path().join("cert-pins.json");
    let contents = std::fs::read_to_string(&path).expect("read");
    let mut map: HashMap<String, String> =
        serde_json::from_str(&contents).expect("parse");
    map.insert(
        "relay.damus.io".into(),
        hex::encode([0xFF; 32]),
    );
    let json = serde_json::to_string_pretty(&map).expect("serialize");
    std::fs::write(&path, &json).expect("write");

    let loaded = load_cert_pins(dir.path());
    assert_eq!(loaded.get_pin("relay.damus.io"), Some(&[0xFFu8; 32]));
}

#[test]
fn test_clear_all_pins_file() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut pins = CertificatePinSet::new();
    pins.add_pin("relay1.example.com".into(), [0x11; 32]);
    pins.add_pin("relay2.example.com".into(), [0x22; 32]);
    save_cert_pins(dir.path(), &pins);

    let empty_pins = CertificatePinSet::new();
    save_cert_pins(dir.path(), &empty_pins);

    let loaded = load_cert_pins(dir.path());
    assert!(loaded.is_empty());

    let contents =
        std::fs::read_to_string(dir.path().join("cert-pins.json")).expect("read");
    let map: HashMap<String, String> = serde_json::from_str(&contents).expect("parse");
    assert!(map.is_empty());
}
