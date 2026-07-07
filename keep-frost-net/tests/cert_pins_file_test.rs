// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;

use keep_frost_net::{CertificatePinSet, SpkiHash};

fn load_cert_pins(keep_path: &Path) -> CertificatePinSet {
    let path = keep_path.join("cert-pins.json");
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return CertificatePinSet::new();
    };
    CertificatePinSet::from_json_bytes(contents.as_bytes())
        .map(|(pins, _malformed)| pins)
        .unwrap_or_default()
}

fn save_cert_pins(keep_path: &Path, pins: &CertificatePinSet) {
    let path = keep_path.join("cert-pins.json");
    let json = serde_json::to_string_pretty(&pins.to_hex_map()).expect("serialize");
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
    assert_eq!(loaded.get_pins("relay.damus.io"), &[[0x42u8; 32]]);
    assert_eq!(loaded.get_pins("relay.primal.net"), &[[0xABu8; 32]]);
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

    let contents = std::fs::read_to_string(dir.path().join("cert-pins.json")).expect("read");
    let map: HashMap<String, Vec<String>> = serde_json::from_str(&contents).expect("parse");

    assert_eq!(map.len(), 1);
    let stored = map.get("relay.damus.io").expect("key exists");
    assert_eq!(stored, &vec![hex::encode(hash)]);
}

#[test]
fn test_pin_replacement_via_json_mutation() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut pins = CertificatePinSet::new();
    pins.add_pin("relay.damus.io".into(), [0x42; 32]);
    save_cert_pins(dir.path(), &pins);

    let path = dir.path().join("cert-pins.json");
    let contents = std::fs::read_to_string(&path).expect("read");
    let mut map: HashMap<String, Vec<String>> = serde_json::from_str(&contents).expect("parse");
    map.insert("relay.damus.io".into(), vec![hex::encode([0xFF; 32])]);
    let json = serde_json::to_string_pretty(&map).expect("serialize");
    std::fs::write(&path, &json).expect("write");

    let loaded = load_cert_pins(dir.path());
    assert_eq!(loaded.get_pins("relay.damus.io"), &[[0xFFu8; 32]]);
}

#[test]
fn test_load_corrupt_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cert-pins.json");
    std::fs::write(&path, "not valid json {{{").expect("write");

    let loaded = load_cert_pins(dir.path());
    assert!(loaded.is_empty());
}

#[test]
fn test_load_invalid_hex_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cert-pins.json");

    let valid_hex = hex::encode([0x42u8; 32]);
    let mut map = HashMap::new();
    map.insert("bad-hex.example.com", "not-hex");
    map.insert("wrong-len.example.com", "aabb");
    map.insert("valid.example.com", valid_hex.as_str());
    let json = serde_json::to_string_pretty(&map).expect("serialize");
    std::fs::write(&path, &json).expect("write");

    let loaded = load_cert_pins(dir.path());
    assert_eq!(loaded.pins().len(), 1);
    assert_eq!(loaded.get_pins("valid.example.com"), &[[0x42u8; 32]]);
    assert!(!loaded.is_pinned("bad-hex.example.com"));
    assert!(!loaded.is_pinned("wrong-len.example.com"));
}

#[test]
fn test_json_mutation_with_invalid_hex() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut pins = CertificatePinSet::new();
    pins.add_pin("relay.damus.io".into(), [0x42; 32]);
    save_cert_pins(dir.path(), &pins);

    let path = dir.path().join("cert-pins.json");
    let contents = std::fs::read_to_string(&path).expect("read");
    let mut map: HashMap<String, Vec<String>> = serde_json::from_str(&contents).expect("parse");
    map.insert("relay.damus.io".into(), vec!["not-hex".into()]);
    let json = serde_json::to_string_pretty(&map).expect("serialize");
    std::fs::write(&path, &json).expect("write");

    let loaded = load_cert_pins(dir.path());
    assert!(!loaded.is_pinned("relay.damus.io"));
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

    let contents = std::fs::read_to_string(dir.path().join("cert-pins.json")).expect("read");
    let map: HashMap<String, Vec<String>> = serde_json::from_str(&contents).expect("parse");
    assert!(map.is_empty());
}
