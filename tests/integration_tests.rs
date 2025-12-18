use std::path::Path;
use tempfile::tempdir;

use keep::crypto::Argon2Params;
use keep::keys::NostrKeypair;
use keep::Keep;

fn create_test_keep(path: &Path) -> Keep {
    keep::storage::Storage::create(path, "testpass123", Argon2Params::TESTING).unwrap();
    let mut keep = Keep::open(path).unwrap();
    keep.unlock("testpass123").unwrap();
    keep
}

#[test]
fn test_full_key_lifecycle() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test-keep");

    let mut keep = create_test_keep(&path);

    let pubkey = keep.generate_key("main").unwrap();
    assert_eq!(keep.keyring().len(), 1);

    let keys = keep.list_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].name, "main");
    assert_eq!(keys[0].pubkey, pubkey);

    keep.delete_key(&pubkey).unwrap();
    assert_eq!(keep.keyring().len(), 0);
    assert_eq!(keep.list_keys().unwrap().len(), 0);
}

#[test]
fn test_import_nsec() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test-keep");

    let mut keep = create_test_keep(&path);

    let keypair = NostrKeypair::generate();
    let nsec = keypair.to_nsec();
    let expected_pubkey = *keypair.public_bytes();

    let pubkey = keep.import_nsec(&nsec, "imported").unwrap();
    assert_eq!(pubkey, expected_pubkey);

    let keys = keep.list_keys().unwrap();
    assert_eq!(keys[0].name, "imported");
}

#[test]
fn test_reopen_keep() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test-keep");

    {
        let mut keep = create_test_keep(&path);
        keep.generate_key("persistent").unwrap();
    }

    {
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass123").unwrap();

        assert_eq!(keep.keyring().len(), 1);
        let slot = keep.keyring().get_by_name("persistent").unwrap();
        assert_eq!(slot.name, "persistent");
    }
}

#[test]
fn test_wrong_password_fails() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test-keep");

    create_test_keep(&path);

    let mut keep = Keep::open(&path).unwrap();
    let result = keep.unlock("wrongpassword");
    assert!(result.is_err());
}

#[test]
fn test_multiple_keys() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test-keep");

    let mut keep = create_test_keep(&path);

    keep.generate_key("key1").unwrap();
    keep.generate_key("key2").unwrap();
    keep.generate_key("key3").unwrap();

    assert_eq!(keep.keyring().len(), 3);
    assert_eq!(keep.list_keys().unwrap().len(), 3);

    assert!(keep.keyring().get_by_name("key1").is_some());
    assert!(keep.keyring().get_by_name("key2").is_some());
    assert!(keep.keyring().get_by_name("key3").is_some());
}

#[test]
fn test_duplicate_import_fails() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test-keep");

    let mut keep = create_test_keep(&path);

    let keypair = NostrKeypair::generate();
    let nsec = keypair.to_nsec();

    keep.import_nsec(&nsec, "first").unwrap();
    let result = keep.import_nsec(&nsec, "duplicate");
    assert!(result.is_err());
}

#[test]
fn test_keyring_signing() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test-keep");

    let mut keep = create_test_keep(&path);
    keep.generate_key("signer").unwrap();

    let slot = keep.keyring().get_by_name("signer").unwrap();
    let keypair = slot.to_nostr_keypair().unwrap();

    let message = b"test message";
    let sig = keypair.sign(message).unwrap();
    assert_eq!(sig.len(), 64);
}
