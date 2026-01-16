// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use keep_enclave_host::{
    MockEnclaveClient, NetworkParam, PolicyConfig, SignerBackend, SigningRequest,
};
use tempfile::tempdir;

fn create_mock_backend() -> MockEnclaveClient {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test-enclave.redb");
    MockEnclaveClient::with_path(&path)
}

#[test]
fn test_backend_key_lifecycle() {
    let backend = create_mock_backend();

    let pubkey = backend.generate_key("testkey").unwrap();
    assert_eq!(pubkey.len(), 32);

    let retrieved = backend.get_public_key("testkey").unwrap();
    assert_eq!(pubkey, retrieved);
}

#[test]
fn test_backend_import_key() {
    let backend = create_mock_backend();

    let secret = [42u8; 32];
    let pubkey = backend.import_key("imported", &secret).unwrap();
    assert_eq!(pubkey.len(), 32);

    let retrieved = backend.get_public_key("imported").unwrap();
    assert_eq!(pubkey, retrieved);
}

#[test]
fn test_backend_sign() {
    let backend = create_mock_backend();
    backend.generate_key("signer").unwrap();

    let request = SigningRequest {
        key_id: "signer".to_string(),
        message: b"test message".to_vec(),
        event_kind: Some(1),
        amount_sats: None,
        destination: None,
        nonce: None,
        timestamp: None,
    };

    let sig = backend.sign(request).unwrap();
    assert_eq!(sig.len(), 64);
}

#[test]
fn test_backend_sign_psbt_mock() {
    let backend = create_mock_backend();
    backend.generate_key("btckey").unwrap();

    let fake_psbt = vec![0x70, 0x73, 0x62, 0x74, 0xff];
    let (signed, _count) = backend
        .sign_psbt("btckey", &fake_psbt, NetworkParam::Testnet)
        .unwrap();

    assert!(!signed.is_empty());
}

#[test]
fn test_backend_policy() {
    let backend = create_mock_backend();

    let config = PolicyConfig { policies: vec![] };
    backend.set_policy(config).unwrap();
}

#[test]
fn test_backend_key_not_found() {
    let backend = create_mock_backend();

    let result = backend.get_public_key("nonexistent");
    assert!(result.is_err());
}

#[test]
fn test_backend_sign_nonexistent_key() {
    let backend = create_mock_backend();

    let request = SigningRequest {
        key_id: "nonexistent".to_string(),
        message: b"test".to_vec(),
        event_kind: None,
        amount_sats: None,
        destination: None,
        nonce: None,
        timestamp: None,
    };

    let result = backend.sign(request);
    assert!(result.is_err());
}

#[test]
fn test_backend_multiple_keys() {
    let backend = create_mock_backend();

    let pk1 = backend.generate_key("key1").unwrap();
    let pk2 = backend.generate_key("key2").unwrap();
    let pk3 = backend.generate_key("key3").unwrap();

    assert_ne!(pk1, pk2);
    assert_ne!(pk2, pk3);
    assert_ne!(pk1, pk3);

    assert_eq!(backend.get_public_key("key1").unwrap(), pk1);
    assert_eq!(backend.get_public_key("key2").unwrap(), pk2);
    assert_eq!(backend.get_public_key("key3").unwrap(), pk3);
}

#[test]
fn test_backend_persistence() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("persist.redb");

    let pubkey = {
        let backend = MockEnclaveClient::with_path(&path);
        backend.generate_key("persistent").unwrap()
    };

    {
        let backend = MockEnclaveClient::with_path(&path);
        let retrieved = backend.get_public_key("persistent").unwrap();
        assert_eq!(pubkey, retrieved);
    }
}

#[test]
fn test_attestation_mock() {
    use keep_enclave_host::{EnclaveRequest, EnclaveResponse};

    let backend = create_mock_backend();
    let nonce = [0x42u8; 32];

    let response = backend.process_request(EnclaveRequest::GetAttestation { nonce });
    match response {
        EnclaveResponse::Attestation { document } => {
            assert!(!document.is_empty());
        }
        _ => panic!("Expected attestation response"),
    }
}
