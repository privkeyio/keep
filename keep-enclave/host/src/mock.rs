// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use k256::schnorr::SigningKey;
use redb::{Database, ReadableDatabase, TableDefinition};
use tracing::warn;

use crate::kms::EncryptedWallet;
use crate::protocol::{
    EnclaveRequest, EnclaveResponse, ErrorCode, PsbtSigningRequest, SigningRequest,
};

#[cfg(test)]
use crate::protocol::NetworkParam;

const KEYS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("keys");
const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

const MOCK_PCR0: [u8; 48] = [0xDE; 48];
const MOCK_PCR1: [u8; 48] = [0xAD; 48];
const MOCK_PCR2: [u8; 48] = [0xBE; 48];

pub struct MockEnclaveClient {
    db: Mutex<Database>,
    path: PathBuf,
}

impl MockEnclaveClient {
    pub fn new() -> Self {
        Self::with_path(&std::env::temp_dir().join("keep-mock-enclave.redb"))
    }

    pub fn with_path(path: &Path) -> Self {
        let db = Database::create(path).expect("Failed to create mock enclave database");

        {
            let wtxn = db.begin_write().expect("Failed to begin write transaction");
            {
                let _ = wtxn.open_table(KEYS_TABLE);
                let _ = wtxn.open_table(META_TABLE);
            }
            wtxn.commit().expect("Failed to commit transaction");
        }

        Self {
            db: Mutex::new(db),
            path: path.to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn process_request(&self, request: EnclaveRequest) -> EnclaveResponse {
        match request {
            EnclaveRequest::GetAttestation { nonce } => self.mock_attestation(nonce),
            EnclaveRequest::GenerateKey { name } => self.mock_generate_key(&name),
            EnclaveRequest::ImportKey { name, secret } => self.mock_import_key(&name, &secret),
            EnclaveRequest::ImportEncryptedKey { name, encrypted } => {
                self.mock_import_encrypted_key(&name, &encrypted)
            }
            EnclaveRequest::ImportFrostKey {
                name,
                key_package,
                pubkey_package,
            } => self.mock_import_frost_key(&name, &key_package, &pubkey_package),
            EnclaveRequest::Sign(req) => self.mock_sign(req),
            EnclaveRequest::SignPsbt(req) => self.mock_sign_psbt(req),
            EnclaveRequest::GetPublicKey { key_id } => self.mock_get_public_key(&key_id),
            EnclaveRequest::SetPolicy(_) => EnclaveResponse::PolicySet,
            EnclaveRequest::FrostRound1 {
                key_id, message, ..
            } => self.mock_frost_round1(&key_id, &message),
            EnclaveRequest::FrostAddCommitment { .. } => EnclaveResponse::PolicySet,
            EnclaveRequest::FrostRound2 { session_id, .. } => self.mock_frost_round2(session_id),
        }
    }

    fn mock_attestation(&self, nonce: [u8; 32]) -> EnclaveResponse {
        let mock_doc = create_mock_attestation_document(&nonce, &self.get_ephemeral_pubkey());
        EnclaveResponse::Attestation { document: mock_doc }
    }

    fn get_ephemeral_pubkey(&self) -> [u8; 32] {
        let db = self.db.lock().unwrap();
        let rtxn = db.begin_read().unwrap();

        if let Ok(table) = rtxn.open_table(META_TABLE) {
            if let Ok(Some(data)) = table.get("ephemeral_secret") {
                let secret: [u8; 32] = data.value().try_into().unwrap_or([0u8; 32]);
                if let Ok(sk) = SigningKey::from_bytes(&secret) {
                    let mut pubkey = [0u8; 32];
                    pubkey.copy_from_slice(&sk.verifying_key().to_bytes());
                    return pubkey;
                }
            }
        }

        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).unwrap_or_default();
        drop(rtxn);

        let wtxn = db.begin_write().unwrap();
        {
            let mut table = wtxn.open_table(META_TABLE).unwrap();
            let _ = table.insert("ephemeral_secret", secret.as_slice());
        }
        wtxn.commit().unwrap();

        if let Ok(sk) = SigningKey::from_bytes(&secret) {
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&sk.verifying_key().to_bytes());
            pubkey
        } else {
            [0u8; 32]
        }
    }

    fn mock_generate_key(&self, name: &str) -> EnclaveResponse {
        let mut secret = [0u8; 32];
        if let Err(e) = getrandom::fill(&mut secret) {
            return EnclaveResponse::Error {
                code: ErrorCode::InternalError,
                message: format!("Random generation failed: {e}"),
            };
        }

        match SigningKey::from_bytes(&secret) {
            Ok(signing_key) => {
                let pubkey_bytes = signing_key.verifying_key().to_bytes();
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(&pubkey_bytes);

                let db = self.db.lock().unwrap();
                let wtxn = db.begin_write().unwrap();
                {
                    let mut table = wtxn.open_table(KEYS_TABLE).unwrap();
                    let _ = table.insert(name, secret.as_slice());
                }
                wtxn.commit().unwrap();

                warn!(
                    path = %self.path.display(),
                    name = name,
                    "MOCK: Key stored in local database (not a real enclave)"
                );

                EnclaveResponse::PublicKey {
                    pubkey: pubkey.to_vec(),
                    name: name.to_string(),
                }
            }
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::InternalError,
                message: format!("Key generation failed: {e}"),
            },
        }
    }

    fn mock_import_key(&self, name: &str, secret: &[u8]) -> EnclaveResponse {
        if secret.len() != 32 {
            return EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                message: format!("Invalid secret length: expected 32, got {}", secret.len()),
            };
        }

        let secret_arr: [u8; 32] = secret.try_into().unwrap();

        match SigningKey::from_bytes(&secret_arr) {
            Ok(signing_key) => {
                let pubkey_bytes = signing_key.verifying_key().to_bytes();
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(&pubkey_bytes);

                let db = self.db.lock().unwrap();
                let wtxn = db.begin_write().unwrap();
                {
                    let mut table = wtxn.open_table(KEYS_TABLE).unwrap();
                    let _ = table.insert(name, secret);
                }
                wtxn.commit().unwrap();

                EnclaveResponse::PublicKey {
                    pubkey: pubkey.to_vec(),
                    name: name.to_string(),
                }
            }
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::InvalidRequest,
                message: format!("Invalid key: {e}"),
            },
        }
    }

    fn mock_import_encrypted_key(
        &self,
        _name: &str,
        _encrypted: &EncryptedWallet,
    ) -> EnclaveResponse {
        EnclaveResponse::Error {
            code: ErrorCode::InternalError,
            message: "Encrypted key import requires real enclave".into(),
        }
    }

    fn mock_sign(&self, req: SigningRequest) -> EnclaveResponse {
        let db = self.db.lock().unwrap();
        let rtxn = db.begin_read().unwrap();
        let table = match rtxn.open_table(KEYS_TABLE) {
            Ok(t) => t,
            Err(e) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InternalError,
                    message: format!("Database error: {e}"),
                }
            }
        };

        let secret = match table.get(req.key_id.as_str()) {
            Ok(Some(data)) => {
                let bytes = data.value();
                let arr: [u8; 32] = match bytes.try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        return EnclaveResponse::Error {
                            code: ErrorCode::InternalError,
                            message: "Invalid stored key".into(),
                        }
                    }
                };
                arr
            }
            Ok(None) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::KeyNotFound,
                    message: format!("Key not found: {}", req.key_id),
                }
            }
            Err(e) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InternalError,
                    message: format!("Database error: {e}"),
                }
            }
        };

        match SigningKey::from_bytes(&secret) {
            Ok(signing_key) => {
                use k256::schnorr::signature::Signer;
                match signing_key.try_sign(&req.message) {
                    Ok(sig) => EnclaveResponse::Signature {
                        signature: sig.to_bytes().to_vec(),
                    },
                    Err(e) => EnclaveResponse::Error {
                        code: ErrorCode::SigningFailed,
                        message: format!("Signing failed: {e}"),
                    },
                }
            }
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::InternalError,
                message: format!("Invalid key: {e}"),
            },
        }
    }

    fn mock_sign_psbt(&self, req: PsbtSigningRequest) -> EnclaveResponse {
        let db = self.db.lock().unwrap();
        let rtxn = db.begin_read().unwrap();
        let table = match rtxn.open_table(KEYS_TABLE) {
            Ok(t) => t,
            Err(e) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InternalError,
                    message: format!("Database error: {e}"),
                }
            }
        };

        let _secret = match table.get(req.key_id.as_str()) {
            Ok(Some(data)) => {
                let bytes = data.value();
                let arr: [u8; 32] = match bytes.try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        return EnclaveResponse::Error {
                            code: ErrorCode::InternalError,
                            message: "Invalid stored key".into(),
                        }
                    }
                };
                arr
            }
            Ok(None) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::KeyNotFound,
                    message: format!("Key not found: {}", req.key_id),
                }
            }
            Err(e) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InternalError,
                    message: format!("Database error: {e}"),
                }
            }
        };

        EnclaveResponse::SignedPsbt {
            psbt: req.psbt.clone(),
            signed_inputs: 0,
        }
    }

    fn mock_get_public_key(&self, key_id: &str) -> EnclaveResponse {
        let db = self.db.lock().unwrap();
        let rtxn = db.begin_read().unwrap();
        let table = match rtxn.open_table(KEYS_TABLE) {
            Ok(t) => t,
            Err(e) => {
                return EnclaveResponse::Error {
                    code: ErrorCode::InternalError,
                    message: format!("Database error: {e}"),
                }
            }
        };

        match table.get(key_id) {
            Ok(Some(data)) => {
                let bytes = data.value();
                let secret: [u8; 32] = match bytes.try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        return EnclaveResponse::Error {
                            code: ErrorCode::InternalError,
                            message: "Invalid stored key".into(),
                        }
                    }
                };

                match SigningKey::from_bytes(&secret) {
                    Ok(sk) => {
                        let mut pubkey = [0u8; 32];
                        pubkey.copy_from_slice(&sk.verifying_key().to_bytes());
                        EnclaveResponse::PublicKey {
                            pubkey: pubkey.to_vec(),
                            name: key_id.to_string(),
                        }
                    }
                    Err(e) => EnclaveResponse::Error {
                        code: ErrorCode::InternalError,
                        message: format!("Invalid key: {e}"),
                    },
                }
            }
            Ok(None) => EnclaveResponse::Error {
                code: ErrorCode::KeyNotFound,
                message: format!("Key not found: {key_id}"),
            },
            Err(e) => EnclaveResponse::Error {
                code: ErrorCode::InternalError,
                message: format!("Database error: {e}"),
            },
        }
    }

    fn mock_import_frost_key(
        &self,
        name: &str,
        _key_package: &[u8],
        _pubkey_package: &[u8],
    ) -> EnclaveResponse {
        EnclaveResponse::PublicKey {
            pubkey: vec![0u8; 32],
            name: name.to_string(),
        }
    }

    fn mock_frost_round1(&self, _key_id: &str, _message: &[u8]) -> EnclaveResponse {
        let mut session_id = [0u8; 32];
        if let Err(e) = getrandom::fill(&mut session_id) {
            return EnclaveResponse::Error {
                code: ErrorCode::InternalError,
                message: format!("Random generation failed: {e}"),
            };
        }

        EnclaveResponse::FrostCommitment {
            commitment: vec![0u8; 66],
            nonces_id: session_id.to_vec(),
        }
    }

    fn mock_frost_round2(&self, _session_id: [u8; 32]) -> EnclaveResponse {
        EnclaveResponse::FrostShare {
            share: vec![0u8; 32],
        }
    }
}

impl Default for MockEnclaveClient {
    fn default() -> Self {
        Self::new()
    }
}

fn create_mock_attestation_document(nonce: &[u8; 32], pubkey: &[u8; 32]) -> Vec<u8> {
    let mut pcrs: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    pcrs.insert(0, MOCK_PCR0.to_vec());
    pcrs.insert(1, MOCK_PCR1.to_vec());
    pcrs.insert(2, MOCK_PCR2.to_vec());

    let module_id = format!("i-mock-{:016x}", rand_u64());
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let attestation = MockAttestationDoc {
        module_id,
        digest: "SHA384".to_string(),
        timestamp,
        pcrs,
        certificate: create_mock_certificate(),
        cabundle: vec![create_mock_certificate(), create_mock_certificate()],
        public_key: Some(pubkey.to_vec()),
        user_data: None,
        nonce: Some(nonce.to_vec()),
    };

    let mut payload = Vec::new();
    ciborium::into_writer(&attestation, &mut payload).unwrap_or_default();

    let protected = vec![0xa1, 0x01, 0x38, 0x22];
    let unprotected = ciborium::Value::Map(vec![]);

    let mut signature = [0u8; 96];
    getrandom::fill(&mut signature).unwrap_or_default();

    let cose_sign1 = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(protected),
        unprotected,
        ciborium::Value::Bytes(payload),
        ciborium::Value::Bytes(signature.to_vec()),
    ]);

    let mut document = Vec::new();
    ciborium::into_writer(&cose_sign1, &mut document).unwrap_or_default();

    document
}

fn create_mock_certificate() -> Vec<u8> {
    let mut cert = Vec::with_capacity(256);
    cert.extend_from_slice(&[0x30, 0x82, 0x01, 0x00]);

    let mut random = [0u8; 64];
    getrandom::fill(&mut random).unwrap_or_default();
    cert.extend_from_slice(&random);

    cert.resize(256, 0);
    cert
}

#[derive(serde::Serialize)]
struct MockAttestationDoc {
    module_id: String,
    digest: String,
    timestamp: u64,
    pcrs: BTreeMap<u32, Vec<u8>>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

fn rand_u64() -> u64 {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).unwrap_or_default();
    u64::from_le_bytes(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    Local,
    Dev,
    Prod,
}

impl AppMode {
    pub fn from_env() -> Self {
        match std::env::var("APP_MODE").as_deref() {
            Ok("dev") => AppMode::Dev,
            Ok("prod") => AppMode::Prod,
            _ => AppMode::Local,
        }
    }
}

impl std::fmt::Display for AppMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppMode::Local => write!(f, "local"),
            AppMode::Dev => write!(f, "dev"),
            AppMode::Prod => write!(f, "prod"),
        }
    }
}

impl std::str::FromStr for AppMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "local" => Ok(AppMode::Local),
            "dev" => Ok(AppMode::Dev),
            "prod" => Ok(AppMode::Prod),
            _ => Err(format!("Invalid app mode: {s}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_mock_generate_and_sign() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.redb");
        let client = MockEnclaveClient::with_path(&path);

        let response = client.mock_generate_key("testkey");
        let pubkey = match response {
            EnclaveResponse::PublicKey { pubkey, name } => {
                assert_eq!(name, "testkey");
                assert_eq!(pubkey.len(), 32);
                pubkey
            }
            _ => panic!("Expected PublicKey response"),
        };

        let message = b"test message";
        let sign_req = SigningRequest {
            key_id: "testkey".to_string(),
            message: message.to_vec(),
            event_kind: None,
            amount_sats: None,
            destination: None,
            nonce: None,
            timestamp: None,
        };
        let sign_response = client.mock_sign(sign_req);
        match sign_response {
            EnclaveResponse::Signature { signature } => {
                assert_eq!(signature.len(), 64);
            }
            _ => panic!("Expected Signature response"),
        }

        let get_response = client.mock_get_public_key("testkey");
        match get_response {
            EnclaveResponse::PublicKey {
                pubkey: retrieved,
                name,
            } => {
                assert_eq!(name, "testkey");
                assert_eq!(retrieved, pubkey);
            }
            _ => panic!("Expected PublicKey response"),
        }
    }

    #[test]
    fn test_mock_attestation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.redb");
        let client = MockEnclaveClient::with_path(&path);

        let nonce = [0x42u8; 32];
        let response = client.mock_attestation(nonce);

        match response {
            EnclaveResponse::Attestation { document } => {
                assert!(!document.is_empty());
            }
            _ => panic!("Expected Attestation response"),
        }
    }

    #[test]
    fn test_mock_psbt_signing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.redb");
        let client = MockEnclaveClient::with_path(&path);

        client.mock_generate_key("btckey");

        let req = PsbtSigningRequest {
            key_id: "btckey".to_string(),
            psbt: vec![0x70, 0x73, 0x62, 0x74],
            network: NetworkParam::Testnet,
            nonce: None,
            timestamp: None,
        };

        let response = client.mock_sign_psbt(req);
        match response {
            EnclaveResponse::SignedPsbt { psbt, .. } => {
                assert!(!psbt.is_empty());
            }
            _ => panic!("Expected SignedPsbt response"),
        }
    }

    #[test]
    fn test_state_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.redb");

        {
            let client = MockEnclaveClient::with_path(&path);
            client.mock_generate_key("persistent");
        }

        {
            let client = MockEnclaveClient::with_path(&path);
            let response = client.mock_get_public_key("persistent");
            match response {
                EnclaveResponse::PublicKey { name, .. } => {
                    assert_eq!(name, "persistent");
                }
                _ => panic!("Expected key to persist"),
            }
        }
    }

    #[test]
    fn test_app_mode_parsing() {
        assert_eq!("local".parse::<AppMode>().unwrap(), AppMode::Local);
        assert_eq!("dev".parse::<AppMode>().unwrap(), AppMode::Dev);
        assert_eq!("prod".parse::<AppMode>().unwrap(), AppMode::Prod);
        assert!("invalid".parse::<AppMode>().is_err());
    }
}
