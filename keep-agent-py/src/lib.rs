// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use pyo3::prelude::*;
use pyo3::exceptions::{PyRuntimeError, PyValueError, PyConnectionError};
use std::sync::Arc;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use ::keep_agent::{
    RateLimitConfig, SessionConfig, SessionManager, SessionMetadata,
    SessionScope, SessionToken, Operation, AgentClient, ApprovalStatus, PendingSession,
};

fn to_py_err(e: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn to_py_value_err(e: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn create_runtime() -> PyResult<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create runtime: {}", e)))
}

#[pyclass]
#[derive(Clone)]
pub struct PySessionScope {
    inner: SessionScope,
}

#[pymethods]
impl PySessionScope {
    #[new]
    #[pyo3(signature = (operations=None))]
    fn new(operations: Option<Vec<String>>) -> PyResult<Self> {
        let ops: Result<Vec<Operation>, _> = operations
            .unwrap_or_else(|| vec!["sign_nostr_event".to_string(), "get_public_key".to_string()])
            .into_iter()
            .map(|s| match s.as_str() {
                "sign_nostr_event" => Ok(Operation::SignNostrEvent),
                "sign_psbt" => Ok(Operation::SignPsbt),
                "get_public_key" => Ok(Operation::GetPublicKey),
                "get_bitcoin_address" => Ok(Operation::GetBitcoinAddress),
                "nip44_encrypt" => Ok(Operation::Nip44Encrypt),
                "nip44_decrypt" => Ok(Operation::Nip44Decrypt),
                _ => Err(PyValueError::new_err(format!("Unknown operation: {}", s))),
            })
            .collect();

        Ok(Self {
            inner: SessionScope::new(ops?),
        })
    }

    #[staticmethod]
    fn nostr_only() -> Self {
        Self {
            inner: SessionScope::nostr_only(),
        }
    }

    #[staticmethod]
    fn bitcoin_only() -> Self {
        Self {
            inner: SessionScope::bitcoin_only(),
        }
    }

    #[staticmethod]
    fn full() -> Self {
        Self {
            inner: SessionScope::full(),
        }
    }

    fn with_event_kinds(&self, kinds: Vec<u16>) -> Self {
        Self {
            inner: self.inner.clone().with_event_kinds(kinds),
        }
    }

    fn with_max_amount(&self, sats: u64) -> Self {
        Self {
            inner: self.inner.clone().with_max_amount(sats),
        }
    }

    fn with_address_allowlist(&self, addresses: Vec<String>) -> Self {
        Self {
            inner: self.inner.clone().with_address_allowlist(addresses),
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyRateLimit {
    inner: RateLimitConfig,
}

#[pymethods]
impl PyRateLimit {
    #[new]
    #[pyo3(signature = (max_per_minute=10, max_per_hour=100, max_per_day=1000))]
    fn new(max_per_minute: u32, max_per_hour: u32, max_per_day: u32) -> Self {
        Self {
            inner: RateLimitConfig::new(max_per_minute, max_per_hour, max_per_day),
        }
    }

    #[staticmethod]
    fn conservative() -> Self {
        Self {
            inner: RateLimitConfig::conservative(),
        }
    }

    #[staticmethod]
    fn permissive() -> Self {
        Self {
            inner: RateLimitConfig::permissive(),
        }
    }

    #[staticmethod]
    fn strict() -> Self {
        Self {
            inner: RateLimitConfig::strict(),
        }
    }
}

#[pyclass]
pub struct PySessionInfo {
    #[pyo3(get)]
    session_id: String,
    #[pyo3(get)]
    created_at: String,
    #[pyo3(get)]
    expires_at: String,
    #[pyo3(get)]
    requests_today: u32,
    #[pyo3(get)]
    requests_remaining: u32,
}

#[pyclass]
pub struct PyAgentSession {
    manager: SessionManager,
    token: SessionToken,
    session_id: String,
    secret_key: Option<Zeroizing<[u8; 32]>>,
}

#[pymethods]
impl PyAgentSession {
    #[new]
    #[pyo3(signature = (scope, rate_limit=None, duration_hours=24, policy=None, secret_key=None))]
    fn new(
        scope: PySessionScope,
        rate_limit: Option<PyRateLimit>,
        duration_hours: u32,
        policy: Option<String>,
        secret_key: Option<String>,
    ) -> PyResult<Self> {
        let secret_bytes: Option<Zeroizing<[u8; 32]>> = if let Some(sk) = secret_key {
            let decoded = hex::decode(&sk)
                .map_err(|e| PyValueError::new_err(format!("Invalid secret key hex: {}", e)))?;
            if decoded.len() != 32 {
                return Err(PyValueError::new_err(format!(
                    "Secret key must be 32 bytes, got {}",
                    decoded.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&decoded);
            Some(Zeroizing::new(arr))
        } else {
            None
        };

        let pubkey_bytes: [u8; 32] = if let Some(ref sk) = secret_bytes {
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            let scalar = k256::NonZeroScalar::try_from(sk.as_ref().as_slice())
                .map_err(|_| PyValueError::new_err("Invalid secret key"))?;
            let pk = k256::PublicKey::from_secret_scalar(&scalar);
            let point = pk.to_encoded_point(true);
            let bytes = point.as_bytes();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[1..33]);
            arr
        } else {
            [0u8; 32]
        };

        let manager = SessionManager::new(pubkey_bytes);

        let mut config = SessionConfig::new(scope.inner)
            .with_duration_hours(duration_hours);

        if let Some(rl) = rate_limit {
            config = config.with_rate_limit(rl.inner);
        }

        if let Some(p) = policy {
            config = config.with_policy(p);
        }

        let (token, session_id) = manager
            .create_session(config, SessionMetadata::default())
            .map_err(to_py_err)?;

        Ok(Self {
            manager,
            token,
            session_id,
            secret_key: secret_bytes,
        })
    }

    fn get_session_info(&self) -> PyResult<PySessionInfo> {
        let session = self.manager
            .validate_and_get(&self.token, &self.session_id)
            .map_err(to_py_err)?;

        let info = session.info();

        Ok(PySessionInfo {
            session_id: info.session_id,
            created_at: info.created_at.to_rfc3339(),
            expires_at: info.expires_at.to_rfc3339(),
            requests_today: info.requests_today,
            requests_remaining: info.requests_remaining,
        })
    }

    fn check_operation(&self, operation: &str) -> PyResult<bool> {
        let session = self.manager
            .validate_and_get(&self.token, &self.session_id)
            .map_err(to_py_err)?;

        let op = match operation {
            "sign_nostr_event" => Operation::SignNostrEvent,
            "sign_psbt" => Operation::SignPsbt,
            "get_public_key" => Operation::GetPublicKey,
            "get_bitcoin_address" => Operation::GetBitcoinAddress,
            "nip44_encrypt" => Operation::Nip44Encrypt,
            "nip44_decrypt" => Operation::Nip44Decrypt,
            _ => return Err(PyValueError::new_err("Unknown operation")),
        };

        match session.check_operation(&op) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn check_event_kind(&self, kind: u16) -> PyResult<bool> {
        let session = self.manager
            .validate_and_get(&self.token, &self.session_id)
            .map_err(to_py_err)?;

        match session.check_event_kind(kind) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn check_amount(&self, sats: u64) -> PyResult<bool> {
        let session = self.manager
            .validate_and_get(&self.token, &self.session_id)
            .map_err(to_py_err)?;

        match session.check_amount(sats) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn record_request(&self) -> PyResult<()> {
        self.manager.record_request(&self.session_id).map_err(to_py_err)
    }

    fn close(&self) -> PyResult<bool> {
        self.manager.revoke_session(&self.session_id).map_err(to_py_err)
    }

    #[pyo3(signature = (kind, content, tags=None))]
    fn sign_event(&self, kind: u16, content: &str, tags: Option<Vec<Vec<String>>>) -> PyResult<String> {
        let session = self.manager
            .validate_and_get(&self.token, &self.session_id)
            .map_err(to_py_err)?;

        session.check_operation(&Operation::SignNostrEvent).map_err(to_py_err)?;
        session.check_event_kind(kind).map_err(to_py_err)?;

        let secret = self.secret_key.as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("No secret key configured. Pass secret_key to constructor."))?;

        self.manager.record_request(&self.session_id).map_err(to_py_err)?;

        use nostr_sdk::prelude::*;

        let hex = Zeroizing::new(hex::encode(secret.as_ref()));
        let keys = Keys::parse(hex.as_str())
            .map_err(to_py_value_err)?;

        let mut nostr_tags: Vec<Tag> = Vec::new();
        for t in tags.unwrap_or_default() {
            if t.is_empty() {
                continue;
            }
            match Tag::parse(&t) {
                Ok(tag) => nostr_tags.push(tag),
                Err(e) => {
                    return Err(PyValueError::new_err(format!(
                        "Invalid tag {:?}: {}",
                        t, e
                    )));
                }
            }
        }

        let event = EventBuilder::new(Kind::from(kind), content)
            .tags(nostr_tags)
            .sign_with_keys(&keys)
            .map_err(to_py_value_err)?;

        let tags_vec: Vec<Vec<String>> = event
            .tags
            .iter()
            .map(|t: &Tag| t.as_slice().iter().map(|s| s.to_string()).collect())
            .collect();

        let result = serde_json::json!({
            "id": event.id.to_hex(),
            "pubkey": event.pubkey.to_hex(),
            "created_at": event.created_at.as_secs(),
            "kind": u16::from(event.kind),
            "tags": tags_vec,
            "content": event.content,
            "sig": hex::encode(event.sig.serialize())
        });

        serde_json::to_string(&result).map_err(to_py_err)
    }

    #[pyo3(signature = (psbt_base64, network=None))]
    fn sign_psbt(&self, psbt_base64: &str, network: Option<&str>) -> PyResult<String> {
        let session = self.manager
            .validate_and_get(&self.token, &self.session_id)
            .map_err(to_py_err)?;

        session.check_operation(&Operation::SignPsbt).map_err(to_py_err)?;

        let mut secret = Zeroizing::new(*self.secret_key.as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("No secret key configured. Pass secret_key to constructor."))?);

        let network = match network.unwrap_or("testnet") {
            "mainnet" | "bitcoin" => keep_bitcoin::Network::Bitcoin,
            "signet" => keep_bitcoin::Network::Signet,
            "regtest" => keep_bitcoin::Network::Regtest,
            _ => keep_bitcoin::Network::Testnet,
        };

        let mut psbt = keep_bitcoin::psbt::parse_psbt_base64(psbt_base64)
            .map_err(|e| PyValueError::new_err(format!("Invalid PSBT: {}", e)))?;

        let signer = keep_bitcoin::BitcoinSigner::new(&mut *secret, network)
            .map_err(to_py_err)?;

        let analysis = signer.analyze_psbt(&psbt).map_err(to_py_err)?;

        if let Some(max_sats) = session.scope().max_amount_sats {
            if analysis.total_output_sats > max_sats {
                return Err(PyValueError::new_err(format!(
                    "Amount {} sats exceeds limit {} sats",
                    analysis.total_output_sats, max_sats
                )));
            }
        }

        if let Some(ref allowlist) = session.scope().address_allowlist {
            for output in &analysis.outputs {
                if !output.is_change {
                    if let Some(ref addr) = output.address {
                        if !allowlist.contains(&addr.to_string()) {
                            return Err(PyValueError::new_err(format!(
                                "Address {} not in allowlist",
                                addr
                            )));
                        }
                    }
                }
            }
        }

        self.manager.record_request(&self.session_id).map_err(to_py_err)?;

        signer.sign_psbt(&mut psbt).map_err(to_py_err)?;

        Ok(keep_bitcoin::psbt::serialize_psbt_base64(&psbt))
    }

    fn get_public_key(&self) -> PyResult<String> {
        let _ = self.secret_key.as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("No secret key configured"))?;

        let session = self.manager
            .validate_and_get(&self.token, &self.session_id)
            .map_err(to_py_err)?;

        session.check_operation(&Operation::GetPublicKey).map_err(to_py_err)?;

        let pubkey = session.pubkey();
        Ok(keep_core::keys::bytes_to_npub(pubkey))
    }

    #[pyo3(signature = (network=None))]
    fn get_bitcoin_address(&self, network: Option<&str>) -> PyResult<String> {
        let session = self.manager
            .validate_and_get(&self.token, &self.session_id)
            .map_err(to_py_err)?;

        session.check_operation(&Operation::GetBitcoinAddress).map_err(to_py_err)?;

        let mut secret = Zeroizing::new(*self.secret_key.as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("No secret key configured. Pass secret_key to constructor."))?);

        let network = match network.unwrap_or("testnet") {
            "mainnet" | "bitcoin" => keep_bitcoin::Network::Bitcoin,
            "signet" => keep_bitcoin::Network::Signet,
            "regtest" => keep_bitcoin::Network::Regtest,
            _ => keep_bitcoin::Network::Testnet,
        };

        let signer = keep_bitcoin::BitcoinSigner::new(&mut *secret, network)
            .map_err(to_py_err)?;

        signer.get_receive_address(0).map_err(to_py_err)
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __exit__(
        &self,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<bool> {
        self.close()?;
        Ok(false)
    }
}

#[pyclass]
pub struct PyRemoteSession {
    client: Arc<Mutex<AgentClient>>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl PyRemoteSession {
    #[staticmethod]
    #[pyo3(signature = (bunker_url, timeout_secs=30))]
    fn connect(bunker_url: &str, timeout_secs: u64) -> PyResult<Self> {
        let rt = create_runtime()?;
        let timeout = std::time::Duration::from_secs(timeout_secs);

        let client = rt.block_on(AgentClient::connect(bunker_url, timeout))
            .map_err(|e| PyConnectionError::new_err(e.to_string()))?;

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            runtime: Arc::new(rt),
        })
    }

    fn sign_event(&self, event_json: &str) -> PyResult<String> {
        let client = self.client.clone();
        self.runtime.block_on(async {
            let c = client.lock().await;
            c.sign_event(event_json).await
        }).map_err(to_py_err)
    }

    fn get_public_key(&self) -> PyResult<String> {
        let client = self.client.clone();
        self.runtime.block_on(async {
            let c = client.lock().await;
            c.get_public_key().await
        }).map_err(to_py_err)
    }

    fn nip44_encrypt(&self, pubkey: &str, plaintext: &str) -> PyResult<String> {
        let client = self.client.clone();
        self.runtime.block_on(async {
            let c = client.lock().await;
            c.nip44_encrypt(pubkey, plaintext).await
        }).map_err(to_py_err)
    }

    fn nip44_decrypt(&self, pubkey: &str, ciphertext: &str) -> PyResult<String> {
        let client = self.client.clone();
        self.runtime.block_on(async {
            let c = client.lock().await;
            c.nip44_decrypt(pubkey, ciphertext).await
        }).map_err(to_py_err)
    }

    fn ping(&self) -> PyResult<bool> {
        let client = self.client.clone();
        self.runtime.block_on(async {
            let c = client.lock().await;
            c.ping().await
        }).map_err(to_py_err)
    }

    fn switch_relays(&self) -> PyResult<Option<Vec<String>>> {
        let client = self.client.clone();
        self.runtime.block_on(async {
            let mut c = client.lock().await;
            c.switch_relays().await
        }).map_err(to_py_err)
    }

    fn disconnect(&self) -> PyResult<()> {
        let client = self.client.clone();
        self.runtime.block_on(async {
            let c = client.lock().await;
            c.disconnect().await;
        });
        Ok(())
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __exit__(
        &self,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<bool> {
        self.disconnect()?;
        Ok(false)
    }
}

#[pyclass]
pub struct PyPendingSession {
    inner: Arc<Mutex<PendingSession>>,
    runtime: Arc<tokio::runtime::Runtime>,
    request_id: String,
    approval_url: String,
}

#[pymethods]
impl PyPendingSession {
    #[staticmethod]
    #[pyo3(signature = (bunker_url, timeout_secs=30))]
    fn create(bunker_url: &str, timeout_secs: u64) -> PyResult<Self> {
        let rt = create_runtime()?;
        let timeout = std::time::Duration::from_secs(timeout_secs);

        let pending = rt.block_on(PendingSession::new(bunker_url, timeout))
            .map_err(|e| PyConnectionError::new_err(e.to_string()))?;

        let request_id = pending.request_id().to_string();
        let approval_url = pending.approval_url();

        Ok(Self {
            inner: Arc::new(Mutex::new(pending)),
            runtime: Arc::new(rt),
            request_id,
            approval_url,
        })
    }

    #[getter]
    fn request_id(&self) -> &str {
        &self.request_id
    }

    #[getter]
    fn approval_url(&self) -> &str {
        &self.approval_url
    }

    #[pyo3(signature = (timeout_secs=5))]
    fn poll(&self, timeout_secs: u64) -> PyResult<String> {
        let inner = self.inner.clone();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        let status = self.runtime.block_on(async {
            let p = inner.lock().await;
            p.poll(timeout).await
        }).map_err(to_py_err)?;

        Ok(match status {
            ApprovalStatus::Pending => "pending".to_string(),
            ApprovalStatus::Approved => "approved".to_string(),
            ApprovalStatus::Denied => "denied".to_string(),
        })
    }

    #[pyo3(signature = (timeout_secs=300))]
    fn wait_for_approval(&self, timeout_secs: u64) -> PyResult<PyRemoteSession> {
        let inner = self.inner.clone();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        let client = self.runtime.block_on(async {
            let p = inner.lock().await;
            p.wait_for_approval(timeout).await
        }).map_err(|e| PyConnectionError::new_err(e.to_string()))?;

        Ok(PyRemoteSession {
            client: Arc::new(Mutex::new(client)),
            runtime: self.runtime.clone(),
        })
    }

    fn disconnect(&self) -> PyResult<()> {
        let inner = self.inner.clone();
        self.runtime.block_on(async {
            let p = inner.lock().await;
            p.disconnect().await;
        });
        Ok(())
    }
}

#[pymodule]
fn _bindings(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySessionScope>()?;
    m.add_class::<PyRateLimit>()?;
    m.add_class::<PySessionInfo>()?;
    m.add_class::<PyAgentSession>()?;
    m.add_class::<PyRemoteSession>()?;
    m.add_class::<PyPendingSession>()?;
    Ok(())
}
