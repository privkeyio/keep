// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![deny(unsafe_code)]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::sync::Arc;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use keep_agent::{
    AgentClient, ApprovalStatus, Operation, PendingSession as RustPendingSession,
    RateLimitConfig, SessionConfig, SessionManager, SessionMetadata, SessionScope, SessionToken,
};

#[napi(object)]
pub struct SessionScopeConfig {
    pub operations: Option<Vec<String>>,
    pub event_kinds: Option<Vec<u32>>,
    pub max_amount_sats: Option<i64>,
    pub address_allowlist: Option<Vec<String>>,
}

#[napi(object)]
pub struct RateLimitOptions {
    pub max_per_minute: Option<u32>,
    pub max_per_hour: Option<u32>,
    pub max_per_day: Option<u32>,
}

#[napi(object)]
pub struct SessionInfoResult {
    pub session_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub requests_today: u32,
    pub requests_remaining: u32,
}

#[napi(object)]
pub struct SignedEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

#[napi]
pub struct KeepAgentSession {
    manager: SessionManager,
    token: Arc<Mutex<SessionToken>>,
    session_id: String,
    secret_key: Option<Zeroizing<[u8; 32]>>,
}

#[napi]
impl KeepAgentSession {
    #[napi(constructor)]
    pub fn new(
        scope_config: Option<SessionScopeConfig>,
        rate_limit: Option<RateLimitOptions>,
        duration_hours: Option<u32>,
        policy: Option<String>,
        secret_key: Option<String>,
    ) -> Result<Self> {
        let secret_bytes: Option<Zeroizing<[u8; 32]>> = if let Some(ref sk) = secret_key {
            let decoded = hex::decode(sk)
                .map_err(|e| Error::from_reason(format!("Invalid secret key hex: {}", e)))?;
            if decoded.len() != 32 {
                return Err(Error::from_reason(format!(
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

        let pubkey: [u8; 32] = if let Some(ref sk) = secret_bytes {
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            let scalar = k256::NonZeroScalar::try_from(sk.as_ref().as_slice())
                .map_err(|_| Error::from_reason("Invalid secret key"))?;
            let pk = k256::PublicKey::from_secret_scalar(&scalar);
            let point = pk.to_encoded_point(true);
            let bytes = point.as_bytes();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[1..33]);
            arr
        } else {
            [0u8; 32]
        };

        let manager = SessionManager::new(pubkey);

        let scope = if let Some(config) = scope_config {
            let ops: Vec<Operation> = config
                .operations
                .unwrap_or_else(|| vec!["sign_nostr_event".to_string(), "get_public_key".to_string()])
                .into_iter()
                .filter_map(|s| match s.as_str() {
                    "sign_nostr_event" => Some(Operation::SignNostrEvent),
                    "sign_psbt" => Some(Operation::SignPsbt),
                    "get_public_key" => Some(Operation::GetPublicKey),
                    "get_bitcoin_address" => Some(Operation::GetBitcoinAddress),
                    "nip44_encrypt" => Some(Operation::Nip44Encrypt),
                    "nip44_decrypt" => Some(Operation::Nip44Decrypt),
                    _ => None,
                })
                .collect();

            let mut scope = SessionScope::new(ops);

            if let Some(kinds) = config.event_kinds {
                let original_len = kinds.len();
                let valid_kinds: Vec<u16> = kinds
                    .into_iter()
                    .filter_map(|k| {
                        if k <= u16::MAX as u32 {
                            Some(k as u16)
                        } else {
                            None
                        }
                    })
                    .collect();
                if valid_kinds.is_empty() && original_len > 0 {
                    return Err(Error::from_reason("All event kinds exceed u16::MAX"));
                }
                scope = scope.with_event_kinds(valid_kinds);
            }
            if let Some(max) = config.max_amount_sats {
                if max < 0 {
                    return Err(Error::from_reason("max_amount_sats must be non-negative".to_string()));
                }
                scope = scope.with_max_amount(max as u64);
            }
            if let Some(addrs) = config.address_allowlist {
                scope = scope.with_address_allowlist(addrs);
            }
            scope
        } else {
            SessionScope::nostr_only()
        };

        let rl = if let Some(config) = rate_limit {
            RateLimitConfig::new(
                config.max_per_minute.unwrap_or(10),
                config.max_per_hour.unwrap_or(100),
                config.max_per_day.unwrap_or(1000),
            )
        } else {
            RateLimitConfig::conservative()
        };

        let mut session_config = SessionConfig::new(scope)
            .with_rate_limit(rl)
            .with_duration_hours(duration_hours.unwrap_or(24));

        if let Some(p) = policy {
            session_config = session_config.with_policy(p);
        }

        let (token, session_id) = manager
            .create_session(session_config, SessionMetadata::default())
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Self {
            manager,
            token: Arc::new(Mutex::new(token)),
            session_id,
            secret_key: secret_bytes,
        })
    }

    #[napi]
    pub async fn get_session_info(&self) -> Result<SessionInfoResult> {
        let token = self.token.lock().await;
        let session = self
            .manager
            .validate_and_get(&token, &self.session_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let info = session.info();

        Ok(SessionInfoResult {
            session_id: info.session_id,
            created_at: info.created_at.to_rfc3339(),
            expires_at: info.expires_at.to_rfc3339(),
            requests_today: info.requests_today,
            requests_remaining: info.requests_remaining,
        })
    }

    #[napi]
    pub async fn check_operation(&self, operation: String) -> Result<bool> {
        let token = self.token.lock().await;
        let session = self
            .manager
            .validate_and_get(&token, &self.session_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let op = match operation.as_str() {
            "sign_nostr_event" => Operation::SignNostrEvent,
            "sign_psbt" => Operation::SignPsbt,
            "get_public_key" => Operation::GetPublicKey,
            "get_bitcoin_address" => Operation::GetBitcoinAddress,
            "nip44_encrypt" => Operation::Nip44Encrypt,
            "nip44_decrypt" => Operation::Nip44Decrypt,
            _ => return Err(Error::from_reason("Unknown operation")),
        };

        Ok(session.check_operation(&op).is_ok())
    }

    #[napi]
    pub async fn check_event_kind(&self, kind: u32) -> Result<bool> {
        if kind > u16::MAX as u32 {
            return Err(Error::from_reason(format!(
                "Event kind {} exceeds maximum value {}",
                kind,
                u16::MAX
            )));
        }
        let token = self.token.lock().await;
        let session = self
            .manager
            .validate_and_get(&token, &self.session_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(session.check_event_kind(kind as u16).is_ok())
    }

    #[napi]
    pub async fn check_amount(&self, sats: i64) -> Result<bool> {
        if sats < 0 {
            return Err(Error::from_reason("sats must be non-negative".to_string()));
        }
        let token = self.token.lock().await;
        let session = self
            .manager
            .validate_and_get(&token, &self.session_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(session.check_amount(sats as u64).is_ok())
    }

    #[napi]
    pub async fn check_address(&self, address: String) -> Result<bool> {
        let token = self.token.lock().await;
        let session = self
            .manager
            .validate_and_get(&token, &self.session_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(session.check_address(&address).is_ok())
    }

    #[napi]
    pub fn record_request(&self) -> Result<()> {
        self.manager
            .record_request(&self.session_id)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn close(&self) -> Result<bool> {
        self.manager
            .revoke_session(&self.session_id)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn sign_event(
        &self,
        kind: u32,
        content: String,
        tags: Option<Vec<Vec<String>>>,
    ) -> Result<SignedEvent> {
        if kind > u16::MAX as u32 {
            return Err(Error::from_reason(format!(
                "Event kind {} exceeds maximum value {}",
                kind,
                u16::MAX
            )));
        }

        let token = self.token.lock().await;
        let session = self
            .manager
            .validate_and_get(&token, &self.session_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        session
            .check_operation(&Operation::SignNostrEvent)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        session
            .check_event_kind(kind as u16)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let secret = self
            .secret_key
            .as_ref()
            .ok_or_else(|| Error::from_reason("No secret key configured"))?;

        self.manager
            .record_request(&self.session_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        use nostr_sdk::prelude::{EventBuilder, Keys, Kind, Tag};

        let hex = Zeroizing::new(hex::encode(secret.as_ref()));
        let keys = Keys::parse(hex.as_str())
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;

        let nostr_tags: Vec<Tag> = tags
            .unwrap_or_default()
            .into_iter()
            .filter_map(|t| {
                if t.is_empty() {
                    None
                } else {
                    Tag::parse(&t).ok()
                }
            })
            .collect();

        let event = EventBuilder::new(Kind::from(kind as u16), &content)
            .tags(nostr_tags)
            .sign_with_keys(&keys)
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;

        let tags_vec: Vec<Vec<String>> = event
            .tags
            .iter()
            .map(|t: &Tag| t.as_slice().iter().map(|s| s.to_string()).collect())
            .collect();

        Ok(SignedEvent {
            id: event.id.to_hex(),
            pubkey: event.pubkey.to_hex(),
            created_at: event.created_at.as_secs() as i64,
            kind: u16::from(event.kind) as u32,
            tags: tags_vec,
            content: event.content.clone(),
            sig: hex::encode(event.sig.serialize()),
        })
    }

    #[napi]
    pub async fn sign_psbt(
        &self,
        psbt_base64: String,
        network: Option<String>,
    ) -> Result<String> {
        let token = self.token.lock().await;
        let session = self
            .manager
            .validate_and_get(&token, &self.session_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        session
            .check_operation(&Operation::SignPsbt)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let mut secret = Zeroizing::new(*self
            .secret_key
            .as_ref()
            .ok_or_else(|| Error::from_reason("No secret key configured"))?);

        let network = match network.as_deref().unwrap_or("testnet") {
            "mainnet" | "bitcoin" => keep_bitcoin::Network::Bitcoin,
            "signet" => keep_bitcoin::Network::Signet,
            "regtest" => keep_bitcoin::Network::Regtest,
            _ => keep_bitcoin::Network::Testnet,
        };

        let mut psbt = keep_bitcoin::psbt::parse_psbt_base64(&psbt_base64)
            .map_err(|e| Error::from_reason(format!("Invalid PSBT: {}", e)))?;

        let signer = keep_bitcoin::BitcoinSigner::new(&mut *secret, network)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let analysis = signer
            .analyze_psbt(&psbt)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        if let Some(max_sats) = session.scope().max_amount_sats {
            if analysis.total_output_sats > max_sats {
                return Err(Error::from_reason(format!(
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
                            return Err(Error::from_reason(format!(
                                "Address {} not in allowlist",
                                addr
                            )));
                        }
                    }
                }
            }
        }

        self.manager
            .record_request(&self.session_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        signer.sign_psbt(&mut psbt).map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(keep_bitcoin::psbt::serialize_psbt_base64(&psbt))
    }

    #[napi]
    pub async fn get_public_key(&self) -> Result<String> {
        let token = self.token.lock().await;
        let session = self
            .manager
            .validate_and_get(&token, &self.session_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        session
            .check_operation(&Operation::GetPublicKey)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let pubkey = session.pubkey();
        Ok(keep_core::keys::bytes_to_npub(pubkey))
    }

    #[napi]
    pub async fn get_bitcoin_address(&self, network: Option<String>) -> Result<String> {
        let token = self.token.lock().await;
        let session = self
            .manager
            .validate_and_get(&token, &self.session_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        session
            .check_operation(&Operation::GetBitcoinAddress)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let mut secret = Zeroizing::new(*self
            .secret_key
            .as_ref()
            .ok_or_else(|| Error::from_reason("No secret key configured"))?);

        let network = match network.as_deref().unwrap_or("testnet") {
            "mainnet" | "bitcoin" => keep_bitcoin::Network::Bitcoin,
            "signet" => keep_bitcoin::Network::Signet,
            "regtest" => keep_bitcoin::Network::Regtest,
            _ => keep_bitcoin::Network::Testnet,
        };

        let signer = keep_bitcoin::BitcoinSigner::new(&mut *secret, network)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        signer
            .get_receive_address(0)
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}

#[napi]
pub struct RemoteSession {
    client: Arc<Mutex<AgentClient>>,
}

#[napi]
impl RemoteSession {
    #[napi(factory)]
    pub async fn connect(bunker_url: String, timeout_seconds: Option<u32>) -> Result<Self> {
        let timeout = std::time::Duration::from_secs(timeout_seconds.unwrap_or(30) as u64);

        let client = AgentClient::connect(&bunker_url, timeout)
            .await
            .map_err(|e| Error::from_reason(format!("Connection failed: {}", e)))?;

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
        })
    }

    #[napi]
    pub async fn sign_event(&self, event_json: String) -> Result<String> {
        let client = self.client.lock().await;
        client
            .sign_event(&event_json)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn get_public_key(&self) -> Result<String> {
        let client = self.client.lock().await;
        client
            .get_public_key()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn nip44_encrypt(&self, pubkey: String, plaintext: String) -> Result<String> {
        let client = self.client.lock().await;
        client
            .nip44_encrypt(&pubkey, &plaintext)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn nip44_decrypt(&self, pubkey: String, ciphertext: String) -> Result<String> {
        let client = self.client.lock().await;
        client
            .nip44_decrypt(&pubkey, &ciphertext)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn ping(&self) -> Result<bool> {
        let client = self.client.lock().await;
        client
            .ping()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn switch_relays(&self) -> Result<Option<Vec<String>>> {
        let mut client = self.client.lock().await;
        client
            .switch_relays()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn disconnect(&self) -> Result<()> {
        let client = self.client.lock().await;
        client.disconnect().await;
        Ok(())
    }
}

#[napi]
pub struct PendingSession {
    inner: Arc<Mutex<RustPendingSession>>,
    request_id: String,
    approval_url: String,
}

#[napi]
impl PendingSession {
    #[napi(factory)]
    pub async fn create(bunker_url: String, timeout_seconds: Option<u32>) -> Result<Self> {
        let timeout = std::time::Duration::from_secs(timeout_seconds.unwrap_or(30) as u64);

        let pending = RustPendingSession::new(&bunker_url, timeout)
            .await
            .map_err(|e| Error::from_reason(format!("Connection failed: {}", e)))?;

        let request_id = pending.request_id().to_string();
        let approval_url = pending.approval_url();

        Ok(Self {
            inner: Arc::new(Mutex::new(pending)),
            request_id,
            approval_url,
        })
    }

    #[napi(getter)]
    pub fn request_id(&self) -> String {
        self.request_id.clone()
    }

    #[napi(getter)]
    pub fn approval_url(&self) -> String {
        self.approval_url.clone()
    }

    #[napi]
    pub async fn poll(&self, timeout_seconds: Option<u32>) -> Result<String> {
        let timeout = std::time::Duration::from_secs(timeout_seconds.unwrap_or(5) as u64);
        let inner = self.inner.lock().await;

        let status = inner
            .poll(timeout)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(match status {
            ApprovalStatus::Pending => "pending".to_string(),
            ApprovalStatus::Approved => "approved".to_string(),
            ApprovalStatus::Denied => "denied".to_string(),
        })
    }

    #[napi]
    pub async fn wait_for_approval(&self, timeout_seconds: Option<u32>) -> Result<RemoteSession> {
        let timeout = std::time::Duration::from_secs(timeout_seconds.unwrap_or(300) as u64);
        let inner = self.inner.lock().await;

        let client = inner
            .wait_for_approval(timeout)
            .await
            .map_err(|e| Error::from_reason(format!("Approval failed: {}", e)))?;

        Ok(RemoteSession {
            client: Arc::new(Mutex::new(client)),
        })
    }

    #[napi]
    pub async fn disconnect(&self) -> Result<()> {
        let inner = self.inner.lock().await;
        inner.disconnect().await;
        Ok(())
    }
}

#[napi]
pub fn create_nostr_scope() -> SessionScopeConfig {
    SessionScopeConfig {
        operations: Some(vec![
            "sign_nostr_event".to_string(),
            "get_public_key".to_string(),
        ]),
        event_kinds: None,
        max_amount_sats: None,
        address_allowlist: None,
    }
}

#[napi]
pub fn create_bitcoin_scope() -> SessionScopeConfig {
    SessionScopeConfig {
        operations: Some(vec![
            "sign_psbt".to_string(),
            "get_public_key".to_string(),
            "get_bitcoin_address".to_string(),
        ]),
        event_kinds: None,
        max_amount_sats: None,
        address_allowlist: None,
    }
}

#[napi]
pub fn create_full_scope() -> SessionScopeConfig {
    SessionScopeConfig {
        operations: Some(vec![
            "sign_nostr_event".to_string(),
            "sign_psbt".to_string(),
            "get_public_key".to_string(),
            "get_bitcoin_address".to_string(),
            "nip44_encrypt".to_string(),
            "nip44_decrypt".to_string(),
        ]),
        event_kinds: None,
        max_amount_sats: None,
        address_allowlist: None,
    }
}
