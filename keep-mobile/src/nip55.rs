// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{KeepMobile, KeepMobileError};
use base64::Engine;
use keep_core::crypto::nip44;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const URI_SCHEME: &str = "nostrsigner:";
const MAX_TAGS_COUNT: usize = 1000;
const MAX_EVENT_SIZE: usize = 128 * 1024;
const TIMESTAMP_DRIFT_SECS: i64 = 15 * 60;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const MAX_REQUESTS_PER_WINDOW: u32 = 10;
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const MAX_BATCH_SIZE: usize = 20;
const MAX_RATE_LIMIT_ENTRIES: usize = 1000;

#[derive(uniffi::Enum, Clone, Debug)]
pub enum Nip55RequestType {
    GetPublicKey,
    SignEvent,
    Nip44Encrypt,
    Nip44Decrypt,
    DecryptZapEvent,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct Nip55Request {
    pub request_type: Nip55RequestType,
    pub content: String,
    pub pubkey: Option<String>,
    pub return_type: String,
    pub callback_url: Option<String>,
    pub id: Option<String>,
    pub current_user: Option<String>,
    pub permissions: Option<String>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct Nip55Response {
    pub result: String,
    pub event: Option<String>,
    pub error: Option<String>,
    pub id: Option<String>,
}

#[derive(Default)]
struct RateLimitState {
    requests: Vec<Instant>,
    backoff_until: Option<Instant>,
    consecutive_failures: u32,
}

#[derive(uniffi::Object)]
pub struct Nip55Handler {
    mobile: Arc<KeepMobile>,
    rate_limits: Mutex<HashMap<String, RateLimitState>>,
}

#[uniffi::export]
impl Nip55Handler {
    #[uniffi::constructor]
    pub fn new(mobile: Arc<KeepMobile>) -> Self {
        Self {
            mobile,
            rate_limits: Mutex::new(HashMap::new()),
        }
    }

    pub fn handle_request(
        &self,
        request: Nip55Request,
        caller_id: String,
    ) -> Result<Nip55Response, KeepMobileError> {
        self.check_rate_limit(&caller_id)?;

        if let Some(ref current_user) = request.current_user {
            self.validate_current_user(current_user)?;
        }

        let request_id = request.id.clone();
        let pubkey = request.pubkey.clone();

        let mut result = match request.request_type {
            Nip55RequestType::GetPublicKey => self.handle_get_public_key(),
            Nip55RequestType::SignEvent => self.handle_sign_event(request.content),
            Nip55RequestType::Nip44Encrypt => {
                let pk = pubkey.ok_or(KeepMobileError::InvalidSession)?;
                self.handle_nip44_encrypt(request.content, pk)
            }
            Nip55RequestType::Nip44Decrypt => {
                let pk = pubkey.ok_or(KeepMobileError::InvalidSession)?;
                self.handle_nip44_decrypt(request.content, pk)
            }
            Nip55RequestType::DecryptZapEvent => Err(KeepMobileError::NotSupported {
                msg: "decrypt_zap_event requires NIP-04 which is not supported".into(),
            }),
        };

        if let Ok(ref mut response) = result {
            response.id = request_id;
        }

        self.record_result(&caller_id, result.is_ok());
        result
    }

    pub fn parse_intent_uri(&self, uri: String) -> Result<Nip55Request, KeepMobileError> {
        let uri_body = uri
            .strip_prefix(URI_SCHEME)
            .ok_or(KeepMobileError::InvalidSession)?;

        let (content_b64, query) = uri_body.split_once('?').unwrap_or((uri_body, ""));

        let content = decode_base64_content(content_b64)?;
        let params = parse_query_params(query)?;

        Ok(Nip55Request {
            request_type: params.request_type,
            content,
            pubkey: params.pubkey,
            return_type: params.return_type,
            callback_url: params.callback_url,
            id: params.id,
            current_user: params.current_user,
            permissions: params.permissions,
        })
    }

    pub fn handle_batch_request(
        &self,
        requests: Vec<Nip55Request>,
        caller_id: String,
    ) -> Vec<Nip55Response> {
        if requests.len() > MAX_BATCH_SIZE {
            return vec![Nip55Response {
                result: String::new(),
                event: None,
                error: Some("batch size exceeded".into()),
                id: None,
            }];
        }

        requests
            .into_iter()
            .map(|req| {
                self.handle_request(req, caller_id.clone())
                    .unwrap_or_else(|_| Nip55Response {
                        result: String::new(),
                        event: None,
                        error: Some("request failed".into()),
                        id: None,
                    })
            })
            .collect()
    }

    pub fn build_result_intent(
        &self,
        response: Nip55Response,
        package: String,
    ) -> Result<String, KeepMobileError> {
        if !is_valid_package_name(&package) {
            return Err(KeepMobileError::InvalidSession);
        }

        let b64 = base64::engine::general_purpose::STANDARD;
        let mut intent = format!("intent:#Intent;scheme=nostrsigner;package={};", package);

        if let Some(event) = &response.event {
            let _ = write!(intent, "S.event={};", b64.encode(event));
        }

        let _ = write!(intent, "S.result={};", b64.encode(&response.result));

        if let Some(error) = &response.error {
            let _ = write!(intent, "S.error={};", b64.encode(error));
        }

        if let Some(id) = &response.id {
            let _ = write!(intent, "S.id={};", b64.encode(id));
        }

        intent.push_str("end");
        Ok(intent)
    }

    pub fn serialize_batch_results(&self, responses: Vec<Nip55Response>) -> String {
        let results: Vec<serde_json::Value> = responses
            .iter()
            .map(|r| {
                let mut obj = serde_json::json!({ "result": r.result });
                if let Some(ref event) = r.event {
                    obj["event"] = event.clone().into();
                }
                if let Some(ref error) = r.error {
                    obj["error"] = error.clone().into();
                }
                if let Some(ref id) = r.id {
                    obj["id"] = id.clone().into();
                }
                obj
            })
            .collect();
        serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string())
    }
}

impl Nip55Handler {
    fn validate_current_user(&self, current_user: &str) -> Result<(), KeepMobileError> {
        let info = self
            .mobile
            .get_share_info()
            .ok_or(KeepMobileError::NotInitialized)?;

        if current_user != info.group_pubkey {
            return Err(KeepMobileError::PubkeyMismatch);
        }
        Ok(())
    }

    fn handle_get_public_key(&self) -> Result<Nip55Response, KeepMobileError> {
        let info = self
            .mobile
            .get_share_info()
            .ok_or(KeepMobileError::NotInitialized)?;

        Ok(Nip55Response {
            result: info.group_pubkey,
            event: None,
            error: None,
            id: None,
        })
    }

    fn request_ecdh(&self, pubkey_bytes: &[u8; 33]) -> Result<Zeroizing<[u8; 32]>, KeepMobileError> {
        self.mobile.runtime.block_on(async {
            let node_guard = self.mobile.node.read().await;
            let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;

            node.request_ecdh(pubkey_bytes)
                .await
                .map(Zeroizing::new)
                .map_err(|_| KeepMobileError::FrostError {
                    msg: "ECDH failed".into(),
                })
        })
    }

    fn handle_nip44_encrypt(
        &self,
        plaintext: String,
        pubkey: String,
    ) -> Result<Nip55Response, KeepMobileError> {
        let pubkey_bytes = parse_pubkey_to_compressed(&pubkey)?;
        let shared_secret = self.request_ecdh(&pubkey_bytes)?;

        let encrypted =
            nip44::encrypt(&shared_secret, plaintext.as_bytes()).map_err(|_| {
                KeepMobileError::FrostError {
                    msg: "encryption failed".into(),
                }
            })?;

        let result = base64::engine::general_purpose::STANDARD.encode(&encrypted);

        Ok(Nip55Response {
            result,
            event: None,
            error: None,
            id: None,
        })
    }

    fn handle_nip44_decrypt(
        &self,
        ciphertext: String,
        pubkey: String,
    ) -> Result<Nip55Response, KeepMobileError> {
        let pubkey_bytes = parse_pubkey_to_compressed(&pubkey)?;

        let payload = base64::engine::general_purpose::STANDARD
            .decode(&ciphertext)
            .map_err(|_| KeepMobileError::InvalidSession)?;

        let shared_secret = self.request_ecdh(&pubkey_bytes)?;

        let decrypted =
            nip44::decrypt(&shared_secret, &payload).map_err(|_| KeepMobileError::FrostError {
                msg: "decryption failed".into(),
            })?;

        let result = String::from_utf8(decrypted).map_err(|_| KeepMobileError::Serialization {
            msg: "invalid content".into(),
        })?;

        Ok(Nip55Response {
            result,
            event: None,
            error: None,
            id: None,
        })
    }

    fn handle_sign_event(&self, event_json: String) -> Result<Nip55Response, KeepMobileError> {
        let event: serde_json::Value =
            serde_json::from_str(&event_json).map_err(|_| KeepMobileError::InvalidSession)?;

        validate_nostr_event(&event)?;

        let share_info = self
            .mobile
            .get_share_info()
            .ok_or(KeepMobileError::NotInitialized)?;

        let event_pubkey = event["pubkey"]
            .as_str()
            .ok_or(KeepMobileError::InvalidSession)?;
        if event_pubkey != share_info.group_pubkey {
            return Err(KeepMobileError::PubkeyMismatch);
        }

        let event_hash = compute_nostr_event_id(&event)?;

        let signature = self.mobile.runtime.block_on(async {
            let node_guard = self.mobile.node.read().await;
            let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;

            node.request_signature(event_hash.to_vec(), "nostr_event")
                .await
                .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })
        })?;

        let signature_hex = hex::encode(signature);

        let mut signed_event = event;
        signed_event["id"] = serde_json::Value::String(hex::encode(event_hash));
        signed_event["sig"] = serde_json::Value::String(signature_hex.clone());

        let signed_event_json = serde_json::to_string(&signed_event)
            .map_err(|e| KeepMobileError::Serialization { msg: e.to_string() })?;

        Ok(Nip55Response {
            result: signature_hex,
            event: Some(signed_event_json),
            error: None,
            id: None,
        })
    }

    fn check_rate_limit(&self, caller_id: &str) -> Result<(), KeepMobileError> {
        let mut limits = self
            .rate_limits
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        self.evict_stale_entries(&mut limits, now);

        let state = limits.entry(caller_id.to_string()).or_default();

        if let Some(backoff_until) = state.backoff_until {
            if now < backoff_until {
                return Err(KeepMobileError::RateLimited);
            }
            state.backoff_until = None;
        }

        state
            .requests
            .retain(|&t| now.duration_since(t) < RATE_LIMIT_WINDOW);

        if state.requests.len() >= MAX_REQUESTS_PER_WINDOW as usize {
            return Err(KeepMobileError::RateLimited);
        }

        state.requests.push(now);
        Ok(())
    }

    fn record_result(&self, caller_id: &str, success: bool) {
        let mut limits = self
            .rate_limits
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let state = limits.entry(caller_id.to_string()).or_default();

        if success {
            state.consecutive_failures = 0;
        } else {
            state.consecutive_failures += 1;
            if state.consecutive_failures >= 3 {
                let backoff = Duration::from_secs(2u64.pow(state.consecutive_failures.min(8)))
                    .min(MAX_BACKOFF);
                state.backoff_until = Some(Instant::now() + backoff);
            }
        }
    }

    fn evict_stale_entries(&self, limits: &mut HashMap<String, RateLimitState>, now: Instant) {
        if limits.len() <= MAX_RATE_LIMIT_ENTRIES {
            return;
        }

        limits.retain(|_, state| {
            let recent = state
                .requests
                .iter()
                .any(|&t| now.duration_since(t) < RATE_LIMIT_WINDOW);
            let in_backoff = state.backoff_until.is_some_and(|b| now < b);
            recent || in_backoff
        });
    }
}

fn decode_base64_content(encoded: &str) -> Result<String, KeepMobileError> {
    if encoded.is_empty() {
        return Ok(String::new());
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| KeepMobileError::InvalidSession)?;

    String::from_utf8(decoded).map_err(|_| KeepMobileError::InvalidSession)
}

struct QueryParams {
    request_type: Nip55RequestType,
    pubkey: Option<String>,
    return_type: String,
    callback_url: Option<String>,
    id: Option<String>,
    current_user: Option<String>,
    permissions: Option<String>,
}

fn parse_query_params(query: &str) -> Result<QueryParams, KeepMobileError> {
    let mut params = QueryParams {
        request_type: Nip55RequestType::GetPublicKey,
        pubkey: None,
        return_type: "signature".to_string(),
        callback_url: None,
        id: None,
        current_user: None,
        permissions: None,
    };

    for param in query.split('&') {
        let Some((key, value)) = param.split_once('=') else {
            continue;
        };

        let decoded = url_decode(value);

        match key {
            "type" => params.request_type = parse_request_type(&decoded)?,
            "pubkey" => params.pubkey = Some(decoded),
            "return_type" => params.return_type = decoded,
            "callbackUrl" => {
                if is_safe_callback_url(&decoded) {
                    params.callback_url = Some(decoded);
                }
            }
            "id" => params.id = Some(decoded),
            "current_user" => params.current_user = Some(decoded),
            "permissions" => params.permissions = Some(decoded),
            _ => {}
        }
    }

    Ok(params)
}

fn url_decode(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        match c {
            '%' => {
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        bytes.push(byte);
                        continue;
                    }
                }
                bytes.push(b'%');
                bytes.extend(hex.as_bytes());
            }
            '+' => bytes.push(b' '),
            _ => {
                let mut buf = [0u8; 4];
                bytes.extend(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }

    String::from_utf8_lossy(&bytes).into_owned()
}

fn is_safe_callback_url(url: &str) -> bool {
    const ALLOWED_SCHEMES: &[&str] = &["nostrsigner:", "nostr:"];

    let lower = url.to_lowercase();
    ALLOWED_SCHEMES.iter().any(|s| lower.starts_with(s))
}

fn is_valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
}

fn parse_request_type(value: &str) -> Result<Nip55RequestType, KeepMobileError> {
    match value {
        "get_public_key" => Ok(Nip55RequestType::GetPublicKey),
        "sign_event" => Ok(Nip55RequestType::SignEvent),
        "nip44_encrypt" => Ok(Nip55RequestType::Nip44Encrypt),
        "nip44_decrypt" => Ok(Nip55RequestType::Nip44Decrypt),
        "decrypt_zap_event" => Ok(Nip55RequestType::DecryptZapEvent),
        _ => Err(KeepMobileError::InvalidSession),
    }
}

fn parse_pubkey_to_compressed(pubkey_hex: &str) -> Result<[u8; 33], KeepMobileError> {
    let bytes = hex::decode(pubkey_hex).map_err(|_| KeepMobileError::InvalidSession)?;

    match bytes.len() {
        32 => {
            let mut compressed = [0u8; 33];
            compressed[0] = 0x02;
            compressed[1..].copy_from_slice(&bytes);
            Ok(compressed)
        }
        33 => bytes
            .try_into()
            .map_err(|_| KeepMobileError::InvalidSession),
        _ => Err(KeepMobileError::InvalidSession),
    }
}

fn validate_nostr_event(event: &serde_json::Value) -> Result<(), KeepMobileError> {
    if !event.is_object() {
        return Err(KeepMobileError::InvalidSession);
    }

    let tags = event["tags"]
        .as_array()
        .ok_or(KeepMobileError::InvalidSession)?;

    if !event["pubkey"].is_string()
        || !event["created_at"].is_number()
        || !event["kind"].is_number()
        || !event["content"].is_string()
        || tags.len() > MAX_TAGS_COUNT
    {
        return Err(KeepMobileError::InvalidSession);
    }

    let event_str = serde_json::to_string(event).map_err(|_| KeepMobileError::InvalidSession)?;
    if event_str.len() > MAX_EVENT_SIZE {
        return Err(KeepMobileError::InvalidSession);
    }

    let created_at = event["created_at"]
        .as_i64()
        .ok_or(KeepMobileError::InvalidSession)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if (created_at - now).abs() > TIMESTAMP_DRIFT_SECS {
        return Err(KeepMobileError::InvalidTimestamp);
    }

    Ok(())
}

fn compute_nostr_event_id(event: &serde_json::Value) -> Result<[u8; 32], KeepMobileError> {
    let serialized = serde_json::json!([
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"],
    ]);

    let json_str =
        serde_json::to_string(&serialized).map_err(|_| KeepMobileError::InvalidSession)?;

    let hash = Sha256::digest(json_str.as_bytes());
    Ok(hash.into())
}
