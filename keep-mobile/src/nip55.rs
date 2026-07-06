// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use crate::{KeepMobile, KeepMobileError};
use base64::Engine;
use flate2::write::GzEncoder;
use flate2::Compression;
use keep_core::crypto::{nip04, nip44};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write;
use std::io::Write as IoWrite;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const URI_SCHEME: &str = "nostrsigner:";
const MAX_TAGS_COUNT: usize = 1000;
const MAX_EVENT_SIZE: usize = 128 * 1024;
const TIMESTAMP_DRIFT_SECS: i64 = 15 * 60;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
// Real Nostr clients (e.g. Amethyst sending NIP-17 DMs) easily fire 20-50 sign
// requests in a short burst: kind 14 rumor + kind 13 seal + per-recipient
// kind 1059 gift wraps + per-relay kind 22242 NIP-42 auth + reaction signing,
// all chained. 10/min broke those real-world flows. This is a defense-in-depth
// in-process cap covering legitimate bursts. The primary throttle is the
// Kotlin IPC-level RateLimiter (30/sec) plus per-app permissions; that external
// limiter is a REQUIRED invariant, not optional, since this in-process counter
// alone is not a sufficient DoS guard.
const MAX_REQUESTS_PER_WINDOW: u32 = 60;
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const MAX_BATCH_SIZE: usize = 20;
const MAX_RATE_LIMIT_ENTRIES: usize = 1000;
const MAX_PERMISSIONS_COUNT: usize = 32;
const MAX_PERMISSIONS_JSON_BYTES: usize = 8 * 1024;
const MAX_EVENT_KIND: i32 = 65535;

fn pubkey_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum Nip55RequestType {
    GetPublicKey,
    SignEvent,
    Nip04Encrypt,
    Nip04Decrypt,
    Nip44Encrypt,
    Nip44Decrypt,
    DecryptZapEvent,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CompressionType {
    None,
    Gzip,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct Nip55Request {
    pub request_type: Nip55RequestType,
    pub content: String,
    pub pubkey: Option<String>,
    pub return_type: String,
    pub compression_type: String,
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
    pub rejected: bool,
}

// A single method (+ optional sign_event kind) a client requests to pre-authorize
// via the NIP-55 `permissions` array passed with get_public_key.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct Nip55DeclaredPermission {
    pub request_type: Nip55RequestType,
    pub kind: Option<i32>,
}

// Parses the NIP-55 `permissions` array (`[{"type":"sign_event","kind":22242},
// {"type":"nip44_decrypt"}]`) into the methods/kinds a client wants pre-authorized.
// Unknown method types are dropped, as are `get_public_key` entries (that is the
// entry method itself, not a grantable permission); `kind` is honored only for
// sign_event, and a kind-less sign_event entry is dropped (a sign grant must name
// a kind). Duplicate `(request_type, kind)` entries collapse to the first seen, and
// at most `MAX_PERMISSIONS_COUNT` entries are accepted. Input over
// `MAX_PERMISSIONS_JSON_BYTES` and malformed input both parse to an empty list
// (fail-closed: nothing pre-authorized).
#[uniffi::export]
pub fn nip55_parse_permissions(json: Option<String>) -> Vec<Nip55DeclaredPermission> {
    let Some(json) = json else {
        return Vec::new();
    };
    if json.len() > MAX_PERMISSIONS_JSON_BYTES {
        return Vec::new();
    }
    let entries: Vec<serde_json::Value> = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<Nip55DeclaredPermission> = Vec::new();
    for entry in &entries {
        if out.len() >= MAX_PERMISSIONS_COUNT {
            break;
        }
        let Some(type_str) = entry.get("type").and_then(|t| t.as_str()) else {
            continue;
        };
        let Ok(request_type) = parse_request_type(type_str) else {
            continue;
        };
        if request_type == Nip55RequestType::GetPublicKey {
            continue;
        }
        let kind = if request_type == Nip55RequestType::SignEvent {
            let Some(kind) = entry
                .get("kind")
                .and_then(|k| k.as_i64())
                .and_then(|k| i32::try_from(k).ok())
                .filter(|k| (0..=MAX_EVENT_KIND).contains(k))
            else {
                // A sign_event permission with no (valid) kind cannot be granted.
                continue;
            };
            Some(kind)
        } else {
            None
        };
        let permission = Nip55DeclaredPermission { request_type, kind };
        if out.contains(&permission) {
            continue;
        }
        out.push(permission);
    }
    out
}

/// Outcome of the NIP-42 relay-auth whitelist gate for a kind-22242 request.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum Nip55RelayAuthGate {
    /// Relay is whitelisted — auto-approve without prompting.
    AutoAccept,
    /// A non-empty whitelist does not contain this relay — auto-reject.
    AutoReject,
    /// No whitelist configured (or it is empty) — fall through to normal grant resolution.
    Defer,
}

// Canonicalizes a relay URL to `host[:port]`: strips the ws/wss scheme
// (case-insensitively), any path and trailing slash, drops default ports
// (:443/:80) and a trailing FQDN dot, and lowercases (ASCII-only). Rejects
// non-ASCII hosts and blank input (returns None). The SAME normalization is
// used on whitelist entries and on the extracted relay host before gating so
// they compare consistently.
#[uniffi::export]
pub fn nip55_normalize_relay_host(url: String) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let without_scheme = lower
        .strip_prefix("wss://")
        .or_else(|| lower.strip_prefix("ws://"))
        .unwrap_or(lower.as_str());
    let host = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .trim_end_matches('/');
    if !host.is_ascii() {
        return None;
    }
    let host = host
        .strip_suffix(":443")
        .or_else(|| host.strip_suffix(":80"))
        .unwrap_or(host)
        .trim_end_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

// Extracts the normalized relay host from a NIP-42 (kind 22242) auth event's
// `relay` tag. Returns None if the event is malformed or has no usable relay tag.
#[uniffi::export]
pub fn nip55_extract_relay_host(event_json: String) -> Option<String> {
    let event: serde_json::Value = serde_json::from_str(&event_json).ok()?;
    if event.get("kind").and_then(|k| k.as_u64()) != Some(22242) {
        return None;
    }
    let tags = event.get("tags")?.as_array()?;
    let mut relay_url: Option<&str> = None;
    for tag in tags {
        let Some(arr) = tag.as_array() else {
            continue;
        };
        if arr.first().and_then(|v| v.as_str()) == Some("relay") {
            if relay_url.is_some() {
                return None;
            }
            relay_url = Some(arr.get(1).and_then(|v| v.as_str())?);
        }
    }
    nip55_normalize_relay_host(relay_url?.to_string())
}

// Applies the relay-auth whitelist gate. An empty whitelist defers to normal grant
// resolution; otherwise a request is auto-accepted iff its relay is whitelisted,
// and auto-rejected otherwise (including when the relay could not be determined).
// Whitelist entries are expected to be pre-normalized via nip55_normalize_relay_host.
#[uniffi::export]
pub fn nip55_relay_auth_gate(
    relay_host: Option<String>,
    whitelist: Vec<String>,
) -> Nip55RelayAuthGate {
    if whitelist.is_empty() {
        return Nip55RelayAuthGate::Defer;
    }
    match relay_host {
        Some(host) if whitelist.contains(&host) => Nip55RelayAuthGate::AutoAccept,
        _ => Nip55RelayAuthGate::AutoReject,
    }
}

impl Nip55Response {
    fn ok(result: String) -> Self {
        Self {
            result,
            event: None,
            error: None,
            id: None,
            rejected: false,
        }
    }

    fn with_event(result: String, event: String) -> Self {
        Self {
            result,
            event: Some(event),
            error: None,
            id: None,
            rejected: false,
        }
    }
}

// A failed/rejected request carries null signature/result and rejected=true; a
// success sets both signature and result to the operation output. Matches the
// `Result` object shape that NIP-55 signer clients parse from the results array.
fn serialize_batch_results_json(responses: &[Nip55Response]) -> String {
    let results: Vec<serde_json::Value> = responses
        .iter()
        .map(|r| {
            if r.rejected || r.error.is_some() {
                serde_json::json!({
                    "id": r.id,
                    "package": serde_json::Value::Null,
                    "signature": serde_json::Value::Null,
                    "result": serde_json::Value::Null,
                    "rejected": true,
                })
            } else {
                serde_json::json!({
                    "id": r.id,
                    "package": serde_json::Value::Null,
                    "signature": r.result,
                    "result": r.result,
                })
            }
        })
        .collect();
    serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string())
}

#[derive(Default)]
struct RateLimitState {
    requests: Vec<Instant>,
    backoff_until: Option<Instant>,
    consecutive_failures: u32,
}

fn spawn_async_with_timeout<T: Send + 'static>(
    mobile: &KeepMobile,
    timeout: Duration,
    operation: &str,
    future: impl std::future::Future<Output = Result<T, KeepMobileError>> + Send + 'static,
) -> Result<T, KeepMobileError> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let handle = mobile.runtime.handle().spawn(async move {
        let _ = tx.send(future.await);
    });
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            handle.abort();
            Err(KeepMobileError::FrostError {
                msg: format!("{operation} timed out"),
            })
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(KeepMobileError::FrostError {
            msg: format!("{operation} failed unexpectedly"),
        }),
    }
}

const FROST_OP_TIMEOUT: Duration = Duration::from_secs(65);

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
        if is_rate_limited_type(&request.request_type) {
            self.check_rate_limit(&caller_id)?;
        }

        if let Some(ref current_user) = request.current_user {
            self.validate_current_user(current_user)?;
        }

        let request_id = request.id.clone();
        let pubkey = request.pubkey.clone();
        let compression = parse_compression_type(&request.compression_type);
        let return_type = request.return_type.clone();

        let mut result = match request.request_type {
            Nip55RequestType::GetPublicKey => self.handle_get_public_key(),
            Nip55RequestType::SignEvent => {
                self.handle_sign_event(request.content, &return_type, &compression)
            }
            Nip55RequestType::Nip04Encrypt => {
                let pk = pubkey.ok_or(KeepMobileError::InvalidSession)?;
                self.handle_nip04_encrypt(request.content, pk)
            }
            Nip55RequestType::Nip04Decrypt => {
                let pk = pubkey.ok_or(KeepMobileError::InvalidSession)?;
                self.handle_nip04_decrypt(request.content, pk)
            }
            Nip55RequestType::Nip44Encrypt => {
                let pk = pubkey.ok_or(KeepMobileError::InvalidSession)?;
                self.handle_nip44_encrypt(request.content, pk)
            }
            Nip55RequestType::Nip44Decrypt => {
                let pk = pubkey.ok_or(KeepMobileError::InvalidSession)?;
                self.handle_nip44_decrypt(request.content, pk)
            }
            Nip55RequestType::DecryptZapEvent => self.handle_decrypt_zap_event(request.content),
        };

        if let Ok(ref mut response) = result {
            response.id = request_id;
        }

        if is_rate_limited_type(&request.request_type) {
            self.record_result(&caller_id, result.is_ok());
        }
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
            compression_type: params.compression_type,
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
                rejected: false,
            }];
        }

        requests
            .into_iter()
            .map(|req| {
                let req_id = req.id.clone();
                self.handle_request(req, caller_id.clone())
                    .unwrap_or_else(|_| Nip55Response {
                        result: String::new(),
                        event: None,
                        error: Some("request failed".into()),
                        id: req_id,
                        rejected: false,
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
        let mut intent = format!("intent:#Intent;scheme=nostrsigner;package={package};");

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

    // Serializes batch results to the NIP-55 `results` extra wire format used by
    // signer clients: a JSON array of {id, package, signature, result, rejected?}.
    pub fn serialize_batch_results(&self, responses: Vec<Nip55Response>) -> String {
        serialize_batch_results_json(&responses)
    }
}

impl Nip55Handler {
    fn validate_current_user(&self, current_user: &str) -> Result<(), KeepMobileError> {
        let info = self
            .mobile
            .get_share_info()
            .ok_or(KeepMobileError::NotInitialized)?;

        if !pubkey_eq(current_user, &info.group_pubkey) {
            return Err(KeepMobileError::PubkeyMismatch);
        }
        Ok(())
    }

    fn handle_get_public_key(&self) -> Result<Nip55Response, KeepMobileError> {
        let info = self
            .mobile
            .get_share_info()
            .ok_or(KeepMobileError::NotInitialized)?;

        Ok(Nip55Response::ok(info.group_pubkey))
    }

    fn request_ecdh(
        &self,
        pubkey_bytes: &[u8; 33],
    ) -> Result<Zeroizing<[u8; 32]>, KeepMobileError> {
        let node_arc = self.mobile.node.clone();
        let pubkey_bytes = *pubkey_bytes;
        spawn_async_with_timeout(&self.mobile, FROST_OP_TIMEOUT, "ECDH request", async move {
            let node_guard = node_arc.read().await;
            let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;
            node.request_ecdh(&pubkey_bytes)
                .await
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

        let encrypted = nip44::encrypt(&shared_secret, plaintext.as_bytes()).map_err(|_| {
            KeepMobileError::FrostError {
                msg: "encryption failed".into(),
            }
        })?;

        let result = base64::engine::general_purpose::STANDARD.encode(&encrypted);

        Ok(Nip55Response::ok(result))
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

        Ok(Nip55Response::ok(result))
    }

    fn handle_nip04_encrypt(
        &self,
        plaintext: String,
        pubkey: String,
    ) -> Result<Nip55Response, KeepMobileError> {
        let pubkey_bytes = parse_pubkey_to_compressed(&pubkey)?;
        let shared_secret = self.request_ecdh(&pubkey_bytes)?;

        let encrypted = nip04::encrypt(&shared_secret, plaintext.as_bytes()).map_err(|_| {
            KeepMobileError::FrostError {
                msg: "NIP-04 encryption failed".into(),
            }
        })?;

        Ok(Nip55Response::ok(encrypted))
    }

    fn handle_nip04_decrypt(
        &self,
        ciphertext: String,
        pubkey: String,
    ) -> Result<Nip55Response, KeepMobileError> {
        let pubkey_bytes = parse_pubkey_to_compressed(&pubkey)?;
        let shared_secret = self.request_ecdh(&pubkey_bytes)?;

        let decrypted = nip04::decrypt(&shared_secret, &ciphertext).map_err(|_| {
            KeepMobileError::FrostError {
                msg: "NIP-04 decryption failed".into(),
            }
        })?;

        let result = String::from_utf8(decrypted).map_err(|_| KeepMobileError::Serialization {
            msg: "invalid content".into(),
        })?;

        Ok(Nip55Response::ok(result))
    }

    fn handle_decrypt_zap_event(
        &self,
        event_json: String,
    ) -> Result<Nip55Response, KeepMobileError> {
        let event: serde_json::Value =
            serde_json::from_str(&event_json).map_err(|_| KeepMobileError::InvalidSession)?;

        let kind = event["kind"]
            .as_u64()
            .ok_or(KeepMobileError::InvalidSession)?;
        if kind != 9735 {
            return Err(KeepMobileError::InvalidSession);
        }

        let tags = event["tags"]
            .as_array()
            .ok_or(KeepMobileError::InvalidSession)?;

        let description = tags
            .iter()
            .find(|tag| tag[0].as_str() == Some("description"))
            .and_then(|tag| tag[1].as_str())
            .ok_or(KeepMobileError::InvalidSession)?;

        let zap_request: serde_json::Value =
            serde_json::from_str(description).map_err(|_| KeepMobileError::InvalidSession)?;

        let zap_kind = zap_request["kind"]
            .as_u64()
            .ok_or(KeepMobileError::InvalidSession)?;
        if zap_kind != 9734 {
            return Err(KeepMobileError::InvalidSession);
        }

        let content = zap_request["content"]
            .as_str()
            .ok_or(KeepMobileError::InvalidSession)?;

        if content.is_empty() {
            return Ok(Nip55Response::ok(description.to_string()));
        }

        let sender_pubkey = zap_request["pubkey"]
            .as_str()
            .ok_or(KeepMobileError::InvalidSession)?;

        let pubkey_bytes = parse_pubkey_to_compressed(sender_pubkey)?;
        let shared_secret = self.request_ecdh(&pubkey_bytes)?;

        let decrypted_content =
            nip04::decrypt(&shared_secret, content).map_err(|_| KeepMobileError::FrostError {
                msg: "Failed to decrypt zap message".into(),
            })?;

        let decrypted_str =
            String::from_utf8(decrypted_content).map_err(|_| KeepMobileError::Serialization {
                msg: "invalid content".into(),
            })?;

        let mut decrypted_zap = zap_request;
        decrypted_zap["content"] = serde_json::Value::String(decrypted_str);

        let result = serde_json::to_string(&decrypted_zap)
            .map_err(|e| KeepMobileError::Serialization { msg: e.to_string() })?;

        Ok(Nip55Response::ok(result))
    }

    fn handle_sign_event(
        &self,
        event_json: String,
        return_type: &str,
        compression: &CompressionType,
    ) -> Result<Nip55Response, KeepMobileError> {
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
        if !pubkey_eq(event_pubkey, &share_info.group_pubkey) {
            return Err(KeepMobileError::PubkeyMismatch);
        }

        let event_hash = compute_nostr_event_id(&event)?;

        // #529: attach the structured event body so co-signers can recompute
        // the id and reject a cross-domain label spoof. Every field in the
        // NIP-01 id serialization contributes to the digest, so any change
        // to the body must be reflected in the sig; forwarding the same
        // canonical fields ensures the responder's recompute matches ours.
        let structured = build_structured_nostr_payload(&event)?;

        let node_arc = self.mobile.node.clone();
        let signature = spawn_async_with_timeout(
            &self.mobile,
            FROST_OP_TIMEOUT,
            "Signing request",
            async move {
                let node_guard = node_arc.read().await;
                let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;
                node.request_signature_structured(
                    event_hash.to_vec(),
                    keep_frost_net::MSG_TYPE_NOSTR_EVENT,
                    Some(structured),
                )
                .await
                .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })
            },
        )?;

        let signature_hex = hex::encode(signature);

        let mut signed_event = event;
        signed_event["id"] = serde_json::Value::String(hex::encode(event_hash));
        signed_event["sig"] = serde_json::Value::String(signature_hex.clone());

        let signed_event_json = serde_json::to_string(&signed_event)
            .map_err(|e| KeepMobileError::Serialization { msg: e.to_string() })?;

        let event_result = if return_type == "event" && *compression == CompressionType::Gzip {
            let compressed = compress_gzip(signed_event_json.as_bytes())?;
            let b64 = base64::engine::general_purpose::STANDARD;
            format!("Signer1{}", b64.encode(&compressed))
        } else {
            signed_event_json
        };

        Ok(Nip55Response::with_event(signature_hex, event_result))
    }

    fn check_rate_limit(&self, caller_id: &str) -> Result<(), KeepMobileError> {
        let mut limits = self.rate_limits.lock().unwrap_or_else(|e| e.into_inner());
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
        let mut limits = self.rate_limits.lock().unwrap_or_else(|e| e.into_inner());
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
    compression_type: String,
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
        compression_type: "none".to_string(),
        callback_url: None,
        id: None,
        current_user: None,
        permissions: None,
    };

    for param in query.split('&') {
        let Some((key, value)) = param.split_once('=') else {
            continue;
        };

        let Some(decoded) = url_decode(value) else {
            continue;
        };

        match key {
            "type" => params.request_type = parse_request_type(&decoded)?,
            "pubkey" => params.pubkey = Some(decoded),
            "returnType" | "return_type" => params.return_type = decoded,
            "compressionType" => params.compression_type = decoded,
            "callbackUrl" if is_safe_callback_url(&decoded) => {
                params.callback_url = Some(decoded);
            }
            "id" => params.id = Some(decoded),
            "current_user" => params.current_user = Some(decoded),
            "permissions" => params.permissions = Some(decoded),
            _ => {}
        }
    }

    Ok(params)
}

fn url_decode(s: &str) -> Option<String> {
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

    String::from_utf8(bytes).ok()
}

fn is_safe_callback_url(url: &str) -> bool {
    const ALLOWED_SCHEMES: &[&str] = &["nostrsigner:", "nostr:", "https://"];

    let lower = url.to_lowercase();
    ALLOWED_SCHEMES.iter().any(|s| lower.starts_with(s))
}

fn is_valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn is_rate_limited_type(t: &Nip55RequestType) -> bool {
    // GetPublicKey is a cheap cached-metadata read with no FROST/ECDH crypto and
    // no signing round-trip, so it is exempt. Every other type triggers a signing
    // or encryption operation and must be rate-limited. Exhaustive match so new
    // variants force an explicit decision.
    match t {
        Nip55RequestType::GetPublicKey => false,
        Nip55RequestType::SignEvent
        | Nip55RequestType::Nip04Encrypt
        | Nip55RequestType::Nip04Decrypt
        | Nip55RequestType::Nip44Encrypt
        | Nip55RequestType::Nip44Decrypt
        | Nip55RequestType::DecryptZapEvent => true,
    }
}

fn parse_request_type(value: &str) -> Result<Nip55RequestType, KeepMobileError> {
    match value {
        "get_public_key" => Ok(Nip55RequestType::GetPublicKey),
        "sign_event" => Ok(Nip55RequestType::SignEvent),
        "nip04_encrypt" => Ok(Nip55RequestType::Nip04Encrypt),
        "nip04_decrypt" => Ok(Nip55RequestType::Nip04Decrypt),
        "nip44_encrypt" => Ok(Nip55RequestType::Nip44Encrypt),
        "nip44_decrypt" => Ok(Nip55RequestType::Nip44Decrypt),
        "decrypt_zap_event" => Ok(Nip55RequestType::DecryptZapEvent),
        _ => Err(KeepMobileError::InvalidSession),
    }
}

fn parse_compression_type(value: &str) -> CompressionType {
    match value.to_lowercase().as_str() {
        "gzip" => CompressionType::Gzip,
        _ => CompressionType::None,
    }
}

fn compress_gzip(data: &[u8]) -> Result<Vec<u8>, KeepMobileError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| KeepMobileError::Serialization { msg: e.to_string() })?;
    encoder
        .finish()
        .map_err(|e| KeepMobileError::Serialization { msg: e.to_string() })
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

pub(crate) fn validate_nostr_event(event: &serde_json::Value) -> Result<(), KeepMobileError> {
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

pub(crate) fn compute_nostr_event_id(
    event: &serde_json::Value,
) -> Result<[u8; 32], KeepMobileError> {
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

/// Build the `keep_frost_net::NostrEventPayload` structured wire format from
/// the sign-event request's JSON body so the co-signers can recompute the
/// event id (#529). Same canonical field extraction as
/// [`compute_nostr_event_id`], keyed by NIP-01 field order.
pub(crate) fn build_structured_nostr_payload(
    event: &serde_json::Value,
) -> Result<Vec<u8>, KeepMobileError> {
    let pubkey_hex = event["pubkey"]
        .as_str()
        .ok_or(KeepMobileError::InvalidSession)?;
    let pubkey_bytes = hex::decode(pubkey_hex).map_err(|_| KeepMobileError::InvalidSession)?;
    let pubkey: [u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| KeepMobileError::InvalidSession)?;
    let created_at = event["created_at"]
        .as_u64()
        .ok_or(KeepMobileError::InvalidSession)?;
    let kind = event["kind"]
        .as_u64()
        .and_then(|k| u16::try_from(k).ok())
        .ok_or(KeepMobileError::InvalidSession)?;
    let tags: Vec<Vec<String>> = event["tags"]
        .as_array()
        .ok_or(KeepMobileError::InvalidSession)?
        .iter()
        .map(|tag| {
            tag.as_array()
                .ok_or(KeepMobileError::InvalidSession)?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or(KeepMobileError::InvalidSession)
                })
                .collect()
        })
        .collect::<Result<_, _>>()?;
    let content = event["content"]
        .as_str()
        .ok_or(KeepMobileError::InvalidSession)?
        .to_string();
    let payload = keep_frost_net::NostrEventPayload {
        pubkey,
        created_at,
        kind,
        tags,
        content,
    };
    serde_json::to_vec(&payload).map_err(|_| KeepMobileError::InvalidSession)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_results_success_carries_signature_and_result() {
        let responses = vec![Nip55Response {
            result: "sig123".into(),
            event: None,
            error: None,
            id: Some("a".into()),
            rejected: false,
        }];
        let json: serde_json::Value =
            serde_json::from_str(&serialize_batch_results_json(&responses)).unwrap();
        let obj = &json[0];
        assert_eq!(obj["id"], "a");
        assert!(obj["package"].is_null());
        assert_eq!(obj["signature"], "sig123");
        assert_eq!(obj["result"], "sig123");
        assert!(obj.get("rejected").is_none());
    }

    #[test]
    fn batch_results_error_is_rejected_with_null_values() {
        let responses = vec![Nip55Response {
            result: String::new(),
            event: None,
            error: Some("request failed".into()),
            id: Some("b".into()),
            rejected: false,
        }];
        let json: serde_json::Value =
            serde_json::from_str(&serialize_batch_results_json(&responses)).unwrap();
        let obj = &json[0];
        assert_eq!(obj["id"], "b");
        assert!(obj["signature"].is_null());
        assert!(obj["result"].is_null());
        assert_eq!(obj["rejected"], true);
    }

    #[test]
    fn normalize_relay_host_strips_scheme_path_and_lowercases() {
        assert_eq!(
            nip55_normalize_relay_host("wss://Relay.Example.com/".into()),
            Some("relay.example.com".into())
        );
        assert_eq!(
            nip55_normalize_relay_host("ws://relay.example.com:7777/path".into()),
            Some("relay.example.com:7777".into())
        );
        assert_eq!(nip55_normalize_relay_host("   ".into()), None);
    }

    #[test]
    fn normalize_relay_host_scheme_less_and_default_ports() {
        // Scheme-less input is accepted as-is.
        assert_eq!(
            nip55_normalize_relay_host("relay.example.com".into()),
            Some("relay.example.com".into())
        );
        // Default ports canonicalize away (wss :443, ws :80).
        assert_eq!(
            nip55_normalize_relay_host("relay.com".into()),
            nip55_normalize_relay_host("relay.com:443".into())
        );
        assert_eq!(
            nip55_normalize_relay_host("ws://relay.com:80".into()),
            Some("relay.com".into())
        );
        // Uppercase scheme is stripped case-insensitively.
        assert_eq!(
            nip55_normalize_relay_host("WSS://Relay.Example.com".into()),
            Some("relay.example.com".into())
        );
        // Trailing FQDN dot is stripped.
        assert_eq!(
            nip55_normalize_relay_host("relay.com.".into()),
            Some("relay.com".into())
        );
    }

    #[test]
    fn normalize_relay_host_rejects_non_ascii_homograph() {
        // U+212A KELVIN SIGN lowercases to ASCII 'k' under full Unicode case
        // folding; reject non-ASCII hosts to prevent a whitelist bypass.
        assert_eq!(
            nip55_normalize_relay_host("wss://\u{212a}raken-relay.com".into()),
            None
        );
    }

    #[test]
    fn extract_relay_host_from_22242_event() {
        let event =
            r#"{"kind":22242,"tags":[["relay","wss://relay.example.com/"],["challenge","abc"]]}"#;
        assert_eq!(
            nip55_extract_relay_host(event.into()),
            Some("relay.example.com".into())
        );
        // No relay tag, or malformed -> None (fail-closed).
        assert_eq!(
            nip55_extract_relay_host(r#"{"kind":22242,"tags":[["challenge","abc"]]}"#.into()),
            None
        );
        assert_eq!(nip55_extract_relay_host("not json".into()), None);
    }

    #[test]
    fn extract_relay_host_fail_closed_cases() {
        // Non-22242 kind is rejected even with a valid relay tag.
        assert_eq!(
            nip55_extract_relay_host(
                r#"{"kind":1,"tags":[["relay","wss://relay.example.com/"]]}"#.into()
            ),
            None
        );
        // More than one relay tag is ambiguous -> None.
        assert_eq!(
            nip55_extract_relay_host(
                r#"{"kind":22242,"tags":[["relay","wss://a.example.com"],["relay","wss://b.example.com"]]}"#
                    .into()
            ),
            None
        );
        // Relay tag missing its URL element -> None.
        assert_eq!(
            nip55_extract_relay_host(r#"{"kind":22242,"tags":[["relay"]]}"#.into()),
            None
        );
    }

    #[test]
    fn relay_auth_gate_semantics() {
        // Empty whitelist defers to normal resolution.
        assert_eq!(
            nip55_relay_auth_gate(Some("relay.example.com".into()), vec![]),
            Nip55RelayAuthGate::Defer
        );
        // Whitelisted relay auto-accepts.
        assert_eq!(
            nip55_relay_auth_gate(
                Some("relay.example.com".into()),
                vec!["relay.example.com".into()]
            ),
            Nip55RelayAuthGate::AutoAccept
        );
        // Non-empty whitelist without this relay auto-rejects.
        assert_eq!(
            nip55_relay_auth_gate(
                Some("other.example.com".into()),
                vec!["relay.example.com".into()]
            ),
            Nip55RelayAuthGate::AutoReject
        );
        // Unknown relay against a non-empty whitelist auto-rejects.
        assert_eq!(
            nip55_relay_auth_gate(None, vec!["relay.example.com".into()]),
            Nip55RelayAuthGate::AutoReject
        );
    }

    #[test]
    fn parse_permissions_spec_example() {
        let json = r#"[{"type":"sign_event","kind":22242},{"type":"nip44_decrypt"}]"#;
        let perms = nip55_parse_permissions(Some(json.into()));
        assert_eq!(
            perms,
            vec![
                Nip55DeclaredPermission {
                    request_type: Nip55RequestType::SignEvent,
                    kind: Some(22242),
                },
                Nip55DeclaredPermission {
                    request_type: Nip55RequestType::Nip44Decrypt,
                    kind: None,
                },
            ]
        );
    }

    #[test]
    fn parse_permissions_drops_kindless_sign_event_and_unknown_types() {
        let json = r#"[{"type":"sign_event"},{"type":"bogus"},{"type":"nip04_encrypt","kind":4}]"#;
        let perms = nip55_parse_permissions(Some(json.into()));
        // kindless sign_event dropped, unknown dropped, non-sign kind ignored.
        assert_eq!(
            perms,
            vec![Nip55DeclaredPermission {
                request_type: Nip55RequestType::Nip04Encrypt,
                kind: None,
            }]
        );
    }

    #[test]
    fn parse_permissions_fail_closed_on_garbage_or_none() {
        assert!(nip55_parse_permissions(None).is_empty());
        assert!(nip55_parse_permissions(Some("not json".into())).is_empty());
        assert!(nip55_parse_permissions(Some("{}".into())).is_empty());
        assert!(
            nip55_parse_permissions(Some(r#"[{"type":"sign_event","kind":99999}]"#.into()))
                .is_empty()
        );
    }

    #[test]
    fn parse_permissions_empty_array_is_empty() {
        assert!(nip55_parse_permissions(Some("[]".into())).is_empty());
    }

    #[test]
    fn parse_permissions_dedups_to_first_seen() {
        let json = r#"[{"type":"nip44_decrypt"},{"type":"nip44_decrypt"},{"type":"sign_event","kind":1},{"type":"sign_event","kind":1}]"#;
        let perms = nip55_parse_permissions(Some(json.into()));
        assert_eq!(
            perms,
            vec![
                Nip55DeclaredPermission {
                    request_type: Nip55RequestType::Nip44Decrypt,
                    kind: None,
                },
                Nip55DeclaredPermission {
                    request_type: Nip55RequestType::SignEvent,
                    kind: Some(1),
                },
            ]
        );
    }

    #[test]
    fn parse_permissions_drops_get_public_key() {
        let json = r#"[{"type":"get_public_key"},{"type":"nip44_decrypt"}]"#;
        let perms = nip55_parse_permissions(Some(json.into()));
        assert_eq!(
            perms,
            vec![Nip55DeclaredPermission {
                request_type: Nip55RequestType::Nip44Decrypt,
                kind: None,
            }]
        );
    }

    #[test]
    fn parse_permissions_drops_non_object_elements() {
        let perms = nip55_parse_permissions(Some(r#"["sign_event",42,null]"#.into()));
        assert!(perms.is_empty());
    }

    #[test]
    fn parse_permissions_drops_string_kind() {
        let json = r#"[{"type":"sign_event","kind":"22242"}]"#;
        assert!(nip55_parse_permissions(Some(json.into())).is_empty());
    }

    #[test]
    fn parse_permissions_enforces_count_cap() {
        let entries: Vec<String> = (0..MAX_PERMISSIONS_COUNT as i32 + 10)
            .map(|k| format!(r#"{{"type":"sign_event","kind":{k}}}"#))
            .collect();
        let json = format!("[{}]", entries.join(","));
        let perms = nip55_parse_permissions(Some(json));
        assert_eq!(perms.len(), MAX_PERMISSIONS_COUNT);
    }

    #[test]
    fn parse_permissions_rejects_oversized_input() {
        let entry = r#"{"type":"nip44_decrypt"}"#;
        let count = MAX_PERMISSIONS_JSON_BYTES / entry.len() + 10;
        let json = format!("[{}]", vec![entry; count].join(","));
        assert!(json.len() > MAX_PERMISSIONS_JSON_BYTES);
        assert!(nip55_parse_permissions(Some(json)).is_empty());
    }

    #[test]
    fn batch_results_preserves_order_and_mixes_outcomes() {
        let responses = vec![
            Nip55Response {
                result: "ok".into(),
                event: None,
                error: None,
                id: Some("1".into()),
                rejected: false,
            },
            Nip55Response {
                result: String::new(),
                event: None,
                error: Some("boom".into()),
                id: Some("2".into()),
                rejected: false,
            },
        ];
        let json: serde_json::Value =
            serde_json::from_str(&serialize_batch_results_json(&responses)).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 2);
        assert_eq!(json[0]["result"], "ok");
        assert_eq!(json[1]["id"], "2");
        assert_eq!(json[1]["rejected"], true);
    }

    #[test]
    fn batch_results_rejected_flag_emits_rejected_without_error() {
        let responses = vec![Nip55Response {
            result: String::new(),
            event: None,
            error: None,
            id: Some("r".into()),
            rejected: true,
        }];
        let json: serde_json::Value =
            serde_json::from_str(&serialize_batch_results_json(&responses)).unwrap();
        let obj = &json[0];
        assert_eq!(obj["id"], "r");
        assert!(obj["signature"].is_null());
        assert!(obj["result"].is_null());
        assert_eq!(obj["rejected"], true);
    }

    #[test]
    fn batch_results_rejected_nulls_populated_result() {
        let responses = vec![Nip55Response {
            result: "should-be-ignored".into(),
            event: None,
            error: None,
            id: Some("r".into()),
            rejected: true,
        }];
        let json: serde_json::Value =
            serde_json::from_str(&serialize_batch_results_json(&responses)).unwrap();
        let obj = &json[0];
        assert_eq!(obj["id"], "r");
        assert!(obj["result"].is_null());
        assert!(obj["signature"].is_null());
        assert_eq!(obj["rejected"], true);
    }

    #[test]
    fn batch_results_empty_is_empty_array() {
        assert_eq!(serialize_batch_results_json(&[]), "[]");
    }

    // Amber's batch wire format puts the signature in BOTH `signature` and
    // `result` and never emits the assembled event; the per-request `event`
    // payload is only for the single-result intent path.
    #[test]
    fn batch_results_sign_event_uses_signature_not_event() {
        let responses = vec![Nip55Response {
            result: "sighex".into(),
            event: Some("{\"id\":\"deadbeef\",\"sig\":\"sighex\"}".into()),
            error: None,
            id: Some("c".into()),
            rejected: false,
        }];
        let json: serde_json::Value =
            serde_json::from_str(&serialize_batch_results_json(&responses)).unwrap();
        let obj = &json[0];
        assert_eq!(obj["signature"], "sighex");
        assert_eq!(obj["result"], "sighex");
        assert!(obj.get("event").is_none());
    }
}
