// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use keep_core::error::{CryptoError, KeepError, Result};
use keep_core::keyring::Keyring;

use crate::audit::{AuditAction, AuditEntry, AuditLog};
use crate::frost_signer::{FrostSigner, NetworkFrostSigner};
use crate::permissions::{AppPermission, Permission, PermissionDuration, PermissionManager};
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::types::{
    ApprovalRequest, ApprovalResult, HttpAuthDetails, RememberDuration, ServerCallbacks,
    NIP98_HTTP_AUTH, NIP98_MAX_REMEMBER_SECS,
};

/// Max displayed length of a NIP-98 `u`/`method` value. A kilobyte-scale tag
/// would push the approve/deny controls off-screen (layout DoS) and bury the
/// real request; legitimate HTTP-auth targets are far shorter than this.
const NIP98_DISPLAY_MAX: usize = 512;

/// Cap for the event-content preview shown in a sign-approval prompt. Longer
/// than a URL/method since content is free-form, but still bounded so a huge
/// content cannot push the approve/reject line off-screen.
const CONTENT_PREVIEW_MAX: usize = 256;

/// Cap for the client-declared app name shown in an approval prompt. App names
/// are short labels; a longer one is truncated so it cannot bury the prompt.
const APP_NAME_DISPLAY_MAX: usize = 64;

/// Cap for the NIP-46 method shown in an approval prompt. Method names are short
/// identifiers (`sign_event`, `nip44_encrypt`, ...), so this is generous.
const METHOD_DISPLAY_MAX: usize = 32;

/// Neutralize an attacker-controlled string before it reaches an approval
/// prompt. The value (a NIP-98 `u`/`method` tag, or the content of an event to
/// be signed) is fully attacker-controlled, so strip the characters that let it
/// read as different (trusted) text or inject extra lines: bidi
/// overrides/isolates, zero-width and BOM code points, and every control
/// character (newlines and tabs included). Then truncate to `max` so an
/// oversized value cannot hide the rest of the prompt. Applied at this single
/// choke point so every surface (CLI/desktop/mobile/web) inherits it; callers
/// pass a per-surface `max` (a short cap for a URL/method, a longer one for a
/// content preview).
pub fn sanitize_prompt_field(value: &str, max: usize) -> String {
    let mut out: String = value
        .chars()
        .filter(|c| {
            // Explicit bidi/format/zero-width code points that are NOT in the
            // `Cc` control category `is_control()` covers: line/paragraph
            // separators (Zl/Zp) and the Arabic letter mark (Cf bidi control).
            !matches!(c,
                '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{2029}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
            ) && !c.is_control()
        })
        .collect();
    if out.chars().count() > max {
        out = out.chars().take(max).collect::<String>() + "...";
    }
    out
}

/// Extract the NIP-98 (kind 27235) HTTP-auth target from a sign request so the
/// approval prompt can show the `u`/method the signature will authenticate.
/// Returns `None` for every other kind. A 27235 event that omits `u` or
/// `method` still returns `Some` with the missing field as `None`: the prompt
/// must surface a malformed HTTP-auth request, not silently drop it. The `u`
/// and `method` values are sanitized (see [`sanitize_prompt_field`]) since
/// they are attacker-controlled and land directly in a signing-approval prompt.
fn nip98_http_auth(event: &UnsignedEvent) -> Option<HttpAuthDetails> {
    if event.kind != NIP98_HTTP_AUTH {
        return None;
    }
    let mut url = None;
    let mut method = None;
    // An empty or all-stripped value collapses to `None` so every surface shows
    // its "unspecified" fallback rather than a blank.
    let sanitized = |slice: &[String]| {
        slice
            .get(1)
            .map(|v| sanitize_prompt_field(v, NIP98_DISPLAY_MAX))
            .filter(|s| !s.is_empty())
    };
    for tag in event.tags.iter() {
        let slice = tag.as_slice();
        match slice.first().map(String::as_str) {
            Some("u") if url.is_none() => url = sanitized(slice),
            Some("method") if method.is_none() => method = sanitized(slice),
            _ => {}
        }
    }
    Some(HttpAuthDetails { url, method })
}

fn clamp_nip98_remember(remember: RememberDuration) -> RememberDuration {
    match remember.as_seconds() {
        None if remember == RememberDuration::JustThisTime => RememberDuration::JustThisTime,
        None => RememberDuration::TenMinutes,
        Some(secs) if secs <= NIP98_MAX_REMEMBER_SECS => remember,
        Some(_) => RememberDuration::TenMinutes,
    }
}

fn prepare_frost_event(
    pubkey: PublicKey,
    unsigned: &UnsignedEvent,
) -> Result<(UnsignedEvent, EventId)> {
    let mut frost_event = UnsignedEvent::new(
        pubkey,
        unsigned.created_at,
        unsigned.kind,
        unsigned.tags.clone(),
        unsigned.content.clone(),
    );
    frost_event.ensure_id();
    let event_id = frost_event
        .id
        .ok_or_else(|| KeepError::Runtime("failed to compute event ID".into()))?;
    Ok((frost_event, event_id))
}

fn assemble_signed_event(
    event_id: EventId,
    pubkey: PublicKey,
    frost_event: UnsignedEvent,
    sig_bytes: &[u8],
) -> Result<Event> {
    let sig = nostr_sdk::secp256k1::schnorr::Signature::from_slice(sig_bytes)
        .map_err(|e| CryptoError::invalid_signature(e.to_string()))?;
    Ok(Event::new(
        event_id,
        pubkey,
        frost_event.created_at,
        frost_event.kind,
        frost_event.tags,
        frost_event.content,
        sig,
    ))
}

fn parse_permission_string(perms: &str) -> (Permission, HashSet<Kind>) {
    let mut result = Permission::empty();
    let mut auto_kinds = HashSet::new();
    for part in perms.split(',') {
        let trimmed = part.trim();
        if let Some(kind_str) = trimmed.strip_prefix("sign_event:") {
            result |= Permission::SIGN_EVENT;
            if let Ok(kind_num) = kind_str.parse::<u16>() {
                auto_kinds.insert(Kind::from(kind_num));
            }
        } else {
            match trimmed {
                "get_public_key" => result |= Permission::GET_PUBLIC_KEY,
                "sign_event" => result |= Permission::SIGN_EVENT,
                "nip04_encrypt" => result |= Permission::NIP04_ENCRYPT,
                "nip04_decrypt" => result |= Permission::NIP04_DECRYPT,
                "nip44_encrypt" => result |= Permission::NIP44_ENCRYPT,
                "nip44_decrypt" => result |= Permission::NIP44_DECRYPT,
                _ => {}
            }
        }
    }
    if result.is_empty() {
        (Permission::DEFAULT, auto_kinds)
    } else {
        (result | Permission::GET_PUBLIC_KEY, auto_kinds)
    }
}

pub struct SignerHandler {
    keyring: Arc<Mutex<Keyring>>,
    frost_signer: Option<Arc<Mutex<FrostSigner>>>,
    network_frost_signer: Option<Arc<NetworkFrostSigner>>,
    permissions: Arc<Mutex<PermissionManager>>,
    audit: Arc<Mutex<AuditLog>>,
    callbacks: Option<Arc<dyn ServerCallbacks>>,
    rate_limiters: Mutex<HashMap<PublicKey, RateLimiter>>,
    rate_limit_config: Option<RateLimitConfig>,
    new_conn_timestamps: Mutex<VecDeque<Instant>>,
    expected_secret: Option<Zeroizing<String>>,
    auto_approve: bool,
    /// Permissions granted to a client that connects without requesting any
    /// (many clients, e.g. nostr-tools, send no `connect` permissions). The
    /// act of approving the connection is the grant. Defaults to the
    /// least-privilege `Permission::DEFAULT`.
    connect_grant: Permission,
    /// Event kinds auto-approved per-app for every client that completes the
    /// connect handshake, granted to that specific app pubkey (revocable,
    /// auditable) rather than via the blanket `global_auto_approve` set. The
    /// mobile bunker uses this to auto-approve NIP-98 (kind 27235) for connected
    /// web clients without making it a global rule for unconnected apps.
    connect_auto_approve_kinds: HashSet<Kind>,
    relay_urls: Vec<String>,
    kill_switch: Arc<AtomicBool>,
    /// The transport (bunker URL) pubkey clients connect to. For a remote
    /// signer this differs from the signing identity returned by
    /// `get_public_key` (network-FROST: transport key vs group key), so the
    /// `connect` handshake must validate the client's target against this, not
    /// the signing pubkey.
    transport_pubkey: Option<PublicKey>,
}

impl SignerHandler {
    pub fn new(
        keyring: Arc<Mutex<Keyring>>,
        permissions: Arc<Mutex<PermissionManager>>,
        audit: Arc<Mutex<AuditLog>>,
        callbacks: Option<Arc<dyn ServerCallbacks>>,
    ) -> Self {
        Self {
            keyring,
            frost_signer: None,
            network_frost_signer: None,
            permissions,
            audit,
            callbacks,
            rate_limiters: Mutex::new(HashMap::new()),
            rate_limit_config: None,
            new_conn_timestamps: Mutex::new(VecDeque::new()),
            expected_secret: None,
            auto_approve: false,
            connect_grant: Permission::DEFAULT,
            connect_auto_approve_kinds: HashSet::new(),
            relay_urls: Vec::new(),
            kill_switch: Arc::new(AtomicBool::new(false)),
            transport_pubkey: None,
        }
    }

    pub fn with_transport_pubkey(mut self, pubkey: PublicKey) -> Self {
        self.transport_pubkey = Some(pubkey);
        self
    }

    pub fn with_expected_secret(mut self, secret: String) -> Self {
        self.expected_secret = Some(Zeroizing::new(secret));
        self
    }

    pub fn with_connect_grant(mut self, grant: Permission) -> Self {
        self.connect_grant = grant;
        self
    }

    pub fn with_connect_auto_approve_kinds(mut self, kinds: HashSet<Kind>) -> Self {
        self.connect_auto_approve_kinds = kinds;
        self
    }

    pub fn with_auto_approve(mut self, auto_approve: bool) -> Self {
        self.auto_approve = auto_approve;
        self
    }

    pub fn with_frost_signer(mut self, signer: FrostSigner) -> Self {
        self.frost_signer = Some(Arc::new(Mutex::new(signer)));
        self
    }

    pub fn with_network_frost_signer(mut self, signer: NetworkFrostSigner) -> Self {
        self.network_frost_signer = Some(Arc::new(signer));
        self
    }

    pub fn with_rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit_config = Some(config);
        self
    }

    pub fn with_relay_urls(mut self, urls: Vec<String>) -> Self {
        self.relay_urls = urls;
        self
    }

    pub fn with_kill_switch(mut self, kill_switch: Arc<AtomicBool>) -> Self {
        self.kill_switch = kill_switch;
        self
    }

    pub fn set_kill_switch(&self, active: bool) {
        self.kill_switch.store(active, Ordering::Release);
    }

    fn check_kill_switch(&self) -> Result<()> {
        if self.kill_switch.load(Ordering::Acquire) {
            Err(KeepError::PermissionDenied(
                "kill switch active: all signing blocked".into(),
            ))
        } else {
            Ok(())
        }
    }

    const MAX_RATE_LIMITERS: usize = 1_000;
    const MAX_NEW_CONNS_PER_MINUTE: usize = 50;

    async fn check_rate_limit(&self, app_pubkey: &PublicKey) -> Result<()> {
        let config = match &self.rate_limit_config {
            Some(c) => c,
            None => return Ok(()),
        };

        let mut limiters = self.rate_limiters.lock().await;

        if !limiters.contains_key(app_pubkey) {
            let mut timestamps = self.new_conn_timestamps.lock().await;
            let cutoff = Instant::now() - std::time::Duration::from_secs(60);
            while timestamps.front().is_some_and(|&t| t < cutoff) {
                timestamps.pop_front();
            }
            if timestamps.len() >= Self::MAX_NEW_CONNS_PER_MINUTE {
                return Err(KeepError::RateLimited(60));
            }
            timestamps.push_back(Instant::now());

            if limiters.len() >= Self::MAX_RATE_LIMITERS {
                limiters.retain(|_, rl| {
                    rl.cleanup();
                    !rl.is_empty()
                });
                if limiters.len() >= Self::MAX_RATE_LIMITERS {
                    let oldest_key = limiters
                        .iter()
                        .min_by_key(|(_, rl)| rl.last_used())
                        .map(|(k, _)| *k);
                    if let Some(key) = oldest_key {
                        limiters.remove(&key);
                    }
                }
            }
        }

        let limiter = limiters
            .entry(*app_pubkey)
            .or_insert_with(|| RateLimiter::new(config.clone()));

        if limiter.check_and_record().is_allowed() {
            Ok(())
        } else {
            Err(KeepError::RateLimited(60))
        }
    }

    async fn require_permission(&self, app_pubkey: &PublicKey, perm: Permission) -> Result<()> {
        let pm = self.permissions.lock().await;
        if pm.has_permission(app_pubkey, perm) {
            Ok(())
        } else {
            drop(pm);
            self.audit.lock().await.log(
                AuditEntry::new(AuditAction::PermissionDenied, *app_pubkey)
                    .with_success(false)
                    .with_reason(format!("{perm:?} not permitted")),
            );
            Err(KeepError::PermissionDenied(
                "operation not permitted".into(),
            ))
        }
    }

    pub(crate) async fn our_pubkey(&self) -> Result<PublicKey> {
        if let Some(ref net_frost) = self.network_frost_signer {
            Ok(PublicKey::from_slice(net_frost.group_pubkey())
                .map_err(|e| CryptoError::invalid_key(format!("pubkey: {e}")))?)
        } else if let Some(ref frost) = self.frost_signer {
            let signer = frost.lock().await;
            Ok(PublicKey::from_slice(signer.group_pubkey())
                .map_err(|e| CryptoError::invalid_key(format!("pubkey: {e}")))?)
        } else {
            let keyring = self.keyring.lock().await;
            let slot = keyring
                .get_primary()
                .ok_or_else(|| KeepError::KeyNotFound("no signing key".into()))?;
            Ok(PublicKey::from_slice(&slot.pubkey)
                .map_err(|e| CryptoError::invalid_key(format!("pubkey: {e}")))?)
        }
    }

    pub async fn handle_connect(
        &self,
        app_pubkey: PublicKey,
        our_pubkey: Option<PublicKey>,
        secret: Option<String>,
        permissions: Option<String>,
    ) -> Result<()> {
        self.check_rate_limit(&app_pubkey).await?;

        let app_id = &app_pubkey.to_hex()[..8];
        let name = format!("App {app_id}");

        if let Some(ref expected) = self.expected_secret {
            let expected_hash = Sha256::digest(expected.as_bytes());
            let valid = match &secret {
                Some(s) => {
                    let provided_hash = Sha256::digest(s.as_bytes());
                    provided_hash.ct_eq(&expected_hash).into()
                }
                None => false,
            };
            if !valid {
                self.audit.lock().await.log(
                    AuditEntry::new(AuditAction::Connect, app_pubkey)
                        .with_success(false)
                        .with_reason("invalid secret"),
                );
                return Err(KeepError::PermissionDenied("invalid secret".into()));
            }
        } else if !self.auto_approve {
            // Connect-time approval ignores the remember-duration today: the
            // app-level lifetime is configured separately via the bunker's
            // existing connect path. Per-kind remember semantics apply at
            // `sign_event` (where #575 surfaced the silent NIP-98 grant).
            let result = self
                .request_approval(ApprovalRequest {
                    app_pubkey,
                    app_name: name.clone(),
                    method: "connect".into(),
                    event_kind: None,
                    event_content: None,
                    requested_permissions: permissions.clone(),
                    http_auth: None,
                })
                .await;
            if !result.approved {
                return Err(KeepError::UserRejected);
            }
        }

        if let Some(expected) = our_pubkey {
            // The client targets the transport (bunker URL) pubkey, which for a
            // remote signer differs from the signing identity. Validate against
            // the transport pubkey when known, falling back to the signing key
            // (single-key mode, where they are the same).
            let actual = match self.transport_pubkey {
                Some(pk) => pk,
                None => self.our_pubkey().await?,
            };
            if expected != actual {
                return Err(CryptoError::invalid_key("pubkey mismatch").into());
            }
        }

        let (mut requested_perms, mut auto_kinds) = permissions
            .as_deref()
            .map(parse_permission_string)
            .unwrap_or((self.connect_grant, HashSet::new()));
        auto_kinds.extend(self.connect_auto_approve_kinds.iter().copied());

        if self.auto_approve {
            requested_perms = Permission::ALL;
        }

        let mut pm = self.permissions.lock().await;
        if !pm.connect_with_permissions(app_pubkey, name.clone(), requested_perms, auto_kinds) {
            return Err(KeepError::CapacityExceeded(
                "too many connected apps".into(),
            ));
        }
        drop(pm);

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::Connect, app_pubkey).with_app_name(&name));

        info!(app_id, "app connected");
        Ok(())
    }

    pub async fn handle_get_public_key(&self, app_pubkey: PublicKey) -> Result<PublicKey> {
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::GET_PUBLIC_KEY)
            .await?;

        let pubkey = self.our_pubkey().await?;

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::GetPublicKey, app_pubkey));

        Ok(pubkey)
    }

    pub async fn handle_sign_event(
        &self,
        app_pubkey: PublicKey,
        unsigned_event: UnsignedEvent,
    ) -> Result<Event> {
        self.check_kill_switch()?;
        self.check_rate_limit(&app_pubkey).await?;

        let kind = unsigned_event.kind;

        self.require_permission(&app_pubkey, Permission::SIGN_EVENT)
            .await?;

        let needs_approval = self
            .permissions
            .lock()
            .await
            .needs_approval(&app_pubkey, kind);

        if needs_approval {
            let result = self
                .request_approval(ApprovalRequest {
                    app_pubkey,
                    app_name: self.get_app_name(&app_pubkey).await,
                    method: "sign_event".into(),
                    event_kind: Some(kind),
                    // Sanitize the content preview like the NIP-98 fields: it is
                    // attacker-controlled and lands in the same approval popup,
                    // where an unstripped newline/bidi sequence could inject fake
                    // lines or reorder text above the approve prompt.
                    event_content: Some(sanitize_prompt_field(
                        &unsigned_event.content,
                        CONTENT_PREVIEW_MAX,
                    )),
                    requested_permissions: None,
                    http_auth: nip98_http_auth(&unsigned_event),
                })
                .await;

            if !result.approved {
                self.audit.lock().await.log(
                    AuditEntry::new(AuditAction::UserRejected, app_pubkey)
                        .with_event_kind(kind)
                        .with_success(false),
                );
                return Err(KeepError::UserRejected);
            }

            // #575: when the user approves with a remember-duration, persist
            // a per-app, per-kind grant so subsequent requests within the
            // window skip the prompt. `JustThisTime` is the one-shot default
            // and does not persist; the next request prompts again.
            //
            // #613: NIP-98 (kind 27235) carries security-relevant url/method
            // in tags the prompt does not surface, so a long-lived grant would
            // auto-approve any url/method after one tap (bearer-credential
            // threat). The remember is opt-in and clamped to a short window
            // (`NIP98_MAX_REMEMBER_SECS`); `Forever` is never honored.
            let remember = if kind == NIP98_HTTP_AUTH {
                clamp_nip98_remember(result.remember)
            } else {
                result.remember
            };
            match remember {
                RememberDuration::JustThisTime => {}
                RememberDuration::Forever => {
                    let granted = self
                        .permissions
                        .lock()
                        .await
                        .grant_kind_forever(&app_pubkey, kind);
                    if granted {
                        self.audit.lock().await.log(
                            AuditEntry::new(AuditAction::PermissionChanged, app_pubkey)
                                .with_event_kind(kind)
                                .with_reason("grant kind forever"),
                        );
                        self.persist_permissions().await;
                    }
                }
                timed => {
                    if let Some(secs) = timed.as_seconds() {
                        let granted =
                            self.permissions
                                .lock()
                                .await
                                .grant_kind_for(&app_pubkey, kind, secs);
                        if granted {
                            self.audit.lock().await.log(
                                AuditEntry::new(AuditAction::PermissionChanged, app_pubkey)
                                    .with_event_kind(kind)
                                    .with_reason(format!("grant kind for {secs}s")),
                            );
                            self.persist_permissions().await;
                        }
                    }
                }
            }
        }

        self.check_kill_switch()?;

        let signed_event = if let Some(ref net_frost) = self.network_frost_signer {
            let pubkey = PublicKey::from_slice(net_frost.group_pubkey())
                .map_err(|e| CryptoError::invalid_key(format!("pubkey: {e}")))?;
            let (frost_event, event_id) = prepare_frost_event(pubkey, &unsigned_event)?;
            // #529: pass the full unsigned event as a structured payload so
            // co-signers can recompute the id and reject a cross-domain
            // label spoof (e.g. a Bitcoin sighash relabeled as nostr-event).
            let sig_bytes = net_frost
                .sign_nostr_event(event_id.as_bytes(), &frost_event)
                .await?;
            assemble_signed_event(event_id, pubkey, frost_event, &sig_bytes)?
        } else if let Some(ref frost) = self.frost_signer {
            let signer = frost.lock().await;
            let pubkey = PublicKey::from_slice(signer.group_pubkey())
                .map_err(|e| CryptoError::invalid_key(format!("pubkey: {e}")))?;
            let (frost_event, event_id) = prepare_frost_event(pubkey, &unsigned_event)?;
            let sig_bytes = signer.sign(event_id.as_bytes())?;
            assemble_signed_event(event_id, pubkey, frost_event, &sig_bytes)?
        } else {
            let keyring = self.keyring.lock().await;
            let slot = keyring
                .get_primary()
                .ok_or_else(|| KeepError::KeyNotFound("no signing key".into()))?;

            let keypair = slot.to_nostr_keypair()?;
            let secret = SecretKey::from_slice(keypair.secret_bytes())
                .map_err(|e| CryptoError::invalid_key(format!("secret key: {e}")))?;
            let keys = Keys::new(secret);

            unsigned_event
                .sign(&keys)
                .await
                .map_err(|e| CryptoError::invalid_signature(format!("signing: {e}")))?
        };

        let mut keyring = self.keyring.lock().await;
        if let Some(slot) = keyring.get_primary_mut() {
            slot.session_sign_count += 1;
        }
        drop(keyring);

        self.permissions.lock().await.record_usage(&app_pubkey);

        self.audit.lock().await.log(
            AuditEntry::new(AuditAction::SignEvent, app_pubkey)
                .with_event_kind(kind)
                .with_event_id(signed_event.id),
        );

        let event_kind = kind.as_u16();
        let event_id = &signed_event.id.to_hex()[..8];
        debug!(event_kind, event_id, "signed event");
        Ok(signed_event)
    }

    async fn primary_secret_key(&self) -> Result<SecretKey> {
        let keyring = self.keyring.lock().await;
        let slot = keyring
            .get_primary()
            .ok_or_else(|| KeepError::KeyNotFound("no signing key".into()))?;
        let keypair = slot.to_nostr_keypair()?;
        Ok(SecretKey::from_slice(keypair.secret_bytes())
            .map_err(|e| CryptoError::invalid_key(format!("secret key: {e}")))?)
    }

    async fn require_approval(&self, app_pubkey: PublicKey, method: &str) -> Result<()> {
        let request = ApprovalRequest {
            app_pubkey,
            app_name: self.get_app_name(&app_pubkey).await,
            method: method.into(),
            event_kind: None,
            event_content: None,
            requested_permissions: None,
            http_auth: None,
        };
        if self.request_approval(request).await.approved {
            Ok(())
        } else {
            self.audit
                .lock()
                .await
                .log(AuditEntry::new(AuditAction::UserRejected, app_pubkey).with_reason(method));
            Err(KeepError::UserRejected)
        }
    }

    pub async fn handle_nip44_encrypt(
        &self,
        app_pubkey: PublicKey,
        recipient: PublicKey,
        plaintext: &str,
    ) -> Result<String> {
        self.check_kill_switch()?;
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::NIP44_ENCRYPT)
            .await?;
        self.require_approval(app_pubkey, "nip44_encrypt").await?;
        self.check_kill_switch()?;
        let secret = self.primary_secret_key().await?;
        let ciphertext = nip44::encrypt(&secret, &recipient, plaintext, nip44::Version::V2)
            .map_err(|e| CryptoError::encryption(format!("NIP-44: {e}")))?;

        self.audit.lock().await.log(
            AuditEntry::new(AuditAction::Nip44Encrypt, app_pubkey).with_peer_pubkey(recipient),
        );

        Ok(ciphertext)
    }

    pub async fn handle_nip44_decrypt(
        &self,
        app_pubkey: PublicKey,
        sender: PublicKey,
        ciphertext: &str,
    ) -> Result<String> {
        self.check_kill_switch()?;
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::NIP44_DECRYPT)
            .await?;
        self.require_approval(app_pubkey, "nip44_decrypt").await?;
        self.check_kill_switch()?;

        let secret = self.primary_secret_key().await?;
        let plaintext = nip44::decrypt(&secret, &sender, ciphertext)
            .map_err(|e| CryptoError::decryption(format!("NIP-44: {e}")))?;

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::Nip44Decrypt, app_pubkey).with_peer_pubkey(sender));

        Ok(plaintext)
    }

    pub async fn handle_nip04_encrypt(
        &self,
        app_pubkey: PublicKey,
        recipient: PublicKey,
        plaintext: &str,
    ) -> Result<String> {
        self.check_kill_switch()?;
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::NIP04_ENCRYPT)
            .await?;
        self.require_approval(app_pubkey, "nip04_encrypt").await?;
        self.check_kill_switch()?;
        let secret = self.primary_secret_key().await?;
        let ciphertext = nip04::encrypt(&secret, &recipient, plaintext)
            .map_err(|e| CryptoError::encryption(format!("NIP-04: {e}")))?;

        self.audit.lock().await.log(
            AuditEntry::new(AuditAction::Nip04Encrypt, app_pubkey).with_peer_pubkey(recipient),
        );

        Ok(ciphertext)
    }

    pub async fn handle_nip04_decrypt(
        &self,
        app_pubkey: PublicKey,
        sender: PublicKey,
        ciphertext: &str,
    ) -> Result<String> {
        self.check_kill_switch()?;
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::NIP04_DECRYPT)
            .await?;
        self.require_approval(app_pubkey, "nip04_decrypt").await?;
        self.check_kill_switch()?;

        let secret = self.primary_secret_key().await?;
        let plaintext = nip04::decrypt(&secret, &sender, ciphertext)
            .map_err(|e| CryptoError::decryption(format!("NIP-04: {e}")))?;

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::Nip04Decrypt, app_pubkey).with_peer_pubkey(sender));

        Ok(plaintext)
    }

    pub async fn handle_switch_relays(&self, app_pubkey: PublicKey) -> Result<Option<Vec<String>>> {
        self.check_kill_switch()?;
        self.check_rate_limit(&app_pubkey).await?;
        self.require_permission(&app_pubkey, Permission::GET_PUBLIC_KEY)
            .await?;

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::SwitchRelays, app_pubkey));

        let relays = (!self.relay_urls.is_empty()).then(|| self.relay_urls.clone());
        Ok(relays)
    }

    pub async fn register_client(
        &self,
        app_pubkey: PublicKey,
        name: String,
        permissions_str: Option<&str>,
    ) -> Result<()> {
        self.check_rate_limit(&app_pubkey).await?;

        let (requested_perms, mut auto_kinds) = permissions_str
            .map(parse_permission_string)
            .unwrap_or((self.connect_grant, HashSet::new()));
        auto_kinds.extend(self.connect_auto_approve_kinds.iter().copied());

        let mut pm = self.permissions.lock().await;
        if !pm.connect_with_permissions(app_pubkey, name.clone(), requested_perms, auto_kinds) {
            return Err(KeepError::CapacityExceeded(
                "too many connected apps".into(),
            ));
        }
        drop(pm);

        self.audit
            .lock()
            .await
            .log(AuditEntry::new(AuditAction::Connect, app_pubkey).with_app_name(&name));

        info!(app_id = &app_pubkey.to_hex()[..8], "client registered");
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn restore_client(
        &self,
        pubkey: PublicKey,
        name: String,
        permissions: Permission,
        auto_kinds: HashSet<Kind>,
        duration: PermissionDuration,
        connected_at: Timestamp,
        timed_kind_grants: HashMap<Kind, u64>,
        explicitly_remembered: Option<bool>,
    ) {
        let mut pm = self.permissions.lock().await;
        pm.restore_persisted(
            pubkey,
            name,
            permissions,
            auto_kinds,
            duration,
            connected_at,
            timed_kind_grants,
            explicitly_remembered,
        );
    }

    pub async fn update_client_permissions(&self, pubkey: &PublicKey, permissions: Permission) {
        let mut pm = self.permissions.lock().await;
        pm.set_permissions(pubkey, permissions);
        drop(pm);
        self.audit.lock().await.log(
            AuditEntry::new(AuditAction::PermissionChanged, *pubkey)
                .with_reason(format!("permissions={permissions:?}")),
        );
        self.persist_permissions().await;
    }

    pub async fn update_client_duration(&self, pubkey: &PublicKey, duration: PermissionDuration) {
        let mut pm = self.permissions.lock().await;
        pm.set_duration(pubkey, duration);
        drop(pm);
        self.audit.lock().await.log(
            AuditEntry::new(AuditAction::PermissionChanged, *pubkey)
                .with_reason(format!("duration={duration:?}")),
        );
        self.persist_permissions().await;
    }

    pub async fn update_client_auto_kinds(&self, pubkey: &PublicKey, kinds: HashSet<Kind>) {
        let mut pm = self.permissions.lock().await;
        pm.set_auto_approve_kinds_for_app(pubkey, kinds);
        drop(pm);
        self.audit.lock().await.log(
            AuditEntry::new(AuditAction::PermissionChanged, *pubkey)
                .with_reason("auto_approve_kinds updated"),
        );
        self.persist_permissions().await;
    }

    pub async fn list_clients(&self) -> Vec<AppPermission> {
        let pm = self.permissions.lock().await;
        pm.list_apps().cloned().collect()
    }

    pub async fn revoke_client(&self, pubkey: &PublicKey) {
        self.permissions.lock().await.revoke(pubkey);
        self.persist_permissions().await;
    }

    pub async fn revoke_all_clients(&self) {
        self.permissions.lock().await.revoke_all();
        self.persist_permissions().await;
    }

    /// Snapshot the current grants and hand them to the consumer's persistence
    /// callback. No-op when no callbacks are configured (e.g. headless CLI use).
    /// Called after every grant write or revoke so the durable store always
    /// mirrors the in-memory engine state, keeping the engine the single source
    /// of truth for NIP-46 remember-grants.
    async fn persist_permissions(&self) {
        let Some(ref callbacks) = self.callbacks else {
            return;
        };
        // Hold the permissions lock across both the snapshot and the durable
        // write so concurrent grant/revoke persists commit in the same order
        // they were snapshotted. Dropping the lock before the callback lets two
        // persists race (snapshot in one order, write in the reverse) and
        // durably resurrect a revoked client on the next restart.
        let pm = self.permissions.lock().await;
        let snapshot = pm.stored_snapshot();
        callbacks.persist_permissions(snapshot);
    }

    pub async fn revoke_session_apps(&self) {
        let mut pm = self.permissions.lock().await;
        pm.revoke_session_apps();
    }

    pub(crate) async fn get_app_name(&self, pubkey: &PublicKey) -> String {
        let pm = self.permissions.lock().await;
        pm.get_app(pubkey)
            .map(|app| app.name.clone())
            .unwrap_or_else(|| pubkey.to_hex()[..8].to_string())
    }

    async fn request_approval(&self, mut request: ApprovalRequest) -> ApprovalResult {
        // Sanitize the client-declared app name and method at this single choke point, which every
        // approval path funnels through before any surface callback. Without this, an app name or
        // method carrying bidi overrides (U+202E) or control characters would render raw in the
        // approval prompt an operator approves from (keep-cli TUI, keep-web, mobile, desktop) and
        // could spoof or corrupt it. The content preview and NIP-98 url/method are already sanitized
        // where they are built; this closes the same gap for app_name and method on every surface.
        request.app_name = sanitize_prompt_field(&request.app_name, APP_NAME_DISPLAY_MAX);
        request.method = sanitize_prompt_field(&request.method, METHOD_DISPLAY_MAX);
        if let Some(ref callbacks) = self.callbacks {
            return callbacks.request_approval(request);
        }
        if self.auto_approve {
            warn!(method = %request.method, "auto-approving in headless mode");
            return ApprovalResult::approved_once();
        }
        warn!(method = %request.method, "denying request: no approval callbacks configured");
        ApprovalResult::rejected()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;
    use crate::permissions::PermissionManager;
    use crate::NIP98_HTTP_AUTH;
    use keep_core::keyring::Keyring;
    use keep_core::keys::{KeyType, NostrKeypair};

    fn setup_keyring() -> Arc<Mutex<Keyring>> {
        let mut keyring = Keyring::new();
        let keypair = NostrKeypair::generate().unwrap();
        keyring
            .load_key(
                *keypair.public_bytes(),
                *keypair.secret_bytes(),
                KeyType::Nostr,
                "test".to_string(),
            )
            .unwrap();
        Arc::new(Mutex::new(keyring))
    }

    fn setup_handler() -> SignerHandler {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        SignerHandler::new(keyring, permissions, audit, None).with_auto_approve(true)
    }

    /// Records every `request_approval` invocation (by method) so a test can
    /// assert which operations triggered an interactive prompt. Approves all.
    struct RecordingCallbacks {
        methods: std::sync::Mutex<Vec<String>>,
        app_names: std::sync::Mutex<Vec<String>>,
        http_auth: std::sync::Mutex<Option<HttpAuthDetails>>,
    }
    impl RecordingCallbacks {
        fn new() -> Self {
            Self {
                methods: std::sync::Mutex::new(Vec::new()),
                app_names: std::sync::Mutex::new(Vec::new()),
                http_auth: std::sync::Mutex::new(None),
            }
        }
    }
    impl crate::types::ServerCallbacks for RecordingCallbacks {
        fn on_log(&self, _event: crate::types::LogEvent) {}
        fn request_approval(&self, request: ApprovalRequest) -> ApprovalResult {
            self.app_names.lock().unwrap().push(request.app_name);
            self.methods.lock().unwrap().push(request.method);
            if request.http_auth.is_some() {
                *self.http_auth.lock().unwrap() = request.http_auth;
            }
            ApprovalResult::approved_once()
        }
        fn on_connect(&self, _pubkey: &str, _name: &str) {}
    }

    #[tokio::test]
    async fn request_approval_sanitizes_app_name_and_method() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let cb = Arc::new(RecordingCallbacks::new());
        let handler = SignerHandler::new(keyring, permissions, audit, Some(cb.clone()));

        // A hostile app name/method carrying a bidi override and control chars must be neutralized
        // before it reaches the surface callback that renders the approval prompt.
        let request = ApprovalRequest {
            app_pubkey: Keys::generate().public_key(),
            app_name: "Ev\u{202E}il\nApp".to_string(),
            method: "sign_event\u{202E}\n".to_string(),
            event_kind: None,
            event_content: None,
            requested_permissions: None,
            http_auth: None,
        };
        handler.request_approval(request).await;

        let app = cb.app_names.lock().unwrap().last().cloned().unwrap();
        let method = cb.methods.lock().unwrap().last().cloned().unwrap();
        assert!(
            !app.contains('\u{202E}') && !app.contains('\n'),
            "app_name must be sanitized: {app:?}"
        );
        assert!(
            !method.contains('\u{202E}') && !method.contains('\n'),
            "method must be sanitized: {method:?}"
        );
        // The legitimate text survives, only the spoofing code points are stripped.
        assert_eq!(app, "EvilApp");
        assert_eq!(method, "sign_event");
    }

    // Reproduces the readstr / nostr-tools failure: a client that connects
    // WITHOUT requesting permissions only receives the least-privilege
    // `connect_grant` default (get_public_key), so signing a kind-27235
    // (NIP-98) event is denied — the client logs in but its signed requests
    // all fail. The mobile/web bunkers must override `connect_grant`.
    #[tokio::test]
    async fn default_connect_grant_denies_sign_event() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let cb = Arc::new(RecordingCallbacks::new());
        // Default connect_grant == Permission::DEFAULT (get_public_key only).
        let handler = SignerHandler::new(keyring, permissions, audit, Some(cb));

        let app = Keys::generate().public_key();
        handler.handle_connect(app, None, None, None).await.unwrap();

        let signer_pk = handler.our_pubkey().await.unwrap();
        let unsigned = UnsignedEvent::new(signer_pk, Timestamp::now(), NIP98_HTTP_AUTH, vec![], "");
        let result = handler.handle_sign_event(app, unsigned).await;
        assert!(
            result.is_err(),
            "default connect_grant must not permit sign_event"
        );
    }

    // #575: even with `connect_grant` including SIGN_EVENT and kind 27235 in
    // the global auto-approve set, a NIP-98 sign request MUST still fire the
    // per-request approval prompt. The sign succeeds only because the prompt is
    // approved; it must never be silently auto-signed.
    #[tokio::test]
    async fn http_auth_always_triggers_per_request_prompt() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        permissions
            .lock()
            .await
            .set_auto_approve_kinds(HashSet::from([NIP98_HTTP_AUTH]));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let cb = Arc::new(RecordingCallbacks::new());
        let handler = SignerHandler::new(keyring, permissions, audit, Some(cb.clone()))
            .with_connect_grant(Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT);

        let app = Keys::generate().public_key();
        handler.handle_connect(app, None, None, None).await.unwrap();

        let signer_pk = handler.our_pubkey().await.unwrap();
        let tags = vec![
            Tag::parse(["u", "https://readstr.example/api/feed"]).unwrap(),
            Tag::parse(["method", "GET"]).unwrap(),
        ];
        let unsigned = UnsignedEvent::new(signer_pk, Timestamp::now(), NIP98_HTTP_AUTH, tags, "");
        let signed = handler
            .handle_sign_event(app, unsigned)
            .await
            .expect("kind 27235 signs once the prompt is approved");
        assert_eq!(signed.kind, NIP98_HTTP_AUTH);

        let methods = cb.methods.lock().unwrap().clone();
        assert!(
            methods.iter().any(|m| m == "sign_event"),
            "kind 27235 MUST trigger a per-request approval prompt, saw: {methods:?}"
        );

        // The prompt must carry the `u`/method so the user is not approving a
        // blind HTTP-auth bearer credential (keep-qjx0).
        let http_auth = cb.http_auth.lock().unwrap().clone();
        assert_eq!(
            http_auth,
            Some(HttpAuthDetails {
                url: Some("https://readstr.example/api/feed".into()),
                method: Some("GET".into()),
            }),
            "kind 27235 approval must surface the NIP-98 url/method"
        );
    }

    #[test]
    fn nip98_http_auth_extracts_url_and_method() {
        let signer_pk = Keys::generate().public_key();
        let tags = vec![
            Tag::parse(["u", "https://blossom.example/upload"]).unwrap(),
            Tag::parse(["method", "PUT"]).unwrap(),
        ];
        let ev = UnsignedEvent::new(signer_pk, Timestamp::now(), NIP98_HTTP_AUTH, tags, "");
        assert_eq!(
            nip98_http_auth(&ev),
            Some(HttpAuthDetails {
                url: Some("https://blossom.example/upload".into()),
                method: Some("PUT".into()),
            })
        );

        // A malformed 27235 event (missing `u`) still surfaces as Some so the
        // prompt can flag the omission rather than hide the request.
        let bare = UnsignedEvent::new(signer_pk, Timestamp::now(), NIP98_HTTP_AUTH, vec![], "");
        assert_eq!(
            nip98_http_auth(&bare),
            Some(HttpAuthDetails {
                url: None,
                method: None,
            })
        );

        // Every other kind carries no HTTP-auth target.
        let note = UnsignedEvent::new(signer_pk, Timestamp::now(), Kind::TextNote, vec![], "hi");
        assert_eq!(nip98_http_auth(&note), None);
    }

    #[test]
    fn nip98_http_auth_sanitizes_spoofing_and_bounds_length() {
        let signer_pk = Keys::generate().public_key();

        // A `u` carrying an RTL-override, zero-width, line-separator and the
        // Arabic letter mark (all bidi/format code points) must not be able to
        // make the displayed URL read as a different host than what is signed.
        let spoof = "https://evil.com/\u{202E}moc.doog//:sptth\u{200B}\u{2028}\u{2029}\u{061C}";
        let ev = UnsignedEvent::new(
            signer_pk,
            Timestamp::now(),
            NIP98_HTTP_AUTH,
            vec![
                Tag::parse(["u", spoof]).unwrap(),
                Tag::parse(["method", "GET\u{0007}"]).unwrap(),
            ],
            "",
        );
        let details = nip98_http_auth(&ev).unwrap();
        let url = details.url.unwrap();
        assert_eq!(url, "https://evil.com/moc.doog//:sptth");
        assert_eq!(details.method.as_deref(), Some("GET"));

        // An empty (or all-stripped) `u`/`method` collapses to `None` so the
        // prompt shows its "unspecified" fallback, not a blank.
        let ev = UnsignedEvent::new(
            signer_pk,
            Timestamp::now(),
            NIP98_HTTP_AUTH,
            vec![
                Tag::parse(["u", ""]).unwrap(),
                Tag::parse(["method", "\u{200B}"]).unwrap(),
            ],
            "",
        );
        assert_eq!(
            nip98_http_auth(&ev),
            Some(HttpAuthDetails {
                url: None,
                method: None,
            })
        );

        // An oversized `u` is truncated so it cannot bury the approve/deny controls.
        let long = format!("https://evil.example/{}", "a".repeat(5000));
        let ev = UnsignedEvent::new(
            signer_pk,
            Timestamp::now(),
            NIP98_HTTP_AUTH,
            vec![Tag::parse(["u", &long]).unwrap()],
            "",
        );
        let url = nip98_http_auth(&ev).unwrap().url.unwrap();
        assert!(
            url.chars().count() <= NIP98_DISPLAY_MAX + 3,
            "displayed url must be length-bounded, got {} chars",
            url.chars().count()
        );
        assert!(
            url.ends_with("..."),
            "truncated url must be marked: {url:?}"
        );
    }

    #[test]
    fn sanitize_prompt_field_strips_spoofing_and_caps_by_char_count() {
        // Bidi/zero-width and every control char (newlines/tabs) are removed so
        // an attacker cannot inject fake lines or reorder text in a prompt.
        assert_eq!(
            sanitize_prompt_field("a\u{202E}b\u{200B}c\n\td", 100),
            "abcd"
        );
        // Truncation is by CHARACTER count (not bytes) and marked with an ellipsis;
        // a multibyte input proves it is not a byte cap.
        let out = sanitize_prompt_field(&"\u{00e9}".repeat(50), 10);
        assert_eq!(out.chars().count(), 13); // 10 chars + "..."
        assert!(out.ends_with("..."));
        // Clean, under-cap input is unchanged.
        assert_eq!(sanitize_prompt_field("GET", 16), "GET");
    }

    // #575: NIP-98 (kind 27235) is never auto-approved, not even per-app via
    // `connect_auto_approve_kinds`. The 27235 grant is stripped on connect, so
    // both the connected app and an unconnected one still need approval.
    #[tokio::test]
    async fn connect_auto_approve_kinds_never_cover_nip98() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, Arc::clone(&permissions), audit, None)
            .with_expected_secret("connect-secret".into())
            .with_connect_grant(Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT)
            .with_connect_auto_approve_kinds(HashSet::from([NIP98_HTTP_AUTH]));

        let connected = Keys::generate().public_key();
        handler
            .handle_connect(connected, None, Some("connect-secret".into()), None)
            .await
            .unwrap();

        let never_connected = Keys::generate().public_key();
        let pm = permissions.lock().await;
        assert!(
            pm.needs_approval(&connected, NIP98_HTTP_AUTH),
            "NIP-98 must always prompt even for a connected app"
        );
        assert!(
            pm.needs_approval(&never_connected, NIP98_HTTP_AUTH),
            "NIP-98 must always prompt for unconnected apps"
        );
        assert!(
            !pm.get_app(&connected)
                .unwrap()
                .auto_approve_kinds
                .contains(&NIP98_HTTP_AUTH),
            "NIP-98 must be stripped from the per-app auto-approve set on connect"
        );
    }

    // Requirement 3: the signer must sign the event EXACTLY as received —
    // created_at is not rewritten and tags (including the NIP-98 `payload`
    // tag) are preserved verbatim and in order.
    #[tokio::test]
    async fn sign_event_preserves_created_at_and_tags() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        permissions
            .lock()
            .await
            .set_auto_approve_kinds(HashSet::from([NIP98_HTTP_AUTH]));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None).with_auto_approve(true);

        let app = Keys::generate().public_key();
        handler.handle_connect(app, None, None, None).await.unwrap();
        let signer_pk = handler.our_pubkey().await.unwrap();

        let created_at = Timestamp::from(1_700_000_000);
        let tags = vec![
            Tag::parse(["u", "https://readstr.example/api/feed"]).unwrap(),
            Tag::parse(["method", "POST"]).unwrap(),
            Tag::parse([
                "payload",
                "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
            ])
            .unwrap(),
        ];
        let unsigned = UnsignedEvent::new(signer_pk, created_at, NIP98_HTTP_AUTH, tags.clone(), "");
        let signed = handler.handle_sign_event(app, unsigned).await.unwrap();

        assert_eq!(
            signed.created_at, created_at,
            "created_at must not be rewritten"
        );
        assert!(signed.verify().is_ok(), "signed event must verify");
        assert_eq!(
            signed.tags.to_vec(),
            tags,
            "tags must be preserved verbatim and in order"
        );
    }

    #[tokio::test]
    async fn test_handle_connect() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        let result = handler.handle_connect(app_pubkey, None, None, None).await;
        assert!(result.is_ok());

        let pm = handler.permissions.lock().await;
        assert!(pm.is_connected(&app_pubkey));
    }

    #[tokio::test]
    async fn test_auto_approve_grants_all_permissions_on_connect() {
        // Headless bunker mode (`auto_approve=true`) must grant Permission::ALL
        // on connect so that sign_event / nip04 / nip44 succeed without an
        // interactive approval callback. This is the fix for the regression
        // where headless bunkers rejected every sign_event with "Permission
        // denied: operation not permitted".
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();

        let pm = handler.permissions.lock().await;
        for perm in [
            Permission::GET_PUBLIC_KEY,
            Permission::SIGN_EVENT,
            Permission::NIP04_ENCRYPT,
            Permission::NIP04_DECRYPT,
            Permission::NIP44_ENCRYPT,
            Permission::NIP44_DECRYPT,
        ] {
            assert!(
                pm.has_permission(&app_pubkey, perm),
                "auto_approve must grant {perm:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_handle_connect_with_pubkey_mismatch() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();
        let wrong_pubkey = Keys::generate().public_key();

        let result = handler
            .handle_connect(app_pubkey, Some(wrong_pubkey), None, None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn transport_key_override_allows_connect() {
        // A remote signer's transport (bunker URL) pubkey differs from its
        // signing identity. A client targets the transport pubkey, so connect
        // must validate against it, not `our_pubkey()`.
        let transport = Keys::generate().public_key();
        let handler = setup_handler().with_transport_pubkey(transport);
        let app_pubkey = Keys::generate().public_key();

        // `transport` differs from the keyring's signing key (our_pubkey()).
        let result = handler
            .handle_connect(app_pubkey, Some(transport), None, None)
            .await;
        assert!(result.is_ok());

        // A target that is neither the transport nor signing key is rejected.
        let other = Keys::generate().public_key();
        let result = handler
            .handle_connect(Keys::generate().public_key(), Some(other), None, None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_get_public_key() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();

        let result = handler.handle_get_public_key(app_pubkey).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_get_public_key_no_permission() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        let result = handler.handle_get_public_key(app_pubkey).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_sign_event_no_permission() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        let keyring = handler.keyring.lock().await;
        let slot = keyring.get_primary().unwrap();
        let pubkey = PublicKey::from_slice(&slot.pubkey).unwrap();
        drop(keyring);

        let unsigned = UnsignedEvent::new(pubkey, Timestamp::now(), Kind::TextNote, vec![], "test");

        let result = handler.handle_sign_event(app_pubkey, unsigned).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_nip44_encrypt_decrypt() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();
        let recipient_keys = Keys::generate();
        let recipient = recipient_keys.public_key();

        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();

        {
            let mut pm = handler.permissions.lock().await;
            pm.grant(
                app_pubkey,
                "Test".into(),
                Permission::NIP44_ENCRYPT | Permission::NIP44_DECRYPT,
            );
        }

        let plaintext = "Hello, Nostr!";
        let ciphertext = handler
            .handle_nip44_encrypt(app_pubkey, recipient, plaintext)
            .await
            .unwrap();

        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, plaintext);
    }

    #[tokio::test]
    async fn test_get_app_name() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        let name = handler.get_app_name(&app_pubkey).await;
        assert_eq!(name, &app_pubkey.to_hex()[..8]);

        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();
        let name = handler.get_app_name(&app_pubkey).await;
        assert!(name.starts_with("App "));
    }

    #[test]
    fn test_parse_permission_string_with_kinds() {
        let (perms, kinds) = parse_permission_string("sign_event:1,sign_event:7,nip44_encrypt");
        assert!(perms.contains(Permission::SIGN_EVENT));
        assert!(perms.contains(Permission::NIP44_ENCRYPT));
        assert!(perms.contains(Permission::GET_PUBLIC_KEY));
        assert!(kinds.contains(&Kind::TextNote));
        assert!(kinds.contains(&Kind::Reaction));
        assert_eq!(kinds.len(), 2);
    }

    #[test]
    fn test_parse_permission_string_empty() {
        let (perms, kinds) = parse_permission_string("");
        assert_eq!(perms, Permission::DEFAULT);
        assert!(kinds.is_empty());
    }

    #[test]
    fn test_parse_permission_string_basic() {
        let (perms, kinds) = parse_permission_string("get_public_key,sign_event");
        assert!(perms.contains(Permission::GET_PUBLIC_KEY));
        assert!(perms.contains(Permission::SIGN_EVENT));
        assert!(!perms.contains(Permission::NIP44_ENCRYPT));
        assert!(kinds.is_empty());
    }

    #[tokio::test]
    async fn test_connect_with_kind_permissions() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        handler
            .handle_connect(
                app_pubkey,
                None,
                None,
                Some("sign_event:1,sign_event:7".to_string()),
            )
            .await
            .unwrap();

        let pm = handler.permissions.lock().await;
        assert!(pm.has_permission(&app_pubkey, Permission::SIGN_EVENT));
        assert!(!pm.needs_approval(&app_pubkey, Kind::TextNote));
        assert!(!pm.needs_approval(&app_pubkey, Kind::Reaction));
        assert!(pm.needs_approval(&app_pubkey, Kind::from(30023)));
    }

    #[tokio::test]
    async fn test_switch_relays_empty() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();
        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();

        let result = handler.handle_switch_relays(app_pubkey).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_switch_relays_with_urls() {
        let handler = setup_handler().with_relay_urls(vec!["wss://relay.example.com".into()]);
        let app_pubkey = Keys::generate().public_key();
        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();

        let result = handler.handle_switch_relays(app_pubkey).await.unwrap();
        assert_eq!(result, Some(vec!["wss://relay.example.com".to_string()]));
    }

    #[tokio::test]
    async fn test_update_client_permissions() {
        let handler = setup_handler().with_auto_approve(false);
        let app_pubkey = Keys::generate().public_key();
        let permissions = handler.permissions.clone();
        let mut pm = permissions.lock().await;
        pm.connect_with_permissions(
            app_pubkey,
            "test".into(),
            Permission::DEFAULT,
            HashSet::new(),
        );
        drop(pm);

        assert!(!handler
            .permissions
            .lock()
            .await
            .has_permission(&app_pubkey, Permission::SIGN_EVENT));

        handler
            .update_client_permissions(
                &app_pubkey,
                Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT,
            )
            .await;

        assert!(handler
            .permissions
            .lock()
            .await
            .has_permission(&app_pubkey, Permission::SIGN_EVENT));
    }

    #[tokio::test]
    async fn test_update_client_duration() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();
        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();

        handler
            .update_client_duration(&app_pubkey, PermissionDuration::Seconds(3600))
            .await;

        let pm = handler.permissions.lock().await;
        let app = pm.get_app(&app_pubkey).unwrap();
        assert!(matches!(app.duration, PermissionDuration::Seconds(3600)));
    }

    #[tokio::test]
    async fn test_connect_rejects_wrong_secret() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None)
            .with_expected_secret("correct_secret_value".into());

        let app_pubkey = Keys::generate().public_key();
        let result = handler
            .handle_connect(app_pubkey, None, Some("wrong_secret".into()), None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_rejects_missing_secret_when_expected() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None)
            .with_expected_secret("required_secret".into());

        let app_pubkey = Keys::generate().public_key();
        let result = handler.handle_connect(app_pubkey, None, None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_accepts_correct_secret() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None)
            .with_expected_secret("correct_secret_value".into());

        let app_pubkey = Keys::generate().public_key();
        let result = handler
            .handle_connect(app_pubkey, None, Some("correct_secret_value".into()), None)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limit_blocks_excess_requests() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None)
            .with_auto_approve(true)
            .with_rate_limit(RateLimitConfig::new(3, 100, 1000));

        let app_pubkey = Keys::generate().public_key();

        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();

        let pk_result1 = handler.handle_get_public_key(app_pubkey).await;
        assert!(pk_result1.is_ok());

        let pk_result2 = handler.handle_get_public_key(app_pubkey).await;
        assert!(pk_result2.is_ok());

        let pk_result3 = handler.handle_get_public_key(app_pubkey).await;
        assert!(
            pk_result3.is_err(),
            "should be rate limited after exceeding per-minute limit"
        );
    }

    #[tokio::test]
    async fn test_rate_limit_per_app_isolation() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None)
            .with_auto_approve(true)
            .with_rate_limit(RateLimitConfig::new(2, 100, 1000));

        let app1 = Keys::generate().public_key();
        let app2 = Keys::generate().public_key();

        handler
            .handle_connect(app1, None, None, None)
            .await
            .unwrap();
        handler
            .handle_connect(app2, None, None, None)
            .await
            .unwrap();

        assert!(handler.handle_get_public_key(app1).await.is_ok());
        assert!(handler.handle_get_public_key(app2).await.is_ok());

        assert!(handler.handle_get_public_key(app1).await.is_err());
        assert!(handler.handle_get_public_key(app2).await.is_err());
    }

    #[tokio::test]
    async fn test_global_conn_cap_before_limiter_saturation() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None)
            .with_auto_approve(true)
            .with_rate_limit(RateLimitConfig::new(100, 10_000, 100_000));

        for i in 0..SignerHandler::MAX_NEW_CONNS_PER_MINUTE {
            let pubkey = Keys::generate().public_key();
            let result = handler.handle_connect(pubkey, None, None, None).await;
            assert!(result.is_ok(), "connection {i} should succeed");
        }

        let pubkey = Keys::generate().public_key();
        let result = handler.handle_connect(pubkey, None, None, None).await;
        assert!(result.is_err(), "should hit global new-connection cap");
    }

    #[tokio::test]
    async fn test_connect_without_auto_approve_or_callbacks_is_rejected() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let handler = SignerHandler::new(keyring, permissions, audit, None);

        let app_pubkey = Keys::generate().public_key();
        let result = handler.handle_connect(app_pubkey, None, None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_revoke_client_denies_subsequent_requests() {
        let handler = setup_handler();
        let app_pubkey = Keys::generate().public_key();

        handler
            .handle_connect(app_pubkey, None, None, None)
            .await
            .unwrap();
        assert!(handler.handle_get_public_key(app_pubkey).await.is_ok());

        handler.revoke_client(&app_pubkey).await;
        assert!(handler.handle_get_public_key(app_pubkey).await.is_err());
    }

    #[tokio::test]
    async fn test_revoke_all_clients() {
        let handler = setup_handler();
        let app1 = Keys::generate().public_key();
        let app2 = Keys::generate().public_key();

        handler
            .handle_connect(app1, None, None, None)
            .await
            .unwrap();
        handler
            .handle_connect(app2, None, None, None)
            .await
            .unwrap();
        assert_eq!(handler.list_clients().await.len(), 2);

        handler.revoke_all_clients().await;
        assert_eq!(handler.list_clients().await.len(), 0);
    }

    /// Approves every request with a fixed `remember` value and counts how many
    /// `sign_event` prompts fired, so a test can assert whether a remembered
    /// grant skipped the prompt on the next request.
    struct RememberingCallbacks {
        remember: RememberDuration,
        sign_event_prompts: std::sync::atomic::AtomicUsize,
    }
    impl crate::types::ServerCallbacks for RememberingCallbacks {
        fn on_log(&self, _event: crate::types::LogEvent) {}
        fn request_approval(&self, request: ApprovalRequest) -> ApprovalResult {
            if request.method == "sign_event" {
                self.sign_event_prompts
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            ApprovalResult {
                approved: true,
                remember: self.remember,
            }
        }
        fn on_connect(&self, _pubkey: &str, _name: &str) {}
    }

    #[tokio::test]
    async fn remembered_grant_skips_next_same_kind_prompt() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let cb = Arc::new(RememberingCallbacks {
            remember: RememberDuration::Forever,
            sign_event_prompts: std::sync::atomic::AtomicUsize::new(0),
        });
        let handler = SignerHandler::new(keyring, permissions, audit, Some(cb.clone()))
            .with_connect_grant(Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT);

        let app = Keys::generate().public_key();
        handler.handle_connect(app, None, None, None).await.unwrap();
        let signer_pk = handler.our_pubkey().await.unwrap();

        let first = UnsignedEvent::new(signer_pk, Timestamp::now(), Kind::TextNote, vec![], "one");
        handler.handle_sign_event(app, first).await.unwrap();

        let second = UnsignedEvent::new(signer_pk, Timestamp::now(), Kind::TextNote, vec![], "two");
        handler.handle_sign_event(app, second).await.unwrap();

        assert_eq!(
            cb.sign_event_prompts
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a Forever grant must skip the prompt on the next same-kind request"
        );
    }

    #[tokio::test]
    async fn nip98_forever_is_clamped_to_timed_remember() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let cb = Arc::new(RememberingCallbacks {
            remember: RememberDuration::Forever,
            sign_event_prompts: std::sync::atomic::AtomicUsize::new(0),
        });
        let handler =
            SignerHandler::new(keyring, Arc::clone(&permissions), audit, Some(cb.clone()))
                .with_connect_grant(Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT);

        let app = Keys::generate().public_key();
        handler.handle_connect(app, None, None, None).await.unwrap();
        let signer_pk = handler.our_pubkey().await.unwrap();

        let tags = vec![
            Tag::parse(["u", "https://a.example/api"]).unwrap(),
            Tag::parse(["method", "GET"]).unwrap(),
        ];
        let first = UnsignedEvent::new(
            signer_pk,
            Timestamp::now(),
            NIP98_HTTP_AUTH,
            tags.clone(),
            "",
        );
        handler.handle_sign_event(app, first).await.unwrap();

        let second = UnsignedEvent::new(signer_pk, Timestamp::now(), NIP98_HTTP_AUTH, tags, "");
        handler.handle_sign_event(app, second).await.unwrap();

        assert_eq!(
            cb.sign_event_prompts
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "NIP-98 Forever is clamped to a timed remember, so the second request must skip the prompt"
        );
        let pm = permissions.lock().await;
        let granted = pm.get_app(&app).unwrap();
        assert!(
            !granted.auto_approve_kinds.contains(&NIP98_HTTP_AUTH),
            "NIP-98 must never be granted forever (auto-approve kind)"
        );
        assert!(
            granted.has_unexpired_timed_grant(NIP98_HTTP_AUTH),
            "NIP-98 Forever must be persisted as a short timed grant"
        );
    }

    #[tokio::test]
    async fn nip98_opt_in_short_remember_skips_next_prompt() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let cb = Arc::new(RememberingCallbacks {
            remember: RememberDuration::OneMinute,
            sign_event_prompts: std::sync::atomic::AtomicUsize::new(0),
        });
        let handler =
            SignerHandler::new(keyring, Arc::clone(&permissions), audit, Some(cb.clone()))
                .with_connect_grant(Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT);

        let app = Keys::generate().public_key();
        handler.handle_connect(app, None, None, None).await.unwrap();
        let signer_pk = handler.our_pubkey().await.unwrap();

        let tags = vec![
            Tag::parse(["u", "https://a.example/api"]).unwrap(),
            Tag::parse(["method", "GET"]).unwrap(),
        ];
        let first = UnsignedEvent::new(
            signer_pk,
            Timestamp::now(),
            NIP98_HTTP_AUTH,
            tags.clone(),
            "",
        );
        handler.handle_sign_event(app, first).await.unwrap();

        // Second request uses a DIFFERENT url/method: the grant is scoped to
        // (app, kind) only, so within the window it covers any url/method. This
        // documents the time-only scope boundary (#613) rather than implying
        // per-url scoping.
        let other_tags = vec![
            Tag::parse(["u", "https://b.example/other"]).unwrap(),
            Tag::parse(["method", "POST"]).unwrap(),
        ];
        let second =
            UnsignedEvent::new(signer_pk, Timestamp::now(), NIP98_HTTP_AUTH, other_tags, "");
        handler.handle_sign_event(app, second).await.unwrap();

        assert_eq!(
            cb.sign_event_prompts
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an opt-in OneMinute remember skips the prompt on the next NIP-98 request, \
             even for a different url/method within the clamped window"
        );
        let pm = permissions.lock().await;
        let granted = pm.get_app(&app).unwrap();
        assert!(granted.has_unexpired_timed_grant(NIP98_HTTP_AUTH));
        assert!(!granted.auto_approve_kinds.contains(&NIP98_HTTP_AUTH));
    }

    #[test]
    fn clamp_nip98_remember_never_exceeds_max() {
        use RememberDuration::*;
        // Lock the over-limit fallback to the constant: the clamp returns
        // `TenMinutes` for anything past the cap, which is only safe while
        // `TenMinutes` equals `NIP98_MAX_REMEMBER_SECS`. Catches drift if either
        // the constant or the variant's seconds change independently.
        assert_eq!(TenMinutes.as_seconds(), Some(NIP98_MAX_REMEMBER_SECS));
        assert_eq!(clamp_nip98_remember(JustThisTime), JustThisTime);
        assert_eq!(clamp_nip98_remember(OneMinute), OneMinute);
        assert_eq!(clamp_nip98_remember(FiveMinutes), FiveMinutes);
        assert_eq!(clamp_nip98_remember(TenMinutes), TenMinutes);
        assert_eq!(clamp_nip98_remember(OneHour), TenMinutes);
        assert_eq!(clamp_nip98_remember(OneDay), TenMinutes);
        assert_eq!(clamp_nip98_remember(Forever), TenMinutes);
        for variant in [
            JustThisTime,
            OneMinute,
            FiveMinutes,
            TenMinutes,
            OneHour,
            OneDay,
            Forever,
        ] {
            if let Some(secs) = clamp_nip98_remember(variant).as_seconds() {
                assert!(
                    secs <= NIP98_MAX_REMEMBER_SECS,
                    "{variant:?} clamped above the NIP-98 max"
                );
            }
        }
    }

    /// Captures every `persist_permissions` snapshot so a test can assert the
    /// durable store mirrors the engine after a remember-grant and after a revoke.
    struct PersistCapturingCallbacks {
        snapshots: std::sync::Mutex<Vec<Vec<keep_core::relay::StoredBunkerPermission>>>,
    }
    impl crate::types::ServerCallbacks for PersistCapturingCallbacks {
        fn on_log(&self, _event: crate::types::LogEvent) {}
        fn request_approval(&self, _request: ApprovalRequest) -> ApprovalResult {
            ApprovalResult {
                approved: true,
                remember: RememberDuration::Forever,
            }
        }
        fn on_connect(&self, _pubkey: &str, _name: &str) {}
        fn persist_permissions(&self, grants: Vec<keep_core::relay::StoredBunkerPermission>) {
            self.snapshots.lock().unwrap().push(grants);
        }
    }

    #[tokio::test]
    async fn remember_grant_and_revoke_persist_engine_snapshot() {
        let keyring = setup_keyring();
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(100)));
        let cb = Arc::new(PersistCapturingCallbacks {
            snapshots: std::sync::Mutex::new(Vec::new()),
        });
        let handler = SignerHandler::new(keyring, permissions, audit, Some(cb.clone()))
            .with_connect_grant(Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT);

        let app = Keys::generate().public_key();
        handler.handle_connect(app, None, None, None).await.unwrap();
        let signer_pk = handler.our_pubkey().await.unwrap();

        // A remembered (Forever) sign grant must fire persist with the granted
        // kind captured in the durable snapshot.
        let unsigned = UnsignedEvent::new(signer_pk, Timestamp::now(), Kind::TextNote, vec![], "x");
        handler.handle_sign_event(app, unsigned).await.unwrap();

        let app_hex = app.to_hex();
        let after_grant = cb
            .snapshots
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a remember-grant must persist a snapshot");
        let row = after_grant
            .iter()
            .find(|p| p.pubkey_hex == app_hex)
            .expect("granted app must be in the persisted snapshot");
        assert!(
            row.auto_approve_kinds.contains(&Kind::TextNote.as_u16()),
            "remembered kind must be captured in the persisted snapshot"
        );

        // Revoking the client must fire persist with the app absent.
        handler.revoke_client(&app).await;
        let after_revoke = cb
            .snapshots
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("revoke must persist a snapshot");
        assert!(
            !after_revoke.iter().any(|p| p.pubkey_hex == app_hex),
            "revoked app must be removed from the persisted snapshot"
        );
    }
}
