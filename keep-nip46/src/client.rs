// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::time::Duration;

use nostr_sdk::prelude::*;
use tracing::{debug, warn};
use zeroize::{Zeroize, Zeroizing};

use keep_core::error::{CryptoError, KeepError, NetworkError, StorageError};
use keep_core::relay::{
    normalize_relay_url, validate_relay_url, validate_relay_url_allow_internal,
    ALLOW_INTERNAL_HOSTS, TIMESTAMP_TWEAK_RANGE,
};

use crate::bunker::parse_bunker_url;
use crate::error::Result;
use crate::types::Nip46Response;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const REGISTER_WALLET_TIMEOUT: Duration = Duration::from_secs(180);
/// Default timeout for the best-effort `get_device_info` probe. Kept short so a
/// silent or hostile signer cannot stall registration UX. Callers that need to
/// override (e.g. a known-slow device) can wrap with their own `tokio::time::timeout`.
pub const GET_DEVICE_INFO_TIMEOUT: Duration = Duration::from_secs(8);
const SIGN_TAP_SCRIPT_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_RESPONSE_SIZE: usize = 64 * 1024;
const MAX_HMAC_HEX_LEN: usize = 128;
const HMAC_SHA256_LEN: usize = 32;
const SCHNORR_SIG_LEN: usize = 64;
pub const MAX_WALLET_NAME_LEN: usize = 64;
pub const MAX_DESCRIPTOR_LEN: usize = 4096;
/// Size cap on the JSON result string returned by `get_device_info`.
pub const MAX_DEVICE_INFO_JSON_LEN: usize = 2048;
/// Size caps on individual fields of `DeviceInfo`.
pub const MAX_DEVICE_KIND_LEN: usize = 32;
pub const MAX_FIRMWARE_VERSION_LEN: usize = 64;
pub const MAX_CAPABILITIES: usize = 32;
pub const MAX_CAPABILITY_LEN: usize = 32;
pub const MAX_TAP_SCRIPT_LEN: usize = 10_000;

/// Reject signer-supplied strings that contain control characters. Strings are
/// surfaced verbatim in CLI/UI output, so any C0/C1 control codes would corrupt
/// the terminal or hide content. Accept all other printable Unicode.
pub fn contains_control_chars(s: &str) -> bool {
    s.chars().any(|c| c.is_control())
}

/// Validate a free-form metadata string from a signer or operator: enforce
/// `min_len..=max_len` byte length and reject control characters. `field` is
/// used only for error messages.
pub fn validate_metadata_field(
    field: &str,
    value: &str,
    min_len: usize,
    max_len: usize,
) -> Result<()> {
    if value.len() < min_len || value.len() > max_len {
        return Err(KeepError::InvalidInput(format!(
            "{field} must be {min_len}..={max_len} bytes"
        )));
    }
    if contains_control_chars(value) {
        return Err(KeepError::InvalidInput(format!(
            "{field} contains control characters"
        )));
    }
    Ok(())
}

/// Outcome of a successful `register_wallet` request.
///
/// `hmac` is an opaque device-returned token. It is **not** cryptographically
/// verified by this client; callers must not treat it as an authenticator
/// unless a verification protocol is added on top.
#[derive(Clone)]
pub struct RegisterWalletResponse {
    pub hmac: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for RegisterWalletResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterWalletResponse")
            .field(
                "hmac",
                &self
                    .hmac
                    .as_ref()
                    .map(|h| format!("<redacted; {} bytes>", h.len())),
            )
            .finish()
    }
}

/// Device kind reported by a remote signer in response to `get_device_info`.
///
/// Free-form `Other(String)` arm preserves forward compatibility with signers
/// that report a model name not yet known to this client. Stricter callers can
/// match on the named variants and fall back to the user-supplied value for
/// `Other`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeviceKind {
    Coldcard,
    Ledger,
    BitBox02,
    Jade,
    Trezor,
    Other(String),
}

impl DeviceKind {
    /// Display name for the device, suitable for persisting in
    /// `DeviceRegistration::device_kind`.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Coldcard => "Coldcard",
            Self::Ledger => "Ledger",
            Self::BitBox02 => "BitBox02",
            Self::Jade => "Jade",
            Self::Trezor => "Trezor",
            Self::Other(s) => s.as_str(),
        }
    }

    /// Promote `Other("Coldcard")` etc. to the matching named variant so two
    /// registrations of the same device do not appear distinct. Matching is
    /// case-insensitive ("COLDCARD", "ColdCard", "coldcard" all normalize to
    /// `Coldcard`).
    fn normalize(self) -> Self {
        match self {
            Self::Other(s) => match s.to_ascii_lowercase().as_str() {
                "coldcard" => Self::Coldcard,
                "ledger" => Self::Ledger,
                "bitbox02" => Self::BitBox02,
                "jade" => Self::Jade,
                "trezor" => Self::Trezor,
                _ => Self::Other(s),
            },
            other => other,
        }
    }
}

/// Typed `get_device_info` response.
///
/// `fingerprint` is the BIP32 master key fingerprint as a hex string (8 chars).
/// It is validated when received: must decode to exactly 4 bytes, and the
/// all-zero sentinel (`00000000`, which BIP32 reserves for "no parent") is
/// rejected. Stored normalized to lower-case so later string comparisons /
/// serialization are stable.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInfo {
    pub kind: DeviceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<String>,
    /// 8 hex chars; BIP32 master key fingerprint.
    pub fingerprint: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

impl DeviceInfo {
    /// Decode the hex fingerprint into 4 bytes, if well-formed.
    pub fn fingerprint_bytes(&self) -> Option<[u8; 4]> {
        let s = self.fingerprint.trim();
        if s.len() != 8 {
            return None;
        }
        hex::decode(s).ok()?.try_into().ok()
    }
}

/// Client that sends NIP-46 requests to a remote signer (e.g. a hardware wallet).
pub struct Nip46Client {
    signer_pubkey: PublicKey,
    relays: Vec<String>,
    secret: Option<Zeroizing<String>>,
    client_keys: Keys,
    client: Client,
}

impl Nip46Client {
    pub async fn connect_to(uri: &str) -> Result<Self> {
        let (signer_pubkey, relays, secret) = parse_bunker_url(uri)
            .map_err(|e| KeepError::InvalidInput(format!("invalid NIP-46 URI: {e}")))?;
        Self::connect_with(signer_pubkey, relays, secret).await
    }

    pub async fn connect_with(
        signer_pubkey: PublicKey,
        relays: Vec<String>,
        secret: Option<String>,
    ) -> Result<Self> {
        if relays.is_empty() {
            return Err(NetworkError::relay("at least one relay required").into());
        }

        let validate = if ALLOW_INTERNAL_HOSTS {
            validate_relay_url_allow_internal
        } else {
            validate_relay_url
        };
        let mut normalized = Vec::with_capacity(relays.len());
        for relay in &relays {
            validate(relay).map_err(|e| {
                KeepError::InvalidInput(format!("invalid relay URL '{relay}': {e}"))
            })?;
            normalized.push(normalize_relay_url(relay));
        }
        let relays = normalized;

        let client_keys = Keys::generate();
        let client = Client::new(client_keys.clone());

        let setup = async {
            for relay in &relays {
                client
                    .add_relay(relay.as_str())
                    .await
                    .map_err(|e| NetworkError::relay(format!("add relay: {e}")))?;
            }
            client.connect().await;

            let filter = Filter::new()
                .kind(Kind::NostrConnect)
                .pubkey(client_keys.public_key());
            client
                .subscribe(filter, None)
                .await
                .map_err(|e| NetworkError::subscribe(e.to_string()))?;
            Ok::<_, KeepError>(())
        };

        match tokio::time::timeout(DEFAULT_REQUEST_TIMEOUT, setup).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                client.disconnect().await;
                return Err(NetworkError::timeout(
                    "timed out connecting to NIP-46 relay".to_string(),
                )
                .into());
            }
        }

        Ok(Self {
            signer_pubkey,
            relays,
            secret: secret.map(Zeroizing::new),
            client_keys,
            client,
        })
    }

    pub fn signer_pubkey(&self) -> PublicKey {
        self.signer_pubkey
    }

    pub fn relays(&self) -> &[String] {
        &self.relays
    }

    pub async fn disconnect(self) {
        self.client.disconnect().await;
    }

    pub async fn connect(&self) -> Result<()> {
        let mut params: Vec<Zeroizing<String>> = vec![Zeroizing::new(self.signer_pubkey.to_hex())];
        if let Some(ref s) = self.secret {
            params.push(Zeroizing::new(s.as_str().to_string()));
        }
        let id = new_request_id();
        let response = self.request(&id, "connect", params).await?;
        match (response.result.as_deref(), response.error.as_deref()) {
            (Some(_), None) => Ok(()),
            (_, Some(err)) => {
                Err(NetworkError::response(format!("connect rejected: {err}")).into())
            }
            _ => Err(NetworkError::response("connect returned no result").into()),
        }
    }

    /// Register a wallet descriptor on the remote signer.
    ///
    /// The `descriptor` must already encode both the external (receive) and
    /// internal (change) paths, typically as a BIP-389 multipath descriptor
    /// (e.g. `tr(...<0;1>/*)`). Sending only a single-path descriptor prevents
    /// the device from deriving change addresses.
    pub async fn register_wallet(
        &self,
        name: &str,
        descriptor: &str,
    ) -> Result<RegisterWalletResponse> {
        if name.is_empty() {
            return Err(KeepError::InvalidInput(
                "wallet name must not be empty".into(),
            ));
        }
        if name.len() > MAX_WALLET_NAME_LEN {
            return Err(KeepError::InvalidInput(format!(
                "wallet name exceeds {MAX_WALLET_NAME_LEN} bytes"
            )));
        }
        if descriptor.is_empty() {
            return Err(KeepError::InvalidInput(
                "descriptor must not be empty".into(),
            ));
        }
        if descriptor.len() > MAX_DESCRIPTOR_LEN {
            return Err(KeepError::InvalidInput(format!(
                "descriptor exceeds {MAX_DESCRIPTOR_LEN} bytes"
            )));
        }
        let body = descriptor.split('#').next().unwrap_or(descriptor);
        let has_multipath = keep_core::descriptor::has_multipath_marker(body);
        let has_single_path = keep_core::descriptor::has_single_path_tail(body);
        if has_single_path {
            let msg = if has_multipath {
                "descriptor mixes multipath and single-path keys; normalize all keys to <0;1>"
            } else {
                "descriptor must be multipath (e.g. <0;1>) so the device can derive change"
            };
            return Err(KeepError::InvalidInput(msg.into()));
        }
        if body.contains("<1;0>") {
            return Err(KeepError::InvalidInput(
                "descriptor must use <0;1> multipath order; reorder before sending".into(),
            ));
        }
        if !has_multipath && body.contains('*') {
            return Err(KeepError::InvalidInput(
                "descriptor must be multipath (e.g. <0;1>) so the device can derive change".into(),
            ));
        }

        let id = new_request_id();
        let mut response = self
            .request_with_timeout(
                &id,
                "register_wallet",
                vec![
                    Zeroizing::new(name.to_string()),
                    Zeroizing::new(descriptor.to_string()),
                ],
                REGISTER_WALLET_TIMEOUT,
            )
            .await?;

        if let Some(err) = response.error {
            return Err(NetworkError::response(format!("register_wallet rejected: {err}")).into());
        }

        let hmac = match response.result.as_mut() {
            None => None,
            Some(hex_str) if hex_str.trim().is_empty() => {
                hex_str.zeroize();
                None
            }
            Some(hex_str) => {
                let trimmed_len = hex_str.trim().len();
                if trimmed_len > MAX_HMAC_HEX_LEN {
                    hex_str.zeroize();
                    return Err(KeepError::InvalidInput(format!(
                        "register_wallet hmac too long: {trimmed_len} hex chars (max {MAX_HMAC_HEX_LEN})"
                    )));
                }
                let decode_result = hex::decode(hex_str.trim());
                hex_str.zeroize();
                // Malformed hex (odd length, non-hex chars) is an untrusted-input
                // validation failure, same class as the too-long / wrong-length
                // checks around it; surface it as InvalidInput so callers can
                // handle all three consistently, not as a StorageErr.
                let decoded = decode_result.map_err(|e| {
                    KeepError::InvalidInput(format!("register_wallet hmac hex: {e}"))
                })?;
                if decoded.len() != HMAC_SHA256_LEN {
                    return Err(KeepError::InvalidInput(format!(
                        "register_wallet hmac must be {HMAC_SHA256_LEN} bytes, got {}",
                        decoded.len()
                    )));
                }
                Some(Zeroizing::new(decoded))
            }
        };
        Ok(RegisterWalletResponse { hmac })
    }

    /// Request `DeviceInfo` from the remote signer.
    ///
    /// This is best-effort: callers should treat any error as "info unavailable"
    /// and fall back to user-supplied values rather than aborting wallet
    /// registration.
    pub async fn get_device_info(&self) -> Result<DeviceInfo> {
        let id = new_request_id();
        let response = self
            .request_with_timeout(&id, "get_device_info", Vec::new(), GET_DEVICE_INFO_TIMEOUT)
            .await?;

        if let Some(err) = response.error {
            return Err(NetworkError::response(format!("get_device_info rejected: {err}")).into());
        }

        let result = response
            .result
            .ok_or_else(|| NetworkError::response("get_device_info returned no result"))?;
        if result.len() > MAX_DEVICE_INFO_JSON_LEN {
            return Err(KeepError::InvalidInput(format!(
                "get_device_info payload exceeds {MAX_DEVICE_INFO_JSON_LEN} bytes"
            )));
        }
        let mut info: DeviceInfo = serde_json::from_str(&result)
            .map_err(|e| StorageError::invalid_format(format!("get_device_info payload: {e}")))?;
        info.kind = info.kind.normalize();

        if let DeviceKind::Other(ref s) = info.kind {
            validate_metadata_field("device kind 'Other' label", s, 1, MAX_DEVICE_KIND_LEN)?;
        }
        if let Some(ref fw) = info.firmware_version {
            validate_metadata_field("firmware_version", fw, 0, MAX_FIRMWARE_VERSION_LEN)?;
        }
        let fp_bytes = info.fingerprint_bytes().ok_or_else(|| {
            KeepError::InvalidInput("fingerprint must be 8 hex characters (4 bytes)".into())
        })?;
        if fp_bytes == [0u8; 4] {
            return Err(KeepError::InvalidInput(
                "fingerprint 00000000 is reserved by BIP32 for 'no parent' and cannot identify a device".into(),
            ));
        }
        info.fingerprint = hex::encode(fp_bytes);
        if info.capabilities.len() > MAX_CAPABILITIES {
            return Err(KeepError::InvalidInput(format!(
                "capabilities list exceeds {MAX_CAPABILITIES} entries"
            )));
        }
        for cap in &info.capabilities {
            validate_metadata_field("capability label", cap, 1, MAX_CAPABILITY_LEN)?;
        }
        Ok(info)
    }

    /// Request a taproot script-spend signature from the remote signer for a
    /// recovery-tier PSBT input. The signer is expected to:
    ///   1. Look up the descriptor it has previously registered (the descriptor
    ///      string is passed for display/confirmation; it MUST match a record).
    ///   2. Locate the secret key matching `xonly_pubkey` (e.g. by deriving
    ///      every script-path key in its registered policy).
    ///   3. Display the script and leaf hash for user confirmation.
    ///   4. Schnorr-sign `sighash` under that key.
    ///
    /// All five params are hex-encoded except `descriptor`.
    ///
    /// # Trust assumption
    ///
    /// This call relays a 32-byte sighash to the remote bunker and trusts the
    /// returned 64-byte Schnorr signature is a sig over THAT sighash by the
    /// secret matching `xonly_pubkey`. The bunker is responsible for any
    /// user-facing confirmation; this method does NOT itself prompt or
    /// rate-limit. Callers MUST verify the returned signature against the
    /// sighash and xonly_pubkey before merging it into a PSBT (see
    /// `keep_bitcoin::merge_tap_script_sig`, which does this verification),
    /// and MUST verify the PSBT input being signed is bound to a UTXO they
    /// control (see `keep_bitcoin::verify_script_spend_input_binding`).
    /// Without those two checks, this method is a signing oracle and any
    /// caller that wraps it is too.
    pub async fn sign_tap_script(
        &self,
        sighash: &[u8; 32],
        xonly_pubkey: &[u8; 32],
        leaf_hash: &[u8; 32],
        script_bytes: &[u8],
        descriptor: &str,
    ) -> Result<[u8; SCHNORR_SIG_LEN]> {
        if script_bytes.len() > MAX_TAP_SCRIPT_LEN {
            return Err(KeepError::InvalidInput(format!(
                "tap script exceeds {MAX_TAP_SCRIPT_LEN} bytes"
            )));
        }
        if descriptor.is_empty() {
            return Err(KeepError::InvalidInput(
                "descriptor must not be empty".into(),
            ));
        }
        if descriptor.len() > MAX_DESCRIPTOR_LEN {
            return Err(KeepError::InvalidInput(format!(
                "descriptor exceeds {MAX_DESCRIPTOR_LEN} bytes"
            )));
        }

        let id = new_request_id();
        let mut response = self
            .request_with_timeout(
                &id,
                "sign_tap_script",
                vec![
                    Zeroizing::new(hex::encode(sighash)),
                    Zeroizing::new(hex::encode(xonly_pubkey)),
                    Zeroizing::new(hex::encode(leaf_hash)),
                    Zeroizing::new(hex::encode(script_bytes)),
                    Zeroizing::new(descriptor.to_string()),
                ],
                SIGN_TAP_SCRIPT_TIMEOUT,
            )
            .await?;

        if let Some(err) = response.error {
            return Err(NetworkError::response(format!("sign_tap_script rejected: {err}")).into());
        }

        let hex_str = response.result.as_mut().ok_or_else(|| {
            NetworkError::response("sign_tap_script returned no result".to_string())
        })?;
        let trimmed_len = hex_str.trim().len();
        if trimmed_len != SCHNORR_SIG_LEN * 2 {
            hex_str.zeroize();
            return Err(KeepError::InvalidInput(format!(
                "sign_tap_script signature must be {} hex chars, got {}",
                SCHNORR_SIG_LEN * 2,
                trimmed_len
            )));
        }
        let decode_result = hex::decode(hex_str.trim());
        hex_str.zeroize();
        let decoded = decode_result.map_err(|e| {
            StorageError::invalid_format(format!("sign_tap_script signature hex: {e}"))
        })?;
        let sig: [u8; SCHNORR_SIG_LEN] = decoded.as_slice().try_into().map_err(|_| {
            KeepError::InvalidInput("sign_tap_script signature wrong length".into())
        })?;
        Ok(sig)
    }

    async fn request(
        &self,
        id: &str,
        method: &str,
        params: Vec<Zeroizing<String>>,
    ) -> Result<Nip46Response> {
        self.request_with_timeout(id, method, params, DEFAULT_REQUEST_TIMEOUT)
            .await
    }

    async fn request_with_timeout(
        &self,
        id: &str,
        method: &str,
        params: Vec<Zeroizing<String>>,
        timeout: Duration,
    ) -> Result<Nip46Response> {
        let mut notifications = self.client.notifications();

        // Build the JSON payload directly into a Zeroizing<String> so secret
        // params (e.g. bunker connect secret) never land in an intermediate
        // serde_json::Value::String or non-zeroizing String buffer. Only the
        // per-param JSON-escaping allocation happens on the heap, and we drop
        // that allocation back into a Zeroizing wrapper immediately.
        let mut payload = Zeroizing::new(String::with_capacity(128));
        payload.push_str("{\"id\":");
        append_json_string(&mut payload, id)?;
        payload.push_str(",\"method\":");
        append_json_string(&mut payload, method)?;
        payload.push_str(",\"params\":[");
        for (i, p) in params.iter().enumerate() {
            if i > 0 {
                payload.push(',');
            }
            append_json_string(&mut payload, p.as_str())?;
        }
        payload.push_str("]}");
        // Drop the original params eagerly; each element is Zeroizing<String>
        // and will zero its backing allocation here.
        drop(params);

        let encrypted = nip44::encrypt(
            self.client_keys.secret_key(),
            &self.signer_pubkey,
            payload.as_str(),
            nip44::Version::V2,
        )
        .map_err(|e| CryptoError::encryption(e.to_string()))?;

        let event = EventBuilder::new(Kind::NostrConnect, encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(self.signer_pubkey))
            .sign_with_keys(&self.client_keys)
            .map_err(|e| CryptoError::invalid_signature(format!("sign request: {e}")))?;

        self.client
            .send_event(&event)
            .await
            .map_err(|e| NetworkError::publish(format!("send request: {e}")))?;

        debug!(method, id, "NIP-46 client request sent");

        self.wait_for_response(id, &mut notifications, timeout)
            .await
    }

    async fn wait_for_response(
        &self,
        id: &str,
        notifications: &mut tokio::sync::broadcast::Receiver<RelayPoolNotification>,
        timeout: Duration,
    ) -> Result<Nip46Response> {
        let deadline = tokio::time::Instant::now() + timeout;
        let timeout_err = || NetworkError::timeout(format!("no response for request {id}"));

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(timeout_err().into());
            }

            let notif = match tokio::time::timeout(remaining, notifications.recv()).await {
                Ok(Ok(n)) => n,
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                    warn!(dropped = n, "NIP-46 notification stream lagged");
                    continue;
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                    return Err(NetworkError::response("notification stream closed").into());
                }
                Err(_) => return Err(timeout_err().into()),
            };

            let RelayPoolNotification::Event { event, .. } = notif else {
                continue;
            };
            if event.kind != Kind::NostrConnect {
                continue;
            }
            if event.pubkey != self.signer_pubkey {
                continue;
            }

            if event.content.len() > MAX_RESPONSE_SIZE {
                warn!("NIP-46 response too large, ignoring");
                continue;
            }

            let plaintext = match nip44::decrypt(
                self.client_keys.secret_key(),
                &event.pubkey,
                &event.content,
            ) {
                Ok(p) => p,
                Err(e) => {
                    debug!(error = %e, "failed to decrypt NIP-46 response");
                    continue;
                }
            };

            let response: Nip46Response = match serde_json::from_str(&plaintext) {
                Ok(r) => r,
                Err(e) => {
                    debug!(error = %e, "failed to parse NIP-46 response");
                    continue;
                }
            };

            if response.id != id {
                continue;
            }
            return Ok(response);
        }
    }
}

fn new_request_id() -> String {
    hex::encode(keep_core::crypto::random_bytes::<16>())
}

/// JSON-escape `value` and append the quoted result to `buf`. The intermediate
/// escape allocation is wrapped in `Zeroizing` and dropped at function return,
/// so a secret passed here never lives in a non-zeroized `String`.
fn append_json_string(buf: &mut Zeroizing<String>, value: &str) -> Result<()> {
    let escaped = Zeroizing::new(
        serde_json::to_string(value).map_err(|e| StorageError::serialization(e.to_string()))?,
    );
    buf.push_str(escaped.as_str());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_info_roundtrip_named_kind() {
        let json = r#"{"kind":"Coldcard","firmware_version":"1.2.3","fingerprint":"deadbeef","capabilities":["miniscript","tapminiscript"]}"#;
        let info: DeviceInfo = serde_json::from_str(json).expect("parse named kind");
        assert_eq!(info.kind, DeviceKind::Coldcard);
        assert_eq!(info.fingerprint_bytes(), Some([0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(info.kind.as_str(), "Coldcard");
    }

    #[test]
    fn test_device_info_roundtrip_other_kind() {
        let json = r#"{"kind":{"Other":"Foundation"},"fingerprint":"00112233","capabilities":[]}"#;
        let info: DeviceInfo = serde_json::from_str(json).expect("parse other kind");
        assert_eq!(info.kind, DeviceKind::Other("Foundation".into()));
        assert_eq!(info.kind.as_str(), "Foundation");
        assert!(info.firmware_version.is_none());
    }

    #[test]
    fn test_device_info_rejects_unknown_fields() {
        let json = r#"{"kind":"Ledger","fingerprint":"deadbeef","capabilities":[],"extra":"nope"}"#;
        let err = serde_json::from_str::<DeviceInfo>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn test_fingerprint_bytes_rejects_malformed() {
        let info = DeviceInfo {
            kind: DeviceKind::Trezor,
            firmware_version: None,
            fingerprint: "zz".into(),
            capabilities: Vec::new(),
        };
        assert!(info.fingerprint_bytes().is_none());
    }

    #[test]
    fn test_device_kind_normalize_promotes_other() {
        assert_eq!(
            DeviceKind::Other("Coldcard".into()).normalize(),
            DeviceKind::Coldcard
        );
        assert_eq!(
            DeviceKind::Other("Ledger".into()).normalize(),
            DeviceKind::Ledger
        );
        assert_eq!(
            DeviceKind::Other("Foundation".into()).normalize(),
            DeviceKind::Other("Foundation".into())
        );
    }

    #[test]
    fn test_device_kind_normalize_case_insensitive() {
        assert_eq!(
            DeviceKind::Other("COLDCARD".into()).normalize(),
            DeviceKind::Coldcard
        );
        assert_eq!(
            DeviceKind::Other("coldcard".into()).normalize(),
            DeviceKind::Coldcard
        );
        assert_eq!(
            DeviceKind::Other("ColdCard".into()).normalize(),
            DeviceKind::Coldcard
        );
        assert_eq!(
            DeviceKind::Other("trezor".into()).normalize(),
            DeviceKind::Trezor
        );
        assert_eq!(
            DeviceKind::Other("BITBOX02".into()).normalize(),
            DeviceKind::BitBox02
        );
    }

    #[test]
    fn test_contains_control_chars_rejects_c0() {
        assert!(contains_control_chars("hello\nworld"));
        assert!(contains_control_chars("ansi\x1b[31mred"));
        assert!(!contains_control_chars("ColdcardMk4"));
        assert!(!contains_control_chars("1.2.3-beta"));
    }

    #[test]
    fn test_new_request_id_is_unique() {
        let a = new_request_id();
        let b = new_request_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
    }
}
