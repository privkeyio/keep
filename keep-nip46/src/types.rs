// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use nostr_sdk::prelude::*;
use std::collections::HashSet;

/// NIP-98 HTTP Auth event kind (27235). Web clients such as nostr-tools'
/// `BunkerSigner` sign a fresh auth event for every API call, so the bunkers
/// auto-approve this kind to avoid a per-request prompt that would time out.
pub const NIP98_HTTP_AUTH: Kind = Kind::Custom(27235);

/// #613: maximum lifetime (seconds) for an opt-in NIP-98 (kind 27235) timed
/// remember-grant. NIP-98 carries a per-request `u`/`method` that the approval
/// prompt does not surface, so a remembered grant is a short-lived bearer
/// credential: clamp it hard. Single source of truth for both the approval-path
/// clamp and the authoritative `grant_kind_for` write-path cap.
pub const NIP98_MAX_REMEMBER_SECS: u64 = 600;

#[derive(Debug, Clone)]
pub struct LogEvent {
    pub app: String,
    pub action: String,
    pub success: bool,
    pub detail: Option<String>,
}

/// The security-relevant target of a NIP-98 (kind 27235) HTTP-auth event: the
/// `u` (URL) and `method` the signature will authenticate. NIP-98 content is
/// empty, so without these the approval prompt cannot show what is being
/// authorized and the user approves a blind bearer credential. Populated on
/// `ApprovalRequest` only for kind-27235 sign requests; `None` otherwise. A
/// field is `None` when the event omits that tag (a malformed request the UI
/// should surface as "unspecified", not hide).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpAuthDetails {
    pub url: Option<String>,
    pub method: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub app_pubkey: PublicKey,
    pub app_name: String,
    pub method: String,
    pub event_kind: Option<Kind>,
    pub event_content: Option<String>,
    pub requested_permissions: Option<String>,
    /// For NIP-98 (kind 27235) sign requests, the `u`/method the prompt must
    /// show so the user is not approving a blind HTTP-auth token. `None` for
    /// every other request.
    pub http_auth: Option<HttpAuthDetails>,
}

/// How long an approval extends beyond the current request, captured from the
/// per-request prompt UI. Mirrors keep-android's
/// `nip55/PermissionEntities.kt::PermissionDuration` and Amber's
/// `SettingsScreen.kt::RememberType` 1:1 so the same UX maps cleanly across
/// signers. `JustThisTime` is the one-shot default: the request is approved
/// but no grant is persisted, so the next request prompts again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RememberDuration {
    JustThisTime,
    OneMinute,
    FiveMinutes,
    TenMinutes,
    OneHour,
    OneDay,
    Forever,
}

impl RememberDuration {
    /// Duration in seconds for timed variants, `None` for `JustThisTime` and
    /// `Forever` (which have no expiry semantics).
    pub fn as_seconds(&self) -> Option<u64> {
        match self {
            Self::JustThisTime | Self::Forever => None,
            Self::OneMinute => Some(60),
            Self::FiveMinutes => Some(5 * 60),
            Self::TenMinutes => Some(10 * 60),
            Self::OneHour => Some(60 * 60),
            Self::OneDay => Some(24 * 60 * 60),
        }
    }
}

/// Result of a per-request approval prompt.
///
/// `remember` applies to whichever answer was given, not only to approval. With
/// `approved == true` and a non-`JustThisTime` duration, a per-app, per-kind
/// grant is persisted and subsequent requests within the window skip the
/// prompt. With `approved == false` and a duration, the refusal is remembered
/// the same way and subsequent requests are refused without prompting.
///
/// Callers must therefore send `JustThisTime` on rejection unless the user
/// deliberately chose a duration for *that* answer. Forwarding a value left
/// over from an earlier interaction would create a block the user never asked
/// for, which is the failure this field's symmetry makes possible. Rejecting
/// with `JustThisTime` records nothing, which is the safe default and what
/// `rejected()` and the `From<bool>` conversion both produce.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalResult {
    pub approved: bool,
    pub remember: RememberDuration,
}

impl ApprovalResult {
    pub fn approved_once() -> Self {
        Self {
            approved: true,
            remember: RememberDuration::JustThisTime,
        }
    }

    pub fn rejected() -> Self {
        Self {
            approved: false,
            remember: RememberDuration::JustThisTime,
        }
    }
}

impl From<bool> for ApprovalResult {
    fn from(b: bool) -> Self {
        if b {
            Self::approved_once()
        } else {
            Self::rejected()
        }
    }
}

/// Why a NIP-46 connect was authorized. Carried on `on_connect` so the consumer
/// authorizes the client off an explicit assertion from the server, rather than
/// inferring consent from the callback merely having fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectAuthorization {
    /// The connect secret carried in the bunker URL matched the expected secret.
    SecretMatched,
    /// The user explicitly approved the connect via the approval prompt.
    UserApproved,
    /// The server was configured to auto-approve connects (no secret, no prompt).
    /// Consumers that require explicit consent should NOT persist authorization
    /// for this case.
    AutoApproved,
}

/// `commit_authorized_client` returns this when the consumer refused to record
/// the client (pending revoke, or not the client that server is serving). The
/// connect fails and that client's in-memory grant is removed.
pub const CLIENT_NOT_RECORDED: &str = "the client was not recorded";

/// The clients the consumer lists as connected, which decides who a connect
/// may admit once the app table is near its cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientListing {
    /// No list is kept: a connect is bounded only by the app table.
    Unrestricted,
    /// A listed client is always admitted. A client that is not listed is
    /// admitted while the listed clients and the apps already connected leave
    /// a slot free, and also when the list itself is already full. The
    /// consumer then records the newcomer and drops the oldest listed client,
    /// and that client's grant, so the list returns to its cap.
    ///
    /// Returning this obliges the same impl to override
    /// [`ServerCallbacks::commit_authorized_client`]. The default commit
    /// records nothing. The engine will not drop a client this listing names
    /// to make room, so a table whose other apps are all listed stays one past
    /// its cap, and the next newcomer is refused.
    Listed(HashSet<PublicKey>),
    /// The list could not be read, so no connect is admitted.
    Unavailable,
}

pub trait ServerCallbacks: Send + Sync + 'static {
    fn on_log(&self, event: LogEvent);
    fn request_approval(&self, request: ApprovalRequest) -> ApprovalResult;
    fn on_connect(&self, _pubkey: &str, _name: &str, _authorization: ConnectAuthorization) {}
    /// Read on every connect, after its secret or approval is checked and
    /// before anything is granted. Default: no list. An impl that returns
    /// [`ClientListing::Listed`] also overrides [`Self::commit_authorized_client`].
    fn client_listing(&self) -> ClientListing {
        ClientListing::Unrestricted
    }
    /// Called after the in-memory permission grants change (a remember-grant is
    /// written or a client is revoked), passing a full snapshot of the current
    /// grants so the consumer can persist them durably. Default no-op: keep-web
    /// and the CLI manage persistence out-of-band; the mobile bunker overrides
    /// this to write the snapshot to its relay-config storage so remembered
    /// grants survive a service restart.
    fn persist_permissions(&self, _grants: Vec<keep_core::relay::StoredBunkerPermission>) {}
    /// Records an explicit connect on the consumer's roster after the grant is
    /// installed and before the connect is acknowledged. `Err` fails the
    /// connect. A grant this connect just installed is removed. An app that was
    /// already connected keeps its grants, unless the error is
    /// [`CLIENT_NOT_RECORDED`]: the consumer refused to record the client, and
    /// its in-memory grant is removed too. Default: nothing to record, which
    /// is only correct with [`ClientListing::Unrestricted`]. A
    /// [`ClientListing::Listed`] roster overrides this and records the client,
    /// dropping the oldest when that roster is full.
    fn commit_authorized_client(
        &self,
        _pubkey: &str,
        _authorization: ConnectAuthorization,
    ) -> Result<(), String> {
        Ok(())
    }
    /// Whether `pubkey` may call anything other than the secret-checked
    /// connect. Default: no roster is enforced.
    fn client_authorized(&self, _pubkey: &PublicKey) -> bool {
        true
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Nip46Request {
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub params: Vec<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Nip46Response {
    pub id: String,
    // Omit when absent so a success is `{"result":"ack"}` and an error is
    // `{"error":".."}`, never both. Clients that test for the presence of the
    // `error` key (not just a non-null value) otherwise read a null `error` on
    // a successful response as a rejection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Nip46Response {
    pub fn ok(id: String, result: &str) -> Self {
        Self {
            id,
            result: Some(result.to_string()),
            error: None,
        }
    }

    pub fn error(id: String, error: &str) -> Self {
        Self {
            id,
            result: None,
            error: Some(error.to_string()),
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct PartialEvent {
    pub kind: u16,
    pub content: String,
    #[serde(default)]
    pub tags: Vec<Vec<String>>,
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remember_duration_as_seconds_mapping() {
        assert_eq!(RememberDuration::JustThisTime.as_seconds(), None);
        assert_eq!(RememberDuration::Forever.as_seconds(), None);
        assert_eq!(RememberDuration::OneMinute.as_seconds(), Some(60));
        assert_eq!(RememberDuration::FiveMinutes.as_seconds(), Some(5 * 60));
        assert_eq!(RememberDuration::TenMinutes.as_seconds(), Some(10 * 60));
        assert_eq!(RememberDuration::OneHour.as_seconds(), Some(60 * 60));
        assert_eq!(RememberDuration::OneDay.as_seconds(), Some(24 * 60 * 60));
    }
}
