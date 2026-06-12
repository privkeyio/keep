// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use nostr_sdk::prelude::*;

/// NIP-98 HTTP Auth event kind (27235). Web clients such as nostr-tools'
/// `BunkerSigner` sign a fresh auth event for every API call, so the bunkers
/// auto-approve this kind to avoid a per-request prompt that would time out.
pub const NIP98_HTTP_AUTH: Kind = Kind::Custom(27235);

#[derive(Debug, Clone)]
pub struct LogEvent {
    pub app: String,
    pub action: String,
    pub success: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub app_pubkey: PublicKey,
    pub app_name: String,
    pub method: String,
    pub event_kind: Option<Kind>,
    pub event_content: Option<String>,
    pub requested_permissions: Option<String>,
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

/// Result of a per-request approval prompt. `approved == false` always means
/// reject (with `remember = JustThisTime`). `approved == true` plus a non-
/// `JustThisTime` duration persists a per-app, per-kind grant so subsequent
/// requests within the window auto-approve without re-prompting.
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

pub trait ServerCallbacks: Send + Sync + 'static {
    fn on_log(&self, event: LogEvent);
    fn request_approval(&self, request: ApprovalRequest) -> ApprovalResult;
    fn on_connect(&self, _pubkey: &str, _name: &str) {}
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
