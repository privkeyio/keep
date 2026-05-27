// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use nostr_sdk::prelude::*;

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

pub trait ServerCallbacks: Send + Sync + 'static {
    fn on_log(&self, event: LogEvent);
    fn request_approval(&self, request: ApprovalRequest) -> bool;
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
    // `{"error":".."}` — never both. Clients that test for the presence of the
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
