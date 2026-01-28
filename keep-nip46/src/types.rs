// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

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
}

pub trait ServerCallbacks: Send + Sync + 'static {
    fn on_log(&self, event: LogEvent);
    fn request_approval(&self, request: ApprovalRequest) -> bool;
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct Nip46Request {
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub params: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct Nip46Response {
    pub id: String,
    pub result: Option<String>,
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
