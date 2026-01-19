// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub success: bool,
    pub content: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ToolResult {
    pub fn success(content: Value) -> Self {
        Self {
            success: true,
            content,
            error: None,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            content: Value::Null,
            error: Some(message.into()),
        }
    }
}

pub fn sign_nostr_event_tool() -> ToolDefinition {
    ToolDefinition {
        name: "sign_nostr_event".to_string(),
        description: "Sign a Nostr event. Constrained by session permissions.".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "kind": {
                    "type": "integer",
                    "description": "Event kind (1=text, 4=DM, 7=reaction)"
                },
                "content": {
                    "type": "string",
                    "description": "Event content"
                },
                "tags": {
                    "type": "array",
                    "items": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "description": "Event tags"
                }
            },
            "required": ["kind", "content"]
        }),
    }
}

pub fn sign_psbt_tool() -> ToolDefinition {
    ToolDefinition {
        name: "sign_bitcoin_psbt".to_string(),
        description: "Sign a Bitcoin PSBT. Amount and destination constrained by session."
            .to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "psbt": {
                    "type": "string",
                    "description": "Base64-encoded PSBT"
                }
            },
            "required": ["psbt"]
        }),
    }
}

pub fn get_pubkey_tool() -> ToolDefinition {
    ToolDefinition {
        name: "get_nostr_pubkey".to_string(),
        description: "Get the Nostr public key (npub) for this session".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {}
        }),
    }
}

pub fn get_bitcoin_address_tool() -> ToolDefinition {
    ToolDefinition {
        name: "get_bitcoin_address".to_string(),
        description: "Get a Bitcoin address for receiving payments".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["p2tr", "p2wpkh"],
                    "description": "Address type"
                }
            }
        }),
    }
}

pub fn get_session_info_tool() -> ToolDefinition {
    ToolDefinition {
        name: "get_session_info".to_string(),
        description: "Get information about current session permissions and limits".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {}
        }),
    }
}

pub fn all_tools() -> Vec<ToolDefinition> {
    vec![
        sign_nostr_event_tool(),
        sign_psbt_tool(),
        get_pubkey_tool(),
        get_bitcoin_address_tool(),
        get_session_info_tool(),
    ]
}
