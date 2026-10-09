// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The MCP tools the gateway serves, each offered only to a credential whose
//! grant allows its operation.

use serde_json::{json, Value};

use crate::policy::Grant;
use crate::scope::Operation;

pub const GET_PUBKEY: &str = "get_nostr_pubkey";
pub const SIGN_EVENT: &str = "sign_nostr_event";
pub const GET_ADDRESS: &str = "get_bitcoin_address";
pub const SIGN_PSBT: &str = "sign_bitcoin_psbt";
pub const SESSION_INFO: &str = "get_session_info";

fn key_property() -> Value {
    json!({
        "type": "string",
        "description": "The granted key to use, as hex or npub. Optional when the grant names one key."
    })
}

fn tool(name: &str, description: &str, properties: Value, required: &[&str]) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false
        }
    })
}

/// The operation a tool needs, or `None` for one every credential may call.
pub fn operation(name: &str) -> Option<Operation> {
    match name {
        GET_PUBKEY => Some(Operation::GetPublicKey),
        SIGN_EVENT => Some(Operation::SignNostrEvent),
        GET_ADDRESS => Some(Operation::GetBitcoinAddress),
        SIGN_PSBT => Some(Operation::SignPsbt),
        _ => None,
    }
}

/// The tools `grant` allows, as `tools/list` returns them.
pub fn list(grant: &Grant) -> Vec<Value> {
    let all = [
        tool(
            GET_PUBKEY,
            "Get the public key (npub and hex) of a granted key.",
            json!({ "key": key_property() }),
            &[],
        ),
        tool(
            SIGN_EVENT,
            "Sign a Nostr event with a granted key. Only the event kinds the grant lists are signed.",
            json!({
                "key": key_property(),
                "kind": { "type": "integer", "minimum": 0, "maximum": 65535 },
                "content": { "type": "string" },
                "tags": {
                    "type": "array",
                    "items": { "type": "array", "items": { "type": "string" }, "minItems": 1 }
                }
            }),
            &["kind", "content"],
        ),
        tool(
            GET_ADDRESS,
            "Get the granted key's taproot receive address on the grant's network.",
            json!({
                "key": key_property(),
                "type": { "type": "string", "enum": ["p2tr"] },
                "network": { "type": "string", "description": "Must name the grant's network." }
            }),
            &[],
        ),
        tool(
            SIGN_PSBT,
            "Sign a Bitcoin PSBT with a granted key, within the grant's per-PSBT limit, budget and address allowlist.",
            json!({
                "key": key_property(),
                "psbt": { "type": "string", "description": "Base64-encoded PSBT" },
                "network": { "type": "string", "description": "Must name the grant's network." }
            }),
            &["psbt"],
        ),
        tool(
            SESSION_INFO,
            "Get this credential's grant, limits and expiry.",
            json!({}),
            &[],
        ),
    ];
    all.into_iter()
        .filter(|t| {
            t["name"]
                .as_str()
                .and_then(operation)
                .is_none_or(|op| grant.operations.contains(&op))
        })
        .collect()
}
