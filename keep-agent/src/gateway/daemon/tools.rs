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
pub const LIST_SECRETS: &str = "list_secrets";
pub const HTTP_REQUEST: &str = "http_request";

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
        HTTP_REQUEST => Some(Operation::HttpRequest),
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
        tool(
            HTTP_REQUEST,
            "Send an HTTPS request with a granted secret added as the header its rule names, to a host, port, method and path prefix the rule allows. The secret is never returned: a response that carries it is refused. Redirects are returned, not followed.",
            json!({
                "secret": { "type": "string", "description": "The secret's id, from list_secrets." },
                "method": { "type": "string", "enum": ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"] },
                "url": { "type": "string", "description": "An https URL, written exactly as it parses (lowercase host, no default port, no dot segments)." },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" },
                    "description": "Accept, Content-Type, User-Agent, the If- headers, and any the rule adds."
                },
                "body": { "type": "string" }
            }),
            &["secret", "method", "url"],
        ),
        tool(
            LIST_SECRETS,
            "List the vault secrets this credential may use, by id, name and kind, with where each may be sent. Never returns a secret's value.",
            json!({}),
            &[],
        ),
    ];
    all.into_iter()
        .filter(|t| match t["name"].as_str() {
            Some(LIST_SECRETS) => !grant.secrets.is_empty(),
            name => name
                .and_then(operation)
                .is_none_or(|op| grant.operations.contains(&op)),
        })
        .collect()
}
