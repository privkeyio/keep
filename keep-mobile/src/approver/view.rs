// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! A checked request as the owner sees it: every string through the
//! display rule, and what the agent wrote marked apart.

use keep_approval::approver::{agent_text, shown, Shown, GATEWAY_TEXT_CHARS};
use keep_approval::binding::{CheckedRequest, Payload};
use keep_approval::messages::{Reason, Request};
use serde_json::Value;

/// One line of a request, as the app shows it.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct ApprovalField {
    pub label: String,
    /// The value, through the display rule.
    pub value: String,
    /// Written by the agent: shown apart, labeled as the agent's.
    pub by_agent: bool,
    /// The value's length in characters before the display rule.
    pub chars: u32,
    /// Hidden characters removed, which the app states.
    pub removed: u32,
    /// Whether the value was cut short.
    pub truncated: bool,
}

/// A request waiting for the owner.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub request_id: String,
    /// What is asked: `sign_nostr_event`, `sign_psbt`, `nip44_encrypt`,
    /// `nip44_decrypt` or `management`.
    pub op: String,
    /// Why the policy asked, in words.
    pub reason: String,
    /// The credential asking, by name, when an agent asks.
    pub credential: Option<String>,
    /// That credential's id, which freeze and unfreeze take, only when an
    /// agent asks: a management request can name a credential not yet
    /// issued.
    pub credential_id: Option<String>,
    /// Seconds left to decide, by this phone's clock.
    pub seconds_left: u64,
    pub fields: Vec<ApprovalField>,
    /// Things the owner must read first.
    pub warnings: Vec<String>,
}

fn field(label: &str, shown: Shown, by_agent: bool) -> ApprovalField {
    ApprovalField {
        label: label.into(),
        value: shown.text,
        by_agent,
        chars: shown.chars as u32,
        removed: shown.removed as u32,
        truncated: shown.truncated,
    }
}

fn gateway(label: &str, value: &str) -> ApprovalField {
    field(label, shown(value, GATEWAY_TEXT_CHARS), false)
}

fn agent(label: &str, value: &str) -> ApprovalField {
    field(label, agent_text(value), true)
}

fn sats(n: u64) -> String {
    format!("{n} sats")
}

fn kind_name(kind: u16) -> &'static str {
    match kind {
        0 => "profile metadata",
        3 => "follow list",
        5 => "deletion",
        62 => "request to vanish",
        7374 => "Cashu quote (NIP-60)",
        7375 => "Cashu tokens (NIP-60)",
        7376 => "Cashu spending history (NIP-60)",
        9321 => "nutzap (NIP-61)",
        37375 => "Cashu wallet (legacy NIP-60)",
        10000..=19999 => "replaceable event",
        20000..=29999 => "ephemeral event",
        _ => "event",
    }
}

fn reason_text(reason: &Reason) -> String {
    match reason {
        Reason::Kind { kind } => format!("signs kind {kind} ({})", kind_name(*kind)),
        Reason::EncryptToOwnKey => "encrypts to one of the wallet's own keys".into(),
        Reason::DecryptOwnPayload => "decrypts a message to one of the wallet's own keys".into(),
        Reason::AboveThreshold {
            requested,
            spent,
            threshold,
        } => format!(
            "spends {} with {} already spent, above the {} that needs approval",
            sats(*requested),
            sats(*spent),
            sats(*threshold)
        ),
        Reason::Management => "changes what agents may do".into(),
    }
}

/// Every leaf of `value`, as `path: value` rows in order.
fn flatten(prefix: &str, value: &Value, out: &mut Vec<ApprovalField>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&path, v, out);
            }
        }
        Value::Array(items) if items.is_empty() => out.push(gateway(prefix, "(none)")),
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                flatten(&format!("{prefix}[{i}]"), v, out);
            }
        }
        Value::String(s) => out.push(gateway(prefix, s)),
        other => out.push(gateway(prefix, &other.to_string())),
    }
}

/// The request as the app shows it.
pub fn view(
    request: &Request,
    checked: &CheckedRequest,
    clock_skew: bool,
    seconds_left: u64,
) -> ApprovalRequest {
    let mut fields = Vec::new();
    let mut warnings = Vec::new();
    if let Some(key) = &request.key {
        fields.push(gateway("signing key", &key.to_hex()));
    }
    if let Some(network) = &request.network {
        fields.push(gateway(
            "network",
            &serde_json::to_value(network)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default(),
        ));
    }
    match &checked.payload {
        Payload::Nostr(p) => {
            let e = &p.event;
            fields.push(gateway(
                "kind",
                &format!("{} ({})", e.kind, kind_name(e.kind)),
            ));
            fields.push(gateway("pubkey", &e.pubkey.to_hex()));
            fields.push(gateway("created at", &e.created_at.to_string()));
            fields.push(agent("content", &e.content));
            for (i, tag) in e.tags.iter().enumerate() {
                let tag = serde_json::to_string(tag).unwrap_or_default();
                fields.push(agent(&format!("tag {i}"), &tag));
            }
        }
        Payload::Psbt(_) => {
            if let Some(psbt) = &checked.psbt {
                fields.push(gateway("transaction", &psbt.txid));
                for o in &psbt.outputs {
                    let to = o
                        .address
                        .clone()
                        .unwrap_or_else(|| format!("script {}", hex::encode(&o.script)));
                    let label = match &o.change_path {
                        Some(path) => format!("output {} (change, {path})", o.index),
                        None => format!("output {}", o.index),
                    };
                    fields.push(gateway(&label, &format!("{to}: {}", sats(o.amount))));
                }
                fields.push(gateway("fee", &sats(psbt.fee)));
                fields.push(gateway("leaving the wallet", &sats(psbt.leaving_wallet)));
            }
            if let Some(b) = &request.budget {
                fields.push(gateway(
                    "credential budget",
                    &format!(
                        "{} spent of {}",
                        sats(b.credential_spent),
                        sats(b.credential_window)
                    ),
                ));
                fields.push(gateway(
                    "wallet budget",
                    &format!(
                        "{} spent of {}",
                        sats(b.wallet_spent),
                        sats(b.wallet_window)
                    ),
                ));
            }
        }
        Payload::Nip44Encrypt(p) => {
            fields.push(gateway("counterparty", &p.peer.to_hex()));
            fields.push(agent("plaintext", &p.plaintext));
        }
        Payload::Nip44Decrypt(p) => {
            fields.push(gateway("counterparty", &p.peer.to_hex()));
            fields.push(agent("plaintext", &p.plaintext));
            warnings
                .push("Approving sends this plaintext to the agent and its model provider.".into());
        }
        Payload::Management(change) => flatten("", &change.to_value(), &mut fields),
    }
    if clock_skew {
        warnings
            .push("The gateway's clock and this phone's differ by more than five minutes.".into());
    }
    ApprovalRequest {
        request_id: request.request_id.to_hex(),
        op: serde_json::to_value(request.op)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default(),
        reason: reason_text(&request.reason),
        credential: request
            .credential
            .as_ref()
            .map(|c| shown(&c.name, GATEWAY_TEXT_CHARS).text),
        credential_id: request
            .credential
            .as_ref()
            .filter(|_| !matches!(checked.payload, Payload::Management(_)))
            .map(|c| c.id.to_hex()),
        seconds_left,
        fields,
        warnings,
    }
}
