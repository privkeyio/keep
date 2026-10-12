// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The protocol's messages, as JSON rumor content. Parsing is strict:
//! `"v"` must be 1, unknown fields, duplicate names and anything outside the
//! schema are refused.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::binding::{Network, Op};
use crate::change::{parse_without_duplicates, Scope};
use crate::{malformed, Hex16, Hex32, Hex64, Result};

/// The `"v"` field: always 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct V1;

impl Serialize for V1 {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_u8(crate::VERSION)
    }
}

impl<'de> Deserialize<'de> for V1 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        match u64::deserialize(d)? {
            1 => Ok(V1),
            other => Err(serde::de::Error::custom(format!(
                "protocol version {other} is not supported"
            ))),
        }
    }
}

/// Parse a message from rumor content, strictly.
pub fn parse<T: DeserializeOwned>(text: &str) -> Result<T> {
    let value = parse_without_duplicates(text)?;
    serde_json::from_value(value).map_err(|e| malformed(format!("message: {e}")))
}

/// Serialize a message as rumor content.
pub fn to_text<T: Serialize>(message: &T) -> String {
    serde_json::to_string(message).expect("messages always serialize")
}

/// The credential a request is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    pub id: Hex16,
    pub name: String,
    pub uid: u32,
}

/// Why the policy asked for an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Reason {
    Kind {
        kind: u16,
    },
    EncryptToOwnKey,
    DecryptOwnPayload,
    AboveThreshold {
        requested: u64,
        spent: u64,
        threshold: u64,
    },
    Management,
}

// Derived, an internally tagged enum lets extra fields through on a variant
// with none, so each variant is parsed on its own, refusing unknown fields.
impl<'de> Deserialize<'de> for Reason {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Kind {
            kind: u16,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Nothing {}
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Threshold {
            requested: u64,
            spent: u64,
            threshold: u64,
        }
        let mut map = serde_json::Map::<String, Value>::deserialize(d)?;
        let Some(Value::String(tag)) = map.remove("type") else {
            return Err(D::Error::custom("a reason has a type"));
        };
        let rest = Value::Object(map);
        let fields = |e: serde_json::Error| D::Error::custom(format!("reason: {e}"));
        Ok(match tag.as_str() {
            "kind" => Reason::Kind {
                kind: Kind::deserialize(rest).map_err(fields)?.kind,
            },
            "encrypt_to_own_key" => {
                Nothing::deserialize(rest).map_err(fields)?;
                Reason::EncryptToOwnKey
            }
            "decrypt_own_payload" => {
                Nothing::deserialize(rest).map_err(fields)?;
                Reason::DecryptOwnPayload
            }
            "above_threshold" => {
                let t = Threshold::deserialize(rest).map_err(fields)?;
                Reason::AboveThreshold {
                    requested: t.requested,
                    spent: t.spent,
                    threshold: t.threshold,
                }
            }
            "management" => {
                Nothing::deserialize(rest).map_err(fields)?;
                Reason::Management
            }
            other => return Err(D::Error::custom(format!("unknown reason {other:?}"))),
        })
    }
}

/// A field that must be present, and may be null. Serde otherwise takes a
/// missing `Option` field as null, which would give a request two forms.
pub(crate) fn nullable<'de, D, T>(d: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

/// A spend's budget context, before the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub credential_spent: u64,
    pub credential_window: u64,
    pub wallet_spent: u64,
    pub wallet_window: u64,
}

/// One wallet ledger in an anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletAnchor {
    /// `main:` or `test:` and the wallet's public key in hex.
    pub wallet: String,
    /// One more on every reservation, never decreasing.
    pub seq: u64,
    /// The window's spent total.
    pub spent: u64,
    /// The wallet's window budget.
    pub window: u64,
}

/// The audit log's and ledgers' anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorState {
    /// The audit log's entry count: entries ever written.
    pub seq: u64,
    /// The hash of the last audit entry.
    pub head: Hex32,
    pub wallets: Vec<WalletAnchor>,
}

/// What is frozen, and the freeze epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frozen {
    pub epoch: u64,
    pub all: bool,
    pub credentials: Vec<Hex16>,
}

/// An approval request (kind 24250). `payload` depends on `op`; see
/// [`crate::binding::Payload`]. Its `Debug` leaves out the payload, which
/// can hold a decrypted message.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub v: V1,
    pub request_id: Hex32,
    pub request_hash: Hex32,
    pub created_at: u64,
    pub deadline_secs: u64,
    #[serde(deserialize_with = "nullable")]
    pub credential: Option<CredentialRef>,
    pub op: Op,
    #[serde(deserialize_with = "nullable")]
    pub key: Option<Hex32>,
    #[serde(deserialize_with = "nullable")]
    pub network: Option<Network>,
    pub reason: Reason,
    pub payload: Value,
    #[serde(deserialize_with = "nullable")]
    pub budget: Option<Budget>,
    pub anchor: AnchorState,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("request_id", &self.request_id)
            .field("request_hash", &self.request_hash)
            .field("created_at", &self.created_at)
            .field("deadline_secs", &self.deadline_secs)
            .field("credential", &self.credential)
            .field("op", &self.op)
            .field("key", &self.key)
            .field("network", &self.network)
            .field("reason", &self.reason)
            .field("budget", &self.budget)
            .field("anchor", &self.anchor)
            .finish_non_exhaustive()
    }
}

/// Approve or deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Approve,
    Deny,
}

/// A decision (kind 24251).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub v: V1,
    pub request_id: Hex32,
    pub request_hash: Hex32,
    pub decision: Verdict,
    pub sig: Hex64,
}

/// Freeze or unfreeze.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeAction {
    Freeze,
    Unfreeze,
}

/// A freeze or unfreeze (kind 24252).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Freeze {
    pub v: V1,
    pub action: FreezeAction,
    pub scope: Scope,
    pub counter: u64,
    pub epoch: u64,
    /// The key that made `sig`: the transport key for a freeze, the approver
    /// key for an unfreeze.
    pub signer: Hex32,
    pub sig: Hex64,
}

/// An anchor (kind 24253).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub v: V1,
    pub at: u64,
    pub anchor: AnchorState,
    pub frozen: Frozen,
}

/// Pairing (kind 24254).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Pairing {
    /// From the phone, sealed by its transport key.
    Pair {
        v: V1,
        label: String,
        approver: Hex32,
        proof: Hex32,
        approver_sig: Hex64,
    },
    /// From the gateway, once the device is registered.
    Paired {
        v: V1,
        transport: Hex32,
        approver: Hex32,
        relays: Vec<String>,
        deadline_secs: u64,
        anchor: AnchorState,
        frozen: Frozen,
    },
    /// From the gateway, when pairing is refused.
    Refused { v: V1, reason: String },
}

/// How a request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    Approved,
    Denied,
    Expired,
    Canceled,
}

/// An outcome (kind 24255).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub v: V1,
    pub request_id: Hex32,
    pub outcome: OutcomeKind,
    /// The deciding device's approver key, when a device decided.
    #[serde(deserialize_with = "nullable")]
    pub by: Option<Hex32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision_text() -> String {
        format!(
            r#"{{"v":1,"request_id":"{}","request_hash":"{}","decision":"approve","sig":"{}"}}"#,
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(64)
        )
    }

    #[test]
    fn messages_parse_strictly() {
        let d: Decision = parse(&decision_text()).unwrap();
        assert_eq!(d.decision, Verdict::Approve);
        assert_eq!(parse::<Decision>(&to_text(&d)).unwrap(), d);
        // Another version, an unknown field, a duplicate name, a bad verdict.
        for bad in [
            decision_text().replace("\"v\":1", "\"v\":2"),
            decision_text().replace("\"v\":1", "\"v\":1,\"x\":0"),
            decision_text().replace("\"v\":1", "\"v\":1,\"v\":1"),
            decision_text().replace("approve", "maybe"),
            decision_text().replace(",\"sig\"", ",\"extra\":1,\"sig\""),
        ] {
            assert!(parse::<Decision>(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn pairing_messages_are_tagged() {
        let pair = Pairing::Pair {
            v: V1,
            label: "My phone".into(),
            approver: Hex32([4; 32]),
            proof: Hex32([5; 32]),
            approver_sig: Hex64([6; 64]),
        };
        let text = to_text(&pair);
        assert!(text.contains("\"type\":\"pair\""));
        assert_eq!(parse::<Pairing>(&text).unwrap(), pair);
        let refused = r#"{"type":"refused","v":1,"reason":"expired"}"#;
        assert!(matches!(
            parse::<Pairing>(refused).unwrap(),
            Pairing::Refused { .. }
        ));
        assert!(parse::<Pairing>(r#"{"type":"refused","v":1,"reason":"x","y":1}"#).is_err());
    }

    /// Every reason parses back, and an extra field is refused on each,
    /// including those with no fields of their own.
    #[test]
    fn reasons_parse_strictly() {
        for reason in [
            Reason::Kind { kind: 1 },
            Reason::EncryptToOwnKey,
            Reason::DecryptOwnPayload,
            Reason::AboveThreshold {
                requested: 1,
                spent: 2,
                threshold: 3,
            },
            Reason::Management,
        ] {
            let text = to_text(&reason);
            assert_eq!(parse::<Reason>(&text).unwrap(), reason);
            let extra = text.replacen('{', "{\"x\":\"y\",", 1);
            assert!(parse::<Reason>(&extra).is_err(), "{extra}");
        }
        for bad in [
            r#"{"type":"kind"}"#,
            r#"{"type":"other"}"#,
            r#"{"kind":1}"#,
            r#"{"type":1}"#,
            r#"{"type":"kind","kind":65536}"#,
        ] {
            assert!(parse::<Reason>(bad).is_err(), "{bad}");
        }
    }

    /// A nullable field must still be present.
    #[test]
    fn nullable_fields_are_required() {
        let outcome = format!(
            r#"{{"v":1,"request_id":"{}","outcome":"expired""#,
            "11".repeat(32)
        );
        assert!(parse::<Outcome>(&format!("{outcome},\"by\":null}}")).is_ok());
        assert!(parse::<Outcome>(&format!("{outcome}}}")).is_err());
    }
}
