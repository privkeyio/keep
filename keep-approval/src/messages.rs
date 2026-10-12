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
use crate::sig::Alg;
use crate::{malformed, Hex16, Hex32, Hex33, Hex64, Result};

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

/// A wallet ledger's name: `main:` or `test:` (the test networks share
/// one ledger) and the wallet's x-only public key as 64 lowercase hex
/// characters. Anything else is refused when parsed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WalletName(String);

impl WalletName {
    /// The name of `key`'s ledger on mainnet (`main:`) or a test network.
    pub fn new(mainnet: bool, key: &[u8; 32]) -> Self {
        let prefix = if mainnet { "main:" } else { "test:" };
        Self(format!("{prefix}{}", hex::encode(key)))
    }

    /// Parse a ledger name strictly.
    pub fn parse(s: &str) -> Result<Self> {
        let key = s
            .strip_prefix("main:")
            .or_else(|| s.strip_prefix("test:"))
            .ok_or_else(|| malformed("a wallet is main: or test: and a key"))?;
        if !crate::codec::is_lower_hex(key, 32) {
            return Err(malformed("a wallet's key is 64 lowercase hex characters"));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for WalletName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for WalletName {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for WalletName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// One wallet ledger in an anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletAnchor {
    pub wallet: WalletName,
    /// One more on every reservation, never decreasing.
    pub seq: u64,
    /// The window's spent total.
    pub spent: u64,
    /// The wallet's window budget.
    pub window: u64,
}

/// A place in the audit log: its entry count and the hash of its last
/// entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogPoint {
    pub seq: u64,
    pub head: Hex32,
}

/// The audit log's and ledgers' anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorState {
    /// The audit log's entry count: entries ever written.
    pub seq: u64,
    /// The hash of the last audit entry.
    pub head: Hex32,
    /// The log's place in the anchor the gateway sent before this one, to
    /// any device in any message, as `keep.db` recorded it; null only in the
    /// first anchor after approvals are enabled.
    #[serde(deserialize_with = "nullable")]
    pub prev: Option<LogPoint>,
    pub wallets: Vec<WalletAnchor>,
}

impl AnchorState {
    /// The log's place this anchor shows.
    pub fn point(&self) -> LogPoint {
        LogPoint {
            seq: self.seq,
            head: self.head,
        }
    }
}

/// An unfreeze the gateway applied, from an approved `unfreeze` change or a
/// device's own unfreeze, with the epoch it moved the gateway to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unfrozen {
    pub scope: Scope,
    pub epoch: u64,
}

/// The most recent unfreezes a [`Frozen`] lists.
pub const MAX_UNFROZEN: usize = 16;

/// What is frozen, and the freeze epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frozen {
    pub epoch: u64,
    pub all: bool,
    pub credentials: Vec<Hex16>,
    /// The unfreezes applied within the wrap time window, oldest first, at
    /// most [`MAX_UNFROZEN`], so every phone can tell a freeze cleared by an
    /// unfreeze (another phone's included) from one cleared by a rollback.
    pub unfrozen: Vec<Unfrozen>,
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

/// Wipe every string in `value`.
fn wipe(value: &mut Value) {
    use zeroize::Zeroize;
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(map) => map.values_mut().for_each(wipe),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

// The payload can hold a decrypted message: wiped when the request goes.
impl Drop for Request {
    fn drop(&mut self) {
        wipe(&mut self.payload);
    }
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
    pub signer: SignerKey,
    pub sig: Hex64,
}

/// The key that signed a freeze or unfreeze: a device's transport key (32
/// bytes, x-only secp256k1) or its approver key (33 bytes, compressed
/// P-256). The length tells them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerKey {
    Transport(Hex32),
    Approver(Hex33),
}

impl SignerKey {
    /// The key's bytes, as the freeze digest covers them.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            SignerKey::Transport(k) => &k.0,
            SignerKey::Approver(k) => &k.0,
        }
    }
}

impl Serialize for SignerKey {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            SignerKey::Transport(k) => k.serialize(s),
            SignerKey::Approver(k) => k.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for SignerKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        match s.len() {
            64 => Hex32::parse(&s).map(SignerKey::Transport),
            66 => Hex33::parse(&s).map(SignerKey::Approver),
            _ => Err(malformed("a signer is a 32-byte or 33-byte key")),
        }
        .map_err(serde::de::Error::custom)
    }
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
        /// The approver key's type: `"p256"` is the only one.
        alg: Alg,
        approver: Hex33,
        proof: Hex32,
        approver_sig: Hex64,
    },
    /// From the gateway, once the device is registered.
    Paired {
        v: V1,
        transport: Hex32,
        approver: Hex33,
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
    pub by: Option<Hex33>,
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
            alg: Alg::P256,
            approver: Hex33([4; 33]),
            proof: Hex32([5; 32]),
            approver_sig: Hex64([6; 64]),
        };
        let text = to_text(&pair);
        assert!(text.contains("\"type\":\"pair\""));
        assert!(text.contains("\"alg\":\"p256\""));
        assert_eq!(parse::<Pairing>(&text).unwrap(), pair);
        // Any other approver key type, or none, is refused.
        for other in ["\"alg\":\"P256\"", "\"alg\":\"secp256k1\"", "\"alg\":null"] {
            let bad = text.replace("\"alg\":\"p256\"", other);
            assert!(parse::<Pairing>(&bad).is_err(), "{bad}");
        }
        let missing = text.replace("\"alg\":\"p256\",", "");
        assert!(parse::<Pairing>(&missing).is_err(), "{missing}");
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

    /// A freeze's signer is a 32-byte or 33-byte key, in lowercase hex.
    #[test]
    fn signer_keys_are_told_apart_by_length() {
        let t: SignerKey = serde_json::from_str(&format!("\"{}\"", "ab".repeat(32))).unwrap();
        assert!(matches!(t, SignerKey::Transport(_)));
        let a: SignerKey = serde_json::from_str(&format!("\"{}\"", "02".repeat(33))).unwrap();
        assert!(matches!(a, SignerKey::Approver(_)));
        for bad in [
            "ab".repeat(31),
            "ab".repeat(34),
            "AB".repeat(32),
            "0".repeat(65),
        ] {
            assert!(serde_json::from_str::<SignerKey>(&format!("\"{bad}\"")).is_err());
        }
    }

    /// A wallet's name is main: or test: and 64 lowercase hex characters.
    #[test]
    fn wallet_names_are_strict() {
        let key = "ab".repeat(32);
        for good in [format!("main:{key}"), format!("test:{key}")] {
            assert!(WalletName::parse(&good).is_ok(), "{good}");
        }
        for bad in [
            format!("Main:{key}"),
            format!("main:{}", key.to_uppercase()),
            format!("main:{key}0"),
            format!("main:{}", &key[2..]),
            format!("main:{key}\u{202e}"),
            format!("sign:{key}"),
            key.clone(),
        ] {
            assert!(WalletName::parse(&bad).is_err(), "{bad}");
            assert!(
                serde_json::from_str::<WalletName>(&serde_json::to_string(&bad).unwrap()).is_err()
            );
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
