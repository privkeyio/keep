// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Management change objects, the canonical JSON their hash covers, and the
//! strict parse an approver runs on them.
//!
//! Every number in a change object is a JSON string of decimal digits and
//! every key and id is lowercase hex, so a serialized change holds only
//! strings, arrays and objects, which RFC 8785 (JSON Canonicalization
//! Scheme) serializes one way only. A change that holds anything else, an
//! unknown field, a duplicate name or a list out of order is refused.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::{malformed, sha256, Hex16, Hex32, Hex33, Result};

/// A management change, as a request carries it in `payload.change`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    /// Issue a credential. `id`, `created_at` and `expires_at` are fixed by
    /// the gateway before asking, so the approved change is exactly what is
    /// applied.
    IssueCredential {
        id: Hex16,
        name: String,
        uid: Decimal,
        created_at: Decimal,
        expires_at: Decimal,
        grant: ChangeGrant,
    },
    /// Clear a freeze, if `epoch` is still the gateway's freeze epoch.
    Unfreeze { scope: Scope, epoch: Decimal },
    /// Register a paired device.
    AddApprover {
        transport: Hex32,
        approver: Hex33,
        label: String,
        fingerprint: String,
    },
    /// Remove a device.
    RemoveApprover { transport: Hex32, approver: Hex33 },
}

/// What a freeze or unfreeze covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The whole gateway.
    All,
    /// One credential.
    Credential(Hex16),
}

impl Serialize for Scope {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct One<'a> {
            credential: &'a Hex16,
        }
        match self {
            Scope::All => s.serialize_str("all"),
            Scope::Credential(id) => One { credential: id }.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct One {
            credential: Hex16,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Name(String),
            One(One),
        }
        match Wire::deserialize(d)? {
            Wire::Name(n) if n == "all" => Ok(Scope::All),
            Wire::Name(_) => Err(serde::de::Error::custom("scope is \"all\" or a credential")),
            Wire::One(one) => Ok(Scope::Credential(one.credential)),
        }
    }
}

/// The grant an `issue_credential` change carries: the gateway's grant
/// schema with every number as a decimal string and keys as hex. Lists are
/// strictly ascending, so each grant has one form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeGrant {
    pub keys: Vec<Hex32>,
    pub operations: Vec<String>,
    pub event_kinds: Vec<Decimal>,
    pub nip44_peers: Vec<Hex32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitcoin: Option<ChangeBitcoin>,
    pub limits: ChangeLimits,
}

/// A grant's Bitcoin part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeBitcoin {
    pub network: String,
    pub per_psbt_sats: Decimal,
    pub window_sats: Decimal,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_above_sats: Option<Decimal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_allowlist: Option<Vec<String>>,
}

/// A grant's request limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeLimits {
    pub per_minute: Decimal,
    pub per_hour: Decimal,
    pub per_day: Decimal,
}

/// The operations a grant may name.
pub const OPERATIONS: [&str; 6] = [
    "get_bitcoin_address",
    "get_public_key",
    "nip44_decrypt",
    "nip44_encrypt",
    "sign_nostr_event",
    "sign_psbt",
];

/// The Bitcoin networks a grant may name.
pub const NETWORKS: [&str; 5] = ["bitcoin", "regtest", "signet", "testnet", "testnet4"];

/// A non-negative integer carried as a JSON string of decimal digits, with
/// no sign, no leading zero (but "0") and nothing else.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Decimal(pub u64);

impl fmt::Debug for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for Decimal {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Decimal {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        crate::codec::parse_decimal(&s)
            .map(Decimal)
            .ok_or_else(|| serde::de::Error::custom("expected a decimal string in range"))
    }
}

impl Change {
    /// The `change_type` byte the request hash covers.
    pub fn type_code(&self) -> u8 {
        match self {
            Change::IssueCredential { .. } => 1,
            Change::Unfreeze { .. } => 2,
            Change::AddApprover { .. } => 3,
            Change::RemoveApprover { .. } => 4,
        }
    }

    /// Parse a change strictly: only strings, arrays and objects, no
    /// duplicate names, the schema exactly, lists strictly ascending.
    pub fn parse(value: &Value) -> Result<Self> {
        only_strings(value)?;
        let change: Change =
            serde_json::from_value(value.clone()).map_err(|e| malformed(format!("change: {e}")))?;
        change.check()?;
        Ok(change)
    }

    /// The change as a JSON value, ready to send.
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("a change always serializes")
    }

    /// RFC 8785 canonical JSON of the change.
    pub fn canonical(&self) -> Vec<u8> {
        canonical_json(&self.to_value()).expect("a change holds only strings, arrays and objects")
    }

    /// SHA-256 of the canonical JSON, which the request hash covers.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical())
    }

    fn check(&self) -> Result<()> {
        match self {
            Change::IssueCredential {
                name, uid, grant, ..
            } => {
                check_label(name, "name")?;
                if uid.0 > u64::from(u32::MAX) {
                    return Err(malformed("uid out of range"));
                }
                grant.check()?;
            }
            Change::AddApprover {
                transport,
                approver,
                label,
                fingerprint,
            } => {
                check_label(label, "label")?;
                if *fingerprint != crate::sig::fingerprint(&transport.0, &approver.0) {
                    return Err(malformed("the fingerprint is not the device's"));
                }
            }
            Change::RemoveApprover { .. } | Change::Unfreeze { .. } => {}
        }
        Ok(())
    }
}

/// The most characters in a device label or a credential name.
pub const MAX_LABEL_CHARS: usize = 64;

/// Check a device label or a credential name, which an approver shows as
/// the gateway's word: 1 to [`MAX_LABEL_CHARS`] characters, not only
/// spaces, and nothing that could hide or reorder text (see
/// [`crate::approver::is_hidden`]).
pub fn check_label(text: &str, what: &str) -> Result<()> {
    let chars = text.chars().count();
    if chars > MAX_LABEL_CHARS {
        return Err(malformed(format!(
            "a {what} is at most {MAX_LABEL_CHARS} characters"
        )));
    }
    if text.trim().is_empty() {
        return Err(malformed(format!("a {what} is not empty or only spaces")));
    }
    if text.chars().any(crate::approver::is_hidden) {
        return Err(malformed(format!(
            "a {what} holds a control or invisible character"
        )));
    }
    Ok(())
}

impl ChangeGrant {
    fn check(&self) -> Result<()> {
        ascending(&self.keys, "keys")?;
        ascending(&self.operations, "operations")?;
        ascending(&self.event_kinds, "event_kinds")?;
        ascending(&self.nip44_peers, "nip44_peers")?;
        if let Some(op) = self
            .operations
            .iter()
            .find(|o| !OPERATIONS.contains(&o.as_str()))
        {
            return Err(malformed(format!("unknown operation {op:?}")));
        }
        if self.event_kinds.iter().any(|k| k.0 > u64::from(u16::MAX)) {
            return Err(malformed("event kind out of range"));
        }
        if self
            .event_kinds
            .iter()
            .any(|k| crate::kind::is_protocol_kind(k.0 as u16))
        {
            return Err(malformed(
                "a grant cannot list the approval protocol's kinds",
            ));
        }
        if let Some(b) = &self.bitcoin {
            if !NETWORKS.contains(&b.network.as_str()) {
                return Err(malformed(format!("unknown network {:?}", b.network)));
            }
            if let Some(list) = &b.address_allowlist {
                ascending(list, "address_allowlist")?;
                for address in list {
                    check_address(address, &b.network)?;
                }
            }
        }
        for limit in [
            self.limits.per_minute,
            self.limits.per_hour,
            self.limits.per_day,
        ] {
            if limit.0 > u64::from(u32::MAX) {
                return Err(malformed("limit out of range"));
            }
        }
        Ok(())
    }
}

/// The longest address a grant's allowlist may hold: a 40-byte witness
/// program in bech32m on the longest prefix fits in far less.
pub const MAX_ADDRESS_CHARS: usize = 90;

/// Check an allowlisted address, which an approver shows as the gateway's
/// word: at most [`MAX_ADDRESS_CHARS`] ASCII letters and digits, and a valid
/// address on the grant's network.
fn check_address(address: &str, network: &str) -> Result<()> {
    if address.is_empty()
        || address.len() > MAX_ADDRESS_CHARS
        || !address.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(malformed(
            "an allowlisted address holds letters and digits only",
        ));
    }
    let network = match network {
        "bitcoin" => bitcoin::Network::Bitcoin,
        "testnet" => bitcoin::Network::Testnet,
        "testnet4" => bitcoin::Network::Testnet4,
        "signet" => bitcoin::Network::Signet,
        _ => bitcoin::Network::Regtest,
    };
    let parsed: bitcoin::Address<bitcoin::address::NetworkUnchecked> = address
        .parse()
        .map_err(|_| malformed("an allowlisted address does not parse"))?;
    if !parsed.is_valid_for_network(network) {
        return Err(malformed("an allowlisted address is for another network"));
    }
    Ok(())
}

fn ascending<T: Ord>(list: &[T], what: &str) -> Result<()> {
    if crate::codec::strictly_ascending(list) {
        Ok(())
    } else {
        Err(malformed(format!("{what} must be strictly ascending")))
    }
}

/// Refuse anything but strings, arrays and objects.
fn only_strings(value: &Value) -> Result<()> {
    match value {
        Value::String(_) => Ok(()),
        Value::Array(items) => items.iter().try_for_each(only_strings),
        Value::Object(map) => map.values().try_for_each(only_strings),
        Value::Null | Value::Bool(_) | Value::Number(_) => {
            Err(malformed("a change holds only strings, arrays and objects"))
        }
    }
}

/// Parse JSON text, refusing an object with a name twice.
pub fn parse_without_duplicates(text: &str) -> Result<Value> {
    use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};

    struct Strict;

    impl<'de> DeserializeSeed<'de> for Strict {
        type Value = Value;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> std::result::Result<Value, D::Error> {
            d.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for Strict {
        type Value = Value;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("JSON")
        }
        fn visit_bool<E>(self, v: bool) -> std::result::Result<Value, E> {
            Ok(Value::Bool(v))
        }
        fn visit_i64<E>(self, v: i64) -> std::result::Result<Value, E> {
            Ok(Value::from(v))
        }
        fn visit_u64<E>(self, v: u64) -> std::result::Result<Value, E> {
            Ok(Value::from(v))
        }
        fn visit_f64<E>(self, v: f64) -> std::result::Result<Value, E> {
            Ok(Value::from(v))
        }
        fn visit_str<E>(self, v: &str) -> std::result::Result<Value, E> {
            Ok(Value::String(v.to_owned()))
        }
        fn visit_string<E>(self, v: String) -> std::result::Result<Value, E> {
            Ok(Value::String(v))
        }
        fn visit_unit<E>(self) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_none<E>(self) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
            let mut items = Vec::new();
            while let Some(item) = seq.next_element_seed(Strict)? {
                items.push(item);
            }
            Ok(Value::Array(items))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
            let mut out = serde_json::Map::new();
            while let Some(key) = map.next_key::<String>()? {
                let value = map.next_value_seed(Strict)?;
                if out.insert(key.clone(), value).is_some() {
                    return Err(serde::de::Error::custom(format!("duplicate name {key:?}")));
                }
            }
            Ok(Value::Object(out))
        }
    }

    let mut de = serde_json::Deserializer::from_str(text);
    let value = Strict
        .deserialize(&mut de)
        .map_err(|e| malformed(format!("JSON: {e}")))?;
    de.end().map_err(|e| malformed(format!("JSON: {e}")))?;
    Ok(value)
}

/// RFC 8785 canonical JSON of a value holding only strings, arrays and
/// objects: object members sorted by the UTF-16 code units of their names,
/// no whitespace, strings escaped as ECMAScript's `JSON.stringify` does.
pub(crate) fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push(b'{');
            for (i, (name, item)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(name, out);
                out.push(b':');
                write_canonical(item, out)?;
            }
            out.push(b'}');
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {
            return Err(malformed(
                "canonical JSON here holds only strings, arrays and objects",
            ))
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn grant() -> Value {
        json!({
            "keys": ["11".repeat(32)],
            "operations": ["sign_nostr_event", "sign_psbt"],
            "event_kinds": ["0", "1"],
            "nip44_peers": [],
            "bitcoin": {
                "network": "bitcoin",
                "per_psbt_sats": "50000",
                "window_sats": "100000",
                "approval_above_sats": "20000"
            },
            "limits": {"per_minute": "10", "per_hour": "100", "per_day": "1000"}
        })
    }

    fn issue() -> Value {
        json!({
            "type": "issue_credential",
            "id": "22".repeat(16),
            "name": "writer",
            "uid": "1001",
            "created_at": "1791580000",
            "expires_at": "1794172000",
            "grant": grant(),
        })
    }

    fn add_approver() -> Value {
        json!({
            "type": "add_approver",
            "transport": "33".repeat(32),
            "approver": "02".repeat(33),
            "label": "My phone",
            "fingerprint": crate::sig::fingerprint(&[0x33; 32], &[0x02; 33]),
        })
    }

    #[test]
    fn every_change_round_trips() {
        let changes = [
            issue(),
            json!({"type": "unfreeze", "scope": "all", "epoch": "41"}),
            json!({"type": "unfreeze", "scope": {"credential": "22".repeat(16)}, "epoch": "41"}),
            add_approver(),
            json!({"type": "remove_approver", "transport": "33".repeat(32), "approver": "02".repeat(33)}),
        ];
        for (code, value) in [1u8, 2, 2, 3, 4].into_iter().zip(changes) {
            let change = Change::parse(&value).unwrap();
            assert_eq!(change.type_code(), code);
            assert_eq!(change.to_value(), value);
        }
    }

    /// Anything outside the schema is refused: a number, a boolean, a null,
    /// an unknown field, a list out of order, an unknown operation or
    /// network, a padded decimal, a value out of range.
    #[test]
    fn strict_parse_refuses_everything_else() {
        let mut bad: Vec<Value> = Vec::new();
        let mut v = issue();
        v["uid"] = json!(1001);
        bad.push(v);
        let mut v = issue();
        v["grant"]["bitcoin"]["approval_above_sats"] = Value::Null;
        bad.push(v);
        let mut v = issue();
        v["grant"]["bitcoin"]["approval_above_sats"] = json!(true);
        bad.push(v);
        let mut v = issue();
        v["extra"] = json!("x");
        bad.push(v);
        let mut v = issue();
        v["grant"]["extra"] = json!("x");
        bad.push(v);
        let mut v = issue();
        v["grant"]["event_kinds"] = json!(["1", "0"]);
        bad.push(v);
        let mut v = issue();
        v["grant"]["event_kinds"] = json!(["1", "1"]);
        bad.push(v);
        for kind in ["24250", "24255"] {
            let mut v = issue();
            v["grant"]["event_kinds"] = json!(["1", kind]);
            bad.push(v);
        }
        let mut v = issue();
        v["grant"]["keys"] = json!(["22".repeat(32), "11".repeat(32)]);
        bad.push(v);
        let mut v = issue();
        v["grant"]["nip44_peers"] = json!(["22".repeat(32), "22".repeat(32)]);
        bad.push(v);
        let mut v = issue();
        v["grant"]["operations"] = json!(["sign_psbt", "sign_nostr_event"]);
        bad.push(v);
        let mut v = issue();
        v["grant"]["bitcoin"]["address_allowlist"] = json!(["bc1q2", "bc1q1"]);
        bad.push(v);
        let mut v = issue();
        v["uid"] = json!("+1001");
        bad.push(v);
        let mut v = issue();
        v["uid"] = json!(" 1001");
        bad.push(v);
        let mut v = issue();
        v["grant"]["operations"] = json!(["sign_everything"]);
        bad.push(v);
        let mut v = issue();
        v["grant"]["bitcoin"]["network"] = json!("mainnet");
        bad.push(v);
        let mut v = issue();
        v["uid"] = json!("01001");
        bad.push(v);
        let mut v = issue();
        v["uid"] = json!("-1");
        bad.push(v);
        let mut v = issue();
        v["uid"] = json!("4294967296");
        bad.push(v);
        let mut v = issue();
        v["grant"]["event_kinds"] = json!(["65536"]);
        bad.push(v);
        let mut v = issue();
        v["grant"]["limits"]["per_day"] = json!("4294967296");
        bad.push(v);
        let mut v = issue();
        v["id"] = json!("AB".repeat(16));
        bad.push(v);
        bad.push(json!({"type": "unfreeze", "scope": "some", "epoch": "1"}));
        bad.push(json!({"type": "unfreeze", "scope": {"credential": "22".repeat(16), "x": "y"}, "epoch": "1"}));
        bad.push(json!({"type": "freeze", "scope": "all", "epoch": "1"}));
        // A device change: a fingerprint not the keys', an approver key of
        // another length, a label too long, empty or hiding text.
        let mut v = add_approver();
        v["fingerprint"] = json!(crate::sig::fingerprint(&[0x34; 32], &[0x02; 33]));
        bad.push(v);
        let mut v = add_approver();
        v["fingerprint"] = json!(v["fingerprint"].as_str().unwrap().replace(' ', ""));
        bad.push(v);
        let mut v = add_approver();
        v["approver"] = json!("33".repeat(32));
        bad.push(v);
        bad.push(json!({"type": "remove_approver", "transport": "33".repeat(32), "approver": "33".repeat(32)}));
        // An allowlisted address that is not one, is for another network, or
        // could hide text.
        for list in [
            json!(["bc1q2"]),
            json!(["tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"]),
            json!(["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\u{200b}"]),
            json!([format!("bc1q{}", "q".repeat(MAX_ADDRESS_CHARS))]),
        ] {
            let mut v = issue();
            v["grant"]["bitcoin"]["address_allowlist"] = list;
            bad.push(v);
        }
        for label in [
            "",
            " ",
            &"x".repeat(MAX_LABEL_CHARS + 1),
            "My\u{202e}phone",
            "My\nphone",
        ] {
            let mut v = add_approver();
            v["label"] = json!(label);
            bad.push(v);
            let mut v = issue();
            v["name"] = json!(label);
            bad.push(v);
        }
        for (i, v) in bad.iter().enumerate() {
            assert!(Change::parse(v).is_err(), "case {i} parsed: {v}");
        }
    }

    #[test]
    fn allowlisted_addresses_on_the_grants_network_are_fine() {
        let mut v = issue();
        v["grant"]["bitcoin"]["address_allowlist"] = json!([
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        ]);
        assert!(Change::parse(&v).is_ok());
    }

    #[test]
    fn labels_up_to_the_limit_are_fine() {
        for label in ["a", "My phone", &"é".repeat(MAX_LABEL_CHARS)] {
            let mut v = add_approver();
            v["label"] = json!(label);
            assert!(Change::parse(&v).is_ok(), "{label}");
        }
    }

    #[test]
    fn duplicate_names_are_refused() {
        let text = r#"{"type":"unfreeze","scope":"all","epoch":"1","epoch":"2"}"#;
        assert!(parse_without_duplicates(text).is_err());
        let text = r#"{"type":"unfreeze","scope":"all","epoch":"1"}"#;
        assert!(Change::parse(&parse_without_duplicates(text).unwrap()).is_ok());
        assert!(parse_without_duplicates(&format!("{text} x")).is_err());
    }

    /// RFC 8785: members sorted by UTF-16 code units (so an astral
    /// character sorts before U+FB33), strings escaped like
    /// `JSON.stringify`, no whitespace.
    #[test]
    fn canonical_json_follows_rfc_8785() {
        let v = json!({
            "\u{fb33}": "x",
            "\u{1f600}": "y",
            "b": ["1", {"z": "", "a": "q\"\\\u{1}\n\u{7f}é"}],
            "a": "",
        });
        let out = String::from_utf8(canonical_json(&v).unwrap()).unwrap();
        assert_eq!(
            out,
            "{\"a\":\"\",\"b\":[\"1\",{\"a\":\"q\\\"\\\\\\u0001\\n\u{7f}é\",\"z\":\"\"}],\"\u{1f600}\":\"y\",\"\u{fb33}\":\"x\"}"
        );
        assert!(canonical_json(&json!({"a": 1})).is_err());
    }
}
