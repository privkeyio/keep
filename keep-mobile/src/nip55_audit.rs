// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! NIP-55 signing-audit hash chain: the tamper-evident HMAC chain over the
//! permission operation log. This is the single source of truth for the chain
//! crypto and verification; the Android layer owns only the Room storage and
//! supplies the per-app HMAC key from its keystore.
//!
//! The hash is a **keyed** HMAC-SHA256 (forgeable only with the key), matching
//! the scheme keep-android wrote previously, so existing rows stay valid. This
//! deliberately does NOT use the unkeyed blake2b chain in `audit.rs`, which is
//! strictly weaker for tamper evidence.

use keep_core::crypto::hmac_sha256;

/// A persisted audit-log row as the Android storage layer holds it.
#[derive(uniffi::Record, Clone, Debug)]
pub struct Nip55AuditEntry {
    pub id: i64,
    pub timestamp: i64,
    pub caller: String,
    pub request_type: String,
    pub event_kind: Option<i32>,
    pub decision: String,
    pub was_automatic: bool,
    pub previous_hash: Option<String>,
    pub entry_hash: String,
}

/// Result of verifying the audit chain. Mirrors keep-android's
/// `ChainVerificationResult`. `Valid` and `PartiallyVerified` mean intact (the
/// latter skipped pre-chain legacy rows); the rest are integrity failures.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum Nip55ChainStatus {
    Valid,
    PartiallyVerified { legacy_entries_skipped: u32 },
    Truncated { entry_id: i64 },
    Broken { entry_id: i64 },
    Tampered { entry_id: i64 },
}

#[allow(clippy::too_many_arguments)]
fn audit_entry_hash_inner(
    previous_hash: Option<&str>,
    caller: &str,
    request_type: &str,
    event_kind: Option<i32>,
    decision: &str,
    timestamp: i64,
    was_automatic: bool,
    hmac_key: &[u8],
) -> String {
    // Must match keep-android `PermissionStore.calculateEntryHash` byte-for-byte:
    // pipe-delimited UTF-8, empty string for absent prev_hash / event_kind.
    let content = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        previous_hash.unwrap_or(""),
        caller,
        request_type,
        event_kind.map(|k| k.to_string()).unwrap_or_default(),
        decision,
        timestamp,
        was_automatic,
    );
    hex::encode(hmac_sha256(hmac_key, content.as_bytes()))
}

/// Compute the keyed-HMAC chain hash for one audit entry. The hex output links
/// the next entry's `previous_hash`.
#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn nip55_audit_entry_hash(
    previous_hash: Option<String>,
    caller: String,
    request_type: String,
    event_kind: Option<i32>,
    decision: String,
    timestamp: i64,
    was_automatic: bool,
    hmac_key: Vec<u8>,
) -> String {
    audit_entry_hash_inner(
        previous_hash.as_deref(),
        &caller,
        &request_type,
        event_kind,
        &decision,
        timestamp,
        was_automatic,
        &hmac_key,
    )
}

/// Constant-time string compare (length check then XOR-accumulate), matching the
/// Android `constantTimeEquals` used on hash values.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn ct_eq_opt(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => ct_eq(x, y),
        _ => false,
    }
}

/// Verify the ordered audit chain with the keyed HMAC. Faithful port of
/// keep-android `PermissionStore.verifyAuditChain`: tolerates a leading run of
/// pre-chain legacy rows (empty hashes), detects a truncated head, a broken
/// `previous_hash` link, and a tampered entry whose recomputed hash differs.
#[uniffi::export]
pub fn nip55_verify_audit_chain(
    entries: Vec<Nip55AuditEntry>,
    hmac_key: Vec<u8>,
) -> Nip55ChainStatus {
    use std::collections::HashSet;

    let known_hashes: HashSet<&str> = entries
        .iter()
        .map(|e| e.entry_hash.as_str())
        .filter(|h| !h.is_empty())
        .collect();

    let mut in_legacy = true;
    let mut legacy_skipped: u32 = 0;
    let mut truncated = false;
    let mut expected_prev: Option<String> = None;

    for entry in &entries {
        if in_legacy {
            if entry.entry_hash.is_empty() {
                legacy_skipped += 1;
                continue;
            }
            in_legacy = false;
            if let Some(prev) = entry.previous_hash.as_deref() {
                if !prev.is_empty() {
                    if !known_hashes.contains(prev) {
                        truncated = true;
                    } else {
                        return Nip55ChainStatus::Broken { entry_id: entry.id };
                    }
                }
            }
        } else {
            if entry.entry_hash.is_empty() {
                return Nip55ChainStatus::Broken { entry_id: entry.id };
            }
            if !ct_eq_opt(entry.previous_hash.as_deref(), expected_prev.as_deref()) {
                return Nip55ChainStatus::Broken { entry_id: entry.id };
            }
        }

        let calculated = audit_entry_hash_inner(
            entry.previous_hash.as_deref(),
            &entry.caller,
            &entry.request_type,
            entry.event_kind,
            &entry.decision,
            entry.timestamp,
            entry.was_automatic,
            &hmac_key,
        );
        if !ct_eq(&calculated, &entry.entry_hash) {
            return Nip55ChainStatus::Tampered { entry_id: entry.id };
        }

        expected_prev = Some(entry.entry_hash.clone());
    }

    if truncated {
        let head_id = entries
            .iter()
            .find(|e| !e.entry_hash.is_empty())
            .map(|e| e.id)
            .unwrap_or(0);
        Nip55ChainStatus::Truncated { entry_id: head_id }
    } else if legacy_skipped > 0 {
        Nip55ChainStatus::PartiallyVerified {
            legacy_entries_skipped: legacy_skipped,
        }
    } else {
        Nip55ChainStatus::Valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-audit-hmac-key-0123456789ab";

    fn entry(
        id: i64,
        prev: Option<&str>,
        caller: &str,
        kind: Option<i32>,
        decision: &str,
        ts: i64,
        auto: bool,
    ) -> Nip55AuditEntry {
        let hash = audit_entry_hash_inner(prev, caller, "SIGN_EVENT", kind, decision, ts, auto, KEY);
        Nip55AuditEntry {
            id,
            timestamp: ts,
            caller: caller.to_string(),
            request_type: "SIGN_EVENT".to_string(),
            event_kind: kind,
            decision: decision.to_string(),
            was_automatic: auto,
            previous_hash: prev.map(|s| s.to_string()),
            entry_hash: hash,
        }
    }

    #[test]
    fn hash_matches_exact_kotlin_serialization() {
        // Locks the pipe-delimited content format: empty prev, kind -1, decimal ts,
        // "true"/"false". Independent HMAC over the literal must equal the function.
        let got = nip55_audit_entry_hash(
            None,
            "com.app".into(),
            "SIGN_EVENT".into(),
            Some(-1),
            "allow".into(),
            1_700_000_000_000,
            true,
            KEY.to_vec(),
        );
        let literal = "|com.app|SIGN_EVENT|-1|allow|1700000000000|true";
        let expected = hex::encode(hmac_sha256(KEY, literal.as_bytes()));
        assert_eq!(got, expected);
    }

    #[test]
    fn absent_event_kind_is_empty_segment() {
        let got = nip55_audit_entry_hash(
            Some("ab".into()),
            "c".into(),
            "GET_PUBLIC_KEY".into(),
            None,
            "deny".into(),
            5,
            false,
            KEY.to_vec(),
        );
        let literal = "ab|c|GET_PUBLIC_KEY||deny|5|false";
        assert_eq!(got, hex::encode(hmac_sha256(KEY, literal.as_bytes())));
    }

    #[test]
    fn valid_chain_verifies() {
        let e1 = entry(1, None, "com.app", Some(1), "allow", 100, false);
        let e2 = entry(2, Some(&e1.entry_hash), "com.app", Some(1), "allow", 200, true);
        assert_eq!(
            nip55_verify_audit_chain(vec![e1, e2], KEY.to_vec()),
            Nip55ChainStatus::Valid
        );
    }

    #[test]
    fn empty_chain_is_valid() {
        assert_eq!(
            nip55_verify_audit_chain(vec![], KEY.to_vec()),
            Nip55ChainStatus::Valid
        );
    }

    #[test]
    fn tampered_entry_detected() {
        let e1 = entry(1, None, "com.app", Some(1), "allow", 100, false);
        let mut e2 = entry(2, Some(&e1.entry_hash), "com.app", Some(1), "allow", 200, true);
        // Flip a field but keep the (now-stale) hash -> recompute mismatches.
        e2.decision = "deny".to_string();
        assert_eq!(
            nip55_verify_audit_chain(vec![e1, e2], KEY.to_vec()),
            Nip55ChainStatus::Tampered { entry_id: 2 }
        );
    }

    #[test]
    fn broken_link_detected() {
        let e1 = entry(1, None, "com.app", Some(1), "allow", 100, false);
        // e2 points its previous_hash at the wrong value.
        let e2 = entry(2, Some("deadbeef"), "com.app", Some(1), "allow", 200, true);
        assert_eq!(
            nip55_verify_audit_chain(vec![e1, e2], KEY.to_vec()),
            Nip55ChainStatus::Broken { entry_id: 2 }
        );
    }

    #[test]
    fn leading_legacy_rows_partially_verified() {
        let legacy = Nip55AuditEntry {
            id: 1,
            timestamp: 1,
            caller: "old".into(),
            request_type: "SIGN_EVENT".into(),
            event_kind: None,
            decision: "allow".into(),
            was_automatic: false,
            previous_hash: None,
            entry_hash: String::new(),
        };
        let e2 = entry(2, None, "com.app", Some(1), "allow", 200, false);
        let e3 = entry(3, Some(&e2.entry_hash), "com.app", Some(1), "allow", 300, false);
        assert_eq!(
            nip55_verify_audit_chain(vec![legacy, e2, e3], KEY.to_vec()),
            Nip55ChainStatus::PartiallyVerified {
                legacy_entries_skipped: 1
            }
        );
    }

    #[test]
    fn truncated_head_detected() {
        // First non-empty entry references a prev hash not present in the set.
        let e2 = entry(2, Some("00ff00ff"), "com.app", Some(1), "allow", 200, false);
        let e3 = entry(3, Some(&e2.entry_hash), "com.app", Some(1), "allow", 300, false);
        assert_eq!(
            nip55_verify_audit_chain(vec![e2, e3], KEY.to_vec()),
            Nip55ChainStatus::Truncated { entry_id: 2 }
        );
    }
}
