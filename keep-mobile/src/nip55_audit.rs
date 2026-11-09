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
    /// Identifies the request a row belongs to, so a later row can name it.
    /// 32 lowercase hex characters, or `None` for rows that carry no id.
    pub request_id: Option<String>,
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
    request_id: Option<&str>,
    hmac_key: &[u8],
) -> String {
    // Must match keep-android `PermissionStore.calculateEntryHash` byte-for-byte:
    // pipe-delimited UTF-8, empty string for absent prev_hash / event_kind.
    //
    // Trust boundary & serialization safety (see #802): tamper-evidence rests
    // entirely on `hmac_key` -- a Keystore-held secret an attacker with audit-DB
    // write access cannot read -- NOT on the row's database id. The row `id` is a
    // local ordering/display value and is deliberately absent from this pre-image;
    // chain POSITION is authenticated instead by `previous_hash` linking each
    // entry to its predecessor's `entry_hash`. The `|` delimiter needs no escaping
    // because no field can contain it: `previous_hash` is hex, `event_kind` and
    // `timestamp` are integers, `was_automatic` is a bool, `request_type` and
    // `decision` are closed enums, and `caller` is either the reserved `"self"`
    // sentinel or a runtime-VERIFIED Android package name (charset [A-Za-z0-9_.],
    // via `Nip55ContentProvider.getVerifiedCaller`). A length-prefixed (TLV)
    // framing would be more robust in the abstract but is a coordinated
    // keep-android byte-format change + row migration, unnecessary given these
    // field domains.
    //
    // A request id is appended as an eighth segment only when present, so rows
    // without one hash exactly as before. It is lowercase hex, and the seventh
    // segment is "true" or "false", so neither can absorb the extra delimiter.
    let mut content = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        previous_hash.unwrap_or(""),
        caller,
        request_type,
        event_kind.map(|k| k.to_string()).unwrap_or_default(),
        decision,
        timestamp,
        was_automatic,
    );
    if let Some(id) = request_id {
        content.push('|');
        content.push_str(id);
    }
    hex::encode(hmac_sha256(hmac_key, content.as_bytes()))
}

fn is_request_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
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
    request_id: Option<String>,
    hmac_key: Vec<u8>,
) -> String {
    // Fail closed on a missing key, matching keep-android `calculateEntryHash`
    // (`?: throw IllegalStateException("HMAC key not initialized ...")`). Without
    // this an empty key silently yields a key-independent, forgeable MAC.
    let hmac_key = zeroize::Zeroizing::new(hmac_key);
    assert!(
        !hmac_key.is_empty(),
        "HMAC key not initialized - cannot compute audit entry hash"
    );
    assert!(
        request_id.as_deref().is_none_or(is_request_id),
        "audit request id must be 32 lowercase hex characters"
    );
    audit_entry_hash_inner(
        previous_hash.as_deref(),
        &caller,
        &request_type,
        event_kind,
        &decision,
        timestamp,
        was_automatic,
        request_id.as_deref(),
        hmac_key.as_slice(),
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
    let verifier = Nip55AuditChainVerifier::new(hmac_key);
    verifier.feed(entries);
    verifier.finish(None)
}

// A legitimate log has at most a small run of leading empty-hash ("legacy") rows,
// from the pre-hash-chain migration (v0.1.0..v0.4.0 rows, the oldest, and time-pruned
// at 30 days). Bound that run so an attacker with audit-DB write access cannot prepend
// an unbounded number of unauthenticated leading rows to mask the genesis or downgrade
// the verdict. The bound is generous (no real early-adopter chain approaches it) so it
// never false-flags a legitimate legacy prefix; exceeding it is treated as tampering.
const MAX_LEADING_LEGACY: u32 = 1024;

/// The first chained entry. A `previous_hash` on it names a predecessor the
/// log no longer holds (a truncated head), unless some entry in the log has
/// that hash, which means the rows are out of order (a broken link). Only the
/// whole log can tell the two apart, so the verdict waits for `finish`.
struct ChainHead {
    id: i64,
    previous_hash: Option<String>,
    previous_hash_seen: bool,
}

struct ChainState {
    in_legacy: bool,
    legacy_skipped: u32,
    head: Option<ChainHead>,
    failure: Option<Nip55ChainStatus>,
    expected_prev: Option<String>,
    chained_count: u64,
    last_chained: Option<(i64, String)>,
}

/// Verifies the audit chain a page at a time, so the log never has to be held
/// in memory at once. Feed every row in id order, in as many pages as needed,
/// then call `finish`. The verdict is the one `nip55_verify_audit_chain_with_tip`
/// gives for the same rows in one list.
///
/// Every page and the expected tip MAC must come from one consistent snapshot
/// (one read transaction). A row appended or pruned between pages can read as
/// a truncated or broken chain, or go unnoticed, so a verdict over pages from
/// different snapshots says nothing. Page by id (`id > last id`), not by offset, stop
/// only on an empty page, and treat a failed read as a failed verification: a
/// page left out at the tail goes unnoticed without a tip MAC. The object holds
/// the HMAC key until it is closed, so close it when done.
#[derive(uniffi::Object)]
pub struct Nip55AuditChainVerifier {
    hmac_key: zeroize::Zeroizing<Vec<u8>>,
    state: std::sync::Mutex<ChainState>,
}

#[uniffi::export]
impl Nip55AuditChainVerifier {
    #[uniffi::constructor]
    pub fn new(hmac_key: Vec<u8>) -> Self {
        // Fail closed on a missing key, matching keep-android `verifyAuditChain`.
        assert!(
            !hmac_key.is_empty(),
            "HMAC key not initialized - cannot verify audit chain"
        );
        Self {
            hmac_key: zeroize::Zeroizing::new(hmac_key),
            state: std::sync::Mutex::new(ChainState {
                in_legacy: true,
                legacy_skipped: 0,
                head: None,
                failure: None,
                expected_prev: None,
                chained_count: 0,
                last_chained: None,
            }),
        }
    }

    /// The next rows of the log, continuing in id order from the last page.
    pub fn feed(&self, entries: Vec<Nip55AuditEntry>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        for entry in &entries {
            state.step(entry, &self.hmac_key);
        }
    }

    /// The verdict for every row fed so far. With `expected_tip_mac`, an
    /// otherwise intact chain is also checked against its separately stored
    /// tip record, as in `nip55_verify_audit_chain_with_tip`.
    pub fn finish(&self, expected_tip_mac: Option<String>) -> Nip55ChainStatus {
        // A feed that panicked part way left a row counted but unchecked.
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let state = poisoned.into_inner();
                return Nip55ChainStatus::Broken {
                    entry_id: state.last_chained.as_ref().map_or(0, |(id, _)| *id),
                };
            }
        };
        if let Some(head) = &state.head {
            if head.previous_hash_seen {
                return Nip55ChainStatus::Broken { entry_id: head.id };
            }
        }
        if let Some(failure) = &state.failure {
            return failure.clone();
        }
        if let Some(head) = &state.head {
            if head.previous_hash.is_some() {
                return Nip55ChainStatus::Truncated { entry_id: head.id };
            }
        }
        let base = if state.legacy_skipped > 0 {
            Nip55ChainStatus::PartiallyVerified {
                legacy_entries_skipped: state.legacy_skipped,
            }
        } else {
            Nip55ChainStatus::Valid
        };
        let Some(expected) = expected_tip_mac else {
            return base;
        };
        let actual = nip55_audit_tip_mac(
            state.chained_count,
            state.last_chained.as_ref().map(|(_, hash)| hash.clone()),
            self.hmac_key.to_vec(),
        );
        if ct_eq(&actual, &expected) {
            base
        } else {
            Nip55ChainStatus::Truncated {
                entry_id: state.last_chained.as_ref().map_or(0, |(id, _)| *id),
            }
        }
    }
}

impl ChainState {
    fn step(&mut self, entry: &Nip55AuditEntry, hmac_key: &[u8]) {
        if !entry.entry_hash.is_empty() {
            if let Some(head) = &mut self.head {
                if head.previous_hash.as_deref() == Some(entry.entry_hash.as_str()) {
                    head.previous_hash_seen = true;
                }
            }
            self.chained_count += 1;
            self.last_chained = Some((entry.id, entry.entry_hash.clone()));
        }
        if self.failure.is_none() {
            if let Err(failure) = self.check(entry, hmac_key) {
                self.failure = Some(failure);
            }
        }
    }

    fn check(&mut self, entry: &Nip55AuditEntry, hmac_key: &[u8]) -> Result<(), Nip55ChainStatus> {
        let tampered = Nip55ChainStatus::Tampered { entry_id: entry.id };
        let broken = Nip55ChainStatus::Broken { entry_id: entry.id };
        if self.in_legacy {
            if entry.entry_hash.is_empty() {
                // Legacy rows predate request ids, so one that carries an id
                // was written by someone without the key.
                if entry.request_id.is_some() {
                    return Err(tampered);
                }
                self.legacy_skipped += 1;
                if self.legacy_skipped > MAX_LEADING_LEGACY {
                    return Err(tampered);
                }
                return Ok(());
            }
            self.in_legacy = false;
            let previous_hash = entry.previous_hash.clone().filter(|p| !p.is_empty());
            self.head = Some(ChainHead {
                id: entry.id,
                previous_hash_seen: previous_hash.as_deref() == Some(entry.entry_hash.as_str()),
                previous_hash,
            });
        } else {
            if entry.entry_hash.is_empty() {
                return Err(broken);
            }
            if !ct_eq_opt(
                entry.previous_hash.as_deref(),
                self.expected_prev.as_deref(),
            ) {
                return Err(broken);
            }
        }

        if !entry.request_id.as_deref().is_none_or(is_request_id) {
            return Err(tampered);
        }
        let calculated = audit_entry_hash_inner(
            entry.previous_hash.as_deref(),
            &entry.caller,
            &entry.request_type,
            entry.event_kind,
            &entry.decision,
            entry.timestamp,
            entry.was_automatic,
            entry.request_id.as_deref(),
            hmac_key,
        );
        if !ct_eq(&calculated, &entry.entry_hash) {
            return Err(tampered);
        }
        self.expected_prev = Some(entry.entry_hash.clone());
        Ok(())
    }
}

/// Domain tag prefixing the tip MAC content so, even sharing the per-app HMAC
/// key with the per-entry chain hash, the two message types can never collide.
const TIP_MAC_DOMAIN: &str = "nip55-audit-tip-v1";

/// Authenticate the audit chain's tip: `count` is the number of **chained**
/// (non-legacy, non-empty-hash) entries and `last_entry_hash` is the last such
/// entry's hash (`None` for an empty/all-legacy log). This MAC is persisted
/// **separately** from the log (a keystore slot the log table cannot reach). The
/// backward-link chain alone cannot detect deleting the newest rows (the
/// remaining prefix stays perfectly linked) or wiping the whole log (an empty
/// log verifies as valid); comparing the log's current `(count, last_hash)`
/// against this independently stored MAC catches both.
///
/// The caller must compute `count`/`last_entry_hash` over the same chained-entry
/// set the verifier uses (see [`nip55_verify_audit_chain_with_tip`]), and must
/// store this MAC confidentially and rollback-resistantly: this construction
/// binds the current tip but has no epoch, so replaying an older leaked tip MAC
/// alongside a log truncated to that earlier length would still validate.
#[uniffi::export]
pub fn nip55_audit_tip_mac(
    count: u64,
    last_entry_hash: Option<String>,
    hmac_key: Vec<u8>,
) -> String {
    assert!(
        !hmac_key.is_empty(),
        "HMAC key not initialized - cannot compute audit tip MAC"
    );
    let hmac_key = zeroize::Zeroizing::new(hmac_key);
    // Domain tag + count binding: `|` cannot appear in the decimal count or the
    // hex hash, so the encoding is unambiguous and cannot collide with the
    // 6- or 7-pipe per-entry content even under the shared key.
    let content = format!(
        "{}|{}|{}",
        TIP_MAC_DOMAIN,
        count,
        last_entry_hash.unwrap_or_default()
    );
    hex::encode(hmac_sha256(hmac_key.as_slice(), content.as_bytes()))
}

/// Verify the audit chain and its separately-stored tip record. Runs the same
/// link/hash verification as [`nip55_verify_audit_chain`], then, when an
/// `expected_tip_mac` is supplied, recomputes the tip MAC from the log's current
/// chained-entry count and last hash and compares it constant-time. A mismatch
/// means the newest rows were removed (tail truncation) or the log was wiped —
/// reported as `Truncated`. `expected_tip_mac == None` means no tip record has
/// been written yet (pre-adoption), so the tip check is skipped.
#[uniffi::export]
pub fn nip55_verify_audit_chain_with_tip(
    entries: Vec<Nip55AuditEntry>,
    hmac_key: Vec<u8>,
    expected_tip_mac: Option<String>,
) -> Nip55ChainStatus {
    let verifier = Nip55AuditChainVerifier::new(hmac_key);
    verifier.feed(entries);
    verifier.finish(expected_tip_mac)
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
        let hash = audit_entry_hash_inner(
            prev,
            caller,
            "SIGN_EVENT",
            kind,
            decision,
            ts,
            auto,
            None,
            KEY,
        );
        Nip55AuditEntry {
            id,
            timestamp: ts,
            caller: caller.to_string(),
            request_type: "SIGN_EVENT".to_string(),
            event_kind: kind,
            decision: decision.to_string(),
            was_automatic: auto,
            request_id: None,
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
            None,
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
            None,
            KEY.to_vec(),
        );
        let literal = "ab|c|GET_PUBLIC_KEY||deny|5|false";
        assert_eq!(got, hex::encode(hmac_sha256(KEY, literal.as_bytes())));
    }

    const REQUEST: &str = "0123456789abcdef0123456789abcdef";

    fn with_request(prev: Option<&str>, id: i64, request_id: &str) -> Nip55AuditEntry {
        let mut e = entry(id, prev, "com.app", Some(1), "allow", 100 + id, true);
        e.request_id = Some(request_id.into());
        e.entry_hash = audit_entry_hash_inner(
            prev,
            "com.app",
            "SIGN_EVENT",
            Some(1),
            "allow",
            100 + id,
            true,
            Some(request_id),
            KEY,
        );
        e
    }

    #[test]
    fn a_request_id_is_an_eighth_segment() {
        let got = nip55_audit_entry_hash(
            None,
            "com.app".into(),
            "SIGN_EVENT".into(),
            Some(1),
            "abandoned".into(),
            5,
            true,
            Some(REQUEST.into()),
            KEY.to_vec(),
        );
        let literal = format!("|com.app|SIGN_EVENT|1|abandoned|5|true|{REQUEST}");
        assert_eq!(got, hex::encode(hmac_sha256(KEY, literal.as_bytes())));
    }

    #[test]
    fn a_malformed_request_id_is_not_hashed() {
        for bad in [
            format!("{REQUEST}|x"),
            REQUEST.to_ascii_uppercase(),
            REQUEST[1..].to_string(),
            String::new(),
        ] {
            let hashed = std::panic::catch_unwind(|| {
                nip55_audit_entry_hash(
                    None,
                    "com.app".into(),
                    "SIGN_EVENT".into(),
                    Some(1),
                    "allow".into(),
                    5,
                    true,
                    Some(bad.clone()),
                    KEY.to_vec(),
                )
            });
            assert!(hashed.is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_legacy_row_carrying_a_request_id_is_tampered() {
        let mut legacy = legacy_entry(1);
        legacy.request_id = Some(REQUEST.into());
        let e2 = entry(2, None, "com.app", Some(1), "allow", 200, false);
        assert_eq!(
            nip55_verify_audit_chain(vec![legacy, e2], KEY.to_vec()),
            Nip55ChainStatus::Tampered { entry_id: 1 }
        );
    }

    #[test]
    fn a_tip_anchored_chain_ending_in_a_request_id_verifies() {
        let e1 = entry(1, None, "com.app", Some(1), "allow", 100, false);
        let e2 = with_request(Some(&e1.entry_hash), 2, REQUEST);
        let entries = vec![e1, e2];
        let tip = tip_of(&entries);
        assert_eq!(
            nip55_verify_audit_chain_with_tip(entries, KEY.to_vec(), Some(tip)),
            Nip55ChainStatus::Valid
        );
    }

    #[test]
    fn a_request_id_is_covered_by_the_chain() {
        let e1 = entry(1, None, "com.app", Some(1), "allow", 100, false);
        let e2 = with_request(Some(&e1.entry_hash), 2, REQUEST);
        let e3 = entry(
            3,
            Some(&e2.entry_hash),
            "com.app",
            Some(1),
            "allow",
            300,
            false,
        );
        let intact = vec![e1, e2, e3];
        assert_eq!(
            nip55_verify_audit_chain(intact.clone(), KEY.to_vec()),
            Nip55ChainStatus::Valid
        );

        let other = "fedcba9876543210fedcba9876543210";
        for (case, request_id) in [
            ("re-pointed", Some(other.to_string())),
            ("removed", None),
            ("uppercased", Some(REQUEST.to_ascii_uppercase())),
            ("delimiter", Some(format!("{}|", &REQUEST[1..]))),
            ("empty", Some(String::new())),
        ] {
            let mut rows = intact.clone();
            rows[1].request_id = request_id;
            assert_eq!(
                nip55_verify_audit_chain(rows, KEY.to_vec()),
                Nip55ChainStatus::Tampered { entry_id: 2 },
                "{case}"
            );
        }
        let mut added = intact;
        added[2].request_id = Some(REQUEST.into());
        assert_eq!(
            nip55_verify_audit_chain(added, KEY.to_vec()),
            Nip55ChainStatus::Tampered { entry_id: 3 }
        );
    }

    #[test]
    fn valid_chain_verifies() {
        let e1 = entry(1, None, "com.app", Some(1), "allow", 100, false);
        let e2 = entry(
            2,
            Some(&e1.entry_hash),
            "com.app",
            Some(1),
            "allow",
            200,
            true,
        );
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

    fn chain(n: usize) -> Vec<Nip55AuditEntry> {
        let mut out = Vec::new();
        let mut prev: Option<String> = None;
        for i in 0..n {
            let e = entry(
                i as i64 + 1,
                prev.as_deref(),
                "com.app",
                Some(1),
                "allow",
                100 + i as i64,
                false,
            );
            prev = Some(e.entry_hash.clone());
            out.push(e);
        }
        out
    }

    fn tip_of(entries: &[Nip55AuditEntry]) -> String {
        let chained: Vec<&Nip55AuditEntry> = entries
            .iter()
            .filter(|e| !e.entry_hash.is_empty())
            .collect();
        nip55_audit_tip_mac(
            chained.len() as u64,
            chained.last().map(|e| e.entry_hash.clone()),
            KEY.to_vec(),
        )
    }

    #[test]
    fn tip_verifies_intact_chain() {
        let c = chain(3);
        let tip = tip_of(&c);
        assert_eq!(
            nip55_verify_audit_chain_with_tip(c, KEY.to_vec(), Some(tip)),
            Nip55ChainStatus::Valid
        );
    }

    #[test]
    fn tip_detects_tail_truncation() {
        let full = chain(3);
        let tip = tip_of(&full); // records 3 entries
        let truncated: Vec<_> = full.into_iter().take(2).collect(); // delete the newest
                                                                    // The link chain alone still says Valid (the bug); the tip catches it.
        assert_eq!(
            nip55_verify_audit_chain(truncated.clone(), KEY.to_vec()),
            Nip55ChainStatus::Valid
        );
        assert!(matches!(
            nip55_verify_audit_chain_with_tip(truncated, KEY.to_vec(), Some(tip)),
            Nip55ChainStatus::Truncated { .. }
        ));
    }

    #[test]
    fn tip_detects_full_deletion() {
        let tip = tip_of(&chain(2));
        // An empty log verifies as Valid on its own (the bug); the tip catches it.
        assert_eq!(
            nip55_verify_audit_chain(vec![], KEY.to_vec()),
            Nip55ChainStatus::Valid
        );
        assert!(matches!(
            nip55_verify_audit_chain_with_tip(vec![], KEY.to_vec(), Some(tip)),
            Nip55ChainStatus::Truncated { .. }
        ));
    }

    #[test]
    fn tip_none_skips_check() {
        assert_eq!(
            nip55_verify_audit_chain_with_tip(chain(2), KEY.to_vec(), None),
            Nip55ChainStatus::Valid
        );
    }

    #[test]
    fn tip_mac_binds_count_and_last_hash() {
        let h = Some("abcd".to_string());
        assert_ne!(
            nip55_audit_tip_mac(2, h.clone(), KEY.to_vec()),
            nip55_audit_tip_mac(3, h.clone(), KEY.to_vec())
        );
        assert_ne!(
            nip55_audit_tip_mac(2, h, KEY.to_vec()),
            nip55_audit_tip_mac(2, Some("ffff".to_string()), KEY.to_vec())
        );
    }

    #[test]
    fn tampered_entry_detected() {
        let e1 = entry(1, None, "com.app", Some(1), "allow", 100, false);
        let mut e2 = entry(
            2,
            Some(&e1.entry_hash),
            "com.app",
            Some(1),
            "allow",
            200,
            true,
        );
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
            request_id: None,
            previous_hash: None,
            entry_hash: String::new(),
        };
        let e2 = entry(2, None, "com.app", Some(1), "allow", 200, false);
        let e3 = entry(
            3,
            Some(&e2.entry_hash),
            "com.app",
            Some(1),
            "allow",
            300,
            false,
        );
        assert_eq!(
            nip55_verify_audit_chain(vec![legacy, e2, e3], KEY.to_vec()),
            Nip55ChainStatus::PartiallyVerified {
                legacy_entries_skipped: 1
            }
        );
    }

    fn legacy_entry(id: i64) -> Nip55AuditEntry {
        Nip55AuditEntry {
            id,
            timestamp: id,
            caller: "old".to_string(),
            request_type: "SIGN_EVENT".to_string(),
            event_kind: None,
            decision: "allow".to_string(),
            was_automatic: false,
            request_id: None,
            previous_hash: None,
            entry_hash: String::new(),
        }
    }

    #[test]
    fn leading_legacy_at_cap_still_partial() {
        // Exactly MAX_LEADING_LEGACY (1024) legacy rows + a valid tail stays
        // PartiallyVerified: a legitimate (if large) pre-hash-chain prefix is not flagged.
        let mut entries: Vec<Nip55AuditEntry> = (1..=1024).map(legacy_entry).collect();
        entries.push(entry(2000, None, "com.app", Some(1), "allow", 5000, false));
        assert_eq!(
            nip55_verify_audit_chain(entries, KEY.to_vec()),
            Nip55ChainStatus::PartiallyVerified {
                legacy_entries_skipped: 1024
            }
        );
    }

    #[test]
    fn leading_legacy_over_cap_is_tampered() {
        // One row past the cap trips before the tail is reached, so a prepended-blank-row
        // downgrade/injection is bounded rather than unbounded.
        let mut entries: Vec<Nip55AuditEntry> = (1..=1025).map(legacy_entry).collect();
        entries.push(entry(2000, None, "com.app", Some(1), "allow", 5000, false));
        assert_eq!(
            nip55_verify_audit_chain(entries, KEY.to_vec()),
            Nip55ChainStatus::Tampered { entry_id: 1025 }
        );
    }

    #[test]
    fn all_legacy_over_cap_is_tampered() {
        // An all-empty-hash log past the cap is tampering, not Valid/PartiallyVerified.
        let entries: Vec<Nip55AuditEntry> = (1..=1025).map(legacy_entry).collect();
        assert_eq!(
            nip55_verify_audit_chain(entries, KEY.to_vec()),
            Nip55ChainStatus::Tampered { entry_id: 1025 }
        );
    }

    #[test]
    fn small_legacy_prefix_still_partial() {
        // A small legacy-only log (early adopter, no post-upgrade activity) is unaffected.
        let entries: Vec<Nip55AuditEntry> = (1..=10).map(legacy_entry).collect();
        assert_eq!(
            nip55_verify_audit_chain(entries, KEY.to_vec()),
            Nip55ChainStatus::PartiallyVerified {
                legacy_entries_skipped: 10
            }
        );
    }

    #[test]
    fn tip_path_inherits_legacy_cap() {
        // The tip-MAC entry point delegates to the base verifier, so a conclusive base
        // Tampered (from the cap) short-circuits and is returned as-is.
        let mut entries: Vec<Nip55AuditEntry> = (1..=1025).map(legacy_entry).collect();
        entries.push(entry(2000, None, "com.app", Some(1), "allow", 5000, false));
        let tip = tip_of(&entries);
        assert_eq!(
            nip55_verify_audit_chain_with_tip(entries, KEY.to_vec(), Some(tip)),
            Nip55ChainStatus::Tampered { entry_id: 1025 }
        );
    }

    #[test]
    #[should_panic(expected = "HMAC key not initialized")]
    fn empty_key_rejected_on_hash() {
        nip55_audit_entry_hash(
            None,
            "com.app".into(),
            "SIGN_EVENT".into(),
            Some(1),
            "allow".into(),
            100,
            false,
            None,
            Vec::new(),
        );
    }

    #[test]
    #[should_panic(expected = "HMAC key not initialized")]
    fn empty_key_rejected_on_verify() {
        let e1 = entry(1, None, "com.app", Some(1), "allow", 100, false);
        nip55_verify_audit_chain(vec![e1], Vec::new());
    }

    #[test]
    fn truncated_head_detected() {
        // First non-empty entry references a prev hash not present in the set.
        let e2 = entry(2, Some("00ff00ff"), "com.app", Some(1), "allow", 200, false);
        let e3 = entry(
            3,
            Some(&e2.entry_hash),
            "com.app",
            Some(1),
            "allow",
            300,
            false,
        );
        assert_eq!(
            nip55_verify_audit_chain(vec![e2, e3], KEY.to_vec()),
            Nip55ChainStatus::Truncated { entry_id: 2 }
        );
    }

    // The one-list verifier as it was before the paged one replaced it, kept
    // to prove the paged verifier gives the same verdict.
    fn reference_verify(entries: Vec<Nip55AuditEntry>, hmac_key: Vec<u8>) -> Nip55ChainStatus {
        use std::collections::HashSet;

        // Fail closed on a missing key, matching keep-android `verifyAuditChain`.
        assert!(
            !hmac_key.is_empty(),
            "HMAC key not initialized - cannot verify audit chain"
        );
        let hmac_key = zeroize::Zeroizing::new(hmac_key);

        let known_hashes: HashSet<&str> = entries
            .iter()
            .map(|e| e.entry_hash.as_str())
            .filter(|h| !h.is_empty())
            .collect();

        // A legitimate log has at most a small run of leading empty-hash ("legacy") rows,
        // from the pre-hash-chain migration (v0.1.0..v0.4.0 rows, the oldest, and time-pruned
        // at 30 days). Bound that run so an attacker with audit-DB write access cannot prepend
        // an unbounded number of unauthenticated leading rows to mask the genesis or downgrade
        // the verdict. The bound is generous (no real early-adopter chain approaches it) so it
        // never false-flags a legitimate legacy prefix; exceeding it is treated as tampering.
        const MAX_LEADING_LEGACY: u32 = 1024;

        let mut in_legacy = true;
        let mut legacy_skipped: u32 = 0;
        let mut truncated = false;
        let mut expected_prev: Option<String> = None;

        for entry in &entries {
            if in_legacy {
                if entry.entry_hash.is_empty() {
                    // Legacy rows predate request ids, so one that carries an id
                    // was written by someone without the key.
                    if entry.request_id.is_some() {
                        return Nip55ChainStatus::Tampered { entry_id: entry.id };
                    }
                    legacy_skipped += 1;
                    if legacy_skipped > MAX_LEADING_LEGACY {
                        return Nip55ChainStatus::Tampered { entry_id: entry.id };
                    }
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

            if !entry.request_id.as_deref().is_none_or(is_request_id) {
                return Nip55ChainStatus::Tampered { entry_id: entry.id };
            }
            let calculated = audit_entry_hash_inner(
                entry.previous_hash.as_deref(),
                &entry.caller,
                &entry.request_type,
                entry.event_kind,
                &entry.decision,
                entry.timestamp,
                entry.was_automatic,
                entry.request_id.as_deref(),
                hmac_key.as_slice(),
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

    fn reference_verify_with_tip(
        entries: Vec<Nip55AuditEntry>,
        hmac_key: Vec<u8>,
        expected_tip_mac: Option<String>,
    ) -> Nip55ChainStatus {
        let base = reference_verify(entries.clone(), hmac_key.clone());
        // A link/hash failure is already conclusive; only add the tip check to an
        // otherwise-intact chain.
        match base {
            Nip55ChainStatus::Valid | Nip55ChainStatus::PartiallyVerified { .. } => {}
            other => return other,
        }
        let Some(expected) = expected_tip_mac else {
            return base;
        };

        let chained: Vec<&Nip55AuditEntry> = entries
            .iter()
            .filter(|e| !e.entry_hash.is_empty())
            .collect();
        let count = chained.len() as u64;
        let last_hash = chained.last().map(|e| e.entry_hash.clone());
        let actual = nip55_audit_tip_mac(count, last_hash, hmac_key);
        if ct_eq(&actual, &expected) {
            base
        } else {
            Nip55ChainStatus::Truncated {
                entry_id: chained.last().map(|e| e.id).unwrap_or(0),
            }
        }
    }

    struct Rng(u64);
    impl Rng {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % n as u64) as usize
        }
    }

    fn mutated_log(rng: &mut Rng) -> Vec<Nip55AuditEntry> {
        let mut rows: Vec<Nip55AuditEntry> = (0..rng.below(4))
            .map(|i| legacy_entry(i as i64 - 10))
            .collect();
        let mut prev: Option<String> = None;
        for i in 0..rng.below(8) {
            let e = if rng.below(3) == 0 {
                with_request(prev.as_deref(), i as i64 + 1, REQUEST)
            } else {
                entry(
                    i as i64 + 1,
                    prev.as_deref(),
                    "com.app",
                    Some(1),
                    "allow",
                    100 + i as i64,
                    false,
                )
            };
            prev = Some(e.entry_hash.clone());
            rows.push(e);
        }
        for _ in 0..rng.below(3) {
            if rows.is_empty() {
                break;
            }
            let i = rng.below(rows.len());
            let j = rng.below(rows.len());
            match rng.below(10) {
                0 => {
                    rows.remove(i);
                }
                1 => rows.swap(i, j),
                2 => rows[i].decision = "deny".into(),
                3 => rows[i].previous_hash = Some(rows[j].entry_hash.clone()),
                4 => rows[i].previous_hash = Some("00ff00ff".into()),
                5 => rows[i].entry_hash = String::new(),
                6 => {
                    let dup = rows[i].clone();
                    rows.insert(j, dup);
                }
                7 => rows.insert(i, legacy_entry(0)),
                8 => rows[i].request_id = Some(REQUEST.into()),
                _ => rows[i].previous_hash = None,
            }
        }
        rows
    }

    fn paged(rows: &[Nip55AuditEntry], tip: Option<String>, rng: &mut Rng) -> Nip55ChainStatus {
        let verifier = Nip55AuditChainVerifier::new(KEY.to_vec());
        let mut rest = rows;
        while !rest.is_empty() || rng.below(4) == 0 {
            let take = rng.below(rest.len() + 1);
            verifier.feed(rest[..take].to_vec());
            rest = &rest[take..];
        }
        verifier.finish(tip)
    }

    #[test]
    fn the_paged_verifier_agrees_with_the_one_list_verifier() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20_000 {
            let rows = mutated_log(&mut rng);
            let tip = match rng.below(4) {
                0 => None,
                1 => Some(tip_of(&rows)),
                2 => Some(tip_of(&rows[..rows.len().saturating_sub(1)])),
                _ => Some("00".into()),
            };
            let want = reference_verify_with_tip(rows.clone(), KEY.to_vec(), tip.clone());
            seen.insert(std::mem::discriminant(&want));
            assert_eq!(
                paged(&rows, tip, &mut rng),
                want,
                "{:?}",
                rows.iter().map(|e| e.id).collect::<Vec<_>>()
            );
        }
        assert_eq!(seen.len(), 5, "every verdict should be reached");
    }

    #[test]
    fn the_paged_verifier_agrees_past_the_legacy_cap() {
        for extra in [0, 1] {
            let mut rows: Vec<Nip55AuditEntry> = (0..MAX_LEADING_LEGACY as i64 + extra)
                .map(legacy_entry)
                .collect();
            rows.extend(chain(3));
            let want = reference_verify_with_tip(rows.clone(), KEY.to_vec(), Some(tip_of(&rows)));
            assert_eq!(paged(&rows, Some(tip_of(&rows)), &mut Rng(7)), want);
        }
    }

    #[test]
    fn a_verifier_poisoned_mid_feed_is_not_intact() {
        let verifier = std::sync::Arc::new(Nip55AuditChainVerifier::new(KEY.to_vec()));
        verifier.feed(chain(2));
        let held = std::sync::Arc::clone(&verifier);
        let _ = std::thread::spawn(move || {
            let _guard = held.state.lock().unwrap();
            panic!("feed failed part way");
        })
        .join();
        assert_eq!(
            verifier.finish(None),
            Nip55ChainStatus::Broken { entry_id: 2 }
        );
    }
}
