// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use super::*;
use crate::error::AgentError;
use crate::policy::{BitcoinGrant, Grant};
use crate::scope::Operation;
use keep_core::agent::{AgentCredential, AgentRefusal};
use keep_core::audit::{AuditEntry, AuditEventType};
use keep_core::Keep;

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const KEY: [u8; 32] = [1; 32];
const ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

struct Vault {
    _dir: tempfile::TempDir,
    keep: Keep,
    log: std::path::PathBuf,
}

impl Vault {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keep");
        keep_core::storage::Storage::create(
            &path,
            "testpass",
            keep_core::crypto::Argon2Params::TESTING,
        )
        .unwrap();
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        Self {
            log: path.join("audit.log"),
            _dir: dir,
            keep,
        }
    }

    /// Make the audit log unwritable, or writable again.
    fn break_log(&self, broken: bool) {
        if broken {
            std::fs::rename(&self.log, self.log.with_extension("bak")).unwrap();
            std::fs::create_dir(&self.log).unwrap();
        } else {
            std::fs::remove_dir(&self.log).unwrap();
            std::fs::rename(self.log.with_extension("bak"), &self.log).unwrap();
        }
    }

    fn entries(&self, event: AuditEventType) -> Vec<AuditEntry> {
        self.keep
            .audit_read_all()
            .unwrap()
            .into_iter()
            .filter(|e| e.event_type == event)
            .collect()
    }

    fn reasons(&self, event: AuditEventType) -> Vec<String> {
        self.entries(event)
            .into_iter()
            .filter_map(|e| e.reason)
            .collect()
    }

    fn issue(&mut self, ttl: u64) -> (GrantedCredential, zeroize::Zeroizing<String>) {
        issue_credential(&mut self.keep, "agent", 1000, grant(), NOW, ttl).unwrap()
    }
}

fn grant() -> Grant {
    Grant {
        keys: [KEY].into(),
        operations: [Operation::SignNostrEvent, Operation::SignPsbt].into(),
        event_kinds: [1].into(),
        nip44_peers: Default::default(),
        bitcoin: Some(BitcoinGrant {
            network: keep_bitcoin::Network::Bitcoin,
            per_psbt_sats: 1_000,
            window_sats: 10_000,
            approval_above_sats: None,
            address_allowlist: Some([ADDR.to_string()].into()),
        }),
        limits: Default::default(),
    }
}

#[test]
fn an_issued_grant_comes_back_validated_and_refusals_name_their_credential() {
    let mut v = Vault::new();
    let (issued, token) = v.issue(3600);
    let loaded = authenticate(&v.keep, &token, 1000, NOW).unwrap().unwrap();
    assert_eq!(loaded.grant, grant().validated().unwrap());
    assert_eq!(loaded.credential, issued.credential);
    assert_eq!(
        authenticate(&v.keep, &token, 1001, NOW)
            .unwrap()
            .unwrap_err(),
        Refused {
            because: RefusedBecause::Credential(AgentRefusal::WrongUid),
            credential: Some(issued.credential.id),
        }
    );
    assert_eq!(
        authenticate(&v.keep, &token[1..], 1000, NOW)
            .unwrap()
            .unwrap_err()
            .credential,
        None
    );

    let mut invalid = grant();
    invalid.keys.clear();
    assert!(issue_credential(&mut v.keep, "bad", 1000, invalid, NOW, 3600).is_err());
    assert_eq!(
        v.keep.agent_credentials().unwrap().len(),
        1,
        "nothing issued"
    );

    let (broken, broken_token) = v
        .keep
        .issue_agent_credential("broken", 1000, b"not json".to_vec(), NOW, 3600)
        .unwrap();
    assert_eq!(
        authenticate(&v.keep, &broken_token, 1000, NOW)
            .unwrap()
            .unwrap_err(),
        Refused {
            because: RefusedBecause::Grant,
            credential: Some(broken.id),
        }
    );
}

#[test]
fn a_grant_that_is_not_validated_as_stored_does_not_load() {
    let stored = |bytes: Vec<u8>| {
        let (credential, _) = AgentCredential::issue("agent", 1000, bytes, NOW, 3600).unwrap();
        GrantedCredential::new(credential).unwrap_err().to_string()
    };
    assert!(stored(b"not json".to_vec()).contains("does not decode"));
    let mut extra = serde_json::to_value(grant()).unwrap();
    extra["approver"] = serde_json::json!("x");
    assert!(stored(serde_json::to_vec(&extra).unwrap()).contains("does not decode"));
    let mut invalid = grant();
    invalid.keys.clear();
    assert!(stored(serde_json::to_vec(&invalid).unwrap()).contains("keys"));
    let mut uncanonical = grant();
    uncanonical.bitcoin.as_mut().unwrap().address_allowlist = Some([ADDR.to_uppercase()].into());
    assert!(stored(serde_json::to_vec(&uncanonical).unwrap()).contains("validated form"));
    let (credential, _) = AgentCredential::issue(
        "agent",
        1000,
        serde_json::to_vec(&grant()).unwrap(),
        NOW,
        3600,
    )
    .unwrap();
    assert!(GrantedCredential::new(credential).is_ok());
}

#[test]
fn identical_refusals_collapse_and_different_ones_are_each_recorded() {
    let mut v = Vault::new();
    let mut audit = AgentAudit::default();
    let (a, b) = ([1; 16], [2; 16]);
    let id = hex::encode(a);
    for i in 0..5 {
        audit
            .record_refusal(&mut v.keep, &a, RefusalKind::Denied, "kind 4", NOW + i)
            .unwrap();
    }
    audit
        .record_refusal(&mut v.keep, &a, RefusalKind::Denied, "kind 5", NOW + 5)
        .unwrap();
    audit
        .record_refusal(&mut v.keep, &a, RefusalKind::NeedsApproval, "kind 4", NOW)
        .unwrap();
    audit
        .record_refusal(&mut v.keep, &b, RefusalKind::Denied, "kind 4", NOW)
        .unwrap();
    let refused = v.reasons(AuditEventType::AgentRefused);
    assert_eq!(refused.len(), 4, "{refused:?}");
    assert!(refused.contains(&format!("agent {id} denied \"kind 4\"")));
    assert!(refused.contains(&format!("agent {id} denied \"kind 5\"")));
    assert!(v
        .entries(AuditEventType::AgentRefused)
        .iter()
        .all(|e| !e.success));

    let later = NOW + REFUSAL_WINDOW_SECS;
    audit.flush_expired(&mut v.keep, later).unwrap();
    let refused = v.reasons(AuditEventType::AgentRefused);
    assert!(
        refused.contains(&format!("agent {id} denied x4 more since {NOW} \"kind 4\"")),
        "{refused:?}"
    );
    assert_eq!(
        refused.len(),
        5,
        "windows without repeats add nothing: {refused:?}"
    );

    audit
        .record_refusal(&mut v.keep, &a, RefusalKind::Denied, "kind 4", later)
        .unwrap();
    audit
        .record_refusal(&mut v.keep, &a, RefusalKind::Denied, "kind 4", later)
        .unwrap();
    audit.flush_all(&mut v.keep, later).unwrap();
    assert!(v.reasons(AuditEventType::AgentRefused).contains(&format!(
        "agent {id} denied x1 more since {later} \"kind 4\""
    )));
}

#[test]
fn a_write_that_fails_does_not_spend_the_budget() {
    let mut v = Vault::new();
    let (issued, token) = v.issue(3 * DAY);
    let id = issued.credential.id;
    let mut audit = AgentAudit::with_budgets(3, u32::MAX);
    v.break_log(true);
    for _ in 0..5 {
        assert!(audit
            .record_signature(&mut v.keep, &id, &KEY, b"m", "sign", NOW)
            .is_err());
    }
    v.break_log(false);
    for _ in 0..3 {
        audit
            .record_signature(&mut v.keep, &id, &KEY, b"m", "sign", NOW)
            .unwrap();
    }
    assert!(authenticate(&v.keep, &token, 1000, NOW).unwrap().is_ok());
}

#[test]
fn a_spent_budget_is_recorded_once_and_freezes_the_credential_once() {
    let mut v = Vault::new();
    let (issued, token) = v.issue(3 * DAY);
    let id = issued.credential.id;
    let mut audit = AgentAudit::with_budgets(3, u32::MAX);
    audit
        .record_refusal(&mut v.keep, &id, RefusalKind::Denied, "kind 4", NOW)
        .unwrap();
    audit
        .record_refusal(&mut v.keep, &id, RefusalKind::Denied, "kind 4", NOW)
        .unwrap();
    for i in 0..2 {
        audit
            .record_signature(&mut v.keep, &id, &KEY, b"m", &format!("sign {i}"), NOW)
            .unwrap();
    }
    let signed = v.reasons(AuditEventType::Sign);
    assert!(signed[0].starts_with(&format!("agent {} sign 0", hex::encode(id))));

    for _ in 0..3 {
        assert!(matches!(
            audit.record_signature(&mut v.keep, &id, &KEY, b"m", "over", NOW),
            Err(AgentError::RateLimitExceeded(m)) if m.contains("is frozen")
        ));
    }
    audit.flush_all(&mut v.keep, NOW).unwrap();
    let refused = v.reasons(AuditEventType::AgentRefused);
    assert_eq!(
        refused
            .iter()
            .filter(|r| r.ends_with("audit budget used for today"))
            .count(),
        1,
        "{refused:?}"
    );
    assert!(
        !refused.iter().any(|r| r.contains("more since")),
        "a count over the budget is dropped: {refused:?}"
    );
    assert_eq!(v.entries(AuditEventType::Sign).len(), 2);
    assert_eq!(v.entries(AuditEventType::AgentFreeze).len(), 1);
    assert_eq!(
        authenticate(&v.keep, &token, 1000, NOW)
            .unwrap()
            .unwrap_err()
            .because,
        RefusedBecause::Credential(AgentRefusal::Frozen)
    );

    v.keep.set_agent_credential_frozen(&id, false).unwrap();
    audit.reset(&id);
    audit
        .record_signature(&mut v.keep, &id, &KEY, b"m", "after unfreeze", NOW)
        .unwrap();

    let mut renewed = AgentAudit::with_budgets(1, u32::MAX);
    renewed
        .record_signature(&mut v.keep, &id, &KEY, b"m", "a", NOW)
        .unwrap();
    assert!(renewed
        .record_signature(&mut v.keep, &id, &KEY, b"m", "b", NOW)
        .is_err());
    renewed
        .record_signature(&mut v.keep, &id, &KEY, b"m", "next day", NOW + DAY)
        .unwrap();
    assert_eq!(
        authenticate(&v.keep, &token, 1000, NOW + DAY)
            .unwrap()
            .unwrap_err()
            .because,
        RefusedBecause::Credential(AgentRefusal::Frozen),
        "the budget renews; the freeze stays until the owner lifts it"
    );
}

#[test]
fn the_gateway_budget_spans_credentials_without_freezing_them() {
    let mut v = Vault::new();
    let (first, token) = v.issue(3600);
    let (second, _) = v.issue(3600);
    let (a, b) = (first.credential.id, second.credential.id);
    let mut audit = AgentAudit::with_budgets(u32::MAX, 3);
    audit
        .record_signature(&mut v.keep, &a, &KEY, b"m", "1", NOW)
        .unwrap();
    audit
        .record_signature(&mut v.keep, &b, &KEY, b"m", "2", NOW)
        .unwrap();
    audit
        .record_refusal(&mut v.keep, &a, RefusalKind::Denied, "x", NOW)
        .unwrap();
    for id in [a, b, a] {
        assert!(matches!(
            audit.record_signature(&mut v.keep, &id, &KEY, b"m", "over", NOW),
            Err(AgentError::RateLimitExceeded(m)) if m.contains("gateway")
        ));
    }
    let refused = v.reasons(AuditEventType::AgentRefused);
    assert_eq!(
        refused
            .iter()
            .filter(|r| r.ends_with("gateway audit budget used for today"))
            .count(),
        1
    );
    assert!(refused.contains(&format!(
        "agent {} gateway audit budget used for today",
        hex::encode([0u8; 16])
    )));
    assert!(v.entries(AuditEventType::AgentFreeze).is_empty());
    assert!(authenticate(&v.keep, &token, 1000, NOW).unwrap().is_ok());
    audit
        .record_signature(&mut v.keep, &b, &KEY, b"m", "next day", NOW + DAY)
        .unwrap();
}

#[test]
fn a_flush_that_fails_keeps_its_window() {
    let mut v = Vault::new();
    let mut audit = AgentAudit::default();
    let id = [3; 16];
    for _ in 0..3 {
        audit
            .record_refusal(&mut v.keep, &id, RefusalKind::Denied, "x", NOW)
            .unwrap();
    }
    v.break_log(true);
    assert!(audit
        .flush_expired(&mut v.keep, NOW + REFUSAL_WINDOW_SECS)
        .is_err());
    assert_eq!(audit.open_windows(), 1);
    v.break_log(false);
    audit
        .flush_expired(&mut v.keep, NOW + REFUSAL_WINDOW_SECS)
        .unwrap();
    assert_eq!(audit.open_windows(), 0);
    assert!(v
        .reasons(AuditEventType::AgentRefused)
        .iter()
        .any(|r| r.contains("denied x2 more since")));
}

#[test]
fn open_windows_and_tracked_credentials_are_bounded() {
    let mut v = Vault::new();
    let mut audit = AgentAudit::with_budgets(u32::MAX, u32::MAX);
    let id = |i: u32| {
        let mut id = [0; 16];
        id[..4].copy_from_slice(&i.to_le_bytes());
        id
    };
    for i in 0..1_024 {
        for _ in 0..2 {
            audit
                .record_refusal(&mut v.keep, &id(i), RefusalKind::Denied, "x", NOW)
                .unwrap();
        }
    }
    assert_eq!(v.entries(AuditEventType::AgentRefused).len(), 1_024);
    audit
        .record_refusal(&mut v.keep, &id(1_024), RefusalKind::Denied, "x", NOW)
        .unwrap();
    assert_eq!(audit.open_windows(), 1);
    assert_eq!(
        v.entries(AuditEventType::AgentRefused).len(),
        2 * 1_024 + 1,
        "every open window was written out"
    );

    audit.flush_all(&mut v.keep, NOW).unwrap();
    audit
        .record_refusal(&mut v.keep, &id(5_000), RefusalKind::Denied, "x", NOW + DAY)
        .unwrap();
    assert_eq!(audit.tracked(), 1, "stale budgets are dropped");
}

#[test]
fn a_refusal_or_signature_that_cannot_be_recorded_fails() {
    let mut v = Vault::new();
    let mut audit = AgentAudit::default();
    v.break_log(true);
    assert!(audit
        .record_refusal(&mut v.keep, &[1; 16], RefusalKind::Denied, "x", NOW)
        .is_err());
    assert!(audit
        .record_signature(&mut v.keep, &[1; 16], &KEY, b"m", "x", NOW)
        .is_err());
}

#[test]
fn a_signature_writes_out_refusal_windows_that_have_passed() {
    let mut v = Vault::new();
    let mut audit = AgentAudit::default();
    let id = [4; 16];
    for _ in 0..2 {
        audit
            .record_refusal(&mut v.keep, &id, RefusalKind::Denied, "x", NOW)
            .unwrap();
    }
    audit
        .record_signature(
            &mut v.keep,
            &id,
            &KEY,
            b"m",
            "sign",
            NOW + REFUSAL_WINDOW_SECS,
        )
        .unwrap();
    assert_eq!(audit.open_windows(), 0);
    assert!(v
        .reasons(AuditEventType::AgentRefused)
        .iter()
        .any(|r| r.contains("denied x1 more since")));
}

/// A credential over its own budget is frozen even while the gateway's budget
/// is spent too.
#[test]
fn a_credential_over_budget_is_frozen_when_the_gateway_is_too() {
    let mut v = Vault::new();
    let (issued, token) = v.issue(3600);
    let id = issued.credential.id;
    let mut audit = AgentAudit::with_budgets(1, 1);
    audit
        .record_signature(&mut v.keep, &id, &KEY, b"m", "1", NOW)
        .unwrap();
    assert!(audit
        .record_signature(&mut v.keep, &id, &KEY, b"m", "2", NOW)
        .is_err());
    assert_eq!(
        authenticate(&v.keep, &token, 1000, NOW)
            .unwrap()
            .unwrap_err()
            .because,
        RefusedBecause::Credential(AgentRefusal::Frozen)
    );
}

/// The "budget used" notice is retried until it is written.
#[test]
fn a_budget_notice_that_fails_is_retried() {
    let mut v = Vault::new();
    let (issued, _) = v.issue(3600);
    let id = issued.credential.id;
    let mut audit = AgentAudit::with_budgets(1, u32::MAX);
    audit
        .record_signature(&mut v.keep, &id, &KEY, b"m", "1", NOW)
        .unwrap();
    v.break_log(true);
    assert!(audit
        .record_signature(&mut v.keep, &id, &KEY, b"m", "2", NOW)
        .is_err());
    v.break_log(false);
    assert!(audit
        .record_signature(&mut v.keep, &id, &KEY, b"m", "3", NOW)
        .is_err());
    assert_eq!(
        v.reasons(AuditEventType::AgentRefused)
            .iter()
            .filter(|r| r.ends_with("audit budget used for today"))
            .count(),
        1
    );
}

/// One credential holds a bounded number of open windows; past it, its
/// refusals are written one by one.
#[test]
fn one_credential_holds_a_bounded_number_of_windows() {
    let mut v = Vault::new();
    let mut audit = AgentAudit::with_budgets(u32::MAX, u32::MAX);
    let id = [5; 16];
    for i in 0..40 {
        audit
            .record_refusal(&mut v.keep, &id, RefusalKind::Denied, &format!("d{i}"), NOW)
            .unwrap();
    }
    assert_eq!(audit.open_windows(), 32);
    audit
        .record_refusal(&mut v.keep, &id, RefusalKind::Denied, "d39", NOW)
        .unwrap();
    assert_eq!(v.entries(AuditEventType::AgentRefused).len(), 41);
}

/// Every summary label fits the audit log's label limit, however large the
/// count and time.
#[test]
fn every_summary_label_fits() {
    for kind in [
        RefusalKind::Unauthenticated,
        RefusalKind::Denied,
        RefusalKind::NeedsApproval,
        RefusalKind::RateLimited,
        RefusalKind::Invalid,
    ] {
        let label = format!("{} x{} more since {}", kind.label(), u32::MAX, u64::MAX);
        assert!(keep_core::agent::valid_audit_label(&label), "{label}");
    }
}

/// A counted entry is charged to its credential's budget.
#[test]
fn a_flushed_count_is_charged() {
    let mut v = Vault::new();
    let (issued, _) = v.issue(3600);
    let id = issued.credential.id;
    let mut audit = AgentAudit::with_budgets(2, u32::MAX);
    for _ in 0..2 {
        audit
            .record_refusal(&mut v.keep, &id, RefusalKind::Denied, "kind 4", NOW)
            .unwrap();
    }
    audit
        .flush_expired(&mut v.keep, NOW + REFUSAL_WINDOW_SECS)
        .unwrap();
    assert!(audit
        .record_signature(&mut v.keep, &id, &KEY, b"m", "1", NOW + REFUSAL_WINDOW_SECS)
        .is_err());
}

/// Refusals use at most half the gateway's budget, so signatures keep room.
#[test]
fn refusals_cannot_crowd_out_signatures() {
    let mut v = Vault::new();
    let (issued, _) = v.issue(3600);
    let id = issued.credential.id;
    let mut audit = AgentAudit::with_budgets(u32::MAX, 4);
    for i in 0..2 {
        audit
            .record_refusal(&mut v.keep, &[i; 16], RefusalKind::Denied, "x", NOW)
            .unwrap();
    }
    assert!(audit
        .record_refusal(&mut v.keep, &[9; 16], RefusalKind::Denied, "x", NOW)
        .is_err());
    assert!(audit
        .record_refusal(&mut v.keep, &[9; 16], RefusalKind::Denied, "y", NOW)
        .is_err());
    for n in ["1", "2"] {
        audit
            .record_signature(&mut v.keep, &id, &KEY, b"m", n, NOW)
            .unwrap();
    }
    assert_eq!(
        v.reasons(AuditEventType::AgentRefused)
            .iter()
            .filter(|r| r.ends_with("gateway refusal budget used for today"))
            .count(),
        1
    );
}

/// A credential the budget froze is not frozen again on later days.
#[test]
fn a_frozen_credential_is_frozen_once() {
    let mut v = Vault::new();
    let (issued, _) = v.issue(3 * 24 * 3600);
    let id = issued.credential.id;
    let mut audit = AgentAudit::with_budgets(1, u32::MAX);
    for day in 0..3 {
        let now = NOW + day * 24 * 3600;
        for n in ["1", "2"] {
            let _ = audit.record_signature(&mut v.keep, &id, &KEY, b"m", n, now);
        }
    }
    assert_eq!(v.entries(AuditEventType::AgentFreeze).len(), 1);
}

/// Once its budget froze a credential, its refusals are not written: they
/// would only spend the gateway's refusal budget. The owner's unfreeze lifts
/// that.
#[test]
fn a_credential_its_budget_froze_writes_no_more_refusals() {
    let mut v = Vault::new();
    let (issued, _) = v.issue(3 * DAY);
    let id = issued.credential.id;
    let mut audit = AgentAudit::with_budgets(1, u32::MAX);
    audit
        .record_signature(&mut v.keep, &id, &KEY, b"m", "1", NOW)
        .unwrap();
    assert!(audit
        .record_signature(&mut v.keep, &id, &KEY, b"m", "2", NOW)
        .is_err());
    assert!(audit.froze(&id));
    let before = v.entries(AuditEventType::AgentRefused).len();
    for i in 0..5 {
        audit
            .record_refusal(
                &mut v.keep,
                &id,
                RefusalKind::Unauthenticated,
                &format!("frozen {i}"),
                NOW + DAY + i,
            )
            .unwrap();
    }
    assert_eq!(v.entries(AuditEventType::AgentRefused).len(), before);
    v.keep.set_agent_credential_frozen(&id, false).unwrap();
    audit.reset(&id);
    assert!(!audit.froze(&id));
    audit
        .record_refusal(&mut v.keep, &id, RefusalKind::Denied, "x", NOW + DAY)
        .unwrap();
    assert_eq!(v.entries(AuditEventType::AgentRefused).len(), before + 1);
}

/// Pruning stale budgets keeps the credentials a budget froze, so none is
/// frozen and recorded twice.
#[test]
fn pruning_keeps_credentials_their_budget_froze() {
    let mut v = Vault::new();
    let (issued, _) = v.issue(3 * DAY);
    let id = issued.credential.id;
    let mut audit = AgentAudit::with_budgets(1, u32::MAX);
    audit
        .record_signature(&mut v.keep, &id, &KEY, b"m", "1", NOW)
        .unwrap();
    assert!(audit
        .record_signature(&mut v.keep, &id, &KEY, b"m", "2", NOW)
        .is_err());
    let other = |i: u32| {
        let mut id = [0xee; 16];
        id[..4].copy_from_slice(&i.to_le_bytes());
        id
    };
    for i in 0..300 {
        let _ = audit.record_refusal(
            &mut v.keep,
            &other(i),
            RefusalKind::Denied,
            "x",
            NOW + DAY + 1,
        );
    }
    assert!(audit.froze(&id), "still tracked after the stale prune");
    let later = NOW + 2 * DAY;
    audit
        .record_signature(&mut v.keep, &id, &KEY, b"m", "3", later)
        .unwrap();
    assert!(audit
        .record_signature(&mut v.keep, &id, &KEY, b"m", "4", later)
        .is_err());
    assert_eq!(
        v.entries(AuditEventType::AgentFreeze).len(),
        1,
        "not frozen a second time"
    );
}

/// What a credential was served is recorded and budgeted like a signature,
/// and an over-budget credential is neither served nor admitted.
#[test]
fn served_answers_and_admission_are_budgeted() {
    let mut v = Vault::new();
    let (issued, token) = v.issue(3600);
    let id = issued.credential.id;
    let mut audit = AgentAudit::with_budgets(2, u32::MAX);
    audit.admit(&mut v.keep, &id, NOW).unwrap();
    audit
        .record_served(&mut v.keep, &id, "get_nostr_pubkey", Some("k\n"), NOW)
        .unwrap();
    let served = v.reasons(AuditEventType::AgentServed);
    assert_eq!(
        served,
        [format!(
            "agent {} get_nostr_pubkey \"k\\n\"",
            hex::encode(id)
        )]
    );
    audit
        .record_signature(&mut v.keep, &id, &KEY, b"m", "1", NOW)
        .unwrap();
    assert!(audit
        .record_served(&mut v.keep, &id, "get_nostr_pubkey", None, NOW)
        .is_err());
    assert!(audit.admit(&mut v.keep, &id, NOW).is_err());
    assert_eq!(v.reasons(AuditEventType::AgentServed).len(), 1);
    assert_eq!(
        authenticate(&v.keep, &token, 1000, NOW)
            .unwrap()
            .unwrap_err()
            .because,
        RefusedBecause::Credential(AgentRefusal::Frozen)
    );
    v.break_log(true);
    let mut fresh = AgentAudit::default();
    assert!(fresh
        .record_served(&mut v.keep, &[9; 16], "get_nostr_pubkey", None, NOW)
        .is_err());
}
