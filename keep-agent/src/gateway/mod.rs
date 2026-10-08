// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The agent gateway's credential and audit layer over the vault: grants are
//! decoded and validated whenever a credential is loaded, and every decision
//! is recorded before its result is returned.

mod audit;
mod credential;

pub use audit::{AgentAudit, AUDIT_BUDGET_PER_DAY, REFUSAL_WINDOW_SECS};
pub use credential::{authenticate, issue_credential, GrantedCredential};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{BitcoinGrant, Grant};
    use crate::scope::Operation;
    use keep_core::agent::{AgentCredential, AgentRefusal};
    use keep_core::audit::AuditEventType;
    use keep_core::Keep;

    const NOW: u64 = 1_800_000_000;
    const KEY: [u8; 32] = [1; 32];
    const ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    fn vault(dir: &std::path::Path) -> Keep {
        let path = dir.join("keep");
        keep_core::storage::Storage::create(
            &path,
            "testpass",
            keep_core::crypto::Argon2Params::TESTING,
        )
        .unwrap();
        let mut keep = Keep::open(&path).unwrap();
        keep.unlock("testpass").unwrap();
        keep
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
        }
    }

    fn entries(keep: &Keep, event: AuditEventType) -> Vec<String> {
        keep.audit_read_all()
            .unwrap()
            .into_iter()
            .filter(|e| e.event_type == event)
            .filter_map(|e| e.reason)
            .collect()
    }

    #[test]
    fn an_issued_grant_comes_back_validated() {
        let dir = tempfile::tempdir().unwrap();
        let mut keep = vault(dir.path());
        let (issued, token) =
            issue_credential(&mut keep, "agent", 1000, grant(), NOW, 3600).unwrap();
        let loaded = authenticate(&keep, &token, 1000, NOW).unwrap().unwrap();
        assert_eq!(loaded.grant, grant().validated().unwrap());
        assert_eq!(loaded.credential, issued.credential);
        assert_eq!(
            authenticate(&keep, &token, 1001, NOW).unwrap().unwrap_err(),
            AgentRefusal::WrongUid
        );

        let mut invalid = grant();
        invalid.keys.clear();
        assert!(issue_credential(&mut keep, "bad", 1000, invalid, NOW, 3600).is_err());
        assert_eq!(keep.agent_credentials().unwrap().len(), 1, "nothing issued");
    }

    #[test]
    fn a_grant_that_is_not_validated_as_stored_does_not_load() {
        let stored = |bytes: Vec<u8>| {
            let (credential, _) = AgentCredential::issue("agent", 1000, bytes, NOW, 3600).unwrap();
            GrantedCredential::new(credential).unwrap_err().to_string()
        };
        assert!(stored(b"not json".to_vec()).contains("does not decode"));
        let mut invalid = grant();
        invalid.keys.clear();
        assert!(stored(serde_json::to_vec(&invalid).unwrap()).contains("keys"));
        let mut uncanonical = grant();
        uncanonical.bitcoin.as_mut().unwrap().address_allowlist =
            Some([ADDR.to_uppercase()].into());
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
    fn repeated_refusals_are_collapsed_per_window() {
        let dir = tempfile::tempdir().unwrap();
        let mut keep = vault(dir.path());
        let mut audit = AgentAudit::default();
        let (a, b) = ([1; 16], [2; 16]);
        for i in 0..5 {
            audit
                .record_refusal(&mut keep, &a, "deny", "kind 4 is not granted", NOW + i)
                .unwrap();
        }
        audit
            .record_refusal(&mut keep, &a, "approval", "kind 0", NOW)
            .unwrap();
        audit
            .record_refusal(&mut keep, &b, "deny", "kind 4 is not granted", NOW)
            .unwrap();
        assert_eq!(entries(&keep, AuditEventType::AgentRefused).len(), 3);

        let later = NOW + REFUSAL_WINDOW_SECS;
        audit
            .record_refusal(&mut keep, &a, "deny", "kind 5 is not granted", later)
            .unwrap();
        let refused = entries(&keep, AuditEventType::AgentRefused);
        let id = hex::encode(a);
        assert!(
            refused.contains(&format!("agent {id} deny: 4 more since {NOW}")),
            "{refused:?}"
        );
        assert!(refused.contains(&format!("agent {id} deny: kind 5 is not granted")));
        assert_eq!(refused.len(), 5, "{refused:?}");

        audit
            .record_refusal(&mut keep, &a, "deny", "again", later + 1)
            .unwrap();
        audit.flush_all(&mut keep, later + 2).unwrap();
        let refused = entries(&keep, AuditEventType::AgentRefused);
        assert!(
            refused.contains(&format!("agent {id} deny: 1 more since {later}")),
            "{refused:?}"
        );
    }

    #[test]
    fn a_credential_that_spends_its_audit_budget_is_frozen_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut keep = vault(dir.path());
        let (issued, token) =
            issue_credential(&mut keep, "agent", 1000, grant(), NOW, 3 * 86_400).unwrap();
        let id = issued.credential.id;
        let mut audit = AgentAudit::with_budget(3);
        for i in 0..3 {
            audit
                .record_signature(&mut keep, &id, &KEY, b"msg", &format!("sign {i}"), NOW)
                .unwrap();
        }
        let signed = entries(&keep, AuditEventType::Sign);
        assert_eq!(signed.len(), 3);
        assert!(signed[0].starts_with(&format!("agent {} sign 0", hex::encode(id))));

        for _ in 0..3 {
            assert!(matches!(
                audit.record_signature(&mut keep, &id, &KEY, b"msg", "over", NOW),
                Err(crate::error::AgentError::RateLimitExceeded(_))
            ));
            assert!(audit
                .record_refusal(&mut keep, &id, "deny", "over", NOW)
                .is_err());
        }
        assert_eq!(entries(&keep, AuditEventType::Sign).len(), 3);
        assert_eq!(entries(&keep, AuditEventType::AgentFreeze).len(), 1);
        assert_eq!(
            authenticate(&keep, &token, 1000, NOW).unwrap().unwrap_err(),
            AgentRefusal::Frozen
        );

        let tomorrow = NOW + 86_400;
        audit
            .record_signature(&mut keep, &id, &KEY, b"msg", "next day", tomorrow)
            .unwrap();
        assert_eq!(
            authenticate(&keep, &token, 1000, tomorrow)
                .unwrap()
                .unwrap_err(),
            AgentRefusal::Frozen,
            "the budget renews; the freeze stays until the owner lifts it"
        );
    }

    /// Open refusal windows are bounded: past the bound, every open window is
    /// written out and forgotten.
    #[test]
    fn open_refusal_windows_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let mut keep = vault(dir.path());
        let mut audit = AgentAudit::with_budget(u32::MAX);
        let id = |i: u32| {
            let mut id = [0; 16];
            id[..4].copy_from_slice(&i.to_le_bytes());
            id
        };
        for i in 0..1_024 {
            audit
                .record_refusal(&mut keep, &id(i), "deny", "x", NOW)
                .unwrap();
            audit
                .record_refusal(&mut keep, &id(i), "deny", "x", NOW)
                .unwrap();
        }
        assert_eq!(entries(&keep, AuditEventType::AgentRefused).len(), 1_024);
        audit
            .record_refusal(&mut keep, &id(1_024), "deny", "x", NOW)
            .unwrap();
        assert_eq!(audit.open_windows(), 1);
        let refused = entries(&keep, AuditEventType::AgentRefused);
        assert_eq!(
            refused.len(),
            2 * 1_024 + 1,
            "every open window was written out"
        );
    }

    #[test]
    fn a_refusal_that_cannot_be_recorded_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut keep = vault(dir.path());
        let audit_log = dir.path().join("keep").join("audit.log");
        std::fs::remove_file(&audit_log).unwrap();
        std::fs::create_dir(&audit_log).unwrap();
        let mut audit = AgentAudit::default();
        assert!(audit
            .record_refusal(&mut keep, &[1; 16], "deny", "x", NOW)
            .is_err());
        assert!(audit
            .record_signature(&mut keep, &[1; 16], &KEY, b"m", "x", NOW)
            .is_err());
    }
}
