// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! What `keep.db` remembers about the vault's audit log, so that a log
//! replaced behind the vault's back is noticed on the next unlock, and a
//! failed migration stays reported after its marker file is deleted.
//!
//! The log's last sequence number and hash never go back while the log is
//! intact (see [`crate::audit::AuditLog`]). The record holds the latest pair
//! the vault saw, under the data key: an older copy of the log put back (the
//! old log a migration kept, which migrates again from the start, or an
//! earlier backup of the log) shows a lower sequence number, or the same one
//! with another hash. Rolling `keep.db` back together with the log is not
//! caught here; an outside record, such as the anchors an approver keeps,
//! catches that.

use serde::{Deserialize, Serialize};

/// The config key the record is stored under.
pub(crate) const AUDIT_RECORD_KEY: &[u8] = b"audit_record";

/// A log found behind what the vault recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRollback {
    /// The sequence number the vault had recorded.
    pub recorded_seq: u64,
    /// The head the vault had recorded with it.
    pub recorded_head: [u8; 32],
    /// The log's last sequence number when it was found behind.
    pub found_seq: u64,
    /// The log's head then.
    pub found_head: [u8; 32],
    /// When it was found, in Unix seconds.
    pub found_at: i64,
}

impl std::fmt::Display for AuditRollback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the audit log was at entry {} (head {}) but was found at entry {} (head {})",
            self.recorded_seq,
            hex::encode(self.recorded_head),
            self.found_seq,
            hex::encode(self.found_head)
        )
    }
}

/// What `keep.db` holds about the audit log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    /// The latest sequence number the vault saw its log at; zero before the
    /// first record.
    pub seq: u64,
    /// The log's last entry hash at that sequence number.
    pub head: [u8; 32],
    /// The name of the old log a migration that failed its check kept
    /// beside the log.
    pub failed_migration: Option<String>,
    /// The first time the log was found behind the record, until the owner
    /// acknowledges it.
    pub rollback: Option<AuditRollback>,
}

/// Something about the audit log the owner must be told on every unlock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditWarning {
    /// A migration found the old log failed its chain check, and the old
    /// log, named here, is still kept beside the log: entries from before
    /// the migration cannot be trusted.
    FailedMigration {
        /// The kept old log's file name.
        kept: String,
    },
    /// The log was found behind what the vault recorded: it was replaced by
    /// an older copy, or set aside.
    RolledBack(AuditRollback),
}

impl std::fmt::Display for AuditWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FailedMigration { kept } => write!(
                f,
                "the audit log was moved to sequence numbers and the old log FAILED its chain \
                 check: entries from before the move cannot be trusted; keep {kept} in the vault \
                 folder for investigation and run `keep audit verify`"
            ),
            Self::RolledBack(r) => write!(
                f,
                "{r}: it was replaced by an older copy or set aside, so entries may be missing; \
                 run `keep audit verify`, and once investigated, `keep audit acknowledge`"
            ),
        }
    }
}

impl AuditRecord {
    /// Compare the log as it is now (`seq`, `head`) with the record, note a
    /// rollback if the log is behind and none is noted yet, and move the
    /// record to the log. Returns whether a rollback was found now.
    pub(crate) fn observe(&mut self, seq: u64, head: [u8; 32], now: i64) -> bool {
        let behind = self.seq > 0 && (seq < self.seq || (seq == self.seq && head != self.head));
        let found = behind && self.rollback.is_none();
        if found {
            self.rollback = Some(AuditRollback {
                recorded_seq: self.seq,
                recorded_head: self.head,
                found_seq: seq,
                found_head: head,
                found_at: now,
            });
        }
        self.seq = seq;
        self.head = head;
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_log_behind_the_record_is_a_rollback_once() {
        let mut r = AuditRecord::default();
        // The first record notes nothing.
        assert!(!r.observe(10, [1; 32], 0));
        // Moving forward is fine, whatever the head.
        assert!(!r.observe(12, [2; 32], 0));
        assert!(!r.observe(12, [2; 32], 0));
        // The same count with another head, or a lower count, is a rollback.
        let mut same = r.clone();
        assert!(same.observe(12, [3; 32], 5));
        assert_eq!(same.rollback.unwrap().found_head, [3; 32]);
        assert!(r.observe(11, [9; 32], 7));
        let noted = r.rollback.unwrap();
        assert_eq!(
            (noted.recorded_seq, noted.found_seq, noted.found_at),
            (12, 11, 7)
        );
        // The first rollback stays noted; the record follows the log.
        assert!(!r.observe(1, [0; 32], 9));
        assert_eq!(r.rollback, Some(noted));
        assert_eq!(r.seq, 1);
        assert!(r.to_string_for_tests().contains("found at entry 11"));
    }

    impl AuditRecord {
        fn to_string_for_tests(&self) -> String {
            AuditWarning::RolledBack(self.rollback.unwrap()).to_string()
        }
    }
}
