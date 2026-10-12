// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! What `keep.db` remembers about the vault's audit log, so that a log
//! replaced behind the vault's back is noticed on the next unlock, and what
//! the owner must be told stays reported until the owner acknowledges it.
//!
//! The log's last sequence number and hash never go back while the log is
//! intact (see [`crate::audit::AuditLog`]). The record holds the pair the log
//! was at after its latest entry, under the data key: an older copy of the
//! log put back shows a lower sequence number, or the same one with another
//! hash, and another log swapped in no longer holds the recorded entry.
//! Rolling `keep.db` back together with the log is not caught here; an
//! outside record, such as the anchors an approver keeps, catches that.

use serde::{Deserialize, Serialize};

/// The config key the record is stored under.
pub(crate) const AUDIT_RECORD_KEY: &[u8] = b"audit_record";

/// Carried in the reason of every unlock entry and retention entry a keep
/// that keeps the record writes, so a log holding one while `keep.db` has no
/// record shows the record was deleted.
pub(crate) const RECORD_NOTE: &str = "audit record kept";

/// A log found not continuing what the vault recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRollback {
    /// The sequence number the vault had recorded.
    pub recorded_seq: u64,
    /// The head the vault had recorded with it.
    pub recorded_head: [u8; 32],
    /// The log's last sequence number when it was first found so.
    pub found_seq: u64,
    /// The log's head then.
    pub found_head: [u8; 32],
    /// When it was first found, in Unix seconds.
    pub found_at: i64,
    /// How many unlocks found the log so, until the owner acknowledged it.
    pub count: u64,
    /// The lowest sequence number the log was found at in that time.
    pub lowest_found_seq: u64,
}

impl std::fmt::Display for AuditRollback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the audit log was at entry {} (head {}) but was found at entry {} (head {}) not continuing it",
            self.recorded_seq,
            hex::encode(self.recorded_head),
            self.found_seq,
            hex::encode(self.found_head)
        )?;
        if self.count > 1 {
            write!(
                f,
                ", and found so {} times in all, as low as entry {}",
                self.count, self.lowest_found_seq
            )?;
        }
        Ok(())
    }
}

/// How many set-aside logs the record names before it only counts them.
pub(crate) const MAX_NOTED: usize = 16;

/// A log set aside because it held lines this keep could not read, or a
/// migration whose old chain failed its check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetAside {
    /// The name the old log was kept under beside the log.
    pub kept: String,
    /// Not one line of it decrypted under the vault's data key.
    pub unreadable: bool,
    /// Where the record had the log when it was set aside.
    pub recorded_seq: u64,
    /// The head the record had with it.
    pub recorded_head: [u8; 32],
    /// A data key rotation was under way and unfinished.
    pub rotation: bool,
}

/// The log's chain found broken at unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainBroken {
    /// When it was first found so, in Unix seconds.
    pub found_at: i64,
    /// How many entries or lines broke the chain rules the last time.
    pub failures: u64,
    /// The sequence number (or line number) of the first break then.
    pub first_failure: u64,
}

/// The record itself found missing or unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordLost {
    /// The record was gone while the log showed one had been kept;
    /// otherwise it could not be read.
    pub missing: bool,
    /// When it was found so, in Unix seconds.
    pub found_at: i64,
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
    /// Migrations that failed their check, and logs set aside, until the
    /// owner acknowledges them: the first [`MAX_NOTED`].
    pub set_asides: Vec<SetAside>,
    /// How many more there were past those.
    pub more_set_asides: u64,
    /// The log found not continuing the record, until the owner
    /// acknowledges it.
    pub rollback: Option<AuditRollback>,
    /// The record found missing or unreadable, until the owner acknowledges
    /// it.
    pub lost: Option<RecordLost>,
    /// The names signing audit logs that could not be read were kept under,
    /// until the owner acknowledges them: the first [`MAX_NOTED`].
    pub signing_set_asides: Vec<String>,
    /// The log's chain found broken, until the owner acknowledges it.
    pub chain_broken: Option<ChainBroken>,
    /// The fingerprint of the breaks the owner acknowledged, so only new
    /// ones are reported.
    pub chain_acknowledged: Option<[u8; 32]>,
    /// The sequence number and hash a pruning about to replace the log
    /// will leave it at, until the record follows it.
    pub retention_pending: Option<(u64, [u8; 32])>,
}

/// Something about the audit log the owner must be told on every unlock
/// until it is acknowledged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditWarning {
    /// A migration found the old log failed its chain check, or the log was
    /// set aside because it held lines this keep could not read.
    FailedMigration {
        /// What was set aside, and why.
        set_aside: SetAside,
        /// The kept old log is no longer beside the log.
        missing: bool,
    },
    /// The log was found not continuing what the vault recorded.
    RolledBack(AuditRollback),
    /// The record of the log was missing or unreadable, so a log replaced
    /// before then would not have been noticed.
    RecordLost(RecordLost),
    /// The signing audit log could not be read and was set aside.
    SigningLogSetAside {
        /// The name it was kept under.
        kept: String,
        /// That file is no longer beside the log.
        missing: bool,
    },
    /// More logs were set aside than the record names.
    MoreSetAside(u64),
    /// The log's chain is broken in a way not acknowledged before.
    ChainBroken(ChainBroken),
}

const ACKNOWLEDGE: &str =
    "run `keep audit verify`, and once investigated, `keep audit acknowledge`";

impl std::fmt::Display for AuditWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kept_text = |kept: &str, missing: bool| {
            if missing {
                format!("the kept log {kept} is missing from the vault folder")
            } else {
                format!("keep {kept} in the vault folder for investigation")
            }
        };
        match self {
            Self::FailedMigration { set_aside, missing } if set_aside.unreadable => {
                let why = if set_aside.rotation {
                    "a `keep rotate-data-key` was under way and unfinished, which leaves the log \
                     under the data key it replaced"
                } else {
                    "no data key change was under way, so it was replaced or damaged"
                };
                write!(
                    f,
                    "the audit log could not be read under the vault's data key ({why}), so it \
                     was set aside and a new log started: the entries up to entry {} (head {}) \
                     cannot be read; {}; {ACKNOWLEDGE}",
                    set_aside.recorded_seq,
                    hex::encode(set_aside.recorded_head),
                    kept_text(&set_aside.kept, *missing)
                )
            }
            Self::FailedMigration { set_aside, missing } => write!(
                f,
                "the audit log was moved to sequence numbers or set aside, and the old log FAILED \
                 its chain check or held entries this keep cannot read: entries from before then \
                 cannot be trusted; {}; {ACKNOWLEDGE}",
                kept_text(&set_aside.kept, *missing)
            ),
            Self::RolledBack(r) => write!(
                f,
                "{r}: it was replaced or cut back, so entries may be missing; {ACKNOWLEDGE}"
            ),
            Self::RecordLost(lost) if lost.missing => write!(
                f,
                "the vault's record of the audit log is missing, though the log or the vault's \
                 contents show it had one: a log replaced before this unlock would not have been \
                 noticed; {ACKNOWLEDGE}"
            ),
            Self::RecordLost(_) => write!(
                f,
                "the vault's record of the audit log could not be read and was started again: a \
                 log replaced before this unlock would not have been noticed; {ACKNOWLEDGE}"
            ),
            Self::SigningLogSetAside { kept, missing } => write!(
                f,
                "the signing audit log could not be read (an interrupted `keep rotate-data-key`, \
                 damage, or entries this keep cannot read) and was set aside, and a new one \
                 started; {}; {ACKNOWLEDGE}",
                kept_text(kept, *missing)
            ),
            Self::MoreSetAside(count) => write!(
                f,
                "{count} more logs were set aside than the vault's record names; {ACKNOWLEDGE}"
            ),
            Self::ChainBroken(broken) => write!(
                f,
                "the audit log's hash chain is broken in {} places, the first at entry or line \
                 {}: entries were removed, changed or put in from another log; {ACKNOWLEDGE}",
                broken.failures, broken.first_failure
            ),
        }
    }
}

impl AuditRecord {
    /// Compare the log as it is now (`seq`, `head`) with the record and move
    /// the record to it. The log is behind when its count is lower, or the
    /// same with another head; past the record, `continues` says whether it
    /// still holds the recorded entry. A log behind or not continuing is
    /// noted as a rollback, counted with any noted before. Returns whether
    /// one was found now.
    pub(crate) fn observe(&mut self, seq: u64, head: [u8; 32], continues: bool, now: i64) -> bool {
        let behind = self.seq > 0 && (seq < self.seq || (seq == self.seq && head != self.head));
        let diverged = self.seq > 0 && seq > self.seq && !continues;
        let found = behind || diverged;
        if found {
            match &mut self.rollback {
                Some(r) => {
                    r.count = r.count.saturating_add(1);
                    r.lowest_found_seq = r.lowest_found_seq.min(seq);
                }
                None => {
                    self.rollback = Some(AuditRollback {
                        recorded_seq: self.seq,
                        recorded_head: self.head,
                        found_seq: seq,
                        found_head: head,
                        found_at: now,
                        count: 1,
                        lowest_found_seq: seq,
                    });
                }
            }
        }
        self.seq = seq;
        self.head = head;
        found
    }

    /// Note a log set aside, once per kept name, naming the first
    /// [`MAX_NOTED`] and counting the rest.
    pub(crate) fn note_set_aside(&mut self, set_aside: SetAside) {
        if self.set_asides.iter().any(|s| s.kept == set_aside.kept) {
            return;
        }
        if self.set_asides.len() < MAX_NOTED {
            self.set_asides.push(set_aside);
        } else {
            self.more_set_asides = self.more_set_asides.saturating_add(1);
        }
    }

    /// Note a signing log set aside, once per kept name, as
    /// [`AuditRecord::note_set_aside`] does.
    pub(crate) fn note_signing_set_aside(&mut self, kept: &str) {
        if self.signing_set_asides.iter().any(|k| k == kept) {
            return;
        }
        if self.signing_set_asides.len() < MAX_NOTED {
            self.signing_set_asides.push(kept.to_string());
        } else {
            self.more_set_asides = self.more_set_asides.saturating_add(1);
        }
    }

    /// Whether anything is noted for the owner to acknowledge.
    pub(crate) fn pending(&self) -> bool {
        !self.set_asides.is_empty()
            || self.more_set_asides > 0
            || self.rollback.is_some()
            || self.lost.is_some()
            || !self.signing_set_asides.is_empty()
            || self.chain_broken.is_some()
    }

    /// Clear everything noted for the owner, once acknowledged.
    pub(crate) fn clear_pending(&mut self) {
        self.set_asides.clear();
        self.more_set_asides = 0;
        self.rollback = None;
        self.lost = None;
        self.signing_set_asides.clear();
        self.chain_broken = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_log_behind_the_record_is_a_rollback_and_every_later_one_counts() {
        let mut r = AuditRecord::default();
        // The first record notes nothing.
        assert!(!r.observe(10, [1; 32], true, 0));
        // Moving forward is fine, whatever the head, while it continues.
        assert!(!r.observe(12, [2; 32], true, 0));
        assert!(!r.observe(12, [2; 32], true, 0));
        assert!(r.rollback.is_none());
        // Past the record but not holding the recorded entry.
        let mut swapped = r.clone();
        assert!(swapped.observe(20, [4; 32], false, 3));
        assert_eq!(swapped.rollback.unwrap().found_seq, 20);
        // The same count with another head, or a lower count, is a rollback.
        let mut same = r.clone();
        assert!(same.observe(12, [3; 32], true, 5));
        assert_eq!(same.rollback.unwrap().found_head, [3; 32]);
        assert!(r.observe(11, [9; 32], true, 7));
        let noted = r.rollback.unwrap();
        assert_eq!(
            (
                noted.recorded_seq,
                noted.found_seq,
                noted.found_at,
                noted.count
            ),
            (12, 11, 7, 1)
        );
        // A later rollback is counted, and the lowest count kept, beside the
        // first; the record follows the log.
        assert!(r.observe(1, [0; 32], true, 9));
        assert!(!r.observe(5, [5; 32], true, 9));
        let kept = r.rollback.unwrap();
        assert_eq!(
            (
                kept.found_seq,
                kept.found_at,
                kept.count,
                kept.lowest_found_seq
            ),
            (11, 7, 2, 1)
        );
        assert_eq!(r.seq, 5);
        let text = AuditWarning::RolledBack(kept).to_string();
        assert!(text.contains("found at entry 11"), "{text}");
        assert!(text.contains("2 times in all, as low as entry 1"), "{text}");
        assert!(r.pending());
    }
}
