// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use keep_core::Keep;

use crate::error::{AgentError, Result};

/// Repeats of one kind of refusal for one credential within this many seconds
/// are written as a single counted entry.
pub const REFUSAL_WINDOW_SECS: u64 = 60;

/// Entries one credential may cause in the audit log per day. A credential
/// that reaches it is frozen, since its requests could no longer be recorded.
pub const AUDIT_BUDGET_PER_DAY: u32 = 2_000;

const DAY_SECS: u64 = 24 * 60 * 60;

/// Open refusal windows held at most; reaching it flushes them all.
const MAX_PENDING: usize = 1_024;

/// Records the gateway's decisions in the vault's audit log, bounding what
/// any one credential can write: repeated refusals are collapsed, and each
/// credential has a daily budget.
pub struct AgentAudit {
    budget: u32,
    pending: HashMap<([u8; 16], &'static str), Window>,
    spent: HashMap<[u8; 16], Spent>,
}

struct Window {
    opened: u64,
    repeats: u32,
}

struct Spent {
    since: u64,
    entries: u32,
    frozen: bool,
}

impl Default for AgentAudit {
    fn default() -> Self {
        Self::with_budget(AUDIT_BUDGET_PER_DAY)
    }
}

impl AgentAudit {
    /// An audit gate allowing each credential `budget` entries a day.
    pub fn with_budget(budget: u32) -> Self {
        Self {
            budget,
            pending: HashMap::new(),
            spent: HashMap::new(),
        }
    }

    /// Record a refused request of `kind` (a fixed label, such as `"deny"` or
    /// `"approval"`) by credential `id` at `now`. The first of its kind in a
    /// window is written now; repeats are counted and written as one entry once
    /// the window has passed. Fails when the entry cannot be written.
    pub fn record_refusal(
        &mut self,
        keep: &mut Keep,
        id: &[u8; 16],
        kind: &'static str,
        detail: &str,
        now: u64,
    ) -> Result<()> {
        self.flush_expired(keep, now)?;
        if let Some(window) = self.pending.get_mut(&(*id, kind)) {
            window.repeats = window.repeats.saturating_add(1);
            return Ok(());
        }
        if self.pending.len() >= MAX_PENDING {
            self.flush_all(keep, now)?;
        }
        self.spend(keep, id, now)?;
        keep.record_agent_refusal(id, &format!("{kind}: {detail}"))?;
        self.pending.insert(
            (*id, kind),
            Window {
                opened: now,
                repeats: 0,
            },
        );
        Ok(())
    }

    /// Record a signature credential `id` obtained, before it is returned. An
    /// `Err` means the signature must be withheld.
    pub fn record_signature(
        &mut self,
        keep: &mut Keep,
        id: &[u8; 16],
        pubkey: &[u8; 32],
        message: &[u8],
        context: &str,
        now: u64,
    ) -> Result<()> {
        self.spend(keep, id, now)?;
        let context = format!("agent {} {context}", hex::encode(id));
        keep.record_agent_signature(pubkey, message, &context)?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn open_windows(&self) -> usize {
        self.pending.len()
    }

    /// Write a counted entry for every refusal window that has passed.
    pub fn flush_expired(&mut self, keep: &mut Keep, now: u64) -> Result<()> {
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, w)| now >= w.opened.saturating_add(REFUSAL_WINDOW_SECS))
            .map(|(key, _)| *key)
            .collect();
        self.flush(keep, &expired, now)
    }

    /// Write a counted entry for every open refusal window.
    pub fn flush_all(&mut self, keep: &mut Keep, now: u64) -> Result<()> {
        let keys: Vec<_> = self.pending.keys().copied().collect();
        self.flush(keep, &keys, now)
    }

    /// A counted entry counts against the credential's budget too; once that
    /// is spent (and the credential frozen) the count is dropped.
    fn flush(
        &mut self,
        keep: &mut Keep,
        keys: &[([u8; 16], &'static str)],
        now: u64,
    ) -> Result<()> {
        for key in keys {
            let Some(window) = self.pending.remove(key) else {
                continue;
            };
            if window.repeats > 0 && self.spend(keep, &key.0, now).is_ok() {
                let (id, kind) = key;
                let detail = format!("{kind}: {} more since {}", window.repeats, window.opened);
                if let Err(e) = keep.record_agent_refusal(id, &detail) {
                    self.pending.insert(*key, window);
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }

    /// Count one entry against credential `id`'s daily budget. The credential is
    /// frozen the first time its budget is exhausted, and nothing more is
    /// recorded for it until the next day.
    fn spend(&mut self, keep: &mut Keep, id: &[u8; 16], now: u64) -> Result<()> {
        let spent = self.spent.entry(*id).or_insert(Spent {
            since: now,
            entries: 0,
            frozen: false,
        });
        if now >= spent.since.saturating_add(DAY_SECS) {
            *spent = Spent {
                since: now,
                entries: 0,
                frozen: false,
            };
        }
        if spent.entries >= self.budget {
            if !spent.frozen {
                match keep.set_agent_credential_frozen(id, true) {
                    Ok(()) => spent.frozen = true,
                    Err(e) => {
                        tracing::warn!(id = %hex::encode(id), error = %e, "could not freeze agent credential over its audit budget")
                    }
                }
            }
            return Err(AgentError::RateLimitExceeded(format!(
                "agent {} has used its audit budget and is frozen",
                hex::encode(id)
            )));
        }
        spent.entries += 1;
        Ok(())
    }
}
