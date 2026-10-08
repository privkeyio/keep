// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use keep_core::agent::MAX_AUDIT_TEXT;
use keep_core::Keep;

use crate::error::{AgentError, Result};

/// Repeats of one refusal (same credential, kind and detail) within this many
/// seconds are written as a single counted entry.
pub const REFUSAL_WINDOW_SECS: u64 = 60;

/// Entries one credential may write to the audit log per day. A credential
/// that reaches it is frozen, since its requests could no longer be recorded.
pub const AUDIT_BUDGET_PER_DAY: u32 = 2_000;

/// Entries every credential together may write per day, well under the log's
/// agent ceiling, so agents cannot fill it in a day.
pub const GATEWAY_AUDIT_BUDGET_PER_DAY: u32 = 40_000;

const DAY_SECS: u64 = 24 * 60 * 60;

/// Open refusal windows held at most; reaching it flushes them all.
const MAX_PENDING: usize = 1_024;

/// Credentials whose budgets are tracked before stale ones are dropped.
const MAX_TRACKED: usize = 256;

/// Why a request was refused, as the audit log records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalKind {
    /// The token or its credential was refused.
    Unauthenticated,
    /// The policy denied the request.
    Denied,
    /// The request needs an approval it does not have.
    NeedsApproval,
    /// The credential is over its request rate.
    RateLimited,
    /// The request is malformed.
    Invalid,
}

impl RefusalKind {
    fn label(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::Denied => "denied",
            Self::NeedsApproval => "needs approval",
            Self::RateLimited => "rate limited",
            Self::Invalid => "invalid",
        }
    }
}

/// Records the gateway's decisions in the vault's audit log, bounding what
/// agents can write: identical refusals are collapsed, each credential has a
/// daily budget, and so does the gateway as a whole.
///
/// State is held in memory. The daemon calls [`Self::flush_expired`] on a
/// timer and [`Self::flush_all`] before it stops, since counts still open in
/// a window are lost if the process exits; calls [`Self::reset`] after the
/// owner unfreezes a credential; passes only authenticated credential ids; and
/// passes `now` from one clock that only advances with elapsed time.
pub struct AgentAudit {
    credential_budget: u32,
    gateway_budget: u32,
    pending: HashMap<WindowKey, Window>,
    spent: HashMap<[u8; 16], Spent>,
    gateway: Spent,
}

type WindowKey = ([u8; 16], RefusalKind, String);

struct Window {
    opened: u64,
    repeats: u32,
}

#[derive(Default)]
struct Spent {
    since: u64,
    entries: u32,
    exhausted: bool,
    frozen: bool,
}

impl Spent {
    fn starting(now: u64) -> Self {
        Self {
            since: now,
            ..Self::default()
        }
    }

    fn roll(&mut self, now: u64) {
        if now >= self.since.saturating_add(DAY_SECS) {
            *self = Self::starting(now);
        }
    }
}

enum Exhausted {
    Credential,
    Gateway,
}

impl Default for AgentAudit {
    fn default() -> Self {
        Self::with_budgets(AUDIT_BUDGET_PER_DAY, GATEWAY_AUDIT_BUDGET_PER_DAY)
    }
}

impl AgentAudit {
    /// An audit gate allowing each credential `credential_budget` entries a
    /// day, and every credential together `gateway_budget`.
    pub fn with_budgets(credential_budget: u32, gateway_budget: u32) -> Self {
        Self {
            credential_budget,
            gateway_budget,
            pending: HashMap::new(),
            spent: HashMap::new(),
            gateway: Spent::default(),
        }
    }

    /// Record a refused request by credential `id` at `now`. The first refusal
    /// with this kind and detail in a window is written now; repeats are
    /// counted and written as one entry once the window has passed. `detail`
    /// may hold text the agent sent. Fails when the entry cannot be written.
    pub fn record_refusal(
        &mut self,
        keep: &mut Keep,
        id: &[u8; 16],
        kind: RefusalKind,
        detail: &str,
        now: u64,
    ) -> Result<()> {
        self.flush_expired(keep, now)?;
        let key = (*id, kind, capped(detail));
        if let Some(window) = self.pending.get_mut(&key) {
            window.repeats = window.repeats.saturating_add(1);
            return Ok(());
        }
        if self.pending.len() >= MAX_PENDING {
            self.flush_all(keep, now)?;
        }
        self.check(keep, id, now)?;
        keep.record_agent_refusal(id, kind.label(), Some(&key.2))?;
        self.charge(id);
        self.pending.insert(
            key,
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
        self.flush_expired(keep, now)?;
        self.check(keep, id, now)?;
        let context = format!("agent {} {context}", hex::encode(id));
        keep.record_agent_signature(pubkey, message, &context)?;
        self.charge(id);
        Ok(())
    }

    /// Restore credential `id`'s budget, after the owner unfreezes it.
    pub fn reset(&mut self, id: &[u8; 16]) {
        self.spent.remove(id);
    }

    /// Write a counted entry for every refusal window that has passed.
    pub fn flush_expired(&mut self, keep: &mut Keep, now: u64) -> Result<()> {
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, w)| now >= w.opened.saturating_add(REFUSAL_WINDOW_SECS))
            .map(|(key, _)| key.clone())
            .collect();
        self.flush(keep, expired, now)
    }

    /// Write a counted entry for every open refusal window.
    pub fn flush_all(&mut self, keep: &mut Keep, now: u64) -> Result<()> {
        let keys: Vec<_> = self.pending.keys().cloned().collect();
        self.flush(keep, keys, now)
    }

    /// A counted entry is budgeted like any other; a count over the budget is
    /// dropped, once the budget's end has itself been recorded.
    fn flush(&mut self, keep: &mut Keep, keys: Vec<WindowKey>, now: u64) -> Result<()> {
        for key in keys {
            let Some(window) = self.pending.remove(&key) else {
                continue;
            };
            if window.repeats == 0 || self.check(keep, &key.0, now).is_err() {
                continue;
            }
            let label = format!(
                "{} x{} more since {}",
                key.1.label(),
                window.repeats,
                window.opened
            );
            if let Err(e) = keep.record_agent_refusal(&key.0, &label, Some(&key.2)) {
                self.pending.insert(key, window);
                return Err(e.into());
            }
            self.charge(&key.0);
        }
        Ok(())
    }

    /// Whether credential `id` and the gateway can still write today. The
    /// first time a budget runs out, one entry beyond it says so, and a
    /// credential over its own budget is frozen.
    fn check(&mut self, keep: &mut Keep, id: &[u8; 16], now: u64) -> Result<()> {
        self.gateway.roll(now);
        if self.spent.len() >= MAX_TRACKED && !self.spent.contains_key(id) {
            self.spent
                .retain(|_, s| now < s.since.saturating_add(DAY_SECS));
        }
        let spent = self
            .spent
            .entry(*id)
            .or_insert_with(|| Spent::starting(now));
        spent.roll(now);
        let exhausted = if self.gateway.entries >= self.gateway_budget {
            Exhausted::Gateway
        } else if spent.entries >= self.credential_budget {
            Exhausted::Credential
        } else {
            return Ok(());
        };
        match exhausted {
            Exhausted::Gateway => {
                if !self.gateway.exhausted {
                    self.gateway.exhausted = true;
                    let _ =
                        keep.record_agent_refusal(id, "gateway audit budget used for today", None);
                }
                Err(AgentError::RateLimitExceeded(
                    "the gateway has used its audit budget for today".into(),
                ))
            }
            Exhausted::Credential => {
                if !spent.exhausted {
                    spent.exhausted = true;
                    let _ = keep.record_agent_refusal(id, "audit budget used for today", None);
                }
                if !spent.frozen {
                    match keep.set_agent_credential_frozen(id, true) {
                        Ok(()) => spent.frozen = true,
                        Err(e) => tracing::warn!(
                            id = %hex::encode(id),
                            error = %e,
                            "could not freeze agent credential over its audit budget"
                        ),
                    }
                }
                let state = if spent.frozen {
                    "and is frozen"
                } else {
                    "and could not be frozen"
                };
                Err(AgentError::RateLimitExceeded(format!(
                    "agent {} has used its audit budget {state}",
                    hex::encode(id)
                )))
            }
        }
    }

    fn charge(&mut self, id: &[u8; 16]) {
        self.gateway.entries = self.gateway.entries.saturating_add(1);
        if let Some(spent) = self.spent.get_mut(id) {
            spent.entries = spent.entries.saturating_add(1);
        }
    }

    #[cfg(test)]
    pub(super) fn open_windows(&self) -> usize {
        self.pending.len()
    }

    #[cfg(test)]
    pub(super) fn tracked(&self) -> usize {
        self.spent.len()
    }
}

/// `detail` cut to the audit log's limit at a character boundary.
fn capped(detail: &str) -> String {
    let mut end = detail.len().min(MAX_AUDIT_TEXT);
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail[..end].to_string()
}
