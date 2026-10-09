// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use keep_core::agent::cap_text;
use keep_core::Keep;

use crate::error::{AgentError, Result};

/// Repeats of one refusal (same credential, kind and detail) within this many
/// seconds are written as a single counted entry.
pub const REFUSAL_WINDOW_SECS: u64 = 60;

/// Entries one credential may write to the audit log per day. A credential
/// that reaches it is frozen, since its requests could no longer be recorded.
pub const AUDIT_BUDGET_PER_DAY: u32 = 2_000;

/// Entries every credential together may write per day, well under the log's
/// agent ceiling, so agents cannot fill it in a day. Refusals may use only
/// half of it, so refused requests cannot leave signatures without room.
pub const GATEWAY_AUDIT_BUDGET_PER_DAY: u32 = 40_000;

const DAY_SECS: u64 = 24 * 60 * 60;

/// Open refusal windows held at most; reaching it flushes them all.
const MAX_PENDING: usize = 1_024;

/// Credentials whose budgets are tracked before stale ones are dropped.
const MAX_TRACKED: usize = 256;

/// Open refusal windows one credential may hold; past it, its refusals are
/// written one by one, so it cannot leave a burst of counts for another
/// credential's request to write out.
const MAX_WINDOWS_PER_CREDENTIAL: usize = 32;

/// The id the gateway's own budget entry is recorded under.
const GATEWAY_ID: [u8; 16] = [0; 16];

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
    /// The gateway could not complete the request.
    Failed,
}

impl RefusalKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::Denied => "denied",
            Self::NeedsApproval => "needs approval",
            Self::RateLimited => "rate limited",
            Self::Invalid => "invalid",
            Self::Failed => "failed",
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
/// owner unfreezes or deletes a credential; passes only the ids of
/// credentials a token matched (accepted or refused); and passes `now` from
/// one clock that only advances with elapsed time. A restart starts every
/// budget afresh; the vault's agent ceiling still bounds the log.
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
    refusals: u32,
    exhausted: bool,
    refusals_exhausted: bool,
    frozen: bool,
}

impl Spent {
    fn starting(now: u64) -> Self {
        Self {
            since: now,
            ..Self::default()
        }
    }

    /// Start a new day once a day has passed. A credential the budget froze
    /// stays marked frozen, so it is not frozen again each day.
    fn roll(&mut self, now: u64) {
        if now >= self.since.saturating_add(DAY_SECS) {
            *self = Self {
                frozen: self.frozen,
                ..Self::starting(now)
            };
        }
    }
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
    ///
    /// Nothing is written for a credential its budget froze: its budget's end
    /// is already recorded, and it would only spend the gateway's refusals.
    pub fn record_refusal(
        &mut self,
        keep: &mut Keep,
        id: &[u8; 16],
        kind: RefusalKind,
        detail: &str,
        now: u64,
    ) -> Result<()> {
        self.flush_expired(keep, now)?;
        if self.spent.get(id).is_some_and(|s| s.frozen) {
            return Ok(());
        }
        let key = (*id, kind, cap_text(detail).to_string());
        if let Some(window) = self.pending.get_mut(&key) {
            window.repeats = window.repeats.saturating_add(1);
            return Ok(());
        }
        if self.pending.len() >= MAX_PENDING {
            self.flush_all(keep, now)?;
        }
        self.check(keep, id, true, now)?;
        keep.record_agent_refusal(id, kind.label(), Some(&key.2))?;
        self.charge(id, true);
        if self.pending.keys().filter(|k| k.0 == *id).count() >= MAX_WINDOWS_PER_CREDENTIAL {
            return Ok(());
        }
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
        self.check(keep, id, false, now)?;
        let context = format!("agent {} {context}", hex::encode(id));
        keep.record_agent_signature(pubkey, message, &context)?;
        self.charge(id, false);
        Ok(())
    }

    /// Record what credential `id` was served, other than a signature, before
    /// it is returned. `label` is the gateway's own text naming the request;
    /// `detail` may hold text the agent sent. An `Err` means the answer must
    /// be withheld.
    pub fn record_served(
        &mut self,
        keep: &mut Keep,
        id: &[u8; 16],
        label: &str,
        detail: Option<&str>,
        now: u64,
    ) -> Result<()> {
        self.flush_expired(keep, now)?;
        self.check(keep, id, false, now)?;
        keep.record_agent_served(id, label, detail)?;
        self.charge(id, false);
        Ok(())
    }

    /// Whether credential `id` may be answered at all at `now`, for requests
    /// that return nothing worth an entry (the protocol handshake). Writes
    /// nothing unless a budget has just run out, so a credential over its
    /// budget whose freeze failed is still refused, and its freeze retried.
    pub fn admit(&mut self, keep: &mut Keep, id: &[u8; 16], now: u64) -> Result<()> {
        self.flush_expired(keep, now)?;
        self.check(keep, id, false, now)
    }

    /// Whether credential `id`'s budget froze it, until [`Self::reset`].
    pub fn froze(&self, id: &[u8; 16]) -> bool {
        self.spent.get(id).is_some_and(|s| s.frozen)
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
            if window.repeats == 0 || self.check(keep, &key.0, true, now).is_err() {
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
            self.charge(&key.0, true);
        }
        Ok(())
    }

    /// Whether credential `id` and the gateway can still write a refusal or a
    /// signature today. The first time a budget runs out, one entry beyond it
    /// says so, and a credential over its own budget is frozen.
    fn check(&mut self, keep: &mut Keep, id: &[u8; 16], refusal: bool, now: u64) -> Result<()> {
        self.gateway.roll(now);
        if self.spent.len() >= MAX_TRACKED && !self.spent.contains_key(id) {
            // A credential its budget froze stays tracked, so it is not frozen
            // and recorded again; [`Self::reset`] drops it.
            self.spent
                .retain(|_, s| s.frozen || now < s.since.saturating_add(DAY_SECS));
        }
        let spent = self
            .spent
            .entry(*id)
            .or_insert_with(|| Spent::starting(now));
        spent.roll(now);
        let credential_over = spent.entries >= self.credential_budget;
        let gateway_over = self.gateway.entries >= self.gateway_budget;
        let refusals_over = refusal && self.gateway.refusals >= self.gateway_budget / 2;
        if credential_over {
            if !spent.exhausted
                && keep
                    .record_agent_refusal(id, "audit budget used for today", None)
                    .is_ok()
            {
                spent.exhausted = true;
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
            return Err(AgentError::RateLimitExceeded(format!(
                "agent {} has used its audit budget {state}",
                hex::encode(id)
            )));
        }
        if gateway_over {
            if !self.gateway.exhausted
                && keep
                    .record_agent_refusal(&GATEWAY_ID, "gateway audit budget used for today", None)
                    .is_ok()
            {
                self.gateway.exhausted = true;
            }
            return Err(AgentError::RateLimitExceeded(
                "the gateway has used its audit budget for today".into(),
            ));
        }
        if refusals_over {
            if !self.gateway.refusals_exhausted
                && keep
                    .record_agent_refusal(
                        &GATEWAY_ID,
                        "gateway refusal budget used for today",
                        None,
                    )
                    .is_ok()
            {
                self.gateway.refusals_exhausted = true;
            }
            return Err(AgentError::RateLimitExceeded(
                "the gateway has used its refusal budget for today".into(),
            ));
        }
        Ok(())
    }

    fn charge(&mut self, id: &[u8; 16], refusal: bool) {
        self.gateway.entries = self.gateway.entries.saturating_add(1);
        if refusal {
            self.gateway.refusals = self.gateway.refusals.saturating_add(1);
        }
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
