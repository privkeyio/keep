// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The agent gateway's credential and audit layer over the vault: grants are
//! decoded and validated whenever a credential is loaded, signatures are
//! recorded before they are returned, and refusals are recorded within budgets
//! that keep agents from filling the audit log (see [`AgentAudit`]).

mod audit;
mod credential;

pub use audit::{
    AgentAudit, RefusalKind, AUDIT_BUDGET_PER_DAY, GATEWAY_AUDIT_BUDGET_PER_DAY,
    REFUSAL_WINDOW_SECS,
};
pub use credential::{authenticate, issue_credential, GrantedCredential, Refused, RefusedBecause};

#[cfg(test)]
mod tests;
