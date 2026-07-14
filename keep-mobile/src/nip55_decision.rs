// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Unified NIP-55 signing-decision orchestrator.
//!
//! The auto-sign decision was a policy engine implemented in Kotlin
//! (`Nip55ContentProvider` for the background/auto path and `Nip55Activity` for
//! the foreground path), which duplicated the gate ordering, precedence and
//! DENY-wins rules across two files -- a divergence risk in security-critical
//! signing. This module hoists that decision into Rust so both paths share one
//! source of truth. It composes the existing policy primitives
//! (`nip55_relay_auth_gate`, `evaluate_sign_policy`, `nip55_resolve_decision`,
//! `assess_signing_risk`) in the exact gate order:
//!
//!   caller-verified -> kill-switch -> lock -> front-door rate limit ->
//!   velocity -> relay-auth whitelist -> sign policy -> app expiry ->
//!   standing permission (per-app DENY wins over a whitelisted relay).
//!
//! The function is pure: the Android layer gathers the platform inputs (verified
//! caller, kill-switch/lock flags, the stateful front-door and opt-in rate-limit
//! results, velocity window counts, stored permission rows, and the current
//! clock readings) and this function makes the decision. Availability failures
//! (no signing handler, no permission store) are caller-side plumbing errors and
//! are handled by the caller before it invokes this function.

use crate::nip55::{
    nip55_extract_relay_host, nip55_relay_auth_gate, signable_event_kind_from_json,
    Nip55RelayAuthGate, Nip55RequestType,
};
use crate::nip55_policy::{nip55_resolve_decision, Nip55PermissionDecision, Nip55StoredPermission};
use crate::signing_policy::{
    assess_signing_risk, evaluate_sign_policy, AutoSignDecision, PolicyMode, SignPolicyEvaluation,
    SigningAuthLevel, SigningRequestContext, SigningRiskAssessment,
};

const KIND_NIP42_AUTH: u32 = 22242;

/// Result of the caller's velocity check. The caller runs the check-and-record
/// atomically (querying the window counts and recording the request in one
/// transaction, so concurrent requests cannot race past the limit) and passes
/// the outcome here. `TimedOut` and `Blocked` both fail closed.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum Nip55VelocityCheck {
    Allowed,
    Blocked,
    TimedOut,
}

// When a caller is not opted in to auto-signing, the sign-policy gate is fed a
// synthetic "allowed" rate-check so `evaluate_sign_policy` runs; the not-opted-in
// denial itself happens inside `evaluate_sign_policy` via its `!is_opted_in`
// check. These limits are cosmetic (only the variant and `recent_count` reach the
// decision) and mirror the Android `VelocityConfig` defaults.
const NON_OPT_IN_HOURLY_LIMIT: u32 = 1000;
const NON_OPT_IN_DAILY_LIMIT: u32 = 5000;

/// Platform inputs for a single NIP-55 signing decision. The Android layer
/// gathers each field (running the stateful limiters, querying the velocity log
/// and permission store, reading the clocks) and this record carries the results
/// into the pure decision.
#[derive(uniffi::Record, Clone, Debug)]
pub struct Nip55DecisionInputs {
    /// The Android-verified calling package. Empty or `caller_verified == false`
    /// is a hard "Request denied".
    pub package_name: String,
    /// Whether the caller passed Android package-signature verification.
    pub caller_verified: bool,
    /// Kill switch: signing globally disabled.
    pub signing_killed: bool,
    /// Keep is locked (PIN store requires authentication).
    pub is_locked: bool,

    pub request_type: Nip55RequestType,
    /// The raw event JSON for a `SignEvent`. The signed event kind is derived
    /// from these bytes (never trusted from a separate field) so the auto-sign
    /// classification is bound to what is actually signed. Unused for
    /// non-`SignEvent` operations.
    pub event_json: String,

    /// Result of the coarse per-package front-door limiter (`false` fails closed).
    pub front_door_within_limit: bool,

    /// Outcome of the caller's atomic velocity check-and-record.
    pub velocity_check: Nip55VelocityCheck,

    /// Pre-normalized relay-auth whitelist (empty defers to normal resolution).
    pub relay_whitelist: Vec<String>,
    /// Whether reading the whitelist failed; `true` forces an auto-reject.
    pub relay_whitelist_read_failed: bool,

    /// The resolved sign policy (per-app override -> global -> Manual default),
    /// mapped to Auto/Manual by the caller.
    pub policy_mode: PolicyMode,
    /// Whether the caller is opted in to auto-signing.
    pub is_opted_in: bool,
    /// The opt-in rate-limiter result. `None` (limiter unavailable, or its check
    /// timed out or errored) fails open to the UI. Ignored when not opted in.
    pub opt_in_rate_check: Option<AutoSignDecision>,
    /// Whether this app has signed this event kind before (audit-derived).
    pub has_signed_kind_before: bool,
    /// Age of the app's first grant, if known.
    pub app_age_ms: Option<u64>,
    /// Current local hour (0-23) for risk scoring.
    pub current_hour: u32,

    /// Whether the app grant is expired: `None` (a lookup timeout) and
    /// `Some(true)` both reject; `Some(false)` continues.
    pub app_expired: Option<bool>,
    /// Whether the standing-permission lookup succeeded; `false` fails closed.
    pub permission_lookup_ok: bool,
    /// The kind-specific stored permission row (or the kind-agnostic row when the
    /// request carries no kind), already scoped to the correct relay by the caller.
    pub stored_exact_permission: Option<Nip55StoredPermission>,
    /// The kind-agnostic stored permission row.
    pub stored_generic_permission: Option<Nip55StoredPermission>,
    /// Monotonic and wall clock readings for permission-expiry evaluation.
    pub now_elapsed_ms: i64,
    pub now_wall_ms: i64,
}

/// The decision for a NIP-55 request.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum Nip55Outcome {
    /// Auto-approve. Still subject to the caller's execution-time checks
    /// (pre-approval and, for `GetPublicKey`, pubkey verification).
    AutoApprove,
    /// Reject the request (NIP-55 `rejected = true`). `reason` is the audit action
    /// label, matching the Android audit log.
    Reject { reason: String },
    /// A hard error (a distinct error cursor, not a rejection).
    Error { message: String },
    /// No auto-decision: prompt the user. Carries the risk assessment and the
    /// authentication level the UI must enforce.
    RequireUi {
        required_auth: SigningAuthLevel,
        risk: SigningRiskAssessment,
    },
}

fn auth_rank(level: &SigningAuthLevel) -> u8 {
    match level {
        SigningAuthLevel::None => 0,
        SigningAuthLevel::Pin => 1,
        SigningAuthLevel::Biometric => 2,
        SigningAuthLevel::Explicit => 3,
    }
}

/// Whether the foreground approval must present a biometric prompt: every
/// non-`GetPublicKey` request does, and a `GetPublicKey` does only when the risk
/// requires at least PIN-level auth. Mirrors the Android `needsBiometric`
/// computation so the foreground path shares this rule.
#[uniffi::export]
pub fn nip55_needs_biometric(
    request_type: Nip55RequestType,
    required_auth: SigningAuthLevel,
) -> bool {
    request_type != Nip55RequestType::GetPublicKey
        || auth_rank(&required_auth) >= auth_rank(&SigningAuthLevel::Pin)
}

fn recent_count_of(rate_check: &AutoSignDecision) -> u32 {
    match rate_check {
        AutoSignDecision::Allowed { recent_count, .. } => *recent_count,
        _ => 0,
    }
}

/// Evaluate a NIP-55 signing request against the full policy gate sequence and
/// return the decision. See the module docs for the gate order.
#[uniffi::export]
pub fn evaluate_nip55_request(inputs: Nip55DecisionInputs) -> Nip55Outcome {
    // Gate 0: caller must be a verified, non-blank package.
    if !inputs.caller_verified || inputs.package_name.trim().is_empty() {
        return Nip55Outcome::Error {
            message: "Request denied".to_string(),
        };
    }

    // Gate 1: kill switch.
    if inputs.signing_killed {
        return Nip55Outcome::Error {
            message: "Signing is disabled (kill switch is active)".to_string(),
        };
    }

    // Gate 2: lock.
    if inputs.is_locked {
        return Nip55Outcome::Error {
            message: "Keep is locked, please unlock it first".to_string(),
        };
    }

    // Gate 3: coarse front-door rate limit.
    if !inputs.front_door_within_limit {
        return Nip55Outcome::Error {
            message: "Too many requests, please try again later".to_string(),
        };
    }

    // Gate 4: request-count velocity. The caller's atomic check-and-record has
    // already decided; a timeout or a block both fail closed.
    match inputs.velocity_check {
        Nip55VelocityCheck::TimedOut => {
            return Nip55Outcome::Reject {
                reason: "deny_velocity_timeout".to_string(),
            }
        }
        Nip55VelocityCheck::Blocked => {
            return Nip55Outcome::Reject {
                reason: "velocity_blocked".to_string(),
            }
        }
        Nip55VelocityCheck::Allowed => {}
    }

    // Derive the event kind from the bytes that will actually be signed, using
    // the same parse as the signer. A SignEvent whose kind cannot be determined
    // cannot be classified for sensitivity, so it fails closed rather than
    // risking an auto-approve of a mislabeled sensitive event.
    let event_kind: Option<u32> = if inputs.request_type == Nip55RequestType::SignEvent {
        match signable_event_kind_from_json(&inputs.event_json) {
            Some(kind) => Some(u32::from(kind)),
            None => {
                return Nip55Outcome::Reject {
                    reason: "invalid_event_kind".to_string(),
                }
            }
        }
    } else {
        None
    };

    // The NIP-42 relay-auth gate is only meaningful for a kind-22242 SignEvent;
    // it is computed once and reused by the pre-policy gate and the grant lookup.
    let is_relay_auth =
        inputs.request_type == Nip55RequestType::SignEvent && event_kind == Some(KIND_NIP42_AUTH);
    let relay_gate: Option<Nip55RelayAuthGate> = if is_relay_auth {
        Some(if inputs.relay_whitelist_read_failed {
            Nip55RelayAuthGate::AutoReject
        } else {
            let host = nip55_extract_relay_host(inputs.event_json.clone());
            nip55_relay_auth_gate(host, inputs.relay_whitelist.clone())
        })
    } else {
        None
    };

    // Gate 5: enforce the relay-auth whitelist AUTO_REJECT before the sign policy,
    // so a non-whitelisted relay can never be auto-approved by an Auto sign policy.
    if relay_gate == Some(Nip55RelayAuthGate::AutoReject) {
        return Nip55Outcome::Reject {
            reason: "deny_relay_whitelist".to_string(),
        };
    }

    let ctx = SigningRequestContext {
        operation: inputs.request_type.clone(),
        package_name: inputs.package_name.clone(),
        event_kind,
        has_signed_kind_before: inputs.has_signed_kind_before,
        app_age_ms: inputs.app_age_ms,
    };

    // Gate 6: sign policy. When opted in, use the limiter result (an unavailable
    // limiter fails open to the UI, i.e. falls through to gate 7). When not opted
    // in, feed a synthetic "allowed" so evaluate_sign_policy runs and applies its
    // own not-opted-in denial.
    let (policy_result, recent_count) = if inputs.is_opted_in {
        match &inputs.opt_in_rate_check {
            None => (SignPolicyEvaluation::FallToUi, 0),
            Some(rate_check) => (
                evaluate_sign_policy(
                    inputs.policy_mode.clone(),
                    ctx.clone(),
                    true,
                    rate_check.clone(),
                ),
                recent_count_of(rate_check),
            ),
        }
    } else {
        let fabricated = AutoSignDecision::Allowed {
            hourly_count: 0,
            daily_count: 0,
            recent_count: 0,
            hourly_limit: NON_OPT_IN_HOURLY_LIMIT,
            daily_limit: NON_OPT_IN_DAILY_LIMIT,
        };
        (
            evaluate_sign_policy(inputs.policy_mode.clone(), ctx.clone(), false, fabricated),
            0,
        )
    };

    if policy_result == SignPolicyEvaluation::AutoApprove {
        return Nip55Outcome::AutoApprove;
    }

    // Gate 7: app expiry (fail closed on a lookup timeout or an expired app).
    match inputs.app_expired {
        None => {
            return Nip55Outcome::Reject {
                reason: "deny_timeout".to_string(),
            }
        }
        Some(true) => {
            return Nip55Outcome::Reject {
                reason: "deny_expired".to_string(),
            }
        }
        Some(false) => {}
    }

    // The relay AUTO_REJECT was already enforced at gate 5 (the gate is computed
    // once), so only the standing-permission lookup remains.
    if !inputs.permission_lookup_ok {
        return Nip55Outcome::Reject {
            reason: "lookup_timeout".to_string(),
        };
    }

    // `event_kind` is bounded to u16 at derivation, so the i32 cast never wraps.
    let decision = nip55_resolve_decision(
        inputs.stored_exact_permission.clone(),
        inputs.stored_generic_permission.clone(),
        event_kind.map(|k| k as i32),
        inputs.now_elapsed_ms,
        inputs.now_wall_ms,
    );

    // A whitelisted relay auto-signs, but an explicit per-app DENY still wins.
    // `decision` is the per-kind (kind-22242) resolution: because 22242 is a
    // sensitive kind, a kind-agnostic DENY row never falls back here (matching
    // how the standing-permission storage resolves it), so a blanket DENY does
    // not block a whitelisted relay. This reaches gate 7 only after the expiry
    // and lookup checks above have already passed.
    if relay_gate == Some(Nip55RelayAuthGate::AutoAccept)
        && decision != Some(Nip55PermissionDecision::Deny)
    {
        return Nip55Outcome::AutoApprove;
    }

    match decision {
        Some(Nip55PermissionDecision::Allow) => Nip55Outcome::AutoApprove,
        Some(Nip55PermissionDecision::Deny) => Nip55Outcome::Reject {
            reason: "deny".to_string(),
        },
        Some(Nip55PermissionDecision::Ask) | None => {
            let risk = assess_signing_risk(ctx, recent_count, inputs.current_hour);
            Nip55Outcome::RequireUi {
                required_auth: risk.required_auth.clone(),
                risk,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_MS: u64 = 24 * 60 * 60 * 1000;

    // Baseline: a benign non-sensitive SignEvent that clears gates 0-6 (Manual
    // policy -> FallToUi) and reaches gate 7 with no standing decision, i.e.
    // RequireUi. Individual tests mutate one field to exercise one gate.
    fn base() -> Nip55DecisionInputs {
        Nip55DecisionInputs {
            package_name: "com.example.client".to_string(),
            caller_verified: true,
            signing_killed: false,
            is_locked: false,
            request_type: Nip55RequestType::SignEvent,
            event_json: r#"{"kind":1}"#.to_string(),
            front_door_within_limit: true,
            velocity_check: Nip55VelocityCheck::Allowed,
            relay_whitelist: vec![],
            relay_whitelist_read_failed: false,
            policy_mode: PolicyMode::Manual,
            is_opted_in: false,
            opt_in_rate_check: None,
            has_signed_kind_before: true,
            app_age_ms: Some(2 * DAY_MS),
            current_hour: 12,
            app_expired: Some(false),
            permission_lookup_ok: true,
            stored_exact_permission: None,
            stored_generic_permission: None,
            now_elapsed_ms: 10_000_000,
            now_wall_ms: 1_700_000_000_000,
        }
    }

    fn allowed() -> AutoSignDecision {
        AutoSignDecision::Allowed {
            hourly_count: 1,
            daily_count: 1,
            recent_count: 0,
            hourly_limit: 100,
            daily_limit: 500,
        }
    }

    fn perm(decision: &str) -> Nip55StoredPermission {
        Nip55StoredPermission {
            decision: decision.to_string(),
            expires_at: None,
            created_at: 0,
            created_at_elapsed: 0,
            duration_ms: None,
        }
    }

    fn reject_reason(outcome: &Nip55Outcome) -> &str {
        match outcome {
            Nip55Outcome::Reject { reason } => reason,
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    fn error_message(outcome: &Nip55Outcome) -> &str {
        match outcome {
            Nip55Outcome::Error { message } => message,
            other => panic!("expected Error, got {other:?}"),
        }
    }

    fn is_require_ui(outcome: &Nip55Outcome) -> bool {
        matches!(outcome, Nip55Outcome::RequireUi { .. })
    }

    // Gate 0: caller verification.
    #[test]
    fn unverified_caller_is_denied() {
        let mut i = base();
        i.caller_verified = false;
        assert_eq!(error_message(&evaluate_nip55_request(i)), "Request denied");
    }

    #[test]
    fn blank_package_is_denied() {
        let mut i = base();
        i.package_name = "   ".to_string();
        assert_eq!(error_message(&evaluate_nip55_request(i)), "Request denied");
    }

    // Gate 1: kill switch.
    #[test]
    fn kill_switch_errors() {
        let mut i = base();
        i.signing_killed = true;
        assert_eq!(
            error_message(&evaluate_nip55_request(i)),
            "Signing is disabled (kill switch is active)"
        );
    }

    // Gate 2: lock.
    #[test]
    fn lock_errors() {
        let mut i = base();
        i.is_locked = true;
        assert_eq!(
            error_message(&evaluate_nip55_request(i)),
            "Keep is locked, please unlock it first"
        );
    }

    // Gate 3: front-door rate limit.
    #[test]
    fn front_door_rate_limit_errors() {
        let mut i = base();
        i.front_door_within_limit = false;
        assert_eq!(
            error_message(&evaluate_nip55_request(i)),
            "Too many requests, please try again later"
        );
    }

    // Gate precedence: earlier gates win over later ones.
    #[test]
    fn caller_verification_precedes_kill_switch() {
        let mut i = base();
        i.caller_verified = false;
        i.signing_killed = true;
        assert_eq!(error_message(&evaluate_nip55_request(i)), "Request denied");
    }

    #[test]
    fn kill_switch_precedes_front_door() {
        let mut i = base();
        i.signing_killed = true;
        i.front_door_within_limit = false;
        assert_eq!(
            error_message(&evaluate_nip55_request(i)),
            "Signing is disabled (kill switch is active)"
        );
    }

    // Gate 4: velocity.
    #[test]
    fn velocity_query_timeout_rejects() {
        let mut i = base();
        i.velocity_check = Nip55VelocityCheck::TimedOut;
        assert_eq!(
            reject_reason(&evaluate_nip55_request(i)),
            "deny_velocity_timeout"
        );
    }

    #[test]
    fn velocity_blocked_rejects() {
        let mut i = base();
        i.velocity_check = Nip55VelocityCheck::Blocked;
        assert_eq!(
            reject_reason(&evaluate_nip55_request(i)),
            "velocity_blocked"
        );
    }

    #[test]
    fn front_door_precedes_velocity() {
        let mut i = base();
        i.front_door_within_limit = false;
        i.velocity_check = Nip55VelocityCheck::TimedOut;
        assert_eq!(
            error_message(&evaluate_nip55_request(i)),
            "Too many requests, please try again later"
        );
    }

    // Gate 5: relay-auth whitelist pre-gate (kind 22242 only).
    fn relay_auth_event(host: &str) -> String {
        format!(r#"{{"kind":22242,"tags":[["relay","wss://{host}"]]}}"#)
    }

    #[test]
    fn relay_not_whitelisted_rejects_before_policy() {
        let mut i = base();
        i.event_json = relay_auth_event("relay.notallowed.com");
        i.relay_whitelist = vec!["relay.allowed.com".to_string()];
        i.is_opted_in = true;
        i.policy_mode = PolicyMode::Auto;
        i.opt_in_rate_check = Some(allowed());
        assert_eq!(
            reject_reason(&evaluate_nip55_request(i)),
            "deny_relay_whitelist"
        );
    }

    #[test]
    fn relay_whitelist_read_failure_rejects_for_auth_kind() {
        let mut i = base();
        i.event_json = relay_auth_event("relay.allowed.com");
        i.relay_whitelist = vec!["relay.allowed.com".to_string()];
        i.relay_whitelist_read_failed = true;
        assert_eq!(
            reject_reason(&evaluate_nip55_request(i)),
            "deny_relay_whitelist"
        );
    }

    #[test]
    fn relay_gate_ignored_for_non_auth_kind() {
        // A non-22242 kind never consults the relay gate, even with a read
        // failure and a non-empty whitelist (base event_json is kind 1).
        let mut i = base();
        i.relay_whitelist = vec!["relay.allowed.com".to_string()];
        i.relay_whitelist_read_failed = true;
        assert!(is_require_ui(&evaluate_nip55_request(i)));
    }

    // The relay-auth gate and the sensitive-kind gate key off the kind derived
    // from event_json, not a caller claim: a duplicate `kind` key resolves (serde
    // last-wins, matching the signer) to 22242 and is gated as relay-auth.
    #[test]
    fn derived_kind_drives_relay_auth_not_a_caller_claim() {
        let mut i = base();
        i.event_json = r#"{"kind":1,"tags":[["relay","wss://relay.notallowed.com"]],"kind":22242}"#
            .to_string();
        i.relay_whitelist = vec!["relay.allowed.com".to_string()];
        i.is_opted_in = true;
        i.policy_mode = PolicyMode::Auto;
        i.opt_in_rate_check = Some(allowed());
        assert_eq!(
            reject_reason(&evaluate_nip55_request(i)),
            "deny_relay_whitelist"
        );
    }

    // A SignEvent whose kind cannot be derived from the bytes fails closed.
    #[test]
    fn sign_event_missing_kind_rejects() {
        let mut i = base();
        i.event_json = r#"{"tags":[]}"#.to_string();
        assert_eq!(
            reject_reason(&evaluate_nip55_request(i)),
            "invalid_event_kind"
        );
    }

    #[test]
    fn sign_event_out_of_range_kind_rejects() {
        let mut i = base();
        i.event_json = r#"{"kind":70000}"#.to_string(); // > u16::MAX
        assert_eq!(
            reject_reason(&evaluate_nip55_request(i)),
            "invalid_event_kind"
        );
    }

    #[test]
    fn sign_event_malformed_json_rejects() {
        let mut i = base();
        i.event_json = "not json".to_string();
        assert_eq!(
            reject_reason(&evaluate_nip55_request(i)),
            "invalid_event_kind"
        );
    }

    // Even opted-in under an Auto policy, a sensitive kind in the bytes escalates
    // to the UI rather than auto-approving.
    #[test]
    fn sensitive_kind_in_bytes_blocks_auto_approve() {
        let mut i = base();
        i.event_json = r#"{"kind":4}"#.to_string();
        i.is_opted_in = true;
        i.policy_mode = PolicyMode::Auto;
        i.opt_in_rate_check = Some(allowed());
        assert!(is_require_ui(&evaluate_nip55_request(i)));
    }

    // Gate 6: sign policy.
    #[test]
    fn opted_in_auto_policy_benign_auto_approves() {
        let mut i = base();
        i.is_opted_in = true;
        i.policy_mode = PolicyMode::Auto;
        i.opt_in_rate_check = Some(allowed());
        assert_eq!(evaluate_nip55_request(i), Nip55Outcome::AutoApprove);
    }

    #[test]
    fn not_opted_in_auto_policy_never_auto_approves() {
        let mut i = base();
        i.is_opted_in = false;
        i.policy_mode = PolicyMode::Auto;
        // Falls through to gate 7; no stored grant -> RequireUi (not AutoApprove).
        assert!(is_require_ui(&evaluate_nip55_request(i)));
    }

    #[test]
    fn opted_in_sensitive_kind_falls_to_ui() {
        let mut i = base();
        i.is_opted_in = true;
        i.policy_mode = PolicyMode::Auto;
        i.event_json = r#"{"kind":4}"#.to_string(); // sensitive (NIP-04 DM)
        i.opt_in_rate_check = Some(allowed());
        assert!(is_require_ui(&evaluate_nip55_request(i)));
    }

    #[test]
    fn opted_in_limiter_unavailable_falls_to_ui() {
        let mut i = base();
        i.is_opted_in = true;
        i.policy_mode = PolicyMode::Auto;
        i.opt_in_rate_check = None;
        assert!(is_require_ui(&evaluate_nip55_request(i)));
    }

    #[test]
    fn opted_in_rate_limited_falls_to_ui() {
        let mut i = base();
        i.is_opted_in = true;
        i.policy_mode = PolicyMode::Auto;
        i.opt_in_rate_check = Some(AutoSignDecision::HourlyLimitExceeded);
        assert!(is_require_ui(&evaluate_nip55_request(i)));
    }

    #[test]
    fn opted_in_limiter_unavailable_still_honors_stored_allow() {
        // Limiter unavailable falls to gate 7, which can still auto-approve on a
        // standing ALLOW grant.
        let mut i = base();
        i.is_opted_in = true;
        i.policy_mode = PolicyMode::Auto;
        i.opt_in_rate_check = None;
        i.stored_exact_permission = Some(perm("allow"));
        assert_eq!(evaluate_nip55_request(i), Nip55Outcome::AutoApprove);
    }

    // Gate 7: expiry, lookup, standing decision.
    #[test]
    fn app_expiry_timeout_rejects() {
        let mut i = base();
        i.app_expired = None;
        assert_eq!(reject_reason(&evaluate_nip55_request(i)), "deny_timeout");
    }

    #[test]
    fn app_expired_rejects() {
        let mut i = base();
        i.app_expired = Some(true);
        assert_eq!(reject_reason(&evaluate_nip55_request(i)), "deny_expired");
    }

    #[test]
    fn permission_lookup_timeout_rejects() {
        let mut i = base();
        i.permission_lookup_ok = false;
        assert_eq!(reject_reason(&evaluate_nip55_request(i)), "lookup_timeout");
    }

    #[test]
    fn stored_allow_auto_approves() {
        let mut i = base();
        i.stored_exact_permission = Some(perm("allow"));
        assert_eq!(evaluate_nip55_request(i), Nip55Outcome::AutoApprove);
    }

    #[test]
    fn stored_deny_rejects() {
        let mut i = base();
        i.stored_exact_permission = Some(perm("deny"));
        assert_eq!(reject_reason(&evaluate_nip55_request(i)), "deny");
    }

    #[test]
    fn stored_ask_requires_ui() {
        let mut i = base();
        i.stored_exact_permission = Some(perm("ask"));
        assert!(is_require_ui(&evaluate_nip55_request(i)));
    }

    #[test]
    fn no_stored_decision_requires_ui() {
        assert!(is_require_ui(&evaluate_nip55_request(base())));
    }

    // Gate 7: whitelisted-relay AUTO_ACCEPT with per-app DENY-wins.
    #[test]
    fn whitelisted_relay_auto_approves() {
        let mut i = base();
        i.event_json = relay_auth_event("relay.allowed.com");
        i.relay_whitelist = vec!["relay.allowed.com".to_string()];
        assert_eq!(evaluate_nip55_request(i), Nip55Outcome::AutoApprove);
    }

    #[test]
    fn whitelisted_relay_deny_still_wins() {
        let mut i = base();
        i.event_json = relay_auth_event("relay.allowed.com");
        i.relay_whitelist = vec!["relay.allowed.com".to_string()];
        i.stored_exact_permission = Some(perm("deny"));
        assert_eq!(reject_reason(&evaluate_nip55_request(i)), "deny");
    }

    // A whitelisted relay must not bypass the gate-7 fail-closed checks (expiry
    // and lookup), which run before the AUTO_ACCEPT auto-sign.
    fn whitelisted_relay_base() -> Nip55DecisionInputs {
        let mut i = base();
        i.event_json = relay_auth_event("relay.allowed.com");
        i.relay_whitelist = vec!["relay.allowed.com".to_string()];
        i
    }

    #[test]
    fn whitelisted_relay_app_expiry_timeout_still_rejects() {
        let mut i = whitelisted_relay_base();
        i.app_expired = None;
        assert_eq!(reject_reason(&evaluate_nip55_request(i)), "deny_timeout");
    }

    #[test]
    fn whitelisted_relay_expired_app_still_rejects() {
        let mut i = whitelisted_relay_base();
        i.app_expired = Some(true);
        assert_eq!(reject_reason(&evaluate_nip55_request(i)), "deny_expired");
    }

    #[test]
    fn whitelisted_relay_lookup_timeout_still_rejects() {
        let mut i = whitelisted_relay_base();
        i.permission_lookup_ok = false;
        assert_eq!(reject_reason(&evaluate_nip55_request(i)), "lookup_timeout");
    }

    // Non-SignEvent operations: gate 6 always falls to UI, gate 7 still resolves.
    #[test]
    fn get_public_key_stored_allow_auto_approves() {
        let mut i = base();
        i.request_type = Nip55RequestType::GetPublicKey;
        i.stored_exact_permission = Some(perm("allow"));
        assert_eq!(evaluate_nip55_request(i), Nip55Outcome::AutoApprove);
    }

    #[test]
    fn encrypt_op_requires_ui_with_sensitive_operation_risk() {
        let mut i = base();
        i.request_type = Nip55RequestType::Nip44Encrypt;
        i.is_opted_in = true;
        i.policy_mode = PolicyMode::Auto;
        i.opt_in_rate_check = Some(allowed());
        match evaluate_nip55_request(i) {
            Nip55Outcome::RequireUi { risk, .. } => {
                assert!(risk
                    .factors
                    .contains(&crate::signing_policy::SigningRiskFactor::SensitiveOperation));
            }
            other => panic!("expected RequireUi, got {other:?}"),
        }
    }

    // RequireUi carries the risk-derived auth level.
    #[test]
    fn require_ui_sensitive_kind_escalates_auth() {
        let mut i = base();
        i.event_json = r#"{"kind":4}"#.to_string(); // sensitive -> risk >= 40 -> Biometric
        match evaluate_nip55_request(i) {
            Nip55Outcome::RequireUi {
                required_auth,
                risk,
            } => {
                assert!(risk.score >= 40);
                assert_eq!(required_auth, SigningAuthLevel::Biometric);
            }
            other => panic!("expected RequireUi, got {other:?}"),
        }
    }

    // needs_biometric helper.
    #[test]
    fn needs_biometric_rules() {
        assert!(!nip55_needs_biometric(
            Nip55RequestType::GetPublicKey,
            SigningAuthLevel::None
        ));
        assert!(nip55_needs_biometric(
            Nip55RequestType::GetPublicKey,
            SigningAuthLevel::Pin
        ));
        assert!(nip55_needs_biometric(
            Nip55RequestType::GetPublicKey,
            SigningAuthLevel::Explicit
        ));
        assert!(nip55_needs_biometric(
            Nip55RequestType::SignEvent,
            SigningAuthLevel::None
        ));
    }
}
