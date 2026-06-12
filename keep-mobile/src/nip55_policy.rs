// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! NIP-55 permission policy: the standing-authorization decision, the
//! grant-duration clamp, and the expiry rules for app-scoped signing
//! permissions. This is the single source of truth for the policy; the Android
//! layer owns only the Room storage and supplies the current wall and monotonic
//! clock readings (a platform capability), mirroring how `RiskAssessor` gathers
//! data for the Rust `assess_signing_risk` scorer.

use crate::signing_policy::is_sensitive_kind;

const MINUTE_MS: i64 = 60_000;
const HOUR_MS: i64 = 60 * MINUTE_MS;
const DAY_MS: i64 = 24 * HOUR_MS;

/// How long a granted NIP-55 permission persists. Mirrors keep-android's
/// `nip55/PermissionEntities.kt::PermissionDuration`. `JustThisTime` is the
/// one-shot default (never persisted); `Forever` never expires.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nip55PermissionDuration {
    JustThisTime,
    OneMinute,
    FiveMinutes,
    TenMinutes,
    OneHour,
    OneDay,
    Forever,
}

impl Nip55PermissionDuration {
    fn millis(self) -> Option<i64> {
        match self {
            Self::JustThisTime | Self::Forever => None,
            Self::OneMinute => Some(MINUTE_MS),
            Self::FiveMinutes => Some(5 * MINUTE_MS),
            Self::TenMinutes => Some(10 * MINUTE_MS),
            Self::OneHour => Some(HOUR_MS),
            Self::OneDay => Some(DAY_MS),
        }
    }
}

/// A standing per-(app, request-type, kind) decision. `Ask` and an absent row
/// both mean "prompt the user".
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nip55PermissionDecision {
    Allow,
    Deny,
    Ask,
}

/// A persisted permission row as the Android storage layer holds it. Times are
/// epoch / uptime milliseconds (`i64`, matching Kotlin `Long`);
/// `created_at_elapsed` is `SystemClock.elapsedRealtime()` (0 on legacy rows
/// written before monotonic tracking).
#[derive(uniffi::Record, Clone, Debug)]
pub struct Nip55StoredPermission {
    pub decision: String,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub created_at_elapsed: i64,
    pub duration_ms: Option<i64>,
}

/// Parse a stored decision string. Unknown values fail closed to `Deny`,
/// mirroring `PermissionDecision.fromString`.
fn parse_decision(value: &str) -> Nip55PermissionDecision {
    match value.to_ascii_lowercase().as_str() {
        "allow" => Nip55PermissionDecision::Allow,
        "ask" => Nip55PermissionDecision::Ask,
        _ => Nip55PermissionDecision::Deny,
    }
}

/// Whole-millisecond lifetime of a duration; `None` for the one-shot and
/// forever variants.
#[uniffi::export]
pub fn nip55_duration_millis(duration: Nip55PermissionDuration) -> Option<i64> {
    duration.millis()
}

/// Whether a grant of this duration is written to storage (everything except
/// the one-shot `JustThisTime`).
#[uniffi::export]
pub fn nip55_duration_should_persist(duration: Nip55PermissionDuration) -> bool {
    duration != Nip55PermissionDuration::JustThisTime
}

/// Clamp an about-to-be-granted duration: a `Forever` grant for a sensitive
/// event kind is downgraded to one day, so a single approval can never
/// permanently auto-approve a sensitive operation. Mirrors
/// `PermissionStore.grantPermission`.
#[uniffi::export]
pub fn nip55_effective_grant_duration(
    event_kind: Option<i32>,
    duration: Nip55PermissionDuration,
) -> Nip55PermissionDuration {
    if let Some(kind) = event_kind {
        if kind >= 0
            && is_sensitive_kind(kind as u32)
            && duration == Nip55PermissionDuration::Forever
        {
            return Nip55PermissionDuration::OneDay;
        }
    }
    duration
}

/// True when a `(created_at, duration)` lifetime has expired. Prefers the
/// monotonic (`created_at_elapsed` + `duration_ms`) clock and falls back to
/// wall-clock when the monotonic stamp is absent; a backwards wall-clock jump
/// relative to `created_at` reads as expired (fail-closed against clock
/// manipulation). The single source of truth for NIP-55 expiry, shared by
/// permission rows and per-app settings. Mirrors
/// `PermissionEntities.kt::isTimestampExpired`.
#[uniffi::export]
pub fn nip55_timestamp_expired(
    expires_at: Option<i64>,
    created_at: i64,
    created_at_elapsed: i64,
    duration_ms: Option<i64>,
    now_elapsed_ms: i64,
    now_wall_ms: i64,
) -> bool {
    if expires_at.is_none() && duration_ms.is_none() {
        return false;
    }
    if let Some(duration_ms) = duration_ms {
        if created_at_elapsed > 0 {
            if now_elapsed_ms < created_at_elapsed {
                return true;
            }
            if now_elapsed_ms - created_at_elapsed >= duration_ms {
                return true;
            }
        } else {
            let wall_expiry = created_at.saturating_add(duration_ms);
            if now_wall_ms >= wall_expiry {
                return true;
            }
        }
    }
    if let Some(expires_at) = expires_at {
        let clock_manipulated = now_wall_ms < created_at;
        if clock_manipulated || expires_at <= now_wall_ms {
            return true;
        }
    }
    false
}

fn is_expired(perm: &Nip55StoredPermission, now_elapsed_ms: i64, now_wall_ms: i64) -> bool {
    nip55_timestamp_expired(
        perm.expires_at,
        perm.created_at,
        perm.created_at_elapsed,
        perm.duration_ms,
        now_elapsed_ms,
        now_wall_ms,
    )
}

/// Resolve the standing decision for a request. `exact` is the row keyed by the
/// specific event kind (or the kind-agnostic row when the request carries no
/// kind); `generic` is the kind-agnostic row. A non-sensitive kind falls back
/// to the generic grant; a sensitive kind never does (it must be granted
/// per-kind). `None` means "no standing decision -- prompt the user". Mirrors
/// `PermissionStore.getPermissionDecision`.
#[uniffi::export]
pub fn nip55_resolve_decision(
    exact: Option<Nip55StoredPermission>,
    generic: Option<Nip55StoredPermission>,
    event_kind: Option<i32>,
    now_elapsed_ms: i64,
    now_wall_ms: i64,
) -> Option<Nip55PermissionDecision> {
    if let Some(p) = &exact {
        if !is_expired(p, now_elapsed_ms, now_wall_ms) {
            return Some(parse_decision(&p.decision));
        }
    }
    if let Some(kind) = event_kind {
        if kind >= 0 && !is_sensitive_kind(kind as u32) {
            if let Some(g) = &generic {
                if !is_expired(g, now_elapsed_ms, now_wall_ms) {
                    return Some(parse_decision(&g.decision));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // From signing_policy::SENSITIVE_KINDS: kind 4 (DM) is sensitive, kind 1
    // (text note) is not.
    const SENSITIVE_KIND: i32 = 4;
    const PLAIN_KIND: i32 = 1;

    fn perm(
        decision: &str,
        created_at: i64,
        created_at_elapsed: i64,
        duration_ms: Option<i64>,
    ) -> Nip55StoredPermission {
        Nip55StoredPermission {
            decision: decision.to_string(),
            expires_at: None,
            created_at,
            created_at_elapsed,
            duration_ms,
        }
    }

    #[test]
    fn no_expiry_fields_never_expires() {
        let p = perm("allow", 1_000, 0, None);
        assert!(!is_expired(&p, 10_000_000, 10_000_000));
    }

    #[test]
    fn monotonic_within_window_lives_past_window_expires() {
        // created at elapsed=1000, 1h duration.
        let p = perm("allow", 0, 1_000, Some(HOUR_MS));
        assert!(!is_expired(&p, 1_000 + HOUR_MS - 1, 0));
        assert!(is_expired(&p, 1_000 + HOUR_MS, 0));
    }

    #[test]
    fn monotonic_clock_rewind_reads_expired() {
        // Device rebooted: elapsedRealtime reset below created_at_elapsed.
        let p = perm("allow", 0, 5_000, Some(HOUR_MS));
        assert!(is_expired(&p, 10, 999_999_999));
    }

    #[test]
    fn wall_clock_fallback_when_no_monotonic_stamp() {
        let p = perm("allow", 1_000, 0, Some(HOUR_MS));
        assert!(!is_expired(&p, 0, 1_000 + HOUR_MS - 1));
        assert!(is_expired(&p, 0, 1_000 + HOUR_MS));
    }

    #[test]
    fn legacy_expires_at_clock_manipulation_fails_closed() {
        let p = Nip55StoredPermission {
            decision: "allow".into(),
            expires_at: Some(10_000),
            created_at: 5_000,
            created_at_elapsed: 0,
            duration_ms: None,
        };
        // Wall clock set before created_at -> manipulated -> expired.
        assert!(is_expired(&p, 0, 4_000));
        // Normal: not yet reached.
        assert!(!is_expired(&p, 0, 9_000));
        // Past expiry.
        assert!(is_expired(&p, 0, 10_000));
    }

    #[test]
    fn sensitive_forever_clamps_to_one_day() {
        assert_eq!(
            nip55_effective_grant_duration(Some(SENSITIVE_KIND), Nip55PermissionDuration::Forever),
            Nip55PermissionDuration::OneDay
        );
        // Non-forever sensitive grants are untouched.
        assert_eq!(
            nip55_effective_grant_duration(Some(SENSITIVE_KIND), Nip55PermissionDuration::OneHour),
            Nip55PermissionDuration::OneHour
        );
        // Non-sensitive forever survives.
        assert_eq!(
            nip55_effective_grant_duration(Some(PLAIN_KIND), Nip55PermissionDuration::Forever),
            Nip55PermissionDuration::Forever
        );
        // No kind: forever survives.
        assert_eq!(
            nip55_effective_grant_duration(None, Nip55PermissionDuration::Forever),
            Nip55PermissionDuration::Forever
        );
    }

    #[test]
    fn exact_grant_is_returned() {
        let exact = Some(perm("allow", 0, 0, None));
        assert_eq!(
            nip55_resolve_decision(exact, None, Some(PLAIN_KIND), 0, 0),
            Some(Nip55PermissionDecision::Allow)
        );
    }

    #[test]
    fn non_sensitive_falls_back_to_generic() {
        // No exact row, generic allow, non-sensitive kind -> allow.
        let generic = Some(perm("allow", 0, 0, None));
        assert_eq!(
            nip55_resolve_decision(None, generic, Some(PLAIN_KIND), 0, 0),
            Some(Nip55PermissionDecision::Allow)
        );
    }

    #[test]
    fn sensitive_never_falls_back_to_generic() {
        let generic = Some(perm("allow", 0, 0, None));
        assert_eq!(
            nip55_resolve_decision(None, generic, Some(SENSITIVE_KIND), 0, 0),
            None
        );
    }

    #[test]
    fn expired_exact_does_not_decide() {
        // Exact row expired; no generic -> prompt.
        let exact = Some(perm("allow", 0, 1_000, Some(HOUR_MS)));
        assert_eq!(
            nip55_resolve_decision(exact, None, Some(PLAIN_KIND), 1_000 + HOUR_MS, 0),
            None
        );
    }

    #[test]
    fn deny_is_returned_and_unknown_fails_closed() {
        let deny = Some(perm("deny", 0, 0, None));
        assert_eq!(
            nip55_resolve_decision(deny, None, None, 0, 0),
            Some(Nip55PermissionDecision::Deny)
        );
        let garbage = Some(perm("not-a-decision", 0, 0, None));
        assert_eq!(
            nip55_resolve_decision(garbage, None, None, 0, 0),
            Some(Nip55PermissionDecision::Deny)
        );
    }

    #[test]
    fn nothing_stored_prompts() {
        assert_eq!(
            nip55_resolve_decision(None, None, Some(PLAIN_KIND), 0, 0),
            None
        );
    }

    #[test]
    fn raw_timestamp_export_matches_monotonic_window() {
        // 1h grant, monotonic stamp present.
        assert!(!nip55_timestamp_expired(
            None,
            0,
            1_000,
            Some(HOUR_MS),
            1_000 + HOUR_MS - 1,
            0
        ));
        assert!(nip55_timestamp_expired(
            None,
            0,
            1_000,
            Some(HOUR_MS),
            1_000 + HOUR_MS,
            0
        ));
        // No lifetime fields -> never expires.
        assert!(!nip55_timestamp_expired(
            None,
            0,
            0,
            None,
            i64::MAX,
            i64::MAX
        ));
    }

    #[test]
    fn duration_millis_and_should_persist() {
        assert_eq!(
            nip55_duration_millis(Nip55PermissionDuration::JustThisTime),
            None
        );
        assert_eq!(
            nip55_duration_millis(Nip55PermissionDuration::Forever),
            None
        );
        assert_eq!(
            nip55_duration_millis(Nip55PermissionDuration::OneHour),
            Some(HOUR_MS)
        );
        assert_eq!(
            nip55_duration_millis(Nip55PermissionDuration::OneDay),
            Some(DAY_MS)
        );
        assert!(!nip55_duration_should_persist(
            Nip55PermissionDuration::JustThisTime
        ));
        assert!(nip55_duration_should_persist(
            Nip55PermissionDuration::Forever
        ));
        assert!(nip55_duration_should_persist(
            Nip55PermissionDuration::OneMinute
        ));
    }
}
