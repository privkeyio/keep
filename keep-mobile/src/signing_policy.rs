// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::Mutex;

const HIGH_FREQUENCY_THRESHOLD: u32 = 10;
const NEW_APP_THRESHOLD_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_TRACKED_PACKAGES: usize = 500;

const HOURLY_LIMIT: u32 = 100;
const DAILY_LIMIT: u32 = 500;
const UNUSUAL_ACTIVITY_THRESHOLD: u32 = 50;
const UNUSUAL_ACTIVITY_WINDOW_MS: u64 = 60_000;
const COOLING_OFF_PERIOD_MS: u64 = 15 * 60 * 1000;
const HOUR_MS: u64 = 60 * 60 * 1000;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

const SENSITIVE_KINDS: &[u32] = &[
    0,     // Metadata (profile)
    3,     // Contacts (follow list)
    4,     // Encrypted Direct Message (NIP-04)
    13,    // Seal (NIP-59)
    14,    // Direct Message (NIP-17)
    1059,  // Gift Wrap (NIP-59)
    1984,  // Report
    10000, // Mute List
    10002, // Relay List Metadata
    10003, // Bookmark List
    10004, // Search Relay List
    10006, // Blocked Relays List
    10050, // DM Relay List
    22242, // Client Authentication (NIP-42)
    27235, // HTTP Auth (NIP-98)
];

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum SigningAuthLevel {
    None,
    Pin,
    Biometric,
    Explicit,
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum SigningRiskFactor {
    SensitiveEventKind,
    UnusualTime,
    HighFrequency,
    NewApp,
    FirstKind,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct SigningRiskAssessment {
    pub score: u32,
    pub factors: Vec<SigningRiskFactor>,
    pub required_auth: SigningAuthLevel,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct SigningRequestContext {
    pub package_name: String,
    pub event_kind: Option<u32>,
    pub current_hour: u32,
    pub recent_request_count: u32,
    pub has_signed_kind_before: bool,
    pub app_age_ms: Option<u64>,
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum AutoSignDecision {
    Allowed { hourly_count: u32, daily_count: u32 },
    HourlyLimitExceeded,
    DailyLimitExceeded,
    UnusualActivity,
    CoolingOff { until_ms: u64 },
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum SignPolicyEvaluation {
    AutoApprove,
    FallToUi,
    Denied { reason: String },
}

#[uniffi::export]
pub fn is_sensitive_kind(kind: u32) -> bool {
    SENSITIVE_KINDS.contains(&kind) || (30000..=39999).contains(&kind)
}

#[uniffi::export]
pub fn sensitive_kind_warning(kind: u32) -> Option<String> {
    let warning = match kind {
        0 => "Modifying profile metadata can affect your identity across all Nostr clients",
        3 => "Modifying contacts can affect who you follow across all Nostr clients",
        4 => "Encrypted direct messages contain private communications",
        13 => "Sealed events contain encrypted private communications",
        14 => "Direct messages contain private communications",
        1059 => "Gift wrapped events may contain private communications",
        1984 => "Reports can affect reputation and content moderation",
        10000 => "Modifying mute list can affect your experience across all Nostr clients",
        10002 => "Modifying relay list can affect your connectivity across all Nostr clients",
        10003 => "Modifying bookmarks can affect your saved content across all Nostr clients",
        10004 => "Modifying search relay list can affect your search experience",
        10006 => "Modifying blocked relays can affect your connectivity",
        10050 => {
            "Modifying DM relay list can affect your private messaging across all Nostr clients"
        }
        22242 => "Client authentication can grant relay access permissions",
        27235 => "HTTP authentication can authorize external service access",
        k if (30000..=39999).contains(&k) => {
            return Some(
                "Replaceable events can be overwritten and may contain sensitive data".to_string(),
            );
        }
        _ => return None,
    };
    Some(warning.to_string())
}

#[uniffi::export]
pub fn assess_signing_risk(ctx: SigningRequestContext) -> SigningRiskAssessment {
    let mut factors = Vec::new();

    if let Some(kind) = ctx.event_kind {
        if is_sensitive_kind(kind) {
            factors.push(SigningRiskFactor::SensitiveEventKind);
        }
        if !ctx.has_signed_kind_before {
            factors.push(SigningRiskFactor::FirstKind);
        }
    }

    if ctx.recent_request_count > HIGH_FREQUENCY_THRESHOLD {
        factors.push(SigningRiskFactor::HighFrequency);
    }

    if ctx.current_hour < 6 || ctx.current_hour >= 23 {
        factors.push(SigningRiskFactor::UnusualTime);
    }

    match ctx.app_age_ms {
        None => factors.push(SigningRiskFactor::NewApp),
        Some(age) if age < NEW_APP_THRESHOLD_MS => factors.push(SigningRiskFactor::NewApp),
        _ => {}
    }

    let score: u32 = factors
        .iter()
        .map(|f| match f {
            SigningRiskFactor::SensitiveEventKind => 40,
            SigningRiskFactor::UnusualTime => 10,
            SigningRiskFactor::HighFrequency => 20,
            SigningRiskFactor::NewApp => 15,
            SigningRiskFactor::FirstKind => 15,
        })
        .sum::<u32>()
        .min(100);

    let required_auth = if score >= 60 {
        SigningAuthLevel::Explicit
    } else if score >= 40 {
        SigningAuthLevel::Biometric
    } else if score >= 20 {
        SigningAuthLevel::Pin
    } else {
        SigningAuthLevel::None
    };

    SigningRiskAssessment {
        score,
        factors,
        required_auth,
    }
}

struct UsageWindow {
    count: u32,
    window_start_ms: u64,
}

#[derive(uniffi::Object)]
pub struct SigningRateLimiter {
    state: Mutex<RateLimiterState>,
}

impl Default for SigningRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

struct RateLimiterState {
    hourly: HashMap<String, UsageWindow>,
    daily: HashMap<String, UsageWindow>,
    recent: HashMap<String, UsageWindow>,
    cooled_off_until: HashMap<String, u64>,
}

#[uniffi::export]
impl SigningRateLimiter {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(RateLimiterState {
                hourly: HashMap::new(),
                daily: HashMap::new(),
                recent: HashMap::new(),
                cooled_off_until: HashMap::new(),
            }),
        }
    }

    pub fn check_and_record(&self, package_name: String, now_ms: u64) -> AutoSignDecision {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(&until) = state.cooled_off_until.get(&package_name) {
            if now_ms < until {
                return AutoSignDecision::CoolingOff { until_ms: until };
            }
            state.cooled_off_until.remove(&package_name);
        }

        let hourly = increment_usage(&mut state.hourly, &package_name, now_ms, HOUR_MS);
        if hourly > HOURLY_LIMIT {
            state
                .cooled_off_until
                .insert(package_name, now_ms + COOLING_OFF_PERIOD_MS);
            return AutoSignDecision::HourlyLimitExceeded;
        }

        let daily = increment_usage(&mut state.daily, &package_name, now_ms, DAY_MS);
        if daily > DAILY_LIMIT {
            state
                .cooled_off_until
                .insert(package_name, now_ms + COOLING_OFF_PERIOD_MS);
            return AutoSignDecision::DailyLimitExceeded;
        }

        let recent = increment_usage(
            &mut state.recent,
            &package_name,
            now_ms,
            UNUSUAL_ACTIVITY_WINDOW_MS,
        );
        if recent > UNUSUAL_ACTIVITY_THRESHOLD {
            state
                .cooled_off_until
                .insert(package_name, now_ms + COOLING_OFF_PERIOD_MS);
            return AutoSignDecision::UnusualActivity;
        }

        evict_if_needed(&mut state.hourly);
        evict_if_needed(&mut state.daily);
        evict_if_needed(&mut state.recent);

        AutoSignDecision::Allowed {
            hourly_count: hourly,
            daily_count: daily,
        }
    }

    pub fn clear_cooling_off(&self, package_name: String) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.cooled_off_until.remove(&package_name);
    }

    pub fn clear_all(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.hourly.clear();
        state.daily.clear();
        state.recent.clear();
        state.cooled_off_until.clear();
    }

    pub fn get_usage_stats(&self, package_name: String, now_ms: u64) -> Vec<u32> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let hourly = get_usage_count(&state.hourly, &package_name, now_ms, HOUR_MS);
        let daily = get_usage_count(&state.daily, &package_name, now_ms, DAY_MS);
        vec![hourly, daily, HOURLY_LIMIT, DAILY_LIMIT]
    }
}

#[uniffi::export]
pub fn evaluate_sign_policy(
    policy_mode: String,
    event_kind: Option<u32>,
    is_opted_in: bool,
    rate_check: AutoSignDecision,
) -> SignPolicyEvaluation {
    match policy_mode.as_str() {
        "manual" => SignPolicyEvaluation::FallToUi,
        "auto" => {
            if let Some(kind) = event_kind {
                if is_sensitive_kind(kind) {
                    return SignPolicyEvaluation::FallToUi;
                }
            }

            if !is_opted_in {
                return SignPolicyEvaluation::FallToUi;
            }

            match rate_check {
                AutoSignDecision::Allowed { .. } => SignPolicyEvaluation::AutoApprove,
                AutoSignDecision::HourlyLimitExceeded => SignPolicyEvaluation::Denied {
                    reason: "deny_hourly_limit".to_string(),
                },
                AutoSignDecision::DailyLimitExceeded => SignPolicyEvaluation::Denied {
                    reason: "deny_daily_limit".to_string(),
                },
                AutoSignDecision::UnusualActivity => SignPolicyEvaluation::Denied {
                    reason: "deny_unusual_activity".to_string(),
                },
                AutoSignDecision::CoolingOff { .. } => SignPolicyEvaluation::Denied {
                    reason: "deny_cooling_off".to_string(),
                },
            }
        }
        _ => SignPolicyEvaluation::FallToUi,
    }
}

fn increment_usage(
    map: &mut HashMap<String, UsageWindow>,
    package_name: &str,
    now_ms: u64,
    window_ms: u64,
) -> u32 {
    let entry = map.entry(package_name.to_string()).or_insert(UsageWindow {
        count: 0,
        window_start_ms: now_ms,
    });

    let window_expired =
        entry.window_start_ms > now_ms || now_ms - entry.window_start_ms >= window_ms;

    if window_expired {
        entry.count = 1;
        entry.window_start_ms = now_ms;
    } else {
        entry.count += 1;
    }

    entry.count
}

fn get_usage_count(
    map: &HashMap<String, UsageWindow>,
    package_name: &str,
    now_ms: u64,
    window_ms: u64,
) -> u32 {
    match map.get(package_name) {
        Some(w) if w.window_start_ms <= now_ms && now_ms - w.window_start_ms < window_ms => w.count,
        _ => 0,
    }
}

fn evict_if_needed(map: &mut HashMap<String, UsageWindow>) {
    if map.len() > MAX_TRACKED_PACKAGES {
        if let Some(oldest_key) = map
            .iter()
            .min_by_key(|(_, w)| w.window_start_ms)
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest_key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_kinds() {
        assert!(is_sensitive_kind(0));
        assert!(is_sensitive_kind(4));
        assert!(is_sensitive_kind(1059));
        assert!(is_sensitive_kind(30000));
        assert!(is_sensitive_kind(35000));
        assert!(!is_sensitive_kind(1));
        assert!(!is_sensitive_kind(7));
        assert!(!is_sensitive_kind(29999));
        assert!(!is_sensitive_kind(40000));
    }

    #[test]
    fn test_sensitive_kind_warnings() {
        assert!(sensitive_kind_warning(0).is_some());
        assert!(sensitive_kind_warning(4).is_some());
        assert!(sensitive_kind_warning(30001).is_some());
        assert!(sensitive_kind_warning(1).is_none());
    }

    #[test]
    fn test_risk_assessment_no_factors() {
        let ctx = SigningRequestContext {
            package_name: "com.test".to_string(),
            event_kind: Some(1),
            current_hour: 12,
            recent_request_count: 0,
            has_signed_kind_before: true,
            app_age_ms: Some(48 * 60 * 60 * 1000),
        };
        let result = assess_signing_risk(ctx);
        assert_eq!(result.score, 0);
        assert!(result.factors.is_empty());
        assert_eq!(result.required_auth, SigningAuthLevel::None);
    }

    #[test]
    fn test_risk_assessment_sensitive_kind() {
        let ctx = SigningRequestContext {
            package_name: "com.test".to_string(),
            event_kind: Some(4),
            current_hour: 12,
            recent_request_count: 0,
            has_signed_kind_before: true,
            app_age_ms: Some(48 * 60 * 60 * 1000),
        };
        let result = assess_signing_risk(ctx);
        assert!(result
            .factors
            .contains(&SigningRiskFactor::SensitiveEventKind));
        assert_eq!(result.required_auth, SigningAuthLevel::Biometric);
    }

    #[test]
    fn test_risk_assessment_high_score() {
        let ctx = SigningRequestContext {
            package_name: "com.test".to_string(),
            event_kind: Some(4),
            current_hour: 3,
            recent_request_count: 20,
            has_signed_kind_before: false,
            app_age_ms: None,
        };
        let result = assess_signing_risk(ctx);
        assert_eq!(result.required_auth, SigningAuthLevel::Explicit);
    }

    #[test]
    fn test_rate_limiter_allowed() {
        let limiter = SigningRateLimiter::new();
        let result = limiter.check_and_record("com.test".to_string(), 1000);
        assert!(matches!(result, AutoSignDecision::Allowed { .. }));
    }

    #[test]
    fn test_rate_limiter_hourly_limit() {
        let limiter = SigningRateLimiter::new();
        let base = 1_000_000u64;
        // Space 1201ms apart: stays within hourly window (100*1201=120100 < 3600000)
        // and avoids unusual activity trigger (~50 per 60s window, threshold is >50)
        let gap = 1201u64;
        for i in 0..HOURLY_LIMIT {
            let ts = base + (i as u64) * gap;
            let result = limiter.check_and_record("com.test".to_string(), ts);
            assert!(
                matches!(result, AutoSignDecision::Allowed { .. }),
                "Expected Allowed at iteration {i}, got {:?}",
                result
            );
        }
        let ts = base + (HOURLY_LIMIT as u64) * gap;
        let result = limiter.check_and_record("com.test".to_string(), ts);
        assert!(matches!(result, AutoSignDecision::HourlyLimitExceeded));
    }

    #[test]
    fn test_rate_limiter_cooling_off() {
        let limiter = SigningRateLimiter::new();
        for i in 0..=HOURLY_LIMIT {
            limiter.check_and_record("com.test".to_string(), 1000 + i as u64);
        }
        let result = limiter.check_and_record("com.test".to_string(), 2000);
        assert!(matches!(result, AutoSignDecision::CoolingOff { .. }));
    }

    #[test]
    fn test_evaluate_sign_policy_manual() {
        let result = evaluate_sign_policy(
            "manual".to_string(),
            None,
            false,
            AutoSignDecision::Allowed {
                hourly_count: 0,
                daily_count: 0,
            },
        );
        assert_eq!(result, SignPolicyEvaluation::FallToUi);
    }

    #[test]
    fn test_evaluate_sign_policy_auto_sensitive() {
        let result = evaluate_sign_policy(
            "auto".to_string(),
            Some(4),
            true,
            AutoSignDecision::Allowed {
                hourly_count: 1,
                daily_count: 1,
            },
        );
        assert_eq!(result, SignPolicyEvaluation::FallToUi);
    }

    #[test]
    fn test_evaluate_sign_policy_auto_approved() {
        let result = evaluate_sign_policy(
            "auto".to_string(),
            Some(1),
            true,
            AutoSignDecision::Allowed {
                hourly_count: 1,
                daily_count: 1,
            },
        );
        assert_eq!(result, SignPolicyEvaluation::AutoApprove);
    }

    #[test]
    fn test_evaluate_sign_policy_auto_not_opted_in() {
        let result = evaluate_sign_policy(
            "auto".to_string(),
            Some(1),
            false,
            AutoSignDecision::Allowed {
                hourly_count: 0,
                daily_count: 0,
            },
        );
        assert_eq!(result, SignPolicyEvaluation::FallToUi);
    }
}
