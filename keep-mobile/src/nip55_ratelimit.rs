// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! NIP-55 request rate limiting: the coarse per-package front-door limiter and
//! the request-count velocity thresholds. Both policies live here in Rust; the
//! Android side keeps the per-request Room velocity log (an event log, like the
//! audit log) and feeds the counts in.

use std::collections::HashMap;
use std::sync::Mutex;

const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
const WEEK_MS: i64 = 7 * DAY_MS;

const VELOCITY_HOURLY_LIMIT: u32 = 1000;
const VELOCITY_DAILY_LIMIT: u32 = 5000;
const VELOCITY_WEEKLY_LIMIT: u32 = 20000;

/// Outcome of the request-count velocity check. `Blocked` carries the window
/// length so the caller can derive a reset time from its oldest logged request.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum Nip55VelocityResult {
    Allowed,
    Blocked { reason: String, window_ms: i64 },
}

/// Apply the hourly/daily/weekly request-count limits to the supplied window
/// counts (queried from the Android velocity log). The thresholds and ordering
/// are the single source of truth here. Mirrors `PermissionStore.checkLimit`.
#[uniffi::export]
pub fn nip55_check_velocity(
    hourly_count: u32,
    daily_count: u32,
    weekly_count: u32,
) -> Nip55VelocityResult {
    if hourly_count >= VELOCITY_HOURLY_LIMIT {
        return Nip55VelocityResult::Blocked {
            reason: format!("Hourly limit ({hourly_count}/{VELOCITY_HOURLY_LIMIT})"),
            window_ms: HOUR_MS,
        };
    }
    if daily_count >= VELOCITY_DAILY_LIMIT {
        return Nip55VelocityResult::Blocked {
            reason: format!("Daily limit ({daily_count}/{VELOCITY_DAILY_LIMIT})"),
            window_ms: DAY_MS,
        };
    }
    if weekly_count >= VELOCITY_WEEKLY_LIMIT {
        return Nip55VelocityResult::Blocked {
            reason: format!("Weekly limit ({weekly_count}/{VELOCITY_WEEKLY_LIMIT})"),
            window_ms: WEEK_MS,
        };
    }
    Nip55VelocityResult::Allowed
}

const FRONT_DOOR_WINDOW_MS: u64 = 1000;
const FRONT_DOOR_MAX_REQUESTS: u32 = 30;
const FRONT_DOOR_MAX_ENTRIES: usize = 1000;

struct RateEntry {
    count: u32,
    window_start_ms: u64,
}

/// Coarse front-door limiter: at most 30 requests per second per caller,
/// checked before any other work. In-memory and transient (a 1-second window
/// need not survive a restart); the monotonic clock is supplied by the caller.
/// Mirrors keep-android `RateLimiter`.
#[derive(uniffi::Object)]
pub struct Nip55RequestRateLimiter {
    entries: Mutex<HashMap<String, RateEntry>>,
}

impl Default for Nip55RequestRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[uniffi::export]
impl Nip55RequestRateLimiter {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Record a request and return whether it is within the per-second limit.
    /// A blank package name is always rejected.
    pub fn check(&self, package_name: String, now_elapsed_ms: u64) -> bool {
        if package_name.is_empty() {
            return false;
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());

        match entries.get_mut(&package_name) {
            Some(entry) => {
                if now_elapsed_ms.saturating_sub(entry.window_start_ms) >= FRONT_DOOR_WINDOW_MS {
                    entry.count = 1;
                    entry.window_start_ms = now_elapsed_ms;
                    true
                } else {
                    entry.count = entry.count.saturating_add(1);
                    entry.count <= FRONT_DOOR_MAX_REQUESTS
                }
            }
            None => {
                if entries.len() >= FRONT_DOOR_MAX_ENTRIES {
                    if let Some(oldest) = entries
                        .iter()
                        .min_by_key(|(_, e)| e.window_start_ms)
                        .map(|(k, _)| k.clone())
                    {
                        entries.remove(&oldest);
                    }
                }
                entries.insert(
                    package_name,
                    RateEntry {
                        count: 1,
                        window_start_ms: now_elapsed_ms,
                    },
                );
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn velocity_allows_under_limits() {
        assert_eq!(nip55_check_velocity(0, 0, 0), Nip55VelocityResult::Allowed);
        assert_eq!(
            nip55_check_velocity(999, 4999, 19999),
            Nip55VelocityResult::Allowed
        );
    }

    #[test]
    fn velocity_blocks_hourly_first() {
        match nip55_check_velocity(1000, 0, 0) {
            Nip55VelocityResult::Blocked { window_ms, .. } => assert_eq!(window_ms, HOUR_MS),
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn velocity_blocks_daily_and_weekly() {
        match nip55_check_velocity(0, 5000, 0) {
            Nip55VelocityResult::Blocked { window_ms, .. } => assert_eq!(window_ms, DAY_MS),
            other => panic!("expected daily Blocked, got {other:?}"),
        }
        match nip55_check_velocity(0, 0, 20000) {
            Nip55VelocityResult::Blocked { window_ms, .. } => assert_eq!(window_ms, WEEK_MS),
            other => panic!("expected weekly Blocked, got {other:?}"),
        }
    }

    #[test]
    fn front_door_allows_up_to_limit_then_blocks() {
        let limiter = Nip55RequestRateLimiter::new();
        for i in 0..FRONT_DOOR_MAX_REQUESTS {
            assert!(
                limiter.check("com.app".into(), 1000),
                "request {i} should pass"
            );
        }
        // The 31st within the same second is blocked.
        assert!(!limiter.check("com.app".into(), 1000));
    }

    #[test]
    fn front_door_resets_after_window() {
        let limiter = Nip55RequestRateLimiter::new();
        for _ in 0..FRONT_DOOR_MAX_REQUESTS {
            limiter.check("com.app".into(), 1000);
        }
        assert!(!limiter.check("com.app".into(), 1500));
        // New 1-second window -> allowed again.
        assert!(limiter.check("com.app".into(), 2000));
    }

    #[test]
    fn front_door_rejects_blank_package() {
        let limiter = Nip55RequestRateLimiter::new();
        assert!(!limiter.check("".into(), 1000));
    }

    #[test]
    fn front_door_is_per_package() {
        let limiter = Nip55RequestRateLimiter::new();
        for _ in 0..FRONT_DOOR_MAX_REQUESTS {
            limiter.check("com.a".into(), 1000);
        }
        assert!(!limiter.check("com.a".into(), 1000));
        // A different caller is unaffected.
        assert!(limiter.check("com.b".into(), 1000));
    }
}
