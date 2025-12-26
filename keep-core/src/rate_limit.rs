#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

const MAX_ATTEMPTS: u32 = 5;
const BASE_DELAY_SECS: u64 = 1;
const MAX_DELAY_SECS: u64 = 300;

static RATE_LIMITER: Lazy<Mutex<RateLimiter>> = Lazy::new(|| Mutex::new(RateLimiter::new()));

fn normalize_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

struct RateLimitEntry {
    failed_attempts: u32,
    last_failure: Option<Instant>,
}

impl RateLimitEntry {
    fn new() -> Self {
        Self {
            failed_attempts: 0,
            last_failure: None,
        }
    }

    fn delay_duration(&self) -> Duration {
        if self.failed_attempts < MAX_ATTEMPTS {
            return Duration::ZERO;
        }
        let excess = self.failed_attempts - MAX_ATTEMPTS;
        let delay_secs = BASE_DELAY_SECS.saturating_mul(1u64 << excess.min(8));
        Duration::from_secs(delay_secs.min(MAX_DELAY_SECS))
    }

    fn remaining_delay(&self) -> Duration {
        let Some(last) = self.last_failure else {
            return Duration::ZERO;
        };
        let required = self.delay_duration();
        let elapsed = last.elapsed();
        required.saturating_sub(elapsed)
    }

    fn record_failure(&mut self) {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        self.last_failure = Some(Instant::now());
    }

    fn reset(&mut self) {
        self.failed_attempts = 0;
        self.last_failure = None;
    }
}

struct RateLimiter {
    entries: HashMap<PathBuf, RateLimitEntry>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn get_or_create(&mut self, path: &Path) -> &mut RateLimitEntry {
        self.entries
            .entry(path.to_path_buf())
            .or_insert_with(RateLimitEntry::new)
    }
}

pub fn check_rate_limit(path: &Path) -> Result<(), Duration> {
    let normalized = normalize_path(path);
    let Ok(mut limiter) = RATE_LIMITER.lock() else {
        return Err(Duration::from_secs(MAX_DELAY_SECS));
    };
    let entry = limiter.get_or_create(&normalized);
    let remaining = entry.remaining_delay();
    if remaining > Duration::ZERO {
        Err(remaining)
    } else {
        Ok(())
    }
}

pub fn record_failure(path: &Path) {
    let normalized = normalize_path(path);
    let Ok(mut limiter) = RATE_LIMITER.lock() else {
        return;
    };
    let entry = limiter.get_or_create(&normalized);
    entry.record_failure();
}

pub fn record_success(path: &Path) {
    let normalized = normalize_path(path);
    let Ok(mut limiter) = RATE_LIMITER.lock() else {
        return;
    };
    if let Some(entry) = limiter.entries.get_mut(&normalized) {
        entry.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_path(suffix: &str) -> PathBuf {
        PathBuf::from(format!("/test/rate_limit/{}", suffix))
    }

    #[test]
    fn test_no_delay_on_first_attempts() {
        let path = unique_path("no_delay");

        for _ in 0..MAX_ATTEMPTS {
            assert!(check_rate_limit(&path).is_ok());
            record_failure(&path);
        }
    }

    #[test]
    fn test_delay_after_max_attempts() {
        let path = unique_path("delay_after_max");

        for _ in 0..MAX_ATTEMPTS {
            let _ = check_rate_limit(&path);
            record_failure(&path);
        }

        record_failure(&path);
        let result = check_rate_limit(&path);
        assert!(result.is_err());
        let delay = result.unwrap_err();
        assert!(delay.as_secs() >= BASE_DELAY_SECS);
    }

    #[test]
    fn test_exponential_backoff() {
        let mut entry = RateLimitEntry::new();

        for _ in 0..(MAX_ATTEMPTS - 1) {
            entry.record_failure();
        }
        assert_eq!(entry.delay_duration(), Duration::from_secs(0));

        entry.record_failure();
        assert_eq!(entry.delay_duration(), Duration::from_secs(1));

        entry.record_failure();
        assert_eq!(entry.delay_duration(), Duration::from_secs(2));

        entry.record_failure();
        assert_eq!(entry.delay_duration(), Duration::from_secs(4));

        entry.record_failure();
        assert_eq!(entry.delay_duration(), Duration::from_secs(8));
    }

    #[test]
    fn test_max_delay_cap() {
        let mut entry = RateLimitEntry::new();

        for _ in 0..50 {
            entry.record_failure();
        }

        assert!(entry.delay_duration().as_secs() <= MAX_DELAY_SECS);
    }

    #[test]
    fn test_success_resets_counter() {
        let path = unique_path("success_reset");

        for _ in 0..MAX_ATTEMPTS + 2 {
            let _ = check_rate_limit(&path);
            record_failure(&path);
        }

        record_success(&path);
        assert!(check_rate_limit(&path).is_ok());
    }

    #[test]
    fn test_delay_expires() {
        let path = unique_path("delay_expires");

        for _ in 0..MAX_ATTEMPTS + 1 {
            let _ = check_rate_limit(&path);
            record_failure(&path);
        }

        {
            let mut limiter = RATE_LIMITER.lock().unwrap();
            if let Some(entry) = limiter.entries.get_mut(&path) {
                entry.last_failure = Some(Instant::now() - Duration::from_secs(10));
            }
        }

        assert!(check_rate_limit(&path).is_ok());
    }

    #[test]
    fn test_independent_paths() {
        let path1 = unique_path("independent_1");
        let path2 = unique_path("independent_2");

        for _ in 0..MAX_ATTEMPTS + 2 {
            let _ = check_rate_limit(&path1);
            record_failure(&path1);
        }

        assert!(check_rate_limit(&path2).is_ok());
    }
}
