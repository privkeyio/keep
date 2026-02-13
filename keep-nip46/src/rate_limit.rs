// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub max_per_minute: u32,
    pub max_per_hour: u32,
    pub max_per_day: u32,
}

impl RateLimitConfig {
    pub fn new(per_minute: u32, per_hour: u32, per_day: u32) -> Self {
        Self {
            max_per_minute: per_minute,
            max_per_hour: per_hour,
            max_per_day: per_day,
        }
    }

    pub fn permissive() -> Self {
        Self::new(60, 1000, 10000)
    }

    pub fn conservative() -> Self {
        Self::new(10, 100, 1000)
    }

    pub fn strict() -> Self {
        Self::new(5, 50, 500)
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self::conservative()
    }
}

#[derive(Debug, Clone)]
pub struct RateLimiter {
    config: RateLimitConfig,
    requests: VecDeque<DateTime<Utc>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            requests: VecDeque::new(),
        }
    }

    pub fn check(&self) -> RateLimitStatus {
        let now = Utc::now();
        self.check_at(now)
    }

    pub fn check_at(&self, now: DateTime<Utc>) -> RateLimitStatus {
        let minute_ago = now - Duration::minutes(1);
        let hour_ago = now - Duration::hours(1);
        let day_ago = now - Duration::days(1);

        let per_minute = self.requests.iter().filter(|t| **t > minute_ago).count() as u32;
        let per_hour = self.requests.iter().filter(|t| **t > hour_ago).count() as u32;
        let per_day = self.requests.iter().filter(|t| **t > day_ago).count() as u32;

        if per_minute >= self.config.max_per_minute {
            return RateLimitStatus::Exceeded {
                window: "minute".to_string(),
                limit: self.config.max_per_minute,
                current: per_minute,
                retry_after_secs: 60,
            };
        }

        if per_hour >= self.config.max_per_hour {
            return RateLimitStatus::Exceeded {
                window: "hour".to_string(),
                limit: self.config.max_per_hour,
                current: per_hour,
                retry_after_secs: 3600,
            };
        }

        if per_day >= self.config.max_per_day {
            return RateLimitStatus::Exceeded {
                window: "day".to_string(),
                limit: self.config.max_per_day,
                current: per_day,
                retry_after_secs: 86400,
            };
        }

        RateLimitStatus::Allowed {
            remaining_minute: self.config.max_per_minute - per_minute,
            remaining_hour: self.config.max_per_hour - per_hour,
            remaining_day: self.config.max_per_day - per_day,
        }
    }

    pub fn record(&mut self) {
        self.record_at(Utc::now());
    }

    pub fn record_at(&mut self, timestamp: DateTime<Utc>) {
        self.requests.push_back(timestamp);
        self.cleanup_at(timestamp);
    }

    pub fn check_and_record(&mut self) -> RateLimitStatus {
        self.check_and_record_at(Utc::now())
    }

    pub fn check_and_record_at(&mut self, timestamp: DateTime<Utc>) -> RateLimitStatus {
        let status = self.check_at(timestamp);
        if status.is_allowed() {
            self.record_at(timestamp);
        }
        status
    }

    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    pub fn last_used(&self) -> DateTime<Utc> {
        self.requests
            .back()
            .copied()
            .unwrap_or_else(|| DateTime::<Utc>::MIN_UTC)
    }

    pub fn cleanup(&mut self) {
        self.cleanup_at(Utc::now());
    }

    fn cleanup_at(&mut self, now: DateTime<Utc>) {
        let cutoff = now - Duration::days(1);
        while let Some(front) = self.requests.front() {
            if *front < cutoff {
                self.requests.pop_front();
            } else {
                break;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum RateLimitStatus {
    Allowed {
        remaining_minute: u32,
        remaining_hour: u32,
        remaining_day: u32,
    },
    Exceeded {
        window: String,
        limit: u32,
        current: u32,
        retry_after_secs: u32,
    },
}

impl RateLimitStatus {
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitStatus::Allowed { .. })
    }

    #[allow(dead_code)]
    pub fn is_exceeded(&self) -> bool {
        matches!(self, RateLimitStatus::Exceeded { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_allows_within_limits() {
        let config = RateLimitConfig::new(10, 100, 1000);
        let limiter = RateLimiter::new(config);
        assert!(limiter.check().is_allowed());
    }

    #[test]
    fn test_rate_limit_exceeds_minute() {
        let config = RateLimitConfig::new(2, 100, 1000);
        let mut limiter = RateLimiter::new(config);
        let now = Utc::now();

        limiter.record_at(now);
        limiter.record_at(now);
        match limiter.check_at(now) {
            RateLimitStatus::Exceeded { window, limit, .. } => {
                assert_eq!(window, "minute");
                assert_eq!(limit, 2);
            }
            _ => panic!("expected exceeded"),
        }
    }

    #[test]
    fn test_rate_limit_cleanup() {
        let config = RateLimitConfig::new(10, 100, 1000);
        let mut limiter = RateLimiter::new(config);
        let now = Utc::now();
        let two_days_ago = now - Duration::days(2);

        limiter.record_at(two_days_ago);
        limiter.cleanup_at(now);

        assert!(limiter.requests.is_empty());
    }
}
