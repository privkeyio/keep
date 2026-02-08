// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    refill_rate: f64,
}

impl TokenBucket {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
            refill_rate,
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let tokens_to_add = elapsed * self.refill_rate;
        self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
        self.last_refill = now;
    }

    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn is_expired(&self, window: Duration) -> bool {
        self.last_refill.elapsed() > window
    }
}

struct RateLimitBuckets {
    buckets: HashMap<String, TokenBucket>,
    last_cleanup: Instant,
    window: Duration,
}

impl RateLimitBuckets {
    fn new(window: Duration) -> Self {
        Self {
            buckets: HashMap::new(),
            last_cleanup: Instant::now(),
            window,
        }
    }

    fn check(&mut self, key_id: &str, max: u32) -> bool {
        self.maybe_cleanup();

        let capacity = max as f64;
        let refill_rate = capacity / self.window.as_secs_f64();

        let bucket = self
            .buckets
            .entry(key_id.to_string())
            .or_insert_with(|| TokenBucket::new(capacity, refill_rate));

        bucket.try_consume()
    }

    fn record(&mut self, key_id: &str, max: u32) {
        self.maybe_cleanup();

        let capacity = max as f64;
        let refill_rate = capacity / self.window.as_secs_f64();

        self.buckets
            .entry(key_id.to_string())
            .or_insert_with(|| TokenBucket::new(capacity, refill_rate));
    }

    fn maybe_cleanup(&mut self) {
        if self.last_cleanup.elapsed() < CLEANUP_INTERVAL {
            return;
        }

        let window = self.window;
        self.buckets.retain(|_, bucket| !bucket.is_expired(window));
        self.last_cleanup = Instant::now();
    }
}

pub struct RateLimiter {
    minute_buckets: Mutex<RateLimitBuckets>,
    hour_buckets: Mutex<RateLimitBuckets>,
    day_buckets: Mutex<RateLimitBuckets>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            minute_buckets: Mutex::new(RateLimitBuckets::new(Duration::from_secs(60))),
            hour_buckets: Mutex::new(RateLimitBuckets::new(Duration::from_secs(3600))),
            day_buckets: Mutex::new(RateLimitBuckets::new(Duration::from_secs(86400))),
        }
    }

    pub fn check_minute(&self, key_id: &str, max: u32) -> bool {
        let mut buckets = self.minute_buckets.lock().unwrap();
        buckets.check(key_id, max)
    }

    pub fn check_hour(&self, key_id: &str, max: u32) -> bool {
        let mut buckets = self.hour_buckets.lock().unwrap();
        buckets.check(key_id, max)
    }

    pub fn check_day(&self, key_id: &str, max: u32) -> bool {
        let mut buckets = self.day_buckets.lock().unwrap();
        buckets.check(key_id, max)
    }

    pub fn record(&self, key_id: &str) {
        if let Ok(mut buckets) = self.minute_buckets.lock() {
            buckets.record(key_id, 60);
        }
        if let Ok(mut buckets) = self.hour_buckets.lock() {
            buckets.record(key_id, 600);
        }
        if let Ok(mut buckets) = self.day_buckets.lock() {
            buckets.record(key_id, 5000);
        }
    }

    pub fn clear(&self) {
        if let Ok(mut buckets) = self.minute_buckets.lock() {
            buckets.buckets.clear();
        }
        if let Ok(mut buckets) = self.hour_buckets.lock() {
            buckets.buckets.clear();
        }
        if let Ok(mut buckets) = self.day_buckets.lock() {
            buckets.buckets.clear();
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new();

        assert!(limiter.check_minute("key1", 5));

        for _ in 0..4 {
            assert!(limiter.check_minute("key1", 5));
        }

        assert!(!limiter.check_minute("key1", 5));
        assert!(limiter.check_minute("key2", 5));
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(10.0, 10.0);

        for _ in 0..10 {
            assert!(bucket.try_consume());
        }
        assert!(!bucket.try_consume());

        std::thread::sleep(Duration::from_millis(200));
        assert!(bucket.try_consume());
    }
}
