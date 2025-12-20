use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    minute_counts: HashMap<String, (Instant, u32)>,
    hour_counts: HashMap<String, (Instant, u32)>,
    day_counts: HashMap<String, (Instant, u32)>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            minute_counts: HashMap::new(),
            hour_counts: HashMap::new(),
            day_counts: HashMap::new(),
        }
    }

    pub fn check_minute(&mut self, key_id: &str, max: u32) -> bool {
        self.check_bucket(&mut self.minute_counts.clone(), key_id, max, Duration::from_secs(60))
    }

    pub fn check_hour(&mut self, key_id: &str, max: u32) -> bool {
        self.check_bucket(&mut self.hour_counts.clone(), key_id, max, Duration::from_secs(3600))
    }

    pub fn check_day(&mut self, key_id: &str, max: u32) -> bool {
        self.check_bucket(&mut self.day_counts.clone(), key_id, max, Duration::from_secs(86400))
    }

    fn check_bucket(
        &mut self,
        bucket: &mut HashMap<String, (Instant, u32)>,
        key_id: &str,
        max: u32,
        window: Duration,
    ) -> bool {
        let now = Instant::now();

        if let Some((start, count)) = bucket.get(key_id) {
            if now.duration_since(*start) > window {
                true
            } else {
                *count < max
            }
        } else {
            true
        }
    }

    pub fn record(&mut self, key_id: &str) {
        let now = Instant::now();
        let key = key_id.to_string();

        Self::record_bucket(&mut self.minute_counts, &key, now, Duration::from_secs(60));
        Self::record_bucket(&mut self.hour_counts, &key, now, Duration::from_secs(3600));
        Self::record_bucket(&mut self.day_counts, &key, now, Duration::from_secs(86400));
    }

    fn record_bucket(
        bucket: &mut HashMap<String, (Instant, u32)>,
        key_id: &str,
        now: Instant,
        window: Duration,
    ) {
        if let Some((start, count)) = bucket.get_mut(key_id) {
            if now.duration_since(*start) > window {
                *start = now;
                *count = 1;
            } else {
                *count += 1;
            }
        } else {
            bucket.insert(key_id.to_string(), (now, 1));
        }
    }

    pub fn clear(&mut self) {
        self.minute_counts.clear();
        self.hour_counts.clear();
        self.day_counts.clear();
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
        let mut limiter = RateLimiter::new();

        assert!(limiter.check_minute("key1", 5));

        for _ in 0..5 {
            limiter.record("key1");
        }

        assert!(!limiter.check_minute("key1", 5));
        assert!(limiter.check_minute("key2", 5));
    }
}
