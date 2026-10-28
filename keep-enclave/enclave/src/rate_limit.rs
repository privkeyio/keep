// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Token buckets behind the policy's per-minute, per-hour and per-day rules.
//!
//! Nothing here is persisted, so the enclave cannot know what a key signed
//! before it last started. Rather than trust the host about that, every
//! bucket is taken to have been empty when the enclave started (and again
//! when a policy is loaded) and to have refilled at its rule's rate since.
//! A restart forced by the host therefore buys nothing beyond the normal
//! refill. The cost is a wait after every launch, since signing needs a
//! policy and loading one drains the buckets: a rule allowing `max`
//! signatures per window allows its first one window/`max` after the policy
//! is loaded, and its full burst a whole window after. Each running enclave
//! keeps its own count, so these limits bound one enclave, not every
//! enclave that can unseal the key.
//!
//! A bucket belongs to a key's public key, not the name the host imported it
//! under, so one secret imported under several names shares its limits, and
//! to the rule's window and maximum, so two rules on one key never share a
//! bucket and each is held to its own maximum.

use std::collections::HashMap;
use std::time::{Duration, Instant};

const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Window {
    Minute,
    Hour,
    Day,
}

impl Window {
    fn length(self) -> Duration {
        match self {
            Window::Minute => Duration::from_secs(60),
            Window::Hour => Duration::from_secs(3_600),
            Window::Day => Duration::from_secs(86_400),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct BucketKey {
    window: Window,
    pubkey: [u8; 32],
    max: u32,
}

#[derive(Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    refill_rate: f64,
}

impl TokenBucket {
    /// A bucket first used at `now`, refilled from empty since `drained_at`.
    fn new(window: Window, max: u32, drained_at: Instant, now: Instant) -> Self {
        let capacity = f64::from(max);
        let refill_rate = capacity / window.length().as_secs_f64();
        let elapsed = now.saturating_duration_since(drained_at).as_secs_f64();
        Self {
            tokens: (elapsed * refill_rate).min(capacity),
            last_refill: now,
            capacity,
            refill_rate,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }
}

pub struct RateLimiter {
    buckets: HashMap<BucketKey, TokenBucket>,
    drained_at: Instant,
    last_cleanup: Instant,
    #[cfg(test)]
    skew: Duration,
}

impl RateLimiter {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            buckets: HashMap::new(),
            drained_at: now,
            last_cleanup: now,
            #[cfg(test)]
            skew: Duration::ZERO,
        }
    }

    fn now(&self) -> Instant {
        let now = Instant::now();
        #[cfg(test)]
        let now = now + self.skew;
        now
    }

    /// Whether `pubkey` has a signature left under a rule allowing `max` per
    /// `window`. Asking spends nothing: [`RateLimiter::record`] does, once a
    /// signature is made.
    pub fn allows(&mut self, window: Window, pubkey: &[u8; 32], max: u32) -> bool {
        let now = self.now();
        self.bucket(window, pubkey, max, now).tokens >= 1.0
    }

    /// Count one signature by `pubkey` against every rule in `limits`,
    /// whether or not evaluating the policy consulted that rule, so a branch
    /// that let the signature through another way still counts. A bucket the
    /// signature finds empty stays empty rather than going into debt.
    pub fn record(&mut self, pubkey: &[u8; 32], limits: impl IntoIterator<Item = (Window, u32)>) {
        let now = self.now();
        for (window, max) in limits {
            let bucket = self.bucket(window, pubkey, max, now);
            bucket.tokens = (bucket.tokens - 1.0).max(0.0);
        }
    }

    /// Empty every bucket, as at launch. Loading a policy does this, so a
    /// looser policy the host loaded first cannot leave its allowance behind.
    pub fn drain(&mut self) {
        self.buckets.clear();
        self.drained_at = self.now();
    }

    fn bucket(
        &mut self,
        window: Window,
        pubkey: &[u8; 32],
        max: u32,
        now: Instant,
    ) -> &mut TokenBucket {
        self.maybe_cleanup(now);
        let drained_at = self.drained_at;
        let bucket = self
            .buckets
            .entry(BucketKey {
                window,
                pubkey: *pubkey,
                max,
            })
            .or_insert_with(|| TokenBucket::new(window, max, drained_at, now));
        bucket.refill(now);
        bucket
    }

    /// Drop buckets left alone for a whole window. Such a bucket is full, and
    /// so is the one made in its place later, since its refill counts from
    /// the last drain, which is at least that long ago.
    fn maybe_cleanup(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_cleanup) < CLEANUP_INTERVAL {
            return;
        }
        self.buckets.retain(|key, bucket| {
            now.saturating_duration_since(bucket.last_refill) <= key.window.length()
        });
        self.last_cleanup = now;
    }

    /// Run the limiter's clock `by` ahead.
    #[cfg(test)]
    pub fn advance(&mut self, by: Duration) {
        self.skew += by;
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

    const KEY: [u8; 32] = [1u8; 32];
    const OTHER: [u8; 32] = [2u8; 32];

    fn spend(limiter: &mut RateLimiter, pubkey: &[u8; 32], window: Window, max: u32) -> bool {
        if !limiter.allows(window, pubkey, max) {
            return false;
        }
        limiter.record(pubkey, [(window, max)]);
        true
    }

    #[test]
    fn a_fresh_limiter_allows_nothing_until_a_token_has_refilled() {
        let mut limiter = RateLimiter::new();
        assert!(!limiter.allows(Window::Minute, &KEY, 5));
        assert!(!limiter.allows(Window::Hour, &KEY, 5));
        assert!(!limiter.allows(Window::Day, &KEY, 5));
        limiter.advance(Duration::from_secs(12));
        assert!(spend(&mut limiter, &KEY, Window::Minute, 5));
        assert!(!spend(&mut limiter, &KEY, Window::Minute, 5));
    }

    #[test]
    fn a_full_window_after_launch_allows_the_whole_burst_and_no_more() {
        let mut limiter = RateLimiter::new();
        limiter.advance(Duration::from_secs(60));
        for _ in 0..5 {
            assert!(spend(&mut limiter, &KEY, Window::Minute, 5));
        }
        assert!(!spend(&mut limiter, &KEY, Window::Minute, 5));
        assert!(spend(&mut limiter, &OTHER, Window::Minute, 5));
    }

    #[test]
    fn a_bucket_refills_at_its_rate() {
        let mut limiter = RateLimiter::new();
        limiter.advance(Duration::from_secs(60));
        for _ in 0..5 {
            assert!(spend(&mut limiter, &KEY, Window::Minute, 5));
        }
        assert!(!spend(&mut limiter, &KEY, Window::Minute, 5));
        limiter.advance(Duration::from_secs(12));
        assert!(spend(&mut limiter, &KEY, Window::Minute, 5));
        assert!(!spend(&mut limiter, &KEY, Window::Minute, 5));
    }

    #[test]
    fn draining_empties_buckets_already_in_use() {
        let mut limiter = RateLimiter::new();
        limiter.advance(Duration::from_secs(3_600));
        assert!(limiter.allows(Window::Minute, &KEY, 5));
        limiter.drain();
        assert!(!limiter.allows(Window::Minute, &KEY, 5));
        assert!(!limiter.allows(Window::Minute, &OTHER, 5));
    }

    #[test]
    fn asking_spends_nothing() {
        let mut limiter = RateLimiter::new();
        limiter.advance(Duration::from_secs(60));
        for _ in 0..100 {
            assert!(limiter.allows(Window::Minute, &KEY, 1));
        }
        limiter.record(&KEY, [(Window::Minute, 1)]);
        assert!(!limiter.allows(Window::Minute, &KEY, 1));
    }

    #[test]
    fn each_maximum_is_held_to_its_own_bucket() {
        let mut limiter = RateLimiter::new();
        limiter.advance(Duration::from_secs(60));
        let both = [(Window::Minute, 100), (Window::Minute, 2)];
        for _ in 0..2 {
            assert!(limiter.allows(Window::Minute, &KEY, 100));
            assert!(limiter.allows(Window::Minute, &KEY, 2));
            limiter.record(&KEY, both);
        }
        assert!(limiter.allows(Window::Minute, &KEY, 100));
        assert!(!limiter.allows(Window::Minute, &KEY, 2));
    }

    #[test]
    fn an_empty_bucket_does_not_go_into_debt() {
        let mut limiter = RateLimiter::new();
        limiter.advance(Duration::from_secs(60));
        for _ in 0..50 {
            limiter.record(&KEY, [(Window::Minute, 5)]);
        }
        limiter.advance(Duration::from_secs(12));
        assert!(limiter.allows(Window::Minute, &KEY, 5));
    }

    #[test]
    fn a_zero_maximum_never_allows() {
        let mut limiter = RateLimiter::new();
        limiter.advance(Duration::from_secs(86_400));
        assert!(!limiter.allows(Window::Minute, &KEY, 0));
        assert!(!limiter.allows(Window::Day, &KEY, 0));
    }

    #[test]
    fn an_idle_bucket_cleaned_up_comes_back_as_it_left() {
        let mut limiter = RateLimiter::new();
        limiter.advance(Duration::from_secs(60));
        assert!(spend(&mut limiter, &KEY, Window::Minute, 5));
        limiter.advance(Duration::from_secs(400));
        assert!(limiter.allows(Window::Minute, &OTHER, 5));
        assert!(!limiter.buckets.contains_key(&BucketKey {
            window: Window::Minute,
            pubkey: KEY,
            max: 5
        }));
        for _ in 0..5 {
            assert!(spend(&mut limiter, &KEY, Window::Minute, 5));
        }
        assert!(!spend(&mut limiter, &KEY, Window::Minute, 5));
    }

    #[test]
    fn cleanup_keeps_a_bucket_still_refilling() {
        let mut limiter = RateLimiter::new();
        limiter.advance(Duration::from_secs(86_400));
        for _ in 0..5 {
            assert!(spend(&mut limiter, &KEY, Window::Hour, 5));
        }
        limiter.advance(CLEANUP_INTERVAL + Duration::from_secs(1));
        assert!(!limiter.allows(Window::Hour, &KEY, 5));
    }
}
