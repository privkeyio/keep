// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Request counters for the gateway's per-minute, per-hour and per-day limits.

use std::collections::HashMap;
use std::hash::Hash;

use crate::policy::RequestLimits;

const WINDOWS: [(u64, &str); 3] = [(60, "minute"), (3_600, "hour"), (86_400, "day")];

/// Requests counted in fixed windows of a minute, an hour and a day. A request
/// is counted only when every window has room, so one refused for its rate
/// does not use up the next window.
#[derive(Debug, Default, Clone)]
pub struct Counter {
    windows: [(u64, u32); 3],
}

impl Counter {
    /// Count a request at `now` against `limits`, or name the window that is
    /// full. Windows start at multiples of their length, on the gateway's
    /// clock, which never goes back.
    pub fn hit(&mut self, limits: &RequestLimits, now: u64) -> Result<(), &'static str> {
        let caps = [limits.per_minute, limits.per_hour, limits.per_day];
        for (i, &(len, _)) in WINDOWS.iter().enumerate() {
            let start = now - now % len;
            if self.windows[i].0 != start {
                self.windows[i] = (start, 0);
            }
        }
        for (i, &(_, name)) in WINDOWS.iter().enumerate() {
            if self.windows[i].1 >= caps[i] {
                return Err(name);
            }
        }
        for window in &mut self.windows {
            window.1 += 1;
        }
        Ok(())
    }

    fn idle_since(&self, now: u64) -> bool {
        let day = WINDOWS[2].0;
        self.windows[2].0 != now - now % day
    }
}

/// A counter per key, holding at most `max` keys. Past it, keys idle since the
/// current day began are dropped; if none are, the request is refused rather
/// than forgetting a count.
pub struct Counters<K> {
    max: usize,
    counters: HashMap<K, Counter>,
}

impl<K: Eq + Hash + Copy> Counters<K> {
    pub fn new(max: usize) -> Self {
        Self {
            max,
            counters: HashMap::new(),
        }
    }

    pub fn hit(&mut self, key: K, limits: &RequestLimits, now: u64) -> Result<(), &'static str> {
        if !self.counters.contains_key(&key) && self.counters.len() >= self.max {
            self.counters.retain(|_, c| !c.idle_since(now));
            if self.counters.len() >= self.max {
                return Err("tracker");
            }
        }
        self.counters.entry(key).or_default().hit(limits, now)
    }

    /// Forget `key`'s counts.
    pub fn remove(&mut self, key: &K) {
        self.counters.remove(key);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.counters.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1_800_000_000 - 1_800_000_000 % 86_400;

    fn limits(per_minute: u32, per_hour: u32, per_day: u32) -> RequestLimits {
        RequestLimits {
            per_minute,
            per_hour,
            per_day,
        }
    }

    #[test]
    fn each_window_caps_its_requests_and_refusals_are_not_counted() {
        let l = limits(2, 3, 4);
        let mut c = Counter::default();
        assert_eq!(c.hit(&l, T), Ok(()));
        assert_eq!(c.hit(&l, T + 1), Ok(()));
        for _ in 0..5 {
            assert_eq!(c.hit(&l, T + 2), Err("minute"));
        }
        assert_eq!(c.hit(&l, T + 60), Ok(()));
        assert_eq!(c.hit(&l, T + 61), Err("hour"));
        assert_eq!(c.hit(&l, T + 3_600), Ok(()));
        assert_eq!(c.hit(&l, T + 3_660), Err("day"));
        assert_eq!(c.hit(&l, T + 86_400), Ok(()));
    }

    #[test]
    fn the_tracker_is_bounded_and_refuses_when_nothing_is_idle() {
        let l = limits(10, 10, 10);
        let mut c = Counters::new(2);
        c.hit(1u32, &l, T).unwrap();
        c.hit(2u32, &l, T).unwrap();
        assert_eq!(c.hit(3u32, &l, T + 5), Err("tracker"));
        c.hit(1u32, &l, T + 5).unwrap();
        c.hit(3u32, &l, T + 86_400).unwrap();
        assert_eq!(c.len(), 1, "idle keys were dropped");
        c.remove(&3);
        assert_eq!(c.len(), 0);
    }
}
