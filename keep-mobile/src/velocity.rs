// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::{DateTime, Duration, Utc};
use std::collections::VecDeque;

const MAX_TRACKED_TRANSACTIONS: usize = 10_000;

#[derive(Clone, Debug)]
struct TrackedTransaction {
    timestamp: DateTime<Utc>,
    amount_sats: u64,
}

pub struct VelocityTracker {
    transactions: VecDeque<TrackedTransaction>,
}

impl VelocityTracker {
    pub fn new() -> Self {
        Self {
            transactions: VecDeque::new(),
        }
    }

    pub fn record(&mut self, amount_sats: u64) {
        self.cleanup_old();

        if self.transactions.len() >= MAX_TRACKED_TRANSACTIONS {
            self.transactions.pop_front();
        }

        self.transactions.push_back(TrackedTransaction {
            timestamp: Utc::now(),
            amount_sats,
        });
    }

    pub fn daily_total(&self) -> u64 {
        let cutoff = Utc::now() - Duration::days(1);
        self.transactions
            .iter()
            .filter(|tx| tx.timestamp > cutoff)
            .map(|tx| tx.amount_sats)
            .fold(0u64, |acc, amt| acc.saturating_add(amt))
    }

    pub fn weekly_total(&self) -> u64 {
        let cutoff = Utc::now() - Duration::days(7);
        self.transactions
            .iter()
            .filter(|tx| tx.timestamp > cutoff)
            .map(|tx| tx.amount_sats)
            .fold(0u64, |acc, amt| acc.saturating_add(amt))
    }

    pub fn cleanup_old(&mut self) {
        let cutoff = Utc::now() - Duration::days(7);
        while let Some(front) = self.transactions.front() {
            if front.timestamp <= cutoff {
                self.transactions.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn clear(&mut self) {
        self.transactions.clear();
    }

    #[allow(dead_code)]
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
}

impl Default for VelocityTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_daily_total() {
        let mut tracker = VelocityTracker::new();
        tracker.record(1000);
        tracker.record(2000);
        tracker.record(3000);

        assert_eq!(tracker.daily_total(), 6000);
        assert_eq!(tracker.weekly_total(), 6000);
        assert_eq!(tracker.transaction_count(), 3);
    }

    #[test]
    fn test_saturating_add() {
        let mut tracker = VelocityTracker::new();
        tracker.record(u64::MAX);
        tracker.record(u64::MAX);

        assert_eq!(tracker.daily_total(), u64::MAX);
    }

    #[test]
    fn test_cleanup() {
        let mut tracker = VelocityTracker::new();
        tracker.record(1000);
        tracker.cleanup_old();
        assert_eq!(tracker.transaction_count(), 1);
    }

    #[test]
    fn test_clear() {
        let mut tracker = VelocityTracker::new();
        tracker.record(1000);
        tracker.record(2000);
        tracker.clear();
        assert_eq!(tracker.transaction_count(), 0);
        assert_eq!(tracker.daily_total(), 0);
    }

    #[test]
    fn test_max_transactions_cap() {
        let mut tracker = VelocityTracker::new();
        for _ in 0..MAX_TRACKED_TRANSACTIONS + 100 {
            tracker.record(1);
        }
        assert_eq!(tracker.transaction_count(), MAX_TRACKED_TRANSACTIONS);
    }
}
