// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// The only bound on the history, and deliberately a count rather than an age.
///
/// Dropping entries older than the longest limit window looks equivalent and is
/// not: the cutoff comes from the device wall clock, and a clock moved forward
/// past that window matches every entry. Reading the record applied the prune,
/// and the next spend wrote the pruned history back, so a clock pushed eight
/// days ahead and then corrected left `daily_total` and `weekly_total` reading
/// zero permanently, with the limits they back bypassed and no way to recover
/// the history they were counting.
///
/// A count cannot be moved by the clock. The totals already select their own
/// window when they are asked, so nothing needed the stored history to be
/// pruned by time for the limits to be right; the prune only bounded the size,
/// which this does without trusting anything.
const MAX_TRACKED_TRANSACTIONS: usize = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TrackedTransaction {
    timestamp: DateTime<Utc>,
    amount_sats: u64,
}

#[derive(Serialize, Deserialize)]
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

    #[allow(dead_code)]
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
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

    /// Reading the record must not discard what it holds, whatever the clock
    /// says about the age of the entries.
    ///
    /// A spend recorded an hour ago looks eight days old to a device whose
    /// clock was pushed eight days forward, which is what the entries here
    /// stand in for: the age cannot be produced by moving the real clock in a
    /// test, so it is written into the timestamps instead. Pruning on load
    /// dropped exactly these, and the next spend persisted the result, so the
    /// loss outlived the clock being corrected and the daily and weekly limits
    /// were left counting nothing.
    #[test]
    fn a_clock_moved_past_the_window_does_not_erase_the_history() {
        let mut tracker = VelocityTracker::new();
        tracker.transactions.push_back(TrackedTransaction {
            timestamp: Utc::now() - Duration::days(8),
            amount_sats: 1000,
        });
        tracker.transactions.push_back(TrackedTransaction {
            timestamp: Utc::now() - Duration::days(9),
            amount_sats: 2000,
        });
        let stored = tracker.to_bytes().expect("serialize");

        let reloaded = VelocityTracker::from_bytes(&stored).expect("deserialize");
        assert_eq!(
            reloaded.transaction_count(),
            2,
            "reading the record must not discard what it holds"
        );

        // Recording a spend persists the history as it stands, so a write
        // cannot launder the loss into storage either.
        let mut reloaded = reloaded;
        reloaded.record(500);
        let round_tripped = VelocityTracker::from_bytes(&reloaded.to_bytes().expect("serialize"))
            .expect("deserialize");
        assert_eq!(round_tripped.transaction_count(), 3);
    }

    /// Entries outside a window are not counted by it, which is the job the
    /// prune was wrongly credited with: the totals select their own window, so
    /// the stored history never had to be trimmed for them to be right.
    #[test]
    fn the_totals_select_their_own_window() {
        let mut tracker = VelocityTracker::new();
        tracker.transactions.push_back(TrackedTransaction {
            timestamp: Utc::now() - Duration::days(3),
            amount_sats: 5000,
        });
        tracker.record(1000);

        assert_eq!(
            tracker.daily_total(),
            1000,
            "a 3-day-old spend is not today"
        );
        assert_eq!(tracker.weekly_total(), 6000, "but it is inside the week");
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
