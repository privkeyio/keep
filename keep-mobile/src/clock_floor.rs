// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! A lower bound on the current time that the device's own clock cannot lower.
//!
//! The spending policy expires, and expiry is the state a warden stops renewing
//! into: past it every rule refuses. Deciding that from the wall clock alone
//! means the date setting decides whether the policy is in force, so setting
//! the clock back inside the validity window turns an expired policy back into
//! an enforced one, with no root and no prompt.
//!
//! What closes it is a time floor: the latest wall reading the app has ever
//! seen, kept in storage and consulted on every decision. Expiry is evaluated
//! at `max(now, floor)`, so winding the clock back leaves the floor in charge
//! and an expired policy stays expired. The floor can only ever make the
//! evaluated time later, which can expire a bundle but never un-expire one, so
//! every way it can be wrong refuses rather than permits.
//!
//! This works here and would not work against a record rollback: that needs
//! root or offline access to the data partition, which is also enough to
//! rewrite this record, whereas the date setting is not.
//!
//! The reason the floor is bounded rather than simply raised to whatever the
//! clock says is the failure [`crate::audit`]'s `monotonic_timestamp` is
//! written around. One reading from a clock set to 2099 would park the floor
//! there, and from then on every bundle is expired, including a replacement a
//! warden signs today, so the policy refuses forever with no way back. The
//! floor therefore advances only as far as monotonic time proves has elapsed: a
//! jump to 2099 moves it by seconds, and the poisoning is not available.
//!
//! The monotonic reading comes from the caller, as it already does for
//! [`crate::signing_policy::SigningRateLimiter`], because only the platform has
//! it. On Android it is `SystemClock.elapsedRealtime()`, which counts across
//! sleep and resets on reboot.

use serde::{Deserialize, Serialize};

/// Slack allowed on top of the elapsed monotonic time when advancing the floor.
///
/// Covers the gap between the two readings being taken and a second of
/// rounding, nothing more. It does not need to cover a legitimate forward
/// correction, such as a device whose battery died resyncing by NTP: the floor
/// is a lower bound, so lagging a real correction is harmless, and the
/// evaluated time is `max(now, floor)`, which is the corrected reading itself.
const ADVANCE_SLACK_SECS: u64 = 60;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(crate) struct ClockFloor {
    /// The latest wall-clock second the app accepts as already past.
    pub(crate) floor_secs: u64,
    /// The monotonic reading taken alongside `floor_secs`, for measuring how
    /// much time has since been proven to pass.
    pub(crate) anchor_elapsed_ms: u64,
}

impl ClockFloor {
    pub(crate) fn new(now_secs: u64, now_elapsed_ms: u64) -> Self {
        Self {
            floor_secs: now_secs,
            anchor_elapsed_ms: now_elapsed_ms,
        }
    }

    /// The floor after observing `now_secs` alongside `now_elapsed_ms`, and
    /// whether it changed enough to be worth storing.
    ///
    /// `None` for the monotonic reading means the caller had none, which is the
    /// case at construction. The floor is then consulted and not advanced:
    /// raising it needs proof that time passed, and reading it does not.
    pub(crate) fn observe(self, now_secs: u64, now_elapsed_ms: Option<u64>) -> (Self, bool) {
        let Some(now_elapsed_ms) = now_elapsed_ms else {
            return (self, false);
        };

        // A monotonic reading below the anchor means the device rebooted, since
        // the counter restarts there, so nothing can be proven about the gap.
        // The anchor is moved to the new reading and the floor is left alone.
        // That is safe because a stale floor is still a lower bound on real
        // time: when the clock reads later than the floor, the clock is used.
        // The cost is that the floor lags by however long the device was off,
        // so a rewind that far back is not detected.
        if now_elapsed_ms < self.anchor_elapsed_ms {
            return (
                Self {
                    floor_secs: self.floor_secs,
                    anchor_elapsed_ms: now_elapsed_ms,
                },
                true,
            );
        }

        let proven_secs = (now_elapsed_ms - self.anchor_elapsed_ms) / 1_000;
        let ceiling = self
            .floor_secs
            .saturating_add(proven_secs)
            .saturating_add(ADVANCE_SLACK_SECS);
        let advanced = Self {
            floor_secs: self.floor_secs.max(now_secs.min(ceiling)),
            anchor_elapsed_ms: now_elapsed_ms,
        };
        let changed = advanced.floor_secs != self.floor_secs
            || advanced.anchor_elapsed_ms != self.anchor_elapsed_ms;
        (advanced, changed)
    }

    /// The time to evaluate validity at: never earlier than the floor.
    pub(crate) fn effective_secs(&self, now_secs: u64) -> u64 {
        now_secs.max(self.floor_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60;

    #[test]
    fn winding_the_clock_back_does_not_move_the_evaluated_time_back() {
        let floor = ClockFloor::new(1_000_000, 0);
        let (floor, _) = floor.observe(1_000_000 + 10 * MIN, Some(10 * MIN * 1_000));

        // The attack: the date is set back a week. The floor is what validity
        // is judged against, so an expired policy stays expired.
        assert_eq!(
            floor.effective_secs(1_000_000 - 7 * 24 * 3600),
            1_000_000 + 10 * MIN
        );
    }

    #[test]
    fn a_clock_set_far_forward_cannot_park_the_floor_there() {
        let floor = ClockFloor::new(1_000_000, 0);

        // One reading from a clock set decades ahead, a second of monotonic
        // time after the anchor.
        let (poisoned, _) = floor.observe(4_000_000_000, Some(1_000));

        // The floor moved by the proven second plus the slack, not by decades,
        // so a policy signed today is still inside its window afterwards.
        assert!(
            poisoned.floor_secs <= 1_000_000 + 1 + ADVANCE_SLACK_SECS,
            "floor advanced to {}",
            poisoned.floor_secs
        );
    }

    #[test]
    fn the_floor_tracks_time_that_monotonic_proves_passed() {
        let floor = ClockFloor::new(1_000_000, 5_000);
        let (floor, changed) = floor.observe(1_000_000 + 30 * MIN, Some(5_000 + 30 * MIN * 1_000));

        assert!(changed);
        assert_eq!(floor.floor_secs, 1_000_000 + 30 * MIN);
        assert_eq!(floor.anchor_elapsed_ms, 5_000 + 30 * MIN * 1_000);
    }

    #[test]
    fn a_reboot_re_anchors_without_advancing_the_floor() {
        let floor = ClockFloor::new(1_000_000, 9_000_000);
        let (floor, changed) = floor.observe(1_000_000 + 24 * 3600, Some(12_000));

        assert!(changed, "the anchor has to follow the restarted counter");
        assert_eq!(
            floor.floor_secs, 1_000_000,
            "nothing proves the gap, so the floor cannot advance"
        );
        assert_eq!(floor.anchor_elapsed_ms, 12_000);
        // Still usable: the clock reads later than the floor, so the clock wins.
        assert_eq!(
            floor.effective_secs(1_000_000 + 24 * 3600),
            1_000_000 + 24 * 3600
        );
    }

    #[test]
    fn no_monotonic_reading_consults_the_floor_without_advancing_it() {
        let floor = ClockFloor::new(1_000_000, 4_000);
        let (same, changed) = floor.observe(1_000_000 + 3600, None);

        assert!(!changed);
        assert_eq!(same.floor_secs, 1_000_000);
        assert_eq!(same.anchor_elapsed_ms, 4_000);
        assert_eq!(same.effective_secs(999_000), 1_000_000);
    }
}
