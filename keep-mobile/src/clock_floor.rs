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
//! What closes it is a time floor: the latest wall reading the app has seen,
//! kept in storage and consulted on every decision. Expiry is judged at
//! `max(now, floor)`, so winding the clock back leaves the floor in charge and
//! an expired policy stays expired.
//!
//! This works here and would not work against a record rollback: that needs
//! root or offline access to the data partition, which is also enough to
//! rewrite this record, whereas the date setting is not.
//!
//! The floor applies to expiry only, not to the not-yet-valid bound. A floor
//! ahead of the real clock makes a bundle look older, which can only expire
//! one; applied to the future bound it would make a future-dated bundle look
//! current, which would un-refuse it. So [`PolicyClock`] carries both readings
//! and each bound uses the one that can only refuse.
//!
//! The reason the floor is bounded rather than simply raised to whatever the
//! clock says is the failure [`crate::audit`]'s `monotonic_timestamp` is
//! written around. One reading from a clock set far ahead would park the floor
//! there, and from then on every bundle is expired, including a replacement a
//! warden signs today, so the policy refuses forever with no way back. The
//! floor therefore advances only by as much as monotonic time proves has
//! elapsed since the reading it was taken with.
//!
//! That proof is why there is no slack: a tolerance granted per observation is
//! granted again on the next one, so a caller that asks repeatedly walks the
//! floor forward at the tolerance per call regardless of how little time
//! passed. Advancing strictly by proven elapsed time has no such rate.
//!
//! The monotonic reading comes from the caller, as it already does for
//! [`crate::signing_policy::SigningRateLimiter`], because only the platform has
//! it. On Android it is `SystemClock.elapsedRealtime()`, which counts across
//! sleep and resets on reboot.

use serde::{Deserialize, Serialize};

/// The two readings a validity decision needs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PolicyClock {
    /// What the device clock says, used for the not-yet-valid bound.
    pub(crate) clock_secs: i64,
    /// Never earlier than the stored floor, used for the expiry bound.
    pub(crate) effective_secs: i64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(crate) struct ClockFloor {
    /// The latest wall-clock second the app accepts as already past.
    pub(crate) floor_secs: u64,
    /// The monotonic reading taken alongside `floor_secs`, for measuring how
    /// much time has since been proven to pass.
    ///
    /// `None` when the floor was written without one, which is the case at
    /// construction. An advance needs a reading to measure from, so the first
    /// one only anchors. Storing a zero instead would claim the floor was taken
    /// at boot, and the next reading would then credit the whole device uptime
    /// as elapsed and advance the floor by it.
    pub(crate) anchor_elapsed_ms: Option<u64>,
}

impl ClockFloor {
    pub(crate) fn new(now_secs: u64, now_elapsed_ms: Option<u64>) -> Self {
        Self {
            floor_secs: now_secs,
            anchor_elapsed_ms: now_elapsed_ms,
        }
    }

    /// The floor after observing `now_secs` alongside `now_elapsed_ms`, and
    /// whether it changed enough to be worth storing.
    ///
    /// `None` for the monotonic reading means the caller had none. The floor is
    /// then consulted and not advanced: raising it needs proof that time
    /// passed, and reading it does not.
    pub(crate) fn observe(self, now_secs: u64, now_elapsed_ms: Option<u64>) -> (Self, bool) {
        let Some(now_elapsed_ms) = now_elapsed_ms else {
            return (self, false);
        };

        // No anchor yet, or a reading below the one held, which means the device
        // rebooted since the counter restarts there. Either way nothing can be
        // proven about the gap, so the reading is adopted as the anchor and the
        // floor is left alone.
        //
        // Safe because the floor only has to be a lower bound on real time, and
        // a stale lower bound is still valid: when the clock reads later than
        // the floor, the clock is used. The cost is that the floor lags by
        // however long the device was off, so a rewind that far back is not
        // detected.
        let anchor = match self.anchor_elapsed_ms {
            Some(anchor) if now_elapsed_ms >= anchor => anchor,
            _ => {
                return (
                    Self {
                        floor_secs: self.floor_secs,
                        anchor_elapsed_ms: Some(now_elapsed_ms),
                    },
                    true,
                )
            }
        };

        let proven_secs = (now_elapsed_ms - anchor) / 1_000;
        if proven_secs == 0 {
            // Nothing proven, so nothing to advance by, and the anchor stays
            // where it is so the next observation measures from the same point
            // rather than restarting the measurement. Not storing this is also
            // what keeps a decision from writing to storage every time.
            return (self, false);
        }

        let ceiling = self.floor_secs.saturating_add(proven_secs);
        let floor_secs = self.floor_secs.max(now_secs.min(ceiling));
        // The anchor moves by the whole seconds that were credited, not to the
        // reading itself, so the remainder below a second is carried instead of
        // discarded. Moving it to the reading would throw away up to 999 ms on
        // every advance, and a caller asking just under every two seconds would
        // then credit one second per two and hold the floor at half of real
        // time.
        let anchor_elapsed_ms = anchor.saturating_add(proven_secs.saturating_mul(1_000));
        // Stored only when the floor itself moved. When it did not, which is
        // every call while the clock reads behind the floor, keeping the old
        // anchor is what lets the proven time accrue rather than being consumed
        // by a call that could not use it. It also keeps a decision from
        // writing to storage every time one is more than a second after the
        // last.
        let changed = floor_secs != self.floor_secs;
        (
            Self {
                floor_secs,
                anchor_elapsed_ms: if changed {
                    Some(anchor_elapsed_ms)
                } else {
                    self.anchor_elapsed_ms
                },
            },
            changed,
        )
    }

    /// The readings to judge validity with: the clock as given, and an expiry
    /// time never earlier than the floor.
    pub(crate) fn clock_at(&self, now_secs: u64) -> PolicyClock {
        let effective = now_secs.max(self.floor_secs);
        PolicyClock {
            clock_secs: i64::try_from(now_secs).unwrap_or(i64::MAX),
            // Saturating rather than unreachable: a floor this code produced is
            // bounded, but one read back from a corrupt or tampered record can
            // carry any `u64`. Saturating sends that to "everything expired",
            // which refuses.
            effective_secs: i64::try_from(effective).unwrap_or(i64::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60;
    const DAY: u64 = 24 * 3600;

    #[test]
    fn winding_the_clock_back_does_not_move_the_expiry_time_back() {
        let floor = ClockFloor::new(1_000_000, Some(0));
        let (floor, _) = floor.observe(1_000_000 + 10 * MIN, Some(10 * MIN * 1_000));

        // The attack: the date is set back a week. Expiry is judged against the
        // floor, so an expired policy stays expired.
        let clock = floor.clock_at(1_000_000 - 7 * DAY);
        assert_eq!(clock.effective_secs, (1_000_000 + 10 * MIN) as i64);
        // The clock reading itself is reported as it is, because the
        // not-yet-valid bound must not be moved later.
        assert_eq!(clock.clock_secs, (1_000_000 - 7 * DAY) as i64);
    }

    #[test]
    fn a_clock_set_far_forward_cannot_park_the_floor_there() {
        let floor = ClockFloor::new(1_000_000, Some(5_000));

        // One reading from a clock set decades ahead, one second of monotonic
        // time after the anchor.
        let (poisoned, _) = floor.observe(4_000_000_000, Some(6_000));
        assert_eq!(
            poisoned.floor_secs, 1_000_001,
            "the floor may only advance by the proven second"
        );

        // And the same reading on a device that has been up for weeks, which is
        // the case a zero anchor used to credit in full.
        let (poisoned, _) = floor.observe(4_000_000_000, Some(5_000 + 40 * DAY * 1_000));
        assert_eq!(
            poisoned.floor_secs,
            1_000_000 + 40 * DAY,
            "uptime past the anchor is proven time, but no more than that"
        );
    }

    #[test]
    fn a_floor_written_without_a_reading_only_anchors_on_the_next_one() {
        // What construction writes: a floor with no anchor.
        let floor = ClockFloor::new(1_000_000, None);
        assert_eq!(floor.anchor_elapsed_ms, None);

        // A device up for 40 days, clock set far forward. Crediting the uptime
        // here would move the floor past every validity window and refuse the
        // warden replacement that would fix it.
        let (anchored, changed) = floor.observe(4_000_000_000, Some(40 * DAY * 1_000));
        assert!(changed);
        assert_eq!(
            anchored.floor_secs, 1_000_000,
            "an unanchored floor cannot advance, only anchor"
        );
        assert_eq!(anchored.anchor_elapsed_ms, Some(40 * DAY * 1_000));
    }

    #[test]
    fn repeated_observations_do_not_walk_the_floor_forward() {
        let mut floor = ClockFloor::new(1_000_000, Some(1_000));

        // The clock is set a month ahead and the caller asks 10,000 times
        // within the same monotonic second. Granting any tolerance per call
        // would walk the floor there; proven time grants none.
        for _ in 0..10_000 {
            let (next, changed) = floor.observe(1_000_000 + 30 * DAY, Some(1_000));
            assert!(!changed, "nothing proven, so nothing to store");
            floor = next;
        }
        assert_eq!(floor.floor_secs, 1_000_000);
        assert_eq!(floor.anchor_elapsed_ms, Some(1_000));
    }

    #[test]
    fn the_floor_tracks_time_that_monotonic_proves_passed() {
        let floor = ClockFloor::new(1_000_000, Some(5_000));
        let (floor, changed) = floor.observe(1_000_000 + 30 * MIN, Some(5_000 + 30 * MIN * 1_000));

        assert!(changed);
        assert_eq!(floor.floor_secs, 1_000_000 + 30 * MIN);
        assert_eq!(floor.anchor_elapsed_ms, Some(5_000 + 30 * MIN * 1_000));
        // Exactly the credited seconds, so nothing is carried here.
    }

    /// Time below a whole second is carried, not discarded. Moving the anchor
    /// to the reading would throw away the remainder on every advance, so a
    /// caller asking just under every two seconds would credit one second per
    /// two and hold the floor at half of real time.
    #[test]
    fn accrual_below_a_second_is_carried_rather_than_discarded() {
        let mut floor = ClockFloor::new(1_000_000, Some(0));

        // Ten asks at 1,900 ms apart: 19 s of real time, and each ask on its
        // own proves only one whole second.
        for i in 1..=10u64 {
            let reading = i * 1_900;
            let (next, _) = floor.observe(1_000_000 + 19, Some(reading));
            floor = next;
        }

        assert_eq!(
            floor.floor_secs, 1_000_019,
            "the carried remainders have to add up to the real elapsed time"
        );
    }

    /// A floor that did not move is not written, which keeps a decision off
    /// storage and keeps the unused proven time accruing.
    #[test]
    fn an_advance_that_cannot_happen_is_not_stored() {
        let floor = ClockFloor::new(1_000_000, Some(0));

        // The clock reads behind the floor, so there is nothing to advance to.
        let (same, changed) = floor.observe(999_000, Some(60_000));
        assert!(!changed, "nothing moved, so nothing to store");
        assert_eq!(same.floor_secs, 1_000_000);
        assert_eq!(
            same.anchor_elapsed_ms,
            Some(0),
            "the anchor stays so the minute still counts once the clock is back"
        );

        // Once the clock is restored the whole minute is still available.
        let (advanced, changed) = same.observe(1_000_060, Some(60_000));
        assert!(changed);
        assert_eq!(advanced.floor_secs, 1_000_060);
    }

    #[test]
    fn a_reboot_re_anchors_without_advancing_the_floor() {
        let floor = ClockFloor::new(1_000_000, Some(9_000_000));
        let (floor, changed) = floor.observe(1_000_000 + DAY, Some(12_000));

        assert!(changed, "the anchor has to follow the restarted counter");
        assert_eq!(
            floor.floor_secs, 1_000_000,
            "nothing proves the gap, so the floor cannot advance"
        );
        assert_eq!(floor.anchor_elapsed_ms, Some(12_000));
        // Still usable: the clock reads later than the floor, so the clock wins.
        assert_eq!(
            floor.clock_at(1_000_000 + DAY).effective_secs,
            (1_000_000 + DAY) as i64
        );
    }

    #[test]
    fn no_monotonic_reading_consults_the_floor_without_advancing_it() {
        let floor = ClockFloor::new(1_000_000, Some(4_000));
        let (same, changed) = floor.observe(1_000_000 + 3600, None);

        assert!(!changed);
        assert_eq!(same.floor_secs, 1_000_000);
        assert_eq!(same.anchor_elapsed_ms, Some(4_000));
        assert_eq!(same.clock_at(999_000).effective_secs, 1_000_000);
    }

    #[test]
    fn a_corrupt_floor_saturates_to_everything_expired() {
        let floor = ClockFloor {
            floor_secs: u64::MAX,
            anchor_elapsed_ms: Some(0),
        };
        assert_eq!(floor.clock_at(1_000_000).effective_secs, i64::MAX);
    }
}
