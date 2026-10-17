// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! Rolling total across approved key-path spends.
//!
//! [`KeySpendPolicy`](crate::KeySpendPolicy) bounds one spend. Nothing bounded
//! how many, so a member that passes the per-spend gate could pass it again
//! immediately: with the group's change address allowlisted, which is what the
//! flag help instructs, repeated spends walk the balance out. The count is not
//! one per block either, since a requester can chain spends of its own change up
//! to whatever the mempool accepts as descendants.
//!
//! The window is rolling rather than per calendar day so it cannot be doubled by
//! straddling a boundary: two maximum spends minutes apart, one at 23:58 and one
//! at 00:01, are one window's worth.
//!
//! It is deliberately NOT keyed on the requester. A requester is always a share
//! holder, so compromising a member yields the identity any per-requester bucket
//! would key on, and the thing being protected is the group's funds rather than
//! any one peer's quota. One total for the node is what actually bounds the
//! loss.
//!
//! What it bounds is signatures issued, not funds at risk. A signature does not
//! expire, so a member can take the full total every window and broadcast every
//! transaction it collected at once: N windows of patience is N totals movable
//! in one block. Read the number as how much this node is willing to have
//! signed per day, not as how much can be taken.
//!
//! It is also a denial-of-service surface that node-local accounting cannot
//! close. `consumed` is summed from prevouts the requester asserts and this node
//! has no chain access to check them, so any share holder can fill the total
//! with one sham request at no cost in real satoshis and stop this node
//! co-signing until the window rolls. Nothing here can distinguish that from an
//! honest large spend; what still holds is the destination allowlist, which
//! bounds where money can go regardless.
//!
//! The clock is [`Instant`], which is monotonic, so no clock change can wind the
//! window back; the cost is that it does not advance while the machine is
//! suspended, which makes the window at least 24 hours of uptime rather than of
//! wall time. That is the conservative direction. A durable total, the stated
//! follow-up, cannot use `Instant` at all, since it is not serializable, and
//! will need a boot-time anchor plus a decision about a backwards clock jump.
//!
//! What this bounds is THIS node's participation, not the group's spending, and
//! the difference is a factor of however many co-signers there are. A refused
//! request makes the requester fail over to another co-signer, whose window is
//! its own, so a group with two opted-in co-signers each allowing `N` admits
//! `2N` before anything stops. An operator sizing this should divide by the
//! number of co-signers that opt in, and the only way to make it a group total
//! is to agree one across them, which needs state they share rather than state
//! each keeps. The end-to-end test
//! `the_window_bounds_each_co_signer_and_a_requester_can_use_both` pins exactly
//! this, so it is a stated property rather than a surprise.

use std::time::{Duration, Instant};

use bitcoin::hashes::Hash;
use bitcoin::{Amount, Txid};

/// How many entries the window tracks before it starts merging the older ones.
/// A bound on memory rather than on spending: the total is preserved across a
/// merge, so reaching this changes how precisely the window remembers, never
/// how much it permits.
const MAX_TRACKED_SPENDS: usize = 4096;

/// A rolling total of what approved key-path spends consumed.
///
/// The lock lives inside rather than around it, so a caller holding one in a
/// hook does not have to name a lock type to build it, and every check records
/// under the same lock it decided under.
///
/// Deliberately not `Clone`: the hook holds one through an `Arc` and charges
/// every spend against it, so a clone would silently make the accounting
/// per-request and the total unenforceable.
#[derive(Debug)]
pub struct KeySpendWindow {
    window: Duration,
    max_total: Amount,
    spends: parking_lot::Mutex<Vec<(Instant, Txid, Amount)>>,
}

/// A day, the interval the window rolls over, matching the daily ceiling
/// keep-mobile's limiter already uses so the two read the same way.
pub const KEY_SPEND_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

impl KeySpendWindow {
    /// Allow at most `max_total` consumed across any `window`.
    pub fn new(window: Duration, max_total: Amount) -> Self {
        Self {
            window,
            max_total,
            spends: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// Allow at most `max_total_sats` across any [`KEY_SPEND_WINDOW`], taking
    /// satoshis so a caller needs neither `bitcoin` nor a lock type to build
    /// one. A zero total refuses every spend.
    pub fn daily(max_total_sats: u64) -> Self {
        Self::new(KEY_SPEND_WINDOW, Amount::from_sat(max_total_sats))
    }

    /// Record transaction `txid` consuming `consumed` against the window and
    /// report whether it fits.
    ///
    /// `false` means refuse the spend, and nothing is recorded in that case: a
    /// refused spend never happened, so it must not count toward the total and
    /// push later honest spends over.
    ///
    /// A txid already inside the window is allowed without being charged again.
    /// A transaction spending several of the group's inputs is one signing
    /// session per input, each reporting the whole transaction's `consumed`, so
    /// charging per session would count one spend N times and make the operator's
    /// total mean less than it says. Charging per transaction is also what makes
    /// the number comparable to the per-spend cap, which is likewise per
    /// transaction.
    pub fn check_and_record(&self, txid: Txid, consumed: Amount) -> bool {
        self.check_and_record_at(txid, consumed, Instant::now())
    }

    /// Time-injectable core of [`check_and_record`], so the window boundary is
    /// directly testable without sleeping.
    pub fn check_and_record_at(&self, txid: Txid, consumed: Amount, now: Instant) -> bool {
        // A configured zero means this node is not spending, which has to hold
        // for a zero-consumption spend too: `total > max_total` alone would let
        // one through, and the answer should not depend on an amount that cannot
        // occur. Matches `KeySpendPolicy`, where a zero cap refuses outright.
        if self.max_total == Amount::ZERO {
            return false;
        }
        let cutoff = now.checked_sub(self.window);
        let mut spends = self.spends.lock();
        spends.retain(|(at, _, _)| cutoff.map(|c| *at >= c).unwrap_or(true));

        // At capacity, merge the older half into one entry rather than refuse.
        // An entry is nearly free to create: `consumed` is summed from
        // requester-supplied prevouts, so a member can claim a trivial amount
        // and still take a slot, and refusing here would hand it a 24-hour
        // lockout of every honest spend at no cost to itself. Merging keeps the
        // total exactly as conservative while bounding memory. The merged entry
        // takes the NEWEST timestamp of the entries it replaces, so the amount
        // is held at least as long as any of them would have held it, and a
        // zero txid so it matches no transaction and cannot free-pass one.
        if spends.len() >= MAX_TRACKED_SPENDS {
            let keep_from = spends.len() / 2;
            let merged: Option<(Instant, Amount)> = spends[..keep_from].iter().try_fold(
                (
                    spends.first().map(|(at, _, _)| *at).unwrap_or(now),
                    Amount::ZERO,
                ),
                |(newest, sum), (at, _, amount)| Some((newest.max(*at), sum.checked_add(*amount)?)),
            );
            let Some((newest, sum)) = merged else {
                return false;
            };
            spends.drain(..keep_from);
            spends.insert(0, (newest, Txid::from_raw_hash(Hash::all_zeros()), sum));
        }

        // What this transaction has already been charged, if the window has seen
        // it. Another input of the same transaction reports the same `consumed`
        // and must not be charged twice.
        let charged = spends
            .iter()
            .position(|(_, seen, _)| *seen == txid)
            .map(|i| (i, spends[i].2));

        // Only the increase is charged. The prevout amounts `consumed` is summed
        // from are requester-supplied and the txid does not commit to them, so a
        // first request can understate them and be charged the smaller figure.
        // That signature is useless on chain, because the sighash commits to the
        // real amounts, but a second request for the same transaction carrying
        // the true amounts is the one that matters and would otherwise ride in
        // free, with the fee it destroys never counted. Charging the difference
        // keeps "once per transaction" while pricing it at the largest claim.
        let already = charged.map(|(_, amount)| amount).unwrap_or(Amount::ZERO);
        let Some(extra) = consumed.checked_sub(already) else {
            // Not more than has been charged, so nothing further is owed.
            return true;
        };

        let mut total = extra;
        for (_, _, amount) in spends.iter() {
            // Checked: the per-spend cap is an operator value and the window
            // holds many of them, so the sum can leave u64 even when no single
            // spend can. A wrapping total would read as a small one.
            total = match total.checked_add(*amount) {
                Some(total) => total,
                None => return false,
            };
        }
        if total > self.max_total {
            return false;
        }
        match charged {
            // The timestamp moves with the charge, not only the amount. Leaving
            // it at the understated request's instant would expire the real
            // charge on that clock: seed a transaction at 1 sat, raise it to its
            // true value a second before the window closes, and the whole amount
            // prunes a second later, admitting another one immediately. That is
            // the boundary doubling this design exists to prevent, moved from
            // midnight to the entry's own expiry. Holding the full amount from
            // the latest charge over-retains the part already counted, which is
            // the safe direction.
            Some((i, _)) => spends[i] = (now, txid, consumed),
            None => spends.push((now, txid, consumed)),
        }
        true
    }

    /// What the window currently holds, for logging what is left.
    ///
    /// Prunes first, so it reports the live total rather than one inflated by
    /// spends that have aged out. The sum cannot overflow: every push is gated
    /// on the total staying within `max_total`, `spends` is private, and
    /// [`Self::check_and_record_at`] is its only mutator.
    pub fn recorded(&self) -> Amount {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window);
        let mut spends = self.spends.lock();
        spends.retain(|(at, _, _)| cutoff.map(|c| *at >= c).unwrap_or(true));
        spends.iter().fold(Amount::ZERO, |acc, (_, _, a)| acc + *a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sats(n: u64) -> Amount {
        Amount::from_sat(n)
    }

    /// A distinct transaction id per `n`, so each test spend is its own
    /// transaction unless it deliberately reuses one.
    fn tx(n: u32) -> Txid {
        let mut raw = [0u8; 32];
        raw[..4].copy_from_slice(&n.to_le_bytes());
        Txid::from_byte_array(raw)
    }

    fn window() -> KeySpendWindow {
        KeySpendWindow::new(KEY_SPEND_WINDOW, sats(100_000))
    }

    #[test]
    fn spends_accumulate_until_the_total_is_reached() {
        let now = Instant::now();
        let w = window();
        assert!(w.check_and_record_at(tx(1), sats(60_000), now));
        assert!(w.check_and_record_at(tx(2), sats(40_000), now));
        assert_eq!(w.recorded(), sats(100_000));
        // The next satoshi is over, however small.
        assert!(!w.check_and_record_at(tx(3), sats(1), now));
    }

    // A refused spend must not be recorded. Counting it would let one rejected
    // request consume budget that honest spends then cannot use, which turns the
    // cap into a smaller cap after every refusal.
    #[test]
    fn a_refused_spend_is_not_recorded() {
        let now = Instant::now();
        let w = window();
        assert!(!w.check_and_record_at(tx(1), sats(200_000), now));
        assert_eq!(w.recorded(), Amount::ZERO);
        assert!(w.check_and_record_at(tx(2), sats(100_000), now));
    }

    // A transaction with several of the group's inputs is one signing session
    // per input, each reporting the whole transaction's consumed value. Charging
    // per session would count it N times and make the operator's total mean
    // less than it says, so the same txid is charged once.
    #[test]
    fn one_transaction_is_charged_once_however_many_of_its_inputs_are_signed() {
        let now = Instant::now();
        let w = window();
        assert!(w.check_and_record_at(tx(1), sats(60_000), now));
        // Further inputs of the same transaction, at a different amount and a
        // different instant, so an implementation keyed on either of those
        // rather than on the txid fails here.
        assert!(w.check_and_record_at(tx(1), sats(60_000), now + Duration::from_secs(5)));
        assert!(w.check_and_record_at(tx(1), sats(50_000), now + Duration::from_secs(9)));
        assert_eq!(w.recorded(), sats(60_000), "charged once, not three times");

        // A genuinely different transaction is still charged.
        assert!(w.check_and_record_at(tx(2), sats(40_000), now));
        assert!(!w.check_and_record_at(tx(3), sats(1), now));
    }

    // The amounts a spend reports come from prevouts the requester supplies, and
    // the txid does not commit to them, so the first request for a transaction
    // can understate what it consumes. That signature is useless on chain, since
    // the sighash commits to the real amounts, and the request that matters is
    // the second one carrying the true figures. Charging only the increase
    // prices the transaction at its largest claim while still charging it once.
    #[test]
    fn a_later_request_for_the_same_transaction_is_charged_the_difference() {
        let now = Instant::now();
        let w = window();
        // Understated: claims to consume what it pays out, so no fee.
        assert!(w.check_and_record_at(tx(1), sats(10_000), now));
        assert_eq!(w.recorded(), sats(10_000));

        // The same transaction with the true amounts, 90 000 more.
        assert!(w.check_and_record_at(tx(1), sats(100_000), now));
        assert_eq!(
            w.recorded(),
            sats(100_000),
            "the window holds the larger claim, not the first one"
        );

        // And the budget is genuinely gone, rather than only appearing to be.
        assert!(!w.check_and_record_at(tx(2), sats(1), now));
    }

    // The boundary doubling the rolling design exists to prevent, by way of the
    // increase: seed a transaction cheaply, raise it to its true amount just
    // before the window closes, and if the entry still expires on the first
    // request's clock the whole amount leaves at once and another full spend
    // fits seconds later. The charge has to carry the later instant.
    #[test]
    fn raising_a_charge_also_moves_when_it_expires() {
        let start = Instant::now();
        let day = KEY_SPEND_WINDOW;
        let w = window();

        // A cheap seed, then the true amount a second before the window closes.
        assert!(w.check_and_record_at(tx(1), sats(1), start));
        let late = start + day - Duration::from_secs(1);
        assert!(w.check_and_record_at(tx(1), sats(100_000), late));

        // A second after the seed's window would have closed, the real charge is
        // still held, so a second full spend does not fit.
        let after_seed_expiry = start + day + Duration::from_secs(1);
        assert!(!w.check_and_record_at(tx(2), sats(100_000), after_seed_expiry));
        assert_eq!(w.recorded(), sats(100_000));

        // It frees a day after the charge that raised it, not a day after the
        // seed.
        assert!(w.check_and_record_at(tx(3), sats(100_000), late + day + Duration::from_secs(1)));
    }

    // The increase has to fit, not merely be recorded: a second request whose
    // true amount would exceed the total is refused, and the smaller charge it
    // already made stays as it was.
    #[test]
    fn an_increase_that_does_not_fit_is_refused_without_raising_the_charge() {
        let now = Instant::now();
        let w = window();
        assert!(w.check_and_record_at(tx(1), sats(10_000), now));
        assert!(w.check_and_record_at(tx(2), sats(80_000), now));
        // tx(1) truly consumes 30 000, which would put the total at 110 000.
        assert!(!w.check_and_record_at(tx(1), sats(30_000), now));
        assert_eq!(
            w.recorded(),
            sats(90_000),
            "the refused increase is not kept"
        );
    }

    // An entry costs almost nothing to create, so refusing at capacity would
    // hand any member a free lockout of every honest spend until entries age
    // out. Merging the older half keeps the total identical and memory bounded.
    #[test]
    fn at_capacity_entries_merge_instead_of_locking_the_window() {
        let now = Instant::now();
        let w = KeySpendWindow::new(KEY_SPEND_WINDOW, sats(u64::MAX));
        for i in 0..MAX_TRACKED_SPENDS as u32 {
            assert!(
                w.check_and_record_at(tx(i), sats(1), now + Duration::from_millis(u64::from(i))),
                "entry {i} must be admitted"
            );
        }
        let before = w.recorded();
        assert_eq!(before, sats(MAX_TRACKED_SPENDS as u64));

        // The next distinct transaction is admitted rather than refused, and the
        // total is preserved across the merge.
        let next = now + Duration::from_secs(1);
        assert!(
            w.check_and_record_at(tx(99_999), sats(5), next),
            "a full window must still admit a spend that fits the total"
        );
        assert_eq!(w.recorded(), before + sats(5));
    }

    // The point of rolling: budget returns gradually as individual spends age
    // out, rather than all at once on a boundary that can be straddled.
    #[test]
    fn budget_returns_only_as_spends_age_out() {
        let start = Instant::now();
        let day = Duration::from_secs(24 * 60 * 60);
        let w = window();
        assert!(w.check_and_record_at(tx(1), sats(100_000), start));
        // One second before the window closes, still full.
        assert!(!w.check_and_record_at(tx(2), sats(1), start + day - Duration::from_secs(1)));
        // Once that spend has aged out, the whole budget is available again.
        assert!(w.check_and_record_at(tx(3), sats(100_000), start + day + Duration::from_secs(1)));
    }

    #[test]
    fn spends_inside_the_window_are_summed_not_compared_individually() {
        let start = Instant::now();
        let w = window();
        // Each is comfortably under the total on its own.
        for i in 0..4u32 {
            assert!(w.check_and_record_at(
                tx(i),
                sats(25_000),
                start + Duration::from_secs(u64::from(i) * 60)
            ));
        }
        assert!(!w.check_and_record_at(tx(9), sats(25_000), start + Duration::from_secs(300)));
    }

    // A hostile sequence can sum past u64 even when each spend is within an
    // operator's cap. Without the checked add the total wraps and reads small.
    #[test]
    fn a_total_that_overflows_is_refused() {
        let now = Instant::now();
        let w = KeySpendWindow::new(Duration::from_secs(60), Amount::from_sat(u64::MAX));
        assert!(w.check_and_record_at(tx(1), sats(u64::MAX), now));
        assert!(!w.check_and_record_at(tx(2), sats(u64::MAX), now));
    }

    #[test]
    fn a_zero_total_refuses_everything() {
        let now = Instant::now();
        let w = KeySpendWindow::new(Duration::from_secs(60), Amount::ZERO);
        assert!(!w.check_and_record_at(tx(1), sats(1), now));
        // Even a zero-value spend, which would otherwise be free: a configured
        // zero means this node is not spending.
        assert!(!w.check_and_record_at(tx(2), Amount::ZERO, now));
    }
}
