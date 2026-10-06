// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Learning the group's verifying-share set from members' announces, for a
//! share stored without it.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use keep_core::frost::{complete_verifying_shares, predict_verifying_shares, SharePackage};
use nostr_sdk::prelude::PublicKey;

use crate::protocol::AnnouncePayload;

/// Most proven points kept per member index. Anyone can prove a point they
/// made up, so each index keeps several, oldest first, and the search picks the
/// ones that fit; a later forger cannot push out a member already recorded.
const MAX_CANDIDATES: usize = 64;
/// A candidate whose author stops announcing is dropped after this long, so a
/// forger has to keep announcing to hold a slot.
const CANDIDATE_TTL: Duration = Duration::from_secs(90);
/// Upper bound on basis combinations tried per check; with a threshold above
/// 3 it lowers the per-index capacity so the search stays within it.
const MAX_COMBINATIONS: usize = 4096;

/// Candidates kept per index for `threshold`: the search enumerates the
/// candidates of threshold - 2 indices, so their product stays bounded.
fn capacity(threshold: u16) -> usize {
    if threshold <= 3 {
        return MAX_CANDIDATES;
    }
    let per_index = (MAX_COMBINATIONS as f64).powf(1.0 / f64::from(threshold - 2));
    (per_index.floor() as usize).clamp(2, MAX_CANDIDATES)
}
/// Minimum spacing of the announces this node sends in reply while learning.
const RECIPROCAL_INTERVAL: Duration = Duration::from_secs(20);
/// Set searches allowed in a burst, then one per `SEARCH_INTERVAL`, so a flood
/// of forged announces costs the node a bounded amount of work; changes made
/// while out of budget are searched on the next announce once it refills.
const SEARCH_BURST: u32 = 8;
const SEARCH_INTERVAL: Duration = Duration::from_secs(2);

struct Candidate {
    author: PublicKey,
    point: [u8; 33],
    payload: AnnouncePayload,
    first_seen: Instant,
    last_seen: Instant,
}

#[derive(Default)]
pub(crate) struct LearnedVerifyingShares {
    candidates: BTreeMap<u16, Vec<Candidate>>,
    complete: Option<BTreeMap<u16, [u8; 33]>>,
    last_reciprocal: Option<Instant>,
    search_budget: Option<(u32, Instant)>,
    dirty: bool,
    mismatch_reported: bool,
}

pub(crate) enum Learning {
    /// The set is not complete yet; `reciprocate` asks the node to announce so
    /// members that have not seen it yet can admit it.
    Pending { reciprocate: bool },
    /// The set was just completed. `held` are the other members' announces to
    /// admit now.
    Completed {
        set: BTreeMap<u16, [u8; 33]>,
        held: Vec<(PublicKey, AnnouncePayload)>,
    },
    /// The set was already complete.
    Known,
}

impl LearnedVerifyingShares {
    pub(crate) fn complete(&self) -> Option<&BTreeMap<u16, [u8; 33]>> {
        self.complete.as_ref()
    }

    /// Records a proven announce and checks whether the recorded candidates now
    /// contain the group's whole set for `share`.
    pub(crate) fn record(
        &mut self,
        share: &SharePackage,
        own_share: [u8; 33],
        author: PublicKey,
        payload: &AnnouncePayload,
        now: Instant,
    ) -> Learning {
        if self.complete.is_some() {
            return Learning::Known;
        }
        let index = payload.share_index;
        for list in self.candidates.values_mut() {
            list.retain(|c| now.saturating_duration_since(c.last_seen) < CANDIDATE_TTL);
        }
        let list = self.candidates.entry(index).or_default();
        let mut new_author = false;
        let mut changed = false;
        let room = list.len() < capacity(share.metadata.threshold);
        match list.iter_mut().find(|c| c.author == author) {
            Some(existing) => {
                if existing.point != payload.verifying_share {
                    changed = true;
                    existing.point = payload.verifying_share;
                    existing.first_seen = now;
                }
                existing.payload = payload.clone();
                existing.last_seen = now;
            }
            None if room => {
                new_author = true;
                list.push(Candidate {
                    author,
                    point: payload.verifying_share,
                    payload: payload.clone(),
                    first_seen: now,
                    last_seen: now,
                });
            }
            None => {}
        }
        list.sort_by_key(|c| c.first_seen);

        let reciprocate = new_author
            && self
                .last_reciprocal
                .is_none_or(|t| now.saturating_duration_since(t) >= RECIPROCAL_INTERVAL);
        if reciprocate {
            self.last_reciprocal = Some(now);
        }

        let own = share.metadata.identifier;
        let others: Vec<u16> = (1..=share.metadata.total_shares)
            .filter(|&i| i != own)
            .collect();
        if others
            .iter()
            .any(|i| self.candidates.get(i).is_none_or(|l| l.is_empty()))
        {
            return Learning::Pending { reciprocate };
        }

        self.dirty |= new_author || changed;
        if !self.dirty || !self.take_search_budget(now) {
            return Learning::Pending { reciprocate };
        }
        self.dirty = false;
        match self.search(share, own_share, &others) {
            Some(picks) => {
                let mut set: BTreeMap<u16, [u8; 33]> = picks
                    .iter()
                    .map(|(&i, &k)| (i, self.candidates[&i][k].point))
                    .collect();
                set.insert(own, own_share);
                let held = picks
                    .iter()
                    .filter(|(&i, _)| i != index)
                    .map(|(&i, &k)| {
                        let c = &self.candidates[&i][k];
                        (c.author, c.payload.clone())
                    })
                    .collect();
                self.candidates.clear();
                self.complete = Some(set.clone());
                Learning::Completed { set, held }
            }
            None => {
                if !self.mismatch_reported {
                    self.mismatch_reported = true;
                    tracing::warn!(
                        "Every member has announced but no combination of their verifying shares fits this share; if this share was refreshed, import the refreshed share"
                    );
                }
                Learning::Pending { reciprocate }
            }
        }
    }

    fn take_search_budget(&mut self, now: Instant) -> bool {
        let (tokens, since) = self.search_budget.get_or_insert((SEARCH_BURST, now));
        let refilled = now.saturating_duration_since(*since).as_secs() / SEARCH_INTERVAL.as_secs();
        if refilled > 0 {
            *tokens = tokens
                .saturating_add(u32::try_from(refilled).unwrap_or(u32::MAX))
                .min(SEARCH_BURST);
            *since = now;
        }
        if *tokens == 0 {
            return false;
        }
        *tokens -= 1;
        true
    }

    /// The candidate position chosen for each index in `others` such that the
    /// set passes [`complete_verifying_shares`]. Enumerates the candidates of
    /// the threshold - 2 indices with the fewest, predicts every other member's
    /// point from them, and looks each prediction up among its candidates.
    fn search(
        &self,
        share: &SharePackage,
        own_share: [u8; 33],
        others: &[u16],
    ) -> Option<BTreeMap<u16, usize>> {
        let basis_len = usize::from(share.metadata.threshold).checked_sub(2)?;
        let mut by_count = others.to_vec();
        by_count.sort_by_key(|i| self.candidates[i].len());
        let basis_indices = &by_count[..basis_len];
        let radix: Vec<usize> = basis_indices
            .iter()
            .map(|i| self.candidates[i].len())
            .collect();
        let mut digits = vec![0usize; basis_len];
        for _ in 0..MAX_COMBINATIONS {
            let basis: BTreeMap<u16, [u8; 33]> = basis_indices
                .iter()
                .zip(&digits)
                .map(|(&i, &k)| (i, self.candidates[&i][k].point))
                .collect();
            if let Some(picks) =
                self.match_prediction(share, own_share, &basis, basis_indices, &digits)
            {
                return Some(picks);
            }
            let mut d = 0;
            loop {
                if d == digits.len() {
                    return None;
                }
                digits[d] += 1;
                if digits[d] < radix[d] {
                    break;
                }
                digits[d] = 0;
                d += 1;
            }
        }
        None
    }

    fn match_prediction(
        &self,
        share: &SharePackage,
        own_share: [u8; 33],
        basis: &BTreeMap<u16, [u8; 33]>,
        basis_indices: &[u16],
        digits: &[usize],
    ) -> Option<BTreeMap<u16, usize>> {
        let predicted = predict_verifying_shares(share, basis).ok()?;
        let mut picks: BTreeMap<u16, usize> = basis_indices
            .iter()
            .copied()
            .zip(digits.iter().copied())
            .collect();
        for (index, point) in &predicted {
            let k = self
                .candidates
                .get(index)?
                .iter()
                .position(|c| c.point == *point)?;
            picks.insert(*index, k);
        }
        let mut set: BTreeMap<u16, [u8; 33]> = picks
            .iter()
            .map(|(&i, &k)| (i, self.candidates[&i][k].point))
            .collect();
        set.insert(share.metadata.identifier, own_share);
        complete_verifying_shares(share, &set).ok()?;
        Some(picks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::SigningKey;
    use keep_core::frost::{verifying_share_map, ThresholdConfig, TrustedDealer};
    use nostr_sdk::Keys;

    fn payload(index: u16, point: [u8; 33]) -> AnnouncePayload {
        AnnouncePayload::new([0u8; 32], index, point, [0u8; 64], 0)
    }

    fn forged_point() -> [u8; 33] {
        let key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let mut point = [0u8; 33];
        point[0] = 0x02;
        point[1..].copy_from_slice(&key.verifying_key().to_bytes());
        point
    }

    struct Group {
        share: SharePackage,
        real: BTreeMap<u16, [u8; 33]>,
    }

    fn group() -> Group {
        let (shares, _) = TrustedDealer::new(ThresholdConfig::new(3, 5).unwrap())
            .generate("learn")
            .unwrap();
        let real = verifying_share_map(&shares[0].pubkey_package().unwrap(), 5).unwrap();
        Group {
            share: shares.into_iter().next().unwrap(),
            real,
        }
    }

    fn record(
        learned: &mut LearnedVerifyingShares,
        g: &Group,
        author: PublicKey,
        index: u16,
        point: [u8; 33],
        now: Instant,
    ) -> Learning {
        learned.record(&g.share, g.real[&1], author, &payload(index, point), now)
    }

    #[test]
    fn interleaved_forgeries_do_not_stall_learning() {
        let g = group();
        let mut learned = LearnedVerifyingShares::default();
        let start = Instant::now();
        let members: BTreeMap<u16, PublicKey> = (2..=5)
            .map(|i| (i, Keys::generate().public_key()))
            .collect();
        for (step, &index) in [2u16, 3, 4, 5].iter().enumerate() {
            let now = start + SEARCH_INTERVAL * step as u32;
            for forged_index in 2..=5u16 {
                let forger = Keys::generate().public_key();
                assert!(matches!(
                    record(&mut learned, &g, forger, forged_index, forged_point(), now),
                    Learning::Pending { .. }
                ));
            }
            assert!(matches!(
                record(
                    &mut learned,
                    &g,
                    members[&index],
                    index,
                    g.real[&index],
                    now
                ),
                Learning::Pending { .. }
            ));
        }
        // The next announce after the search interval finds the set, though
        // every slot still holds forgeries.
        let later = start + SEARCH_INTERVAL * 5;
        let Learning::Completed { set, held } =
            record(&mut learned, &g, members[&2], 2, g.real[&2], later)
        else {
            panic!("the real set must complete");
        };
        assert_eq!(set, g.real);
        let mut authors: Vec<PublicKey> = held.iter().map(|(a, _)| *a).collect();
        authors.sort();
        let mut expected: Vec<PublicKey> = [3u16, 4, 5].iter().map(|i| members[i]).collect();
        expected.sort();
        assert_eq!(authors, expected);
    }

    #[test]
    fn a_full_slot_keeps_its_oldest_candidates_until_they_expire() {
        let g = group();
        let mut learned = LearnedVerifyingShares::default();
        let start = Instant::now();
        let member = Keys::generate().public_key();
        record(&mut learned, &g, member, 2, g.real[&2], start);
        for _ in 0..10 {
            record(
                &mut learned,
                &g,
                Keys::generate().public_key(),
                2,
                forged_point(),
                start,
            );
        }
        assert!(learned.candidates[&2].iter().any(|c| c.author == member));
        assert_eq!(learned.candidates[&2].len(), 11);

        let later = start + CANDIDATE_TTL + Duration::from_secs(1);
        record(&mut learned, &g, member, 2, g.real[&2], later);
        assert_eq!(learned.candidates[&2].len(), 1);
    }

    #[test]
    fn reciprocal_announces_are_rate_limited() {
        let g = group();
        let mut learned = LearnedVerifyingShares::default();
        let now = Instant::now();
        let mut reciprocated = 0;
        for _ in 0..8 {
            if let Learning::Pending { reciprocate: true } = record(
                &mut learned,
                &g,
                Keys::generate().public_key(),
                3,
                forged_point(),
                now,
            ) {
                reciprocated += 1;
            }
        }
        assert_eq!(reciprocated, 1);
    }

    #[test]
    fn a_set_that_never_fits_stays_pending() {
        let g = group();
        let other = group();
        let mut learned = LearnedVerifyingShares::default();
        let now = Instant::now();
        for i in 2..=5u16 {
            let outcome = record(
                &mut learned,
                &g,
                Keys::generate().public_key(),
                i,
                other.real[&i],
                now,
            );
            assert!(matches!(outcome, Learning::Pending { .. }));
        }
        assert!(learned.complete().is_none());
        assert!(learned.mismatch_reported);
    }

    #[test]
    fn capacity_keeps_the_search_bounded() {
        for threshold in 2..=20u16 {
            let per_index = capacity(threshold);
            assert!(per_index >= 2);
            let combos = (per_index as f64).powi(i32::from(threshold.saturating_sub(2)));
            assert!(
                combos <= MAX_COMBINATIONS as f64 || per_index == 2 || threshold <= 3,
                "threshold {threshold}"
            );
        }
    }

    #[test]
    fn forgeries_recorded_first_do_not_block_the_real_set() {
        let g = group();
        let mut learned = LearnedVerifyingShares::default();
        let now = Instant::now();
        for index in 2..=5u16 {
            for _ in 0..(capacity(3) - 1) {
                record(
                    &mut learned,
                    &g,
                    Keys::generate().public_key(),
                    index,
                    forged_point(),
                    now,
                );
            }
        }
        for index in 2..5u16 {
            let outcome = record(
                &mut learned,
                &g,
                Keys::generate().public_key(),
                index,
                g.real[&index],
                now,
            );
            assert!(matches!(outcome, Learning::Pending { .. }));
        }
        let outcome = record(
            &mut learned,
            &g,
            Keys::generate().public_key(),
            5,
            g.real[&5],
            now + SEARCH_INTERVAL,
        );
        let Learning::Completed { set, .. } = outcome else {
            panic!("the real set must be found among the forgeries");
        };
        assert_eq!(set, g.real);
    }

    #[test]
    fn searches_are_rate_limited_under_a_flood() {
        let g = group();
        let mut learned = LearnedVerifyingShares::default();
        let now = Instant::now();
        for index in 2..=5u16 {
            record(
                &mut learned,
                &g,
                Keys::generate().public_key(),
                index,
                forged_point(),
                now,
            );
        }
        let mut searched = 0;
        for _ in 0..40 {
            let before = learned.search_budget.map(|(t, _)| t);
            record(
                &mut learned,
                &g,
                Keys::generate().public_key(),
                3,
                forged_point(),
                now,
            );
            if learned.search_budget.map(|(t, _)| t) != before {
                searched += 1;
            }
        }
        assert!(searched < usize::try_from(SEARCH_BURST).unwrap());
        assert!(!learned.take_search_budget(now));
        assert!(learned.take_search_budget(now + SEARCH_INTERVAL));
    }
}
