// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Learning the group's verifying-share set from members' announces, for a
//! share stored without it.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use ::rand::RngExt;
use k256::ProjectivePoint;
use keep_core::frost::{
    complete_verifying_shares, verifying_share_point, SharePackage, VerifyingSetContext,
};
use nostr_sdk::prelude::PublicKey;

use crate::protocol::AnnouncePayload;

/// Most proven points kept per member index. Anyone can prove a point they
/// made up, so each index keeps several; when full, a newcomer replaces a
/// random one, so a member that keeps announcing gets back in.
const MAX_CANDIDATES: usize = 64;
/// Most proven points kept across all indices.
const MAX_TOTAL_CANDIDATES: usize = 512;
/// Announces larger than this are not kept for replay; their member is
/// admitted at its next announce instead.
const MAX_HELD_PAYLOAD: usize = 4096;
/// A candidate whose author stops announcing is dropped after this long.
const CANDIDATE_TTL: Duration = Duration::from_secs(90);
/// Most basis combinations a search can try; per-index capacity keeps every
/// search within it.
const MAX_COMBINATIONS: usize = 1024;
/// Minimum spacing of the announces this node sends in reply while learning.
const RECIPROCAL_INTERVAL: Duration = Duration::from_secs(20);
/// Searches allowed in a burst, then one per `SEARCH_INTERVAL`; changes made
/// while out of budget are searched on the next announce once it refills.
const SEARCH_BURST: u32 = 8;
const SEARCH_INTERVAL: Duration = Duration::from_secs(2);

/// Candidates kept per index: the search enumerates the candidates of
/// threshold - 2 indices, so their product must stay within
/// `MAX_COMBINATIONS`, and all indices together within `MAX_TOTAL_CANDIDATES`.
fn capacity(threshold: u16, total: u16) -> usize {
    let basis = u32::from(threshold.saturating_sub(2));
    let mut per_index = MAX_CANDIDATES;
    while per_index > 1
        && per_index
            .checked_pow(basis)
            .is_none_or(|c| c > MAX_COMBINATIONS)
    {
        per_index -= 1;
    }
    let others = usize::from(total.saturating_sub(1)).max(1);
    per_index.min((MAX_TOTAL_CANDIDATES / others).max(1))
}

struct Candidate {
    author: PublicKey,
    point: [u8; 33],
    element: ProjectivePoint,
    payload: Option<AnnouncePayload>,
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
    /// The set was just completed. `held` are other members' announces to
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
        context: &VerifyingSetContext,
        own_share: [u8; 33],
        author: PublicKey,
        payload: &AnnouncePayload,
        now: Instant,
    ) -> Learning {
        if self.complete.is_some() {
            return Learning::Known;
        }
        let Some(element) = verifying_share_point(&payload.verifying_share) else {
            return Learning::Pending { reciprocate: false };
        };
        let index = payload.share_index;
        for list in self.candidates.values_mut() {
            list.retain(|c| now.saturating_duration_since(c.last_seen) < CANDIDATE_TTL);
        }
        let held_payload = (serde_json::to_vec(payload).map_or(usize::MAX, |b| b.len())
            <= MAX_HELD_PAYLOAD)
            .then(|| payload.clone());
        let capacity = capacity(share.metadata.threshold, share.metadata.total_shares);
        let list = self.candidates.entry(index).or_default();
        let mut new_author = false;
        let mut changed = false;
        if let Some(existing) = list.iter_mut().find(|c| c.author == author) {
            if existing.point != payload.verifying_share {
                existing.point = payload.verifying_share;
                existing.element = element;
                existing.first_seen = now;
                changed = true;
            }
            existing.payload = held_payload;
            existing.last_seen = now;
        } else {
            if list.len() >= capacity {
                let evicted = ::rand::rng().random_range(0..list.len());
                list.swap_remove(evicted);
            }
            new_author = true;
            list.push(Candidate {
                author,
                point: payload.verifying_share,
                element,
                payload: held_payload,
                first_seen: now,
                last_seen: now,
            });
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
        self.dirty |= new_author || changed;
        if others
            .iter()
            .any(|i| self.candidates.get(i).is_none_or(|l| l.is_empty()))
            || !self.dirty
            || !self.take_search_budget(now)
        {
            return Learning::Pending { reciprocate };
        }
        self.dirty = false;

        let Some(picks) = self.search(context, &others) else {
            if !self.mismatch_reported {
                self.mismatch_reported = true;
                tracing::warn!(
                    "Every member has announced but no combination of their verifying shares fits this share; if this share was refreshed, import the refreshed share"
                );
            }
            return Learning::Pending { reciprocate };
        };
        let mut set: BTreeMap<u16, [u8; 33]> = picks
            .iter()
            .map(|(&i, &k)| (i, self.candidates[&i][k].point))
            .collect();
        set.insert(own, own_share);
        if complete_verifying_shares(share, &set).is_err() {
            return Learning::Pending { reciprocate };
        }
        let held = picks
            .iter()
            .map(|(&i, &k)| (i, &self.candidates[&i][k]))
            .filter(|(i, c)| !(*i == index && c.author == author))
            .filter_map(|(_, c)| c.payload.clone().map(|p| (c.author, p)))
            .collect();
        self.candidates.clear();
        self.complete = Some(set.clone());
        Learning::Completed { set, held }
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

    /// The candidate position chosen for each index in `others`. Enumerates
    /// the candidates of the threshold - 2 indices with the fewest; for each
    /// combination, predicts the other members' points one at a time (weighted
    /// basis points are computed once per target) and stops at the first
    /// prediction no candidate matches.
    fn search(
        &self,
        context: &VerifyingSetContext,
        others: &[u16],
    ) -> Option<BTreeMap<u16, usize>> {
        let basis_len = usize::from(context.threshold()).checked_sub(2)?;
        let mut by_count = others.to_vec();
        by_count.sort_by_key(|i| self.candidates[i].len());
        let (basis, targets) = by_count.split_at(basis_len);
        let radix: Vec<usize> = basis.iter().map(|i| self.candidates[i].len()).collect();
        if radix.iter().product::<usize>() > MAX_COMBINATIONS {
            return None;
        }

        // Per target: its constant and, per basis index, each candidate's
        // weighted point; built on first use.
        let mut weighted: Vec<Option<(ProjectivePoint, Vec<Vec<ProjectivePoint>>)>> =
            vec![None; targets.len()];
        let mut digits = vec![0usize; basis_len];
        loop {
            let mut picks = Vec::with_capacity(targets.len());
            for (t, &target) in targets.iter().enumerate() {
                if weighted[t].is_none() {
                    let prediction = context.prediction(basis, target)?;
                    let per_basis = basis
                        .iter()
                        .zip(&prediction.weights)
                        .map(|(i, w)| self.candidates[i].iter().map(|c| c.element * w).collect())
                        .collect();
                    weighted[t] = Some((prediction.constant, per_basis));
                }
                let (constant, per_basis) = weighted[t].as_ref()?;
                let predicted = per_basis
                    .iter()
                    .zip(&digits)
                    .fold(*constant, |acc, (cands, &d)| acc + cands[d]);
                match self.candidates[&target]
                    .iter()
                    .position(|c| c.element == predicted)
                {
                    Some(k) => picks.push((target, k)),
                    None => break,
                }
            }
            if picks.len() == targets.len() {
                let mut chosen: BTreeMap<u16, usize> = picks.into_iter().collect();
                chosen.extend(basis.iter().copied().zip(digits.iter().copied()));
                return Some(chosen);
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
        context: VerifyingSetContext,
        real: BTreeMap<u16, [u8; 33]>,
    }

    fn group_of(threshold: u16, total: u16) -> Group {
        let (shares, _) = TrustedDealer::new(ThresholdConfig::new(threshold, total).unwrap())
            .generate("learn")
            .unwrap();
        let real = verifying_share_map(&shares[0].pubkey_package().unwrap(), total).unwrap();
        let share = shares.into_iter().next().unwrap();
        Group {
            context: VerifyingSetContext::new(&share).unwrap(),
            share,
            real,
        }
    }

    fn group() -> Group {
        group_of(3, 5)
    }

    fn record(
        learned: &mut LearnedVerifyingShares,
        g: &Group,
        author: PublicKey,
        index: u16,
        point: [u8; 33],
        now: Instant,
    ) -> Learning {
        learned.record(
            &g.share,
            &g.context,
            g.real[&g.share.metadata.identifier],
            author,
            &payload(index, point),
            now,
        )
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
    fn full_slots_of_earlier_forgeries_do_not_lock_members_out() {
        let g = group();
        let cap = capacity(3, 5);
        let mut learned = LearnedVerifyingShares::default();
        let start = Instant::now();
        let forgers: Vec<(u16, PublicKey)> = (2..=5u16)
            .flat_map(|i| (0..cap).map(move |_| (i, Keys::generate().public_key())))
            .collect();
        let points: BTreeMap<PublicKey, [u8; 33]> =
            forgers.iter().map(|(_, a)| (*a, forged_point())).collect();
        let members: BTreeMap<u16, PublicKey> = (2..=5)
            .map(|i| (i, Keys::generate().public_key()))
            .collect();
        // Forgers fill every slot first and keep re-announcing; members keep
        // announcing too, every 20 s.
        let mut completed = None;
        for round in 0..60u32 {
            let now = start + Duration::from_secs(u64::from(round) * 20);
            for (index, forger) in &forgers {
                record(&mut learned, &g, *forger, *index, points[forger], now);
            }
            for (&index, &member) in &members {
                if let Learning::Completed { set, .. } = record(
                    &mut learned,
                    &g,
                    member,
                    index,
                    g.real[&index],
                    now + SEARCH_INTERVAL * 8,
                ) {
                    completed = Some(set);
                }
            }
            if completed.is_some() {
                break;
            }
        }
        assert_eq!(completed, Some(g.real.clone()));
    }

    #[test]
    fn a_full_slot_takes_a_newcomer_and_expires_silent_candidates() {
        let g = group();
        let cap = capacity(3, 5);
        let mut learned = LearnedVerifyingShares::default();
        let start = Instant::now();
        for _ in 0..(cap * 2) {
            record(
                &mut learned,
                &g,
                Keys::generate().public_key(),
                2,
                forged_point(),
                start,
            );
        }
        assert_eq!(learned.candidates[&2].len(), cap);
        let member = Keys::generate().public_key();
        record(&mut learned, &g, member, 2, g.real[&2], start);
        assert!(learned.candidates[&2].iter().any(|c| c.author == member));

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
    fn capacity_keeps_every_search_complete() {
        for total in [3u16, 5, 20, 255] {
            for threshold in 2..=total.min(40) {
                let per_index = capacity(threshold, total);
                assert!(per_index >= 1);
                let combos = per_index
                    .checked_pow(u32::from(threshold.saturating_sub(2)))
                    .unwrap();
                assert!(combos <= MAX_COMBINATIONS, "{threshold}-of-{total}");
                assert!(
                    per_index * usize::from(total - 1)
                        <= MAX_TOTAL_CANDIDATES.max(usize::from(total - 1))
                );
            }
        }
    }

    #[test]
    fn a_high_threshold_group_learns_its_set() {
        let g = group_of(16, 18);
        let mut learned = LearnedVerifyingShares::default();
        let now = Instant::now();
        let mut outcome = None;
        for i in 2..=18u16 {
            outcome = Some(record(
                &mut learned,
                &g,
                Keys::generate().public_key(),
                i,
                g.real[&i],
                now,
            ));
        }
        let Some(Learning::Completed { set, .. }) = outcome else {
            panic!("a 16-of-18 set must be learned");
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
        for _ in 0..40 {
            record(
                &mut learned,
                &g,
                Keys::generate().public_key(),
                3,
                forged_point(),
                now,
            );
        }
        assert!(!learned.take_search_budget(now));
        assert!(learned.take_search_budget(now + SEARCH_INTERVAL));
    }

    #[test]
    fn a_worst_case_search_is_fast() {
        let g = group_of(4, 20);
        let mut learned = LearnedVerifyingShares::default();
        let start = Instant::now();
        let cap = capacity(4, 20);
        for i in 2..=20u16 {
            for _ in 0..cap {
                record(
                    &mut learned,
                    &g,
                    Keys::generate().public_key(),
                    i,
                    forged_point(),
                    start,
                );
            }
        }
        let others: Vec<u16> = (2..=20).collect();
        let timer = Instant::now();
        assert!(learned.search(&g.context, &others).is_none());
        assert!(
            timer.elapsed() < Duration::from_secs(5),
            "worst-case search took {:?}",
            timer.elapsed()
        );
    }
}
