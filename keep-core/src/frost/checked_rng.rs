// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Secret generation that checks the draw the secret is built from.
//!
//! The periodic entropy probe certifies the source by drawing samples of its own.
//! A secret drawn afterwards comes from a different call, so a source that
//! fails between the probe and the draw yields key material no check ever
//! looked at. The window is narrow and periodic probing closes most of it, but
//! it is worth closing where the draw becomes a secret.
//!
//! For a nonce, because of how one is built: frost-core derives it as
//! `H3(random_bytes || signing_share)` (frost-core 3.0.0, `round1.rs:77-90`),
//! so a source stuck on a constant hands back the same nonce in every session,
//! and one nonce used over two different messages recovers the signing share.
//!
//! For the longer-lived secrets, because they outlive the session they are
//! drawn in. A degraded draw behind a DKG polynomial or a trusted-dealer split
//! makes the group key itself guessable, and behind a share refresh it makes
//! the refresh delta guessable, which means the refresh does not heal a
//! compromise it was run to heal. Those draws are 32-byte fills too, in a
//! rejection loop (k256 0.13.4, `arithmetic/scalar.rs:195-205`), so the same
//! criteria apply to them, and a polynomial of several coefficients gives more
//! consecutive draws to compare than a commitment does.
//!
//! What this catches, within one call: a source stuck on any constant; an
//! all-zero fill of any width; two blocks closer than the Hamming floor, which
//! is a source that moves but barely; a source cycling through a handful of
//! values, because every block is compared against all the blocks before it
//! and not just the one immediately before. A call that draws fewer blocks than the
//! criteria need draws more from the same source until it has them, so a call
//! that makes a single draw is judged rather than waved through. Bytes drawn
//! that no whole block could be formed from are refused outright instead of
//! being certified by those extra draws.
//!
//! What it does not catch, stated here so the check is not trusted past its
//! reach. The judge is built per call, so a source that replays the same
//! sequence across calls emits the same nonce pair in every session and passes
//! every comparison made here. That is the case that recovers the share, and it
//! is the gap tracked as follow-up work; within one call, hiding and binding
//! matching does not by itself recover anything. It also cannot see a source
//! that is compromised rather than broken: bytes an attacker chose but that
//! look statistically healthy pass every criterion, and no test at the draw can
//! do better. At a site that makes a single draw the only comparison is against
//! bytes drawn after the secret, which catches a source that is still degraded
//! when probed but not one that emits a single chosen value and then recovers.

// The Ed25519 half is gated on keep-core's `ed25519` feature. This file is also
// compiled into the enclave, which does not declare that feature.
#![allow(unexpected_cfgs)]

use frost_secp256k1_tr::rand_core::{impls, CryptoRng, Error as RngError, OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

/// Why a draw could not be trusted.
///
/// The two arms are kept apart because they call for different responses. A
/// source that answered with constant output is a property of the machine and
/// will not improve on its own, so a co-signer should stop and stay stopped.
/// A call that failed to complete is a different statement, closer to "no file
/// descriptors" than to "the kernel is broken", and treating it as permanent
/// turns a transient fault into an outage that needs an operator to clear.
/// They also read differently in a log, which matters when someone is trying to
/// work out what happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyHealthError {
    /// The source answered, and what it returned failed the health criteria.
    Degraded,
    /// The source could not be read at all.
    Unavailable,
}

impl std::fmt::Display for EntropyHealthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Degraded => write!(
                f,
                "RNG health check failed: constant or zero output detected"
            ),
            Self::Unavailable => write!(f, "RNG unavailable: the OS refused to provide entropy"),
        }
    }
}

impl std::error::Error for EntropyHealthError {}

/// How many bits differ between two 32-byte draws.
pub(crate) fn hamming_distance(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

/// Bits two draws must differ by before they count as independent.
pub(crate) const MIN_HAMMING: u32 = 64;

/// The most byte positions that may hold the same value in every sample before
/// the samples are refused. Only meaningful across three or more samples.
pub(crate) const MAX_FROZEN_POSITIONS: usize = 3;

/// How many of the 32 byte positions hold the same value, whatever it is, in
/// every one of `samples`.
///
/// This replaces a test that refused any position holding `0x00` or `0xff` in
/// every sample, which got both its rate and its coverage wrong.
///
/// Its rate: that happens to healthy randomness about once in 260,000
/// three-sample calls, measured at 12 in 3,000,000 checked draws against the
/// analytic 11.4. Every failure latches a co-signing node, and the periodic
/// check runs every 30 seconds, so a healthy always-on node took itself out of
/// service about once a month.
///
/// Its coverage: it caught a frozen extreme byte, and any number of them, but
/// never a frozen byte of any other value. A source that fills part of a buffer
/// and leaves the rest as it was is the case that matters, because several
/// draws turn bytes straight into a scalar with no hash between: the dealer's
/// key, every polynomial coefficient, refresh and repair deltas, and the DKG
/// proof-of-knowledge nonce. Twelve frozen bytes there leave 160 bits in known
/// positions, about 2^80 work to recover, and the Hamming floor does not catch
/// it until roughly half the bytes are frozen.
///
/// Counting positions frozen at any value, and refusing above
/// [`MAX_FROZEN_POSITIONS`], fixes both. A position matches across three
/// independent samples with probability 1 in 65,536, so four or more of 32
/// doing so is a binomial tail of about 2e-15, the same order as the Hamming
/// floor, and no healthy node latches on it. What it still lets through, one to
/// three frozen positions, leaves at least 232 bits.
///
/// Three samples is the floor. Across two, a position matches with probability
/// 1 in 256, and four of 32 matching becomes about 8e-6 per call, which is the
/// rate this exists to get away from.
pub(crate) fn frozen_positions(samples: &[[u8; 32]]) -> usize {
    debug_assert!(
        samples.len() >= 3,
        "frozen_positions needs three samples; below that healthy input trips it"
    );
    let Some((first, rest)) = samples.split_first() else {
        return 0;
    };
    (0..32)
        .filter(|&pos| rest.iter().all(|s| s[pos] == first[pos]))
        .count()
}

/// The health criteria for a pair of draws, for a caller judging the bytes it
/// was handed rather than a sample drawn beside them: neither draw all-zero,
/// the two distinct, and at least [`MIN_HAMMING`] bits apart, which a source
/// repeating itself with a handful of bits flipped still fails.
///
/// These are the same criteria the periodic entropy probe applies to each of
/// its pairs. The frozen-position count is not among them, because across two
/// samples healthy randomness trips it often enough to latch a node; it needs
/// three, see [`frozen_positions`].
pub(crate) fn pair_looks_random(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let nonzero = |s: &[u8; 32]| s.iter().any(|&b| b != 0);
    nonzero(a) && nonzero(b) && a != b && hamming_distance(a, b) >= MIN_HAMMING
}

/// An RNG that holds every fill it hands out to the health criteria.
///
/// `RngCore` cannot fail, so a bad draw is recorded and whoever drew has to
/// consult it afterwards. The fields are private and there is no public
/// constructor, so that obligation cannot be missed by a caller who does not
/// know it exists: [`checked_draw`] is the only way to one, and it always
/// consults the verdict.
pub struct CheckedRng<R> {
    inner: R,
    /// The blocks judged so far, so each new one is compared against all of
    /// them and not just against its neighbor. Holding one block alone makes
    /// the comparisons adjacent-only, which a source alternating two values
    /// passes: it is never asked whether a block it already emitted came back.
    /// Cleared on drop, though frost-core leaves its own copy of the same
    /// bytes, and the serialized signing share beside them, unscrubbed on the
    /// heap, so this is hygiene rather than a boundary anything should lean on.
    judged: Vec<Zeroizing<[u8; 32]>>,
    /// Bytes from a fill that did not end on a block boundary, held so the
    /// remainder joins the next fill instead of going unjudged. Never 32 or
    /// more: a full block is judged and this resets.
    pending: Zeroizing<[u8; 32]>,
    pending_len: usize,
    /// How many 32-byte blocks have been judged, counted separately from
    /// `judged` because that one stops growing at [`MAX_RETAINED`].
    blocks: usize,
    /// How many fills the closure asked for, at any width.
    fills: usize,
    fault: Option<EntropyHealthError>,
}

/// How many judged blocks are kept for comparison.
///
/// Every new block is compared against all of these, so the work is quadratic
/// in what is retained. Well past the widest draw any call here makes: a
/// threshold-5 DKG polynomial is 6 blocks, and an Ed25519 dealer split at that
/// threshold is 6 too, so in practice nothing is ever dropped.
const MAX_RETAINED: usize = 8;

/// How many blocks a call must have judged before its verdict is trusted.
///
/// Two allow exactly one comparison, which a source alternating two values
/// passes: draw A, probe B, A against B looks healthy while the source holds
/// one bit of entropy. Three is the smallest number that catches it, because
/// the third block is A again and A against A fails.
const MIN_JUDGED: usize = 3;

impl<R: RngCore> CheckedRng<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            judged: Vec::new(),
            pending: Zeroizing::new([0u8; 32]),
            pending_len: 0,
            blocks: 0,
            fills: 0,
            fault: None,
        }
    }

    fn judge(&mut self, drawn: &[u8]) {
        if drawn.is_empty() {
            return;
        }
        self.fills += 1;
        if drawn.iter().all(|&b| b == 0) {
            self.fault = Some(EntropyHealthError::Degraded);
            return;
        }
        // Accumulated into whole blocks rather than judged per fill, so the
        // width a consumer happens to use cannot leave bytes unexamined. That
        // matters: a secp256k1 scalar is one 32-byte fill (k256 0.13.4,
        // `arithmetic/scalar.rs:195-205`) while an Ed25519 scalar is a single
        // 64-byte one (curve25519-dalek 4.1.3, `scalar.rs:597-601`), and a rule
        // written for one width alone judges nothing at all on the other.
        // Anything left over at the end of the call is accounted for in
        // `finish`, so a ragged total cannot pass as checked.
        let mut rest = drawn;
        while !rest.is_empty() {
            let take = (32 - self.pending_len).min(rest.len());
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&rest[..take]);
            self.pending_len += take;
            rest = &rest[take..];
            if self.pending_len == 32 {
                self.judge_block(Zeroizing::new(*self.pending));
                self.pending_len = 0;
            }
        }
    }

    fn judge_block(&mut self, block: Zeroizing<[u8; 32]>) {
        let repeats = self
            .judged
            .iter()
            .any(|previous| !pair_looks_random(previous, &block));
        if repeats {
            self.fault = Some(EntropyHealthError::Degraded);
        }
        self.blocks += 1;
        if self.judged.len() < MAX_RETAINED {
            self.judged.push(block);
        }
    }

    /// Draw extra blocks from the same source until [`MIN_JUDGED`] have been
    /// judged.
    ///
    /// One draw can be checked for nothing beyond being all zero, because the
    /// criteria compare one draw against another. Some calls make exactly one:
    /// a share refresh at a threshold of two draws a single coefficient
    /// (frost-core 3.0.0, `keys/refresh.rs:82`), and that coefficient is the
    /// refresh delta, so leaving it unjudged would mean a refresh that heals
    /// nothing while reporting success.
    ///
    /// Drawing what the comparison needs closes that on the first such call.
    /// Carrying a block between calls instead would miss it, because the call
    /// that matters is often the only one a short-lived process makes, and
    /// would keep bytes that fed a secret alive process-wide for nothing. The
    /// probe is never used for anything and goes out of scope here.
    ///
    /// Worth being exact about what a probe buys at a one-block site: the only
    /// comparison is the secret block against bytes drawn after it. That
    /// catches a source stuck, cycling or barely moving, because such a source
    /// is still that way when probed. It says nothing about a source that emits
    /// one chosen value and then healthy bytes, which no check at the draw can
    /// see.
    fn finish(&mut self) {
        // The closure never touched this source, so it drew no secret here and
        // there is nothing to judge. Reached on an ordinary error path:
        // frost-core validates signer counts before it draws, so a refused
        // threshold returns without a fill. Not a verdict, so not a fault, and
        // not an assertion either: asserting here turns that validation error
        // into a panic in any build with debug assertions on.
        if self.fills == 0 {
            return;
        }
        // Bytes were drawn that no block could be formed from, so the criteria
        // never saw them. `Unavailable` rather than `Degraded` because this is
        // the absence of a verdict, not a bad one: nothing was learned about
        // the source, so a caller should refuse this draw without concluding
        // the machine is broken. No call here can reach it today, since every
        // fill behind these secrets is 32 or 64 bytes wide; it is what stops a
        // narrower draw from being certified by probe blocks alone, which would
        // read as assurance over bytes nothing examined.
        if self.pending_len > 0 || self.blocks == 0 {
            self.fault = Some(EntropyHealthError::Unavailable);
            return;
        }
        while self.fault.is_none() && self.blocks < MIN_JUDGED {
            let mut probe = Zeroizing::new([0u8; 32]);
            self.fill_bytes(probe.as_mut());
        }
        // A source that fills only part of what it is asked for leaves the rest
        // as it was, so the same byte positions hold the same value in every
        // block. The pairwise checks miss that until about half the bytes are
        // frozen, and several draws here take bytes straight into a scalar,
        // so it is counted across every block judged. The threshold and why it
        // does not latch a healthy node are on `frozen_positions`.
        if self.fault.is_none() && self.judged.len() >= MIN_JUDGED {
            let blocks = Zeroizing::new(self.judged.iter().map(|b| **b).collect::<Vec<_>>());
            if frozen_positions(&blocks) > MAX_FROZEN_POSITIONS {
                self.fault = Some(EntropyHealthError::Degraded);
            }
        }
    }
}

impl<R> Drop for CheckedRng<R> {
    fn drop(&mut self) {
        self.judged.zeroize();
        self.pending.zeroize();
    }
}

impl<R: RngCore> RngCore for CheckedRng<R> {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
        self.judge(dest);
    }

    /// Nothing on the nonce path reaches this: frost-core fills through
    /// `fill_bytes` (frost-core 3.0.0, `round1.rs:54`), and `OsRng::fill_bytes`
    /// panics rather than reporting a source it could not read, so a draw here
    /// can only ever come back `Degraded`, never `Unavailable`.
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.inner.try_fill_bytes(dest)?;
        self.judge(dest);
        Ok(())
    }
}

impl<R: CryptoRng + RngCore> CryptoRng for CheckedRng<R> {}

/// Run `draw` against a judged source, refusing what it produced if any fill
/// behind it failed the health criteria.
///
/// The judged source can only be reached from inside `draw`, and the verdict is
/// consulted on the way out, so there is no way to hold one and skip the check.
///
/// On the error path the value `draw` returned is dropped rather than handed
/// back, so key material from a bad draw is not left where a caller could
/// reach it; the frost-core types that carry secrets are `ZeroizeOnDrop`, so
/// dropping them clears them.
///
/// That covers the returned value and nothing else. A closure that captures
/// something writable and copies drawn bytes into it has put them beyond this
/// function's reach, and no verdict reached afterwards can take them back, so
/// a `draw` closure should return what it drew rather than stash it.
pub fn checked_draw<T>(
    draw: impl FnOnce(&mut CheckedRng<OsRng>) -> T,
) -> Result<T, EntropyHealthError> {
    checked_draw_from(OsRng, draw)
}

fn checked_draw_from<R: CryptoRng + RngCore, T>(
    source: R,
    draw: impl FnOnce(&mut CheckedRng<R>) -> T,
) -> Result<T, EntropyHealthError> {
    let mut rng = CheckedRng::new(source);
    let drawn = draw(&mut rng);
    rng.finish();
    match rng.fault {
        Some(e) => Err(e),
        None => Ok(drawn),
    }
}

/// `round1::commit` through [`checked_draw`].
pub fn commit_checked(
    share: &frost_secp256k1_tr::keys::SigningShare,
) -> Result<
    (
        frost_secp256k1_tr::round1::SigningNonces,
        frost_secp256k1_tr::round1::SigningCommitments,
    ),
    EntropyHealthError,
> {
    checked_draw(|rng| {
        #[expect(clippy::disallowed_methods)] // the one sanctioned draw
        frost_secp256k1_tr::round1::commit(share, rng)
    })
}

/// [`commit_checked`] for the Ed25519 ciphersuite.
#[cfg(feature = "ed25519")]
pub fn commit_checked_ed25519(
    share: &frost_ed25519::keys::SigningShare,
) -> Result<
    (
        frost_ed25519::round1::SigningNonces,
        frost_ed25519::round1::SigningCommitments,
    ),
    EntropyHealthError,
> {
    checked_draw(|rng| {
        #[expect(clippy::disallowed_methods)] // the one sanctioned draw
        frost_ed25519::round1::commit(share, rng)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_share(seed: u8) -> frost_secp256k1_tr::keys::SigningShare {
        let mut key = [seed; 32];
        key[31] = 1;
        frost_secp256k1_tr::keys::SigningShare::deserialize(&key).unwrap()
    }

    /// Fills every byte with the same value every time, which is a source stuck
    /// on a constant.
    struct StuckRng(u8);

    /// Distinct each draw but barely moving, which is a source with almost no
    /// entropy rather than a frozen one.
    struct CreepingRng(u8);

    /// Copies the first half of every fill over the second. Healthy from one
    /// fill to the next, and repeating itself inside a wide one, so nothing but
    /// judging a wide fill against itself can see it.
    struct MirroredRng;

    impl RngCore for MirroredRng {
        fn next_u32(&mut self) -> u32 {
            impls::next_u32_via_fill(self)
        }
        fn next_u64(&mut self) -> u64 {
            impls::next_u64_via_fill(self)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let (head, tail) = dest.split_at_mut(dest.len() / 2);
            OsRng.fill_bytes(head);
            tail.copy_from_slice(&head[..tail.len()]);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for MirroredRng {}

    macro_rules! impl_rng {
        ($t:ty, |$s:ident, $dest:ident| $body:block) => {
            impl RngCore for $t {
                fn next_u32(&mut self) -> u32 {
                    impls::next_u32_via_fill(self)
                }
                fn next_u64(&mut self) -> u64 {
                    impls::next_u64_via_fill(self)
                }
                fn fill_bytes(&mut self, dest: &mut [u8]) {
                    let $s = self;
                    let $dest = dest;
                    $body
                }
                fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
                    self.fill_bytes(dest);
                    Ok(())
                }
            }
            impl CryptoRng for $t {}
        };
    }

    impl_rng!(StuckRng, |s, dest| {
        dest.fill(s.0);
    });

    /// Alternates between two values that are far apart, so every comparison
    /// against the block immediately before it passes while the source holds
    /// one bit of entropy. Only comparing a block against every block already
    /// judged, over at least three of them, can see it.
    struct CyclingRng(bool);

    impl_rng!(CyclingRng, |s, dest| {
        dest.fill(if s.0 { 0x00 } else { 0xff });
        dest[0] = if s.0 { 0x01 } else { 0xfe };
        s.0 = !s.0;
    });

    /// Random except for one byte position that holds the same value in every
    /// block. A position matching across three blocks happens to healthy
    /// randomness once in 65,536 per position, so one or a few must not be
    /// refused; see `frozen_positions` for where the line is.
    struct ConstantPositionRng;

    /// Fills only the first `.0` bytes of every 32-byte block and leaves the
    /// rest at `.1`, which is a source that does part of what it is asked and
    /// is the case the frozen-position count exists for.
    struct PartialFillRng(usize, u8);

    /// Three blocks with exactly `.0` positions frozen and no others, built
    /// rather than drawn. The unfrozen bytes take a different value in each
    /// block, so none of them can match by chance and push the count past
    /// `.0`, which is what made a random head flaky at the boundary. Every pair
    /// is still nonzero, distinct and at least 112 bits apart, so the count is
    /// the only criterion in play.
    struct ExactlyFrozenRng(usize, usize);

    impl_rng!(ExactlyFrozenRng, |s, dest| {
        const UNFROZEN: [u8; 3] = [0x0f, 0xf0, 0x33];
        for block in dest.chunks_mut(32) {
            let value = UNFROZEN[s.1 % UNFROZEN.len()];
            for (pos, byte) in block.iter_mut().enumerate() {
                *byte = if pos < s.0 { 0x00 } else { value };
            }
            s.1 += 1;
        }
    });

    impl_rng!(PartialFillRng, |s, dest| {
        for block in dest.chunks_mut(32) {
            let (head, tail) = block.split_at_mut(s.0.min(block.len()));
            OsRng.fill_bytes(head);
            tail.fill(s.1);
        }
    });

    impl_rng!(ConstantPositionRng, |_s, dest| {
        OsRng.fill_bytes(dest);
        for block in dest.chunks_mut(32) {
            block[5] = 0x00;
        }
    });

    /// Healthy, and counts the bytes drawn through it, for pinning how much a
    /// call draws beyond the secret itself.
    #[derive(Default)]
    struct CountingRng(usize);

    impl_rng!(CountingRng, |s, dest| {
        s.0 += dest.len();
        OsRng.fill_bytes(dest);
    });

    impl_rng!(CreepingRng, |s, dest| {
        dest.fill(0x5a);
        dest[0] = s.0;
        s.0 = s.0.wrapping_add(1);
    });

    /// The failure this exists for, end to end through `round1::commit` rather
    /// than against the criteria alone: a commitment draws twice, so a stuck
    /// source makes hiding and binding the same nonce, and every session after
    /// it repeats that nonce.
    #[test]
    fn a_commitment_from_a_stuck_source_is_refused() {
        assert_eq!(
            checked_draw_from(StuckRng(0xab), |rng| {
                #[expect(clippy::disallowed_methods)] // drawn through the checked source
                frost_secp256k1_tr::round1::commit(&test_share(3), rng)
            }),
            Err(EntropyHealthError::Degraded)
        );
    }

    /// The pair test can say nothing until a second draw arrives, and a fill
    /// narrower than a pair is never compared at all, so a source answering
    /// with zeros is refused on the fill itself. That is the only check on the
    /// `next_u32`/`next_u64` path, which is routed through `fill_bytes` so that
    /// every byte handed out is looked at.
    #[test]
    fn a_zero_fill_is_refused_on_its_own() {
        let mut wide = CheckedRng::new(OsRng);
        wide.judge(&[0u8; 32]);
        assert_eq!(wide.fault, Some(EntropyHealthError::Degraded));

        let mut narrow = CheckedRng::new(OsRng);
        narrow.judge(&[0u8; 4]);
        assert_eq!(
            narrow.fault,
            Some(EntropyHealthError::Degraded),
            "a width the pair criteria cannot judge still gets this one"
        );
    }

    /// Distinct is not enough. Two draws a few bits apart are not independent,
    /// and a source that only creeps is as reusable as one that is frozen.
    #[test]
    fn a_commitment_from_a_barely_moving_source_is_refused() {
        assert_eq!(
            checked_draw_from(CreepingRng(0), |rng| {
                #[expect(clippy::disallowed_methods)] // drawn through the checked source
                frost_secp256k1_tr::round1::commit(&test_share(3), rng)
            }),
            Err(EntropyHealthError::Degraded)
        );
    }

    /// The healthy case, so none of the above can pass by refusing everything.
    #[test]
    fn the_os_source_passes_and_commits() {
        let share = test_share(7);
        let (first, _) = commit_checked(&share).expect("the OS source must pass");
        let (second, _) = commit_checked(&share).expect("the OS source must pass");
        assert_ne!(
            first.hiding().serialize(),
            first.binding().serialize(),
            "hiding and binding come from two draws and must differ"
        );
        assert_ne!(
            first.hiding().serialize(),
            second.hiding().serialize(),
            "a second commitment must not repeat the first"
        );
    }

    /// The long-lived secrets go through the same criteria, and get more
    /// comparisons than a nonce does: a trusted-dealer split draws a
    /// polynomial, so a stuck source is caught between its coefficients.
    ///
    /// This is the draw that matters most. A nonce from a bad draw loses the
    /// share; this one never had a group key worth protecting in the first
    /// place, and no later step can recover from it.
    #[test]
    fn a_group_key_from_a_stuck_source_is_refused() {
        assert_eq!(
            checked_draw_from(StuckRng(0xab), |rng| {
                #[expect(clippy::disallowed_methods)] // drawn through the checked source
                frost_secp256k1_tr::keys::generate_with_dealer(
                    3,
                    2,
                    frost_secp256k1_tr::keys::IdentifierList::Default,
                    rng,
                )
            })
            .err(),
            Some(EntropyHealthError::Degraded)
        );
    }

    /// The healthy case for the same draw, so the refusal above cannot be a
    /// gate that says no to everything.
    #[test]
    fn the_os_source_produces_a_group_key() {
        let (shares, _) = checked_draw(|rng| {
            #[expect(clippy::disallowed_methods)] // drawn through the checked source
            frost_secp256k1_tr::keys::generate_with_dealer(
                3,
                2,
                frost_secp256k1_tr::keys::IdentifierList::Default,
                rng,
            )
        })
        .expect("the OS source must pass")
        .expect("dealer generation must succeed");
        assert_eq!(shares.len(), 3);
    }

    /// A call that draws once is judged because the probe supplies the second
    /// block the criteria need. Without it the only check on a lone draw is
    /// whether it is all zero, and a share refresh at a threshold of two is
    /// exactly that shape, with the refresh delta as the secret at stake.
    #[test]
    fn a_single_draw_is_probed_until_it_can_be_judged() {
        assert_eq!(
            checked_draw_from(StuckRng(0x5a), |rng| {
                let mut buf = [0u8; 32];
                rng.fill_bytes(&mut buf);
            })
            .err(),
            Some(EntropyHealthError::Degraded),
            "one draw plus the probe is two blocks, which a stuck source fails"
        );
    }

    /// A fill wider than one block is judged against itself, on the bytes that
    /// became the secret rather than on a probe drawn after it. An Ed25519
    /// scalar is a single 64-byte fill, so a rule written for 32 bytes alone
    /// would judge nothing of that whole ciphersuite at the point of use.
    ///
    /// `MirroredRng` is what isolates this from the probe: it looks healthy
    /// from one fill to the next and repeats itself inside a wide one, so only
    /// judging block by block catches it. A probe drawn afterwards would not,
    /// which is the same weakness as certifying the source beside the draw
    /// instead of the draw itself.
    #[test]
    fn a_wide_fill_is_judged_block_by_block() {
        assert_eq!(
            checked_draw_from(MirroredRng, |rng| {
                let mut buf = [0u8; 64];
                rng.fill_bytes(&mut buf);
            })
            .err(),
            Some(EntropyHealthError::Degraded)
        );
    }

    /// And a stuck source is caught at a wide fill as well, through whichever
    /// of the two tests reaches it first.
    #[test]
    fn a_wide_fill_from_a_stuck_source_is_refused() {
        assert_eq!(
            checked_draw_from(StuckRng(0x5a), |rng| {
                let mut buf = [0u8; 64];
                rng.fill_bytes(&mut buf);
            })
            .err(),
            Some(EntropyHealthError::Degraded)
        );
    }

    /// The Ed25519 group key, which is the case the width rule above exists
    /// for: every scalar on that ciphersuite arrives as one 64-byte fill.
    #[cfg(feature = "ed25519")]
    #[test]
    fn an_ed25519_group_key_from_a_stuck_source_is_refused() {
        assert_eq!(
            checked_draw_from(StuckRng(0xab), |rng| {
                #[expect(clippy::disallowed_methods)] // drawn through the checked source
                frost_ed25519::keys::generate_with_dealer(
                    3,
                    2,
                    frost_ed25519::keys::IdentifierList::Default,
                    rng,
                )
            })
            .err(),
            Some(EntropyHealthError::Degraded)
        );
    }

    /// The healthy Ed25519 case, so the refusal above is not the only answer.
    #[cfg(feature = "ed25519")]
    #[test]
    fn the_os_source_produces_an_ed25519_group_key() {
        let (shares, _) = checked_draw(|rng| {
            #[expect(clippy::disallowed_methods)] // drawn through the checked source
            frost_ed25519::keys::generate_with_dealer(
                3,
                2,
                frost_ed25519::keys::IdentifierList::Default,
                rng,
            )
        })
        .expect("the OS source must pass")
        .expect("dealer generation must succeed");
        assert_eq!(shares.len(), 3);
    }

    /// A zero-width fill is not a stuck source. `all` is true over nothing, so
    /// the all-zero test has to say so explicitly.
    #[test]
    fn an_empty_fill_is_not_a_fault() {
        let mut checked = CheckedRng::new(OsRng);
        checked.judge(&[]);
        assert_eq!(checked.fault, None);
    }

    /// A source alternating two values passes every adjacent comparison, so
    /// retaining one block is not enough. Three secp256k1 coefficients come
    /// back A, B, A, and only a block compared against every earlier one
    /// catches the repeat.
    #[test]
    fn a_source_alternating_two_values_is_refused() {
        let mut rng = CheckedRng::new(CyclingRng(true));
        let mut block = [0u8; 32];
        for _ in 0..3 {
            rng.fill_bytes(&mut block);
        }
        rng.finish();
        assert_eq!(
            rng.fault,
            Some(EntropyHealthError::Degraded),
            "a period-two source must not pass"
        );
    }

    /// The same source through a real key generation, so the refusal is not
    /// just a property of the criteria in isolation.
    #[test]
    fn a_group_key_from_an_alternating_source_is_refused() {
        assert_eq!(
            checked_draw_from(CyclingRng(true), |rng| {
                #[expect(clippy::disallowed_methods)]
                frost_secp256k1_tr::keys::generate_with_dealer(
                    3,
                    2,
                    frost_secp256k1_tr::keys::IdentifierList::Default,
                    rng,
                )
            })
            .err(),
            Some(EntropyHealthError::Degraded)
        );
    }

    /// Bytes too narrow to form a block cannot be judged, and must not be
    /// certified by the probe blocks drawn after them. Without this the verdict
    /// would be `Ok` over bytes no criterion looked at, which reads as
    /// assurance and is worse than no check.
    #[test]
    fn a_draw_too_narrow_to_judge_is_refused() {
        let verdict = checked_draw_from(OsRng, |rng| {
            let mut narrow = [0u8; 8];
            rng.fill_bytes(&mut narrow);
        });
        assert_eq!(verdict.err(), Some(EntropyHealthError::Unavailable));
    }

    /// A fill that does not end on a block boundary leaves a remainder, and the
    /// remainder is secret material too. Either it joins the next fill or the
    /// call is refused; it is never silently dropped.
    #[test]
    fn a_ragged_fill_is_not_passed_as_checked() {
        let verdict = checked_draw_from(OsRng, |rng| {
            let mut ragged = [0u8; 48];
            rng.fill_bytes(&mut ragged);
        });
        assert_eq!(verdict.err(), Some(EntropyHealthError::Unavailable));

        // Two of them do complete a block between them, so the remainder is
        // carried rather than discarded.
        let verdict = checked_draw_from(OsRng, |rng| {
            let mut ragged = [0u8; 48];
            rng.fill_bytes(&mut ragged);
            rng.fill_bytes(&mut ragged);
        });
        assert!(verdict.is_ok(), "a carried remainder must complete a block");
    }

    /// A closure that never draws is an ordinary error path, not a fault and
    /// not a panic: frost-core validates signer counts before it touches the
    /// source, so a refused threshold returns without a fill.
    #[test]
    fn a_closure_that_never_draws_is_not_a_fault() {
        let verdict = checked_draw_from(OsRng, |_| 7);
        assert_eq!(verdict, Ok(7));
    }

    /// A one-block draw is probed up to the three blocks the criteria need, and
    /// the probes come from the same source rather than being invented.
    #[test]
    fn a_single_draw_is_probed_up_to_three_blocks() {
        let mut counter = CountingRng::default();
        let verdict = {
            let rng = &mut counter;
            checked_draw_from(rng, |rng| {
                let mut block = [0u8; 32];
                rng.fill_bytes(&mut block);
            })
        };
        assert!(verdict.is_ok());
        assert_eq!(
            counter.0, 96,
            "one secret block plus two probes, all from the judged source"
        );
    }

    /// A byte position that repeats across the blocks of one call is not a
    /// fault on its own. The test this replaces refused a single position held
    /// at `0x00` or `0xff`, which healthy randomness does about once in 260,000
    /// three-block calls, and since a refusal latches a co-signer, a node making
    /// nonce commitments took itself out of service at that rate.
    #[test]
    fn a_byte_position_repeating_across_blocks_is_not_a_fault() {
        let mut rng = CheckedRng::new(ConstantPositionRng);
        let mut block = [0u8; 32];
        for _ in 0..3 {
            rng.fill_bytes(&mut block);
        }
        rng.finish();
        assert_eq!(rng.fault, None);
    }

    fn verdict_of(source: impl RngCore + CryptoRng) -> Option<EntropyHealthError> {
        let mut rng = CheckedRng::new(source);
        let mut block = [0u8; 32];
        for _ in 0..3 {
            rng.fill_bytes(&mut block);
        }
        rng.finish();
        rng.fault
    }

    /// A source that fills twenty bytes of each block and leaves twelve zero is
    /// refused. Every pair is still distinct, nonzero and well past the
    /// Hamming floor, so nothing but the frozen-position count sees it, and
    /// before that count existed it passed. A draw that turns bytes straight
    /// into a scalar would then hold 96 known bits.
    #[test]
    fn a_source_filling_only_part_of_each_block_is_refused() {
        assert_eq!(
            verdict_of(PartialFillRng(20, 0x00)),
            Some(EntropyHealthError::Degraded)
        );
    }

    /// The count is of positions frozen at any value. The test it replaces
    /// only ever looked for `0x00` and `0xff`, so a source leaving its unfilled
    /// bytes at anything else passed it.
    #[test]
    fn a_frozen_region_of_any_value_is_refused() {
        assert_eq!(
            verdict_of(PartialFillRng(20, 0x5a)),
            Some(EntropyHealthError::Degraded)
        );
    }

    /// The line is four frozen positions: three pass and four do not. Three
    /// leaves at least 232 bits per block, and refusing at fewer would bring
    /// back the rate the old test latched healthy nodes at.
    ///
    /// Built rather than drawn: with random unfrozen bytes, any one of them
    /// matching across the three blocks by chance tips three into four, which
    /// made this fail on a healthy source about once in 2,260 runs.
    #[test]
    fn three_frozen_positions_pass_and_four_are_refused() {
        assert_eq!(verdict_of(ExactlyFrozenRng(3, 0)), None);
        assert_eq!(
            verdict_of(ExactlyFrozenRng(4, 0)),
            Some(EntropyHealthError::Degraded)
        );
    }
}
