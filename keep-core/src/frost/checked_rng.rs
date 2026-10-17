// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Secret generation that checks the draw the secret is built from.
//!
//! [`check_entropy_health`] certifies the source by drawing samples of its own.
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
//! What this catches: a source stuck on any constant, because a commitment
//! draws twice and the two come back equal; an all-zero fill of any width; and
//! two draws in one commitment closer than the Hamming floor, which is a source
//! that moves but barely.
//!
//! What it does not catch, stated here so the check is not trusted past its
//! reach. It compares only the draws inside one commitment, since the judge is
//! built per call, so a source that replays a sequence across commitments emits
//! the same nonce pair in every session and passes every comparison made here.
//! That is the case that recovers the share, and it is the gap tracked as
//! follow-up work; within one commitment, hiding and binding matching does not
//! by itself recover anything. It also cannot see a source that is compromised
//! rather than broken: bytes an attacker chose but that look statistically
//! healthy pass every criterion, and no test at the draw can do better. The
//! three-sample probe in keep-frost-net covers a short cycle that this misses,
//! but it is periodic and exists only there, so keep-core and keep-cli callers
//! have the within-commitment check alone.
//!
//! [`check_entropy_health`]: crate::entropy::check_entropy_health

use frost_secp256k1_tr::rand_core::{impls, CryptoRng, Error as RngError, OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::entropy::{pair_looks_random, EntropyHealthError};

/// An RNG that holds every fill it hands out to the health criteria.
///
/// `RngCore` cannot fail, so a bad draw is recorded and whoever drew has to
/// consult it afterwards. The fields are private and there is no public
/// constructor, so that obligation cannot be missed by a caller who does not
/// know it exists: [`checked_draw`] is the only way to one, and it always
/// consults the verdict.
pub struct CheckedRng<R> {
    inner: R,
    /// The last 32-byte block judged, for the next one to be compared against.
    /// Cleared on drop, though frost-core leaves its own copy of the same
    /// bytes, and the serialized signing share beside them, unscrubbed on the
    /// heap, so this is hygiene rather than a boundary anything should lean on.
    previous: Option<[u8; 32]>,
    /// How many 32-byte blocks have been judged, which is what decides whether
    /// any comparison actually happened.
    blocks: usize,
    /// How many fills the closure asked for, at any width.
    fills: usize,
    fault: Option<EntropyHealthError>,
}

impl<R: RngCore> CheckedRng<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            previous: None,
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
        // Block by block, so a fill wider than one block is judged against
        // itself rather than skipped. That matters: a secp256k1 scalar is one
        // 32-byte fill (k256 0.13.4, `arithmetic/scalar.rs:195-205`) while an
        // Ed25519 scalar is a single 64-byte one (curve25519-dalek 4.1.3,
        // `scalar.rs:597-601`), so a rule written for one width alone would
        // quietly judge nothing at all on the other.
        let (blocks, _partial) = drawn.as_chunks::<32>();
        for block in blocks {
            let block = Zeroizing::new(*block);
            if let Some(previous) = &self.previous {
                if !pair_looks_random(previous, &block) {
                    self.fault = Some(EntropyHealthError::Degraded);
                }
            }
            self.previous = Some(*block);
            self.blocks += 1;
        }
    }

    /// Draw extra blocks from the same source until two have been judged.
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
    fn probe_until_comparable(&mut self) {
        // Zero fills means the closure never touched this source, so whatever
        // it drew went unjudged. Not a verdict on the source, so not a fault:
        // a debug assertion, which is where a draw written against `OsRng`
        // instead of the source handed to it gets caught.
        debug_assert!(
            self.fills > 0,
            "checked_draw drew nothing through the checked source"
        );
        while self.fault.is_none() && self.blocks < 2 {
            let mut probe = Zeroizing::new([0u8; 32]);
            self.fill_bytes(probe.as_mut());
        }
    }
}

impl<R> Drop for CheckedRng<R> {
    fn drop(&mut self) {
        self.previous.zeroize();
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
    rng.probe_until_comparable();
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
        #[allow(clippy::disallowed_methods)] // the one sanctioned draw
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
        #[allow(clippy::disallowed_methods)] // the one sanctioned draw
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
                #[allow(clippy::disallowed_methods)] // drawn through the checked source
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
                #[allow(clippy::disallowed_methods)] // drawn through the checked source
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
                #[allow(clippy::disallowed_methods)] // drawn through the checked source
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
            #[allow(clippy::disallowed_methods)] // drawn through the checked source
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
                #[allow(clippy::disallowed_methods)] // drawn through the checked source
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
            #[allow(clippy::disallowed_methods)] // drawn through the checked source
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
}
