// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Nonce generation that checks the draw the nonce is built from.
//!
//! [`check_entropy_health`] certifies the source by drawing samples of its own.
//! A nonce drawn afterwards comes from a different call, so a source that fails
//! between the probe and the draw yields a nonce no check ever looked at. The
//! window is narrow and periodic probing closes most of it, but it is worth
//! closing here specifically, because of what a nonce is: frost-core derives it
//! as `H3(random_bytes || signing_share)` (frost-core 3.0.0, `round1.rs:77-90`),
//! so a source stuck on a constant hands back the same nonce in every session,
//! and one nonce used over two different messages recovers the signing share.
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
/// consult it afterwards. Nothing outside this module builds one, so that
/// obligation cannot be missed by a caller who does not know it exists: the
/// `commit_checked` functions are the only way to one.
struct CheckedRng<R> {
    inner: R,
    /// The last 32-byte fill, for the next one to be compared against. Cleared
    /// on drop, though frost-core leaves its own copy of the same bytes, and
    /// the serialized signing share beside them, unscrubbed on the heap, so
    /// this is hygiene rather than a boundary anything should lean on.
    previous: Option<[u8; 32]>,
    fault: Option<EntropyHealthError>,
}

impl<R: RngCore> CheckedRng<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            previous: None,
            fault: None,
        }
    }

    fn judge(&mut self, drawn: &[u8]) {
        if !drawn.is_empty() && drawn.iter().all(|&b| b == 0) {
            self.fault = Some(EntropyHealthError::Degraded);
            return;
        }
        // Nonce generation fills exactly 32 bytes at a time (frost-core 3.0.0,
        // `round1.rs:53-54`), twice per commitment, which is the pair compared
        // below. A fill of another width gets the all-zero test and nothing
        // more, because the pair criteria are written for that width.
        let Ok(drawn) = <[u8; 32]>::try_from(drawn) else {
            return;
        };
        let drawn = Zeroizing::new(drawn);
        if let Some(previous) = &self.previous {
            if !pair_looks_random(previous, &drawn) {
                self.fault = Some(EntropyHealthError::Degraded);
            }
        }
        self.previous = Some(*drawn);
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

/// `round1::commit`, refusing what it produced when the draw behind it failed
/// the health criteria.
///
/// On the error path the nonces are dropped rather than returned, and
/// `SigningNonces` is `ZeroizeOnDrop`, so a nonce from a bad draw is cleared
/// instead of being left where a caller could reach it.
pub fn commit_checked(
    share: &frost_secp256k1_tr::keys::SigningShare,
) -> Result<
    (
        frost_secp256k1_tr::round1::SigningNonces,
        frost_secp256k1_tr::round1::SigningCommitments,
    ),
    EntropyHealthError,
> {
    commit_with(share, OsRng)
}

fn commit_with<R: CryptoRng + RngCore>(
    share: &frost_secp256k1_tr::keys::SigningShare,
    source: R,
) -> Result<
    (
        frost_secp256k1_tr::round1::SigningNonces,
        frost_secp256k1_tr::round1::SigningCommitments,
    ),
    EntropyHealthError,
> {
    let mut rng = CheckedRng::new(source);
    #[allow(clippy::disallowed_methods)] // the one sanctioned draw
    let committed = frost_secp256k1_tr::round1::commit(share, &mut rng);
    match rng.fault {
        Some(e) => Err(e),
        None => Ok(committed),
    }
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
    let mut rng = CheckedRng::new(OsRng);
    #[allow(clippy::disallowed_methods)] // the one sanctioned draw
    let committed = frost_ed25519::round1::commit(share, &mut rng);
    match rng.fault {
        Some(e) => Err(e),
        None => Ok(committed),
    }
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
            commit_with(&test_share(3), StuckRng(0xab)),
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
            commit_with(&test_share(3), CreepingRng(0)),
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

    /// A zero-width fill is not a stuck source. `all` is true over nothing, so
    /// the all-zero test has to say so explicitly.
    #[test]
    fn an_empty_fill_is_not_a_fault() {
        let mut checked = CheckedRng::new(OsRng);
        checked.judge(&[]);
        assert_eq!(checked.fault, None);
    }
}
