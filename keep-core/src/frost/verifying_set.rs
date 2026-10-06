// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Checking a group's verifying-share set learned from its members.

use std::collections::BTreeMap;

use frost_secp256k1_tr::keys::{PublicKeyPackage, VerifyingShare};
use frost_secp256k1_tr::Identifier;
use k256::{ProjectivePoint, Scalar};

use super::share::SharePackage;
use crate::error::{KeepError, Result};

/// Builds the group's full public-key package for `share` from every member's
/// verifying share (compressed, by index), accepting the set only if it covers
/// every index, includes `share`'s own verifying share, and all of them lie on
/// one polynomial of degree threshold - 1 whose value at 0 is the group key.
///
/// Members prove their own shares when they announce. Outsiders cannot make a
/// passing set: every point beyond the threshold is fixed by the polynomial, so
/// a forged one needs a secret that depends on the group secret. Enough
/// colluding members (n - t + 2 or more) can agree on another consistent set;
/// that never exposes a key or allows a forgery, and n - t + 1 members can
/// already block signing by refusing.
pub fn complete_verifying_shares(
    share: &SharePackage,
    verifying_shares: &BTreeMap<u16, [u8; 33]>,
) -> Result<PublicKeyPackage> {
    let invalid = |why: &str| KeepError::Frost(format!("Verifying-share set rejected: {why}"));
    let key_package = share.key_package()?;
    let total = share.metadata.total_shares;
    let threshold = *key_package.min_signers();
    let own = share.metadata.identifier;
    if threshold < 2 || threshold > total {
        return Err(invalid("invalid threshold"));
    }
    if verifying_shares.len() != usize::from(total)
        || verifying_shares.keys().any(|&i| i == 0 || i > total)
    {
        return Err(invalid("it does not cover every member exactly"));
    }

    let mut points = BTreeMap::new();
    for (&index, bytes) in verifying_shares {
        let vs = VerifyingShare::deserialize(bytes).map_err(|_| invalid("bad point"))?;
        points.insert(index, vs);
    }
    if points.get(&own) != Some(key_package.verifying_share()) {
        return Err(invalid("it does not include this share"));
    }

    let group = key_package.verifying_key().to_element();
    let mut basis: Vec<(Scalar, ProjectivePoint)> = vec![(Scalar::ZERO, group)];
    basis.push((x(own), points[&own].to_element()));
    for (&index, vs) in &points {
        if basis.len() == usize::from(threshold) {
            break;
        }
        if index != own {
            basis.push((x(index), vs.to_element()));
        }
    }
    for (&index, vs) in &points {
        if basis.iter().any(|(bx, _)| *bx == x(index)) {
            continue;
        }
        if interpolate(&basis, x(index))? != vs.to_element() {
            return Err(invalid("it is not one polynomial through the group key"));
        }
    }

    let mut map = BTreeMap::new();
    for (index, vs) in points {
        let id = Identifier::try_from(index).map_err(|_| invalid("bad index"))?;
        map.insert(id, vs);
    }
    Ok(PublicKeyPackage::new(
        map,
        *key_package.verifying_key(),
        Some(threshold),
    ))
}

/// What predicting other members' verifying shares needs from a share,
/// detached from it.
#[derive(Clone)]
pub struct VerifyingSetContext {
    group: ProjectivePoint,
    own: (Scalar, ProjectivePoint),
    own_index: u16,
    threshold: u16,
    total: u16,
}

/// How member `target`'s verifying share follows from a fixed set of basis
/// members: the share is `constant + sum(weights[k] * basis[k])`.
pub struct Prediction {
    /// The group key's and this share's own contribution.
    pub constant: ProjectivePoint,
    /// One weight per basis member, in the order the basis was given.
    pub weights: Vec<Scalar>,
}

impl VerifyingSetContext {
    /// Captures what predictions need from `share`.
    pub fn new(share: &SharePackage) -> Result<Self> {
        let key_package = share.key_package()?;
        Ok(Self {
            group: key_package.verifying_key().to_element(),
            own: (
                x(share.metadata.identifier),
                key_package.verifying_share().to_element(),
            ),
            own_index: share.metadata.identifier,
            threshold: *key_package.min_signers(),
            total: share.metadata.total_shares,
        })
    }

    /// The share's threshold.
    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    /// How member `target`'s verifying share follows from `basis_indices`:
    /// threshold - 2 other members which, with the group key and this share's
    /// own, fix the polynomial. `None` if the basis is unusable.
    pub fn prediction(&self, basis_indices: &[u16], target: u16) -> Option<Prediction> {
        if self.threshold < 2
            || basis_indices.len() + 2 != usize::from(self.threshold)
            || target == 0
            || target > self.total
            || target == self.own_index
            || basis_indices.contains(&target)
        {
            return None;
        }
        let mut xs = vec![Scalar::ZERO, self.own.0];
        for &i in basis_indices {
            if i == 0 || i > self.total || i == self.own_index {
                return None;
            }
            xs.push(x(i));
        }
        let at = x(target);
        let mut weights = Vec::with_capacity(xs.len());
        for (k, xk) in xs.iter().enumerate() {
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;
            for (m, xm) in xs.iter().enumerate() {
                if m != k {
                    num *= at - xm;
                    den *= *xk - xm;
                }
            }
            weights.push(num * Option::<Scalar>::from(den.invert())?);
        }
        Some(Prediction {
            constant: self.group * weights[0] + self.own.1 * weights[1],
            weights: weights.split_off(2),
        })
    }
}

/// A verifying share as a curve point.
pub fn verifying_share_point(bytes: &[u8; 33]) -> Option<ProjectivePoint> {
    Some(VerifyingShare::deserialize(bytes).ok()?.to_element())
}

/// Every member's verifying share in `package` by index, for indices 1..=total.
pub fn verifying_share_map(
    package: &PublicKeyPackage,
    total: u16,
) -> Result<BTreeMap<u16, [u8; 33]>> {
    let mut map = BTreeMap::new();
    for (index, vs) in (1..=total).filter_map(|i| {
        let id = Identifier::try_from(i).ok()?;
        package.verifying_shares().get(&id).map(|vs| (i, vs))
    }) {
        let bytes = vs
            .serialize()
            .map_err(|e| KeepError::Frost(format!("Failed to serialize verifying share: {e}")))?;
        let bytes: [u8; 33] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeepError::Frost("Invalid verifying share length".into()))?;
        map.insert(index, bytes);
    }
    Ok(map)
}

/// The package `share` should store once `verifying_shares` is accepted, or
/// `None` when `share` already holds every member's verifying share.
pub fn completed_pubkey_package(
    share: &SharePackage,
    verifying_shares: &BTreeMap<u16, [u8; 33]>,
) -> Result<Option<PublicKeyPackage>> {
    if share.pubkey_package()?.verifying_shares().len() == usize::from(share.metadata.total_shares)
    {
        return Ok(None);
    }
    complete_verifying_shares(share, verifying_shares).map(Some)
}

fn x(index: u16) -> Scalar {
    Scalar::from(u64::from(index))
}

fn interpolate(basis: &[(Scalar, ProjectivePoint)], at: Scalar) -> Result<ProjectivePoint> {
    let mut sum = ProjectivePoint::IDENTITY;
    for (k, (xk, pk)) in basis.iter().enumerate() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (m, (xm, _)) in basis.iter().enumerate() {
            if m != k {
                num *= at - xm;
                den *= *xk - xm;
            }
        }
        let inv = Option::<Scalar>::from(den.invert())
            .ok_or_else(|| KeepError::Frost("Duplicate interpolation point".into()))?;
        sum += *pk * (num * inv);
    }
    Ok(sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{ThresholdConfig, TrustedDealer};

    fn full_set(share: &SharePackage) -> BTreeMap<u16, [u8; 33]> {
        verifying_share_map(
            &share.pubkey_package().unwrap(),
            share.metadata.total_shares,
        )
        .unwrap()
    }

    fn groups() -> Vec<Vec<SharePackage>> {
        let mut out = Vec::new();
        for (t, n) in [(2u16, 3u16), (3, 3), (3, 5), (4, 7)] {
            let dealer = TrustedDealer::new(ThresholdConfig::new(t, n).unwrap());
            out.push(dealer.generate("set").unwrap().0);
        }
        let dealer = TrustedDealer::new(ThresholdConfig::new(3, 5).unwrap());
        let shares = dealer.generate("set").unwrap().0;
        out.push(crate::frost::refresh_shares(&shares).unwrap().0);
        out
    }

    #[test]
    fn the_real_set_is_accepted() {
        for shares in groups() {
            let set = full_set(&shares[0]);
            for share in &shares {
                let package = complete_verifying_shares(share, &set).unwrap();
                assert_eq!(
                    package.verifying_shares(),
                    share.pubkey_package().unwrap().verifying_shares()
                );
            }
        }
    }

    #[test]
    fn a_replaced_member_share_is_rejected() {
        use k256::elliptic_curve::Field;
        for shares in groups() {
            let total = shares[0].metadata.total_shares;
            for victim in 2..=total {
                let mut set = full_set(&shares[0]);
                let forged = ProjectivePoint::GENERATOR
                    * Scalar::random(&mut frost_secp256k1_tr::rand_core::OsRng);
                set.insert(
                    victim,
                    VerifyingShare::new(forged)
                        .serialize()
                        .unwrap()
                        .try_into()
                        .unwrap(),
                );
                assert!(complete_verifying_shares(&shares[0], &set).is_err());
            }
        }
    }

    #[test]
    fn a_partial_or_foreign_set_is_rejected() {
        let shares = &groups()[2];
        let mut partial = full_set(&shares[0]);
        partial.remove(&5);
        assert!(complete_verifying_shares(&shares[0], &partial).is_err());

        let mut extra = full_set(&shares[0]);
        extra.insert(6, extra[&1]);
        assert!(complete_verifying_shares(&shares[0], &extra).is_err());

        let other = &groups()[2];
        assert!(complete_verifying_shares(&shares[0], &full_set(&other[0])).is_err());
    }

    #[test]
    fn predictions_from_real_members_match_the_set() {
        for shares in groups() {
            let set = full_set(&shares[0]);
            let context = VerifyingSetContext::new(&shares[0]).unwrap();
            let threshold = usize::from(shares[0].metadata.threshold);
            let basis: Vec<u16> = set
                .keys()
                .copied()
                .filter(|i| *i != 1)
                .take(threshold - 2)
                .collect();
            for (index, point) in &set {
                if *index == 1 || basis.contains(index) {
                    continue;
                }
                let prediction = context.prediction(&basis, *index).unwrap();
                let predicted = basis
                    .iter()
                    .zip(&prediction.weights)
                    .fold(prediction.constant, |acc, (i, w)| {
                        acc + verifying_share_point(&set[i]).unwrap() * w
                    });
                assert_eq!(Some(predicted), verifying_share_point(point));
            }
        }
    }
}
