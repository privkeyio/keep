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
/// Members prove their own shares when they announce, and a forged entry would
/// need a share whose secret depends on the group secret, so a set that passes
/// can only be the group's real one.
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
        let package = share.pubkey_package().unwrap();
        (1..=share.metadata.total_shares)
            .map(|i| {
                let vs = package.verifying_shares()[&Identifier::try_from(i).unwrap()];
                (i, vs.serialize().unwrap().try_into().unwrap())
            })
            .collect()
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
}
