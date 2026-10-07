// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Key-path spends of a FROST group's taproot outputs (BIP-341).
//!
//! A `tr()` output does not commit to its internal key directly: the output key
//! is `Q = P + H_TapTweak(x(P) [|| merkle_root])·G`, with `P` lifted to even y.
//! For keep's wallets `P` is the group key after the BIP-32 path tweak
//! (`tr(<group xpub>/<chain>/<index>)`, no script tree) or the group key itself
//! (`tr(<group>, <recovery tree>)`). A signature only spends the output when every
//! share is tweaked to `Q`'s secret, which is what [`TaprootTweak`] does on top of
//! the path tweak in [`super::bip32_signing`].

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::TapNodeHash;
use bitcoin::ScriptBuf;
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage, Tweak};
use frost_secp256k1_tr::VerifyingKey;

use crate::error::{KeepError, Result};

use super::bip32_signing::{
    derive_child, tweak_key_package_at_path, tweak_public_key_package_at_path,
};
use super::SharePackage;

/// The BIP-341 tweak for a key-path spend: no script tree for a BIP-86 output,
/// or the tree's merkle root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TaprootTweak {
    /// The script tree's merkle root; `None` for an output with no script tree.
    pub merkle_root: Option<[u8; 32]>,
}

impl TaprootTweak {
    /// The tweak for an output with this script tree (`None`: no tree).
    pub fn new(merkle_root: Option<[u8; 32]>) -> Self {
        Self { merkle_root }
    }

    /// The scriptPubKey a key-path spend with this tweak signs for, given the
    /// x-only internal key.
    pub fn script_pubkey(&self, internal_key: &[u8; 32]) -> Result<ScriptBuf> {
        let internal = XOnlyPublicKey::from_slice(internal_key)
            .map_err(|e| KeepError::Frost(format!("taproot internal key invalid: {e}")))?;
        let root = self.merkle_root.map(TapNodeHash::from_byte_array);
        Ok(ScriptBuf::new_p2tr(
            &Secp256k1::verification_only(),
            internal,
            root,
        ))
    }

    /// `kp` tweaked to the output key's share.
    pub fn tweak_key_package(&self, kp: KeyPackage) -> KeyPackage {
        kp.tweak(self.merkle_root.as_ref())
    }

    /// `pkp` tweaked to the output key, for aggregating the shares
    /// [`Self::tweak_key_package`] signs with.
    pub fn tweak_public_key_package(&self, pkp: PublicKeyPackage) -> PublicKeyPackage {
        pkp.tweak(self.merkle_root.as_ref())
    }
}

/// The taproot internal key at `path` below the x-only `group` key: the group
/// key itself for an empty path.
pub fn internal_key(group: &[u8; 32], path: &[u32]) -> Result<[u8; 32]> {
    if path.is_empty() {
        Ok(*group)
    } else {
        Ok(derive_child(group, path)?.child_pubkey)
    }
}

/// `kp` as it signs for `path` below `group` and, for a key-path spend, with
/// `tweak` on top.
pub fn spend_key_package(
    kp: &KeyPackage,
    group: &[u8; 32],
    path: &[u32],
    tweak: Option<TaprootTweak>,
) -> Result<KeyPackage> {
    let kp = tweak_key_package_at_path(kp, group, path)?;
    Ok(match tweak {
        Some(t) => t.tweak_key_package(kp),
        None => kp,
    })
}

/// The public key package matching [`spend_key_package`], for aggregation.
pub fn spend_public_key_package(
    pkp: &PublicKeyPackage,
    group: &[u8; 32],
    path: &[u32],
    tweak: Option<TaprootTweak>,
) -> Result<PublicKeyPackage> {
    let pkp = tweak_public_key_package_at_path(pkp, group, path)?;
    Ok(match tweak {
        Some(t) => t.tweak_public_key_package(pkp),
        None => pkp,
    })
}

/// The x-only form of a FROST verifying key: the taproot internal key it stands
/// for.
pub fn x_only(verifying_key: &VerifyingKey) -> Result<[u8; 32]> {
    let bytes = verifying_key
        .serialize()
        .map_err(|e| KeepError::Frost(format!("verifying key serialize: {e}")))?;
    bytes
        .get(1..33)
        .and_then(|x| x.try_into().ok())
        .ok_or_else(|| KeepError::Frost("verifying key is not a 33-byte point".into()))
}

/// The x-only output key of a P2TR scriptPubKey.
pub fn output_key(script_pubkey: &ScriptBuf) -> Result<XOnlyPublicKey> {
    if !script_pubkey.is_p2tr() {
        return Err(KeepError::Frost("scriptPubKey is not P2TR".into()));
    }
    XOnlyPublicKey::from_slice(&script_pubkey.as_bytes()[2..34])
        .map_err(|e| KeepError::Frost(format!("P2TR output key invalid: {e}")))
}

/// Sign `sighash` with local shares for a key-path spend of the output at
/// `path` (BIP-32 path tweak, then the BIP-341 tweak), and check the signature
/// against the output key of `script_pubkey` before returning it.
pub fn sign_key_path_spend_with_local_shares(
    shares: &[SharePackage],
    sighash: &[u8; 32],
    path: &[u32],
    tweak: TaprootTweak,
    script_pubkey: &ScriptBuf,
) -> Result<[u8; 64]> {
    let first = shares
        .first()
        .ok_or_else(|| KeepError::Frost("No shares provided".into()))?;
    let threshold = first.metadata.threshold as usize;
    if shares.len() < threshold {
        return Err(KeepError::Frost(format!(
            "Need {} shares to sign, only {} provided",
            threshold,
            shares.len()
        )));
    }
    let group = x_only(first.pubkey_package()?.verifying_key())?;
    if tweak.script_pubkey(&internal_key(&group, path)?)? != *script_pubkey {
        return Err(KeepError::Frost(
            "scriptPubKey is not this group's output for the path and tweak".into(),
        ));
    }

    let key_packages = shares[..threshold]
        .iter()
        .map(|s| spend_key_package(&s.key_package()?, &group, path, Some(tweak)))
        .collect::<Result<Vec<_>>>()?;
    let signature = super::signing::aggregate_local(&key_packages, sighash)?;

    verify_key_path_signature(&signature, sighash, script_pubkey)?;
    Ok(signature)
}

/// Check a BIP-340 signature over `sighash` against the output key of a P2TR
/// `script_pubkey`, the check consensus applies to a key-path spend.
pub fn verify_key_path_signature(
    signature: &[u8; 64],
    sighash: &[u8; 32],
    script_pubkey: &ScriptBuf,
) -> Result<()> {
    let signature = Signature::from_slice(signature)
        .map_err(|e| KeepError::Frost(format!("signature is not BIP-340 shaped: {e}")))?;
    Secp256k1::verification_only()
        .verify_schnorr(
            &signature,
            &Message::from_digest(*sighash),
            &output_key(script_pubkey)?,
        )
        .map_err(|e| {
            KeepError::Frost(format!(
                "signature does not verify under the output key it spends: {e}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{ThresholdConfig, TrustedDealer};
    use bitcoin::key::TapTweak;
    use frost_secp256k1_tr::rand_core::OsRng;
    use frost_secp256k1_tr::{round1, round2, SigningPackage};
    use std::collections::BTreeMap;

    fn dealer_shares(threshold: u16, total: u16) -> Vec<SharePackage> {
        let dealer = TrustedDealer::new(ThresholdConfig::new(threshold, total).unwrap());
        dealer.generate("taproot-test").unwrap().0
    }

    /// Dealer groups until one has `odd` parity, so both branches run.
    fn dealer_shares_with_parity(odd: bool) -> Vec<SharePackage> {
        (0..128)
            .map(|_| dealer_shares(2, 3))
            .find(|s| {
                let vk = s[0]
                    .key_package()
                    .unwrap()
                    .verifying_key()
                    .serialize()
                    .unwrap();
                (vk[0] == 0x03) == odd
            })
            .expect("no group of the wanted parity in 128 tries")
    }

    fn group_of(shares: &[SharePackage]) -> [u8; 32] {
        x_only(shares[0].key_package().unwrap().verifying_key()).unwrap()
    }

    fn verifies_under(sig: &[u8; 64], msg: &[u8; 32], key: &[u8; 32]) -> bool {
        Secp256k1::verification_only()
            .verify_schnorr(
                &Signature::from_slice(sig).unwrap(),
                &Message::from_digest(*msg),
                &XOnlyPublicKey::from_slice(key).unwrap(),
            )
            .is_ok()
    }

    #[test]
    fn script_pubkey_is_the_bip341_output_of_the_internal_key() {
        let secp = Secp256k1::new();
        let internal = XOnlyPublicKey::from_slice(&group_of(&dealer_shares(2, 3))).unwrap();
        for root in [None, Some([7u8; 32])] {
            let (q, _) = internal.tap_tweak(&secp, root.map(TapNodeHash::from_byte_array));
            let spk = TaprootTweak::new(root)
                .script_pubkey(&internal.serialize())
                .unwrap();
            assert_eq!(output_key(&spk).unwrap(), q.to_x_only_public_key());
        }
    }

    /// The signature spends the BIP-86 output at the path, and only that: it does
    /// not verify under the untweaked child key the old code signed for.
    #[test]
    fn bip86_spend_at_a_path_verifies_under_the_output_key_for_both_parities() {
        for odd in [false, true] {
            let shares = dealer_shares_with_parity(odd);
            let group = group_of(&shares);
            let path = [1u32, 4];
            let child = derive_child(&group, &path).unwrap().child_pubkey;
            let tweak = TaprootTweak::default();
            let spk = tweak.script_pubkey(&child).unwrap();
            let sighash = [0x42u8; 32];

            let sig =
                sign_key_path_spend_with_local_shares(&shares[1..], &sighash, &path, tweak, &spk)
                    .unwrap();
            verify_key_path_signature(&sig, &sighash, &spk).unwrap();
            assert!(!verifies_under(&sig, &sighash, &child), "odd={odd}");
        }
    }

    #[test]
    fn recovery_tree_key_path_spend_verifies_under_the_output_key() {
        for odd in [false, true] {
            let shares = dealer_shares_with_parity(odd);
            let group = group_of(&shares);
            let tweak = TaprootTweak::new(Some([0xab; 32]));
            let spk = tweak.script_pubkey(&group).unwrap();
            let sighash = [0x24u8; 32];

            let sig =
                sign_key_path_spend_with_local_shares(&shares[..2], &sighash, &[], tweak, &spk)
                    .unwrap();
            verify_key_path_signature(&sig, &sighash, &spk).unwrap();
            let bip86 = TaprootTweak::default().script_pubkey(&group).unwrap();
            assert!(verify_key_path_signature(&sig, &sighash, &bip86).is_err());
        }
    }

    /// DKG groups come out of frost already TapTweaked once (`post_dkg`); keep
    /// treats that key as the internal key, and the tweak composes on top.
    #[test]
    fn dkg_group_spends_its_outputs() {
        let shares = crate::frost::dkg::tests::software_dkg_shares(2, 3);
        let group = group_of(&shares);
        assert_eq!(&group, shares[0].group_pubkey());
        for (path, root) in [(vec![0u32, 3], None), (vec![], Some([5u8; 32]))] {
            let internal = if path.is_empty() {
                group
            } else {
                derive_child(&group, &path).unwrap().child_pubkey
            };
            let tweak = TaprootTweak::new(root);
            let spk = tweak.script_pubkey(&internal).unwrap();
            let sighash = [0x99u8; 32];
            let sig =
                sign_key_path_spend_with_local_shares(&shares[..2], &sighash, &path, tweak, &spk)
                    .unwrap();
            verify_key_path_signature(&sig, &sighash, &spk).unwrap();
        }
    }

    #[test]
    fn a_script_pubkey_that_is_not_the_groups_output_is_refused() {
        let shares = dealer_shares(2, 3);
        let group = group_of(&shares);
        let path = [0u32, 1];
        let child = derive_child(&group, &path).unwrap().child_pubkey;
        let other_child = derive_child(&group, &[0, 2]).unwrap().child_pubkey;
        let sighash = [1u8; 32];
        for (tweak, spk) in [
            (
                TaprootTweak::default(),
                TaprootTweak::default().script_pubkey(&other_child).unwrap(),
            ),
            (
                TaprootTweak::default(),
                TaprootTweak::new(Some([1; 32]))
                    .script_pubkey(&child)
                    .unwrap(),
            ),
            (
                TaprootTweak::new(Some([1; 32])),
                TaprootTweak::new(Some([2; 32]))
                    .script_pubkey(&child)
                    .unwrap(),
            ),
        ] {
            assert!(sign_key_path_spend_with_local_shares(
                &shares[..2],
                &sighash,
                &path,
                tweak,
                &spk
            )
            .is_err());
        }
    }

    /// The coordinator's side: shares tweaked independently by each signer,
    /// aggregated against the public key package tweaked the same way, as the
    /// network path does.
    #[test]
    fn tweaked_public_key_package_aggregates_independent_shares() {
        for odd in [false, true] {
            let shares = dealer_shares_with_parity(odd);
            let group = group_of(&shares);
            let path = [0u32, 7];
            let tweak = TaprootTweak::new(None);
            let pkp = tweak.tweak_public_key_package(
                tweak_public_key_package_at_path(
                    &shares[0].pubkey_package().unwrap(),
                    &group,
                    &path,
                )
                .unwrap(),
            );
            let kps: Vec<KeyPackage> = shares[..2]
                .iter()
                .map(|s| {
                    tweak.tweak_key_package(
                        tweak_key_package_at_path(&s.key_package().unwrap(), &group, &path)
                            .unwrap(),
                    )
                })
                .collect();
            let sighash = [0x5au8; 32];
            let mut nonces = BTreeMap::new();
            let mut commitments = BTreeMap::new();
            for kp in &kps {
                let (n, c) = round1::commit(kp.signing_share(), &mut OsRng);
                nonces.insert(*kp.identifier(), n);
                commitments.insert(*kp.identifier(), c);
            }
            let package = SigningPackage::new(commitments, &sighash);
            let sig_shares: BTreeMap<_, _> = kps
                .iter()
                .map(|kp| {
                    let id = *kp.identifier();
                    (id, round2::sign(&package, &nonces[&id], kp).unwrap())
                })
                .collect();
            let sig = frost_secp256k1_tr::aggregate(&package, &sig_shares, &pkp).unwrap();
            let sig: [u8; 64] = sig.serialize().unwrap().try_into().unwrap();

            let child = derive_child(&group, &path).unwrap().child_pubkey;
            let spk = tweak.script_pubkey(&child).unwrap();
            verify_key_path_signature(&sig, &sighash, &spk).unwrap();
            assert_eq!(
                x_only(pkp.verifying_key()).unwrap(),
                output_key(&spk).unwrap().serialize()
            );
        }
    }
}
