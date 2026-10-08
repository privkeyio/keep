// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! PSBTs that spend a FROST group's own taproot outputs on the key path.
//!
//! A group's wallet descriptor is either `tr([fp/86'/coin'/0']<group xpub>/0/*)`
//! (keep's BIP-86 wallet: the xpub is the group key with keep's deterministic
//! chaincode, so a key origin's last two steps are the path below the group key)
//! or `tr(<group>, <recovery tree>)`. [`FrostWallet`] finds the inputs that spend
//! one of those outputs, checking the spent scriptPubKey rather than trusting the
//! PSBT's key origins, and recognizes change the same way.

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource};
use bitcoin::hashes::Hash;
use bitcoin::psbt::{Input, Output, Psbt};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::Signature as TaprootSignature;
use bitcoin::{Address, Network, ScriptBuf, TxOut};
use keep_core::frost::taproot::{self, TaprootTweak};
use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
use std::collections::BTreeMap;
use std::str::FromStr;

type TapKeyOrigins =
    BTreeMap<bitcoin::XOnlyPublicKey, (Vec<bitcoin::taproot::TapLeafHash>, KeySource)>;

use crate::address::coin_type;
use crate::descriptor::{descriptor_address_at_index, DescriptorExport};
use crate::error::{BitcoinError, Result};
use crate::psbt::{requested_sighash_type, OutputInfo, PsbtAnalysis, CHANGE_INDEX_LIMIT};

/// One input the group signs: the path below the group key, the BIP-341 tweak,
/// the scriptPubKey it spends and the sighash type the PSBT asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPathSpend {
    pub input: usize,
    pub path: Vec<u32>,
    pub tweak: TaprootTweak,
    pub script_pubkey: ScriptBuf,
    pub sighash_type: TapSighashType,
}

/// A FROST group's taproot wallet. It spends the group's BIP-86 outputs (one per
/// path below the group key, whatever descriptor is stored) and the outputs of
/// every stored descriptor version, but recognizes change only for the latest
/// version: a replaced version was often replaced because its recovery tree is no
/// longer trusted, so paying it counts as money leaving.
pub struct FrostWallet {
    group: [u8; 32],
    network: Network,
    fingerprint: Fingerprint,
    /// The `tr(<group>[, <tree>])` outputs of every version: each spent with its
    /// tree's root.
    singles: Vec<(ScriptBuf, Option<[u8; 32]>)>,
    /// The latest version is the BIP-86 wallet: its change chain is change.
    bip86_change: bool,
    /// The latest version's single output, which is its change.
    single_change: Option<ScriptBuf>,
}

fn keep_error(e: keep_core::error::KeepError) -> BitcoinError {
    BitcoinError::Signing(e.to_string())
}

impl FrostWallet {
    /// The wallet whose latest external descriptor is `latest`, which must be the
    /// group's (its first address is the group's, or its internal key is the
    /// group key). Change is recognized for this version only.
    pub fn new(group: [u8; 32], latest: &str, network: Network) -> Result<Self> {
        let fingerprint = Fingerprint::from_str(&DescriptorExport::pubkey_fingerprint(&group))
            .map_err(|e| BitcoinError::Descriptor(format!("group fingerprint: {e}")))?;
        let mut wallet = Self {
            group,
            network,
            fingerprint,
            singles: Vec::new(),
            bip86_change: false,
            single_change: None,
        };
        wallet.add(latest, true)?;
        Ok(wallet)
    }

    /// Also spend the outputs of an older stored version, which must be the
    /// group's too; outputs paying it are not change.
    pub fn add_older(&mut self, external_descriptor: &str) -> Result<()> {
        self.add(external_descriptor, false)
    }

    fn add(&mut self, external_descriptor: &str, latest: bool) -> Result<()> {
        let body = external_descriptor
            .split('#')
            .next()
            .unwrap_or(external_descriptor);
        let parsed: Descriptor<DescriptorPublicKey> = body
            .parse()
            .map_err(|e| BitcoinError::Descriptor(format!("invalid descriptor: {e}")))?;
        let Descriptor::Tr(tr) = &parsed else {
            return Err(BitcoinError::Descriptor("not a taproot descriptor".into()));
        };
        if parsed.has_wildcard() {
            if tr.tap_tree().is_some() {
                return Err(BitcoinError::Descriptor(
                    "a ranged descriptor with a script tree is not a keep FROST wallet".into(),
                ));
            }
            if descriptor_address_at_index(external_descriptor, self.network, 0)?.script_pubkey()
                != self.bip86_script(&[0, 0])?
            {
                return Err(BitcoinError::Descriptor(
                    "the descriptor is not this group's wallet".into(),
                ));
            }
            self.bip86_change |= latest;
        } else {
            let definite = parsed
                .at_derivation_index(0)
                .map_err(|e| BitcoinError::Descriptor(format!("definite descriptor: {e}")))?;
            let Descriptor::Tr(tr) = &definite else {
                return Err(BitcoinError::Descriptor("not a taproot descriptor".into()));
            };
            let info = tr.spend_info();
            if info.internal_key().serialize() != self.group {
                return Err(BitcoinError::Descriptor(
                    "the descriptor's internal key is not the group key".into(),
                ));
            }
            let script_pubkey = definite.script_pubkey();
            if latest {
                self.single_change = Some(script_pubkey.clone());
            }
            self.singles.push((
                script_pubkey,
                info.merkle_root().map(|root| root.to_byte_array()),
            ));
        }
        Ok(())
    }

    /// The BIP-86 output at `path` below the group key.
    fn bip86_script(&self, path: &[u32]) -> Result<ScriptBuf> {
        TaprootTweak::default()
            .script_pubkey(&taproot::internal_key(&self.group, path).map_err(keep_error)?)
            .map_err(keep_error)
    }

    /// The path below the group key an origin names, if it has the wallet's
    /// shape `86'/coin'/0'/{0,1}/i`.
    fn group_path(&self, path: &DerivationPath) -> Option<Vec<u32>> {
        let coin = coin_type(self.network);
        match path.as_ref() {
            [ChildNumber::Hardened { index: 86 }, ChildNumber::Hardened { index: c }, ChildNumber::Hardened { index: 0 }, ChildNumber::Normal {
                index: chain @ (0 | 1),
            }, ChildNumber::Normal { index }]
                if *c == coin =>
            {
                Some(vec![*chain, *index])
            }
            _ => None,
        }
    }

    /// The BIP-86 path below the group key an origin set names whose output is
    /// `spent`, if any: the origins only name paths to try.
    fn bip86_path(
        &self,
        origins: &TapKeyOrigins,
        spent: &ScriptBuf,
        change_only: bool,
    ) -> Result<Option<Vec<u32>>> {
        for (leaves, (fp, path)) in origins.values() {
            if !leaves.is_empty() || *fp != self.fingerprint {
                continue;
            }
            let Some(group_path) = self.group_path(path) else {
                continue;
            };
            if change_only && !matches!(group_path.as_slice(), [1, i] if *i < CHANGE_INDEX_LIMIT) {
                continue;
            }
            if self.bip86_script(&group_path)? == *spent {
                return Ok(Some(group_path));
            }
        }
        Ok(None)
    }

    /// How the group spends input `input`, if it is one of the group's outputs:
    /// the spent scriptPubKey decides.
    fn spend_of(
        &self,
        input: &Input,
        spent: &ScriptBuf,
    ) -> Result<Option<(Vec<u32>, TaprootTweak)>> {
        for (script_pubkey, merkle_root) in &self.singles {
            let root_matches = input
                .tap_merkle_root
                .is_none_or(|r| Some(r.to_byte_array()) == *merkle_root);
            if spent == script_pubkey && root_matches {
                return Ok(Some((Vec::new(), TaprootTweak::new(*merkle_root))));
            }
        }
        if input.tap_merkle_root.is_some() {
            return Ok(None);
        }
        Ok(self
            .bip86_path(&input.tap_key_origins, spent, false)?
            .map(|path| (path, TaprootTweak::default())))
    }

    /// Whether `output` pays the latest version's change: one of the first change
    /// addresses of the BIP-86 wallet, which a watch-only wallet looks at, or a
    /// recovery wallet's output. Origins only name the index to check.
    fn is_change(&self, output: &Output, script_pubkey: &ScriptBuf) -> bool {
        self.single_change.as_ref() == Some(script_pubkey)
            || (self.bip86_change
                && self
                    .bip86_path(&output.tap_key_origins, script_pubkey, true)
                    .is_ok_and(|path| path.is_some()))
    }

    /// What the PSBT spends and pays, and the inputs the group signs. Every
    /// input needs its UTXO (BIP-341 sighashes commit to all of them), and the
    /// group's inputs may only ask for SIGHASH_DEFAULT or ALL.
    pub fn analyze(&self, psbt: &Psbt) -> Result<(PsbtAnalysis, Vec<KeyPathSpend>)> {
        let mut input_sats = Vec::with_capacity(psbt.inputs.len());
        let mut total_input_sats = 0u64;
        let mut spends = Vec::new();
        for (i, input) in psbt.inputs.iter().enumerate() {
            let utxo = input
                .witness_utxo
                .as_ref()
                .ok_or(BitcoinError::MissingWitnessUtxo(i))?;
            total_input_sats = total_input_sats
                .checked_add(utxo.value.to_sat())
                .ok_or_else(|| BitcoinError::InvalidPsbt("input value overflow".into()))?;
            input_sats.push(utxo.value.to_sat());
            if let Some((path, tweak)) = self.spend_of(input, &utxo.script_pubkey)? {
                spends.push(KeyPathSpend {
                    input: i,
                    path,
                    tweak,
                    script_pubkey: utxo.script_pubkey.clone(),
                    sighash_type: requested_sighash_type(psbt, i)?,
                });
            }
        }

        let mut outputs = Vec::with_capacity(psbt.unsigned_tx.output.len());
        let mut total_output_sats = 0u64;
        for (i, txout) in psbt.unsigned_tx.output.iter().enumerate() {
            total_output_sats = total_output_sats
                .checked_add(txout.value.to_sat())
                .ok_or_else(|| BitcoinError::InvalidPsbt("output value overflow".into()))?;
            let is_change = psbt
                .outputs
                .get(i)
                .is_some_and(|o| self.is_change(o, &txout.script_pubkey));
            outputs.push(OutputInfo {
                index: i,
                address: Address::from_script(&txout.script_pubkey, self.network)
                    .ok()
                    .map(|a| a.to_string()),
                amount_sats: txout.value.to_sat(),
                is_change,
            });
        }
        let fee_sats = total_input_sats
            .checked_sub(total_output_sats)
            .ok_or_else(|| BitcoinError::InvalidPsbt("outputs exceed inputs".into()))?;

        let analysis = PsbtAnalysis {
            num_inputs: psbt.inputs.len(),
            num_outputs: psbt.unsigned_tx.output.len(),
            total_input_sats,
            total_output_sats,
            fee_sats,
            input_sats,
            outputs,
            signable_inputs: spends.iter().map(|s| s.input).collect(),
            network: self.network,
        };
        Ok((analysis, spends))
    }
}

/// The key-spend sighash of each spend, over every input's UTXO.
pub fn sighashes(psbt: &Psbt, spends: &[KeyPathSpend]) -> Result<Vec<[u8; 32]>> {
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or(BitcoinError::MissingWitnessUtxo(i))
        })
        .collect::<Result<_>>()?;
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    spends
        .iter()
        .map(|s| {
            cache
                .taproot_key_spend_signature_hash(
                    s.input,
                    &Prevouts::All(&prevouts),
                    s.sighash_type,
                )
                .map(|h| h.to_byte_array())
                .map_err(|e| BitcoinError::Sighash(e.to_string()))
        })
        .collect()
}

/// Write each spend's signature, after checking every one against the output
/// key it spends, so a bad signature leaves the PSBT untouched.
pub fn apply_signatures(
    psbt: &mut Psbt,
    spends: &[KeyPathSpend],
    sighashes: &[[u8; 32]],
    signatures: &[[u8; 64]],
) -> Result<()> {
    if spends.len() != sighashes.len() || spends.len() != signatures.len() {
        return Err(BitcoinError::Signing(
            "one sighash and one signature per spend".into(),
        ));
    }
    let mut checked = Vec::with_capacity(spends.len());
    for ((spend, sighash), signature) in spends.iter().zip(sighashes).zip(signatures) {
        taproot::verify_key_path_signature(signature, sighash, &spend.script_pubkey)
            .map_err(keep_error)?;
        let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(signature)
            .map_err(|e| BitcoinError::Signing(e.to_string()))?;
        checked.push((spend.input, signature, spend.sighash_type));
    }
    for (input, signature, sighash_type) in checked {
        psbt.inputs[input].tap_key_sig = Some(TaprootSignature {
            signature,
            sighash_type,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::psbt::PsbtSighashType;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, Txid, Witness, XOnlyPublicKey};
    use keep_core::frost::taproot::sign_key_path_spend_with_local_shares;
    use keep_core::frost::{SharePackage, ThresholdConfig, TrustedDealer};

    const NET: Network = Network::Regtest;

    fn new_group() -> (Vec<SharePackage>, [u8; 32]) {
        let (shares, _) = TrustedDealer::new(ThresholdConfig::two_of_three())
            .generate("frost-psbt-test")
            .unwrap();
        let group = taproot::x_only(shares[0].pubkey_package().unwrap().verifying_key()).unwrap();
        (shares, group)
    }

    fn bip86(group: &[u8; 32]) -> FrostWallet {
        let desc = DescriptorExport::from_frost_wallet(group, None, NET).unwrap();
        FrostWallet::new(*group, desc.external_descriptor(), NET).unwrap()
    }

    fn fp(group: &[u8; 32]) -> Fingerprint {
        Fingerprint::from_str(&DescriptorExport::pubkey_fingerprint(group)).unwrap()
    }

    fn child(group: &[u8; 32], path: &[u32]) -> ([u8; 32], ScriptBuf) {
        let internal = taproot::internal_key(group, path).unwrap();
        (
            internal,
            TaprootTweak::default().script_pubkey(&internal).unwrap(),
        )
    }

    /// A key origin entry: the key, its leaf hashes and its source.
    type Origin = (
        XOnlyPublicKey,
        (
            Vec<bitcoin::taproot::TapLeafHash>,
            (Fingerprint, DerivationPath),
        ),
    );

    fn origin(group: &[u8; 32], key: [u8; 32], path: &str) -> Origin {
        (
            XOnlyPublicKey::from_slice(&key).unwrap(),
            (vec![], (fp(group), DerivationPath::from_str(path).unwrap())),
        )
    }

    fn foreign() -> ScriptBuf {
        let (k, _) = bitcoin::secp256k1::Keypair::from_seckey_slice(
            &bitcoin::secp256k1::Secp256k1::new(),
            &[9u8; 32],
        )
        .unwrap()
        .x_only_public_key();
        ScriptBuf::new_p2tr(&bitcoin::secp256k1::Secp256k1::new(), k, None)
    }

    /// A PSBT spending `inputs` (100 000 sats each) to a foreign 30 000 sat
    /// output and `change` (a scriptPubKey with its origin, 69 000 sats).
    fn psbt(inputs: Vec<(ScriptBuf, Option<Origin>)>, change: Option<(ScriptBuf, Origin)>) -> Psbt {
        let mut output = vec![TxOut {
            value: Amount::from_sat(30_000),
            script_pubkey: foreign(),
        }];
        if let Some((spk, _)) = &change {
            output.push(TxOut {
                value: Amount::from_sat(69_000),
                script_pubkey: spk.clone(),
            });
        }
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: (0..inputs.len() as u32)
                .map(|vout| TxIn {
                    previous_output: OutPoint::new(Txid::from_byte_array([3; 32]), vout),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for (i, (spk, origin)) in inputs.into_iter().enumerate() {
            psbt.inputs[i].witness_utxo = Some(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: spk,
            });
            if let Some((k, o)) = origin {
                psbt.inputs[i].tap_internal_key = Some(k);
                psbt.inputs[i].tap_key_origins.insert(k, o);
            }
        }
        if let Some((_, (k, o))) = change {
            psbt.outputs[1].tap_key_origins.insert(k, o);
        }
        psbt
    }

    fn sign_all(shares: &[SharePackage], psbt: &mut Psbt, spends: &[KeyPathSpend]) {
        let sighashes = sighashes(psbt, spends).unwrap();
        let sigs: Vec<[u8; 64]> = spends
            .iter()
            .zip(&sighashes)
            .map(|(s, h)| {
                sign_key_path_spend_with_local_shares(
                    &shares[..2],
                    h,
                    &s.path,
                    s.tweak,
                    &s.script_pubkey,
                )
                .unwrap()
            })
            .collect();
        apply_signatures(psbt, spends, &sighashes, &sigs).unwrap();
    }

    #[test]
    fn the_groups_bip86_inputs_are_found_and_signed_and_change_is_recognized() {
        let (shares, group) = new_group();
        let wallet = bip86(&group);
        let (k0, s0) = child(&group, &[0, 3]);
        let (k1, s1) = child(&group, &[1, 7]);
        let (kc, sc) = child(&group, &[1, 8]);
        let mut psbt = psbt(
            vec![
                (s0.clone(), Some(origin(&group, k0, "86'/1'/0'/0/3"))),
                (foreign(), None),
                (s1.clone(), Some(origin(&group, k1, "86'/1'/0'/1/7"))),
            ],
            Some((sc, origin(&group, kc, "86'/1'/0'/1/8"))),
        );
        let (analysis, spends) = wallet.analyze(&psbt).unwrap();
        assert_eq!(analysis.signable_inputs, vec![0, 2]);
        assert_eq!(spends[0].path, vec![0, 3]);
        assert_eq!(spends[1].path, vec![1, 7]);
        assert!(!analysis.outputs[0].is_change && analysis.outputs[1].is_change);
        assert_eq!(analysis.fee_sats, 300_000 - 99_000);
        assert_eq!(analysis.leaving_wallet_sats(), 30_000 + 201_000);

        sign_all(&shares, &mut psbt, &spends);
        assert!(psbt.inputs[0].tap_key_sig.is_some() && psbt.inputs[2].tap_key_sig.is_some());
        assert!(psbt.inputs[1].tap_key_sig.is_none());
    }

    #[test]
    fn origins_only_name_a_path_the_spent_script_decides() {
        let (_, group) = new_group();
        let wallet = bip86(&group);
        let (k3, s3) = child(&group, &[0, 3]);
        let (k4, _) = child(&group, &[0, 4]);
        let mut other_fp = origin(&group, k3, "86'/1'/0'/0/3");
        other_fp.1 .1 .0 = Fingerprint::from([1, 2, 3, 4]);
        let mut leaf = origin(&group, k3, "86'/1'/0'/0/3");
        leaf.1 .0 = vec![bitcoin::taproot::TapLeafHash::all_zeros()];
        for (label, spk, o) in [
            (
                "origin for another index",
                s3.clone(),
                origin(&group, k4, "86'/1'/0'/0/4"),
            ),
            (
                "key and path disagree",
                s3.clone(),
                origin(&group, k3, "86'/1'/0'/0/4"),
            ),
            (
                "mainnet coin type",
                s3.clone(),
                origin(&group, k3, "86'/0'/0'/0/3"),
            ),
            (
                "a third chain, even with its real key and script",
                child(&group, &[2, 3]).1,
                origin(&group, child(&group, &[2, 3]).0, "86'/1'/0'/2/3"),
            ),
            (
                "hardened index",
                s3.clone(),
                origin(&group, k3, "86'/1'/0'/0/3'"),
            ),
            (
                "another account",
                s3.clone(),
                origin(&group, k3, "86'/1'/1'/0/3"),
            ),
            ("another fingerprint", s3.clone(), other_fp.clone()),
            ("script-path origin", s3.clone(), leaf.clone()),
            (
                "foreign output",
                foreign(),
                origin(&group, k3, "86'/1'/0'/0/3"),
            ),
        ] {
            let (analysis, _) = wallet.analyze(&psbt(vec![(spk, Some(o))], None)).unwrap();
            assert!(analysis.signable_inputs.is_empty(), "{label}");
        }
        let mut with_root = psbt(vec![(s3, Some(origin(&group, k3, "86'/1'/0'/0/3")))], None);
        with_root.inputs[0].tap_merkle_root = Some(bitcoin::taproot::TapNodeHash::all_zeros());
        assert!(wallet
            .analyze(&with_root)
            .unwrap()
            .0
            .signable_inputs
            .is_empty());
    }

    #[test]
    fn change_is_the_wallets_first_change_addresses_only() {
        let (_, group) = new_group();
        let wallet = bip86(&group);
        let (k0, s0) = child(&group, &[0, 3]);
        let input = (s0, Some(origin(&group, k0, "86'/1'/0'/0/3")));
        for (path, origin_path, change) in [
            ([1u32, 999], "86'/1'/0'/1/999", true),
            ([1, 1000], "86'/1'/0'/1/1000", false),
            ([0, 5], "86'/1'/0'/0/5", false),
            ([1, 5], "86'/1'/0'/1/6", false),
        ] {
            let (k, s) = child(&group, &path);
            let (analysis, _) = wallet
                .analyze(&psbt(
                    vec![input.clone()],
                    Some((s, origin(&group, k, origin_path))),
                ))
                .unwrap();
            assert_eq!(analysis.outputs[1].is_change, change, "{origin_path}");
        }
        let (k, _) = child(&group, &[1, 5]);
        let (analysis, _) = wallet
            .analyze(&psbt(
                vec![input],
                Some((foreign(), origin(&group, k, "86'/1'/0'/1/5"))),
            ))
            .unwrap();
        assert!(
            !analysis.outputs[1].is_change,
            "an origin on a foreign output"
        );
    }

    #[test]
    fn missing_utxos_and_narrow_sighashes_are_refused() {
        let (_, group) = new_group();
        let wallet = bip86(&group);
        let (k0, s0) = child(&group, &[0, 3]);
        let mut p = psbt(
            vec![
                (s0, Some(origin(&group, k0, "86'/1'/0'/0/3"))),
                (foreign(), None),
            ],
            None,
        );
        let mut missing = p.clone();
        missing.inputs[1].witness_utxo = None;
        assert!(matches!(
            wallet.analyze(&missing),
            Err(BitcoinError::MissingWitnessUtxo(1))
        ));
        p.inputs[0].sighash_type = Some(PsbtSighashType::from(TapSighashType::All));
        assert_eq!(
            wallet.analyze(&p).unwrap().1[0].sighash_type,
            TapSighashType::All
        );
        for narrow in [TapSighashType::None, TapSighashType::SinglePlusAnyoneCanPay] {
            p.inputs[0].sighash_type = Some(PsbtSighashType::from(narrow));
            assert!(wallet.analyze(&p).is_err(), "{narrow:?}");
        }
        p.inputs[1].sighash_type = Some(PsbtSighashType::from(TapSighashType::None));
        p.inputs[0].sighash_type = None;
        assert!(
            wallet.analyze(&p).is_ok(),
            "a foreign input's sighash is not ours to judge"
        );
    }

    #[test]
    fn a_bad_signature_leaves_the_psbt_untouched() {
        let (shares, group) = new_group();
        let wallet = bip86(&group);
        let (k0, s0) = child(&group, &[0, 3]);
        let (k1, s1) = child(&group, &[0, 4]);
        let mut p = psbt(
            vec![
                (s0, Some(origin(&group, k0, "86'/1'/0'/0/3"))),
                (s1, Some(origin(&group, k1, "86'/1'/0'/0/4"))),
            ],
            None,
        );
        let (_, spends) = wallet.analyze(&p).unwrap();
        let hashes = sighashes(&p, &spends).unwrap();
        let good = sign_key_path_spend_with_local_shares(
            &shares[..2],
            &hashes[0],
            &spends[0].path,
            spends[0].tweak,
            &spends[0].script_pubkey,
        )
        .unwrap();
        assert!(apply_signatures(&mut p, &spends, &hashes, &[good, good]).is_err());
        assert!(p.inputs.iter().all(|i| i.tap_key_sig.is_none()));
    }

    #[test]
    fn a_recovery_wallet_is_spent_on_its_key_path_with_the_trees_root() {
        let (shares, group) = new_group();
        let recovery_key = hex::encode(&foreign().as_bytes()[2..34]);
        let descriptor = format!("tr({},pk({recovery_key}))", hex::encode(group));
        let wallet = FrostWallet::new(group, &descriptor, NET).unwrap();
        let (script_pubkey, merkle_root) = &wallet.singles[0];
        assert!(merkle_root.is_some());
        let mut p = psbt(
            vec![(script_pubkey.clone(), None)],
            Some((
                script_pubkey.clone(),
                origin(&group, group, "86'/1'/0'/1/0"),
            )),
        );
        let (analysis, spends) = wallet.analyze(&p).unwrap();
        assert_eq!(spends[0].path, Vec::<u32>::new());
        assert_eq!(spends[0].tweak, TaprootTweak::new(*merkle_root));
        assert!(analysis.outputs[1].is_change);
        sign_all(&shares, &mut p, &spends);

        let mut wrong_root = p.clone();
        wrong_root.inputs[0].tap_merkle_root = Some(bitcoin::taproot::TapNodeHash::all_zeros());
        assert!(wallet.analyze(&wrong_root).unwrap().1.is_empty());
    }

    #[test]
    fn a_descriptor_that_is_not_the_groups_is_refused() {
        let (_, group) = new_group();
        let (_, other) = new_group();
        let theirs = DescriptorExport::from_frost_wallet(&other, None, NET).unwrap();
        assert!(FrostWallet::new(group, theirs.external_descriptor(), NET).is_err());
        let key = hex::encode(&foreign().as_bytes()[2..34]);
        assert!(FrostWallet::new(group, &format!("tr({key})"), NET).is_err());
        assert!(FrostWallet::new(
            group,
            "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
            NET
        )
        .is_err());
        let mut ours = bip86(&group);
        assert!(
            ours.add_older(theirs.external_descriptor()).is_err(),
            "every stored version must be the group's"
        );
    }

    fn recovery_descriptor(group: &[u8; 32], recovery_seed: u8) -> String {
        let (key, _) = bitcoin::secp256k1::Keypair::from_seckey_slice(
            &bitcoin::secp256k1::Secp256k1::new(),
            &[recovery_seed; 32],
        )
        .unwrap()
        .x_only_public_key();
        format!(
            "tr({},pk({}))",
            hex::encode(group),
            hex::encode(key.serialize())
        )
    }

    /// Coins at an older version's outputs stay spendable, and so do the group's
    /// BIP-86 outputs whatever is stored; but only the latest version's outputs
    /// are change, so paying a replaced recovery tree counts as leaving.
    #[test]
    fn older_versions_are_spendable_but_only_the_latest_is_change() {
        let (shares, group) = new_group();
        let (old, new) = (
            recovery_descriptor(&group, 21),
            recovery_descriptor(&group, 22),
        );
        let mut wallet = FrostWallet::new(group, &new, NET).unwrap();
        wallet.add_older(&old).unwrap();
        let (new_spk, old_spk) = (wallet.singles[0].0.clone(), wallet.singles[1].0.clone());
        let (k0, s0) = child(&group, &[0, 3]);
        let (kc, sc) = child(&group, &[1, 4]);
        let mut p = psbt(
            vec![
                (s0, Some(origin(&group, k0, "86'/1'/0'/0/3"))),
                (old_spk.clone(), None),
                (new_spk.clone(), None),
            ],
            Some((old_spk.clone(), origin(&group, group, "86'/1'/0'/1/0"))),
        );
        let (analysis, spends) = wallet.analyze(&p).unwrap();
        assert_eq!(analysis.signable_inputs, vec![0, 1, 2]);
        assert_eq!(spends[1].tweak, TaprootTweak::new(wallet.singles[1].1));
        assert!(
            !analysis.outputs[1].is_change,
            "a replaced tree's output is not change"
        );
        sign_all(&shares, &mut p, &spends);

        let to_new = psbt(
            vec![(new_spk.clone(), None)],
            Some((new_spk, origin(&group, group, "86'/1'/0'/1/0"))),
        );
        assert!(wallet.analyze(&to_new).unwrap().0.outputs[1].is_change);
        let to_bip86_change = psbt(
            vec![(old_spk, None)],
            Some((sc, origin(&group, kc, "86'/1'/0'/1/4"))),
        );
        assert!(
            !wallet.analyze(&to_bip86_change).unwrap().0.outputs[1].is_change,
            "the BIP-86 chain is change only when it is the latest version"
        );
    }
}
