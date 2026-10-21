// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
#![deny(unsafe_code)]

//! Taproot key-path PSBT signing for a key held in the enclave, with the
//! semantics of keep-bitcoin's `PsbtSigner`.
//!
//! A key's outputs are the BIP-86 output of the secret used directly as a key
//! (signed for only on mainnet, since that output is the same on every network)
//! and the BIP-86 outputs of the children `m/86'/coin'/account'/{0,1}/index` of
//! the master key the secret seeds, which is where a key imported from a keep
//! vault holds its wallet's funds. PSBT key origins only name which child to try:
//! a key signs an input, or counts an output as change, only when the key,
//! tweaked, is the output key in that scriptPubKey.

use crate::error::{EnclaveError, Result};
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource, Xpriv};
use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{Signature as TaprootSignature, TapLeafHash};
use bitcoin::{Address, Network, ScriptBuf, Transaction, TxOut, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

type TapKeyOrigins = BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>;

/// Change is recognized only on the first 1000 addresses of the change chain of
/// account 0, where a watch-only wallet built from the exported descriptors looks
/// for it. An output to any other key of the wallet is treated as a spend.
const CHANGE_INDEX_LIMIT: u32 = 1000;

/// The most key origins naming this key that one input or output may carry.
const MAX_WALLET_ORIGINS: usize = 8;

/// The most key origins naming this key, on a path that is checked, a whole PSBT
/// may carry. Each costs a tweak check, so this bounds the work a hostile PSBT can
/// force.
const MAX_PSBT_WALLET_ORIGINS: usize = 2048;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtAnalysis {
    pub total_input_sats: u64,
    pub total_output_sats: u64,
    pub fee_sats: u64,
    pub destinations: Vec<PsbtDestination>,
}

impl PsbtAnalysis {
    /// The most this transaction can take from the key's wallet: every output
    /// except recognized change, plus the fee.
    pub fn leaving_wallet_sats(&self) -> u64 {
        self.destinations
            .iter()
            .filter(|d| !d.is_change)
            .map(|d| d.amount_sats)
            .fold(self.fee_sats, u64::saturating_add)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtDestination {
    pub address: Option<String>,
    /// The output's scriptPubKey, hex encoded.
    pub script_hex: String,
    pub amount_sats: u64,
    pub is_change: bool,
}

pub struct PsbtKeys<'a> {
    secret: &'a [u8; 32],
    x_only_pubkey: XOnlyPublicKey,
    single_key_output: Option<XOnlyPublicKey>,
    fingerprint: Fingerprint,
    secp: Secp256k1<All>,
    network: Network,
}

fn coin_type(network: Network) -> u32 {
    if network == Network::Bitcoin {
        0
    } else {
        1
    }
}

impl<'a> PsbtKeys<'a> {
    pub fn new(secret: &'a [u8; 32], network: Network) -> Result<Self> {
        let secp = Secp256k1::new();
        let mut keypair = Keypair::from_seckey_slice(&secp, secret)
            .map_err(|e| EnclaveError::InvalidKey(e.to_string()))?;
        let (x_only_pubkey, _) = keypair.x_only_public_key();
        keypair.non_secure_erase();

        let mut master = Self::master(secret, network)?;
        let fingerprint = master.fingerprint(&secp);
        master.private_key.non_secure_erase();

        let single_key_output = (network == Network::Bitcoin).then(|| {
            x_only_pubkey
                .tap_tweak(&secp, None)
                .0
                .to_x_only_public_key()
        });

        Ok(Self {
            secret,
            x_only_pubkey,
            single_key_output,
            fingerprint,
            secp,
            network,
        })
    }

    fn master(secret: &[u8; 32], network: Network) -> Result<Xpriv> {
        Xpriv::new_master(network, secret)
            .map_err(|e| EnclaveError::Signing(format!("Failed to create master key: {e}")))
    }

    /// `m/86'/coin'/account'/{0,1}/index` for this network's coin type.
    fn is_wallet_path(&self, path: &DerivationPath) -> bool {
        let coin = coin_type(self.network);
        matches!(
            path.as_ref(),
            [
                ChildNumber::Hardened { index: 86 },
                ChildNumber::Hardened { index: c },
                ChildNumber::Hardened { .. },
                ChildNumber::Normal { index: 0 | 1 },
                ChildNumber::Normal { .. },
            ] if *c == coin
        )
    }

    /// `m/86'/coin'/0'/1/index` with `index < CHANGE_INDEX_LIMIT`.
    fn is_change_path(&self, path: &DerivationPath) -> bool {
        let coin = coin_type(self.network);
        matches!(
            path.as_ref(),
            [
                ChildNumber::Hardened { index: 86 },
                ChildNumber::Hardened { index: c },
                ChildNumber::Hardened { index: 0 },
                ChildNumber::Normal { index: 1 },
                ChildNumber::Normal { index: i },
            ] if *c == coin && *i < CHANGE_INDEX_LIMIT
        )
    }

    /// The keypair for `path` from the master key the secret seeds, or the secret
    /// itself as a key for `None`.
    fn derive_keypair(&self, path: Option<&DerivationPath>) -> Result<Keypair> {
        let Some(path) = path else {
            return Keypair::from_seckey_slice(&self.secp, self.secret)
                .map_err(|e| EnclaveError::InvalidKey(e.to_string()));
        };
        let mut master = Self::master(self.secret, self.network)?;
        let derived = master.derive_priv(&self.secp, path);
        master.private_key.non_secure_erase();
        let mut child =
            derived.map_err(|e| EnclaveError::Signing(format!("Derivation failed: {e}")))?;
        let keypair = child.to_keypair(&self.secp);
        child.private_key.non_secure_erase();
        Ok(keypair)
    }

    /// The tweaked key that spends BIP-86 output `spk` on the key path, if this
    /// key holds it: the secret as a key (when `single_key`), or the child named by
    /// an `origins` entry with this key's fingerprint whose path `accept` allows.
    /// Each candidate is checked publicly first, so metadata can never make the
    /// signer use a key that does not own the output.
    fn key_path_signer(
        &self,
        spk: &ScriptBuf,
        origins: &TapKeyOrigins,
        single_key: bool,
        accept: impl Fn(&DerivationPath) -> bool,
    ) -> Result<Option<Keypair>> {
        if !spk.is_p2tr() {
            return Ok(None);
        }
        let named = origins
            .values()
            .filter(|(leaves, (fp, _))| leaves.is_empty() && *fp == self.fingerprint)
            .count();
        if named > MAX_WALLET_ORIGINS {
            return Err(EnclaveError::Signing(format!(
                "an input or output names this key {named} times; at most {MAX_WALLET_ORIGINS} are read"
            )));
        }
        let Ok(output_key) = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34]) else {
            return Ok(None);
        };
        let owns = |key: XOnlyPublicKey| {
            key.tap_tweak(&self.secp, None).0.to_x_only_public_key() == output_key
        };
        let (expected, path) = if single_key && self.single_key_output == Some(output_key) {
            (self.x_only_pubkey, None)
        } else {
            match origins.iter().find(|(key, (leaves, (fp, path)))| {
                leaves.is_empty() && *fp == self.fingerprint && accept(path) && owns(**key)
            }) {
                Some((key, (_, (_, path)))) => (*key, Some(path)),
                None => return Ok(None),
            }
        };
        let mut keypair = self.derive_keypair(path)?;
        let derived_key = keypair.x_only_public_key().0;
        let tweaked = keypair.tap_tweak(&self.secp, None);
        keypair.non_secure_erase();
        let mut tweaked = tweaked.to_keypair();
        if derived_key != expected || tweaked.x_only_public_key().0 != output_key {
            tweaked.non_secure_erase();
            return Ok(None);
        }
        Ok(Some(tweaked))
    }

    /// The signer for input `index`: its witness UTXO must be a BIP-86 output of
    /// one of this key's outputs. Inputs naming a script tree are left alone.
    fn input_signer(&self, psbt: &Psbt, index: usize) -> Result<Option<Keypair>> {
        let input = &psbt.inputs[index];
        let Some(utxo) = &input.witness_utxo else {
            return Ok(None);
        };
        if input.tap_merkle_root.is_some() {
            return Ok(None);
        }
        self.key_path_signer(&utxo.script_pubkey, &input.tap_key_origins, true, |p| {
            self.is_wallet_path(p)
        })
    }

    fn check_wallet_origins(&self, psbt: &Psbt) -> Result<()> {
        let named = |origins: &TapKeyOrigins, accept: &dyn Fn(&DerivationPath) -> bool| {
            origins
                .values()
                .filter(|(leaves, (fp, path))| {
                    leaves.is_empty() && *fp == self.fingerprint && accept(path)
                })
                .count()
        };
        let named = psbt
            .inputs
            .iter()
            .map(|i| named(&i.tap_key_origins, &|p| self.is_wallet_path(p)))
            .chain(
                psbt.outputs
                    .iter()
                    .map(|o| named(&o.tap_key_origins, &|p| self.is_change_path(p))),
            )
            .sum::<usize>();
        if named > MAX_PSBT_WALLET_ORIGINS {
            return Err(EnclaveError::Signing(format!(
                "the PSBT names this key {named} times; at most {MAX_PSBT_WALLET_ORIGINS} are read"
            )));
        }
        Ok(())
    }

    fn is_change_output(&self, psbt: &Psbt, index: usize) -> bool {
        let (Some(txout), Some(output)) =
            (psbt.unsigned_tx.output.get(index), psbt.outputs.get(index))
        else {
            return false;
        };
        match self.key_path_signer(&txout.script_pubkey, &output.tap_key_origins, false, |p| {
            self.is_change_path(p)
        }) {
            Ok(Some(mut keypair)) => {
                keypair.non_secure_erase();
                true
            }
            _ => false,
        }
    }

    pub fn analyze(&self, psbt: &Psbt) -> Result<PsbtAnalysis> {
        self.check_wallet_origins(psbt)?;
        let mut total_input_sats = 0u64;
        for (i, input) in psbt.inputs.iter().enumerate() {
            let utxo = input
                .witness_utxo
                .as_ref()
                .ok_or_else(|| EnclaveError::Signing(format!("input {i} missing witness UTXO")))?;
            total_input_sats = total_input_sats
                .checked_add(utxo.value.to_sat())
                .ok_or_else(|| EnclaveError::Signing("input value overflow".into()))?;
            if let Some(mut keypair) = self.input_signer(psbt, i)? {
                keypair.non_secure_erase();
                requested_sighash_type(psbt, i)?;
            }
        }

        let mut destinations = Vec::with_capacity(psbt.unsigned_tx.output.len());
        let mut total_output_sats = 0u64;
        for (i, output) in psbt.unsigned_tx.output.iter().enumerate() {
            total_output_sats = total_output_sats
                .checked_add(output.value.to_sat())
                .ok_or_else(|| EnclaveError::Signing("output value overflow".into()))?;
            destinations.push(PsbtDestination {
                address: Address::from_script(&output.script_pubkey, self.network)
                    .ok()
                    .map(|a| a.to_string()),
                script_hex: hex::encode(output.script_pubkey.as_bytes()),
                amount_sats: output.value.to_sat(),
                is_change: self.is_change_output(psbt, i),
            });
        }

        let fee_sats = total_input_sats
            .checked_sub(total_output_sats)
            .ok_or_else(|| EnclaveError::Signing("outputs exceed inputs".into()))?;

        Ok(PsbtAnalysis {
            total_input_sats,
            total_output_sats,
            fee_sats,
            destinations,
        })
    }

    /// Sign every input this key owns. Every input is checked and every
    /// signature made before any is written, so a refusal never leaves a partly
    /// signed PSBT.
    pub fn sign(&self, psbt: &mut Psbt) -> Result<usize> {
        self.check_wallet_origins(psbt)?;
        let prevouts: Vec<TxOut> =
            psbt.inputs
                .iter()
                .enumerate()
                .map(|(i, input)| {
                    input.witness_utxo.clone().ok_or_else(|| {
                        EnclaveError::Signing(format!("input {i} missing witness UTXO"))
                    })
                })
                .collect::<Result<Vec<_>>>()?;
        let prevouts = Prevouts::All(&prevouts);

        // Sized up front so it never reallocates, and erased in place below:
        // `Keypair` is `Copy`, so each move would leave a copy in freed memory.
        let mut signers: Vec<(usize, Keypair, TapSighashType)> =
            Vec::with_capacity(psbt.inputs.len());
        let mut result = Ok(());
        for i in 0..psbt.inputs.len() {
            match self.input_signer(psbt, i) {
                Ok(None) => {}
                Ok(Some(mut keypair)) => {
                    let requested = requested_sighash_type(psbt, i);
                    if let Ok(sighash_type) = requested {
                        signers.push((i, keypair, sighash_type));
                    }
                    keypair.non_secure_erase();
                    if let Err(e) = requested {
                        result = Err(e);
                        break;
                    }
                }
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        let mut signatures = Vec::with_capacity(signers.len());
        if result.is_ok() {
            let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
            for (i, keypair, sighash_type) in &signers {
                match self.signature(&mut sighash_cache, *i, &prevouts, keypair, *sighash_type) {
                    Ok(signature) => signatures.push((*i, signature)),
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                }
            }
        }
        for (_, keypair, _) in signers.iter_mut() {
            keypair.non_secure_erase();
        }
        result?;
        let signed = signatures.len();
        for (i, signature) in signatures {
            psbt.inputs[i].tap_key_sig = Some(signature);
        }
        Ok(signed)
    }

    fn signature(
        &self,
        sighash_cache: &mut SighashCache<&Transaction>,
        index: usize,
        prevouts: &Prevouts<TxOut>,
        keypair: &Keypair,
        sighash_type: TapSighashType,
    ) -> Result<TaprootSignature> {
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(index, prevouts, sighash_type)
            .map_err(|e| EnclaveError::Signing(format!("Sighash failed: {e}")))?;
        let msg = Message::from_digest_slice(sighash.as_ref())
            .map_err(|e| EnclaveError::Signing(format!("Message failed: {e}")))?;
        // Deterministic BIP-340 nonces, as the enclave has always used: other
        // enclave environments may not provide reliable auxiliary randomness.
        let sig = self.secp.sign_schnorr_no_aux_rand(&msg, keypair);
        // `keypair` is the tweaked key, so this checks the signature against the
        // output key the spent scriptPubKey commits to, as consensus will.
        self.secp
            .verify_schnorr(&sig, &msg, &keypair.x_only_public_key().0)
            .map_err(|e| EnclaveError::Signing(format!("key-path signature check failed: {e}")))?;
        Ok(TaprootSignature {
            signature: sig,
            sighash_type,
        })
    }
}

/// The sighash type input `index` asks for, if it is one the signer will use.
/// DEFAULT and ALL both commit to every input and output; anything narrower is
/// refused rather than silently replaced.
fn requested_sighash_type(psbt: &Psbt, index: usize) -> Result<TapSighashType> {
    match psbt.inputs[index].sighash_type.map(|t| t.taproot_hash_ty()) {
        None => Ok(TapSighashType::Default),
        Some(Ok(t @ (TapSighashType::Default | TapSighashType::All))) => Ok(t),
        Some(_) => Err(EnclaveError::Signing(format!(
            "input {index} requests a sighash type other than DEFAULT or ALL"
        ))),
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use bitcoin::absolute::LockTime;
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
        XOnlyPublicKey,
    };
    use std::str::FromStr;

    pub const SECRET: [u8; 32] = [7u8; 32];

    pub fn x_only(secret: &[u8; 32]) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, secret)
            .unwrap()
            .x_only_public_key()
            .0
    }

    /// The BIP-86 output of `key`, as `Address::p2tr` builds it.
    pub fn p2tr(key: XOnlyPublicKey) -> ScriptBuf {
        Address::p2tr(&Secp256k1::new(), key, None, Network::Bitcoin).script_pubkey()
    }

    /// The x-only key of `path` under the master key `secret` seeds, and the
    /// master fingerprint, as keep-bitcoin derives them.
    pub fn child(
        secret: &[u8; 32],
        network: Network,
        path: &str,
    ) -> (XOnlyPublicKey, bitcoin::bip32::Fingerprint, DerivationPath) {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(network, secret).unwrap();
        let path = DerivationPath::from_str(path).unwrap();
        let key = master
            .derive_priv(&secp, &path)
            .unwrap()
            .to_keypair(&secp)
            .x_only_public_key()
            .0;
        (key, master.fingerprint(&secp), path)
    }

    pub fn other_key() -> XOnlyPublicKey {
        x_only(&[9u8; 32])
    }

    /// A PSBT spending `inputs` (scriptPubKey, value) into `outputs`.
    pub fn psbt(inputs: &[(ScriptBuf, u64)], outputs: &[(ScriptBuf, u64)]) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .enumerate()
                .map(|(i, _)| TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_str(
                            "1111111111111111111111111111111111111111111111111111111111111111",
                        )
                        .unwrap(),
                        vout: i as u32,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs
                .iter()
                .map(|(spk, v)| TxOut {
                    value: Amount::from_sat(*v),
                    script_pubkey: spk.clone(),
                })
                .collect(),
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for (input, (spk, v)) in psbt.inputs.iter_mut().zip(inputs) {
            input.witness_utxo = Some(TxOut {
                value: Amount::from_sat(*v),
                script_pubkey: spk.clone(),
            });
        }
        psbt
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use bitcoin::psbt::PsbtSighashType;

    /// Check input `index`'s key-path signature the way consensus does: against
    /// the output key its spent scriptPubKey commits to.
    fn verifies(psbt: &Psbt, index: usize) -> bool {
        let Some(sig) = psbt.inputs[index].tap_key_sig else {
            return false;
        };
        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .map(|i| i.witness_utxo.clone().unwrap())
            .collect();
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .taproot_key_spend_signature_hash(index, &Prevouts::All(&prevouts), sig.sighash_type)
            .unwrap();
        let msg = Message::from_digest_slice(sighash.as_ref()).unwrap();
        let spk = &prevouts[index].script_pubkey;
        let key = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34]).unwrap();
        Secp256k1::verification_only()
            .verify_schnorr(&sig.signature, &msg, &key)
            .is_ok()
    }

    fn name(
        psbt_origins: &mut TapKeyOrigins,
        key: XOnlyPublicKey,
        fp: Fingerprint,
        path: DerivationPath,
    ) {
        psbt_origins.insert(key, (vec![], (fp, path)));
    }

    #[test]
    fn the_single_key_output_is_signed_with_the_tweaked_key_on_mainnet() {
        let me = x_only(&SECRET);
        let mut psbt = psbt(&[(p2tr(me), 50_000)], &[(p2tr(other_key()), 40_000)]);
        let keys = PsbtKeys::new(&SECRET, Network::Bitcoin).unwrap();
        assert_eq!(keys.sign(&mut psbt).unwrap(), 1);
        assert!(
            verifies(&psbt, 0),
            "signature must verify against the output key"
        );
    }

    #[test]
    fn the_single_key_output_is_not_signed_off_mainnet() {
        let me = x_only(&SECRET);
        let mut psbt = psbt(&[(p2tr(me), 50_000)], &[(p2tr(other_key()), 40_000)]);
        let keys = PsbtKeys::new(&SECRET, Network::Testnet).unwrap();
        assert_eq!(keys.sign(&mut psbt).unwrap(), 0);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
    }

    #[test]
    fn a_bip86_child_named_by_its_origin_is_signed() {
        let (child, fp, path) = child(&SECRET, Network::Testnet, "m/86'/1'/0'/0/3");
        let mut psbt = psbt(&[(p2tr(child), 50_000)], &[(p2tr(other_key()), 40_000)]);
        name(&mut psbt.inputs[0].tap_key_origins, child, fp, path);
        let keys = PsbtKeys::new(&SECRET, Network::Testnet).unwrap();
        assert_eq!(keys.sign(&mut psbt).unwrap(), 1);
        assert!(verifies(&psbt, 0));
    }

    #[test]
    fn forged_input_metadata_does_not_make_the_key_sign() {
        let me = x_only(&SECRET);
        let (child, fp, path) = child(&SECRET, Network::Bitcoin, "m/86'/0'/0'/0/0");
        let mut psbt = psbt(
            &[(p2tr(other_key()), 50_000)],
            &[(p2tr(other_key()), 40_000)],
        );
        psbt.inputs[0].tap_internal_key = Some(me);
        name(&mut psbt.inputs[0].tap_key_origins, me, fp, path.clone());
        name(&mut psbt.inputs[0].tap_key_origins, child, fp, path);
        let keys = PsbtKeys::new(&SECRET, Network::Bitcoin).unwrap();
        assert_eq!(keys.sign(&mut psbt).unwrap(), 0);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
    }

    #[test]
    fn an_origin_naming_a_foreign_key_under_this_fingerprint_is_not_signed() {
        let (_, fp, path) = child(&SECRET, Network::Testnet, "m/86'/1'/0'/0/0");
        let mut psbt = psbt(
            &[(p2tr(other_key()), 50_000)],
            &[(p2tr(other_key()), 40_000)],
        );
        name(&mut psbt.inputs[0].tap_key_origins, other_key(), fp, path);
        let keys = PsbtKeys::new(&SECRET, Network::Testnet).unwrap();
        assert_eq!(keys.sign(&mut psbt).unwrap(), 0);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
    }

    #[test]
    fn a_decoy_wallet_origin_does_not_hide_the_owning_one() {
        let a = child(&SECRET, Network::Testnet, "m/86'/1'/0'/0/0");
        let b = child(&SECRET, Network::Testnet, "m/86'/1'/0'/0/1");
        let (decoy, owner) = if a.0 < b.0 { (a, b) } else { (b, a) };
        let mut psbt = psbt(&[(p2tr(owner.0), 50_000)], &[(p2tr(other_key()), 40_000)]);
        name(
            &mut psbt.inputs[0].tap_key_origins,
            decoy.0,
            decoy.1,
            decoy.2,
        );
        name(
            &mut psbt.inputs[0].tap_key_origins,
            owner.0,
            owner.1,
            owner.2,
        );
        let keys = PsbtKeys::new(&SECRET, Network::Testnet).unwrap();
        assert_eq!(keys.sign(&mut psbt).unwrap(), 1);
        assert!(verifies(&psbt, 0));
    }

    #[test]
    fn change_is_only_an_output_the_change_key_owns() {
        let (change, fp, path) = child(&SECRET, Network::Testnet, "m/86'/1'/0'/1/0");
        let mut psbt = psbt(
            &[(p2tr(other_key()), 100_000)],
            &[(p2tr(change), 30_000), (p2tr(other_key()), 60_000)],
        );
        name(
            &mut psbt.outputs[0].tap_key_origins,
            change,
            fp,
            path.clone(),
        );
        psbt.outputs[1].tap_internal_key = Some(change);
        name(&mut psbt.outputs[1].tap_key_origins, change, fp, path);
        let keys = PsbtKeys::new(&SECRET, Network::Testnet).unwrap();
        let analysis = keys.analyze(&psbt).unwrap();
        assert!(analysis.destinations[0].is_change);
        assert!(
            !analysis.destinations[1].is_change,
            "forged metadata must not make change"
        );
        assert_eq!(analysis.fee_sats, 10_000);
        assert_eq!(
            analysis.leaving_wallet_sats(),
            70_000,
            "the fee counts as leaving"
        );
    }

    #[test]
    fn a_receive_address_is_not_change() {
        let (receive, fp, path) = child(&SECRET, Network::Testnet, "m/86'/1'/0'/0/0");
        let mut psbt = psbt(&[(p2tr(other_key()), 100_000)], &[(p2tr(receive), 90_000)]);
        name(&mut psbt.outputs[0].tap_key_origins, receive, fp, path);
        let analysis = PsbtKeys::new(&SECRET, Network::Testnet)
            .unwrap()
            .analyze(&psbt)
            .unwrap();
        assert!(!analysis.destinations[0].is_change);
    }

    #[test]
    fn a_narrower_sighash_is_refused_and_all_is_kept() {
        let me = x_only(&SECRET);
        let keys = PsbtKeys::new(&SECRET, Network::Bitcoin).unwrap();

        let mut single = psbt(&[(p2tr(me), 50_000)], &[(p2tr(other_key()), 40_000)]);
        single.inputs[0].sighash_type = Some(PsbtSighashType::from(TapSighashType::Single));
        assert!(keys.sign(&mut single).is_err());
        assert!(single.inputs[0].tap_key_sig.is_none());

        let mut all = psbt(&[(p2tr(me), 50_000)], &[(p2tr(other_key()), 40_000)]);
        all.inputs[0].sighash_type = Some(PsbtSighashType::from(TapSighashType::All));
        assert_eq!(keys.sign(&mut all).unwrap(), 1);
        assert_eq!(
            all.inputs[0].tap_key_sig.unwrap().sighash_type,
            TapSighashType::All
        );
        assert!(verifies(&all, 0));
    }

    #[test]
    fn a_refused_input_leaves_no_input_signed() {
        let me = x_only(&SECRET);
        let mut psbt = psbt(
            &[(p2tr(me), 50_000), (p2tr(me), 50_000)],
            &[(p2tr(other_key()), 90_000)],
        );
        psbt.inputs[1].sighash_type = Some(PsbtSighashType::from(TapSighashType::None));
        let keys = PsbtKeys::new(&SECRET, Network::Bitcoin).unwrap();
        assert!(keys.sign(&mut psbt).is_err());
        assert!(psbt.inputs.iter().all(|i| i.tap_key_sig.is_none()));
    }

    #[test]
    fn outputs_exceeding_inputs_and_missing_utxos_are_refused() {
        let keys = PsbtKeys::new(&SECRET, Network::Bitcoin).unwrap();
        let over = psbt(
            &[(p2tr(other_key()), 10_000)],
            &[(p2tr(other_key()), 20_000)],
        );
        assert!(keys.analyze(&over).is_err());
        let mut missing = psbt(
            &[(p2tr(other_key()), 10_000)],
            &[(p2tr(other_key()), 5_000)],
        );
        missing.inputs[0].witness_utxo = None;
        assert!(keys.analyze(&missing).is_err());
    }

    #[test]
    fn too_many_origins_naming_the_key_are_refused() {
        let (_, fp, _) = child(&SECRET, Network::Testnet, "m/86'/1'/0'/0/0");
        let mut psbt = psbt(
            &[(p2tr(other_key()), 50_000)],
            &[(p2tr(other_key()), 40_000)],
        );
        for i in 0..=MAX_WALLET_ORIGINS as u32 {
            let (key, _, path) = child(&[i as u8 + 20; 32], Network::Testnet, "m/86'/1'/0'/0/0");
            name(&mut psbt.inputs[0].tap_key_origins, key, fp, path);
        }
        let keys = PsbtKeys::new(&SECRET, Network::Testnet).unwrap();
        assert!(keys.sign(&mut psbt).is_err());
    }
}
