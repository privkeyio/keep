// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use crate::address::{coin_type, master_xpriv};
use crate::error::{BitcoinError, Result};
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource};
use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{Signature as TaprootSignature, TapLeafHash};
use bitcoin::{Address, Network, ScriptBuf, Transaction, TxOut, XOnlyPublicKey};
use keep_core::crypto::MlockedBox;
use std::collections::BTreeMap;

type TapKeyOrigins = BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>;

#[derive(Debug, Clone)]
pub struct PsbtAnalysis {
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub total_input_sats: u64,
    pub total_output_sats: u64,
    pub fee_sats: u64,
    /// The amount each input spends, by input index.
    pub input_sats: Vec<u64>,
    pub outputs: Vec<OutputInfo>,
    pub signable_inputs: Vec<usize>,
    /// The network the outputs' addresses are rendered for: the signer's.
    pub network: Network,
}

impl PsbtAnalysis {
    /// The most this transaction can take out of the wallet: every output except
    /// recognized change, plus the fee. Change is recognized only when its script is
    /// one of the wallet's change outputs, so this bounds the wallet's loss even when
    /// the PSBT also spends someone else's inputs.
    pub fn leaving_wallet_sats(&self) -> u64 {
        self.outputs
            .iter()
            .filter(|o| !o.is_change)
            .map(|o| o.amount_sats)
            .fold(self.fee_sats, u64::saturating_add)
    }
}

#[derive(Debug, Clone)]
pub struct OutputInfo {
    pub index: usize,
    pub address: Option<String>,
    pub amount_sats: u64,
    pub is_change: bool,
}

// NOTE: `Keypair` and `Xpriv` (from secp256k1 / rust-bitcoin) are `Copy` and do not
// implement `Zeroize`, so erasing them here is best-effort: the copies this code holds
// are cleared with `non_secure_erase`, but copies made inside the libraries are not.
// The public check in `key_path_signer` keeps that to at most one secret derivation
// per input. The canonical secret key is held in `MlockedBox` which provides mlock +
// madvise + zeroize-on-drop, so the authoritative copy is protected at rest.
//
// The wallet's keys are the secret itself used as a key (the original single-key
// address, spent only on mainnet) and the BIP-86 children `m/86'/coin'/account'/{0,1}/index` of the master
// key the secret seeds, which `AddressDerivation` hands out as addresses. Each spends
// its BIP-86 output only on the key path, as BIP-341 requires: the signature is made
// with the tweaked key, whose x-only form is the output key in the scriptPubKey.
pub struct PsbtSigner {
    secret: MlockedBox<32>,
    x_only_pubkey: XOnlyPublicKey,
    /// BIP-86 output key of the secret used directly as a key, signed for only on
    /// mainnet. Unlike the BIP-86 children, whose coin type differs, this output is
    /// the same on every network, so a test-network signer that spent it would be
    /// signing a mainnet spend its caller saw rendered as test-network addresses.
    single_key_output: Option<XOnlyPublicKey>,
    fingerprint: Fingerprint,
    secp: Secp256k1<bitcoin::secp256k1::All>,
    network: Network,
}

/// Change is recognized only where a watch-only wallet built from the exported
/// descriptors looks for it by default: the first 1000 addresses of the change chain
/// of account 0. An output to any other wallet key still belongs to the wallet but is
/// treated as a spend, so it cannot hide funds from that wallet behind the change
/// exemption.
pub(crate) const CHANGE_INDEX_LIMIT: u32 = 1000;

#[cfg(test)]
thread_local! {
    static SECRET_DERIVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl PsbtSigner {
    pub fn new(secret: &mut [u8; 32], network: Network) -> Result<Self> {
        let secp = Secp256k1::new();

        let mut keypair = Keypair::from_seckey_slice(&secp, secret)
            .map_err(|e| BitcoinError::InvalidSecretKey(e.to_string()))?;
        let (x_only_pubkey, _parity) = keypair.x_only_public_key();
        keypair.non_secure_erase();

        let mut master = master_xpriv(secret, network)?;
        let fingerprint = master.fingerprint(&secp);
        master.private_key.non_secure_erase();

        let single_key_output = (network == Network::Bitcoin).then(|| {
            x_only_pubkey
                .tap_tweak(&secp, None)
                .0
                .to_x_only_public_key()
        });

        Ok(Self {
            secret: MlockedBox::new(secret),
            x_only_pubkey,
            single_key_output,
            fingerprint,
            secp,
            network,
        })
    }

    /// The x-only public key of the secret used directly as a key.
    pub fn x_only_public_key(&self) -> XOnlyPublicKey {
        self.x_only_pubkey
    }

    /// `m/86'/coin'/account'/{0,1}/index` for this network's coin type, the layout
    /// `AddressDerivation` produces. Any account: `keep bitcoin descriptor --account`.
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
        #[cfg(test)]
        SECRET_DERIVATIONS.with(|n| n.set(n.get() + 1));
        let Some(path) = path else {
            return Keypair::from_seckey_slice(&self.secp, &*self.secret)
                .map_err(|e| BitcoinError::InvalidSecretKey(e.to_string()));
        };
        let mut master = master_xpriv(&self.secret, self.network)?;
        let derived = master.derive_priv(&self.secp, path);
        master.private_key.non_secure_erase();
        let mut child =
            derived.map_err(|e| BitcoinError::DerivationPath(format!("Derivation failed: {e}")))?;
        let keypair = child.to_keypair(&self.secp);
        child.private_key.non_secure_erase();
        Ok(keypair)
    }

    /// The tweaked wallet key that spends BIP-86 output `spk` on the key path, if the
    /// wallet holds it: the secret as a key (when `single_key`), or the BIP-86 child of an `origins` entry
    /// carrying this wallet's fingerprint whose path `accept` allows. Each candidate
    /// is first checked publicly (its key, tweaked, must be the output key), so PSBT
    /// metadata only names which key to try, can never make the signer use or claim a
    /// key that does not own the output, and costs at most one secret derivation.
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

    /// The signer for input `index`: its witness UTXO must be a BIP-86 output of one
    /// of the wallet's keys. Inputs naming a script tree (`tap_merkle_root`) are not
    /// the wallet's addresses and are left alone.
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

    pub fn analyze(&self, psbt: &Psbt) -> Result<PsbtAnalysis> {
        let mut total_input_sats = 0u64;
        let mut input_sats = Vec::with_capacity(psbt.inputs.len());
        let mut signable_inputs = Vec::new();

        for (i, input) in psbt.inputs.iter().enumerate() {
            let utxo = input.witness_utxo.as_ref().ok_or_else(|| {
                BitcoinError::InvalidPsbt(format!("input {i} missing witness_utxo"))
            })?;
            total_input_sats = total_input_sats
                .checked_add(utxo.value.to_sat())
                .ok_or_else(|| BitcoinError::InvalidPsbt("input value overflow".into()))?;
            input_sats.push(utxo.value.to_sat());

            if self.should_sign_input(psbt, i)? {
                requested_sighash_type(psbt, i)?;
                signable_inputs.push(i);
            }
        }

        let mut outputs = Vec::new();
        let mut total_output_sats = 0u64;

        for (i, output) in psbt.unsigned_tx.output.iter().enumerate() {
            total_output_sats = total_output_sats
                .checked_add(output.value.to_sat())
                .ok_or_else(|| BitcoinError::InvalidPsbt("output value overflow".into()))?;

            let address = Address::from_script(&output.script_pubkey, self.network)
                .ok()
                .map(|a| a.to_string());

            let is_change = self.is_change_output(psbt, i);

            outputs.push(OutputInfo {
                index: i,
                address,
                amount_sats: output.value.to_sat(),
                is_change,
            });
        }

        let fee_sats = total_input_sats
            .checked_sub(total_output_sats)
            .ok_or_else(|| BitcoinError::InvalidPsbt("outputs exceed inputs".into()))?;

        Ok(PsbtAnalysis {
            num_inputs: psbt.inputs.len(),
            num_outputs: psbt.unsigned_tx.output.len(),
            total_input_sats,
            total_output_sats,
            fee_sats,
            input_sats,
            outputs,
            signable_inputs,
            network: self.network,
        })
    }

    pub fn sign(&self, psbt: &mut Psbt) -> Result<usize> {
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
            .collect::<Result<Vec<_>>>()?;

        let prevouts_ref = Prevouts::All(&prevouts);

        // Every input is checked and every signature made before anything is written,
        // so a refusal or a failure never leaves a partly signed PSBT.
        // Sized up front so it never reallocates (each move would leave a copy of the
        // keys in freed memory), and erased in place below: `Keypair` is `Copy`.
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
            // One cache for the whole transaction: its BIP-341 midstate hashes every
            // input and output, so rebuilding it per input costs quadratic time.
            let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
            for (i, keypair, sighash_type) in &signers {
                match self.taproot_keypath_signature(
                    &mut sighash_cache,
                    *i,
                    &prevouts_ref,
                    keypair,
                    *sighash_type,
                ) {
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
        let signed_count = signatures.len();
        for (i, signature) in signatures {
            psbt.inputs[i].tap_key_sig = Some(signature);
        }
        Ok(signed_count)
    }

    fn should_sign_input(&self, psbt: &Psbt, index: usize) -> Result<bool> {
        Ok(match self.input_signer(psbt, index)? {
            Some(mut keypair) => {
                keypair.non_secure_erase();
                true
            }
            None => false,
        })
    }

    fn taproot_keypath_signature(
        &self,
        sighash_cache: &mut SighashCache<&Transaction>,
        index: usize,
        prevouts: &Prevouts<TxOut>,
        keypair: &Keypair,
        sighash_type: TapSighashType,
    ) -> Result<TaprootSignature> {
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(index, prevouts, sighash_type)
            .map_err(|e| BitcoinError::Sighash(e.to_string()))?;

        let msg = Message::from_digest_slice(sighash.as_ref())
            .map_err(|e| BitcoinError::Signing(e.to_string()))?;

        let aux_rand = crate::aux_rand()?;
        let sig = self
            .secp
            .sign_schnorr_with_aux_rand(&msg, keypair, &aux_rand);
        // `keypair` is the tweaked key, so this checks the signature against the
        // output key the spent scriptPubKey commits to, as consensus will.
        self.secp
            .verify_schnorr(&sig, &msg, &keypair.x_only_public_key().0)
            .map_err(|e| BitcoinError::Signing(format!("key-path signature check failed: {e}")))?;

        Ok(TaprootSignature {
            signature: sig,
            sighash_type,
        })
    }

    fn is_change_output(&self, psbt: &Psbt, index: usize) -> bool {
        // Genuine change pays one of the wallet's own key-path outputs. The output's
        // tap_key_origins only name which wallet key to try; the scriptPubKey derived
        // from that key must equal the actual output script. The metadata alone is
        // forgeable by an untrusted PSBT author, who could otherwise mark an
        // arbitrary-destination output as "change" and slip it past spend policies
        // (amount / allowlist) that exempt change.
        let Some(txout) = psbt.unsigned_tx.output.get(index) else {
            return false;
        };
        let Some(output) = psbt.outputs.get(index) else {
            return false;
        };
        // The single-key address is not in the exported descriptors, so a watch-only
        // wallet never sees it: it is the wallet's, but not change.
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
}

/// The sighash type input `index` asks for, if it is one the signer will use. DEFAULT
/// and ALL both commit to every input and output; anything narrower was asked for by
/// the PSBT author and is refused rather than silently replaced.
pub(crate) fn requested_sighash_type(psbt: &Psbt, index: usize) -> Result<TapSighashType> {
    match psbt.inputs[index].sighash_type.map(|t| t.taproot_hash_ty()) {
        None => Ok(TapSighashType::Default),
        Some(Ok(t @ (TapSighashType::Default | TapSighashType::All))) => Ok(t),
        Some(_) => Err(BitcoinError::Signing(format!(
            "input {index} requests a sighash type other than DEFAULT or ALL"
        ))),
    }
}

/// The largest PSBT keep parses. A maximum-size standard transaction (100,000 vB,
/// about 1,700 taproot inputs) with every input's UTXO and key origin is well under
/// it; the bound keeps an attacker's PSBT from costing unbounded time to analyze and
/// sign.
pub const MAX_PSBT_BYTES: usize = 512 * 1024;

pub fn parse_psbt(data: &[u8]) -> Result<Psbt> {
    if data.len() > MAX_PSBT_BYTES {
        return Err(BitcoinError::InvalidPsbt(format!(
            "{} bytes exceeds the {MAX_PSBT_BYTES}-byte limit",
            data.len()
        )));
    }
    Psbt::deserialize(data).map_err(|e| BitcoinError::InvalidPsbt(e.to_string()))
}

pub fn parse_psbt_base64(base64: &str) -> Result<Psbt> {
    use bitcoin::base64::{engine::general_purpose::STANDARD, Engine};
    if base64.len() > MAX_PSBT_BYTES.div_ceil(3) * 4 {
        return Err(BitcoinError::InvalidPsbt(format!(
            "{} base64 characters exceeds the {MAX_PSBT_BYTES}-byte limit",
            base64.len()
        )));
    }
    let bytes = STANDARD
        .decode(base64)
        .map_err(|e| BitcoinError::InvalidPsbt(format!("Invalid base64: {e}")))?;
    parse_psbt(&bytes)
}

pub fn serialize_psbt(psbt: &Psbt) -> Vec<u8> {
    psbt.serialize()
}

pub fn serialize_psbt_base64(psbt: &Psbt) -> String {
    use bitcoin::base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(psbt.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    #[test]
    fn test_psbt_signer_creation() {
        let mut secret = [1u8; 32];
        let signer = PsbtSigner::new(&mut secret, Network::Testnet).unwrap();

        let pubkey = signer.x_only_public_key();
        assert_eq!(pubkey.serialize().len(), 32);
    }

    // === #417 round 4a: targeted unit tests killing the surviving mutations ===

    fn fixture_psbt_to(spk: bitcoin::ScriptBuf, value: u64) -> Psbt {
        use bitcoin::{
            absolute::LockTime, transaction::Version, OutPoint, Sequence, Transaction, TxIn, TxOut,
            Witness,
        };
        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(50_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: bitcoin::Amount::from_sat(value),
            script_pubkey: spk,
        });
        psbt
    }

    fn own_address(signer: &PsbtSigner) -> Address {
        Address::p2tr(
            &Secp256k1::new(),
            signer.x_only_public_key(),
            None,
            Network::Testnet,
        )
    }

    fn other_address(secret: &mut [u8; 32]) -> Address {
        own_address(&PsbtSigner::new(secret, Network::Testnet).unwrap())
    }

    /// `parse_psbt(serialize_psbt(p)) == p`. The `serialize_psbt → vec![]`
    /// and `vec![0]` / `vec![1]` regressions all produce non-PSBT bytes
    /// that `parse_psbt` rejects, so this roundtrip catches every constant-
    /// return mutation on `serialize_psbt`. A `serialize_psbt_base64` →
    /// `"xyzzy"` regression is caught the same way through `parse_psbt_base64`.
    #[test]
    fn psbt_serialization_roundtrip() {
        let psbt = fixture_psbt_to(bitcoin::ScriptBuf::new(), 60_000);

        // Binary roundtrip.
        let bytes = serialize_psbt(&psbt);
        assert!(!bytes.is_empty(), "serialize_psbt must not return empty");
        let parsed = parse_psbt(&bytes).expect("must roundtrip through binary");
        assert_eq!(parsed.unsigned_tx, psbt.unsigned_tx);

        // Base64 roundtrip.
        let b64 = serialize_psbt_base64(&psbt);
        assert!(
            !b64.is_empty(),
            "serialize_psbt_base64 must not return empty"
        );
        let parsed = parse_psbt_base64(&b64).expect("must roundtrip through base64");
        assert_eq!(parsed.unsigned_tx, psbt.unsigned_tx);
    }

    /// `should_sign_input` returns false for an input whose witness_utxo
    /// belongs to a different taproot key. A constant `Ok(true)`
    /// regression would have us sign an input whose UTXO we don't control.
    #[test]
    fn should_sign_input_returns_false_for_unrelated_input() {
        let mut our_secret = [1u8; 32];
        let signer = PsbtSigner::new(&mut our_secret, Network::Testnet).unwrap();

        let mut other_secret = [2u8; 32];
        let other_addr = other_address(&mut other_secret);
        let psbt = fixture_psbt_to(other_addr.script_pubkey(), 60_000);

        assert!(!signer.should_sign_input(&psbt, 0).unwrap());
    }

    /// `should_sign_input` returns true when the input's witness_utxo
    /// script_pubkey is the signer's own p2tr address (the script_pubkey
    /// match arm). A constant `Ok(false)` regression would refuse to sign
    /// an input we actually control.
    #[test]
    fn should_sign_input_returns_true_for_our_own_p2tr_input() {
        let mut our_secret = [1u8; 32];
        let signer = PsbtSigner::new(&mut our_secret, Network::Bitcoin).unwrap();
        let our_addr = own_address(&signer);
        let psbt = fixture_psbt_to(our_addr.script_pubkey(), 60_000);

        assert!(signer.should_sign_input(&psbt, 0).unwrap());
    }

    /// `sign` returns 0 when no input matches our key and writes no
    /// signature. A constant `Ok(1)` regression would report a phantom
    /// signed input.
    #[test]
    fn sign_returns_zero_when_no_inputs_match_our_key() {
        let mut our_secret = [1u8; 32];
        let signer = PsbtSigner::new(&mut our_secret, Network::Testnet).unwrap();

        let mut other_secret = [2u8; 32];
        let other_addr = other_address(&mut other_secret);
        let mut psbt = fixture_psbt_to(other_addr.script_pubkey(), 60_000);

        let signed = signer.sign(&mut psbt).unwrap();
        assert_eq!(signed, 0, "sign must report zero when no inputs match");
        assert!(
            psbt.inputs[0].tap_key_sig.is_none(),
            "no signature should be written for an unrelated input"
        );
    }

    /// `sign` signs an input addressed to our own key, writes the taproot
    /// key-spend signature, and reports the count. This drives
    /// `sign_taproot_keypath`; a constant `Ok(0)` regression would leave
    /// `tap_key_sig` unset while reporting nothing signed.
    #[test]
    fn sign_signs_our_own_input_and_reports_count() {
        let mut our_secret = [1u8; 32];
        let signer = PsbtSigner::new(&mut our_secret, Network::Bitcoin).unwrap();
        let our_addr = own_address(&signer);
        let mut psbt = fixture_psbt_to(our_addr.script_pubkey(), 60_000);

        let signed = signer.sign(&mut psbt).unwrap();
        assert_eq!(signed, 1, "sign must report one signed input");
        assert!(
            psbt.inputs[0].tap_key_sig.is_some(),
            "a signature must be written for our own input"
        );
    }

    // Build a PSBT paying `out_sats` to `output_spk`, funded by an `in_sats` input,
    // optionally forging `output_internal_key` into the output's PSBT metadata.
    fn psbt_paying(
        output_spk: bitcoin::ScriptBuf,
        out_sats: u64,
        in_sats: u64,
        output_internal_key: Option<XOnlyPublicKey>,
    ) -> Psbt {
        use bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, Sequence,
            Transaction, TxIn, Witness,
        };
        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(out_sats),
                script_pubkey: output_spk,
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(in_sats),
            script_pubkey: bitcoin::ScriptBuf::new(),
        });
        psbt.outputs[0].tap_internal_key = output_internal_key;
        psbt
    }

    #[test]
    fn change_is_the_signers_own_key_path_output_not_forged_metadata() {
        let mut secret = [3u8; 32];
        let signer = PsbtSigner::new(&mut secret, Network::Testnet).unwrap();
        let own = own_address(&signer);
        let mut attacker_secret = [9u8; 32];
        let attacker = other_address(&mut attacker_secret);

        // The single-key address is the signer's, but no watch-only wallet built from
        // the exported descriptors sees it, so paying it is not change...
        let change = psbt_paying(own.script_pubkey(), 10_000, 20_000, None);
        assert!(
            !signer.analyze(&change).unwrap().outputs[0].is_change,
            "the single-key address is outside the exported descriptors"
        );

        // ...but an output paying an attacker address is NOT change, even with the
        // signer's x-only key forged into the output's tap_internal_key.
        let forged = psbt_paying(
            attacker.script_pubkey(),
            10_000,
            20_000,
            Some(signer.x_only_public_key()),
        );
        assert!(
            !signer.analyze(&forged).unwrap().outputs[0].is_change,
            "forged tap_internal_key must not make an attacker-destination output change"
        );
    }

    // === Key-path spends of the wallet's own addresses (BIP-86 / BIP-341) ===

    use crate::address::{AddressDerivation, DerivedAddress};
    use bitcoin::bip32::Xpriv;
    use bitcoin::taproot::TapNodeHash;
    use std::str::FromStr;

    const SECRET: [u8; 32] = [7u8; 32];

    fn signer() -> PsbtSigner {
        let mut secret = SECRET;
        PsbtSigner::new(&mut secret, Network::Testnet).unwrap()
    }

    fn derived(change: bool, index: u32) -> DerivedAddress {
        let d = AddressDerivation::new(&SECRET, Network::Testnet).unwrap();
        if change {
            d.get_change_address(index).unwrap()
        } else {
            d.get_receive_address(index).unwrap()
        }
    }

    fn fingerprint() -> Fingerprint {
        AddressDerivation::new(&SECRET, Network::Testnet)
            .unwrap()
            .master_fingerprint()
            .unwrap()
    }

    /// A PSBT spending one input per `spks` entry to an unrelated output.
    fn spending(spks: &[ScriptBuf]) -> Psbt {
        use bitcoin::{
            absolute::LockTime, transaction::Version, Amount, OutPoint, Sequence, Transaction,
            TxIn, Witness,
        };
        let input = |vout| TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::all_zeros(),
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        };
        let mut other = [2u8; 32];
        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: (0..spks.len() as u32).map(input).collect(),
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: other_address(&mut other).script_pubkey(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for (i, spk) in spks.iter().enumerate() {
            psbt.inputs[i].witness_utxo = Some(TxOut {
                value: Amount::from_sat(50_000 + i as u64),
                script_pubkey: spk.clone(),
            });
        }
        psbt
    }

    fn with_origin(
        psbt: &mut Psbt,
        input: usize,
        key: XOnlyPublicKey,
        fp: Fingerprint,
        path: &str,
    ) {
        psbt.inputs[input]
            .tap_key_origins
            .insert(key, (vec![], (fp, DerivationPath::from_str(path).unwrap())));
    }

    /// The key-path signature on `input` verifies under the output key of the
    /// scriptPubKey it spends, with the BIP-341 sighash over every prevout: the rule
    /// a node applies to a key-path witness.
    fn spends_on_chain(psbt: &Psbt, input: usize) -> bool {
        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .map(|i| i.witness_utxo.clone().unwrap())
            .collect();
        let Some(sig) = psbt.inputs[input].tap_key_sig else {
            return false;
        };
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .taproot_key_spend_signature_hash(input, &Prevouts::All(&prevouts), sig.sighash_type)
            .unwrap();
        let msg = Message::from_digest(sighash.to_byte_array());
        let spk = &prevouts[input].script_pubkey;
        let output_key = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34]).unwrap();
        spk.is_p2tr()
            && Secp256k1::verification_only()
                .verify_schnorr(&sig.signature, &msg, &output_key)
                .is_ok()
    }

    #[test]
    fn signs_the_wallets_bip86_addresses_so_they_spend() {
        let r0 = derived(false, 0);
        let r5 = derived(false, 5);
        let c2 = derived(true, 2);
        let mut psbt = spending(&[
            r0.address.script_pubkey(),
            r5.address.script_pubkey(),
            c2.address.script_pubkey(),
        ]);
        for (i, a) in [&r0, &r5, &c2].iter().enumerate() {
            with_origin(
                &mut psbt,
                i,
                a.public_key,
                fingerprint(),
                &a.path.to_string(),
            );
        }
        assert_eq!(signer().sign(&mut psbt).unwrap(), 3);
        for i in 0..3 {
            assert!(spends_on_chain(&psbt, i), "input {i} must spend its output");
        }
    }

    #[test]
    fn legacy_single_key_address_spends_with_the_tweak_on_mainnet_only() {
        for network in [Network::Testnet, Network::Signet, Network::Regtest] {
            let mut secret = SECRET;
            let s = PsbtSigner::new(&mut secret, network).unwrap();
            let mut psbt = spending(&[own_address(&s).script_pubkey()]);
            assert!(
                s.analyze(&psbt).unwrap().signable_inputs.is_empty(),
                "{network}"
            );
            assert_eq!(s.sign(&mut psbt).unwrap(), 0, "{network}");
        }
        let mut secret = SECRET;
        let s = PsbtSigner::new(&mut secret, Network::Bitcoin).unwrap();
        let mut psbt = spending(&[own_address(&s).script_pubkey()]);
        assert_eq!(s.sign(&mut psbt).unwrap(), 1);
        assert!(
            spends_on_chain(&psbt, 0),
            "must verify under the tweaked output key"
        );
        let sig = psbt.inputs[0].tap_key_sig.unwrap().signature;
        let prevouts = [psbt.inputs[0].witness_utxo.clone().unwrap()];
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        assert!(
            Secp256k1::verification_only()
                .verify_schnorr(
                    &sig,
                    &Message::from_digest(sighash.to_byte_array()),
                    &s.x_only_public_key()
                )
                .is_err(),
            "an untweaked signature is what nodes reject"
        );
    }

    #[test]
    fn bip86_input_needs_the_wallets_key_origin() {
        let a = derived(false, 0);
        let mut psbt = spending(&[a.address.script_pubkey()]);
        assert_eq!(
            signer().sign(&mut psbt).unwrap(),
            0,
            "no origin, no key to try"
        );
    }

    /// The key-path scriptPubKey of the wallet's own key at `path`, whatever the
    /// layout, as BIP-86 would build it.
    fn wallet_key_spk(path: &str) -> ScriptBuf {
        let secp = Secp256k1::new();
        let child = Xpriv::new_master(Network::Testnet, &SECRET)
            .unwrap()
            .derive_priv(&secp, &DerivationPath::from_str(path).unwrap())
            .unwrap();
        let (xonly, _) = child.to_keypair(&secp).x_only_public_key();
        Address::p2tr(&secp, xonly, None, Network::Testnet).script_pubkey()
    }

    #[test]
    fn forged_or_foreign_origins_never_make_an_input_signable() {
        let a = derived(false, 0);
        let mut other = [2u8; 32];
        let foreign = other_address(&mut other).script_pubkey();
        let cases: Vec<(&str, ScriptBuf, Fingerprint, &str, Option<TapNodeHash>)> = vec![
            (
                "foreign output, our origin",
                foreign,
                fingerprint(),
                "86'/1'/0'/0/0",
                None,
            ),
            (
                "our output, another wallet's fingerprint",
                a.address.script_pubkey(),
                Fingerprint::from([1, 2, 3, 4]),
                "86'/1'/0'/0/0",
                None,
            ),
            (
                "the wallet key, a BIP-84 path outside the address layout",
                wallet_key_spk("84'/1'/0'/0/0"),
                fingerprint(),
                "84'/1'/0'/0/0",
                None,
            ),
            (
                "the wallet key, the mainnet coin type outside the address layout",
                wallet_key_spk("86'/0'/0'/0/0"),
                fingerprint(),
                "86'/0'/0'/0/0",
                None,
            ),
            (
                "the wallet key, a third chain outside the address layout",
                wallet_key_spk("86'/1'/0'/2/0"),
                fingerprint(),
                "86'/1'/0'/2/0",
                None,
            ),
            (
                "our output, a forged merkle root",
                a.address.script_pubkey(),
                fingerprint(),
                "86'/1'/0'/0/0",
                Some(TapNodeHash::from_byte_array([9; 32])),
            ),
        ];
        for (label, spk, fp, path, root) in cases {
            let mut psbt = spending(&[spk]);
            with_origin(&mut psbt, 0, a.public_key, fp, path);
            psbt.inputs[0].tap_merkle_root = root;
            assert_eq!(signer().sign(&mut psbt).unwrap(), 0, "{label}");
            assert!(psbt.inputs[0].tap_key_sig.is_none(), "{label}");
        }
    }

    #[test]
    fn change_to_a_derived_address_is_recognized_only_with_a_matching_origin() {
        let s = signer();
        let c = derived(true, 3);
        let mut psbt = psbt_paying(c.address.script_pubkey(), 10_000, 20_000, None);
        assert!(
            !s.analyze(&psbt).unwrap().outputs[0].is_change,
            "no origin: counted as a spend"
        );
        psbt.outputs[0]
            .tap_key_origins
            .insert(c.public_key, (vec![], (fingerprint(), c.path.clone())));
        assert!(s.analyze(&psbt).unwrap().outputs[0].is_change);

        let mut other = [2u8; 32];
        let mut forged = psbt_paying(
            other_address(&mut other).script_pubkey(),
            10_000,
            20_000,
            None,
        );
        forged.outputs[0]
            .tap_key_origins
            .insert(c.public_key, (vec![], (fingerprint(), c.path.clone())));
        assert!(
            !s.analyze(&forged).unwrap().outputs[0].is_change,
            "origin on a foreign output"
        );
    }

    #[test]
    fn change_is_only_the_first_change_addresses_of_account_0() {
        let s = signer();
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Testnet, &SECRET).unwrap();
        let output_to = |path: &str| {
            let child = master
                .derive_priv(&secp, &DerivationPath::from_str(path).unwrap())
                .unwrap();
            let (xonly, _) = child.to_keypair(&secp).x_only_public_key();
            let mut psbt = psbt_paying(
                Address::p2tr(&secp, xonly, None, Network::Testnet).script_pubkey(),
                10_000,
                20_000,
                None,
            );
            psbt.outputs[0].tap_key_origins.insert(
                xonly,
                (
                    vec![],
                    (fingerprint(), DerivationPath::from_str(path).unwrap()),
                ),
            );
            s.analyze(&psbt).unwrap().outputs[0].is_change
        };
        assert!(output_to("86'/1'/0'/1/0"));
        assert!(output_to("86'/1'/0'/1/999"));
        assert!(
            !output_to("86'/1'/0'/1/1000"),
            "past the watched change range"
        );
        assert!(!output_to("86'/1'/0'/1/2147483647"));
        assert!(!output_to("86'/1'/1'/1/0"), "another account");
        assert!(!output_to("86'/1'/0'/0/0"), "the receive chain");
    }

    #[test]
    fn signs_for_any_account_and_on_mainnet() {
        let d = AddressDerivation::new(&SECRET, Network::Testnet).unwrap();
        let a = d.derive_taproot_address(4, false, 9).unwrap();
        let mut psbt = spending(&[a.address.script_pubkey()]);
        with_origin(
            &mut psbt,
            0,
            a.public_key,
            fingerprint(),
            &a.path.to_string(),
        );
        assert_eq!(signer().sign(&mut psbt).unwrap(), 1);
        assert!(spends_on_chain(&psbt, 0));

        let mut secret = SECRET;
        let main = PsbtSigner::new(&mut secret, Network::Bitcoin).unwrap();
        let d = AddressDerivation::new(&SECRET, Network::Bitcoin).unwrap();
        let a = d.get_receive_address(2).unwrap();
        assert!(a.path.to_string().starts_with("86'/0'/0'"));
        let mut psbt = spending(&[a.address.script_pubkey()]);
        let fp = d.master_fingerprint().unwrap();
        with_origin(&mut psbt, 0, a.public_key, fp, &a.path.to_string());
        assert_eq!(main.sign(&mut psbt).unwrap(), 1);
        assert!(spends_on_chain(&psbt, 0));
    }

    #[test]
    fn psbts_past_the_size_limit_are_refused_before_parsing() {
        use bitcoin::base64::{engine::general_purpose::STANDARD, Engine};
        let mut psbt = spending(&[derived(false, 0).address.script_pubkey()]);
        let base = psbt.serialize().len();
        psbt.inputs[0].unknown.insert(
            bitcoin::psbt::raw::Key {
                type_value: 0xf0,
                key: vec![],
            },
            vec![0u8; MAX_PSBT_BYTES - base - 8],
        );
        let at_limit = psbt.serialize();
        assert!(at_limit.len() <= MAX_PSBT_BYTES);
        assert!(
            parse_psbt(&at_limit).is_ok(),
            "{:?}",
            parse_psbt(&at_limit).err()
        );
        assert!(parse_psbt_base64(&STANDARD.encode(&at_limit)).is_ok());

        psbt.inputs[0]
            .unknown
            .values_mut()
            .for_each(|v| v.extend([0u8; 16]));
        let over = psbt.serialize();
        assert!(over.len() > MAX_PSBT_BYTES);
        assert!(
            matches!(parse_psbt(&over), Err(BitcoinError::InvalidPsbt(m)) if m.contains("limit"))
        );
        // Refused on its length alone, before decoding allocates anything.
        assert!(matches!(
            parse_psbt_base64(&STANDARD.encode(&over)),
            Err(BitcoinError::InvalidPsbt(m)) if m.contains("base64 characters")
        ));
    }

    #[test]
    fn mainnet_signs_and_recognizes_change_only_under_coin_type_0() {
        let mut secret = SECRET;
        let main = PsbtSigner::new(&mut secret, Network::Bitcoin).unwrap();
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Bitcoin, &SECRET).unwrap();
        let fp = master.fingerprint(&secp);
        let key_at = |path: &str| {
            let path = DerivationPath::from_str(path).unwrap();
            let child = master.derive_priv(&secp, &path).unwrap();
            let (xonly, _) = child.to_keypair(&secp).x_only_public_key();
            let spk = Address::p2tr(&secp, xonly, None, Network::Bitcoin).script_pubkey();
            (xonly, path, spk)
        };
        for (path, signs) in [
            ("86'/0'/0'/0/5", true),
            ("86'/0'/0'/1/7", true),
            ("86'/0'/3'/0/0", true),
            ("86'/1'/0'/0/5", false),
            ("86'/1'/0'/1/7", false),
        ] {
            let (xonly, path_d, spk) = key_at(path);
            let mut psbt = spending(&[spk]);
            with_origin(&mut psbt, 0, xonly, fp, &path_d.to_string());
            assert_eq!(main.sign(&mut psbt).unwrap(), usize::from(signs), "{path}");
            assert_eq!(spends_on_chain(&psbt, 0), signs, "{path}");
        }
        for (path, change) in [
            ("86'/0'/0'/1/0", true),
            ("86'/0'/0'/1/999", true),
            ("86'/0'/0'/1/1000", false),
            ("86'/0'/0'/0/0", false),
            ("86'/1'/0'/1/0", false),
        ] {
            let (xonly, path_d, spk) = key_at(path);
            let mut psbt = psbt_paying(spk, 10_000, 20_000, None);
            psbt.outputs[0]
                .tap_key_origins
                .insert(xonly, (vec![], (fp, path_d)));
            assert_eq!(
                main.analyze(&psbt).unwrap().outputs[0].is_change,
                change,
                "{path}"
            );
        }
    }

    #[test]
    fn a_foreign_input_without_its_utxo_stops_everything() {
        let a = derived(false, 0);
        let mut other = [2u8; 32];
        let mut psbt = spending(&[
            a.address.script_pubkey(),
            other_address(&mut other).script_pubkey(),
        ]);
        with_origin(
            &mut psbt,
            0,
            a.public_key,
            fingerprint(),
            &a.path.to_string(),
        );
        let analysis = signer().analyze(&psbt).unwrap();
        assert_eq!(analysis.input_sats, vec![50_000, 50_001]);
        assert_eq!(analysis.signable_inputs, vec![0]);

        // BIP-341 commits to every input's amount and script, so without the foreign
        // input's UTXO there is nothing correct to sign.
        psbt.inputs[1].witness_utxo = None;
        assert!(signer().analyze(&psbt).is_err());
        assert!(matches!(
            signer().sign(&mut psbt),
            Err(BitcoinError::MissingWitnessUtxo(1))
        ));
        assert!(psbt.inputs[0].tap_key_sig.is_none());
    }

    #[test]
    fn sighash_all_is_signed_and_narrower_types_are_refused() {
        use bitcoin::psbt::PsbtSighashType;
        let a = derived(false, 1);
        let mut psbt = spending(&[a.address.script_pubkey()]);
        with_origin(
            &mut psbt,
            0,
            a.public_key,
            fingerprint(),
            &a.path.to_string(),
        );
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(TapSighashType::All));
        assert_eq!(signer().sign(&mut psbt).unwrap(), 1);
        assert_eq!(
            psbt.inputs[0].tap_key_sig.unwrap().sighash_type,
            TapSighashType::All
        );
        assert!(spends_on_chain(&psbt, 0));

        for ty in [
            TapSighashType::None,
            TapSighashType::Single,
            TapSighashType::AllPlusAnyoneCanPay,
        ] {
            let mut psbt = spending(&[a.address.script_pubkey()]);
            with_origin(
                &mut psbt,
                0,
                a.public_key,
                fingerprint(),
                &a.path.to_string(),
            );
            psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(ty));
            assert!(signer().sign(&mut psbt).is_err(), "{ty:?}");
            assert!(psbt.inputs[0].tap_key_sig.is_none(), "{ty:?}");
        }
    }

    /// Forged origins all carrying the wallet's fingerprint and a valid path cost
    /// public checks only: one secret derivation for the input that is the wallet's.
    #[test]
    fn forged_origins_cost_at_most_one_secret_derivation_per_input() {
        let a = derived(false, 0);
        let mut psbt = spending(&[a.address.script_pubkey()]);
        let secp = Secp256k1::new();
        for n in 1..=2000u32 {
            let mut sk = [0u8; 32];
            sk[28..].copy_from_slice(&n.to_be_bytes());
            let (xonly, _) = Keypair::from_seckey_slice(&secp, &sk)
                .unwrap()
                .x_only_public_key();
            with_origin(
                &mut psbt,
                0,
                xonly,
                fingerprint(),
                &format!("86'/1'/0'/0/{n}"),
            );
        }
        with_origin(
            &mut psbt,
            0,
            a.public_key,
            fingerprint(),
            &a.path.to_string(),
        );
        let s = signer();
        let before = SECRET_DERIVATIONS.with(|n| n.get());
        let signed = s.sign(&mut psbt).unwrap();
        let used = SECRET_DERIVATIONS.with(|n| n.get()) - before;
        assert_eq!(signed, 1);
        assert!(spends_on_chain(&psbt, 0));
        assert_eq!(used, 1, "secret derivations for one input");
    }

    #[test]
    fn a_refused_input_leaves_the_whole_psbt_unsigned() {
        use bitcoin::psbt::PsbtSighashType;
        let a = derived(false, 0);
        let b = derived(false, 1);
        let mut psbt = spending(&[a.address.script_pubkey(), b.address.script_pubkey()]);
        with_origin(
            &mut psbt,
            0,
            a.public_key,
            fingerprint(),
            &a.path.to_string(),
        );
        with_origin(
            &mut psbt,
            1,
            b.public_key,
            fingerprint(),
            &b.path.to_string(),
        );
        psbt.inputs[1].sighash_type = Some(PsbtSighashType::from(TapSighashType::Single));
        assert!(
            signer().analyze(&psbt).is_err(),
            "analyze refuses before any prompt"
        );
        assert!(signer().sign(&mut psbt).is_err());
        assert!(
            psbt.inputs[0].tap_key_sig.is_none(),
            "nothing written for input 0"
        );
        assert!(psbt.inputs[1].tap_key_sig.is_none());
    }
}
