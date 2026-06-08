// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use crate::error::{BitcoinError, Result};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::Signature as TaprootSignature;
use bitcoin::{Address, Network, TxOut, XOnlyPublicKey};
use keep_core::crypto::MlockedBox;

#[derive(Debug, Clone)]
pub struct PsbtAnalysis {
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub total_input_sats: u64,
    pub total_output_sats: u64,
    pub fee_sats: u64,
    pub outputs: Vec<OutputInfo>,
    pub signable_inputs: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct OutputInfo {
    pub index: usize,
    pub address: Option<String>,
    pub amount_sats: u64,
    pub is_change: bool,
}

// NOTE: `Keypair` (from secp256k1) does not implement `Zeroize` and cannot be reliably
// zeroed. A single `Keypair` is created per `sign()` call to minimize stack copies.
// The canonical secret key is held in `MlockedBox` which provides mlock + madvise +
// zeroize-on-drop, so the authoritative copy is protected at rest.
pub struct PsbtSigner {
    secret: MlockedBox<32>,
    x_only_pubkey: XOnlyPublicKey,
    secp: Secp256k1<bitcoin::secp256k1::All>,
    network: Network,
}

impl PsbtSigner {
    pub fn new(secret: &mut [u8; 32], network: Network) -> Result<Self> {
        let secp = Secp256k1::new();

        let keypair = Keypair::from_seckey_slice(&secp, secret)
            .map_err(|e| BitcoinError::InvalidSecretKey(e.to_string()))?;

        let (x_only_pubkey, _parity) = keypair.x_only_public_key();

        Ok(Self {
            secret: MlockedBox::new(secret),
            x_only_pubkey,
            secp,
            network,
        })
    }

    pub fn x_only_public_key(&self) -> XOnlyPublicKey {
        self.x_only_pubkey
    }

    fn keypair(&self) -> Result<Keypair> {
        Keypair::from_seckey_slice(&self.secp, &*self.secret)
            .map_err(|e| BitcoinError::InvalidSecretKey(e.to_string()))
    }

    pub fn analyze(&self, psbt: &Psbt) -> Result<PsbtAnalysis> {
        let mut total_input_sats = 0u64;
        let mut signable_inputs = Vec::new();

        for (i, input) in psbt.inputs.iter().enumerate() {
            let utxo = input.witness_utxo.as_ref().ok_or_else(|| {
                BitcoinError::InvalidPsbt(format!("input {i} missing witness_utxo"))
            })?;
            total_input_sats = total_input_sats
                .checked_add(utxo.value.to_sat())
                .ok_or_else(|| BitcoinError::InvalidPsbt("input value overflow".into()))?;

            if self.should_sign_input(psbt, i)? {
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
            outputs,
            signable_inputs,
        })
    }

    pub fn sign(&self, psbt: &mut Psbt) -> Result<usize> {
        let mut signed_count = 0;

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

        let keypair = self.keypair()?;

        for i in 0..psbt.inputs.len() {
            if !self.should_sign_input(psbt, i)? {
                continue;
            }

            self.sign_taproot_keypath(psbt, i, &prevouts_ref, &keypair)?;
            signed_count += 1;
        }

        Ok(signed_count)
    }

    fn should_sign_input(&self, psbt: &Psbt, index: usize) -> Result<bool> {
        let input = &psbt.inputs[index];

        if let Some(tap_internal_key) = &input.tap_internal_key {
            if tap_internal_key == &self.x_only_pubkey {
                return Ok(true);
            }
        }

        for pubkey in input.tap_key_origins.keys() {
            if pubkey == &self.x_only_pubkey {
                return Ok(true);
            }
        }

        if let Some(utxo) = &input.witness_utxo {
            let our_address = Address::p2tr(&self.secp, self.x_only_pubkey, None, self.network);
            if utxo.script_pubkey == our_address.script_pubkey() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn sign_taproot_keypath(
        &self,
        psbt: &mut Psbt,
        index: usize,
        prevouts: &Prevouts<TxOut>,
        keypair: &Keypair,
    ) -> Result<()> {
        let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(index, prevouts, TapSighashType::Default)
            .map_err(|e| BitcoinError::Sighash(e.to_string()))?;

        let msg = Message::from_digest_slice(sighash.as_ref())
            .map_err(|e| BitcoinError::Signing(e.to_string()))?;

        let aux_rand = crate::aux_rand()?;
        let sig = self
            .secp
            .sign_schnorr_with_aux_rand(&msg, keypair, &aux_rand);

        let taproot_sig = TaprootSignature {
            signature: sig,
            sighash_type: TapSighashType::Default,
        };

        psbt.inputs[index].tap_key_sig = Some(taproot_sig);

        Ok(())
    }

    fn is_change_output(&self, psbt: &Psbt, index: usize) -> bool {
        if let Some(output) = psbt.outputs.get(index) {
            for pubkey in output.tap_key_origins.keys() {
                if pubkey == &self.x_only_pubkey {
                    return true;
                }
            }

            if let Some(internal_key) = &output.tap_internal_key {
                if internal_key == &self.x_only_pubkey {
                    return true;
                }
            }
        }
        false
    }
}

pub fn parse_psbt(data: &[u8]) -> Result<Psbt> {
    Psbt::deserialize(data).map_err(|e| BitcoinError::InvalidPsbt(e.to_string()))
}

pub fn parse_psbt_base64(base64: &str) -> Result<Psbt> {
    use bitcoin::base64::{engine::general_purpose::STANDARD, Engine};
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
        let signer = PsbtSigner::new(&mut our_secret, Network::Testnet).unwrap();
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
        let signer = PsbtSigner::new(&mut our_secret, Network::Testnet).unwrap();
        let our_addr = own_address(&signer);
        let mut psbt = fixture_psbt_to(our_addr.script_pubkey(), 60_000);

        let signed = signer.sign(&mut psbt).unwrap();
        assert_eq!(signed, 1, "sign must report one signed input");
        assert!(
            psbt.inputs[0].tap_key_sig.is_some(),
            "a signature must be written for our own input"
        );
    }
}
