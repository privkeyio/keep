// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
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
// zeroed. Transient `Keypair` values created during `sign()` may leave stack residue.
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
            if let Some(utxo) = &input.witness_utxo {
                total_input_sats += utxo.value.to_sat();
            }

            if self.should_sign_input(psbt, i)? {
                signable_inputs.push(i);
            }
        }

        let mut outputs = Vec::new();
        let mut total_output_sats = 0u64;

        for (i, output) in psbt.unsigned_tx.output.iter().enumerate() {
            total_output_sats += output.value.to_sat();

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

        let fee_sats = total_input_sats.saturating_sub(total_output_sats);

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

        for i in 0..psbt.inputs.len() {
            if !self.should_sign_input(psbt, i)? {
                continue;
            }

            self.sign_taproot_keypath(psbt, i, &prevouts_ref)?;
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
    ) -> Result<()> {
        let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(index, prevouts, TapSighashType::Default)
            .map_err(|e| BitcoinError::Sighash(e.to_string()))?;

        let msg = Message::from_digest_slice(sighash.as_ref())
            .map_err(|e| BitcoinError::Signing(e.to_string()))?;

        let keypair = self.keypair()?;
        let aux_rand = crate::aux_rand()?;
        let sig = self
            .secp
            .sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);

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

    #[test]
    fn test_psbt_signer_creation() {
        let mut secret = [1u8; 32];
        let signer = PsbtSigner::new(&mut secret, Network::Testnet).unwrap();

        let pubkey = signer.x_only_public_key();
        assert_eq!(pubkey.serialize().len(), 32);
    }
}
