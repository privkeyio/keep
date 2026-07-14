// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use crate::error::KeepMobileError;
use base64::Engine;
use bitcoin::bip32::ChildNumber;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Address, Network, TxOut};

const MAX_PSBT_SIZE: usize = 64 * 1024;

#[derive(uniffi::Record, Clone, Debug)]
pub struct PsbtInfo {
    pub num_inputs: u32,
    pub num_outputs: u32,
    pub total_input_sats: u64,
    pub total_output_sats: u64,
    pub fee_sats: u64,
    pub outputs: Vec<PsbtOutputInfo>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PsbtOutputInfo {
    pub index: u32,
    pub address: Option<String>,
    pub amount_sats: u64,
    pub is_change: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PsbtInputSighash {
    pub input_index: u32,
    pub sighash: Vec<u8>,
}

#[derive(uniffi::Object)]
pub struct PsbtParser {
    psbt: Psbt,
    network: Network,
    /// The wallet's external (`.../0/*`) descriptor, when known. Change
    /// detection derives the wallet's own change script from this and matches it
    /// against an output's `script_pubkey`; without it, change detection fails
    /// closed (no output is labeled change) because PSBT key-origin metadata is
    /// attacker-controllable.
    wallet_descriptor: Option<String>,
}

#[uniffi::export]
impl PsbtParser {
    #[uniffi::constructor]
    pub fn from_base64(base64_psbt: String) -> Result<Self, KeepMobileError> {
        let data = base64::engine::general_purpose::STANDARD
            .decode(&base64_psbt)
            .map_err(|e| KeepMobileError::PsbtError {
                msg: format!("Invalid base64: {e}"),
            })?;

        if data.len() > MAX_PSBT_SIZE {
            return Err(KeepMobileError::PsbtError {
                msg: "PSBT data exceeds maximum size".into(),
            });
        }

        let psbt = keep_bitcoin::psbt::parse_psbt(&data)?;
        Ok(Self {
            psbt,
            network: Network::Bitcoin,
            wallet_descriptor: None,
        })
    }

    #[uniffi::constructor]
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, KeepMobileError> {
        if data.len() > MAX_PSBT_SIZE {
            return Err(KeepMobileError::PsbtError {
                msg: "PSBT data exceeds maximum size".into(),
            });
        }
        let psbt = keep_bitcoin::psbt::parse_psbt(&data)?;
        Ok(Self {
            psbt,
            network: Network::Bitcoin,
            wallet_descriptor: None,
        })
    }

    pub fn set_network(&self, network: String) -> Result<Self, KeepMobileError> {
        let network = match network.to_lowercase().as_str() {
            "mainnet" | "bitcoin" => Network::Bitcoin,
            "testnet" | "testnet3" => Network::Testnet,
            "testnet4" => Network::Testnet4,
            "signet" => Network::Signet,
            "regtest" => Network::Regtest,
            _ => {
                return Err(KeepMobileError::PsbtError {
                    msg: format!("Unknown network: {network}"),
                })
            }
        };
        Ok(Self {
            psbt: self.psbt.clone(),
            network,
            wallet_descriptor: self.wallet_descriptor.clone(),
        })
    }

    /// Attach the wallet's external descriptor so change detection can verify
    /// that an output genuinely pays to the wallet's own change branch. The
    /// descriptor is validated by deriving its change script at index 0.
    pub fn with_wallet_descriptor(&self, descriptor: String) -> Result<Self, KeepMobileError> {
        keep_bitcoin::change_script_at_index(&descriptor, self.network, 0).map_err(|e| {
            KeepMobileError::PsbtError {
                msg: format!("Invalid wallet descriptor: {e}"),
            }
        })?;
        Ok(Self {
            psbt: self.psbt.clone(),
            network: self.network,
            wallet_descriptor: Some(descriptor),
        })
    }

    pub fn analyze(&self) -> Result<PsbtInfo, KeepMobileError> {
        let mut total_input_sats = 0u64;

        for i in 0..self.psbt.inputs.len() {
            let prevout = self.resolve_prevout(i)?;
            total_input_sats = total_input_sats
                .checked_add(prevout.value.to_sat())
                .ok_or_else(|| KeepMobileError::PsbtError {
                    msg: "Input value overflow".into(),
                })?;
        }

        let mut outputs = Vec::new();
        let mut total_output_sats = 0u64;

        for (i, output) in self.psbt.unsigned_tx.output.iter().enumerate() {
            total_output_sats = total_output_sats
                .checked_add(output.value.to_sat())
                .ok_or_else(|| KeepMobileError::PsbtError {
                    msg: "Output value overflow".into(),
                })?;

            let address = Address::from_script(&output.script_pubkey, self.network)
                .ok()
                .map(|a| a.to_string());

            let is_change = self.is_change_output(i);

            outputs.push(PsbtOutputInfo {
                index: i as u32,
                address,
                amount_sats: output.value.to_sat(),
                is_change,
            });
        }

        let fee_sats = total_input_sats
            .checked_sub(total_output_sats)
            .ok_or_else(|| KeepMobileError::PsbtError {
                msg: "Outputs exceed inputs (negative fee)".into(),
            })?;

        Ok(PsbtInfo {
            num_inputs: self.psbt.inputs.len() as u32,
            num_outputs: self.psbt.unsigned_tx.output.len() as u32,
            total_input_sats,
            total_output_sats,
            fee_sats,
            outputs,
        })
    }

    pub fn get_taproot_sighashes(&self) -> Result<Vec<PsbtInputSighash>, KeepMobileError> {
        let prevouts = self.collect_prevouts()?;
        let prevouts_ref = Prevouts::All(&prevouts);
        let mut sighash_cache = SighashCache::new(&self.psbt.unsigned_tx);
        let mut sighashes = Vec::new();

        for i in 0..self.psbt.inputs.len() {
            if !self.is_taproot_input(i) {
                continue;
            }

            let input = &self.psbt.inputs[i];

            if !input.tap_scripts.is_empty() {
                return Err(KeepMobileError::PsbtError {
                    msg: format!(
                        "Input {} is a taproot script-path spend ({} tap_scripts), only key-path spends are supported",
                        i,
                        input.tap_scripts.len()
                    ),
                });
            }

            let sighash_type = self.get_taproot_sighash_type(i)?;

            let sighash = sighash_cache
                .taproot_key_spend_signature_hash(i, &prevouts_ref, sighash_type)
                .map_err(|e| KeepMobileError::PsbtError {
                    msg: format!(
                        "Sighash computation failed for input {i} (key-path, {sighash_type:?}): {e}"
                    ),
                })?;

            sighashes.push(PsbtInputSighash {
                input_index: i as u32,
                sighash: sighash.to_byte_array().to_vec(),
            });
        }

        Ok(sighashes)
    }

    pub fn get_sighash_for_input(&self, input_index: u32) -> Result<Vec<u8>, KeepMobileError> {
        let index = input_index as usize;

        if index >= self.psbt.inputs.len() {
            return Err(KeepMobileError::PsbtError {
                msg: format!(
                    "Input index {} out of bounds (total: {})",
                    index,
                    self.psbt.inputs.len()
                ),
            });
        }

        if !self.is_taproot_input(index) {
            return Err(KeepMobileError::PsbtError {
                msg: format!("Input {index} is not a taproot input"),
            });
        }

        let input = &self.psbt.inputs[index];

        if !input.tap_scripts.is_empty() {
            return Err(KeepMobileError::PsbtError {
                msg: format!(
                    "Input {} is a taproot script-path spend ({} tap_scripts), only key-path spends are supported",
                    index,
                    input.tap_scripts.len()
                ),
            });
        }

        let sighash_type = self.get_taproot_sighash_type(index)?;

        let prevouts = self.collect_prevouts()?;
        let prevouts_ref = Prevouts::All(&prevouts);
        let mut sighash_cache = SighashCache::new(&self.psbt.unsigned_tx);

        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(index, &prevouts_ref, sighash_type)
            .map_err(|e| KeepMobileError::PsbtError {
                msg: format!(
                    "Sighash computation failed for input {index} (key-path, {sighash_type:?}): {e}"
                ),
            })?;

        Ok(sighash.to_byte_array().to_vec())
    }

    pub fn to_base64(&self) -> String {
        keep_bitcoin::psbt::serialize_psbt_base64(&self.psbt)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        keep_bitcoin::psbt::serialize_psbt(&self.psbt)
    }

    pub fn get_input_count(&self) -> u32 {
        self.psbt.inputs.len() as u32
    }

    pub fn get_output_count(&self) -> u32 {
        self.psbt.unsigned_tx.output.len() as u32
    }
}

impl PsbtParser {
    fn resolve_prevout(&self, input_index: usize) -> Result<TxOut, KeepMobileError> {
        let input =
            self.psbt
                .inputs
                .get(input_index)
                .ok_or_else(|| KeepMobileError::PsbtError {
                    msg: format!("Input index {input_index} out of bounds"),
                })?;

        if let Some(utxo) = &input.witness_utxo {
            return Ok(utxo.clone());
        }

        if let Some(non_witness_tx) = &input.non_witness_utxo {
            let tx_input = self
                .psbt
                .unsigned_tx
                .input
                .get(input_index)
                .ok_or_else(|| KeepMobileError::PsbtError {
                    msg: format!("Missing unsigned_tx input at index {input_index}"),
                })?;

            if non_witness_tx.compute_txid() != tx_input.previous_output.txid {
                return Err(KeepMobileError::PsbtError {
                    msg: format!(
                        "non_witness_utxo txid mismatch at input {}: expected {}, got {}",
                        input_index,
                        tx_input.previous_output.txid,
                        non_witness_tx.compute_txid()
                    ),
                });
            }

            let vout = tx_input.previous_output.vout as usize;
            let prevout =
                non_witness_tx
                    .output
                    .get(vout)
                    .ok_or_else(|| KeepMobileError::PsbtError {
                        msg: format!(
                        "non_witness_utxo output index {vout} out of bounds at input {input_index}"
                    ),
                    })?;

            return Ok(prevout.clone());
        }

        Err(KeepMobileError::PsbtError {
            msg: format!(
                "Missing prevout for input {input_index} (no witness_utxo or non_witness_utxo)"
            ),
        })
    }

    fn collect_prevouts(&self) -> Result<Vec<TxOut>, KeepMobileError> {
        (0..self.psbt.inputs.len())
            .map(|i| self.resolve_prevout(i))
            .collect()
    }

    fn is_change_output(&self, index: usize) -> bool {
        // Fail closed: without the wallet descriptor we cannot verify that an
        // output pays to our own change branch. PSBT key-origin metadata is
        // attacker-controllable, so an unverifiable output is never labeled
        // change (it is shown as a normal payment for the user to scrutinize).
        let Some(descriptor) = &self.wallet_descriptor else {
            return false;
        };
        let Some(output) = self.psbt.outputs.get(index) else {
            return false;
        };
        let Some(txout) = self.psbt.unsigned_tx.output.get(index) else {
            return false;
        };

        // Use the PSBT metadata only as a hint for the derivation index; the
        // authority is re-deriving our own change script and matching it against
        // the consensus-committed script_pubkey.
        let der_path = output
            .bip32_derivation
            .values()
            .next()
            .map(|(_, path)| path)
            .or_else(|| {
                output
                    .tap_key_origins
                    .values()
                    .next()
                    .map(|(_, (_, path))| path)
            });
        let Some(der_path) = der_path else {
            return false;
        };
        let der_index = match der_path.into_iter().last() {
            Some(ChildNumber::Normal { index }) => *index,
            _ => return false,
        };

        match keep_bitcoin::change_script_at_index(descriptor, self.network, der_index) {
            Ok(expected) => expected == txout.script_pubkey,
            Err(_) => false,
        }
    }

    fn get_taproot_sighash_type(&self, index: usize) -> Result<TapSighashType, KeepMobileError> {
        let input = self
            .psbt
            .inputs
            .get(index)
            .ok_or_else(|| KeepMobileError::PsbtError {
                msg: format!("Input index {index} out of bounds"),
            })?;

        match &input.sighash_type {
            Some(psbt_sighash) => {
                psbt_sighash
                    .taproot_hash_ty()
                    .map_err(|e| KeepMobileError::PsbtError {
                        msg: format!("Invalid taproot sighash type for input {index}: {e}"),
                    })
            }
            None => Ok(TapSighashType::Default),
        }
    }

    fn is_taproot_input(&self, index: usize) -> bool {
        let Some(input) = self.psbt.inputs.get(index) else {
            return false;
        };

        if input.tap_internal_key.is_some() || !input.tap_key_origins.is_empty() {
            return true;
        }

        if let Ok(prevout) = self.resolve_prevout(index) {
            return prevout.script_pubkey.is_p2tr();
        }

        false
    }
}

impl From<keep_bitcoin::BitcoinError> for KeepMobileError {
    fn from(e: keep_bitcoin::BitcoinError) -> Self {
        KeepMobileError::PsbtError { msg: e.to_string() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, Txid, Witness, XOnlyPublicKey};
    use std::str::FromStr;

    fn create_test_psbt() -> Psbt {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[1u8; 32]).unwrap();
        let (x_only_pubkey, _parity) = keypair.x_only_public_key();

        let tap_script = ScriptBuf::new_p2tr(&secp, x_only_pubkey, None);

        let prev_txid: Txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: tap_script.clone(),
            }],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: tap_script,
        });
        psbt.inputs[0].tap_internal_key = Some(x_only_pubkey);

        psbt
    }

    #[test]
    fn test_psbt_parser_from_bytes() {
        let psbt = create_test_psbt();
        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();
        assert_eq!(parser.get_input_count(), 1);
        assert_eq!(parser.get_output_count(), 1);
    }

    #[test]
    fn test_psbt_analyze() {
        let psbt = create_test_psbt();
        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();
        let info = parser.analyze().unwrap();
        assert_eq!(info.num_inputs, 1);
        assert_eq!(info.num_outputs, 1);
        assert_eq!(info.total_input_sats, 100000);
        assert_eq!(info.total_output_sats, 50000);
        assert_eq!(info.fee_sats, 50000);
    }

    #[test]
    fn test_psbt_sighash_extraction() {
        let psbt = create_test_psbt();
        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();
        let sighashes = parser.get_taproot_sighashes().unwrap();
        assert_eq!(sighashes.len(), 1);
        assert_eq!(sighashes[0].input_index, 0);
        assert_eq!(sighashes[0].sighash.len(), 32);
    }

    #[test]
    fn test_psbt_round_trip() {
        let psbt = create_test_psbt();
        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();
        let bytes2 = parser.to_bytes();
        let parser2 = PsbtParser::from_bytes(bytes2).unwrap();
        assert_eq!(parser2.get_input_count(), parser.get_input_count());
    }

    #[test]
    fn test_psbt_base64_round_trip() {
        let psbt = create_test_psbt();
        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();
        let base64 = parser.to_base64();
        let parser2 = PsbtParser::from_base64(base64).unwrap();
        assert_eq!(parser2.get_input_count(), parser.get_input_count());
    }

    #[test]
    fn test_psbt_invalid_base64() {
        let result = PsbtParser::from_base64("not-valid-base64!!!".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_get_sighash_for_input() {
        let psbt = create_test_psbt();
        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();
        let sighash = parser.get_sighash_for_input(0).unwrap();
        assert_eq!(sighash.len(), 32);
    }

    #[test]
    fn test_get_sighash_out_of_bounds() {
        let psbt = create_test_psbt();
        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();
        let result = parser.get_sighash_for_input(99);
        assert!(result.is_err());
    }

    // --- Change-output detection (keep-9yr): change must be verified against the
    // wallet descriptor, not trusted from attacker-controllable PSBT metadata. ---

    // A testnet BIP-86 external descriptor plus the wallet's own change (`/1/0`)
    // key and script, derived from a fixed seed.
    fn wallet_fixture() -> (String, XOnlyPublicKey, ScriptBuf) {
        use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Testnet, &[7u8; 32]).unwrap();
        let fp = master.fingerprint(&secp);
        let acct_path = DerivationPath::from_str("m/86'/1'/0'").unwrap();
        let acct_xpub = Xpub::from_priv(&secp, &master.derive_priv(&secp, &acct_path).unwrap());
        let descriptor = format!("tr([{fp}/86'/1'/0']{acct_xpub}/0/*)");

        let change_child = acct_xpub
            .derive_pub(&secp, &DerivationPath::from_str("m/1/0").unwrap())
            .unwrap();
        let (change_xonly, _) = change_child.public_key.x_only_public_key();
        let change_spk = keep_bitcoin::change_script_at_index(&descriptor, Network::Testnet, 0)
            .expect("derive change script");
        (descriptor, change_xonly, change_spk)
    }

    fn dummy_txin() -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid: "0000000000000000000000000000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    fn dummy_witness_utxo() -> TxOut {
        TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: ScriptBuf::new_p2tr(
                &Secp256k1::new(),
                Keypair::from_seckey_slice(&Secp256k1::new(), &[3u8; 32])
                    .unwrap()
                    .x_only_public_key()
                    .0,
                None,
            ),
        }
    }

    fn tag_change(psbt: &mut Psbt, out: usize, meta_key: XOnlyPublicKey, path: &str) {
        use bitcoin::bip32::{DerivationPath, Fingerprint};
        let path = DerivationPath::from_str(path).unwrap();
        psbt.outputs[out].tap_key_origins.insert(
            meta_key,
            (vec![], (Fingerprint::from([1u8, 2, 3, 4]), path)),
        );
        psbt.outputs[out].tap_internal_key = Some(meta_key);
    }

    // A single-output PSBT paying `spk`, tagged with taproot key-origin metadata
    // for `path` (the attacker's lever in the original bug).
    fn psbt_with_output_at(spk: ScriptBuf, meta_key: XOnlyPublicKey, path: &str) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![dummy_txin()],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: spk,
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(dummy_witness_utxo());
        tag_change(&mut psbt, 0, meta_key, path);
        psbt
    }

    fn psbt_with_output(spk: ScriptBuf, meta_key: XOnlyPublicKey) -> Psbt {
        psbt_with_output_at(spk, meta_key, "m/86'/1'/0'/1/0")
    }

    fn dummy_key() -> XOnlyPublicKey {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[5u8; 32])
            .unwrap()
            .x_only_public_key()
            .0
    }

    fn parser_with_descriptor(psbt: Psbt, descriptor: String) -> PsbtParser {
        PsbtParser::from_bytes(psbt.serialize())
            .unwrap()
            .set_network("testnet".to_string())
            .unwrap()
            .with_wallet_descriptor(descriptor)
            .unwrap()
    }

    #[test]
    fn genuine_change_is_detected_with_descriptor() {
        let (descriptor, change_xonly, change_spk) = wallet_fixture();
        let psbt = psbt_with_output(change_spk, change_xonly);
        let parser = PsbtParser::from_bytes(psbt.serialize())
            .unwrap()
            .set_network("testnet".to_string())
            .unwrap()
            .with_wallet_descriptor(descriptor)
            .unwrap();
        assert!(parser.analyze().unwrap().outputs[0].is_change);
    }

    #[test]
    fn forged_metadata_on_foreign_address_is_not_change() {
        // The attack: a payment to an address the wallet does not own, decorated
        // with taproot key-origin metadata so the old heuristic marked it change.
        let (descriptor, _change_xonly, _change_spk) = wallet_fixture();
        let secp = Secp256k1::new();
        let attacker_key = Keypair::from_seckey_slice(&secp, &[9u8; 32])
            .unwrap()
            .x_only_public_key()
            .0;
        let attacker_spk = ScriptBuf::new_p2tr(&secp, attacker_key, None);
        let psbt = psbt_with_output(attacker_spk, attacker_key);
        let parser = PsbtParser::from_bytes(psbt.serialize())
            .unwrap()
            .set_network("testnet".to_string())
            .unwrap()
            .with_wallet_descriptor(descriptor)
            .unwrap();
        assert!(!parser.analyze().unwrap().outputs[0].is_change);
    }

    #[test]
    fn change_fails_closed_without_descriptor() {
        // Even a genuine change output is not labeled change when the parser has
        // no wallet descriptor to verify against.
        let (_descriptor, change_xonly, change_spk) = wallet_fixture();
        let psbt = psbt_with_output(change_spk, change_xonly);
        let parser = PsbtParser::from_bytes(psbt.serialize())
            .unwrap()
            .set_network("testnet".to_string())
            .unwrap();
        assert!(!parser.analyze().unwrap().outputs[0].is_change);
    }

    #[test]
    fn with_wallet_descriptor_rejects_invalid_descriptor() {
        let psbt = create_test_psbt();
        let parser = PsbtParser::from_bytes(psbt.serialize()).unwrap();
        assert!(parser
            .with_wallet_descriptor("not a descriptor".to_string())
            .is_err());
    }

    #[test]
    fn genuine_change_detected_at_nonzero_index() {
        // The index comes from the metadata path's last component; change must be
        // re-derived at that same leaf, not only at 0.
        let (descriptor, _k, _s) = wallet_fixture();
        let change5 =
            keep_bitcoin::change_script_at_index(&descriptor, Network::Testnet, 5).unwrap();
        let psbt = psbt_with_output_at(change5, dummy_key(), "m/86'/1'/0'/1/5");
        assert!(
            parser_with_descriptor(psbt, descriptor)
                .analyze()
                .unwrap()
                .outputs[0]
                .is_change
        );
    }

    #[test]
    fn receive_self_payment_is_not_change() {
        // Paying our own receive (`/0/*`) address is a self-send, not change: the
        // change branch (`/1/*`) script at that index must not match.
        let (descriptor, _k, _s) = wallet_fixture();
        let receive3 = keep_bitcoin::descriptor_address_at_index(&descriptor, Network::Testnet, 3)
            .unwrap()
            .script_pubkey();
        let psbt = psbt_with_output_at(receive3, dummy_key(), "m/86'/1'/0'/0/3");
        assert!(
            !parser_with_descriptor(psbt, descriptor)
                .analyze()
                .unwrap()
                .outputs[0]
                .is_change
        );
    }

    #[test]
    fn mixed_outputs_flag_only_genuine_change() {
        // A two-output tx: one genuine change output and one external payment.
        let (descriptor, _k, _s) = wallet_fixture();
        let change0 =
            keep_bitcoin::change_script_at_index(&descriptor, Network::Testnet, 0).unwrap();
        let secp = Secp256k1::new();
        let external_spk = ScriptBuf::new_p2tr(
            &secp,
            Keypair::from_seckey_slice(&secp, &[9u8; 32])
                .unwrap()
                .x_only_public_key()
                .0,
            None,
        );
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![dummy_txin()],
            output: vec![
                TxOut {
                    value: Amount::from_sat(40000),
                    script_pubkey: external_spk,
                },
                TxOut {
                    value: Amount::from_sat(50000),
                    script_pubkey: change0,
                },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(dummy_witness_utxo());
        // Both outputs carry change-looking metadata; only the real one matches.
        tag_change(&mut psbt, 0, dummy_key(), "m/86'/1'/0'/1/0");
        tag_change(&mut psbt, 1, dummy_key(), "m/86'/1'/0'/1/0");
        let info = parser_with_descriptor(psbt, descriptor).analyze().unwrap();
        assert!(
            !info.outputs[0].is_change,
            "external payment must not be change"
        );
        assert!(info.outputs[1].is_change, "genuine change must be change");
    }

    #[test]
    fn test_set_network() {
        let psbt = create_test_psbt();
        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();
        let testnet_parser = parser.set_network("testnet".to_string()).unwrap();
        let info = testnet_parser.analyze().unwrap();
        assert!(info.outputs[0].address.is_some());
        assert!(info.outputs[0].address.as_ref().unwrap().starts_with("tb1"));
    }

    #[test]
    fn test_invalid_network() {
        let psbt = create_test_psbt();
        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();
        let result = parser.set_network("invalid".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_non_witness_utxo_fallback() {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[1u8; 32]).unwrap();
        let (x_only_pubkey, _parity) = keypair.x_only_public_key();
        let tap_script = ScriptBuf::new_p2tr(&secp, x_only_pubkey, None);

        let prev_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100000),
                script_pubkey: tap_script.clone(),
            }],
        };

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_tx.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: tap_script,
            }],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(prev_tx);

        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();
        let info = parser.analyze().unwrap();

        assert_eq!(info.total_input_sats, 100000);
        assert_eq!(info.total_output_sats, 50000);
        assert_eq!(info.fee_sats, 50000);
    }

    #[test]
    fn test_outputs_exceed_inputs_error() {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[1u8; 32]).unwrap();
        let (x_only_pubkey, _parity) = keypair.x_only_public_key();
        let tap_script = ScriptBuf::new_p2tr(&secp, x_only_pubkey, None);

        let prev_txid: Txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(200000),
                script_pubkey: tap_script.clone(),
            }],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: tap_script,
        });

        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();
        let result = parser.analyze();

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeepMobileError::PsbtError { .. }
        ));
    }

    #[test]
    fn test_missing_prevout_error() {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[1u8; 32]).unwrap();
        let (x_only_pubkey, _parity) = keypair.x_only_public_key();
        let tap_script = ScriptBuf::new_p2tr(&secp, x_only_pubkey, None);

        let prev_txid: Txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: tap_script,
            }],
        };

        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();
        let result = parser.analyze();

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeepMobileError::PsbtError { .. }
        ));
    }

    #[test]
    fn test_taproot_sighash_from_non_witness_utxo() {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[1u8; 32]).unwrap();
        let (x_only_pubkey, _parity) = keypair.x_only_public_key();
        let tap_script = ScriptBuf::new_p2tr(&secp, x_only_pubkey, None);

        let prev_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100000),
                script_pubkey: tap_script.clone(),
            }],
        };

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_tx.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: tap_script,
            }],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(prev_tx);

        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();

        let sighashes = parser.get_taproot_sighashes().unwrap();
        assert_eq!(sighashes.len(), 1);
        assert_eq!(sighashes[0].input_index, 0);
        assert_eq!(sighashes[0].sighash.len(), 32);

        let single_sighash = parser.get_sighash_for_input(0).unwrap();
        assert_eq!(single_sighash, sighashes[0].sighash);
    }

    #[test]
    fn test_script_path_spend_rejected() {
        use bitcoin::taproot::{ControlBlock, LeafVersion};

        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[1u8; 32]).unwrap();
        let (x_only_pubkey, _parity) = keypair.x_only_public_key();
        let tap_script = ScriptBuf::new_p2tr(&secp, x_only_pubkey, None);

        let prev_txid: Txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: tap_script.clone(),
            }],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: tap_script,
        });
        psbt.inputs[0].tap_internal_key = Some(x_only_pubkey);

        let dummy_script = ScriptBuf::from_bytes(vec![0x51]);
        let mut control_block_bytes = vec![0xc0u8];
        control_block_bytes.extend_from_slice(&x_only_pubkey.serialize());
        let control_block = ControlBlock::decode(&control_block_bytes).unwrap();
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (dummy_script, LeafVersion::TapScript));

        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();

        let result = parser.get_taproot_sighashes();
        assert!(result.is_err());

        let result = parser.get_sighash_for_input(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_non_taproot_input_rejected() {
        use bitcoin::PublicKey;

        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[1u8; 32]).unwrap();
        let pubkey = PublicKey::new(keypair.public_key());
        let p2wpkh_script = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap());

        let prev_txid: Txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: p2wpkh_script.clone(),
            }],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: p2wpkh_script,
        });

        let bytes = psbt.serialize();
        let parser = PsbtParser::from_bytes(bytes).unwrap();

        let sighashes = parser.get_taproot_sighashes().unwrap();
        assert!(sighashes.is_empty());

        let result = parser.get_sighash_for_input(0);
        assert!(result.is_err());
    }
}
