// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::error::KeepMobileError;
use base64::Engine;
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
        let Some(output) = self.psbt.outputs.get(index) else {
            return false;
        };

        !output.bip32_derivation.is_empty()
            || !output.tap_key_origins.is_empty()
            || output.tap_internal_key.is_some()
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
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, Txid, Witness};

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
