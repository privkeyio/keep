// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::error::KeepMobileError;
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
        if base64_psbt.len() > MAX_PSBT_SIZE {
            return Err(KeepMobileError::PsbtError {
                msg: "PSBT data exceeds maximum size".into(),
            });
        }
        let psbt = keep_bitcoin::psbt::parse_psbt_base64(&base64_psbt)?;
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
                    msg: format!("Unknown network: {}", network),
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

        for input in &self.psbt.inputs {
            if let Some(utxo) = &input.witness_utxo {
                total_input_sats = total_input_sats
                    .checked_add(utxo.value.to_sat())
                    .ok_or_else(|| KeepMobileError::PsbtError {
                        msg: "Input value overflow".into(),
                    })?;
            }
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

        let fee_sats = total_input_sats.saturating_sub(total_output_sats);

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
        let prevouts: Vec<TxOut> = self
            .psbt
            .inputs
            .iter()
            .enumerate()
            .map(|(i, input)| {
                input.witness_utxo.clone().ok_or(KeepMobileError::PsbtError {
                    msg: format!("Missing witness UTXO for input {}", i),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let prevouts_ref = Prevouts::All(&prevouts);
        let mut sighash_cache = SighashCache::new(&self.psbt.unsigned_tx);
        let mut sighashes = Vec::new();

        for i in 0..self.psbt.inputs.len() {
            if !self.is_taproot_input(i) {
                continue;
            }

            let sighash = sighash_cache
                .taproot_key_spend_signature_hash(i, &prevouts_ref, TapSighashType::Default)
                .map_err(|e| KeepMobileError::PsbtError {
                    msg: format!("Sighash computation failed for input {}: {}", i, e),
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

        let prevouts: Vec<TxOut> = self
            .psbt
            .inputs
            .iter()
            .enumerate()
            .map(|(i, input)| {
                input.witness_utxo.clone().ok_or(KeepMobileError::PsbtError {
                    msg: format!("Missing witness UTXO for input {}", i),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let prevouts_ref = Prevouts::All(&prevouts);
        let mut sighash_cache = SighashCache::new(&self.psbt.unsigned_tx);

        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(index, &prevouts_ref, TapSighashType::Default)
            .map_err(|e| KeepMobileError::PsbtError {
                msg: format!("Sighash computation failed for input {}: {}", index, e),
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
    fn is_change_output(&self, _index: usize) -> bool {
        false
    }

    fn is_taproot_input(&self, index: usize) -> bool {
        if let Some(input) = self.psbt.inputs.get(index) {
            if input.tap_internal_key.is_some() {
                return true;
            }
            if !input.tap_key_origins.is_empty() {
                return true;
            }
            if let Some(utxo) = &input.witness_utxo {
                if utxo.script_pubkey.is_p2tr() {
                    return true;
                }
            }
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
}
