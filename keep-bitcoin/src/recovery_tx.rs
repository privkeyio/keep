// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::error::{BitcoinError, Result};
use crate::recovery::{RecoveryOutput, TierInfo};
use bitcoin::key::Secp256k1;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, Keypair, Message};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, Signature as TaprootSignature};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use zeroize::Zeroize;

const MAX_FEE_SATS: u64 = 100_000_000; // 1 BTC

pub struct RecoveryTxBuilder {
    recovery_output: RecoveryOutput,
    secp: Secp256k1<All>,
}

impl RecoveryTxBuilder {
    pub fn new(recovery_output: RecoveryOutput) -> Self {
        Self {
            recovery_output,
            secp: Secp256k1::new(),
        }
    }

    pub fn build_recovery_psbt(
        &self,
        tier_index: usize,
        utxo: OutPoint,
        utxo_value: u64,
        destination: &ScriptBuf,
        fee_sats: u64,
    ) -> Result<Psbt> {
        let tier = self.get_tier(tier_index)?;

        if fee_sats > MAX_FEE_SATS {
            return Err(BitcoinError::Recovery(format!(
                "fee {} sats exceeds maximum {} sats",
                fee_sats, MAX_FEE_SATS
            )));
        }
        if utxo_value <= fee_sats {
            return Err(BitcoinError::Recovery("insufficient funds".into()));
        }
        let output_value = utxo_value - fee_sats;
        if output_value < 330 {
            return Err(BitcoinError::Recovery(
                "output below dust threshold (330 sats)".into(),
            ));
        }

        let sequence = match tier.timelock_blocks {
            Some(timelock_blocks) => crate::recovery::recovery_sequence(timelock_blocks)?,
            None => Sequence::ENABLE_RBF_NO_LOCKTIME,
        };

        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: utxo,
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: destination.clone(),
            }],
        };

        let mut psbt =
            Psbt::from_unsigned_tx(tx).map_err(|e| BitcoinError::Recovery(e.to_string()))?;

        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(utxo_value),
            script_pubkey: self.recovery_output.address.script_pubkey(),
        });

        let control_block = self.control_block(tier)?;
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (tier.script.clone(), LeafVersion::TapScript));

        Ok(psbt)
    }

    pub fn sign_recovery(
        &self,
        psbt: &mut Psbt,
        tier_index: usize,
        secret_key: &[u8; 32],
    ) -> Result<()> {
        let tier = self.get_tier(tier_index)?;
        let mut sk_bytes = *secret_key;
        let keypair = Keypair::from_seckey_slice(&self.secp, &sk_bytes).map_err(|e| {
            sk_bytes.zeroize();
            BitcoinError::InvalidSecretKey(e.to_string())
        })?;
        sk_bytes.zeroize();
        let (x_only, _) = keypair.x_only_public_key();

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

        let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
        let leaf_hash = tier.leaf_hash;

        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| BitcoinError::Sighash(e.to_string()))?;

        let msg = Message::from_digest_slice(sighash.as_ref())
            .map_err(|e| BitcoinError::Signing(e.to_string()))?;

        let sig = self.secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        psbt.inputs[0].tap_script_sigs.insert(
            (x_only, leaf_hash),
            TaprootSignature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            },
        );

        Ok(())
    }

    pub fn finalize_recovery(&self, psbt: &mut Psbt, tier_index: usize) -> Result<Transaction> {
        let tier = self.get_tier(tier_index)?;
        let control_block = self.control_block(tier)?;

        let sig_count = psbt.inputs[0]
            .tap_script_sigs
            .iter()
            .filter(|((_, lh), _)| *lh == tier.leaf_hash)
            .count();

        if (sig_count as u32) < tier.threshold {
            return Err(BitcoinError::Recovery(format!(
                "insufficient signatures: have {}, need {}",
                sig_count, tier.threshold
            )));
        }

        let mut witness = Witness::new();
        let mut sigs_included: u32 = 0;
        for key in tier.keys.iter().rev() {
            if sigs_included < tier.threshold {
                if let Some(sig) = psbt.inputs[0].tap_script_sigs.get(&(*key, tier.leaf_hash)) {
                    witness.push(sig.to_vec());
                    sigs_included += 1;
                } else {
                    witness.push([]);
                }
            } else {
                witness.push([]);
            }
        }
        witness.push(tier.script.as_bytes());
        witness.push(control_block.serialize());

        let mut tx = psbt.unsigned_tx.clone();
        tx.input[0].witness = witness;

        Ok(tx)
    }

    fn get_tier(&self, index: usize) -> Result<&TierInfo> {
        self.recovery_output
            .tiers
            .get(index)
            .ok_or_else(|| BitcoinError::Recovery(format!("tier {} not found", index)))
    }

    fn control_block(&self, tier: &TierInfo) -> Result<ControlBlock> {
        self.recovery_output
            .spend_info
            .control_block(&(tier.script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| BitcoinError::Recovery("no control block for tier script".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::{RecoveryConfig, RecoveryTier, SpendingTier};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Keypair;
    use bitcoin::{Network, XOnlyPublicKey};

    fn test_keypair_full(seed: u8) -> ([u8; 32], [u8; 32]) {
        let secp = Secp256k1::new();
        let mut secret = [seed; 32];
        secret[0] = seed.wrapping_add(1);
        let kp = Keypair::from_seckey_slice(&secp, &secret).unwrap();
        let xonly = kp.x_only_public_key().0.serialize();
        (secret, xonly)
    }

    #[test]
    fn test_build_recovery_psbt() {
        let (_, pk1) = test_keypair_full(1);
        let (_, pk2) = test_keypair_full(2);

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![pk1],
                threshold: 1,
            },
            recovery_tiers: vec![RecoveryTier {
                keys: vec![pk2],
                threshold: 1,
                timelock_months: 6,
            }],
            network: Network::Testnet,
        };

        let output = config.build().unwrap();
        let builder = RecoveryTxBuilder::new(output);

        let utxo = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        let xonly_pk1 = XOnlyPublicKey::from_slice(&pk1).unwrap();
        let dest = ScriptBuf::new_p2tr(&Secp256k1::new(), xonly_pk1, None);

        let psbt = builder
            .build_recovery_psbt(0, utxo, 100_000, &dest, 1_000)
            .unwrap();

        assert_eq!(psbt.unsigned_tx.input.len(), 1);
        assert_eq!(psbt.unsigned_tx.output.len(), 1);
        assert_eq!(psbt.unsigned_tx.output[0].value.to_sat(), 99_000);
        assert!(psbt.unsigned_tx.input[0].sequence.is_relative_lock_time());
    }

    #[test]
    fn test_sign_and_finalize_recovery() {
        let (_, pk1) = test_keypair_full(1);
        let (sk2, pk2) = test_keypair_full(2);
        let secp = Secp256k1::new();

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![pk1],
                threshold: 1,
            },
            recovery_tiers: vec![RecoveryTier {
                keys: vec![pk2],
                threshold: 1,
                timelock_months: 6,
            }],
            network: Network::Testnet,
        };

        let output = config.build().unwrap();
        let builder = RecoveryTxBuilder::new(output);

        let utxo = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        let xonly_pk1 = XOnlyPublicKey::from_slice(&pk1).unwrap();
        let dest = ScriptBuf::new_p2tr(&secp, xonly_pk1, None);

        let mut psbt = builder
            .build_recovery_psbt(0, utxo, 100_000, &dest, 1_000)
            .unwrap();

        builder.sign_recovery(&mut psbt, 0, &sk2).unwrap();

        let tx = builder.finalize_recovery(&mut psbt, 0).unwrap();
        assert!(!tx.input[0].witness.is_empty());
    }

    #[test]
    fn test_finalize_with_excess_signatures() {
        let (_, pk1) = test_keypair_full(1);
        let (sk2, pk2) = test_keypair_full(2);
        let (sk3, pk3) = test_keypair_full(3);
        let (sk4, pk4) = test_keypair_full(4);
        let secp = Secp256k1::new();

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![pk1],
                threshold: 1,
            },
            recovery_tiers: vec![RecoveryTier {
                keys: vec![pk2, pk3, pk4],
                threshold: 2,
                timelock_months: 6,
            }],
            network: Network::Testnet,
        };

        let output = config.build().unwrap();
        let builder = RecoveryTxBuilder::new(output);

        let utxo = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        let xonly_pk1 = XOnlyPublicKey::from_slice(&pk1).unwrap();
        let dest = ScriptBuf::new_p2tr(&secp, xonly_pk1, None);

        let mut psbt = builder
            .build_recovery_psbt(0, utxo, 100_000, &dest, 1_000)
            .unwrap();

        builder.sign_recovery(&mut psbt, 0, &sk2).unwrap();
        builder.sign_recovery(&mut psbt, 0, &sk3).unwrap();
        builder.sign_recovery(&mut psbt, 0, &sk4).unwrap();

        assert_eq!(
            psbt.inputs[0]
                .tap_script_sigs
                .iter()
                .filter(|((_, lh), _)| *lh == builder.recovery_output.tiers[0].leaf_hash)
                .count(),
            3
        );

        let tx = builder.finalize_recovery(&mut psbt, 0).unwrap();
        assert!(!tx.input[0].witness.is_empty());

        let sig_count = tx.input[0]
            .witness
            .iter()
            .take(3)
            .filter(|w| !w.is_empty())
            .count();
        assert_eq!(sig_count, 2);
    }
}
