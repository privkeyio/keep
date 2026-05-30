// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use crate::error::{BitcoinError, Result};
use crate::recovery::{RecoveryOutput, TierInfo};
use bitcoin::hashes::Hash as _;
use bitcoin::key::Secp256k1;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, Keypair, Message};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, Signature as TaprootSignature, TapLeafHash};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use zeroize::Zeroizing;

const MAX_FEE_SATS: u64 = 100_000_000; // 1 BTC
/// Bitcoin Core's default dust threshold for taproot (P2TR) outputs in sats.
/// Outputs smaller than this are non-standard and unlikely to relay.
pub const TAPROOT_DUST_LIMIT_SATS: u64 = 330;
/// Maximum number of inputs in a single consolidating sweep. Taproot
/// script-path inputs carry a sizable witness (signature, leaf script, control
/// block), so a large input count both risks the ~100 kvB standardness weight
/// limit and is costly to sign (one sighash per input per signer). Bound it
/// conservatively; callers needing to consolidate more must batch into
/// multiple sweeps.
pub const MAX_SWEEP_INPUTS: usize = 100;

/// A single UTXO under the recovery output being consolidated by
/// [`RecoveryTxBuilder::build_sweep_psbt`].
#[derive(Clone, Debug)]
pub struct SweepUtxo {
    pub outpoint: OutPoint,
    pub value_sats: u64,
}

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
                "fee {fee_sats} sats exceeds maximum {MAX_FEE_SATS} sats"
            )));
        }
        if utxo_value <= fee_sats {
            return Err(BitcoinError::Recovery("insufficient funds".into()));
        }
        let output_value = utxo_value - fee_sats;
        if output_value < TAPROOT_DUST_LIMIT_SATS {
            return Err(BitcoinError::Recovery(format!(
                "output below dust threshold ({TAPROOT_DUST_LIMIT_SATS} sats)"
            )));
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

    /// Build a consolidating sweep PSBT that spends every UTXO in `utxos`
    /// (all under this recovery output, via the same `tier_index` scriptpath)
    /// into a single output paying `destination`. The output value is the sum
    /// of all UTXO values minus `fee_sats`.
    ///
    /// Every input is tagged with the tier's `tap_scripts` entry and
    /// `witness_utxo`, so each can be signed via [`script_spend_sighashes`] and
    /// aggregated by the PSBT coordination layer. `utxos` must be non-empty and
    /// contain no duplicate outpoints.
    pub fn build_sweep_psbt(
        &self,
        tier_index: usize,
        utxos: &[SweepUtxo],
        destination: &ScriptBuf,
        fee_sats: u64,
    ) -> Result<Psbt> {
        let tier = self.get_tier(tier_index)?;

        if utxos.is_empty() {
            return Err(BitcoinError::Recovery(
                "sweep requires at least one UTXO".into(),
            ));
        }
        if utxos.len() > MAX_SWEEP_INPUTS {
            return Err(BitcoinError::Recovery(format!(
                "sweep input count {} exceeds maximum {MAX_SWEEP_INPUTS}",
                utxos.len()
            )));
        }
        if fee_sats > MAX_FEE_SATS {
            return Err(BitcoinError::Recovery(format!(
                "fee {fee_sats} sats exceeds maximum {MAX_FEE_SATS} sats"
            )));
        }

        let mut seen = std::collections::HashSet::new();
        let mut total_in: u64 = 0;
        for utxo in utxos {
            if !seen.insert(utxo.outpoint) {
                return Err(BitcoinError::Recovery(format!(
                    "duplicate UTXO {} in sweep",
                    utxo.outpoint
                )));
            }
            total_in = total_in
                .checked_add(utxo.value_sats)
                .ok_or_else(|| BitcoinError::Recovery("sweep input value overflow".into()))?;
        }

        if total_in <= fee_sats {
            return Err(BitcoinError::Recovery("insufficient funds".into()));
        }
        let output_value = total_in - fee_sats;
        if output_value < TAPROOT_DUST_LIMIT_SATS {
            return Err(BitcoinError::Recovery(format!(
                "sweep output below dust threshold ({TAPROOT_DUST_LIMIT_SATS} sats)"
            )));
        }

        let sequence = match tier.timelock_blocks {
            Some(timelock_blocks) => crate::recovery::recovery_sequence(timelock_blocks)?,
            None => Sequence::ENABLE_RBF_NO_LOCKTIME,
        };

        let input: Vec<TxIn> = utxos
            .iter()
            .map(|u| TxIn {
                previous_output: u.outpoint,
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::default(),
            })
            .collect();

        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input,
            output: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: destination.clone(),
            }],
        };

        let mut psbt =
            Psbt::from_unsigned_tx(tx).map_err(|e| BitcoinError::Recovery(e.to_string()))?;

        let control_block = self.control_block(tier)?;
        let spk = self.recovery_output.address.script_pubkey();
        for (i, utxo) in utxos.iter().enumerate() {
            psbt.inputs[i].witness_utxo = Some(TxOut {
                value: Amount::from_sat(utxo.value_sats),
                script_pubkey: spk.clone(),
            });
            psbt.inputs[i].tap_scripts.insert(
                control_block.clone(),
                (tier.script.clone(), LeafVersion::TapScript),
            );
        }

        Ok(psbt)
    }

    /// Sign the single input of `psbt` for the given recovery tier.
    ///
    /// `psbt` MUST contain exactly one input. This is the recovery-tier
    /// invariant: every PSBT produced by [`Self::build_recovery_psbt`] is
    /// single-input, and finalize_recovery / aggregate_partial_psbts assume
    /// the same shape. Multi-input PSBTs are rejected.
    pub fn sign_recovery(
        &self,
        psbt: &mut Psbt,
        tier_index: usize,
        secret_key: &[u8; 32],
    ) -> Result<()> {
        let tier = self.get_tier(tier_index)?;
        if psbt.inputs.len() != 1 {
            return Err(BitcoinError::Recovery(format!(
                "sign_recovery requires exactly one PSBT input, got {}",
                psbt.inputs.len()
            )));
        }
        let sk_bytes = Zeroizing::new(*secret_key);
        let keypair = Keypair::from_seckey_slice(&self.secp, &*sk_bytes)
            .map_err(|e| BitcoinError::InvalidSecretKey(e.to_string()))?;
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

        let aux_rand = crate::aux_rand()?;
        let sig = self
            .secp
            .sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);

        psbt.inputs[0].tap_script_sigs.insert(
            (x_only, leaf_hash),
            TaprootSignature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            },
        );

        Ok(())
    }

    /// Finalize a recovery PSBT by attaching the witness stack for the given
    /// tier. Assumes `tier.script` is the CHECKSIGADD-style multisig script
    /// produced by `RecoveryConfig::build` (one stack push per key, in
    /// reverse-key order, followed by the leaf script and control block).
    /// `RecoveryConfig::build` is the only sanctioned producer of tier
    /// scripts, so this layout is guaranteed by construction.
    pub fn finalize_recovery(&self, psbt: &mut Psbt, tier_index: usize) -> Result<Transaction> {
        let tier = self.get_tier(tier_index)?;
        if psbt.inputs.len() != 1 || psbt.unsigned_tx.input.len() != 1 {
            return Err(BitcoinError::Recovery(format!(
                "finalize_recovery requires exactly one PSBT input, got {}",
                psbt.inputs.len()
            )));
        }
        let control_block = self.control_block(tier)?;
        // Defensive check: a CHECKSIGADD witness needs one push per key, so a
        // tier with zero keys cannot be finalized. Fail closed rather than
        // panic, a malformed RecoveryConfig must not crash the node.
        if tier.keys.is_empty() {
            return Err(BitcoinError::Recovery(format!(
                "tier {tier_index} has no keys; cannot build CHECKSIGADD witness"
            )));
        }

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
        let tier = self
            .recovery_output
            .tiers
            .get(index)
            .ok_or_else(|| BitcoinError::Recovery(format!("tier {index} not found")))?;
        if tier.keys.is_empty() {
            return Err(BitcoinError::Recovery(format!("tier {index} has no keys")));
        }
        if tier.threshold < 1 {
            return Err(BitcoinError::Recovery(format!(
                "tier {index} threshold must be at least 1"
            )));
        }
        if tier.threshold as usize > tier.keys.len() {
            return Err(BitcoinError::Recovery(format!(
                "tier {index} threshold {} exceeds key count {}",
                tier.threshold,
                tier.keys.len()
            )));
        }
        Ok(tier)
    }

    fn control_block(&self, tier: &TierInfo) -> Result<ControlBlock> {
        self.recovery_output
            .spend_info
            .control_block(&(tier.script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| BitcoinError::Recovery("no control block for tier script".into()))
    }
}

/// Per-input recovery-tier script-spend sighash bundle.
///
/// Returned by [`script_spend_sighashes`]. Each entry contains the BIP-341
/// sighash bytes the remote signer must sign, plus the leaf hash, leaf script,
/// and control block needed to merge the resulting Schnorr signature back into
/// the PSBT via [`merge_tap_script_sig`].
#[derive(Clone, Debug)]
pub struct ScriptSpendSighash {
    pub input_index: usize,
    pub sighash: [u8; 32],
    pub leaf_hash: TapLeafHash,
    pub script: ScriptBuf,
    pub control_block: ControlBlock,
}

/// Compute the BIP-341 script-spend sighash for every input of `psbt` using
/// the tap_scripts entries already attached to the PSBT. Each input must carry
/// exactly one `tap_scripts` entry (as inserted by [`RecoveryTxBuilder::build_recovery_psbt`])
/// and a `witness_utxo`. Returns one [`ScriptSpendSighash`] per input.
pub fn script_spend_sighashes(psbt: &Psbt) -> Result<Vec<ScriptSpendSighash>> {
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
    let mut out = Vec::with_capacity(psbt.inputs.len());
    for (i, input) in psbt.inputs.iter().enumerate() {
        let mut iter = input.tap_scripts.iter();
        let (control_block, (script, leaf_version)) = iter
            .next()
            .ok_or_else(|| BitcoinError::Recovery(format!("input {i} has no tap_scripts entry")))?;
        if iter.next().is_some() {
            return Err(BitcoinError::Recovery(format!(
                "input {i} has more than one tap_scripts entry; ambiguous tier"
            )));
        }
        let leaf_hash = TapLeafHash::from_script(script, *leaf_version);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                i,
                &Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| BitcoinError::Sighash(e.to_string()))?;
        out.push(ScriptSpendSighash {
            input_index: i,
            sighash: sighash.to_byte_array(),
            leaf_hash,
            script: script.clone(),
            control_block: control_block.clone(),
        });
    }
    Ok(out)
}

/// Insert a remote Schnorr signature into `psbt.inputs[input_index].tap_script_sigs`
/// keyed by `(xonly_pubkey, leaf_hash)` with `SIGHASH_DEFAULT`.
///
/// `sighash` MUST be the BIP-341 script-spend sighash bytes for this input
/// (typically the value taken from the corresponding [`ScriptSpendSighash`]).
/// The signature is verified against `(sighash, xonly_pubkey)` before being
/// inserted; an invalid signature is rejected so callers cannot silently
/// merge garbage from a malicious or buggy remote signer.
pub fn merge_tap_script_sig(
    psbt: &mut Psbt,
    input_index: usize,
    xonly_pubkey: bitcoin::XOnlyPublicKey,
    leaf_hash: TapLeafHash,
    sighash: &[u8; 32],
    schnorr_sig: [u8; 64],
) -> Result<()> {
    let input = psbt
        .inputs
        .get_mut(input_index)
        .ok_or_else(|| BitcoinError::Recovery(format!("input {input_index} out of range")))?;
    let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&schnorr_sig)
        .map_err(|e| BitcoinError::Signing(format!("invalid schnorr sig: {e}")))?;
    let msg = Message::from_digest_slice(sighash)
        .map_err(|e| BitcoinError::Signing(format!("invalid sighash: {e}")))?;
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&signature, &msg, &xonly_pubkey)
        .map_err(|e| BitcoinError::Signing(format!("schnorr verify failed: {e}")))?;
    input.tap_script_sigs.insert(
        (xonly_pubkey, leaf_hash),
        TaprootSignature {
            signature,
            sighash_type: TapSighashType::Default,
        },
    );
    Ok(())
}

/// Verify that the script-spend bundle for `input_index` of `psbt` is bound
/// to the input's `witness_utxo` and that the leaf script commits to
/// `local_xonly`.
///
/// This is the security-critical gate that turns a "blind sighash signer"
/// into one that can only sign for outputs it actually controls. It enforces:
///
/// 1. `witness_utxo` is set and is a 34-byte P2TR script (so the output
///    key can be extracted).
/// 2. The PSBT input carries exactly one `tap_scripts` entry. Multiple
///    candidate scripts make the leaf-hash ambiguous and are rejected.
/// 3. The `(control_block, script, leaf_version)` triple committed to the
///    `witness_utxo`'s taproot output key, i.e. the leaf is provably part
///    of the taproot tree being spent.
/// 4. The leaf script contains `local_xonly` as a 32-byte push. This binds
///    the responder's signing key to a key actually present in the leaf;
///    without it a malicious proposer could ask the responder to sign for
///    an unrelated taproot leaf that happens to commit to the same output.
///
/// Returns the verified [`ScriptSpendSighash`] for this input on success.
pub fn verify_script_spend_input_binding(
    psbt: &Psbt,
    input_index: usize,
    local_xonly: &[u8; 32],
) -> Result<ScriptSpendSighash> {
    let input = psbt
        .inputs
        .get(input_index)
        .ok_or_else(|| BitcoinError::Recovery(format!("input {input_index} out of range")))?;

    let wu = input
        .witness_utxo
        .as_ref()
        .ok_or(BitcoinError::MissingWitnessUtxo(input_index))?;
    let spk = wu.script_pubkey.as_bytes();
    if !wu.script_pubkey.is_p2tr() || spk.len() != 34 {
        return Err(BitcoinError::Recovery(format!(
            "input {input_index} witness_utxo is not a P2TR output",
        )));
    }
    let mut output_key_bytes = [0u8; 32];
    output_key_bytes.copy_from_slice(&spk[2..34]);
    let output_key = XOnlyPublicKey::from_slice(&output_key_bytes).map_err(|e| {
        BitcoinError::Recovery(format!(
            "input {input_index} witness_utxo output key invalid: {e}"
        ))
    })?;

    let mut iter = input.tap_scripts.iter();
    let (control_block, (script, leaf_version)) = iter.next().ok_or_else(|| {
        BitcoinError::Recovery(format!("input {input_index} has no tap_scripts entry"))
    })?;
    if iter.next().is_some() {
        return Err(BitcoinError::Recovery(format!(
            "input {input_index} has more than one tap_scripts entry; ambiguous tier"
        )));
    }

    let secp = Secp256k1::verification_only();
    if !control_block.verify_taproot_commitment(&secp, output_key, script) {
        return Err(BitcoinError::Recovery(format!(
            "input {input_index} tap_scripts entry does not commit to the witness_utxo output key",
        )));
    }

    if !script_contains_xonly(script, local_xonly) {
        return Err(BitcoinError::Recovery(format!(
            "input {input_index} leaf script does not reference the local responder x-only key",
        )));
    }

    let leaf_hash = TapLeafHash::from_script(script, *leaf_version);

    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, inp)| {
            inp.witness_utxo
                .clone()
                .ok_or(BitcoinError::MissingWitnessUtxo(i))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| BitcoinError::Sighash(e.to_string()))?;

    Ok(ScriptSpendSighash {
        input_index,
        sighash: sighash.to_byte_array(),
        leaf_hash,
        script: script.clone(),
        control_block: control_block.clone(),
    })
}

/// Verify every PSBT input's script-spend binding upfront and return the
/// per-input [`ScriptSpendSighash`] bundles. Errors with the offending
/// input index if any input fails the security-critical binding check in
/// [`verify_script_spend_input_binding`].
pub fn verify_all_script_spend_input_bindings(
    psbt: &Psbt,
    local_xonly: &[u8; 32],
) -> Result<Vec<ScriptSpendSighash>> {
    let mut out = Vec::with_capacity(psbt.inputs.len());
    for i in 0..psbt.inputs.len() {
        out.push(verify_script_spend_input_binding(psbt, i, local_xonly)?);
    }
    Ok(out)
}

/// Scan `script` opcodes for any 32-byte push equal to `xonly`. Recovery
/// tier leaves built by `RecoveryConfig::build` push each x-only key with
/// `OP_PUSHBYTES_32`, so any participating key shows up as such a push.
fn script_contains_xonly(script: &bitcoin::Script, xonly: &[u8; 32]) -> bool {
    use bitcoin::script::Instruction;
    for instr in script.instructions() {
        if let Ok(Instruction::PushBytes(b)) = instr {
            if b.as_bytes() == xonly.as_slice() {
                return true;
            }
        }
    }
    false
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
    fn test_build_sweep_psbt_consolidates_utxos() {
        let (_, pk1) = test_keypair_full(1);
        let (_, pk2) = test_keypair_full(2);
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

        let utxos = vec![
            SweepUtxo {
                outpoint: OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 0,
                },
                value_sats: 100_000,
            },
            SweepUtxo {
                outpoint: OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 1,
                },
                value_sats: 50_000,
            },
        ];

        let xonly_pk1 = XOnlyPublicKey::from_slice(&pk1).unwrap();
        let dest = ScriptBuf::new_p2tr(&secp, xonly_pk1, None);

        let psbt = builder.build_sweep_psbt(0, &utxos, &dest, 2_000).unwrap();

        assert_eq!(psbt.unsigned_tx.input.len(), 2);
        assert_eq!(psbt.unsigned_tx.output.len(), 1);
        assert_eq!(psbt.unsigned_tx.output[0].value.to_sat(), 148_000);
        for input in &psbt.inputs {
            assert!(input.witness_utxo.is_some());
            assert_eq!(input.tap_scripts.len(), 1);
        }
        assert!(psbt.unsigned_tx.input[0].sequence.is_relative_lock_time());
    }

    #[test]
    fn test_build_sweep_psbt_rejects_empty_and_duplicate() {
        let (_, pk1) = test_keypair_full(1);
        let (_, pk2) = test_keypair_full(2);
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
        let builder = RecoveryTxBuilder::new(config.build().unwrap());
        let xonly_pk1 = XOnlyPublicKey::from_slice(&pk1).unwrap();
        let dest = ScriptBuf::new_p2tr(&secp, xonly_pk1, None);

        assert!(builder.build_sweep_psbt(0, &[], &dest, 1_000).is_err());

        let op = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        let dup = vec![
            SweepUtxo {
                outpoint: op,
                value_sats: 100_000,
            },
            SweepUtxo {
                outpoint: op,
                value_sats: 100_000,
            },
        ];
        let err = builder.build_sweep_psbt(0, &dup, &dest, 1_000).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn test_build_sweep_psbt_insufficient_funds() {
        let (_, pk1) = test_keypair_full(1);
        let (_, pk2) = test_keypair_full(2);
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
        let builder = RecoveryTxBuilder::new(config.build().unwrap());
        let xonly_pk1 = XOnlyPublicKey::from_slice(&pk1).unwrap();
        let dest = ScriptBuf::new_p2tr(&secp, xonly_pk1, None);
        let utxos = vec![SweepUtxo {
            outpoint: OutPoint {
                txid: bitcoin::Txid::all_zeros(),
                vout: 0,
            },
            value_sats: 500,
        }];
        assert!(builder.build_sweep_psbt(0, &utxos, &dest, 1_000).is_err());
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
