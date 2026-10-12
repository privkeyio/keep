// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The canonical payload of a PSBT signing request, and what an approver
//! recomputes from it before showing it.
//!
//! The gateway builds the payload from the PSBT it will sign, unchanged, and
//! from what its own analysis found: which inputs it signs, and which
//! outputs it verified as its own change by re-deriving them. The approver
//! cannot re-derive change; it recomputes everything else.

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Address, Psbt, Transaction};
use serde::{Deserialize, Serialize};

use crate::binding::Network;
use crate::codec::hex_vec;
use crate::{invalid, malformed, Result};

/// One input's previous output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prevout {
    pub amount: u64,
    #[serde(with = "hex_vec")]
    pub script: Vec<u8>,
}

/// An output the gateway verified as its own change, with the derivation
/// path it re-derived it on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeOutput {
    pub output: u32,
    pub path: String,
}

/// `payload` of a `sign_psbt` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PsbtPayload {
    /// The unsigned transaction, consensus encoded.
    #[serde(with = "hex_vec")]
    pub unsigned_tx: Vec<u8>,
    /// One per input, in order.
    pub prevouts: Vec<Prevout>,
    /// One per input, in order: `PSBT_IN_SIGHASH_TYPE`, or null when unset.
    pub sighash: Vec<Option<u32>>,
    /// The inputs the gateway signs, ascending.
    pub signing_inputs: Vec<u32>,
    /// The outputs the gateway verified as its change, ascending by output.
    pub change: Vec<ChangeOutput>,
    /// Prevouts minus outputs.
    pub fee: u64,
    /// Every output not in `change`, plus the fee.
    pub leaving_wallet: u64,
}

/// The sighash types the signer accepts on the inputs it signs: unset,
/// `DEFAULT` and `ALL`.
fn accepted_sighash(sighash: Option<u32>) -> bool {
    matches!(sighash, None | Some(0) | Some(1))
}

/// Whether `script` is a P2TR output script: `OP_1 <32 bytes>`.
fn is_p2tr(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == 0x51 && script[1] == 0x20
}

/// `PSBT_IN_SIGHASH_TYPE` unset, as the request hash encodes it.
pub const NO_SIGHASH: u32 = 0xFFFF_FFFF;

/// One output, as an approver shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputView {
    pub index: u32,
    /// The output's address on the request's network, when it has one.
    pub address: Option<String>,
    /// The output's script, for an output with no address.
    pub script: Vec<u8>,
    pub amount: u64,
    /// The derivation path, when the gateway verified it as change.
    pub change_path: Option<String>,
}

/// What an approver shows for a PSBT, every figure recomputed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsbtView {
    pub txid: String,
    pub outputs: Vec<OutputView>,
    pub fee: u64,
    pub leaving_wallet: u64,
}

impl PsbtPayload {
    /// The payload for `psbt`, which the gateway signs unchanged:
    /// `signing_inputs` are the inputs it signs and `change` the outputs it
    /// verified as change, each with the last step of its derivation path.
    pub fn from_psbt(
        psbt: &Psbt,
        signing_inputs: &[usize],
        change: &[(usize, u32)],
        network: Network,
    ) -> Result<Self> {
        let tx = &psbt.unsigned_tx;
        let mut prevouts = Vec::with_capacity(psbt.inputs.len());
        let mut sighash = Vec::with_capacity(psbt.inputs.len());
        for (i, input) in psbt.inputs.iter().enumerate() {
            let utxo = input
                .witness_utxo
                .as_ref()
                .ok_or_else(|| malformed(format!("input {i} has no witness UTXO")))?;
            prevouts.push(Prevout {
                amount: utxo.value.to_sat(),
                script: utxo.script_pubkey.to_bytes(),
            });
            sighash.push(input.sighash_type.map(|t| t.to_u32()));
        }
        let mut signing: Vec<u32> = signing_inputs
            .iter()
            .map(|&i| to_u32(i))
            .collect::<Result<_>>()?;
        signing.sort_unstable();
        let mut change_outputs = change
            .iter()
            .map(|&(output, index)| {
                Ok(ChangeOutput {
                    output: to_u32(output)?,
                    path: change_path(network, index),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        change_outputs.sort_by_key(|c| c.output);
        let mut payload = PsbtPayload {
            unsigned_tx: serialize(tx),
            prevouts,
            sighash,
            signing_inputs: signing,
            change: change_outputs,
            fee: 0,
            leaving_wallet: 0,
        };
        let (fee, leaving) = payload.figures(tx)?;
        payload.fee = fee;
        payload.leaving_wallet = leaving;
        payload.check(network)?;
        Ok(payload)
    }

    /// Check the payload as an approver does, and recompute what it shows:
    /// one prevout and one sighash per input, signing inputs and change
    /// outputs in range and ascending, every signing input's sighash one the
    /// signer accepts, change paths on the request's network, and the fee
    /// and the total leaving the wallet equal to the gateway's figures.
    pub fn check(&self, network: Network) -> Result<PsbtView> {
        let tx: Transaction = deserialize(&self.unsigned_tx)
            .map_err(|_| malformed("unsigned_tx is not a transaction"))?;
        let inputs = tx.input.len();
        if self.prevouts.len() != inputs || self.sighash.len() != inputs {
            return Err(invalid("one prevout and one sighash per input"));
        }
        // Null is how an unset type is carried; the number that encodes it
        // would give a second payload with the same hash.
        if self.sighash.contains(&Some(NO_SIGHASH)) {
            return Err(invalid("an unset sighash is carried as null"));
        }
        strictly_ascending(&self.signing_inputs, "signing_inputs")?;
        if self.signing_inputs.iter().any(|&i| i as usize >= inputs) {
            return Err(invalid("a signing input is out of range"));
        }
        if self.signing_inputs.is_empty() {
            return Err(invalid("no input to sign"));
        }
        for &i in &self.signing_inputs {
            if !accepted_sighash(self.sighash[i as usize]) {
                return Err(invalid(format!(
                    "input {i} uses a sighash the signer refuses"
                )));
            }
            // The figures below are the signature's only because the signer
            // is taproot key path over every prevout: a signing input that
            // spent anything else would not commit to the others' amounts.
            if !is_p2tr(&self.prevouts[i as usize].script) {
                return Err(invalid(format!(
                    "input {i} does not spend a taproot output"
                )));
            }
        }
        let outputs: Vec<u32> = self.change.iter().map(|c| c.output).collect();
        strictly_ascending(&outputs, "change")?;
        if outputs.iter().any(|&o| o as usize >= tx.output.len()) {
            return Err(invalid("a change output is out of range"));
        }
        for c in &self.change {
            parse_change_path(network, &c.path)?;
        }
        let (fee, leaving) = self.figures(&tx)?;
        if fee != self.fee || leaving != self.leaving_wallet {
            return Err(invalid(
                "the fee or the total leaving the wallet does not add up",
            ));
        }
        let btc_network = network.bitcoin();
        let outputs = tx
            .output
            .iter()
            .enumerate()
            .map(|(i, out)| OutputView {
                index: i as u32,
                address: Address::from_script(&out.script_pubkey, btc_network)
                    .ok()
                    .map(|a| a.to_string()),
                script: out.script_pubkey.to_bytes(),
                amount: out.value.to_sat(),
                change_path: self
                    .change
                    .iter()
                    .find(|c| c.output as usize == i)
                    .map(|c| c.path.clone()),
            })
            .collect();
        Ok(PsbtView {
            txid: tx.compute_txid().to_string(),
            outputs,
            fee,
            leaving_wallet: leaving,
        })
    }

    /// The canonical bytes the request hash covers.
    pub fn binding_bytes(&self, network: Network) -> Result<Vec<u8>> {
        self.check(network)?;
        let mut out = Vec::new();
        put_bytes(&mut out, &self.unsigned_tx)?;
        put_u32(&mut out, to_u32(self.prevouts.len())?);
        for (prevout, sighash) in self.prevouts.iter().zip(&self.sighash) {
            out.extend_from_slice(&prevout.amount.to_le_bytes());
            put_bytes(&mut out, &prevout.script)?;
            put_u32(&mut out, sighash.unwrap_or(NO_SIGHASH));
        }
        put_u32(&mut out, to_u32(self.signing_inputs.len())?);
        for &i in &self.signing_inputs {
            put_u32(&mut out, i);
        }
        put_u32(&mut out, to_u32(self.change.len())?);
        for c in &self.change {
            put_u32(&mut out, c.output);
            put_u32(&mut out, parse_change_path(network, &c.path)?);
        }
        Ok(out)
    }

    /// The fee (prevouts minus outputs) and the total leaving the wallet
    /// (every output not in `change`, plus the fee).
    fn figures(&self, tx: &Transaction) -> Result<(u64, u64)> {
        let inputs = sum(self.prevouts.iter().map(|p| p.amount))?;
        let outputs = sum(tx.output.iter().map(|o| o.value.to_sat()))?;
        let fee = inputs
            .checked_sub(outputs)
            .ok_or_else(|| invalid("outputs exceed inputs"))?;
        let external = sum(tx
            .output
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.change.iter().any(|c| c.output as usize == *i))
            .map(|(_, o)| o.value.to_sat()))?;
        let leaving = external
            .checked_add(fee)
            .ok_or_else(|| invalid("amounts overflow"))?;
        Ok((fee, leaving))
    }
}

/// The change derivation path for `index` on `network`:
/// `m/86'/<coin>'/0'/1/<index>`, coin 0 on mainnet and 1 elsewhere.
pub fn change_path(network: Network, index: u32) -> String {
    format!("m/86'/{}'/0'/1/{index}", coin(network))
}

fn coin(network: Network) -> u32 {
    if network == Network::Mainnet {
        0
    } else {
        1
    }
}

/// The last step of a change path, which must be exactly
/// `m/86'/<coin>'/0'/1/<index>` for the network, with an unhardened index.
pub fn parse_change_path(network: Network, path: &str) -> Result<u32> {
    let prefix = format!("m/86'/{}'/0'/1/", coin(network));
    let index = path
        .strip_prefix(&prefix)
        .ok_or_else(|| invalid("a change path is not on this network's change chain"))?;
    let digits = !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit());
    if !digits || (index.len() > 1 && index.starts_with('0')) {
        return Err(invalid("a change path's index is not a plain number"));
    }
    let index: u32 = index
        .parse()
        .map_err(|_| invalid("change index out of range"))?;
    if index >= 0x8000_0000 {
        return Err(invalid("a change index must not be hardened"));
    }
    Ok(index)
}

fn sum(mut amounts: impl Iterator<Item = u64>) -> Result<u64> {
    amounts
        .try_fold(0u64, |a, b| a.checked_add(b))
        .ok_or_else(|| invalid("amounts overflow"))
}

fn strictly_ascending(list: &[u32], what: &str) -> Result<()> {
    if list.windows(2).all(|w| w[0] < w[1]) {
        Ok(())
    } else {
        Err(invalid(format!("{what} must be strictly ascending")))
    }
}

fn to_u32(n: usize) -> Result<u32> {
    u32::try_from(n).map_err(|_| malformed("count out of range"))
}

pub(crate) fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}

pub(crate) fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    put_u32(out, to_u32(bytes.len())?);
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::psbt::PsbtSighashType;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    pub fn sample_psbt() -> Psbt {
        let script = |b: u8| {
            let mut s = vec![0x51, 0x20];
            s.extend_from_slice(&[b; 32]);
            ScriptBuf::from_bytes(s)
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: (0..2u8)
                .map(|i| TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(
                            [i + 1; 32],
                        )),
                        vout: u32::from(i),
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![
                TxOut {
                    value: Amount::from_sat(30_000),
                    script_pubkey: script(0xaa),
                },
                TxOut {
                    value: Amount::from_sat(15_000),
                    script_pubkey: script(0xbb),
                },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: script(0x01),
        });
        psbt.inputs[1].witness_utxo = Some(TxOut {
            value: Amount::from_sat(6_000),
            script_pubkey: script(0x02),
        });
        psbt.inputs[1].sighash_type = Some(PsbtSighashType::from_u32(1));
        psbt
    }

    pub fn sample_payload() -> PsbtPayload {
        PsbtPayload::from_psbt(&sample_psbt(), &[1, 0], &[(1, 7)], Network::Mainnet).unwrap()
    }

    /// An input the gateway does not sign may spend anything, with any
    /// sighash: only signing inputs are pinned to taproot key path.
    #[test]
    fn an_input_not_signed_may_spend_anything() {
        let mut p = sample_payload();
        p.signing_inputs = vec![0];
        p.prevouts[1].script = vec![
            0x00, 0x14, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        ];
        p.sighash[1] = Some(0x83);
        assert!(p.check(Network::Mainnet).is_ok());
    }

    #[test]
    fn figures_are_recomputed() {
        let p = sample_payload();
        assert_eq!(p.signing_inputs, [0, 1]);
        assert_eq!(p.fee, 1_000);
        assert_eq!(p.leaving_wallet, 31_000);
        assert_eq!(p.change[0].path, "m/86'/0'/0'/1/7");
        let view = p.check(Network::Mainnet).unwrap();
        assert_eq!(view.outputs.len(), 2);
        assert!(view.outputs[0]
            .address
            .as_deref()
            .unwrap()
            .starts_with("bc1p"));
        assert_eq!(
            view.outputs[1].change_path.as_deref(),
            Some("m/86'/0'/0'/1/7")
        );
    }

    /// Every figure and list an approver checks, broken on its own, is
    /// refused.
    #[test]
    fn approver_checks_refuse_each_fault() {
        let good = sample_payload();
        type Break = Box<dyn Fn(&mut PsbtPayload)>;
        let cases: Vec<(&str, Break)> = vec![
            ("fee", Box::new(|p| p.fee += 1)),
            ("leaving", Box::new(|p| p.leaving_wallet -= 1)),
            (
                "prevout count",
                Box::new(|p| {
                    p.prevouts.pop();
                }),
            ),
            (
                "sighash count",
                Box::new(|p| {
                    p.sighash.pop();
                }),
            ),
            ("prevout amount", Box::new(|p| p.prevouts[0].amount += 1)),
            ("signing order", Box::new(|p| p.signing_inputs = vec![1, 0])),
            (
                "signing duplicate",
                Box::new(|p| p.signing_inputs = vec![0, 0]),
            ),
            ("signing range", Box::new(|p| p.signing_inputs = vec![0, 2])),
            ("nothing to sign", Box::new(|p| p.signing_inputs.clear())),
            ("sighash refused", Box::new(|p| p.sighash[1] = Some(0x83))),
            (
                "signing input not taproot",
                Box::new(|p| {
                    let mut wpkh = vec![0x00, 0x14];
                    wpkh.extend_from_slice(&[7; 20]);
                    p.prevouts[0].script = wpkh;
                }),
            ),
            (
                "signing input with a short taproot-looking script",
                Box::new(|p| p.prevouts[1].script.truncate(33)),
            ),
            (
                "unset sighash as a number",
                Box::new(|p| p.sighash[1] = Some(NO_SIGHASH)),
            ),
            (
                "unset sighash as a number on an input not signed",
                Box::new(|p| {
                    p.signing_inputs = vec![0];
                    p.sighash[1] = Some(NO_SIGHASH);
                }),
            ),
            ("change range", Box::new(|p| p.change[0].output = 2)),
            (
                "extra prevout",
                Box::new(|p| {
                    let extra = p.prevouts[0].clone();
                    p.prevouts.push(extra);
                }),
            ),
            (
                "extra sighash",
                Box::new(|p| {
                    p.sighash.push(None);
                }),
            ),
            (
                "change path network",
                Box::new(|p| p.change[0].path = "m/86'/1'/0'/1/7".into()),
            ),
            (
                "change path padded",
                Box::new(|p| p.change[0].path = "m/86'/0'/0'/1/07".into()),
            ),
            (
                "change path hardened",
                Box::new(|p| p.change[0].path = "m/86'/0'/0'/1/2147483648".into()),
            ),
            (
                "change duplicate",
                Box::new(|p| {
                    let c = p.change[0].clone();
                    p.change.push(c);
                }),
            ),
            ("tx", Box::new(|p| p.unsigned_tx.truncate(10))),
        ];
        assert!(good.check(Network::Mainnet).is_ok());
        for (name, break_it) in cases {
            let mut p = good.clone();
            break_it(&mut p);
            assert!(p.check(Network::Mainnet).is_err(), "{name} passed");
            assert!(p.binding_bytes(Network::Mainnet).is_err(), "{name} encoded");
        }
        // A sighash the signer refuses is fine on an input it does not sign.
        let mut p = good.clone();
        p.signing_inputs = vec![0];
        p.sighash[1] = Some(0x83);
        assert!(p.check(Network::Mainnet).is_ok());
        assert!(good.check(Network::Testnet4).is_err());
        // A change output one past the last, with figures that add up as if
        // it did not exist, is out of range.
        let mut p = good.clone();
        p.change = vec![ChangeOutput {
            output: 2,
            path: "m/86'/0'/0'/1/7".into(),
        }];
        p.leaving_wallet = 46_000;
        assert!(p.check(Network::Mainnet).is_err());
    }

    #[test]
    fn change_paths_are_strict() {
        assert_eq!(
            parse_change_path(Network::Signet, "m/86'/1'/0'/1/0").unwrap(),
            0
        );
        for bad in [
            "m/86'/1'/0'/1/",
            "m/86'/1'/0'/0/3",
            "m/86'/1'/0'/1/3'",
            "m/86'/1'/0'/1/+3",
            "M/86'/1'/0'/1/3",
        ] {
            assert!(parse_change_path(Network::Signet, bad).is_err(), "{bad}");
        }
    }
}
