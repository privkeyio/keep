// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! Destination and amount policy for co-signing a key-path spend.
//!
//! An unattended co-signer that approves key-path spends is deciding where the
//! group's money may go. Authorizing the *requester* cannot carry that decision:
//! a requester is always a share holder (the responder resolves it from the
//! sending pubkey and refuses a request whose participant set is not exactly the
//! threshold including the requester), so compromising a member yields both the
//! share and the identity any per-member rule would key on. This policy
//! therefore constrains the transaction, not the peer: where the money goes and
//! how much of it.
//!
//! Sound because a key-path spend request may only ask for `SIGHASH_DEFAULT` or
//! `SIGHASH_ALL`, which `verify_taproot_key_spend` enforces before this runs, so
//! the signature commits to every output. The outputs checked here are exactly
//! the outputs the signature authorizes.

use std::str::FromStr;

use bitcoin::{Amount, ScriptBuf};

use crate::structured_payload::BitcoinSighashPayload;

/// What an unattended co-signer will approve for a key-path spend.
///
/// The default refuses everything, matching
/// [`SigningHooks::approve_key_path_spend`](crate::SigningHooks::approve_key_path_spend).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeySpendPolicy {
    allowed_destinations: Vec<ScriptBuf>,
    max_consumed: Amount,
    max_fee: Amount,
}

/// What an approved spend moves: what the inputs supply and what the outputs
/// pay, so an operator of an unattended node can see what it co-signed rather
/// than only what it refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Approved {
    /// Everything the inputs supply, the outputs plus the fee.
    pub consumed: Amount,
    /// What the outputs pay to allowed destinations.
    pub paid: Amount,
    /// What is left for miners, the quantity `max_fee` bounds.
    pub fee: Amount,
    /// The unsigned transaction this spend signs an input of.
    ///
    /// One transaction with several of the group's inputs is several signing
    /// sessions over the same transaction, each reporting the same `consumed`,
    /// so anything accumulating across spends has to tell them apart from
    /// genuinely separate transactions. The txid is the identity that does it,
    /// and it is as authentic as the rest: it is computed from the unsigned
    /// transaction the digest commits to.
    pub txid: bitcoin::Txid,
}

impl KeySpendPolicy {
    /// Approve a spend only when every output pays one of
    /// `allowed_destinations` and the transaction consumes at most
    /// `max_consumed`.
    ///
    /// Consumed, not paid out: the cap covers what the inputs supply, which is
    /// the outputs plus the fee. Capping the outputs alone would leave the fee
    /// unbounded, and a spend paying one satoshi to an allowed destination and
    /// the rest of a large input to miners would pass a small cap while burning
    /// the group's funds. `keep-bitcoin`'s `leaving_wallet_sats` counts the fee
    /// for the same reason.
    ///
    /// Every output, not just the ones that look outbound: this co-signer
    /// cannot tell the group's change from a stranger's address without
    /// deriving the group's script for paths the request does not name, so an
    /// operator lists the change destination alongside the others. Change and a
    /// co-funder's input both count toward the total, which overstates what
    /// leaves the group and so errs toward refusing. Making the cap mean
    /// exactly "value leaving the group" needs change recognition.
    ///
    /// `max_fee` bounds the fee on its own, because `max_consumed` cannot. A
    /// cap that permits any real spend is at least the value of the inputs that
    /// spend consumes, and at that cap a request paying one satoshi to an
    /// allowed destination and the rest to miners is within the cap. So the
    /// split between what reaches the destinations and what the miners get
    /// needs its own bound.
    ///
    /// Any part left empty or zero refuses every spend. That is deliberate: the
    /// safe state is the default one, so a node configured with a partial
    /// policy signs nothing rather than anything.
    pub fn new(
        allowed_destinations: Vec<ScriptBuf>,
        max_consumed: Amount,
        max_fee: Amount,
    ) -> Self {
        Self {
            allowed_destinations,
            max_consumed,
            max_fee,
        }
    }

    /// Build from operator-supplied addresses, as a command line or config
    /// file gives them.
    ///
    /// Only the output script is ever compared, and a given witness program
    /// encodes to the same script on every network, so the address prefix
    /// carries no authority here and is not enforced against a configured
    /// network.
    pub fn from_addresses(
        addresses: &[String],
        max_consumed_sats: u64,
        max_fee_sats: u64,
    ) -> Result<Self, String> {
        let mut destinations = Vec::with_capacity(addresses.len());
        for address in addresses {
            let parsed = bitcoin::Address::from_str(address)
                .map_err(|e| format!("{address} is not an address: {e}"))?
                .assume_checked();
            destinations.push(parsed.script_pubkey());
        }
        Ok(Self::new(
            destinations,
            Amount::from_sat(max_consumed_sats),
            Amount::from_sat(max_fee_sats),
        ))
    }

    /// True when this policy cannot approve anything, so a caller can report
    /// "key-path spends refused" rather than describe a policy that is not one.
    pub fn refuses_everything(&self) -> bool {
        self.allowed_destinations.is_empty()
            || self.max_consumed == Amount::ZERO
            || self.max_fee == Amount::ZERO
    }

    /// `Ok` only if the request's own outputs satisfy the policy. The `Err` is
    /// a reason to log, not to return to the requester, which learns only that
    /// this co-signer declined.
    ///
    /// `structured_payload` is the request's payload, which the responder has
    /// already proven hashes to the digest being signed, so the PSBT read here
    /// is the transaction the signature will authorize.
    pub fn approve(&self, structured_payload: Option<&[u8]>) -> Result<Approved, String> {
        if self.allowed_destinations.is_empty() {
            return Err("no destination is allowed, so no key-path spend can be".into());
        }
        if self.max_consumed == Amount::ZERO {
            return Err("the spend cap is zero, so no key-path spend can be approved".into());
        }
        if self.max_fee == Amount::ZERO {
            return Err("the fee cap is zero, so no key-path spend can be approved".into());
        }
        let payload = structured_payload.ok_or_else(|| {
            "a key-path spend without its PSBT payload cannot be checked".to_owned()
        })?;
        let payload: BitcoinSighashPayload = serde_json::from_slice(payload)
            .map_err(|e| format!("bitcoin-sighash payload decode failed: {e}"))?;
        let psbt = bitcoin::Psbt::deserialize(&payload.psbt)
            .map_err(|e| format!("bitcoin-sighash payload PSBT decode failed: {e}"))?;

        // Everything below reads the outputs and the prevouts as authentic
        // because the digest commits to all of them, which holds only for these
        // two flags: ANYONECANPAY binds one input's amount, SINGLE and NONE
        // bind no outputs or only one. `verify_taproot_key_spend` already
        // refuses anything else ahead of this on the request path; repeated
        // here so this public method is sound wherever it is called from.
        if !matches!(payload.sighash_type, 0x00 | 0x01) {
            return Err(format!(
                "a key-path spend must use SIGHASH_DEFAULT or SIGHASH_ALL, not {:#x}",
                payload.sighash_type
            ));
        }

        let outputs = &psbt.unsigned_tx.output;
        if outputs.is_empty() {
            return Err("a spend with no outputs sends the whole input to fees".into());
        }
        if psbt.unsigned_tx.input.is_empty() {
            return Err("a spend with no inputs consumes nothing and signs nothing".into());
        }
        let mut paid = Amount::ZERO;
        for (i, out) in outputs.iter().enumerate() {
            if !self.allowed_destinations.contains(&out.script_pubkey) {
                return Err(format!(
                    "output {i} pays {}, which is not an allowed destination",
                    out.script_pubkey
                ));
            }
            // Checked: a hostile payload can name output values summing past
            // u64, and a wrapping total would read as a small spend.
            paid = paid
                .checked_add(out.value)
                .ok_or_else(|| "the output total overflows".to_owned())?;
        }

        // The signature commits to every input's prevout under
        // `SIGHASH_DEFAULT`/`ALL`, and the digest was recomputed from exactly
        // these prevouts, so they are as authentic as the outputs. The count
        // check keeps this sound when called outside that path.
        if payload.prevouts.len() != psbt.unsigned_tx.input.len() {
            return Err(format!(
                "the payload carries {} prevouts for {} inputs",
                payload.prevouts.len(),
                psbt.unsigned_tx.input.len()
            ));
        }
        let mut consumed = Amount::ZERO;
        for (i, prevout) in payload.prevouts.iter().enumerate() {
            let prevout = bitcoin::consensus::deserialize::<bitcoin::TxOut>(prevout)
                .map_err(|e| format!("prevout {i} decode failed: {e}"))?;
            consumed = consumed
                .checked_add(prevout.value)
                .ok_or_else(|| "the input total overflows".to_owned())?;
        }
        // `Amount`'s `Sub` panics on underflow, so the fee is taken with
        // `checked_sub` rather than relying on this refusal staying above it.
        // Outputs paying more than the inputs supply is consensus-invalid, so
        // no honest request looks like this.
        let fee = consumed.checked_sub(paid).ok_or_else(|| {
            format!(
                "the outputs pay {} sats from {} sats of inputs, which cannot be signed",
                paid.to_sat(),
                consumed.to_sat()
            )
        })?;

        // Satoshis, not `Amount`'s BTC rendering, so these read in the unit the
        // operator configured on the command line.
        if consumed > self.max_consumed {
            return Err(format!(
                "the spend consumes {} sats ({} sats to destinations, {} sats in fees), over the {} sats cap",
                consumed.to_sat(),
                paid.to_sat(),
                fee.to_sat(),
                self.max_consumed.to_sat()
            ));
        }
        if fee > self.max_fee {
            return Err(format!(
                "the spend leaves {} sats in fees, over the {} sats fee cap, paying {} sats of {} sats consumed",
                fee.to_sat(),
                self.max_fee.to_sat(),
                paid.to_sat(),
                consumed.to_sat()
            ));
        }
        Ok(Approved {
            consumed,
            paid,
            fee,
            txid: psbt.unsigned_tx.compute_txid(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Psbt, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    fn spk(b: u8) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
            bitcoin::secp256k1::Keypair::from_seckey_slice(
                &bitcoin::secp256k1::Secp256k1::new(),
                &[b; 32],
            )
            .unwrap()
            .x_only_public_key()
            .0,
        ))
    }

    /// A payload whose transaction pays `outputs`, shaped like the one a
    /// key-path spend request carries. The input is sized to the outputs plus a
    /// 1 000 sat fee, so a case that is meant to be approved is not refused for
    /// consuming more than it pays.
    fn payload(outputs: &[(ScriptBuf, u64)]) -> Vec<u8> {
        let paid = outputs
            .iter()
            .fold(0u64, |acc, (_, sats)| acc.saturating_add(*sats));
        payload_spending(paid.saturating_add(1_000), outputs)
    }

    /// As [`payload`], with the input's value chosen so a test can set the fee
    /// (what the inputs supply minus what the outputs pay).
    fn payload_spending(input_sats: u64, outputs: &[(ScriptBuf, u64)]) -> Vec<u8> {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([1; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: outputs
                .iter()
                .map(|(script_pubkey, sats)| TxOut {
                    value: Amount::from_sat(*sats),
                    script_pubkey: script_pubkey.clone(),
                })
                .collect(),
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(input_sats),
            script_pubkey: spk(9),
        });
        serde_json::to_vec(&BitcoinSighashPayload {
            psbt: psbt.serialize(),
            input_index: 0,
            sighash_type: 0,
            prevouts: vec![bitcoin::consensus::serialize(&TxOut {
                value: Amount::from_sat(input_sats),
                script_pubkey: spk(9),
            })],
        })
        .unwrap()
    }

    /// Allows two destinations, 100 000 sats consumed and 2 000 sats of fee.
    fn policy() -> KeySpendPolicy {
        KeySpendPolicy::new(
            vec![spk(1), spk(2)],
            Amount::from_sat(100_000),
            Amount::from_sat(2_000),
        )
    }

    /// The txid of the transaction a payload carries. It computes the same way
    /// the code does, so on its own it only rules out a constant or the wrong
    /// PSBT; the property it exists to support is pinned by
    /// `the_txid_identifies_the_transaction_not_the_digest` below.
    fn payload_txid(payload: &[u8]) -> bitcoin::Txid {
        let parsed: BitcoinSighashPayload = serde_json::from_slice(payload).unwrap();
        Psbt::deserialize(&parsed.psbt)
            .unwrap()
            .unsigned_tx
            .compute_txid()
    }

    #[test]
    fn a_spend_to_allowed_destinations_within_the_cap_is_approved() {
        let p = payload(&[(spk(1), 60_000), (spk(2), 30_000)]);
        assert_eq!(
            policy().approve(Some(&p)),
            Ok(Approved {
                consumed: Amount::from_sat(91_000),
                paid: Amount::from_sat(90_000),
                fee: Amount::from_sat(1_000),
                txid: payload_txid(&p),
            }),
            "the amounts reported back are what the node logs as co-signed"
        );
    }

    // The destination is the whole point: an output to anywhere unlisted is
    // refused even when the amount is trivial, because an unattended co-signer
    // has nothing else standing between a compromised member and the funds.
    #[test]
    fn one_output_to_an_unlisted_destination_refuses_the_whole_spend() {
        let p = payload(&[(spk(1), 10), (spk(3), 1)]);
        let err = policy().approve(Some(&p)).unwrap_err();
        assert!(err.contains("output 1"), "{err}");
        assert!(err.contains("not an allowed destination"), "{err}");
    }

    #[test]
    fn a_spend_over_the_cap_is_refused_even_to_allowed_destinations() {
        let p = payload(&[(spk(1), 70_000), (spk(2), 40_000)]);
        let err = policy().approve(Some(&p)).unwrap_err();
        assert!(err.contains("over the"), "{err}");
    }

    // Exactly at the cap, fee included, is approved: the bound is on what the
    // spend consumes, so the payment has to leave room for the fee.
    #[test]
    fn the_cap_is_inclusive() {
        let p = payload_spending(100_000, &[(spk(1), 99_000)]);
        assert_eq!(
            policy().approve(Some(&p)),
            Ok(Approved {
                consumed: Amount::from_sat(100_000),
                paid: Amount::from_sat(99_000),
                fee: Amount::from_sat(1_000),
                txid: payload_txid(&p),
            })
        );
        let over = payload_spending(100_001, &[(spk(1), 99_000)]);
        assert!(policy().approve(Some(&over)).is_err());
    }

    // `fee = consumed - paid` is only exact if `paid` is the true sum over
    // outputs, so pin the two shapes that could perturb it: two outputs to one
    // allowed destination must count twice, and a zero-value output must count
    // as nothing. A refactor that grouped outputs by script would break the
    // first and silently understate the fee.
    #[test]
    fn paid_sums_every_output_including_duplicates_and_zero_values() {
        let duplicated = payload_spending(91_000, &[(spk(1), 40_000), (spk(1), 50_000)]);
        assert_eq!(
            policy().approve(Some(&duplicated)),
            Ok(Approved {
                consumed: Amount::from_sat(91_000),
                paid: Amount::from_sat(90_000),
                fee: Amount::from_sat(1_000),
                txid: payload_txid(&duplicated),
            }),
            "two outputs to one destination pay the sum of both"
        );

        let with_zero = payload_spending(91_000, &[(spk(1), 90_000), (spk(2), 0)]);
        assert_eq!(
            policy().approve(Some(&with_zero)),
            Ok(Approved {
                consumed: Amount::from_sat(91_000),
                paid: Amount::from_sat(90_000),
                fee: Amount::from_sat(1_000),
                txid: payload_txid(&with_zero),
            }),
            "a zero-value output moves nothing in either direction"
        );
    }

    // What the dedupe in the rolling window rests on, asserted rather than left
    // in prose: the txid identifies the transaction, so it changes when the
    // transaction does and does NOT change with the sighash type, which alters
    // the digest but not the transaction. If the sighash type moved it, two
    // requests for one transaction would look like two spends; if the funding
    // output did not, two transactions would look like one and the second would
    // ride in free.
    #[test]
    fn the_txid_identifies_the_transaction_not_the_digest() {
        let payload_of = |sighash_type, vout| {
            crate::test_support::key_spend_payload_of(&spk(1), sighash_type, vout).1
        };
        assert_eq!(
            payload_txid(&payload_of(0x00, 0)),
            payload_txid(&payload_of(0x01, 0)),
            "the sighash type changes the digest, not the transaction"
        );
        assert_ne!(
            payload_txid(&payload_of(0x00, 0)),
            payload_txid(&payload_of(0x00, 1)),
            "a different funding output is a different transaction"
        );
    }

    // Operator input is addresses, and a given witness program is the same
    // script whichever network prefix encodes it, so a policy written with a
    // testnet address still matches the mainnet output for that program. That
    // is what the operator named, but it is worth pinning so the behavior is a
    // decision and not an accident.
    #[test]
    fn addresses_parse_to_scripts_and_the_network_prefix_is_not_part_of_the_match() {
        let program = spk(5);
        let encode = |network| {
            bitcoin::Address::from_script(&program, network)
                .unwrap()
                .to_string()
        };
        let from_mainnet =
            KeySpendPolicy::from_addresses(&[encode(bitcoin::Network::Bitcoin)], 10_000, 1_000)
                .unwrap();
        let from_testnet =
            KeySpendPolicy::from_addresses(&[encode(bitcoin::Network::Testnet)], 10_000, 1_000)
                .unwrap();
        assert_eq!(
            from_mainnet, from_testnet,
            "the same witness program must give the same policy"
        );
        assert_eq!(
            from_mainnet,
            KeySpendPolicy::new(
                vec![program],
                Amount::from_sat(10_000),
                Amount::from_sat(1_000)
            ),
            "an address must resolve to exactly its output script"
        );

        let err = KeySpendPolicy::from_addresses(&["not-an-address".to_owned()], 10_000, 1_000)
            .unwrap_err();
        assert!(err.contains("not an address"), "{err}");
    }

    // The attack the output-only cap allowed: pay one satoshi to an allowed
    // destination and leave the rest of a large input to miners. Capping what
    // the outputs pay would read this as a 1 sat spend and approve it while the
    // group loses the whole UTXO to fees.
    #[test]
    fn a_fee_burn_is_refused_however_small_the_payment_is() {
        let p = payload_spending(10_000_000, &[(spk(1), 1)]);
        let err = policy().approve(Some(&p)).unwrap_err();
        assert!(err.contains("consumes"), "{err}");
        assert!(err.contains("in fees"), "{err}");

        // The same transaction is fine once the cap covers what it consumes.
        let generous = KeySpendPolicy::new(
            vec![spk(1)],
            Amount::from_sat(10_000_000),
            Amount::from_sat(10_000_000),
        );
        assert_eq!(
            generous.approve(Some(&p)),
            Ok(Approved {
                consumed: Amount::from_sat(10_000_000),
                paid: Amount::from_sat(1),
                fee: Amount::from_sat(9_999_999),
                txid: payload_txid(&p),
            }),
            "the operator asked for this, and the log says what it cost"
        );
    }

    // The cap is on what the inputs supply, so the fee counts and a spend that
    // pays out under the cap can still exceed it. Asserted in satoshis: an
    // earlier version matched on "90000", which `Amount`'s BTC-denominated
    // Display satisfies with "0.00090000" for any magnitude, so it could not
    // tell 90 000 from 900 000 and proved almost nothing.
    #[test]
    fn the_cap_covers_the_outputs_plus_the_fee() {
        let p = payload_spending(150_000, &[(spk(1), 90_000)]);
        let err = policy().approve(Some(&p)).unwrap_err();
        assert!(err.contains("consumes 150000 sats"), "{err}");
        assert!(err.contains("90000 sats to destinations"), "{err}");
        assert!(err.contains("60000 sats in fees"), "{err}");
    }

    // The fee needs its own bound, because the consumed cap cannot carry it: a
    // cap that permits any real spend is at least the inputs that spend
    // consumes, and at that cap this request is inside it. 99 999 of a 100 000
    // sat input to miners, 1 sat to an allowed destination.
    #[test]
    fn a_fee_burn_inside_the_consumed_cap_is_still_refused() {
        let p = payload_spending(100_000, &[(spk(1), 1)]);
        let err = policy().approve(Some(&p)).unwrap_err();
        assert!(err.contains("99999 sats in fees"), "{err}");
        assert!(err.contains("2000 sats fee cap"), "{err}");

        // The same spend is approved once the operator allows that fee.
        let tolerant = KeySpendPolicy::new(
            vec![spk(1)],
            Amount::from_sat(100_000),
            Amount::from_sat(99_999),
        );
        assert_eq!(
            tolerant.approve(Some(&p)),
            Ok(Approved {
                consumed: Amount::from_sat(100_000),
                paid: Amount::from_sat(1),
                fee: Amount::from_sat(99_999),
                txid: payload_txid(&p),
            })
        );
    }

    // Outputs paying more than the inputs supply is consensus-invalid, and the
    // refusal is what keeps the fee subtraction from underflowing: `Amount`'s
    // `Sub` panics, so without `checked_sub` this would be a remote panic in
    // the request handler of an unattended node.
    #[test]
    fn outputs_paying_more_than_the_inputs_supply_are_refused_not_panicked_on() {
        let p = payload_spending(50_000, &[(spk(1), 90_000)]);
        let err = policy().approve(Some(&p)).unwrap_err();
        assert!(err.contains("cannot be signed"), "{err}");
        assert!(err.contains("90000 sats from 50000 sats"), "{err}");
    }

    // Both totals are only authentic under the two flags that bind every input
    // and output. `verify_taproot_key_spend` enforces this ahead of the policy
    // on the request path, but `approve` is public, so it does not assume it.
    #[test]
    fn a_sighash_type_that_does_not_bind_every_input_and_output_is_refused() {
        let mut parsed: BitcoinSighashPayload =
            serde_json::from_slice(&payload(&[(spk(1), 1_000)])).unwrap();
        for sighash_type in [0x02, 0x03, 0x81, 0x82, 0x83] {
            parsed.sighash_type = sighash_type;
            let p = serde_json::to_vec(&parsed).unwrap();
            let err = policy().approve(Some(&p)).unwrap_err();
            assert!(err.contains("SIGHASH_DEFAULT or SIGHASH_ALL"), "{err}");
        }
    }

    // The input total has its own overflow guard, reachable only with more than
    // one input, so the single-input fixture never exercised it.
    #[test]
    fn an_input_total_that_overflows_is_refused() {
        let mut parsed: BitcoinSighashPayload =
            serde_json::from_slice(&payload(&[(spk(1), 1_000)])).unwrap();
        let huge = bitcoin::consensus::serialize(&TxOut {
            value: Amount::from_sat(u64::MAX),
            script_pubkey: spk(9),
        });
        parsed.prevouts = vec![huge.clone(), huge];
        let mut psbt = Psbt::deserialize(&parsed.psbt).unwrap();
        let input = psbt.unsigned_tx.input[0].clone();
        psbt.unsigned_tx.input.push(input);
        let first = psbt.inputs[0].clone();
        psbt.inputs.push(first);
        parsed.psbt = psbt.serialize();
        let p = serde_json::to_vec(&parsed).unwrap();
        let err = policy().approve(Some(&p)).unwrap_err();
        assert!(err.contains("input total overflows"), "{err}");
    }

    // Prevouts are authentic (the digest was recomputed from them) but their
    // count must match the inputs, or a payload could hide an input's value
    // from the total.
    #[test]
    fn a_prevout_count_that_does_not_match_the_inputs_is_refused() {
        let mut payload: BitcoinSighashPayload =
            serde_json::from_slice(&payload(&[(spk(1), 1_000)])).unwrap();
        payload.prevouts.clear();
        let p = serde_json::to_vec(&payload).unwrap();
        let err = policy().approve(Some(&p)).unwrap_err();
        assert!(err.contains("prevouts for"), "{err}");
    }

    // A partial policy signs nothing. An operator who names destinations but
    // no cap, or either cap without destinations, gets the default refusal
    // rather than the permissive reading of whatever is missing.
    #[test]
    fn a_policy_missing_any_part_refuses_everything() {
        let p = payload(&[(spk(1), 1)]);
        let no_destinations = KeySpendPolicy::new(
            Vec::new(),
            Amount::from_sat(100_000),
            Amount::from_sat(2_000),
        );
        let no_cap = KeySpendPolicy::new(vec![spk(1)], Amount::ZERO, Amount::from_sat(2_000));
        let no_fee_cap = KeySpendPolicy::new(vec![spk(1)], Amount::from_sat(100_000), Amount::ZERO);
        assert!(no_destinations.refuses_everything());
        assert!(no_cap.refuses_everything());
        assert!(no_fee_cap.refuses_everything());
        assert!(no_destinations.approve(Some(&p)).is_err());
        assert!(no_cap.approve(Some(&p)).is_err());
        assert!(no_fee_cap.approve(Some(&p)).is_err());
        assert!(KeySpendPolicy::default().refuses_everything());
        assert!(KeySpendPolicy::default().approve(Some(&p)).is_err());
        assert!(!policy().refuses_everything());
    }

    // A key-path spend always carries a PSBT (protocol validation requires it),
    // so a missing or undecodable one is a malformed request, never a reason to
    // sign.
    #[test]
    fn a_missing_or_undecodable_payload_is_refused() {
        assert!(policy().approve(None).is_err());
        assert!(policy().approve(Some(b"{}")).is_err());
        let garbage = serde_json::to_vec(&BitcoinSighashPayload {
            psbt: vec![0xff; 8],
            input_index: 0,
            sighash_type: 0,
            prevouts: Vec::new(),
        })
        .unwrap();
        assert!(policy().approve(Some(&garbage)).is_err());
    }

    // Every sat of the input would go to miners. Nothing reaches an allowed
    // destination, so the output loop never runs and the cap is never consulted.
    #[test]
    fn a_spend_with_no_outputs_is_refused() {
        let p = payload(&[]);
        let err = policy().approve(Some(&p)).unwrap_err();
        assert!(err.contains("no outputs"), "{err}");
    }

    // A hostile payload can name values that sum past u64, and the dangerous
    // pair is the one that wraps to a SMALL total: u64::MAX + 1 is 0, which a
    // wrapping add reads as comfortably within the cap. Two maxima would wrap
    // to u64::MAX - 1 and still trip the cap, so they prove nothing here.
    #[test]
    fn an_output_total_that_overflows_is_refused() {
        let p = payload(&[(spk(1), u64::MAX), (spk(2), 1)]);
        let err = policy().approve(Some(&p)).unwrap_err();
        assert!(err.contains("overflows"), "{err}");
    }
}
