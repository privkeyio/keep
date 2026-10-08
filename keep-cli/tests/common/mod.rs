// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Helpers shared by the CLI test binaries.
#![allow(dead_code)]

use std::path::Path;
use std::process::Output;

/// A PSBT spending the FROST group's BIP-86 outputs at `paths` (100 000 sats
/// each) plus one foreign input, paying 30 000 sats away and 69 000 to the
/// group's change address `/1/5`, with the key origins a watch-only wallet adds.
pub fn frost_wallet_psbt(group: &[u8; 32], paths: &[[u32; 2]]) -> bitcoin::Psbt {
    use bitcoin::bip32::{DerivationPath, Fingerprint};
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use keep_core::frost::taproot::{internal_key, TaprootTweak};
    use std::str::FromStr;

    let fp =
        Fingerprint::from_str(&keep_bitcoin::DescriptorExport::pubkey_fingerprint(group)).unwrap();
    let child = |path: [u32; 2]| {
        let internal = internal_key(group, &path).unwrap();
        let origin = (
            bitcoin::XOnlyPublicKey::from_slice(&internal).unwrap(),
            (
                vec![],
                (
                    fp,
                    DerivationPath::from_str(&format!("86'/1'/0'/{}/{}", path[0], path[1]))
                        .unwrap(),
                ),
            ),
        );
        (
            TaprootTweak::default().script_pubkey(&internal).unwrap(),
            origin,
        )
    };
    let foreign = {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (k, _) = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &[9u8; 32])
            .unwrap()
            .x_only_public_key();
        ScriptBuf::new_p2tr(&secp, k, None)
    };
    let (change_spk, change_origin) = child([1, 5]);
    let n = paths.len() + 1;
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: (0..n as u32)
            .map(|vout| TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([5; 32]), vout),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![
            TxOut {
                value: Amount::from_sat(30_000),
                script_pubkey: foreign.clone(),
            },
            TxOut {
                value: Amount::from_sat(69_000),
                script_pubkey: change_spk,
            },
        ],
    };
    let mut psbt = bitcoin::Psbt::from_unsigned_tx(tx).unwrap();
    for (i, path) in paths.iter().enumerate() {
        let (spk, (key, origin)) = child(*path);
        psbt.inputs[i].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: spk,
        });
        psbt.inputs[i].tap_internal_key = Some(key);
        psbt.inputs[i].tap_key_origins.insert(key, origin);
    }
    psbt.inputs[n - 1].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: foreign,
    });
    psbt.outputs[1]
        .tap_key_origins
        .insert(change_origin.0, change_origin.1);
    psbt
}

/// Every input with a `tap_key_sig` verifies under the output key it spends,
/// with the BIP-341 sighash over every prevout; returns the signed indexes.
pub fn signed_key_path_inputs(psbt: &bitcoin::Psbt) -> Vec<usize> {
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{Prevouts, SighashCache};
    let prevouts: Vec<_> = psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().unwrap())
        .collect();
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    psbt.inputs
        .iter()
        .enumerate()
        .filter_map(|(i, input)| {
            let sig = input.tap_key_sig?;
            let sighash = cache
                .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), sig.sighash_type)
                .unwrap();
            let spk = &prevouts[i].script_pubkey;
            let key = bitcoin::XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34]).unwrap();
            secp.verify_schnorr(
                &sig.signature,
                &bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array()),
                &key,
            )
            .unwrap_or_else(|e| panic!("input {i} does not verify under its output key: {e}"));
            Some(i)
        })
        .collect()
}

pub fn write_psbt(path: &Path, psbt: &bitcoin::Psbt) {
    std::fs::write(
        path,
        bitcoin::base64::Engine::encode(
            &bitcoin::base64::engine::general_purpose::STANDARD,
            psbt.serialize(),
        ),
    )
    .unwrap();
}

pub fn read_psbt(path: &Path) -> bitcoin::Psbt {
    let data = std::fs::read_to_string(path).unwrap();
    let bytes = bitcoin::base64::Engine::decode(
        &bitcoin::base64::engine::general_purpose::STANDARD,
        data.trim(),
    )
    .unwrap();
    bitcoin::Psbt::deserialize(&bytes).unwrap()
}

pub fn npub_in(output: &Output) -> String {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .find(|w| w.starts_with("npub1") && w.len() == 63)
        .expect("a group npub in the output")
        .to_string()
}
