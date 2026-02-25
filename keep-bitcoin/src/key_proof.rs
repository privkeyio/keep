// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::Signature as TaprootSignature;
use bitcoin::{
    absolute::LockTime, transaction::Version, Address, Amount, Network, OutPoint, ScriptBuf,
    Sequence, Transaction, Txid, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use zeroize::Zeroize;

use crate::error::{BitcoinError, Result};

const PROOF_DOMAIN: &[u8] = b"keep-key-proof/v1";
const INPUT_SATS: u64 = 1000;
const OUTPUT_SATS: u64 = 546;

fn derive_proof_txid(session_id: &[u8; 32], share_index: u16) -> Txid {
    let mut engine = sha256::HashEngine::default();
    engine.input(PROOF_DOMAIN);
    engine.input(session_id);
    engine.input(&share_index.to_le_bytes());
    let hash = sha256::Hash::from_engine(engine);
    let bytes = hash.to_byte_array();
    Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(bytes))
}

fn derive_child_xonly(account_xpub: &str) -> Result<XOnlyPublicKey> {
    let secp = Secp256k1::new();
    let xpub = Xpub::from_str(account_xpub)
        .map_err(|e| BitcoinError::InvalidPsbt(format!("invalid xpub: {e}")))?;
    let child = xpub
        .derive_pub(
            &secp,
            &[
                ChildNumber::Normal { index: 0 },
                ChildNumber::Normal { index: 0 },
            ],
        )
        .map_err(|e| BitcoinError::InvalidPsbt(format!("xpub derivation: {e}")))?;
    Ok(child.to_x_only_pub())
}

pub fn build_key_proof_psbt(
    session_id: &[u8; 32],
    share_index: u16,
    account_xpub: &str,
    network: Network,
) -> Result<Psbt> {
    let secp = Secp256k1::new();
    let x_only = derive_child_xonly(account_xpub)?;
    let txid = derive_proof_txid(session_id, share_index);
    let address = Address::p2tr(&secp, x_only, None, network);
    let script_pubkey = address.script_pubkey();

    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(OUTPUT_SATS),
            script_pubkey: script_pubkey.clone(),
        }],
    };

    let mut psbt =
        Psbt::from_unsigned_tx(tx).map_err(|e| BitcoinError::InvalidPsbt(e.to_string()))?;

    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(INPUT_SATS),
        script_pubkey,
    });
    psbt.inputs[0].tap_internal_key = Some(x_only);

    Ok(psbt)
}

pub fn sign_key_proof(
    psbt: &mut Psbt,
    signing_secret: &[u8; 32],
    network: Network,
) -> Result<Vec<u8>> {
    let secp = Secp256k1::new();
    let coin_type = if network == Network::Bitcoin { 0 } else { 1 };
    let path = DerivationPath::from_str(&format!("m/86'/{coin_type}'/0'/0/0"))
        .map_err(|e| BitcoinError::Signing(format!("derivation path: {e}")))?;

    let master = Xpriv::new_master(network, signing_secret)
        .map_err(|e| BitcoinError::Signing(format!("master key: {e}")))?;
    let child = master
        .derive_priv(&secp, &path)
        .map_err(|e| BitcoinError::Signing(format!("child derivation: {e}")))?;
    let mut child_bytes = child.private_key.secret_bytes();
    let keypair = Keypair::from_seckey_slice(&secp, &child_bytes)
        .map_err(|e| BitcoinError::Signing(e.to_string()))?;
    child_bytes.zeroize();

    let prevouts = vec![psbt.inputs[0]
        .witness_utxo
        .clone()
        .ok_or(BitcoinError::MissingWitnessUtxo(0))?];
    let prevouts_ref = Prevouts::All(&prevouts);

    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(0, &prevouts_ref, TapSighashType::Default)
        .map_err(|e| BitcoinError::Sighash(e.to_string()))?;

    let msg = Message::from_digest_slice(sighash.as_ref())
        .map_err(|e| BitcoinError::Signing(e.to_string()))?;

    let aux_rand = crate::aux_rand()?;
    let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);

    psbt.inputs[0].tap_key_sig = Some(TaprootSignature {
        signature: sig,
        sighash_type: TapSighashType::Default,
    });

    Ok(psbt.serialize())
}

pub fn verify_key_proof(
    session_id: &[u8; 32],
    share_index: u16,
    account_xpub: &str,
    signed_psbt_bytes: &[u8],
    network: Network,
) -> Result<()> {
    let secp = Secp256k1::new();
    let expected_psbt = build_key_proof_psbt(session_id, share_index, account_xpub, network)?;

    let signed_psbt = Psbt::deserialize(signed_psbt_bytes)
        .map_err(|e| BitcoinError::InvalidPsbt(format!("key proof PSBT: {e}")))?;

    if signed_psbt.unsigned_tx != expected_psbt.unsigned_tx {
        return Err(BitcoinError::InvalidPsbt(
            "key proof transaction mismatch".into(),
        ));
    }

    let tap_sig = signed_psbt.inputs[0]
        .tap_key_sig
        .ok_or_else(|| BitcoinError::InvalidPsbt("key proof missing signature".into()))?;

    let x_only = derive_child_xonly(account_xpub)?;

    let prevouts = vec![expected_psbt.inputs[0]
        .witness_utxo
        .clone()
        .ok_or(BitcoinError::MissingWitnessUtxo(0))?];
    let prevouts_ref = Prevouts::All(&prevouts);

    let mut sighash_cache = SighashCache::new(&expected_psbt.unsigned_tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(0, &prevouts_ref, TapSighashType::Default)
        .map_err(|e| BitcoinError::Sighash(e.to_string()))?;

    let msg = Message::from_digest_slice(sighash.as_ref())
        .map_err(|e| BitcoinError::Signing(e.to_string()))?;

    secp.verify_schnorr(&tap_sig.signature, &msg, &x_only)
        .map_err(|_| BitcoinError::InvalidPsbt("key proof signature verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_xpub(secret: &[u8; 32], network: Network) -> (String, [u8; 32]) {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(network, secret).unwrap();
        let coin_type = if network == Network::Bitcoin { 0 } else { 1 };
        let path = DerivationPath::from_str(&format!("m/86'/{coin_type}'/0'")).unwrap();
        let account = master.derive_priv(&secp, &path).unwrap();
        let xpub = Xpub::from_priv(&secp, &account);
        (xpub.to_string(), *secret)
    }

    #[test]
    fn test_deterministic() {
        let session_id = [1u8; 32];
        let secret = [42u8; 32];
        let (xpub, _) = test_xpub(&secret, Network::Testnet);

        let psbt1 = build_key_proof_psbt(&session_id, 1, &xpub, Network::Testnet).unwrap();
        let psbt2 = build_key_proof_psbt(&session_id, 1, &xpub, Network::Testnet).unwrap();

        assert_eq!(psbt1.serialize(), psbt2.serialize());
    }

    #[test]
    fn test_different_session_id() {
        let secret = [42u8; 32];
        let (xpub, _) = test_xpub(&secret, Network::Testnet);

        let psbt1 = build_key_proof_psbt(&[1u8; 32], 1, &xpub, Network::Testnet).unwrap();
        let psbt2 = build_key_proof_psbt(&[2u8; 32], 1, &xpub, Network::Testnet).unwrap();

        assert_ne!(
            psbt1.unsigned_tx.input[0].previous_output.txid,
            psbt2.unsigned_tx.input[0].previous_output.txid
        );
    }

    #[test]
    fn test_different_share_index() {
        let session_id = [1u8; 32];
        let secret = [42u8; 32];
        let (xpub, _) = test_xpub(&secret, Network::Testnet);

        let psbt1 = build_key_proof_psbt(&session_id, 1, &xpub, Network::Testnet).unwrap();
        let psbt2 = build_key_proof_psbt(&session_id, 2, &xpub, Network::Testnet).unwrap();

        assert_ne!(
            psbt1.unsigned_tx.input[0].previous_output.txid,
            psbt2.unsigned_tx.input[0].previous_output.txid
        );
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let session_id = [7u8; 32];
        let secret = [42u8; 32];
        let share_index = 3;
        let (xpub, _) = test_xpub(&secret, Network::Testnet);

        let mut psbt =
            build_key_proof_psbt(&session_id, share_index, &xpub, Network::Testnet).unwrap();
        let signed_bytes = sign_key_proof(&mut psbt, &secret, Network::Testnet).unwrap();

        verify_key_proof(&session_id, share_index, &xpub, &signed_bytes, Network::Testnet)
            .unwrap();
    }

    #[test]
    fn test_verify_wrong_session_id() {
        let secret = [42u8; 32];
        let (xpub, _) = test_xpub(&secret, Network::Testnet);

        let mut psbt = build_key_proof_psbt(&[1u8; 32], 1, &xpub, Network::Testnet).unwrap();
        let signed_bytes = sign_key_proof(&mut psbt, &secret, Network::Testnet).unwrap();

        let result = verify_key_proof(&[2u8; 32], 1, &xpub, &signed_bytes, Network::Testnet);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_xpub() {
        let session_id = [1u8; 32];
        let secret1 = [42u8; 32];
        let secret2 = [43u8; 32];
        let (xpub1, _) = test_xpub(&secret1, Network::Testnet);
        let (xpub2, _) = test_xpub(&secret2, Network::Testnet);

        let mut psbt = build_key_proof_psbt(&session_id, 1, &xpub1, Network::Testnet).unwrap();
        let signed_bytes = sign_key_proof(&mut psbt, &secret1, Network::Testnet).unwrap();

        let result = verify_key_proof(&session_id, 1, &xpub2, &signed_bytes, Network::Testnet);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_tampered_signature() {
        let session_id = [1u8; 32];
        let secret = [42u8; 32];
        let (xpub, _) = test_xpub(&secret, Network::Testnet);

        let mut psbt = build_key_proof_psbt(&session_id, 1, &xpub, Network::Testnet).unwrap();
        let mut signed_bytes = sign_key_proof(&mut psbt, &secret, Network::Testnet).unwrap();

        let last = signed_bytes.len() - 1;
        signed_bytes[last] ^= 0xFF;

        let result = verify_key_proof(&session_id, 1, &xpub, &signed_bytes, Network::Testnet);
        assert!(result.is_err());
    }

    #[test]
    fn test_mainnet() {
        let session_id = [5u8; 32];
        let secret = [42u8; 32];
        let (xpub, _) = test_xpub(&secret, Network::Bitcoin);

        let mut psbt =
            build_key_proof_psbt(&session_id, 1, &xpub, Network::Bitcoin).unwrap();
        let signed_bytes = sign_key_proof(&mut psbt, &secret, Network::Bitcoin).unwrap();

        verify_key_proof(&session_id, 1, &xpub, &signed_bytes, Network::Bitcoin).unwrap();
    }
}
