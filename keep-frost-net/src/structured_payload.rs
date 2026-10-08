// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Structured payload verification for FROST sign requests (#529).
//!
//! `SignRequestPayload::structured_payload` carries a typed body whose schema
//! is keyed by `message_type`. The responder decodes it, recomputes the
//! 32-byte digest that would result from that structured body, and refuses
//! the request if the recomputed digest does not match the `message` field.
//!
//! This closes the label-spoofing threat that motivated #524: a caller
//! authorized to request nostr-event signatures cannot get a Bitcoin taproot
//! sighash blind-signed by relabeling it as `nostr-event`, because the
//! Nostr-canonical hash of the supplied event body would not equal the
//! sighash bytes. The signature itself is still over `message` verbatim, so
//! honest requests remain verifier-compatible at Nostr relays and Bitcoin
//! full nodes.
//!
//! Unknown or unstructured (`raw`) message types have no recompute path here;
//! operators of hybrid groups gate them via [`crate::RefuseRawSignatureHooks`]
//! and (once presence is required) [`crate::RequireStructuredPayloadHooks`].

use crate::{FrostNetError, Result, MSG_TYPE_BITCOIN_SIGHASH, MSG_TYPE_NOSTR_EVENT};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Psbt, TxOut};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Structured payload for a `nostr-event` signing request. Every field
/// contributes to the NIP-01 event id serialization, so recomputing
/// `sha256([0, pubkey_hex, created_at, kind, tags, content])` and comparing
/// to the request's 32-byte digest proves the label matches the body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NostrEventPayload {
    /// Author pubkey (x-only 32 bytes, hex on the wire).
    #[serde(with = "hex_32")]
    pub pubkey: [u8; 32],
    /// Event creation timestamp (Unix seconds).
    pub created_at: u64,
    /// NIP-01 event kind.
    pub kind: u16,
    /// Event tags in canonical NIP-01 order (already sorted by producer).
    pub tags: Vec<Vec<String>>,
    /// Event content (utf-8).
    pub content: String,
}

impl NostrEventPayload {
    /// Build the structured payload from a nostr-sdk unsigned event, so the
    /// CLI and nip46 callers share one field mapping instead of hand-rolling
    /// it (and drifting from the id recompute).
    pub fn from_unsigned_event(event: &nostr_sdk::UnsignedEvent) -> Self {
        Self {
            pubkey: event.pubkey.to_bytes(),
            created_at: event.created_at.as_secs(),
            kind: event.kind.as_u16(),
            tags: event.tags.iter().map(|t| t.clone().to_vec()).collect(),
            content: event.content.clone(),
        }
    }
}

/// Structured payload for a `bitcoin-sighash` signing request. Carries the
/// PSBT plus everything needed to reconstruct the exact BIP-341 taproot
/// key-spend sighash for one input: which input, the sighash flag, and the
/// full prevouts vector (a taproot signature commits to every input's
/// prevout, so the responder needs them all to reproduce the digest).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BitcoinSighashPayload {
    /// BIP-174 encoded PSBT.
    #[serde(with = "hex_vec_bytes")]
    pub psbt: Vec<u8>,
    /// Which input of the unsigned tx to sign.
    pub input_index: u32,
    /// Sighash flag as a u8 (encoded as u32 for cross-language wire clarity).
    pub sighash_type: u32,
    /// Prevouts for every input, in the same order as the tx inputs.
    /// Serialized as consensus-encoded bitcoin::TxOut byte strings.
    #[serde(with = "vec_hex")]
    pub prevouts: Vec<Vec<u8>>,
}

/// The largest key-spend payload (JSON) a sign request carries. The request
/// hex-encodes it inside a NIP-44 message, whose plaintext is capped at 65535
/// bytes, so this leaves room for the hex doubling and the request's other fields.
pub const MAX_KEY_SPEND_PAYLOAD_BYTES: usize = 28 * 1024;

impl BitcoinSighashPayload {
    /// The payload for a key-path spend of input `input_index` of `psbt`, with
    /// the PSBT reduced to what co-signers recompute the sighash from and what a
    /// spend policy reads: the unsigned transaction, every input's UTXO and the
    /// outputs' key origins. The prevouts come from the inputs' UTXOs. Returns
    /// the payload as JSON, refusing one too large for a sign request.
    pub fn for_key_spend(
        psbt: &Psbt,
        input_index: usize,
        sighash_type: TapSighashType,
    ) -> Result<Vec<u8>> {
        let mut reduced = Psbt::from_unsigned_tx(psbt.unsigned_tx.clone())
            .map_err(|e| FrostNetError::PolicyViolation(format!("bitcoin-sighash psbt: {e}")))?;
        let mut prevouts = Vec::with_capacity(psbt.inputs.len());
        for (i, (input, kept)) in psbt
            .inputs
            .iter()
            .zip(reduced.inputs.iter_mut())
            .enumerate()
        {
            let utxo = input.witness_utxo.clone().ok_or_else(|| {
                FrostNetError::PolicyViolation(format!("input {i} has no witness UTXO"))
            })?;
            prevouts.push(bitcoin::consensus::serialize(&utxo));
            kept.witness_utxo = Some(utxo);
        }
        for (output, kept) in psbt.outputs.iter().zip(reduced.outputs.iter_mut()) {
            kept.tap_internal_key = output.tap_internal_key;
            kept.tap_key_origins = output.tap_key_origins.clone();
        }
        let payload = Self {
            psbt: reduced.serialize(),
            input_index: u32::try_from(input_index)
                .map_err(|_| FrostNetError::PolicyViolation("input index out of range".into()))?,
            sighash_type: u32::from(sighash_type as u8),
            prevouts,
        };
        let json = serde_json::to_vec(&payload).map_err(|e| {
            FrostNetError::PolicyViolation(format!("bitcoin-sighash payload encode: {e}"))
        })?;
        if json.len() > MAX_KEY_SPEND_PAYLOAD_BYTES {
            return Err(FrostNetError::PolicyViolation(format!(
                "the PSBT is too large for a sign request ({} bytes of payload, at most {MAX_KEY_SPEND_PAYLOAD_BYTES})",
                json.len()
            )));
        }
        Ok(json)
    }
}

mod vec_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> std::result::Result<S::Ok, S::Error> {
        let hex_vec: Vec<String> = v.iter().map(hex::encode).collect();
        serde::Serialize::serialize(&hex_vec, s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<Vec<Vec<u8>>, D::Error> {
        let hex_vec = Vec::<String>::deserialize(d)?;
        hex_vec
            .into_iter()
            .map(|h| hex::decode(&h).map_err(serde::de::Error::custom))
            .collect()
    }
}

mod hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<[u8; 32], D::Error> {
        let h = String::deserialize(d)?;
        let bytes = hex::decode(&h).map_err(serde::de::Error::custom)?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| serde::de::Error::custom("expected 32-byte hex"))
    }
}

mod hex_vec_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let h = String::deserialize(d)?;
        hex::decode(&h).map_err(serde::de::Error::custom)
    }
}

/// Recompute the digest implied by a structured payload and compare it to
/// the 32-byte request `message`. Returns `Ok(())` on match, a
/// [`FrostNetError::PolicyViolation`] on mismatch or malformed payload.
///
/// Called from the pre-sign path in `signing.rs` whenever the request
/// carries a `structured_payload`. When no payload is present, this is a
/// no-op (the [`crate::RequireStructuredPayloadHooks`] gate is what
/// enforces presence for hybrid groups).
pub fn verify_structured_payload(
    message_type: &str,
    message: &[u8],
    structured: &[u8],
) -> Result<()> {
    if message.len() != 32 {
        return Err(FrostNetError::PolicyViolation(
            "structured payload verification requires a 32-byte message".into(),
        ));
    }
    match message_type {
        MSG_TYPE_NOSTR_EVENT => verify_nostr_event(message, structured),
        MSG_TYPE_BITCOIN_SIGHASH => verify_bitcoin_sighash(message, structured),
        // `raw` has no structured form; if a caller attached one, refuse:
        // a raw request that carries a domain-typed payload is either
        // confused honestly (in which case the operator wants the domain
        // label) or actively bypassing the label; either way, the safe
        // answer is reject. Unknown types get the same treatment.
        _ => Err(FrostNetError::PolicyViolation(format!(
            "structured payload present for unknown message_type={message_type:?}; refusing"
        ))),
    }
}

fn verify_nostr_event(digest: &[u8], structured: &[u8]) -> Result<()> {
    let payload: NostrEventPayload = serde_json::from_slice(structured).map_err(|e| {
        FrostNetError::PolicyViolation(format!("nostr-event structured payload decode failed: {e}"))
    })?;
    // Recompute the NIP-01 event id the same way every requester does:
    // sha256 over the canonical [0, pubkey, created_at, kind, tags, content]
    // JSON array. Hash the raw fields directly rather than round-tripping
    // through nostr-sdk's typed Tag/UnsignedEvent layer, so a tag that does
    // not survive parse -> re-serialize byte-identically cannot cause an
    // honest request to be refused.
    let serialized = serde_json::json!([
        0,
        hex::encode(payload.pubkey),
        payload.created_at,
        payload.kind,
        payload.tags,
        payload.content,
    ]);
    let json = serde_json::to_string(&serialized).map_err(|e| {
        FrostNetError::PolicyViolation(format!("nostr-event recompute serialize failed: {e}"))
    })?;
    let id = Sha256::digest(json.as_bytes());
    if id.as_slice() != digest {
        return Err(FrostNetError::PolicyViolation(
            "structured nostr-event does not hash to the requested digest; \
             refusing to sign (cross-domain label spoof)"
                .into(),
        ));
    }
    Ok(())
}

fn verify_bitcoin_sighash(digest: &[u8], structured: &[u8]) -> Result<()> {
    let payload: BitcoinSighashPayload = serde_json::from_slice(structured).map_err(|e| {
        FrostNetError::PolicyViolation(format!(
            "bitcoin-sighash structured payload decode failed: {e}"
        ))
    })?;
    let psbt = Psbt::deserialize(&payload.psbt).map_err(|e| {
        FrostNetError::PolicyViolation(format!("bitcoin-sighash payload psbt decode: {e}"))
    })?;
    let idx = payload.input_index as usize;
    if idx >= psbt.unsigned_tx.input.len() {
        return Err(FrostNetError::PolicyViolation(
            "bitcoin-sighash payload input_index out of range".into(),
        ));
    }
    if payload.prevouts.len() != psbt.unsigned_tx.input.len() {
        return Err(FrostNetError::PolicyViolation(
            "bitcoin-sighash payload prevouts count must match tx input count".into(),
        ));
    }
    let prevouts: Vec<TxOut> = payload
        .prevouts
        .iter()
        .map(|bytes| {
            bitcoin::consensus::deserialize::<TxOut>(bytes).map_err(|e| {
                FrostNetError::PolicyViolation(format!(
                    "bitcoin-sighash payload prevout decode: {e}"
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let sighash_type = u8::try_from(payload.sighash_type).map_err(|_| {
        FrostNetError::PolicyViolation(format!(
            "bitcoin-sighash flag {} out of byte range",
            payload.sighash_type
        ))
    })?;
    let sighash_flag = TapSighashType::from_consensus_u8(sighash_type).map_err(|e| {
        FrostNetError::PolicyViolation(format!("bitcoin-sighash flag invalid: {e}"))
    })?;
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(idx, &Prevouts::All(&prevouts), sighash_flag)
        .map_err(|e| {
            FrostNetError::PolicyViolation(format!("bitcoin-sighash recompute failed: {e}"))
        })?;
    let sighash_bytes: &[u8] = sighash.as_ref();
    if sighash_bytes != digest {
        return Err(FrostNetError::PolicyViolation(
            "structured bitcoin-sighash does not match the requested digest; \
             refusing to sign (cross-domain label spoof)"
                .into(),
        ));
    }
    Ok(())
}

/// For a key-path spend request ([`crate::TaprootTweakPayload`]): the input
/// being signed must spend `script_pubkey`, this group's output for the request's
/// path and tweak, and the request may only ask for SIGHASH_DEFAULT or
/// SIGHASH_ALL, which commit to every input and output. Run after
/// [`verify_structured_payload`] has proven the digest is this input's sighash
/// over these prevouts; that sighash commits to the spent scriptPubKey, so a
/// payload naming another one yields a signature no node accepts.
pub fn verify_taproot_key_spend(
    structured: &[u8],
    script_pubkey: &bitcoin::ScriptBuf,
) -> Result<()> {
    let payload: BitcoinSighashPayload = serde_json::from_slice(structured).map_err(|e| {
        FrostNetError::PolicyViolation(format!(
            "bitcoin-sighash structured payload decode failed: {e}"
        ))
    })?;
    if !matches!(payload.sighash_type, 0x00 | 0x01) {
        return Err(FrostNetError::PolicyViolation(format!(
            "a key-path spend must use SIGHASH_DEFAULT or SIGHASH_ALL, not {:#x}",
            payload.sighash_type
        )));
    }
    let spent = payload
        .prevouts
        .get(payload.input_index as usize)
        .ok_or_else(|| {
            FrostNetError::PolicyViolation(
                "bitcoin-sighash payload input_index out of range".into(),
            )
        })?;
    let spent = bitcoin::consensus::deserialize::<TxOut>(spent).map_err(|e| {
        FrostNetError::PolicyViolation(format!("bitcoin-sighash payload prevout decode: {e}"))
    })?;
    if spent.script_pubkey != *script_pubkey {
        return Err(FrostNetError::PolicyViolation(
            "the input does not spend this group's output for the requested path and \
             taproot tweak; refusing to sign"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod key_spend_payload_tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, Txid, Witness};

    fn psbt(outputs: usize) -> Psbt {
        let spent = |b: u8| {
            ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
                bitcoin::secp256k1::Keypair::from_seckey_slice(
                    &bitcoin::secp256k1::Secp256k1::new(),
                    &[b; 32],
                )
                .unwrap()
                .x_only_public_key()
                .0,
            ))
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: (0..2)
                .map(|vout| TxIn {
                    previous_output: OutPoint::new(Txid::from_byte_array([1; 32]), vout),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: (0..outputs)
                .map(|_| TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: spent(3),
                })
                .collect(),
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for (i, input) in psbt.inputs.iter_mut().enumerate() {
            input.witness_utxo = Some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: spent(1 + i as u8),
            });
            input.final_script_witness = Some(Witness::from_slice(&[vec![7u8; 500]]));
        }
        psbt
    }

    /// Co-signers recompute the requested sighash from the reduced payload, and
    /// fields they do not need are left out.
    #[test]
    fn a_key_spend_payload_recomputes_the_sighash() {
        let psbt = psbt(2);
        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .map(|i| i.witness_utxo.clone().unwrap())
            .collect();
        for sighash_type in [TapSighashType::Default, TapSighashType::All] {
            let sighash = SighashCache::new(&psbt.unsigned_tx)
                .taproot_key_spend_signature_hash(1, &Prevouts::All(&prevouts), sighash_type)
                .unwrap();
            let json = BitcoinSighashPayload::for_key_spend(&psbt, 1, sighash_type).unwrap();
            verify_structured_payload(MSG_TYPE_BITCOIN_SIGHASH, sighash.as_ref(), &json).unwrap();
            let payload: BitcoinSighashPayload = serde_json::from_slice(&json).unwrap();
            let reduced = Psbt::deserialize(&payload.psbt).unwrap();
            assert!(reduced
                .inputs
                .iter()
                .all(|i| i.final_script_witness.is_none()));
            assert_eq!(reduced.inputs[1].witness_utxo, psbt.inputs[1].witness_utxo);
        }
    }

    #[test]
    fn a_key_spend_payload_needs_every_utxo_and_fits_a_request() {
        let mut missing = psbt(1);
        missing.inputs[0].witness_utxo = None;
        assert!(
            BitcoinSighashPayload::for_key_spend(&missing, 1, TapSighashType::Default).is_err()
        );
        let e = BitcoinSighashPayload::for_key_spend(&psbt(400), 0, TapSighashType::Default)
            .expect_err("a PSBT too large for one request");
        assert!(e.to_string().contains("too large"), "{e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, Witness};
    use nostr_sdk::prelude::*;

    fn build_nostr_event_and_payload() -> ([u8; 32], NostrEventPayload) {
        let keys = Keys::generate();
        let mut event = UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::TextNote,
            vec![Tag::parse::<Vec<String>, String>(vec!["t".into(), "test".into()]).unwrap()],
            "hello #529".to_string(),
        );
        event.ensure_id();
        let id = event.id.unwrap();
        let payload = NostrEventPayload {
            pubkey: keys.public_key().to_bytes(),
            created_at: 1_700_000_000,
            kind: 1,
            tags: vec![vec!["t".into(), "test".into()]],
            content: "hello #529".to_string(),
        };
        (*id.as_bytes(), payload)
    }

    fn build_bitcoin_sighash_payload() -> ([u8; 32], BitcoinSighashPayload) {
        // Minimal single-input transaction spending a p2tr output. Derive a
        // valid x-only pubkey by using the well-known secp256k1 generator's
        // x coordinate (any valid curve point works; we don't spend, we just
        // recompute the sighash which commits to the script bytes).
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let (xonly, _parity) = sk.x_only_public_key(&secp);
        let prev_script = bitcoin::ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly),
        );
        let prev_out = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: prev_script,
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&prev_out)),
                TapSighashType::Default,
            )
            .unwrap();
        let prev_bytes = bitcoin::consensus::serialize(&prev_out);
        let payload = BitcoinSighashPayload {
            psbt: psbt.serialize(),
            input_index: 0,
            sighash_type: TapSighashType::Default as u32,
            prevouts: vec![prev_bytes],
        };
        (*sighash.as_ref(), payload)
    }

    #[test]
    fn nostr_event_payload_matching_digest_verifies() {
        let (digest, payload) = build_nostr_event_and_payload();
        let bytes = serde_json::to_vec(&payload).unwrap();
        verify_structured_payload(MSG_TYPE_NOSTR_EVENT, &digest, &bytes).unwrap();
    }

    #[test]
    fn nostr_event_digest_from_raw_field_hash_verifies() {
        // Compute the digest exactly like the nip55/CLI requesters do: a direct
        // sha256 over the canonical [0, pubkey_hex, created_at, kind, tags,
        // content] JSON array, with no nostr-sdk typed round-trip. This pins the
        // responder's direct-hash recompute to the requester's construction, so
        // an honest request always verifies (the #529 false-refusal regression).
        let payload = NostrEventPayload {
            pubkey: [0x02; 32],
            created_at: 1_700_000_123,
            kind: 1,
            tags: vec![
                vec!["t".into(), "test".into()],
                vec!["e".into(), "abcd".into()],
            ],
            content: "hello #529 direct hash".to_string(),
        };
        let serialized = serde_json::json!([
            0,
            hex::encode(payload.pubkey),
            payload.created_at,
            payload.kind,
            payload.tags,
            payload.content,
        ]);
        let json = serde_json::to_string(&serialized).unwrap();
        let digest: [u8; 32] = Sha256::digest(json.as_bytes()).into();
        let bytes = serde_json::to_vec(&payload).unwrap();
        verify_structured_payload(MSG_TYPE_NOSTR_EVENT, &digest, &bytes).unwrap();
    }

    #[test]
    fn responder_branch_nostr_event_non_matching_payload_refuses() {
        // Pins the exact branch `handle_sign_request` relies on: a request
        // labeled nostr-event whose structured payload does not hash to the
        // 32-byte message must yield a PolicyViolation (the responder maps this
        // to a `policy_violation` session error and never signs).
        let payload = NostrEventPayload {
            pubkey: [0x03; 32],
            created_at: 1_700_000_000,
            kind: 1,
            tags: vec![],
            content: "responder path".to_string(),
        };
        let bytes = serde_json::to_vec(&payload).unwrap();
        let wrong_digest = [0x42u8; 32];
        let err = verify_structured_payload(MSG_TYPE_NOSTR_EVENT, &wrong_digest, &bytes)
            .expect_err("non-matching payload must be refused on the responder branch");
        assert!(matches!(err, FrostNetError::PolicyViolation(_)));
    }

    #[test]
    fn bitcoin_sighash_out_of_byte_range_flag_refuses() {
        // A sighash_type outside the u8 range must be rejected, not truncated
        // into a valid flag (e.g. 256 wrapping to Default).
        let (digest, mut payload) = build_bitcoin_sighash_payload();
        payload.sighash_type = 256;
        let bytes = serde_json::to_vec(&payload).unwrap();
        let err = verify_structured_payload(MSG_TYPE_BITCOIN_SIGHASH, &digest, &bytes)
            .expect_err("out-of-range sighash flag must be refused");
        assert!(matches!(err, FrostNetError::PolicyViolation(_)));
    }

    #[test]
    fn nostr_event_payload_mismatch_refuses() {
        let (_digest, payload) = build_nostr_event_and_payload();
        let bytes = serde_json::to_vec(&payload).unwrap();
        // A different digest of the same length: the label spoof case.
        let bogus_digest = [0x99u8; 32];
        let err = verify_structured_payload(MSG_TYPE_NOSTR_EVENT, &bogus_digest, &bytes)
            .expect_err("mismatched digest must refuse");
        assert!(matches!(err, FrostNetError::PolicyViolation(_)));
    }

    #[test]
    fn bitcoin_sighash_payload_matching_digest_verifies() {
        let (digest, payload) = build_bitcoin_sighash_payload();
        let bytes = serde_json::to_vec(&payload).unwrap();
        verify_structured_payload(MSG_TYPE_BITCOIN_SIGHASH, &digest, &bytes).unwrap();
    }

    #[test]
    fn bitcoin_sighash_payload_mismatch_refuses() {
        let (_digest, payload) = build_bitcoin_sighash_payload();
        let bytes = serde_json::to_vec(&payload).unwrap();
        let bogus_digest = [0x55u8; 32];
        let err = verify_structured_payload(MSG_TYPE_BITCOIN_SIGHASH, &bogus_digest, &bytes)
            .expect_err("mismatched digest must refuse");
        assert!(matches!(err, FrostNetError::PolicyViolation(_)));
    }

    #[test]
    fn cross_domain_label_spoof_refused_nostr_labeled_as_bitcoin() {
        // Requester labels a Nostr event id as "bitcoin-sighash" and attaches
        // a nostr event body as the structured payload. The BitcoinSighash
        // decoder fails, refusing before signing.
        let (nostr_digest, nostr_payload) = build_nostr_event_and_payload();
        let bytes = serde_json::to_vec(&nostr_payload).unwrap();
        let err = verify_structured_payload(MSG_TYPE_BITCOIN_SIGHASH, &nostr_digest, &bytes)
            .expect_err("nostr body labeled as bitcoin must be refused");
        assert!(matches!(err, FrostNetError::PolicyViolation(_)));
    }

    #[test]
    fn cross_domain_label_spoof_refused_bitcoin_labeled_as_nostr() {
        // The mirror case: Bitcoin sighash bytes claimed as nostr-event.
        let (btc_digest, btc_payload) = build_bitcoin_sighash_payload();
        let bytes = serde_json::to_vec(&btc_payload).unwrap();
        let err = verify_structured_payload(MSG_TYPE_NOSTR_EVENT, &btc_digest, &bytes)
            .expect_err("bitcoin body labeled as nostr must be refused");
        assert!(matches!(err, FrostNetError::PolicyViolation(_)));
    }

    #[test]
    fn unknown_message_type_with_structured_payload_refused() {
        let bytes = serde_json::to_vec(&serde_json::json!({"anything": true})).unwrap();
        let err = verify_structured_payload("unknown-type", &[0u8; 32], &bytes)
            .expect_err("unknown types with structured payload are refused");
        assert!(matches!(err, FrostNetError::PolicyViolation(_)));
    }

    #[test]
    fn non_32_byte_message_refuses_immediately() {
        let bytes = vec![0u8; 8];
        let err = verify_structured_payload(MSG_TYPE_NOSTR_EVENT, &[1u8; 16], &bytes)
            .expect_err("non-32-byte messages must be refused");
        assert!(matches!(err, FrostNetError::PolicyViolation(_)));
    }
}
