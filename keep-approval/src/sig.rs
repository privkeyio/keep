// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Signatures, the pairing proof and the device fingerprint.
//!
//! ```text
//! decision_sig = P256_sign(approver_key, tagged("keep/approval/decision/v1",
//!     32 channel_pubkey || 33 approver_pubkey || 32 request_hash || u8 decision))
//! freeze_sig = BIP340_sign(transport_key, tagged("keep/approval/freeze/v1",
//!     32 channel_pubkey || 32 transport_pubkey || u64 counter || u64 epoch
//!     || u8 action || u8 scope || [16 credential_id]))
//! unfreeze_sig = P256_sign(approver_key, tagged("keep/approval/freeze/v1",
//!     32 channel_pubkey || 33 approver_pubkey || u64 counter || u64 epoch
//!     || u8 action || u8 scope || [16 credential_id]))
//! pair_approver_sig = P256_sign(approver_key, tagged("keep/approval/pair-approver/v1",
//!     32 channel_pubkey || 32 transport_pubkey || 33 approver_pubkey))
//! ```
//!
//! The channel and transport keys are 32-byte x-only secp256k1 keys. The
//! approver key is a P-256 key that lives in the phone's Android Keystore,
//! carried as its 33-byte compressed SEC1 point. `P256_sign(k, d)` is ECDSA
//! over P-256 with SHA-256 applied to the 32-byte digest `d`, sent as 64
//! bytes `r || s` with `s` in the lower half of the order: a high `s` is
//! refused, so each signature has one encoding.
//!
//! The tags differ, so no signature can be used as another. Each action has
//! exactly one valid signer: decisions and unfreezes the device's approver
//! key, freezes its transport key.

use hmac::{Hmac, KeyInit, Mac};
use nostr::secp256k1::schnorr::Signature;
use nostr::secp256k1::{Message, XOnlyPublicKey};
use nostr::{Keys, SECP256K1};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::change::Scope;
use crate::messages::{Decision, Freeze, FreezeAction, Pairing, SignerKey, Verdict, V1};
use crate::{invalid, sha256, tagged_hash, Hex32, Hex33, Hex64, Result};

pub use p256::ecdsa::SigningKey as ApproverSigningKey;

pub const DECISION_TAG: &str = "keep/approval/decision/v1";
pub const FREEZE_TAG: &str = "keep/approval/freeze/v1";
pub const PAIR_APPROVER_TAG: &str = "keep/approval/pair-approver/v1";
/// The prefix the pairing proof's HMAC covers.
pub const PAIR_PROOF_PREFIX: &[u8] = b"keep/approval/pair/v1";

/// The most a freeze or unfreeze counter may move past the last one
/// accepted from its device. A device that could jump to `u64::MAX` would
/// lock itself out of every later freeze and unfreeze.
pub const MAX_COUNTER_STEP: u64 = 1 << 32;

/// The approver key's type, as `pair` carries it as `alg`. Version 1
/// defines one; any other is refused when the message is parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Alg {
    /// P-256 (secp256r1), ECDSA with SHA-256.
    P256,
}

/// The digest a decision signs.
pub fn decision_digest(
    channel: &[u8; 32],
    approver: &[u8; 33],
    request_hash: &[u8; 32],
    verdict: Verdict,
) -> [u8; 32] {
    let mut m = Vec::with_capacity(98);
    m.extend_from_slice(channel);
    m.extend_from_slice(approver);
    m.extend_from_slice(request_hash);
    m.push(match verdict {
        Verdict::Approve => 1,
        Verdict::Deny => 0,
    });
    tagged_hash(DECISION_TAG, &m)
}

/// The digest a freeze or unfreeze signs: `signer` is the transport key
/// (32 bytes) for a freeze and the approver key (33 bytes) for an unfreeze.
pub fn freeze_digest(
    channel: &[u8; 32],
    signer: &SignerKey,
    counter: u64,
    epoch: u64,
    action: FreezeAction,
    scope: Scope,
) -> [u8; 32] {
    let mut m = Vec::with_capacity(99 + 16);
    m.extend_from_slice(channel);
    m.extend_from_slice(signer.as_bytes());
    m.extend_from_slice(&counter.to_le_bytes());
    m.extend_from_slice(&epoch.to_le_bytes());
    m.push(match action {
        FreezeAction::Freeze => 1,
        FreezeAction::Unfreeze => 2,
    });
    match scope {
        Scope::All => m.push(0),
        Scope::Credential(id) => {
            m.push(1);
            m.extend_from_slice(&id.0);
        }
    }
    tagged_hash(FREEZE_TAG, &m)
}

/// The digest the pairing approver signature signs.
pub fn pair_approver_digest(
    channel: &[u8; 32],
    transport: &[u8; 32],
    approver: &[u8; 33],
) -> [u8; 32] {
    let mut m = Vec::with_capacity(97);
    m.extend_from_slice(channel);
    m.extend_from_slice(transport);
    m.extend_from_slice(approver);
    tagged_hash(PAIR_APPROVER_TAG, &m)
}

/// BIP-340 sign `digest` with `keys`.
pub fn sign_bip340(keys: &Keys, digest: &[u8; 32]) -> Hex64 {
    let sig = keys.sign_schnorr(&Message::from_digest(*digest));
    Hex64(sig.serialize())
}

/// BIP-340 verify `sig` over `digest` under the x-only key `signer`.
pub fn verify_bip340(signer: &[u8; 32], digest: &[u8; 32], sig: &Hex64) -> Result<()> {
    let key = XOnlyPublicKey::from_slice(signer).map_err(|_| invalid("not a public key"))?;
    let sig = Signature::from_slice(&sig.0).map_err(|_| invalid("not a signature"))?;
    SECP256K1
        .verify_schnorr(&sig, &Message::from_digest(*digest), &key)
        .map_err(|_| invalid("signature"))
}

/// The compressed SEC1 form of an approver key.
pub fn approver_key(key: &ApproverSigningKey) -> [u8; 33] {
    let point = key.verifying_key().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(point.as_bytes());
    out
}

/// P-256 sign `digest` with an approver key: ECDSA with SHA-256 of the
/// digest, RFC 6979 nonces, `s` normalized to the lower half. A phone does
/// the same in the Keystore with `Signature("SHA256withECDSA")`, negating a
/// high `s`.
pub fn sign_p256(key: &ApproverSigningKey, digest: &[u8; 32]) -> Hex64 {
    use p256::ecdsa::signature::Signer;
    let sig: p256::ecdsa::Signature = key.sign(digest);
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    Hex64(out)
}

/// P-256 verify `sig` over `digest` under the compressed approver key
/// `approver`, refusing a high `s`.
pub fn verify_p256(approver: &[u8; 33], digest: &[u8; 32], sig: &Hex64) -> Result<()> {
    use p256::ecdsa::signature::Verifier;
    // 33 bytes parse only as a compressed point.
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(approver)
        .map_err(|_| invalid("not a P-256 key"))?;
    let sig = p256::ecdsa::Signature::from_slice(&sig.0).map_err(|_| invalid("not a signature"))?;
    if sig.normalize_s().is_some() {
        return Err(invalid("a signature with a high s"));
    }
    key.verify(digest, &sig).map_err(|_| invalid("signature"))
}

fn proof_mac(
    secret: &[u8; 32],
    channel: &[u8; 32],
    transport: &[u8; 32],
    approver: &[u8; 33],
) -> Hmac<Sha256> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(PAIR_PROOF_PREFIX);
    mac.update(channel);
    mac.update(transport);
    mac.update(approver);
    mac
}

/// The pairing proof: `HMAC-SHA256(secret, "keep/approval/pair/v1" ||
/// channel_pubkey || transport_pubkey || approver_pubkey)`.
pub fn pair_proof(
    secret: &[u8; 32],
    channel: &[u8; 32],
    transport: &[u8; 32],
    approver: &[u8; 33],
) -> Hex32 {
    // The MAC output is wiped when it goes; only the proof, which is sent,
    // is copied out.
    let out = proof_mac(secret, channel, transport, approver).finalize();
    let mut proof = [0u8; 32];
    proof.copy_from_slice(out.as_bytes());
    Hex32(proof)
}

/// Check a pairing proof in constant time.
pub fn verify_pair_proof(
    secret: &[u8; 32],
    channel: &[u8; 32],
    transport: &[u8; 32],
    approver: &[u8; 33],
    proof: &Hex32,
) -> Result<()> {
    proof_mac(secret, channel, transport, approver)
        .verify_slice(&proof.0)
        .map_err(|_| invalid("pairing proof"))
}

/// The device fingerprint both screens show: the first 10 bytes of
/// SHA-256 of `transport_pubkey (32) || approver_pubkey (33)`, as hex in
/// groups of 4.
pub fn fingerprint(transport: &[u8; 32], approver: &[u8; 33]) -> String {
    let mut both = [0u8; 65];
    both[..32].copy_from_slice(transport);
    both[32..].copy_from_slice(approver);
    let hex = hex::encode(&sha256(&both)[..10]);
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("hex is ASCII"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A registered device's two keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Device {
    /// Seals every message the device sends, and signs freezes.
    pub transport: [u8; 32],
    /// Signs decisions and unfreezes.
    pub approver: [u8; 33],
}

/// Check a decision from `device` (whose transport key sealed it) for the
/// parked request with `request_id` and `request_hash`: the id and hash it
/// names are that request's, and it is signed by the device's approver key.
/// Returns the verdict.
pub fn check_decision(
    decision: &Decision,
    channel: &[u8; 32],
    device: &Device,
    request_id: &[u8; 32],
    request_hash: &[u8; 32],
) -> Result<Verdict> {
    if decision.request_id.0 != *request_id || decision.request_hash.0 != *request_hash {
        return Err(invalid("the decision names another request"));
    }
    let digest = decision_digest(channel, &device.approver, request_hash, decision.decision);
    verify_p256(&device.approver, &digest, &decision.sig)?;
    Ok(decision.decision)
}

/// Check a freeze or unfreeze from `device` (whose transport key sealed
/// it): its `signer` is the one key that may sign the action (the transport
/// key for a freeze, the approver key for an unfreeze), and the signature
/// verifies under it. The counter and the epoch are the gateway's to check
/// (see [`check_counter`]).
pub fn check_freeze(freeze: &Freeze, channel: &[u8; 32], device: &Device) -> Result<()> {
    let digest = freeze_digest(
        channel,
        &freeze.signer,
        freeze.counter,
        freeze.epoch,
        freeze.action,
        freeze.scope,
    );
    match (freeze.action, freeze.signer) {
        (FreezeAction::Freeze, SignerKey::Transport(k)) if k.0 == device.transport => {
            verify_bip340(&k.0, &digest, &freeze.sig)
        }
        (FreezeAction::Unfreeze, SignerKey::Approver(k)) if k.0 == device.approver => {
            verify_p256(&k.0, &digest, &freeze.sig)
        }
        _ => Err(invalid("signed by a key that may not sign this action")),
    }
}

/// Check a freeze or unfreeze `counter` against `stored`, the last one
/// accepted from the device: it must be greater, and by at most
/// [`MAX_COUNTER_STEP`].
pub fn check_counter(stored: u64, counter: u64) -> Result<()> {
    if counter <= stored {
        return Err(invalid("an old counter"));
    }
    if counter - stored > MAX_COUNTER_STEP {
        return Err(invalid("the counter jumps too far ahead"));
    }
    Ok(())
}

/// Check a `pair` message sealed by `transport`, against the pairing
/// session's `secret`: the transport key is not the channel key, the proof
/// is the session's, and the approver key signed both keys. Returns the
/// device. The approver key is P-256, so it can equal neither the transport
/// key nor the channel key. Whether its keys may be registered (not a vault
/// key, not another device's) is the gateway's to check.
pub fn check_pair(
    channel: &[u8; 32],
    secret: &[u8; 32],
    transport: &[u8; 32],
    approver: &Hex33,
    proof: &Hex32,
    approver_sig: &Hex64,
) -> Result<Device> {
    if transport == channel {
        return Err(invalid("a device key is the channel key"));
    }
    verify_pair_proof(secret, channel, transport, &approver.0, proof)?;
    verify_p256(
        &approver.0,
        &pair_approver_digest(channel, transport, &approver.0),
        approver_sig,
    )?;
    Ok(Device {
        transport: *transport,
        approver: approver.0,
    })
}

/// The x-only public key of `keys`.
pub fn xonly(keys: &Keys) -> [u8; 32] {
    keys.public_key().to_bytes()
}

/// A phone's decision on the request with `request_id` and
/// `request_hash`, signed by its approver key.
pub fn decision(
    approver: &ApproverSigningKey,
    channel: &[u8; 32],
    request_id: Hex32,
    request_hash: Hex32,
    verdict: Verdict,
) -> Decision {
    let digest = decision_digest(channel, &approver_key(approver), &request_hash.0, verdict);
    Decision {
        v: V1,
        request_id,
        request_hash,
        decision: verdict,
        sig: sign_p256(approver, &digest),
    }
}

/// A phone's freeze, signed by its transport key.
pub fn freeze(
    transport: &Keys,
    channel: &[u8; 32],
    counter: u64,
    epoch: u64,
    scope: Scope,
) -> Freeze {
    let signer = SignerKey::Transport(Hex32(xonly(transport)));
    let digest = freeze_digest(
        channel,
        &signer,
        counter,
        epoch,
        FreezeAction::Freeze,
        scope,
    );
    Freeze {
        v: V1,
        action: FreezeAction::Freeze,
        scope,
        counter,
        epoch,
        signer,
        sig: sign_bip340(transport, &digest),
    }
}

/// A phone's unfreeze, signed by its approver key.
pub fn unfreeze(
    approver: &ApproverSigningKey,
    channel: &[u8; 32],
    counter: u64,
    epoch: u64,
    scope: Scope,
) -> Freeze {
    let signer = SignerKey::Approver(Hex33(approver_key(approver)));
    let digest = freeze_digest(
        channel,
        &signer,
        counter,
        epoch,
        FreezeAction::Unfreeze,
        scope,
    );
    Freeze {
        v: V1,
        action: FreezeAction::Unfreeze,
        scope,
        counter,
        epoch,
        signer,
        sig: sign_p256(approver, &digest),
    }
}

/// A phone's `pair` message for the session with `secret`: the proof over
/// both keys and the approver key's signature over them.
pub fn pair(
    transport: &[u8; 32],
    approver: &ApproverSigningKey,
    channel: &[u8; 32],
    secret: &[u8; 32],
    label: &str,
) -> Pairing {
    let a = approver_key(approver);
    Pairing::Pair {
        v: V1,
        label: label.to_string(),
        alg: Alg::P256,
        approver: Hex33(a),
        proof: pair_proof(secret, channel, transport, &a),
        approver_sig: sign_p256(approver, &pair_approver_digest(channel, transport, &a)),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::Hex16;

    pub fn approver_signing_key(byte: u8) -> ApproverSigningKey {
        ApproverSigningKey::from_slice(&[byte; 32]).expect("a valid P-256 scalar")
    }

    fn device() -> (Keys, ApproverSigningKey, Device) {
        let transport = Keys::generate();
        let approver = ApproverSigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let device = Device {
            transport: xonly(&transport),
            approver: approver_key(&approver),
        };
        (transport, approver, device)
    }

    /// Each action has exactly one valid signer: a decision or unfreeze
    /// signed by the transport key, or a freeze by the approver key, is
    /// refused, as is another device's approver key.
    #[test]
    fn each_action_has_one_signer() {
        let channel = [1u8; 32];
        let hash = Hex32([2u8; 32]);
        let id = Hex32([3u8; 32]);
        let (transport, approver, dev) = device();
        let (_, other_approver, _) = device();
        let approve = decision(&approver, &channel, id, hash, Verdict::Approve);
        assert_eq!(
            check_decision(&approve, &channel, &dev, &id.0, &hash.0).unwrap(),
            Verdict::Approve
        );
        // Another device's approver key, over the right digest for that key.
        let other = decision(&other_approver, &channel, id, hash, Verdict::Approve);
        assert!(check_decision(&other, &channel, &dev, &id.0, &hash.0).is_err());
        // The transport key's BIP-340 signature over the decision digest.
        let mut by_transport = approve.clone();
        by_transport.sig = sign_bip340(
            &transport,
            &decision_digest(&channel, &dev.approver, &hash.0, Verdict::Approve),
        );
        assert!(check_decision(&by_transport, &channel, &dev, &id.0, &hash.0).is_err());
        assert!(check_decision(&approve, &channel, &dev, &id.0, &[9; 32]).is_err());
        // A decision signed over the parked hash that names another request.
        let mut renamed = approve.clone();
        renamed.request_hash = Hex32([9; 32]);
        assert!(check_decision(&renamed, &channel, &dev, &id.0, &hash.0).is_err());
        let mut other_id = approve.clone();
        other_id.request_id = Hex32([4; 32]);
        assert!(check_decision(&other_id, &channel, &dev, &id.0, &hash.0).is_err());
        assert!(check_decision(&approve, &channel, &dev, &[4; 32], &hash.0).is_err());
        // A deny cannot be turned into an approve, or the reverse.
        let mut flipped = approve.clone();
        flipped.decision = Verdict::Deny;
        assert!(check_decision(&flipped, &channel, &dev, &id.0, &hash.0).is_err());

        let freeze_msg = freeze(&transport, &channel, 5, 7, Scope::All);
        let unfreeze_msg = unfreeze(&approver, &channel, 5, 7, Scope::All);
        assert!(check_freeze(&freeze_msg, &channel, &dev).is_ok());
        assert!(check_freeze(&unfreeze_msg, &channel, &dev).is_ok());
        // A freeze naming the approver key, or an unfreeze naming the
        // transport key, each validly signed by the key it names.
        let mut freeze_by_approver = unfreeze_msg.clone();
        freeze_by_approver.action = FreezeAction::Freeze;
        freeze_by_approver.sig = sign_p256(
            &approver,
            &freeze_digest(
                &channel,
                &freeze_by_approver.signer,
                5,
                7,
                FreezeAction::Freeze,
                Scope::All,
            ),
        );
        assert!(check_freeze(&freeze_by_approver, &channel, &dev).is_err());
        let mut unfreeze_by_transport = freeze_msg.clone();
        unfreeze_by_transport.action = FreezeAction::Unfreeze;
        unfreeze_by_transport.sig = sign_bip340(
            &transport,
            &freeze_digest(
                &channel,
                &unfreeze_by_transport.signer,
                5,
                7,
                FreezeAction::Unfreeze,
                Scope::All,
            ),
        );
        assert!(check_freeze(&unfreeze_by_transport, &channel, &dev).is_err());
        // Another device's transport key on a freeze, validly signed by it.
        let (other_transport, _, _) = device();
        assert!(check_freeze(
            &freeze(&other_transport, &channel, 5, 7, Scope::All),
            &channel,
            &dev
        )
        .is_err());
        // Another device's approver key on an unfreeze.
        assert!(check_freeze(
            &unfreeze(&other_approver, &channel, 5, 7, Scope::All),
            &channel,
            &dev
        )
        .is_err());
        // A signature over other fields does not carry.
        let mut moved = freeze_msg.clone();
        moved.counter = 6;
        assert!(check_freeze(&moved, &channel, &dev).is_err());
        let mut moved = unfreeze_msg.clone();
        moved.epoch = 8;
        assert!(check_freeze(&moved, &channel, &dev).is_err());
    }

    /// A freeze signature never verifies as a decision, nor a decision as an
    /// unfreeze, even under the same key and over the same 32 bytes of hash.
    #[test]
    fn a_signature_never_verifies_as_another_message() {
        let channel = [1u8; 32];
        let (_, approver, dev) = device();
        let un = unfreeze(&approver, &channel, 1, 0, Scope::All);
        let as_decision = Decision {
            v: V1,
            request_id: Hex32([0; 32]),
            request_hash: Hex32([0; 32]),
            decision: Verdict::Approve,
            sig: un.sig,
        };
        assert!(check_decision(&as_decision, &channel, &dev, &[0; 32], &[0; 32]).is_err());
        let d = decision(
            &approver,
            &channel,
            Hex32([0; 32]),
            Hex32([0; 32]),
            Verdict::Approve,
        );
        let mut as_unfreeze = un.clone();
        as_unfreeze.sig = d.sig;
        assert!(check_freeze(&as_unfreeze, &channel, &dev).is_err());
    }

    /// Pairing needs the session's proof over both keys and the approver
    /// key's signature over both keys, and refuses the channel key as the
    /// transport key.
    #[test]
    fn pairing_needs_both_proofs() {
        let channel = [1u8; 32];
        let secret = [4u8; 32];
        let (_transport, approver, dev) = device();
        let Pairing::Pair {
            approver: a,
            proof,
            approver_sig,
            ..
        } = pair(&dev.transport, &approver, &channel, &secret, "x")
        else {
            unreachable!()
        };
        assert_eq!(
            check_pair(&channel, &secret, &dev.transport, &a, &proof, &approver_sig).unwrap(),
            dev
        );
        // Another key's signature, or one over other keys.
        let (_, other, _) = device();
        let wrong_signer = sign_p256(
            &other,
            &pair_approver_digest(&channel, &dev.transport, &dev.approver),
        );
        assert!(check_pair(&channel, &secret, &dev.transport, &a, &proof, &wrong_signer).is_err());
        let other_keys = sign_p256(
            &approver,
            &pair_approver_digest(&channel, &[9; 32], &dev.approver),
        );
        assert!(check_pair(&channel, &secret, &dev.transport, &a, &proof, &other_keys).is_err());
        // Another session's secret, another transport key.
        assert!(check_pair(
            &channel,
            &[5; 32],
            &dev.transport,
            &a,
            &proof,
            &approver_sig
        )
        .is_err());
        assert!(check_pair(&channel, &secret, &[8; 32], &a, &proof, &approver_sig).is_err());
        // The channel key as the transport key, with a valid proof and
        // signature over it.
        let Pairing::Pair {
            proof,
            approver_sig,
            ..
        } = pair(&channel, &approver, &channel, &secret, "x")
        else {
            unreachable!()
        };
        assert!(verify_pair_proof(&secret, &channel, &channel, &a.0, &proof).is_ok());
        assert!(check_pair(&channel, &secret, &channel, &a, &proof, &approver_sig).is_err());
    }

    #[test]
    fn p256_signatures_are_strict() {
        let key = approver_signing_key(3);
        let a = approver_key(&key);
        let d = [7u8; 32];
        let sig = sign_p256(&key, &d);
        assert!(verify_p256(&a, &d, &sig).is_ok());
        // Deterministic: the same digest gives the same signature.
        assert_eq!(sign_p256(&key, &d), sig);
        // Another digest or key.
        assert!(verify_p256(&a, &[8; 32], &sig).is_err());
        assert!(verify_p256(&approver_key(&approver_signing_key(4)), &d, &sig).is_err());
        // The high-s twin of a valid signature is refused.
        let low = p256::ecdsa::Signature::from_slice(&sig.0).unwrap();
        let (r, s) = low.split_scalars();
        let high = p256::ecdsa::Signature::from_scalars(r, -*s).unwrap();
        assert!(high.normalize_s().is_some(), "the twin is high-s");
        let mut twin = [0u8; 64];
        twin.copy_from_slice(&high.to_bytes());
        assert!(verify_p256(&a, &d, &Hex64(twin)).is_err());
        // An uncompressed or malformed key.
        let mut bad = a;
        bad[0] = 0x04;
        assert!(verify_p256(&bad, &d, &sig).is_err());
        assert!(verify_p256(&[2; 33], &d, &sig).is_err());
    }

    #[test]
    fn counters_move_forward_by_a_bounded_step() {
        assert!(check_counter(5, 6).is_ok());
        assert!(check_counter(5, 5).is_err());
        assert!(check_counter(5, 4).is_err());
        assert!(check_counter(5, 5 + MAX_COUNTER_STEP).is_ok());
        assert!(check_counter(5, 6 + MAX_COUNTER_STEP).is_err());
        assert!(check_counter(0, u64::MAX).is_err());
    }

    #[test]
    fn signatures_verify_only_their_own_digest_and_key() {
        let approver = approver_signing_key(3);
        let channel = [7u8; 32];
        let hash = [9u8; 32];
        let a = approver_key(&approver);
        let d = decision_digest(&channel, &a, &hash, Verdict::Approve);
        let sig = sign_p256(&approver, &d);
        assert!(verify_p256(&a, &d, &sig).is_ok());
        for other in [
            decision_digest(&channel, &a, &hash, Verdict::Deny),
            decision_digest(&channel, &a, &[8; 32], Verdict::Approve),
            decision_digest(&[6; 32], &a, &hash, Verdict::Approve),
            freeze_digest(
                &channel,
                &SignerKey::Approver(Hex33(a)),
                1,
                1,
                FreezeAction::Unfreeze,
                Scope::All,
            ),
        ] {
            assert_ne!(other, d);
            assert!(verify_p256(&a, &other, &sig).is_err());
        }
    }

    #[test]
    fn freeze_digest_covers_every_field() {
        let t = SignerKey::Transport(Hex32([2; 32]));
        let base = freeze_digest(&[1; 32], &t, 3, 4, FreezeAction::Freeze, Scope::All);
        let others = [
            freeze_digest(&[9; 32], &t, 3, 4, FreezeAction::Freeze, Scope::All),
            freeze_digest(
                &[1; 32],
                &SignerKey::Transport(Hex32([9; 32])),
                3,
                4,
                FreezeAction::Freeze,
                Scope::All,
            ),
            freeze_digest(&[1; 32], &t, 9, 4, FreezeAction::Freeze, Scope::All),
            freeze_digest(&[1; 32], &t, 3, 9, FreezeAction::Freeze, Scope::All),
            freeze_digest(&[1; 32], &t, 3, 4, FreezeAction::Unfreeze, Scope::All),
            freeze_digest(
                &[1; 32],
                &t,
                3,
                4,
                FreezeAction::Freeze,
                Scope::Credential(Hex16([0; 16])),
            ),
            freeze_digest(
                &[1; 32],
                &t,
                3,
                4,
                FreezeAction::Freeze,
                Scope::Credential(Hex16([1; 16])),
            ),
        ];
        for (i, other) in others.iter().enumerate() {
            assert_ne!(*other, base, "field {i}");
        }
        assert_ne!(others[5], others[6]);
    }

    #[test]
    fn pairing_proof_and_fingerprint() {
        let secret = [3u8; 32];
        let a = [4u8; 33];
        let proof = pair_proof(&secret, &[1; 32], &[2; 32], &a);
        assert!(verify_pair_proof(&secret, &[1; 32], &[2; 32], &a, &proof).is_ok());
        assert!(verify_pair_proof(&[5; 32], &[1; 32], &[2; 32], &a, &proof).is_err());
        assert!(verify_pair_proof(&secret, &[1; 32], &[4; 32], &a, &proof).is_err());
        assert!(verify_pair_proof(&secret, &[9; 32], &[2; 32], &a, &proof).is_err());
        assert!(verify_pair_proof(&secret, &[1; 32], &[2; 32], &[5; 33], &proof).is_err());
        let fp = fingerprint(&[2; 32], &a);
        assert_eq!(fp.len(), 24);
        assert_eq!(fp.split(' ').count(), 5);
        assert_ne!(fp, fingerprint(&[2; 32], &[5; 33]));
        assert_ne!(fp, fingerprint(&[3; 32], &a));
    }

    /// The MAC states that hold the pairing secret or a tag key are wiped
    /// when dropped: an HMAC is two SHA-256 states and a block buffer, each
    /// wiped on drop with the crates' zeroize features, and its output is
    /// wiped too.
    #[test]
    fn mac_states_are_wiped() {
        fn wiped<T: zeroize::ZeroizeOnDrop>() {}
        wiped::<sha2::block_api::Sha256VarCore>();
        wiped::<hmac::digest::CtOutput<Hmac<Sha256>>>();
    }
}
