// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Signatures, the pairing proof and the device fingerprint.
//!
//! ```text
//! decision_sig = BIP340_sign(approver_key, tagged("keep/approval/decision/v1",
//!     32 channel_pubkey || 32 approver_pubkey || 32 request_hash || u8 decision))
//! freeze_sig = BIP340_sign(signer_key, tagged("keep/approval/freeze/v1",
//!     32 channel_pubkey || 32 signer_pubkey || u64 counter || u64 epoch
//!     || u8 action || u8 scope || [16 credential_id]))
//! pair_approver_sig = BIP340_sign(approver_key, tagged("keep/approval/pair-approver/v1",
//!     32 channel_pubkey || 32 transport_pubkey || 32 approver_pubkey))
//! ```
//!
//! The tags differ, so no signature can be used as another. Each action has
//! exactly one valid signer: decisions and unfreezes the device's approver
//! key, freezes its transport key; the caller checks the signer against the
//! device before calling the verify functions here.

use hmac::{Hmac, KeyInit, Mac};
use nostr::secp256k1::schnorr::Signature;
use nostr::secp256k1::{Message, XOnlyPublicKey};
use nostr::{Keys, SECP256K1};
use sha2::Sha256;

use crate::change::Scope;
use crate::messages::{FreezeAction, Verdict};
use crate::{invalid, sha256, tagged_hash, Hex32, Hex64, Result};

pub const DECISION_TAG: &str = "keep/approval/decision/v1";
pub const FREEZE_TAG: &str = "keep/approval/freeze/v1";
pub const PAIR_APPROVER_TAG: &str = "keep/approval/pair-approver/v1";
/// The prefix the pairing proof's HMAC covers.
pub const PAIR_PROOF_PREFIX: &[u8] = b"keep/approval/pair/v1";

/// The digest a decision signs.
pub fn decision_digest(
    channel: &[u8; 32],
    approver: &[u8; 32],
    request_hash: &[u8; 32],
    verdict: Verdict,
) -> [u8; 32] {
    let mut m = Vec::with_capacity(97);
    m.extend_from_slice(channel);
    m.extend_from_slice(approver);
    m.extend_from_slice(request_hash);
    m.push(match verdict {
        Verdict::Approve => 1,
        Verdict::Deny => 0,
    });
    tagged_hash(DECISION_TAG, &m)
}

/// The digest a freeze or unfreeze signs.
pub fn freeze_digest(
    channel: &[u8; 32],
    signer: &[u8; 32],
    counter: u64,
    epoch: u64,
    action: FreezeAction,
    scope: Scope,
) -> [u8; 32] {
    let mut m = Vec::with_capacity(98 + 16);
    m.extend_from_slice(channel);
    m.extend_from_slice(signer);
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
    approver: &[u8; 32],
) -> [u8; 32] {
    let mut m = Vec::with_capacity(96);
    m.extend_from_slice(channel);
    m.extend_from_slice(transport);
    m.extend_from_slice(approver);
    tagged_hash(PAIR_APPROVER_TAG, &m)
}

/// BIP-340 sign `digest` with `keys`.
pub fn sign(keys: &Keys, digest: &[u8; 32]) -> Hex64 {
    let sig = keys.sign_schnorr(&Message::from_digest(*digest));
    Hex64(sig.serialize())
}

/// BIP-340 verify `sig` over `digest` under the x-only key `signer`.
pub fn verify(signer: &[u8; 32], digest: &[u8; 32], sig: &Hex64) -> Result<()> {
    let key = XOnlyPublicKey::from_slice(signer).map_err(|_| invalid("not a public key"))?;
    let sig = Signature::from_slice(&sig.0).map_err(|_| invalid("not a signature"))?;
    SECP256K1
        .verify_schnorr(&sig, &Message::from_digest(*digest), &key)
        .map_err(|_| invalid("signature"))
}

/// The pairing proof: `HMAC-SHA256(secret, "keep/approval/pair/v1" ||
/// channel_pubkey || transport_pubkey || approver_pubkey)`.
pub fn pair_proof(
    secret: &[u8; 32],
    channel: &[u8; 32],
    transport: &[u8; 32],
    approver: &[u8; 32],
) -> Hex32 {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(PAIR_PROOF_PREFIX);
    mac.update(channel);
    mac.update(transport);
    mac.update(approver);
    Hex32(mac.finalize().into_bytes().into())
}

/// Check a pairing proof in constant time.
pub fn verify_pair_proof(
    secret: &[u8; 32],
    channel: &[u8; 32],
    transport: &[u8; 32],
    approver: &[u8; 32],
    proof: &Hex32,
) -> Result<()> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(PAIR_PROOF_PREFIX);
    mac.update(channel);
    mac.update(transport);
    mac.update(approver);
    mac.verify_slice(&proof.0)
        .map_err(|_| invalid("pairing proof"))
}

/// The device fingerprint both screens show: the first 10 bytes of
/// SHA-256 of `transport_pubkey || approver_pubkey`, as hex in groups of 4.
pub fn fingerprint(transport: &[u8; 32], approver: &[u8; 32]) -> String {
    let mut both = [0u8; 64];
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
    pub approver: [u8; 32],
}

/// Check a decision from `device` (whose transport key sealed it) for the
/// parked request with `request_id` and `request_hash`: the id and hash it
/// names are that request's, and it is signed by the device's approver key.
/// Returns the verdict.
pub fn check_decision(
    decision: &crate::messages::Decision,
    channel: &[u8; 32],
    device: &Device,
    request_id: &[u8; 32],
    request_hash: &[u8; 32],
) -> Result<Verdict> {
    if decision.request_id.0 != *request_id || decision.request_hash.0 != *request_hash {
        return Err(invalid("the decision names another request"));
    }
    let digest = decision_digest(channel, &device.approver, request_hash, decision.decision);
    verify(&device.approver, &digest, &decision.sig)?;
    Ok(decision.decision)
}

/// Check a freeze or unfreeze from `device` (whose transport key sealed
/// it): its `signer` is the one key that may sign the action (the transport
/// key for a freeze, the approver key for an unfreeze), and the signature
/// verifies under it. Counters and the epoch are the gateway's to check.
pub fn check_freeze(
    freeze: &crate::messages::Freeze,
    channel: &[u8; 32],
    device: &Device,
) -> Result<()> {
    let signer = match freeze.action {
        FreezeAction::Freeze => device.transport,
        FreezeAction::Unfreeze => device.approver,
    };
    if freeze.signer.0 != signer {
        return Err(invalid("signed by a key that may not sign this action"));
    }
    let digest = freeze_digest(
        channel,
        &signer,
        freeze.counter,
        freeze.epoch,
        freeze.action,
        freeze.scope,
    );
    verify(&signer, &digest, &freeze.sig)
}

/// Check a `pair` message sealed by `transport`, against the pairing
/// session's `secret`: the two keys differ and neither is the channel key,
/// the proof is the session's, and the approver key signed both keys.
/// Returns the device. Whether its keys may be registered (not a vault key,
/// not another device's) is the gateway's to check.
pub fn check_pair(
    channel: &[u8; 32],
    secret: &[u8; 32],
    transport: &[u8; 32],
    approver: &Hex32,
    proof: &Hex32,
    approver_sig: &Hex64,
) -> Result<Device> {
    if transport == &approver.0 {
        return Err(invalid("the transport and approver keys are the same"));
    }
    if transport == channel || &approver.0 == channel {
        return Err(invalid("a device key is the channel key"));
    }
    verify_pair_proof(secret, channel, transport, &approver.0, proof)?;
    verify(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{Decision, Freeze, V1};
    use crate::Hex16;

    fn device() -> (Keys, Keys, Device) {
        let transport = Keys::generate();
        let approver = Keys::generate();
        let device = Device {
            transport: xonly(&transport),
            approver: xonly(&approver),
        };
        (transport, approver, device)
    }

    /// Each action has exactly one valid signer: a decision or unfreeze
    /// signed by the transport key, or a freeze by the approver key, is
    /// refused, as is another device's approver key.
    #[test]
    fn each_action_has_one_signer() {
        let channel = [1u8; 32];
        let hash = [2u8; 32];
        let (transport, approver, dev) = device();
        let decision = |keys: &Keys| Decision {
            v: V1,
            request_id: Hex32([3; 32]),
            request_hash: Hex32(hash),
            decision: Verdict::Approve,
            sig: sign(
                keys,
                &decision_digest(&channel, &xonly(keys), &hash, Verdict::Approve),
            ),
        };
        assert_eq!(
            check_decision(&decision(&approver), &channel, &dev, &[3; 32], &hash).unwrap(),
            Verdict::Approve
        );
        assert!(check_decision(&decision(&transport), &channel, &dev, &[3; 32], &hash).is_err());
        assert!(check_decision(
            &decision(&Keys::generate()),
            &channel,
            &dev,
            &[3; 32],
            &hash
        )
        .is_err());
        assert!(check_decision(&decision(&approver), &channel, &dev, &[3; 32], &[9; 32]).is_err());
        // A decision signed over the parked hash that names another request.
        let mut renamed = decision(&approver);
        renamed.request_hash = Hex32([9; 32]);
        assert!(check_decision(&renamed, &channel, &dev, &[3; 32], &hash).is_err());
        // A decision for the parked hash naming another request id, under
        // a valid signature.
        let mut other_id = decision(&approver);
        other_id.request_id = Hex32([4; 32]);
        assert!(check_decision(&other_id, &channel, &dev, &[3; 32], &hash).is_err());
        assert!(check_decision(&decision(&approver), &channel, &dev, &[4; 32], &hash).is_err());
        // A deny cannot be turned into an approve.
        let mut flipped = decision(&approver);
        flipped.decision = Verdict::Deny;
        assert!(check_decision(&flipped, &channel, &dev, &[3; 32], &hash).is_err());

        let freeze = |keys: &Keys, action| Freeze {
            v: V1,
            action,
            scope: Scope::All,
            counter: 5,
            epoch: 7,
            signer: Hex32(xonly(keys)),
            sig: sign(
                keys,
                &freeze_digest(&channel, &xonly(keys), 5, 7, action, Scope::All),
            ),
        };
        assert!(check_freeze(&freeze(&transport, FreezeAction::Freeze), &channel, &dev).is_ok());
        assert!(check_freeze(&freeze(&approver, FreezeAction::Freeze), &channel, &dev).is_err());
        assert!(check_freeze(&freeze(&approver, FreezeAction::Unfreeze), &channel, &dev).is_ok());
        assert!(check_freeze(&freeze(&transport, FreezeAction::Unfreeze), &channel, &dev).is_err());
        // A signature over other fields does not carry.
        let mut moved = freeze(&transport, FreezeAction::Freeze);
        moved.counter = 6;
        assert!(check_freeze(&moved, &channel, &dev).is_err());
        let mut named = freeze(&approver, FreezeAction::Freeze);
        named.signer = Hex32(dev.transport);
        assert!(check_freeze(&named, &channel, &dev).is_err());
    }

    /// Pairing needs the session's proof over both keys and the approver
    /// key's signature over both keys, and two different keys.
    #[test]
    fn pairing_needs_both_proofs() {
        let channel = [1u8; 32];
        let secret = [4u8; 32];
        let (_transport, approver, dev) = device();
        let proof = pair_proof(&secret, &channel, &dev.transport, &dev.approver);
        let good_sig = sign(
            &approver,
            &pair_approver_digest(&channel, &dev.transport, &dev.approver),
        );
        let a = Hex32(dev.approver);
        assert_eq!(
            check_pair(&channel, &secret, &dev.transport, &a, &proof, &good_sig).unwrap(),
            dev
        );
        // No approver signature (another key's), or one over other keys.
        let other = Keys::generate();
        let wrong_signer = sign(
            &other,
            &pair_approver_digest(&channel, &dev.transport, &dev.approver),
        );
        assert!(check_pair(&channel, &secret, &dev.transport, &a, &proof, &wrong_signer).is_err());
        let other_keys = sign(
            &approver,
            &pair_approver_digest(&channel, &[9; 32], &dev.approver),
        );
        assert!(check_pair(&channel, &secret, &dev.transport, &a, &proof, &other_keys).is_err());
        // Another session's secret, another transport key.
        assert!(check_pair(&channel, &[5; 32], &dev.transport, &a, &proof, &good_sig).is_err());
        assert!(check_pair(&channel, &secret, &[8; 32], &a, &proof, &good_sig).is_err());
        // The same key twice, with a valid proof and signature over it.
        let one = Keys::generate();
        let k = xonly(&one);
        let proof_same = pair_proof(&secret, &channel, &k, &k);
        let sig_same = sign(&one, &pair_approver_digest(&channel, &k, &k));
        assert!(verify(&k, &pair_approver_digest(&channel, &k, &k), &sig_same).is_ok());
        assert!(check_pair(&channel, &secret, &k, &Hex32(k), &proof_same, &sig_same).is_err());
    }

    /// Neither of a device's keys may be the channel key, even with a valid
    /// proof and signature over it.
    #[test]
    fn pairing_refuses_the_channel_key() {
        let channel_keys = Keys::generate();
        let channel = xonly(&channel_keys);
        let secret = [4u8; 32];
        let other = Keys::generate();
        let o = xonly(&other);
        // The channel key as transport key.
        let proof = pair_proof(&secret, &channel, &channel, &o);
        let sig = sign(&other, &pair_approver_digest(&channel, &channel, &o));
        assert!(check_pair(
            &channel,
            &secret,
            &[7; 32],
            &Hex32(o),
            &pair_proof(&secret, &channel, &[7; 32], &o),
            &sign(&other, &pair_approver_digest(&channel, &[7; 32], &o))
        )
        .is_ok());
        assert!(check_pair(&channel, &secret, &channel, &Hex32(o), &proof, &sig).is_err());
        // The channel key as approver key.
        let proof = pair_proof(&secret, &channel, &o, &channel);
        let sig = sign(&channel_keys, &pair_approver_digest(&channel, &o, &channel));
        assert!(verify(
            &channel,
            &pair_approver_digest(&channel, &o, &channel),
            &sig
        )
        .is_ok());
        assert!(check_pair(&channel, &secret, &o, &Hex32(channel), &proof, &sig).is_err());
    }

    #[test]
    fn signatures_verify_only_their_own_digest_and_key() {
        let approver = Keys::generate();
        let transport = Keys::generate();
        let channel = [7u8; 32];
        let hash = [9u8; 32];
        let a = xonly(&approver);
        let d = decision_digest(&channel, &a, &hash, Verdict::Approve);
        let sig = sign(&approver, &d);
        assert!(verify(&a, &d, &sig).is_ok());
        // Another verdict, hash, channel, signer or key does not verify.
        assert!(verify(
            &a,
            &decision_digest(&channel, &a, &hash, Verdict::Deny),
            &sig
        )
        .is_err());
        assert!(verify(
            &a,
            &decision_digest(&channel, &a, &[8; 32], Verdict::Approve),
            &sig
        )
        .is_err());
        assert!(verify(
            &a,
            &decision_digest(&[6; 32], &a, &hash, Verdict::Approve),
            &sig
        )
        .is_err());
        assert!(verify(&xonly(&transport), &d, &sig).is_err());
        // A freeze signature over the same fields is another digest.
        let f = freeze_digest(&channel, &a, 1, 1, FreezeAction::Freeze, Scope::All);
        assert_ne!(f, d);
        assert!(verify(&a, &f, &sig).is_err());
    }

    #[test]
    fn freeze_digest_covers_every_field() {
        let base = freeze_digest(&[1; 32], &[2; 32], 3, 4, FreezeAction::Freeze, Scope::All);
        let others = [
            freeze_digest(&[9; 32], &[2; 32], 3, 4, FreezeAction::Freeze, Scope::All),
            freeze_digest(&[1; 32], &[9; 32], 3, 4, FreezeAction::Freeze, Scope::All),
            freeze_digest(&[1; 32], &[2; 32], 9, 4, FreezeAction::Freeze, Scope::All),
            freeze_digest(&[1; 32], &[2; 32], 3, 9, FreezeAction::Freeze, Scope::All),
            freeze_digest(&[1; 32], &[2; 32], 3, 4, FreezeAction::Unfreeze, Scope::All),
            freeze_digest(
                &[1; 32],
                &[2; 32],
                3,
                4,
                FreezeAction::Freeze,
                Scope::Credential(Hex16([0; 16])),
            ),
            freeze_digest(
                &[1; 32],
                &[2; 32],
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
        let proof = pair_proof(&secret, &[1; 32], &[2; 32], &[4; 32]);
        assert!(verify_pair_proof(&secret, &[1; 32], &[2; 32], &[4; 32], &proof).is_ok());
        assert!(verify_pair_proof(&[5; 32], &[1; 32], &[2; 32], &[4; 32], &proof).is_err());
        assert!(verify_pair_proof(&secret, &[1; 32], &[4; 32], &[2; 32], &proof).is_err());
        assert!(verify_pair_proof(&secret, &[9; 32], &[2; 32], &[4; 32], &proof).is_err());
        let fp = fingerprint(&[2; 32], &[4; 32]);
        assert_eq!(fp.len(), 24);
        assert_eq!(fp.split(' ').count(), 5);
        assert_ne!(fp, fingerprint(&[4; 32], &[2; 32]));
        let d = pair_approver_digest(&[1; 32], &[2; 32], &[4; 32]);
        assert_ne!(d, pair_approver_digest(&[1; 32], &[4; 32], &[2; 32]));
    }
}
