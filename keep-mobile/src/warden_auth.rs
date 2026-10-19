// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Signed instructions from a trusted warden.
//!
//! The spending policy is a constraint a warden places on the device, and a
//! constraint the person holding the device can remove is not one. So
//! removing the policy, and changing which wardens are trusted, each need a
//! signature from a warden the device already trusts. The second matters as
//! much as the first: if anyone could add a trusted warden, they would add
//! their own key and sign whatever they liked, a revocation or a permissive
//! replacement policy, and the warden check would protect nothing.
//!
//! Every authorization names the device it is for, by a random id the device
//! generates once and keeps with its wardens. Epochs start at 0 everywhere and
//! advance through the same provisioning steps, and a fleet can share one
//! bundle, so without it an authorization sent to one co-signer would verify
//! on any other at the same epoch holding the same policy.
//!
//! Every authorization is single-use. It names the device's current warden
//! epoch, which advances on every change it authorizes, so one captured off a
//! relay cannot be replayed later. Binding to the warden set instead would not
//! be enough: if a warden is added and then removed after being compromised,
//! the set returns to what it was, and the original "add" would verify again
//! and bring the compromised key back.
//!
//! The signed message is a standard BIP340 signature over the 32 bytes
//!
//! ```text
//! SHA256("keep/warden-authorization/v1" || version || action || warden_pubkey
//!        || device_id || subject || epoch as u64 little-endian)
//! ```
//!
//! so any BIP340 signer can produce one. The leading tag separates it from a
//! policy bundle's signed data, so neither can be passed off as the other.
//!
//! An authorization stays valid until the epoch next advances. A warden that
//! sent one and no longer wants it used spends it by making any other change,
//! such as installing a renewal of the policy.

use k256::schnorr::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::error::KeepMobileError;
use crate::policy::{POLICY_PUBKEY_LEN, POLICY_SIGNATURE_LEN};

pub(crate) const WARDEN_AUTH_VERSION: u8 = 1;

const WARDEN_AUTH_TAG: &[u8] = b"keep/warden-authorization/v1";

/// version, action, signer, device, subject, epoch, signature.
const WARDEN_AUTH_LEN: usize = 1 + 1 + POLICY_PUBKEY_LEN + 32 + 32 + 8 + POLICY_SIGNATURE_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WardenAction {
    /// Remove the stored policy. The subject is the policy's digest.
    RevokePolicy = 1,
    /// Trust another warden. The subject is that warden's key.
    AddWarden = 2,
    /// Stop trusting a warden. The subject is that warden's key.
    RemoveWarden = 3,
}

impl WardenAction {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::RevokePolicy),
            2 => Some(Self::AddWarden),
            3 => Some(Self::RemoveWarden),
            _ => None,
        }
    }
}

/// What a warden needs from a device to sign an authorization for it.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct WardenGovernance {
    /// Hex of the random id this device generated for itself.
    pub device_id: String,
    /// The epoch the next authorization has to name.
    pub epoch: u64,
    /// True when the warden set was lost and rebuilt from the stored policy's
    /// signer under a new device id: every other warden was dropped and no
    /// authorization signed before then applies. Cleared by the next
    /// authorized change.
    pub restored: bool,
}

/// The subject a revocation names when the stored policy cannot be attributed
/// to a trusted warden: it will not decrypt, will not parse, or fails its
/// signature, hash or signer check, so no warden knows its digest. Only
/// accepted while the record is in that state, and like every authorization it
/// names this device and its current epoch.
pub(crate) fn unreadable_policy_subject() -> [u8; 32] {
    Sha256::digest(b"keep/unreadable-policy").into()
}

#[derive(Clone, Debug)]
pub(crate) struct WardenAuthorization {
    action: WardenAction,
    warden_pubkey: [u8; POLICY_PUBKEY_LEN],
    device: [u8; 32],
    subject: [u8; 32],
    epoch: u64,
    signature: [u8; POLICY_SIGNATURE_LEN],
}

fn invalid(msg: &str) -> KeepMobileError {
    KeepMobileError::InvalidPolicy { msg: msg.into() }
}

impl WardenAuthorization {
    pub(crate) fn from_hex(hex_str: &str) -> Result<Self, KeepMobileError> {
        if hex_str.len() != 2 * WARDEN_AUTH_LEN {
            return Err(invalid("Authorization has the wrong length"));
        }
        let bytes = hex::decode(hex_str).map_err(|_| invalid("Authorization is not valid hex"))?;
        if bytes[0] != WARDEN_AUTH_VERSION {
            return Err(invalid("Authorization has an unsupported version"));
        }
        let action = WardenAction::from_byte(bytes[1])
            .ok_or_else(|| invalid("Unknown authorization action"))?;

        let mut offset = 2;
        let mut take = |n: usize| {
            let slice = &bytes[offset..offset + n];
            offset += n;
            slice
        };
        let mut warden_pubkey = [0u8; POLICY_PUBKEY_LEN];
        warden_pubkey.copy_from_slice(take(POLICY_PUBKEY_LEN));
        let mut device = [0u8; 32];
        device.copy_from_slice(take(32));
        let mut subject = [0u8; 32];
        subject.copy_from_slice(take(32));
        let mut epoch_bytes = [0u8; 8];
        epoch_bytes.copy_from_slice(take(8));
        let mut signature = [0u8; POLICY_SIGNATURE_LEN];
        signature.copy_from_slice(take(POLICY_SIGNATURE_LEN));

        Ok(Self {
            action,
            warden_pubkey,
            device,
            subject,
            epoch: u64::from_le_bytes(epoch_bytes),
            signature,
        })
    }

    fn message(
        action: WardenAction,
        warden_pubkey: &[u8; POLICY_PUBKEY_LEN],
        device: &[u8; 32],
        subject: &[u8; 32],
        epoch: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(WARDEN_AUTH_TAG);
        hasher.update([WARDEN_AUTH_VERSION, action as u8]);
        hasher.update(warden_pubkey);
        hasher.update(device);
        hasher.update(subject);
        hasher.update(epoch.to_le_bytes());
        hasher.finalize().into()
    }

    /// Checks that this authorizes exactly `action` on `subject` for `device`
    /// at its current `epoch`, signed by a warden in `trusted`.
    ///
    /// The cheap structural checks come first and the signature last. Every
    /// refusal is a fixed message: the authorization arrives from outside and
    /// nothing in it is echoed back.
    pub(crate) fn authorize(
        &self,
        action: WardenAction,
        subject: &[u8; 32],
        device: &[u8; 32],
        epoch: u64,
        trusted: &HashSet<[u8; POLICY_PUBKEY_LEN]>,
    ) -> Result<(), KeepMobileError> {
        if self.action != action {
            return Err(invalid("Authorization is for a different action"));
        }
        if &self.device != device {
            return Err(invalid("Authorization is for a different device"));
        }
        if &self.subject != subject {
            return Err(invalid("Authorization is for a different target"));
        }
        if self.epoch != epoch {
            return Err(invalid(
                "Authorization is for a different warden epoch; it was already used or is stale",
            ));
        }
        if !trusted.contains(&self.warden_pubkey) {
            return Err(invalid("Authorization is not signed by a trusted warden"));
        }
        let verifying_key = VerifyingKey::from_bytes(&self.warden_pubkey)
            .map_err(|_| invalid("Authorization signer is not a valid key"))?;
        let signature = Signature::try_from(self.signature.as_slice())
            .map_err(|_| invalid("Authorization signature is malformed"))?;
        let message = Self::message(
            self.action,
            &self.warden_pubkey,
            &self.device,
            &self.subject,
            self.epoch,
        );
        verifying_key
            .verify_prehash(&message, &signature)
            .map_err(|_| KeepMobileError::PolicySignatureInvalid)
    }
}

/// Produces an authorization the way a warden would, for tests.
#[cfg(test)]
pub(crate) fn sign_authorization(
    signing_key: &k256::schnorr::SigningKey,
    action: WardenAction,
    subject: &[u8; 32],
    device: &[u8; 32],
    epoch: u64,
) -> String {
    use k256::schnorr::signature::hazmat::PrehashSigner;

    let mut warden_pubkey = [0u8; POLICY_PUBKEY_LEN];
    warden_pubkey.copy_from_slice(&signing_key.verifying_key().to_bytes());
    let message = WardenAuthorization::message(action, &warden_pubkey, device, subject, epoch);
    let signature = signing_key.sign_prehash(&message).expect("32-byte prehash");

    let mut out = Vec::with_capacity(WARDEN_AUTH_LEN);
    out.push(WARDEN_AUTH_VERSION);
    out.push(action as u8);
    out.extend_from_slice(&warden_pubkey);
    out.extend_from_slice(device);
    out.extend_from_slice(subject);
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&signature.to_bytes());
    hex::encode(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: [u8; 32] = [0xd1; 32];

    fn key() -> k256::schnorr::SigningKey {
        k256::schnorr::SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng)
    }

    fn pubkey(k: &k256::schnorr::SigningKey) -> [u8; 32] {
        let mut p = [0u8; 32];
        p.copy_from_slice(&k.verifying_key().to_bytes());
        p
    }

    #[test]
    fn a_valid_authorization_authorizes_exactly_what_it_names() {
        let warden = key();
        let trusted: HashSet<_> = [pubkey(&warden)].into();
        let subject = [7u8; 32];
        let auth = WardenAuthorization::from_hex(&sign_authorization(
            &warden,
            WardenAction::AddWarden,
            &subject,
            &DEVICE,
            5,
        ))
        .unwrap();

        assert!(auth
            .authorize(WardenAction::AddWarden, &subject, &DEVICE, 5, &trusted)
            .is_ok());
        assert!(auth
            .authorize(WardenAction::RemoveWarden, &subject, &DEVICE, 5, &trusted)
            .is_err());
        assert!(auth
            .authorize(WardenAction::AddWarden, &[8u8; 32], &DEVICE, 5, &trusted)
            .is_err());
        assert!(
            auth.authorize(WardenAction::AddWarden, &subject, &DEVICE, 6, &trusted)
                .is_err(),
            "a later epoch means it was already used"
        );
    }

    #[test]
    fn an_authorization_from_an_untrusted_key_is_refused() {
        let stranger = key();
        let trusted: HashSet<_> = [pubkey(&key())].into();
        let auth = WardenAuthorization::from_hex(&sign_authorization(
            &stranger,
            WardenAction::RevokePolicy,
            &[1u8; 32],
            &DEVICE,
            0,
        ))
        .unwrap();
        assert!(auth
            .authorize(WardenAction::RevokePolicy, &[1u8; 32], &DEVICE, 0, &trusted)
            .is_err());
    }

    #[test]
    fn a_tampered_authorization_does_not_verify() {
        let warden = key();
        let trusted: HashSet<_> = [pubkey(&warden)].into();
        let hex_auth = sign_authorization(&warden, WardenAction::AddWarden, &[3u8; 32], &DEVICE, 0);
        let mut bytes = hex::decode(hex_auth).unwrap();
        // Move the epoch the signature covers.
        bytes[2 + 32 + 32 + 32] ^= 0x01;
        let auth = WardenAuthorization::from_hex(&hex::encode(bytes)).unwrap();
        let epoch = auth.epoch;
        assert!(matches!(
            auth.authorize(
                WardenAction::AddWarden,
                &[3u8; 32],
                &DEVICE,
                epoch,
                &trusted
            ),
            Err(KeepMobileError::PolicySignatureInvalid)
        ));
    }

    #[test]
    fn an_authorization_for_another_device_is_refused() {
        let warden = key();
        let trusted: HashSet<_> = [pubkey(&warden)].into();
        let auth = WardenAuthorization::from_hex(&sign_authorization(
            &warden,
            WardenAction::RevokePolicy,
            &[2u8; 32],
            &[0xee; 32],
            0,
        ))
        .unwrap();
        assert!(auth
            .authorize(WardenAction::RevokePolicy, &[2u8; 32], &DEVICE, 0, &trusted)
            .is_err());
    }

    /// The tag is part of what is signed, so a signature over the same fields
    /// without it, which is what any other untagged scheme would produce, does
    /// not verify.
    #[test]
    fn the_signed_message_is_tagged() {
        use k256::schnorr::signature::hazmat::PrehashSigner;

        let warden = key();
        let trusted: HashSet<_> = [pubkey(&warden)].into();
        let subject = [4u8; 32];
        let mut untagged = Sha256::new();
        untagged.update([WARDEN_AUTH_VERSION, WardenAction::RevokePolicy as u8]);
        untagged.update(pubkey(&warden));
        untagged.update(DEVICE);
        untagged.update(subject);
        untagged.update(0u64.to_le_bytes());
        let untagged: [u8; 32] = untagged.finalize().into();

        let mut bytes = hex::decode(sign_authorization(
            &warden,
            WardenAction::RevokePolicy,
            &subject,
            &DEVICE,
            0,
        ))
        .unwrap();
        let sig_at = bytes.len() - POLICY_SIGNATURE_LEN;
        bytes[sig_at..].copy_from_slice(&warden.sign_prehash(&untagged).unwrap().to_bytes());
        let auth = WardenAuthorization::from_hex(&hex::encode(bytes)).unwrap();
        assert!(matches!(
            auth.authorize(WardenAction::RevokePolicy, &subject, &DEVICE, 0, &trusted),
            Err(KeepMobileError::PolicySignatureInvalid)
        ));
    }

    /// An authorization assembled from the documented construction and
    /// signed by an independent BIP340 implementation verifies, so a warden
    /// needs nothing from this crate to produce one.
    #[test]
    fn a_standard_bip340_signer_produces_a_valid_authorization() {
        use nostr_sdk::secp256k1::{Keypair, Message, Secp256k1};

        let warden = key();
        let trusted: HashSet<_> = [pubkey(&warden)].into();
        let subject = [6u8; 32];
        let epoch = 3u64;

        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"keep/warden-authorization/v1");
        preimage.push(1);
        preimage.push(WardenAction::AddWarden as u8);
        preimage.extend_from_slice(&pubkey(&warden));
        preimage.extend_from_slice(&DEVICE);
        preimage.extend_from_slice(&subject);
        preimage.extend_from_slice(&epoch.to_le_bytes());
        let digest: [u8; 32] = Sha256::digest(&preimage).into();

        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &warden.to_bytes()).unwrap();
        let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair);

        let mut bytes = vec![1, WardenAction::AddWarden as u8];
        bytes.extend_from_slice(&pubkey(&warden));
        bytes.extend_from_slice(&DEVICE);
        bytes.extend_from_slice(&subject);
        bytes.extend_from_slice(&epoch.to_le_bytes());
        bytes.extend_from_slice(signature.as_ref());

        WardenAuthorization::from_hex(&hex::encode(bytes))
            .unwrap()
            .authorize(WardenAction::AddWarden, &subject, &DEVICE, epoch, &trusted)
            .unwrap();
    }

    #[test]
    fn malformed_input_is_refused_before_anything_is_trusted() {
        assert!(WardenAuthorization::from_hex("zz").is_err());
        assert!(WardenAuthorization::from_hex("00").is_err());
        let warden = key();
        let mut bytes = hex::decode(sign_authorization(
            &warden,
            WardenAction::AddWarden,
            &[0u8; 32],
            &DEVICE,
            0,
        ))
        .unwrap();
        bytes[1] = 9;
        assert!(WardenAuthorization::from_hex(&hex::encode(&bytes)).is_err());
        bytes[1] = WardenAction::AddWarden as u8;
        bytes[0] = 2;
        assert!(WardenAuthorization::from_hex(&hex::encode(&bytes)).is_err());
    }
}
