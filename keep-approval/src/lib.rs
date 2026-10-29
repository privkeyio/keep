// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Agent approvals over Nostr, protocol version 1: everything the agent
//! gateway and an approver device must compute the same way.
//!
//! - [`binding`]: the request hash that binds a decision to one request,
//!   with each operation's canonical payload and the checks an approver
//!   runs before showing a request.
//! - [`psbt`]: the canonical payload of a PSBT signing request, and the
//!   figures an approver recomputes from it.
//! - [`change`]: management change objects and their canonical JSON.
//! - [`sig`]: decision, freeze and pairing signatures, the pairing proof and
//!   the device fingerprint.
//! - [`wrap`]: gift wraps carrying the protocol's messages, with the wrap
//!   tag checked before anything is decrypted, the time window and the size
//!   limit.
//! - [`messages`]: the messages themselves, parsed strictly.
//! - [`pairing`]: the pairing URI the host shows and the phone scans.
//! - [`approver`]: what an approver keeps between messages: the anchors it
//!   has seen, the requests it has seen, and the alerts they raise.
//!
//! Nothing here holds state shared between the two sides or talks to a
//! relay; the gateway and the approver each wire these pieces to their own
//! storage and transport.

pub mod approver;
pub mod binding;
pub mod change;
mod codec;
pub mod messages;
pub mod pairing;
pub mod psbt;
pub mod sig;
#[cfg(feature = "test-attestation")]
pub mod test_attestation;
pub mod wrap;

pub use codec::{Hex16, Hex32, Hex33, Hex64};

/// The protocol version every message carries as `"v"`.
pub const VERSION: u8 = 1;

/// Rumor kinds. They only ever appear inside seals.
pub mod kind {
    /// An approval request, from the gateway to each approver.
    pub const REQUEST: u16 = 24250;
    /// A decision, from an approver to the gateway.
    pub const DECISION: u16 = 24251;
    /// A freeze or unfreeze, from an approver to the gateway.
    pub const FREEZE: u16 = 24252;
    /// An anchor, from the gateway to each approver.
    pub const ANCHOR: u16 = 24253;
    /// Pairing: `pair` from a phone, `paired` or `refused` from the gateway.
    pub const PAIRING: u16 = 24254;
    /// An outcome, from the gateway to each approver.
    pub const OUTCOME: u16 = 24255;

    /// Whether `kind` is one of this protocol's kinds, which no agent may
    /// ever sign, under any grant.
    pub fn is_protocol_kind(kind: u16) -> bool {
        (REQUEST..=OUTCOME).contains(&kind)
    }
}

/// Why something in this protocol was refused. Messages are short and name
/// no secret.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// A message or field that does not parse, or breaks the schema.
    #[error("malformed: {0}")]
    Malformed(String),
    /// A hash, signature, proof or figure that does not check out.
    #[error("does not verify: {0}")]
    Invalid(String),
    /// A message or request larger than the protocol carries.
    #[error("too large: {0}")]
    TooLarge(String),
    /// A gift wrap whose tag matches no expected sender, or that lies outside
    /// the time window. Such wraps are dropped unopened.
    #[error("not for us")]
    NotOurs,
}

/// A result of this crate.
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn malformed(what: impl Into<String>) -> Error {
    Error::Malformed(what.into())
}

pub(crate) fn invalid(what: impl Into<String>) -> Error {
    Error::Invalid(what.into())
}

/// BIP-340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || m)`.
pub fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(message);
    h.finalize().into()
}

/// SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The BIP-340 tagged hash matches the construction in BIP-340's own
    /// reference code (`TapLeaf` of an empty message, as computed by
    /// bitcoin's own tagged hash engine).
    #[test]
    fn tagged_hash_matches_bitcoin() {
        use bitcoin::hashes::{sha256t_hash_newtype, Hash};
        sha256t_hash_newtype! {
            pub struct TestTag = hash_str("keep/approval/request/v1");
            #[hash_newtype(forward)]
            pub struct TestHash(_);
        }
        let ours = tagged_hash("keep/approval/request/v1", b"abc");
        let theirs = TestHash::hash(b"abc");
        assert_eq!(ours, theirs.to_byte_array());
    }

    #[test]
    fn protocol_kinds_are_exactly_the_six() {
        let kinds: Vec<u16> = (0..=u16::MAX)
            .filter(|k| kind::is_protocol_kind(*k))
            .collect();
        assert_eq!(kinds, [24250, 24251, 24252, 24253, 24254, 24255]);
    }
}
