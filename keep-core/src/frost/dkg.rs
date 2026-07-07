// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! In-process DKG (#454) using the standard frost-secp256k1-tr 3-round protocol.
//!
//! `keep frost network dkg` today requires `--hardware <path>` so the private
//! polynomial coefficients live entirely on an attached signer (M5Stack ESP32,
//! etc.). That is safer for production but blocks any user without hardware
//! from participating and blocks CI from exercising DKG end-to-end (#436).
//!
//! [`SoftwareDkgSession`] wraps `frost-secp256k1-tr::keys::dkg::{part1,part2,
//! part3}` behind the same six-step state machine `keep-cli` uses to drive
//! the hardware signer (`init` -> `round1` -> `round1_peer` -> `round2` ->
//! `receive_share` -> `finalize`), so the CLI can dispatch on the presence
//! of `--hardware` without any protocol-level branching.
//!
//! ## Wire compatibility
//!
//! This module speaks a **software-only** wire format ([`SOFTWARE_DKG_VERSION`]
//! is emitted alongside every round1 package). The keep-esp32 firmware ships
//! its own binary format the software side does not know how to parse, and
//! the mirror is also true, so software peers and hardware peers cannot DKG
//! with each other on this branch. Mixed groups must all be one or the
//! other; the CLI marks this explicitly so a bystander does not silently
//! DKG-with-nobody.
//!
//! ## Threat model reminder
//!
//! Software DKG puts every participant's polynomial + coefficient
//! commitments in that participant's process memory for the duration of
//! the run. That is the same trust surface `frost generate` (trusted
//! dealer) has for the full group secret, but SPLIT across the group and
//! reset once `part3` finishes: no single machine ever sees any other
//! participant's polynomial. That is materially better than trusted-dealer,
//! materially worse than hardware DKG. Operators of high-value groups
//! should still prefer hardware; software is here to unblock everyone else
//! and to give CI a real DKG path.

use std::collections::BTreeMap;

use frost_secp256k1_tr::{
    keys::dkg::{part1, part2, part3, round1, round2},
    keys::{KeyPackage, PublicKeyPackage},
    rand_core::OsRng,
    Identifier,
};
use zeroize::Zeroizing;

use crate::error::{KeepError, Result};

/// Wire discriminator. Bumped when the serialized package layout changes so
/// old peers reject the newer packages loudly rather than mis-decoding.
pub const SOFTWARE_DKG_VERSION: u8 = 1;

/// One participant's software DKG state machine. Same six-step public
/// interface `keep-cli` drives against the hardware signer, so the CLI
/// dispatches on the presence of `--hardware` without any protocol branching.
///
/// The state machine is linear and validates every transition, so an
/// out-of-order call (e.g. `dkg_round2` before every peer's round1 arrived)
/// returns a clear error rather than silently producing garbage.
pub struct SoftwareDkgSession {
    identifier: Identifier,
    max_signers: u16,
    min_signers: u16,
    our_index: u16,
    state: DkgState,
}

enum DkgState {
    Init,
    AwaitingRound1 {
        secret: round1::SecretPackage,
        our_round1: round1::Package,
        peer_round1: BTreeMap<Identifier, round1::Package>,
    },
    AwaitingRound2 {
        secret: round2::SecretPackage,
        round1: BTreeMap<Identifier, round1::Package>,
        peer_round2: BTreeMap<Identifier, round2::Package>,
    },
    Finalized,
}

/// Wire-format round1 package emitted by [`SoftwareDkgSession::round1`]. The
/// CLI encodes this as JSON and publishes it on the DKG topic; peers running
/// this same version decode it back via [`SoftwareDkgSession::round1_peer`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SoftwareRound1Wire {
    /// Discriminator so hardware peers reject the payload rather than
    /// silently mis-decoding. Must equal [`SOFTWARE_DKG_VERSION`].
    pub software_dkg_version: u8,
    /// The 1-indexed participant identifier that produced this package.
    pub sender_index: u16,
    /// Hex-encoded `frost_secp256k1_tr::keys::dkg::round1::Package::serialize`
    /// output.
    pub package_hex: String,
}

/// Wire-format round2 share, one per recipient. Encrypted per-recipient at
/// the CLI level (nip44) before publishing.
///
/// `package_hex` is a secret signing share, so `Debug` is redacted and must
/// stay that way: this struct crosses `#[tracing::instrument]` boundaries in
/// the CLI where a derived `Debug` would leak the share into logs.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SoftwareRound2Wire {
    /// Discriminator, same rule as [`SoftwareRound1Wire`].
    pub software_dkg_version: u8,
    /// The 1-indexed participant identifier that produced this share.
    pub sender_index: u16,
    /// Hex-encoded `round2::Package` for the specific recipient. Secret.
    pub package_hex: String,
}

impl std::fmt::Debug for SoftwareRound2Wire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareRound2Wire")
            .field("software_dkg_version", &self.software_dkg_version)
            .field("sender_index", &self.sender_index)
            .field("package_hex", &"<redacted>")
            .finish()
    }
}

impl Drop for SoftwareRound2Wire {
    fn drop(&mut self) {
        // `package_hex` is a plaintext signing share. Scrub it on drop so the
        // hex string does not linger in freed heap; this covers both the wire
        // we produce in `round2()` and the one serde deserializes on receive.
        use zeroize::Zeroize;
        self.package_hex.zeroize();
    }
}

/// Result returned from [`SoftwareDkgSession::finalize`], mirroring the
/// hardware finalize shape so the CLI can share printing / storage code.
pub struct SoftwareDkgResult {
    /// This participant's finalized KeyPackage. Store via
    /// `Keep::frost_store_dkg_share`.
    pub key_package: KeyPackage,
    /// The group's PublicKeyPackage. Also stored via the same helper so the
    /// verifying shares for every peer are available during aggregation.
    pub public_key_package: PublicKeyPackage,
    /// The BIP-340 x-only 32-byte group pubkey the shares reconstruct to.
    pub group_pubkey: [u8; 32],
    /// This participant's 1-indexed share number.
    pub our_index: u16,
}

impl SoftwareDkgSession {
    /// Set up state for a `threshold`-of-`participants` DKG run where this
    /// process holds share `our_index` (1-indexed). Rejects thresholds
    /// outside `2..=participants` and indexes outside `1..=participants` so
    /// a caller cannot pass a validated config to `part1` and get an
    /// `UnknownIdentifier` late in the run.
    pub fn init(threshold: u16, participants: u16, our_index: u16) -> Result<Self> {
        if threshold < 2 || threshold > participants {
            return Err(KeepError::Frost(format!(
                "threshold must satisfy 2 <= t ({threshold}) <= n ({participants})"
            )));
        }
        if our_index < 1 || our_index > participants {
            return Err(KeepError::Frost(format!(
                "share index must satisfy 1..={participants}, got {our_index}"
            )));
        }
        let identifier = Identifier::try_from(our_index).map_err(|e| {
            KeepError::Frost(format!(
                "share index {our_index} is not a valid FROST identifier: {e}"
            ))
        })?;
        Ok(Self {
            identifier,
            max_signers: participants,
            min_signers: threshold,
            our_index,
            state: DkgState::Init,
        })
    }

    /// Run frost-core's `part1` and return the round1 wire package this
    /// participant broadcasts to every peer. Must be called before any
    /// `round1_peer` step and exactly once per session.
    pub fn round1(&mut self) -> Result<SoftwareRound1Wire> {
        if !matches!(self.state, DkgState::Init) {
            return Err(KeepError::Frost(
                "SoftwareDkgSession::round1 called out of order (already past round 1)".into(),
            ));
        }
        let (secret, package) = part1(self.identifier, self.max_signers, self.min_signers, OsRng)
            .map_err(|e| KeepError::Frost(format!("DKG part1 failed: {e}")))?;
        let package_bytes = package
            .serialize()
            .map_err(|e| KeepError::Frost(format!("serialize round1 package: {e}")))?;
        let wire = SoftwareRound1Wire {
            software_dkg_version: SOFTWARE_DKG_VERSION,
            sender_index: self.our_index,
            package_hex: hex::encode(&package_bytes),
        };
        self.state = DkgState::AwaitingRound1 {
            secret,
            our_round1: package,
            peer_round1: BTreeMap::new(),
        };
        Ok(wire)
    }

    /// Consume a peer's round1 wire package. Rejects a duplicate sender, a
    /// self-echo, and a version mismatch. Returns `true` if this call
    /// completed the round1 set (`peers = participants - 1`).
    pub fn round1_peer(&mut self, wire: &SoftwareRound1Wire) -> Result<bool> {
        let peer_round1 = match &mut self.state {
            DkgState::AwaitingRound1 { peer_round1, .. } => peer_round1,
            _ => {
                return Err(KeepError::Frost(
                    "SoftwareDkgSession::round1_peer called out of order".into(),
                ));
            }
        };
        if wire.software_dkg_version != SOFTWARE_DKG_VERSION {
            return Err(KeepError::Frost(format!(
                "peer round1 package uses unsupported software_dkg_version {}, expected {}",
                wire.software_dkg_version, SOFTWARE_DKG_VERSION
            )));
        }
        if wire.sender_index == self.our_index {
            return Err(KeepError::Frost(
                "peer round1 package echoes our own share index; refusing to self-mix".into(),
            ));
        }
        if wire.sender_index < 1 || wire.sender_index > self.max_signers {
            return Err(KeepError::Frost(format!(
                "peer round1 sender_index {} out of range [1, {}]",
                wire.sender_index, self.max_signers,
            )));
        }
        let peer_id = Identifier::try_from(wire.sender_index).map_err(|e| {
            KeepError::Frost(format!(
                "peer index {} is not a valid FROST identifier: {e}",
                wire.sender_index
            ))
        })?;
        if peer_round1.contains_key(&peer_id) {
            return Err(KeepError::Frost(format!(
                "duplicate round1 package from peer {}",
                wire.sender_index
            )));
        }
        let bytes = hex::decode(&wire.package_hex)
            .map_err(|e| KeepError::Frost(format!("decode round1 package hex: {e}")))?;
        let package = round1::Package::deserialize(&bytes)
            .map_err(|e| KeepError::Frost(format!("deserialize round1 package: {e}")))?;
        peer_round1.insert(peer_id, package);
        Ok(peer_round1.len() as u16 + 1 == self.max_signers)
    }

    /// Run frost-core's `part2` and return the per-recipient round2 wire
    /// packages. Refuses to run until every peer's round1 package has
    /// landed.
    pub fn round2(&mut self) -> Result<Vec<(u16, SoftwareRound2Wire)>> {
        let (secret, our_round1, peer_round1) =
            match std::mem::replace(&mut self.state, DkgState::Finalized) {
                DkgState::AwaitingRound1 {
                    secret,
                    our_round1,
                    peer_round1,
                } if (peer_round1.len() as u16) + 1 == self.max_signers => {
                    (secret, our_round1, peer_round1)
                }
                other => {
                    // Restore the pre-call state on an out-of-order call so the
                    // caller keeps its round1 collection. This recovery only
                    // covers the guard-mismatch arm; once the guard passes below,
                    // the state has already advanced to `Finalized`.
                    self.state = other;
                    return Err(KeepError::Frost(
                        "SoftwareDkgSession::round2 called before every peer's round1 arrived"
                            .into(),
                    ));
                }
            };
        // Past this point the state is already `Finalized`: a `part2` failure is
        // a terminal protocol error, so the session is intentionally not rewound.
        let (round2_secret, round2_packages) =
            part2(secret, &peer_round1).map_err(|e| KeepError::Frost(format!("DKG part2: {e}")))?;

        let mut wires: Vec<(u16, SoftwareRound2Wire)> = Vec::new();
        for (peer_id, package) in &round2_packages {
            let recipient_index = identifier_to_u16(peer_id).ok_or_else(|| {
                KeepError::Frost("DKG part2 returned package for unknown identifier".into())
            })?;
            // `bytes` is a plaintext signing share; keep it in a scrubbed
            // buffer so it does not linger in freed heap after this loop.
            let bytes = Zeroizing::new(
                package
                    .serialize()
                    .map_err(|e| KeepError::Frost(format!("serialize round2 package: {e}")))?,
            );
            wires.push((
                recipient_index,
                SoftwareRound2Wire {
                    software_dkg_version: SOFTWARE_DKG_VERSION,
                    sender_index: self.our_index,
                    package_hex: hex::encode(&bytes),
                },
            ));
        }

        // Rebuild the full round1 map with our own entry, which `part3` needs.
        let mut round1_all = peer_round1;
        round1_all.insert(self.identifier, our_round1);

        self.state = DkgState::AwaitingRound2 {
            secret: round2_secret,
            round1: round1_all,
            peer_round2: BTreeMap::new(),
        };
        Ok(wires)
    }

    /// Consume a peer's round2 share targeted at us. Same version + range +
    /// duplicate checks as `round1_peer`. Returns `true` if this call
    /// completed the round2 set.
    pub fn receive_share(&mut self, wire: &SoftwareRound2Wire) -> Result<bool> {
        let peer_round2 = match &mut self.state {
            DkgState::AwaitingRound2 { peer_round2, .. } => peer_round2,
            _ => {
                return Err(KeepError::Frost(
                    "SoftwareDkgSession::receive_share called out of order".into(),
                ));
            }
        };
        if wire.software_dkg_version != SOFTWARE_DKG_VERSION {
            return Err(KeepError::Frost(format!(
                "peer round2 share uses unsupported software_dkg_version {}, expected {}",
                wire.software_dkg_version, SOFTWARE_DKG_VERSION,
            )));
        }
        if wire.sender_index == self.our_index {
            return Err(KeepError::Frost(
                "peer round2 share echoes our own share index; refusing to self-mix".into(),
            ));
        }
        if wire.sender_index < 1 || wire.sender_index > self.max_signers {
            return Err(KeepError::Frost(format!(
                "peer round2 sender_index {} out of range [1, {}]",
                wire.sender_index, self.max_signers,
            )));
        }
        let peer_id = Identifier::try_from(wire.sender_index).map_err(|e| {
            KeepError::Frost(format!(
                "peer index {} is not a valid FROST identifier: {e}",
                wire.sender_index
            ))
        })?;
        if peer_round2.contains_key(&peer_id) {
            return Err(KeepError::Frost(format!(
                "duplicate round2 share from peer {}",
                wire.sender_index
            )));
        }
        let bytes = Zeroizing::new(
            hex::decode(&wire.package_hex)
                .map_err(|e| KeepError::Frost(format!("decode round2 share hex: {e}")))?,
        );
        let package = round2::Package::deserialize(&bytes)
            .map_err(|e| KeepError::Frost(format!("deserialize round2 share: {e}")))?;
        peer_round2.insert(peer_id, package);
        Ok(peer_round2.len() as u16 + 1 == self.max_signers)
    }

    /// Finalize the DKG. Refuses to run until every peer's round2 share has
    /// arrived. On success the session state is consumed; further method
    /// calls return an error.
    pub fn finalize(&mut self) -> Result<SoftwareDkgResult> {
        let (secret, round1, round2) = match std::mem::replace(&mut self.state, DkgState::Finalized)
        {
            DkgState::AwaitingRound2 {
                secret,
                round1,
                peer_round2,
            } if (peer_round2.len() as u16) + 1 == self.max_signers => {
                (secret, round1, peer_round2)
            }
            other => {
                self.state = other;
                return Err(KeepError::Frost(
                    "SoftwareDkgSession::finalize called before every peer's round2 arrived".into(),
                ));
            }
        };

        // part3 wants round1 packages from peers only (not our own), so strip
        // our identifier out before handing the map in.
        let mut round1_peers = round1;
        round1_peers.remove(&self.identifier);

        let (key_package, public_key_package) = part3(&secret, &round1_peers, &round2)
            .map_err(|e| KeepError::Frost(format!("DKG part3: {e}")))?;

        // Single source of truth for x-only group pubkey extraction, shared with
        // the trusted-dealer path so both handle the 32- and 33-byte encodings.
        let group_pubkey = super::dealer::extract_group_pubkey(&public_key_package)?;

        Ok(SoftwareDkgResult {
            key_package,
            public_key_package,
            group_pubkey,
            our_index: self.our_index,
        })
    }

    /// This participant's 1-indexed share number.
    pub fn our_index(&self) -> u16 {
        self.our_index
    }
}

fn identifier_to_u16(id: &Identifier) -> Option<u16> {
    // frost-core's `Identifier` serialize is a big-endian 32-byte scalar
    // where the value we care about lives in the last two bytes for
    // participant indexes 1..=u16::MAX.
    let bytes = id.serialize();
    if bytes.len() < 32 {
        return None;
    }
    for &b in &bytes[..30] {
        if b != 0 {
            return None;
        }
    }
    Some(u16::from_be_bytes([bytes[30], bytes[31]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::signing::sign_with_local_shares;
    use crate::frost::SharePackage;

    /// Run a full 2-of-3 software DKG and verify the resulting shares can
    /// aggregate a valid signature under the derived group pubkey.
    #[test]
    fn end_to_end_2_of_3_software_dkg() {
        run_group(2, 3);
    }

    /// A larger 3-of-5 group, exercising deeper participant sets and
    /// verifying the aggregated signature still verifies under the derived
    /// group pubkey.
    #[test]
    fn end_to_end_3_of_5_software_dkg() {
        run_group(3, 5);
    }

    fn run_group(threshold: u16, participants: u16) {
        let mut sessions: Vec<SoftwareDkgSession> = (1..=participants)
            .map(|idx| SoftwareDkgSession::init(threshold, participants, idx).unwrap())
            .collect();

        // Round 1: every session emits a wire package.
        let round1_wires: Vec<SoftwareRound1Wire> =
            sessions.iter_mut().map(|s| s.round1().unwrap()).collect();

        // Every session ingests every OTHER session's round1 wire.
        for (i, session) in sessions.iter_mut().enumerate() {
            for (j, wire) in round1_wires.iter().enumerate() {
                if i == j {
                    continue;
                }
                session.round1_peer(wire).unwrap();
            }
        }

        // Round 2: each session emits per-recipient wires.
        let mut per_session_round2: Vec<Vec<(u16, SoftwareRound2Wire)>> =
            sessions.iter_mut().map(|s| s.round2().unwrap()).collect();

        // Deliver each round2 share to its intended recipient.
        for (sender_i, wires) in per_session_round2.drain(..).enumerate() {
            for (recipient_index, wire) in wires {
                let recipient_i = (recipient_index - 1) as usize;
                assert_ne!(recipient_i, sender_i, "no self-shares in round 2");
                sessions[recipient_i].receive_share(&wire).unwrap();
            }
        }

        // Finalize every session and check group_pubkey agreement.
        let results: Vec<SoftwareDkgResult> =
            sessions.iter_mut().map(|s| s.finalize().unwrap()).collect();
        let first_group = results[0].group_pubkey;
        for r in &results {
            assert_eq!(r.group_pubkey, first_group);
        }

        // Assemble SharePackages for the threshold set and produce a real
        // signature. If any DKG step corrupted a share this would fail at
        // aggregation time.
        let share_packages: Vec<SharePackage> = results
            .iter()
            .take(threshold as usize)
            .map(|r| {
                let metadata = crate::frost::ShareMetadata::new(
                    r.our_index,
                    threshold,
                    participants,
                    r.group_pubkey,
                    "dkg-test".into(),
                );
                SharePackage::new(metadata, &r.key_package, &r.public_key_package).unwrap()
            })
            .collect();

        let message = b"software dkg produces spendable shares";
        let sig = sign_with_local_shares(&share_packages, message).unwrap();
        assert_eq!(sig.len(), 64);
    }

    /// A version-tag mismatch on a peer's round1 package MUST refuse rather
    /// than silently mis-decoding a future / stranger wire format.
    #[test]
    fn round1_peer_refuses_bad_version() {
        let mut a = SoftwareDkgSession::init(2, 2, 1).unwrap();
        let mut b = SoftwareDkgSession::init(2, 2, 2).unwrap();
        let _ = a.round1().unwrap();
        let mut b_wire = b.round1().unwrap();
        b_wire.software_dkg_version = 99;
        let err = a
            .round1_peer(&b_wire)
            .expect_err("bad version must be refused");
        assert!(matches!(err, KeepError::Frost(_)));
    }

    /// A peer sending two round1 packages is refused; otherwise a hostile
    /// peer could bias the resulting key with a late substitution.
    #[test]
    fn duplicate_round1_package_from_peer_refused() {
        let mut a = SoftwareDkgSession::init(2, 2, 1).unwrap();
        let mut b = SoftwareDkgSession::init(2, 2, 2).unwrap();
        let _ = a.round1().unwrap();
        let b_wire = b.round1().unwrap();
        a.round1_peer(&b_wire).unwrap();
        let err = a
            .round1_peer(&b_wire)
            .expect_err("duplicate round1 must be refused");
        assert!(matches!(err, KeepError::Frost(_)));
    }

    /// Calling `round2` before every peer's round1 lands must refuse without
    /// destroying the state we already have.
    #[test]
    fn round2_before_full_round1_refuses() {
        let mut s = SoftwareDkgSession::init(2, 3, 1).unwrap();
        let _ = s.round1().unwrap();
        let err = s
            .round2()
            .expect_err("incomplete round1 -> round2 must be refused");
        assert!(matches!(err, KeepError::Frost(_)));
    }

    /// Invalid config (threshold above participants, threshold below 2, or
    /// out-of-range index) fails at init.
    #[test]
    fn init_rejects_bad_config() {
        assert!(SoftwareDkgSession::init(1, 3, 1).is_err());
        assert!(SoftwareDkgSession::init(4, 3, 1).is_err());
        assert!(SoftwareDkgSession::init(2, 3, 0).is_err());
        assert!(SoftwareDkgSession::init(2, 3, 4).is_err());
    }

    #[test]
    fn identifier_round_trip() {
        for idx in [1u16, 2, 5, 42, 255, 300, 1000, 65535] {
            let id = Identifier::try_from(idx).unwrap();
            assert_eq!(identifier_to_u16(&id), Some(idx));
        }
    }
}
