// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Mobile adapter for the shared DKG coordinator.
//!
//! keep-mobile no longer carries its own FROST driver or relay coordination: the
//! crypto rounds and the roster-authenticated publish/collect/confirm loops live
//! in [`keep_frost_net::dkg::run_software_dkg`], shared with the CLI so the two
//! cannot drift (`docs/DKG_CEREMONY.md` §4). This module only:
//!
//! - builds the authenticated [`DkgRoster`] from the invite-supplied config,
//! - wires a hardened [`ClientTransport`] (§7: pinned relays supplied by the
//!   caller, the configured SOCKS proxy, reconnect/ping/ban-on-mismatch relay
//!   options, and a disconnect on every exit path),
//! - adapts the coordinator's [`DkgPhase`] to the FFI [`DkgProgressUpdate`], and
//! - turns the finalized share into an encrypted bech32 export the caller stores.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use nostr_sdk::prelude::*;
use zeroize::Zeroizing;

use keep_core::frost::dkg::SoftwareDkgSession;
use keep_core::frost::{ShareExport, ShareMetadata, SharePackage};
use keep_frost_net::dkg::{
    frost_group_id, run_software_dkg, ClientTransport, DkgPhase, DkgProgress, DkgRoster,
};

use crate::error::KeepMobileError;
use crate::network::validate_relay_url;
use crate::types::{DkgConfig, DkgParticipant, DkgProgressUpdate, RosterVerification};

/// Reports DKG progress to the native layer. Implemented on the foreign side
/// (Kotlin) so setup UI can render live state without polling. Called from the
/// runtime thread; implementations must be non-blocking.
#[uniffi::export(with_foreign)]
pub trait DkgProgressCallback: Send + Sync {
    fn on_progress(&self, update: DkgProgressUpdate);
}

/// What a finalized mobile DKG hands back: the hex group pubkey and this device's
/// encrypted bech32 share export, ready to persist through the normal import path.
pub struct DkgResult {
    pub group_pubkey: String,
    pub share_export: String,
}

fn frost_err(msg: impl Into<String>) -> KeepMobileError {
    KeepMobileError::FrostError { msg: msg.into() }
}

/// Bridges the shared coordinator's [`DkgPhase`] to the FFI [`DkgProgressUpdate`].
/// `Complete` is intentionally NOT forwarded here: the caller fires it only after
/// the share is persisted, so the group never surfaces as ready before storage
/// succeeds (§6/§8).
struct CallbackProgress {
    cb: Arc<dyn DkgProgressCallback>,
}

impl DkgProgress for CallbackProgress {
    fn phase(&self, phase: DkgPhase) {
        let update = match phase {
            DkgPhase::Round1 { received, total } => DkgProgressUpdate::Round1 { received, total },
            DkgPhase::Round2 { received, total } => DkgProgressUpdate::Round2 { received, total },
            DkgPhase::Finalizing => DkgProgressUpdate::Finalizing,
            DkgPhase::Confirming { confirmed, total } => {
                DkgProgressUpdate::Confirming { confirmed, total }
            }
            DkgPhase::Complete { .. } => return,
        };
        self.cb.on_progress(update);
    }
}

fn to_u8(v: u16, label: &str) -> Result<u8, KeepMobileError> {
    u8::try_from(v).map_err(|_| frost_err(format!("{label} must be 1..=255, got {v}")))
}

/// Build the authenticated [`DkgRoster`] from the invite-supplied config: parse
/// each participant's per-group subkey pubkey, order strictly by index, and
/// derive the canonical `frost_group_id` over the ordered subkey strings — the
/// same identity path the CLI's `parse_roster_from_event` produces (§4), so a
/// mobile run and a CLI run of the same group agree on the roster and the
/// `d`-tag channel. Fails closed on a bad `(t, n)`, a duplicate/holed index, or
/// an unparseable pubkey.
fn build_roster(config: &DkgConfig) -> Result<DkgRoster, KeepMobileError> {
    let threshold = to_u8(config.threshold, "threshold")?;
    let participants = to_u8(config.participants, "participants")?;
    if threshold < 2 {
        return Err(frost_err("threshold must be at least 2"));
    }
    if participants < threshold {
        return Err(frost_err("participants must be >= threshold"));
    }
    if config.our_index < 1 || config.our_index > config.participants {
        return Err(frost_err(format!(
            "our index must be between 1 and {}",
            config.participants
        )));
    }
    if config.roster.len() != participants as usize {
        return Err(frost_err(format!(
            "roster carries {} entries but config claims {participants} participants",
            config.roster.len()
        )));
    }

    // Index -> raw pubkey string; reject duplicate or out-of-range indices.
    let mut by_str: BTreeMap<u16, String> = BTreeMap::new();
    for p in &config.roster {
        if p.index < 1 || p.index > config.participants {
            return Err(frost_err(format!("roster index {} out of range", p.index)));
        }
        if by_str.insert(p.index, p.pubkey.clone()).is_some() {
            return Err(frost_err(format!("duplicate roster index {}", p.index)));
        }
    }

    // Require indices exactly 1..=participants (no holes) and impose index order
    // on the strings fed to the group_id hash.
    let mut ordered_npubs: Vec<String> = Vec::with_capacity(participants as usize);
    let mut by_index: BTreeMap<u16, PublicKey> = BTreeMap::new();
    for idx in 1..=participants as u16 {
        let s = by_str
            .get(&idx)
            .ok_or_else(|| frost_err(format!("roster is missing participant index {idx}")))?;
        let pk = PublicKey::parse(s).map_err(|e| {
            frost_err(format!(
                "roster pubkey {s:?} for index {idx} is invalid: {e}"
            ))
        })?;
        // Distinct indices are not enough. An invite is attacker-supplied, and
        // repeating one key across two indices yields a roster that hash-binds
        // and authenticates while handing that holder two of the n shares, so a
        // "2-of-3" becomes spendable by them alone. Checked here, on the
        // verifying side, because the attacker never runs our group-create path.
        if by_index.values().any(|existing| existing == &pk) {
            return Err(frost_err(format!(
                "roster repeats one pubkey at index {idx}; every participant \
                 must hold a distinct key"
            )));
        }
        ordered_npubs.push(s.clone());
        by_index.insert(idx, pk);
    }

    let group_id = frost_group_id(&config.group_name, threshold, participants, &ordered_npubs);
    Ok(DkgRoster {
        threshold,
        participants,
        by_index,
        group_id,
    })
}

/// Render a `frost_group_id` as a short, human-comparable fingerprint: the first
/// eight bytes as uppercase hex in four space-separated pairs of bytes. Every
/// device that derives the same `frost_group_id` (same name, threshold, and
/// index-ordered members) renders the same string, so participants can read it
/// aloud out of band; a coordinator who slips an extra key into one device's
/// roster yields a different id there and the mismatch is visible.
fn group_id_fingerprint(group_id: &[u8; 32]) -> String {
    let mut out = String::with_capacity(19);
    for (i, b) in group_id[..8].iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push(' ');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// Assemble the coordinator's roster: index 1 is the coordinator, each collected
/// joiner subkey takes index i+2 in scan order. This is the roster-assembly
/// policy (§4) — kept in Rust rather than the UI so there is one place that
/// decides how indices map to keys. Every key is parsed and de-duplicated here so
/// a malformed or repeated subkey is refused before it reaches the wire; the
/// assembled roster is still validated by [`build_roster`] before the run.
pub(crate) fn assemble_roster(
    coordinator_pubkey: &str,
    joiner_pubkeys: &[String],
) -> Result<Vec<DkgParticipant>, KeepMobileError> {
    // FROST indices are u8, so cap the count before the u16 cast below can wrap
    // (65536 -> index 0). Fail closed here rather than leak a bad index downstream.
    if joiner_pubkeys.len() + 1 > u8::MAX as usize {
        return Err(frost_err(format!(
            "roster carries {} participants but at most {} are allowed",
            joiner_pubkeys.len() + 1,
            u8::MAX
        )));
    }
    let mut entries = Vec::with_capacity(joiner_pubkeys.len() + 1);
    let mut seen: Vec<PublicKey> = Vec::new();
    for (i, pk) in std::iter::once(coordinator_pubkey)
        .chain(joiner_pubkeys.iter().map(String::as_str))
        .enumerate()
    {
        let parsed = PublicKey::parse(pk)
            .map_err(|e| frost_err(format!("roster pubkey {pk:?} is invalid: {e}")))?;
        if seen.contains(&parsed) {
            return Err(frost_err(
                "roster repeats one pubkey; every participant must hold a distinct key",
            ));
        }
        seen.push(parsed);
        entries.push(DkgParticipant {
            index: (i + 1) as u16,
            pubkey: pk.to_string(),
        });
    }
    Ok(entries)
}

/// Validate a finalized roster the same way [`run_dkg`] does — index range and
/// uniqueness, duplicate-pubkey rejection, threshold/participant bounds — resolve
/// the verifying device's index by matching `our_pubkey`, and return a
/// human-comparable fingerprint of the canonical `frost_group_id`. This is the
/// single authenticated identity path for the setup UI: the fingerprint the user
/// reads aloud and the `d`-tag channel the run lands on are the same digest, so
/// the two cannot drift the way a UI-side recomputation did.
pub(crate) fn verify_roster(
    group_name: &str,
    threshold: u16,
    participants: u16,
    roster: &[DkgParticipant],
    our_pubkey: &str,
) -> Result<RosterVerification, KeepMobileError> {
    let our = PublicKey::parse(our_pubkey)
        .map_err(|e| frost_err(format!("this device's pubkey is invalid: {e}")))?;
    let our_index = roster
        .iter()
        .find(|p| PublicKey::parse(&p.pubkey).ok().as_ref() == Some(&our))
        .map(|p| p.index)
        .ok_or_else(|| frost_err("this device is not in the roster"))?;
    let config = DkgConfig {
        group_name: group_name.to_string(),
        threshold,
        participants,
        our_index,
        relays: Vec::new(),
        roster: roster.to_vec(),
    };
    let built = build_roster(&config)?;
    Ok(RosterVerification {
        fingerprint: group_id_fingerprint(&built.group_id),
        our_index,
    })
}

/// Encode the finalized share as an encrypted bech32 export, mirroring what the
/// hardware/import paths persist (the caller stores it through `import_share`).
fn export_share(
    result: &keep_core::frost::dkg::SoftwareDkgResult,
    config: &DkgConfig,
    name: &str,
    passphrase: &str,
    subkey_secret: [u8; 32],
) -> Result<String, KeepMobileError> {
    // C1/§3: persist the per-group signing subkey alongside the share, matching
    // the CLI path (frost_store_dkg_share). Without it a restored share cannot
    // sign this party's per-group events.
    let metadata = ShareMetadata::new(
        result.our_index,
        config.threshold,
        config.participants,
        result.group_pubkey,
        name.to_string(),
    )
    .with_group_subkey_secret(subkey_secret);
    let share_package =
        SharePackage::new(metadata, &result.key_package, &result.public_key_package)?;
    let passphrase = Zeroizing::new(passphrase.to_string());
    let export = ShareExport::from_share(&share_package, &passphrase)?;
    Ok(export.to_bech32()?)
}

/// Run a full relay-driven software DKG through the shared coordinator and return
/// this device's share export.
///
/// `subkey` is this device's per-group signing subkey (minted by
/// `frost_dkg_begin`); it MUST be the key the roster pins for `config.our_index`.
/// `relays` are the already TLS-verified/pinned relays (the caller's
/// `verify_and_pin_relays` output); `proxy` is the configured loopback SOCKS
/// proxy, if any. `cancel` is polled by the coordinator so a UI cancel aborts the
/// run promptly. The transport is disconnected on every exit path (§7).
#[allow(clippy::too_many_arguments)]
pub async fn run_dkg(
    subkey: &Keys,
    config: &DkgConfig,
    relays: &[String],
    proxy: Option<SocketAddr>,
    name: &str,
    passphrase: &str,
    timeout: Duration,
    cancel: &AtomicBool,
    progress: Arc<dyn DkgProgressCallback>,
) -> Result<DkgResult, KeepMobileError> {
    for relay in relays {
        validate_relay_url(relay)?;
    }

    let roster = build_roster(config)?;
    let our_index = config.our_index;

    // The subkey minted in `frost_dkg_begin` must be the one the roster pins for
    // our index, or every event we publish would be rejected by peers as
    // author-mismatched. Fail before touching the network.
    let expected = roster
        .expected_pubkey(our_index)
        .map_err(|e| frost_err(e.to_string()))?;
    if subkey.public_key() != *expected {
        return Err(frost_err(
            "this device's DKG subkey does not match the roster entry for our index; \
             re-run frost_dkg_begin and rebuild the roster",
        ));
    }

    progress.on_progress(DkgProgressUpdate::Connecting);

    let mut session = SoftwareDkgSession::init(config.threshold, config.participants, our_index)
        .map_err(|e| frost_err(format!("init DKG: {e}")))?;

    let transport = ClientTransport::connect_hardened(subkey, relays, proxy).await?;

    let sink = CallbackProgress {
        cb: progress.clone(),
    };
    let group = hex::encode(roster.group_id);
    let outcome = run_software_dkg(
        &mut session,
        &transport,
        subkey,
        &roster,
        &group,
        our_index,
        timeout,
        cancel,
        &sink,
    )
    .await;
    // Disconnect guard: the client has no Drop cleanup, so tear it down whether
    // the run succeeded, errored, or was cancelled (§7).
    transport.disconnect().await;
    let outcome = outcome?;

    let share_export = export_share(
        &outcome.result,
        config,
        name,
        passphrase,
        subkey.secret_key().secret_bytes(),
    )?;
    Ok(DkgResult {
        group_pubkey: hex::encode(outcome.result.group_pubkey),
        share_export,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DkgParticipant;

    fn subkey(seed: u8) -> Keys {
        let sk = nostr_sdk::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        Keys::new(sk.into())
    }

    /// Distinct key for any `n`, unlike `subkey` whose u8 seed tops out at 255
    /// usable values (seed 0 is an invalid secret key). Needed to build a roster
    /// of 256 all-distinct participants, the only way to reach the u8 cap without
    /// duplicate rejection firing first.
    fn subkey_n(n: u16) -> Keys {
        let mut b = [1u8; 32];
        b[0] = (n & 0xff) as u8;
        b[1] = (n >> 8) as u8;
        let sk = nostr_sdk::secp256k1::SecretKey::from_slice(&b).unwrap();
        Keys::new(sk.into())
    }

    fn config_with(
        threshold: u16,
        participants: u16,
        our_index: u16,
        roster: Vec<DkgParticipant>,
    ) -> DkgConfig {
        DkgConfig {
            group_name: "test".into(),
            threshold,
            participants,
            our_index,
            relays: vec!["wss://relay.example.com".into()],
            roster,
        }
    }

    fn roster_of(keys: &[Keys]) -> Vec<DkgParticipant> {
        keys.iter()
            .enumerate()
            .map(|(i, k)| DkgParticipant {
                index: (i + 1) as u16,
                pubkey: k.public_key().to_hex(),
            })
            .collect()
    }

    #[test]
    fn build_roster_accepts_a_consistent_invite() {
        let ks = [subkey(1), subkey(2), subkey(3)];
        let roster = build_roster(&config_with(2, 3, 1, roster_of(&ks))).unwrap();
        assert_eq!(roster.threshold, 2);
        assert_eq!(roster.participants, 3);
        assert_eq!(*roster.expected_pubkey(2).unwrap(), ks[1].public_key());
    }

    /// An invite listing one key at two indices must be refused. It would
    /// otherwise hash-bind and authenticate while giving that holder two of the
    /// n shares, so a "2-of-3" becomes spendable by them alone. The invite is
    /// attacker-supplied, so the check belongs here rather than only in the
    /// group-create path.
    #[test]
    fn build_roster_rejects_one_pubkey_at_two_indices() {
        let ks = [subkey(1), subkey(2), subkey(3)];
        let mut roster = roster_of(&ks);
        // Index 2 now repeats index 1's key.
        roster[1].pubkey = ks[0].public_key().to_hex();

        let err = build_roster(&config_with(2, 3, 1, roster))
            .expect_err("an invite repeating one pubkey must be rejected");
        assert!(
            format!("{err:?}").contains("distinct key"),
            "unexpected error: {err:?}"
        );
    }

    /// A hex invite and a bech32 invite describe the same group, so they must
    /// derive the same id; otherwise a mobile participant and a CLI participant
    /// land on different channels and never meet.
    #[test]
    fn build_roster_group_id_is_independent_of_pubkey_encoding() {
        let ks = [subkey(1), subkey(2)];
        let hex = roster_of(&ks);
        let bech32: Vec<DkgParticipant> = ks
            .iter()
            .enumerate()
            .map(|(i, k)| DkgParticipant {
                index: (i + 1) as u16,
                pubkey: k.public_key().to_bech32().unwrap(),
            })
            .collect();

        let a = build_roster(&config_with(2, 2, 1, hex)).unwrap();
        let b = build_roster(&config_with(2, 2, 1, bech32)).unwrap();
        assert_eq!(a.group_id, b.group_id);
    }

    #[test]
    fn build_roster_derives_the_same_group_id_regardless_of_entry_order() {
        let ks = [subkey(1), subkey(2), subkey(3)];
        let mut shuffled = roster_of(&ks);
        shuffled.reverse();
        let a = build_roster(&config_with(2, 3, 1, roster_of(&ks))).unwrap();
        let b = build_roster(&config_with(2, 3, 1, shuffled)).unwrap();
        assert_eq!(a.group_id, b.group_id);
    }

    #[test]
    fn build_roster_rejects_bad_shapes() {
        let ks = [subkey(1), subkey(2), subkey(3)];
        // threshold < 2
        assert!(build_roster(&config_with(1, 3, 1, roster_of(&ks))).is_err());
        // participants < threshold
        assert!(build_roster(&config_with(3, 2, 1, roster_of(&ks[..2]))).is_err());
        // our_index out of range
        assert!(build_roster(&config_with(2, 3, 9, roster_of(&ks))).is_err());
        // roster length mismatch
        assert!(build_roster(&config_with(2, 3, 1, roster_of(&ks[..2]))).is_err());
        // duplicate index
        let mut dup = roster_of(&ks);
        dup[2].index = 1;
        assert!(build_roster(&config_with(2, 3, 1, dup)).is_err());
        // hole (index 4 instead of 3)
        let mut hole = roster_of(&ks);
        hole[2].index = 4;
        assert!(build_roster(&config_with(2, 3, 1, hole)).is_err());
        // unparseable pubkey
        let mut bad = roster_of(&ks);
        bad[1].pubkey = "not-a-key".into();
        assert!(build_roster(&config_with(2, 3, 1, bad)).is_err());
    }

    #[test]
    fn assemble_roster_numbers_coordinator_first_then_joiners() {
        let ks = [subkey(1), subkey(2), subkey(3)];
        let joiners = vec![ks[1].public_key().to_hex(), ks[2].public_key().to_hex()];
        let roster = assemble_roster(&ks[0].public_key().to_hex(), &joiners).unwrap();
        assert_eq!(roster, roster_of(&ks));
    }

    #[test]
    fn assemble_roster_rejects_duplicate_and_invalid_keys() {
        let ks = [subkey(1), subkey(2)];
        // coordinator repeated as a joiner
        assert!(
            assemble_roster(&ks[0].public_key().to_hex(), &[ks[0].public_key().to_hex()]).is_err()
        );
        // unparseable joiner key
        assert!(assemble_roster(&ks[0].public_key().to_hex(), &["nope".into()]).is_err());
    }

    #[test]
    fn assemble_roster_rejects_more_than_u8_participants() {
        // 255 distinct joiners + coordinator = 256 participants overflows the u8
        // index. The keys must be distinct so the cap is what rejects the roster,
        // not duplicate detection firing first.
        let joiners: Vec<String> = (0..u8::MAX as u16)
            .map(|i| subkey_n(i).public_key().to_hex())
            .collect();
        assert_eq!(joiners.len(), u8::MAX as usize);
        assert!(assemble_roster(&subkey_n(1000).public_key().to_hex(), &joiners).is_err());
    }

    #[test]
    fn verify_roster_resolves_our_index_and_matches_group_id() {
        let ks = [subkey(1), subkey(2), subkey(3)];
        let roster = roster_of(&ks);
        let v = verify_roster("test", 2, 3, &roster, &ks[2].public_key().to_hex()).unwrap();
        assert_eq!(v.our_index, 3);
        let group_id = build_roster(&config_with(2, 3, 1, roster.clone()))
            .unwrap()
            .group_id;
        assert_eq!(v.fingerprint, group_id_fingerprint(&group_id));
        // bech32 pubkey must resolve to the same index as the hex form
        let bech = ks[1].public_key().to_bech32().unwrap();
        assert_eq!(
            verify_roster("test", 2, 3, &roster, &bech)
                .unwrap()
                .our_index,
            2
        );
    }

    #[test]
    fn verify_roster_rejects_outsider_and_bad_roster() {
        let ks = [subkey(1), subkey(2), subkey(3)];
        let roster = roster_of(&ks);
        // a device whose key is not in the roster
        assert!(verify_roster("test", 2, 3, &roster, &subkey(9).public_key().to_hex()).is_err());
        // duplicate pubkey across two indices is rejected by build_roster
        let mut dup = roster.clone();
        dup[2].pubkey = ks[0].public_key().to_hex();
        assert!(verify_roster("test", 2, 3, &dup, &ks[0].public_key().to_hex()).is_err());
    }

    #[test]
    fn group_id_fingerprint_is_four_uppercase_hex_pairs() {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&[0xAB, 0x12, 0xEF, 0x00, 0x9C, 0x34, 0x7D, 0x5E]);
        assert_eq!(group_id_fingerprint(&id), "AB12 EF00 9C34 7D5E");
    }
}
