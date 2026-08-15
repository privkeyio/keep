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
use crate::types::{DkgConfig, DkgProgressUpdate};

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
        let pk = PublicKey::parse(s)
            .map_err(|e| frost_err(format!("roster pubkey {s:?} for index {idx} is invalid: {e}")))?;
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

/// Encode the finalized share as an encrypted bech32 export, mirroring what the
/// hardware/import paths persist (the caller stores it through `import_share`).
fn export_share(
    result: &keep_core::frost::dkg::SoftwareDkgResult,
    config: &DkgConfig,
    name: &str,
    passphrase: &str,
) -> Result<String, KeepMobileError> {
    let metadata = ShareMetadata::new(
        result.our_index,
        config.threshold,
        config.participants,
        result.group_pubkey,
        name.to_string(),
    );
    let share_package = SharePackage::new(metadata, &result.key_package, &result.public_key_package)?;
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

    let mut session =
        SoftwareDkgSession::init(config.threshold, config.participants, our_index)
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

    let share_export = export_share(&outcome.result, config, name, passphrase)?;
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

    fn config_with(threshold: u16, participants: u16, our_index: u16, roster: Vec<DkgParticipant>) -> DkgConfig {
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
}
