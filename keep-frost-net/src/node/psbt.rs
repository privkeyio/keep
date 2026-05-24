// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! WDC PSBT coordination handlers (recovery tier / scriptpath spends).

use std::collections::HashSet;
use std::str::FromStr;

use bitcoin::hashes::Hash;
use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::error::{FrostNetError, Result};
use crate::event::KfpEventBuilder;
use crate::protocol::*;
use crate::psbt_session::{derive_psbt_session_id, SignerId, MAX_PSBT_SESSIONS_PER_PROPOSER};

use super::{sanitize_reason, KfpNode, KfpNodeEvent};

/// Read-only snapshot of a PSBT coordination session, safe for UI display.
///
/// Produced by [`KfpNode::psbt_session_snapshot`]. Returned `None` by the
/// accessor when the stored PSBT cannot be decoded (fail-closed); callers
/// must not offer any approval UI in that case.
#[derive(Debug, Clone)]
pub struct PsbtSessionSnapshot {
    pub session_id: [u8; 32],
    pub tier_index: u32,
    pub initiator_pubkey: PublicKey,
    pub psbt_hash: [u8; 32],
    pub output_count: u32,
    pub fee_sats: Option<u64>,
    pub network: String,
    pub threshold: u32,
    pub expected_signers_len: u32,
    /// Per-output (address string, value sats) decoded from the PSBT's
    /// unsigned transaction. Entries whose script does not yield a
    /// network-valid address are rendered as a hex script prefixed with
    /// `script:` so the UI surfaces *something* rather than dropping the
    /// output silently.
    pub outputs: Vec<(String, u64)>,
}

/// Maximum receive index accepted for a migration sweep destination. Bounds
/// the BIP-44 style gap: a sweep must pay an address within a sane window of
/// the new descriptor's used range, not an arbitrarily deep index.
const MAX_SWEEP_RECEIVE_INDEX: u32 = 1_000;

/// Reject a sweep whose fee exceeds `1 / MAX_SWEEP_FEE_FRACTION` of total input
/// value. Guards against a fee-griefing proposal that burns swept funds while
/// still passing the absolute `MAX_FEE_SATS` cap in the builder.
const MAX_SWEEP_FEE_FRACTION: u64 = 4;

impl KfpNode {
    /// Return a display-safe snapshot for the given PSBT session. Returns
    /// `None` if the session does not exist or the stored PSBT fails to
    /// decode.
    pub fn psbt_session_snapshot(&self, session_id: &[u8; 32]) -> Option<PsbtSessionSnapshot> {
        let sessions = self.psbt_sessions.read();
        let session = sessions.get_session(session_id)?;
        let initiator = *session.initiator()?;
        let descriptor_hash = *session.descriptor_hash();
        let (psbt_hash, output_count, fee_sats) =
            decode_psbt_for_snapshot(session.proposal_psbt())?;
        let network = self
            .descriptor_lookup
            .as_deref()
            .and_then(|l| l.network_for(&self.group_pubkey, &descriptor_hash))
            .unwrap_or_else(|| "unknown".to_string());
        let outputs = decode_psbt_outputs(session.proposal_psbt(), &network);
        Some(PsbtSessionSnapshot {
            session_id: *session.session_id(),
            tier_index: session.tier_index(),
            initiator_pubkey: initiator,
            psbt_hash,
            output_count,
            fee_sats,
            network,
            threshold: session.required_threshold(),
            expected_signers_len: session.expected_signers().len() as u32,
            outputs,
        })
    }
    /// Return the proposal PSBT bytes for the given session, or `None` if
    /// the session is unknown. Used by responders to reconstruct the
    /// script-spend sighash before forwarding it to a NIP-46 signer.
    pub fn psbt_session_proposal_psbt(&self, session_id: &[u8; 32]) -> Option<Vec<u8>> {
        self.psbt_sessions
            .read()
            .get_session(session_id)
            .map(|s| s.proposal_psbt().to_vec())
    }

    /// Return `(initiator_pubkey, descriptor_hash, tier_index)` for the given
    /// PSBT session, or `None` if the session is unknown or has no recorded
    /// initiator.
    pub fn psbt_session_routing(
        &self,
        session_id: &[u8; 32],
    ) -> Option<(PublicKey, [u8; 32], u32)> {
        let sessions = self.psbt_sessions.read();
        let session = sessions.get_session(session_id)?;
        let initiator = *session.initiator()?;
        Some((initiator, *session.descriptor_hash(), session.tier_index()))
    }

    /// Return the lowercase xpub fingerprints listed as expected external
    /// signers for the given PSBT session. Returns `None` if the session is
    /// unknown. Share-based signers are not included.
    pub fn psbt_session_expected_fingerprints(&self, session_id: &[u8; 32]) -> Option<Vec<String>> {
        let sessions = self.psbt_sessions.read();
        let session = sessions.get_session(session_id)?;
        Some(
            session
                .expected_signers()
                .iter()
                .filter_map(|s| match s {
                    crate::psbt_session::SignerId::Fingerprint(fp) => Some(fp.clone()),
                    _ => None,
                })
                .collect(),
        )
    }

    /// Propose a migration sweep: consolidate every UTXO under the OLD
    /// descriptor (spent via the `tier_index` recovery scriptpath) into a
    /// single output paying a fresh receive address derived from the NEW
    /// descriptor of the completed migration `session_id`.
    ///
    /// Preconditions, enforced fail-closed:
    ///   - the migration session must be `Complete` with a finalized descriptor;
    ///   - the NEW descriptor must be persisted and version-linked, i.e. its
    ///     canonical hash resolves via the configured `descriptor_lookup`
    ///     (the `previous_descriptor_hash` chain is written when the migrate
    ///     link is processed);
    ///   - the supplied `old_recovery` must resolve to the descriptor
    ///     identified by `old_descriptor_hash`: the recovery output's
    ///     `script_pubkey` is compared against the finalized OLD descriptor's
    ///     output script and a mismatch is rejected, so a proposer cannot
    ///     sweep coins from an unrelated recovery output.
    ///
    /// The sweep is driven through the existing [`Self::request_psbt_spend`]
    /// coordination keyed on `old_descriptor_hash`, so peers correlate it with
    /// the descriptor bump via the migrate link that already references the
    /// same migration `session_id`.
    ///
    /// Returns the derived PSBT session id.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_descriptor_migration_sweep(
        &self,
        migration_session_id: [u8; 32],
        old_descriptor_hash: [u8; 32],
        old_recovery: &keep_bitcoin::RecoveryOutput,
        tier_index: u32,
        utxos: Vec<keep_bitcoin::SweepUtxo>,
        new_receive_index: u32,
        fee_sats: u64,
        required_threshold: u32,
        expected_share_signers: Vec<u16>,
        expected_fingerprints: Vec<String>,
        timeout_secs: Option<u64>,
    ) -> Result<[u8; 32]> {
        if utxos.is_empty() {
            return Err(FrostNetError::Session(
                "migration sweep requires at least one UTXO".into(),
            ));
        }
        if new_receive_index > MAX_SWEEP_RECEIVE_INDEX {
            return Err(FrostNetError::Session(format!(
                "new receive index {new_receive_index} exceeds gap limit {MAX_SWEEP_RECEIVE_INDEX}"
            )));
        }

        // 1. Resolve the completed migration session and its finalized NEW
        //    descriptor in a single lock scope so every field derives from one
        //    consistent snapshot. Require Complete state so we never sweep into
        //    a descriptor the group has not fully validated.
        let (new_external, new_internal, new_network, new_policy_hash, new_version) = {
            let sessions = self.descriptor_sessions.read();
            let session = sessions
                .get_session(&migration_session_id)
                .ok_or_else(|| FrostNetError::Session("unknown migration session".into()))?;
            if session.group_pubkey() != &self.group_pubkey {
                return Err(FrostNetError::Session(
                    "migration session belongs to a different group".into(),
                ));
            }
            if !matches!(
                session.state(),
                crate::descriptor_session::DescriptorSessionState::Complete
            ) {
                return Err(FrostNetError::Session(
                    "migration session is not Complete; refusing to sweep into an unfinalized descriptor".into(),
                ));
            }
            let finalized = session.descriptor().ok_or_else(|| {
                FrostNetError::Session("migration session has no finalized descriptor".into())
            })?;
            (
                finalized.external.clone(),
                finalized.internal.clone(),
                session.network().to_string(),
                finalized.policy_hash,
                session.policy().version,
            )
        };

        // 2. Require the NEW descriptor be persisted + version-linked. The hash
        //    is recomputed from the finalized session data and must resolve via
        //    the descriptor lookup (which reads the same store the migrate link
        //    writes `previous_descriptor_hash` lineage into).
        let new_descriptor_hash = keep_core::wallet::canonical_descriptor_hash(
            &new_external,
            &new_internal,
            &new_policy_hash,
            new_version,
        )
        .map_err(|e| FrostNetError::Session(format!("canonical descriptor hash failed: {e}")))?;
        let lookup = self.descriptor_lookup.as_deref().ok_or_else(|| {
            FrostNetError::Session(
                "no descriptor lookup configured; cannot confirm the new descriptor is persisted before sweeping".into(),
            )
        })?;
        if !lookup.find_by_hash(&self.group_pubkey, &new_descriptor_hash) {
            return Err(FrostNetError::Session(
                "new descriptor is not persisted (version-linked); finalize and store it before proposing a sweep".into(),
            ));
        }

        let network = bitcoin::Network::from_str(&new_network)
            .map_err(|e| FrostNetError::Session(format!("invalid network {new_network}: {e}")))?;

        // 3. Bind `old_recovery` to `old_descriptor_hash`. The PSBT body
        //    (witness_utxo script, tap_scripts, control blocks) is built
        //    entirely from `old_recovery`, while authorization keys only on
        //    `old_descriptor_hash`. Without this check a proposer could sweep
        //    coins from an unrelated recovery output that the group never
        //    finalized. Resolve the finalized OLD descriptor by hash and require
        //    its output script equal the recovery output's script_pubkey.
        let old_external = self
            .external_descriptor_for_hash(&old_descriptor_hash)?
            .ok_or_else(|| {
                FrostNetError::Session(
                    "old_descriptor_hash does not resolve to a finalized descriptor for this group"
                        .into(),
                )
            })?;
        let old_spk = keep_bitcoin::descriptor_script_pubkey(&old_external)
            .map_err(|e| FrostNetError::Session(format!("old descriptor script_pubkey: {e}")))?;
        if old_spk != old_recovery.address.script_pubkey() {
            return Err(FrostNetError::Session(
                "old_recovery output does not match the descriptor identified by old_descriptor_hash"
                    .into(),
            ));
        }

        // 4. Derive the fresh NEW receive address once and reuse it for both the
        //    PSBT destination and the display output so they cannot diverge.
        let dest_addr = keep_bitcoin::address_at(&new_external, new_receive_index, network)
            .map_err(|e| FrostNetError::Session(format!("new receive address: {e}")))?;
        let destination = dest_addr.script_pubkey();

        // 5. Bound the fee relative to total input value before building, so a
        //    fee-griefing proposal is rejected ahead of the looser absolute cap
        //    enforced inside the builder.
        let total_in: u64 = utxos
            .iter()
            .try_fold(0u64, |acc, u| acc.checked_add(u.value_sats))
            .ok_or_else(|| FrostNetError::Session("sweep input value overflow".into()))?;
        let fee_cap = total_in / MAX_SWEEP_FEE_FRACTION;
        if fee_sats > fee_cap {
            return Err(FrostNetError::Session(format!(
                "sweep fee {fee_sats} exceeds 1/{MAX_SWEEP_FEE_FRACTION} of total input {total_in}"
            )));
        }

        // 6. Build the consolidating sweep PSBT under the OLD recovery tier.
        let builder = keep_bitcoin::RecoveryTxBuilder::new(old_recovery.clone());
        let psbt = builder
            .build_sweep_psbt(tier_index as usize, &utxos, &destination, fee_sats)
            .map_err(|e| FrostNetError::Session(format!("sweep PSBT build failed: {e}")))?;
        let psbt_bytes = psbt.serialize();

        let inputs: Vec<PsbtInputInfo> = utxos
            .iter()
            .enumerate()
            .map(|(i, u)| PsbtInputInfo {
                index: i as u32,
                value_sats: u.value_sats,
                address: None,
            })
            .collect();
        let outputs = vec![PsbtOutputInfo {
            index: 0,
            value_sats: total_in.saturating_sub(fee_sats),
            address: Some(dest_addr.to_string()),
            is_change: false,
        }];

        info!(
            migration_session_id = %hex::encode(migration_session_id),
            old_descriptor_hash = %hex::encode(old_descriptor_hash),
            new_descriptor_hash = %hex::encode(new_descriptor_hash),
            utxos = utxos.len(),
            "Proposing migration sweep"
        );

        // 7. Drive through the existing PSBT propose/sign coordination.
        self.request_psbt_spend(
            old_descriptor_hash,
            tier_index,
            psbt_bytes,
            fee_sats,
            required_threshold,
            expected_share_signers,
            expected_fingerprints,
            inputs,
            outputs,
            timeout_secs,
        )
        .await
    }

    /// Propose a PSBT for a recovery tier spend. Publishes `PsbtPropose` to all
    /// expected signers over NIP-44 encrypted channel.
    ///
    /// Returns the derived session id.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_psbt_spend(
        &self,
        descriptor_hash: [u8; 32],
        tier_index: u32,
        psbt: Vec<u8>,
        fee_sats: u64,
        required_threshold: u32,
        expected_share_signers: Vec<u16>,
        expected_fingerprints: Vec<String>,
        inputs: Vec<PsbtInputInfo>,
        outputs: Vec<PsbtOutputInfo>,
        timeout_secs: Option<u64>,
    ) -> Result<[u8; 32]> {
        if expected_share_signers.is_empty() && expected_fingerprints.is_empty() {
            return Err(FrostNetError::Session(
                "Must specify at least one expected signer".into(),
            ));
        }

        if descriptor_hash == [0u8; 32] {
            return Err(FrostNetError::Session(
                "descriptor_hash is the placeholder all-zero hash; refusing to propose a PSBT for an un-coordinated descriptor".into(),
            ));
        }

        let our_index = self.share.metadata.identifier;
        self.check_psbt_proposer_authorized(our_index)?;
        self.check_psbt_proposer_session_budget(&self.keys.public_key())?;

        let created_at = Timestamp::now().as_secs();
        let session_id = derive_psbt_session_id(
            &self.group_pubkey,
            &descriptor_hash,
            tier_index,
            &psbt,
            created_at,
        );

        let expected_fingerprints: Vec<String> = expected_fingerprints
            .into_iter()
            .map(|fp| fp.to_ascii_lowercase())
            .collect();

        self.reject_dual_identity_signers(&expected_share_signers, &expected_fingerprints)?;

        let signers: HashSet<SignerId> = expected_share_signers
            .iter()
            .map(|idx| SignerId::Share(*idx))
            .chain(
                expected_fingerprints
                    .iter()
                    .map(|fp| SignerId::Fingerprint(fp.clone())),
            )
            .collect();

        let session_timeout = timeout_secs.map(std::time::Duration::from_secs);

        let mut payload = PsbtProposePayload::new(
            session_id,
            self.group_pubkey,
            descriptor_hash,
            tier_index,
            psbt.clone(),
            fee_sats,
            required_threshold,
            created_at,
        )
        .with_inputs(inputs)
        .with_outputs(outputs)
        .with_expected_signers(expected_share_signers)
        .with_expected_fingerprints(expected_fingerprints);
        if let Some(t) = timeout_secs {
            payload = payload.with_timeout(t);
        }

        let msg = KfpMessage::PsbtPropose(payload);
        msg.validate()
            .map_err(|e| FrostNetError::Protocol(e.to_string()))?;

        {
            let mut sessions = self.psbt_sessions.write();
            let session = sessions.create_session(
                session_id,
                self.group_pubkey,
                descriptor_hash,
                tier_index,
                psbt,
                required_threshold,
                signers.clone(),
                session_timeout,
            )?;
            session.set_initiator(self.keys.public_key());
        }

        let expected_signers = signers;
        let online = self.bidirectional_online_peers();
        let target_peers: Vec<PublicKey> = {
            let peers = self.peers.read();
            online
                .into_iter()
                .filter(|pk| {
                    let Some(peer) = peers.get_peer_by_pubkey(pk) else {
                        return false;
                    };
                    expected_signers.iter().any(|sid| match sid {
                        SignerId::Share(idx) => peer.share_index == *idx,
                        SignerId::Fingerprint(fp) => {
                            peer.recovery_xpubs.iter().any(|x| &x.fingerprint == fp)
                        }
                    })
                })
                .collect()
        };
        if target_peers.is_empty() {
            self.psbt_sessions.write().remove_session(&session_id);
            return Err(FrostNetError::Session(
                "No online expected signers to coordinate PSBT with".into(),
            ));
        }

        let (reached, broadcast_err) = self
            .broadcast_psbt_event_partial(&msg, &session_id, "psbt_propose", &target_peers)
            .await;
        if let Some(err) = broadcast_err {
            // Best-effort abort for peers that did receive the proposal so
            // they don't keep the session alive while we consider it failed.
            self.best_effort_abort(
                &session_id,
                &reached,
                "proposer aborting after partial broadcast failure",
            )
            .await;
            self.psbt_sessions.write().remove_session(&session_id);
            return Err(err);
        }

        let _ = self.event_tx.send(KfpNodeEvent::PsbtProposed {
            session_id,
            tier_index,
        });

        info!(
            session_id = %hex::encode(session_id),
            tier_index,
            "PSBT coordination started"
        );

        Ok(session_id)
    }

    pub(crate) async fn handle_psbt_propose(
        &self,
        sender: PublicKey,
        payload: PsbtProposePayload,
    ) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }
        if !self.can_receive_from(&sender) {
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {sender} not allowed to send PSBT proposals"
            )));
        }
        if !payload.is_within_replay_window(self.replay_window_secs) {
            return Err(FrostNetError::ReplayDetected(
                "PSBT proposal outside replay window".into(),
            ));
        }

        let sender_share_index = {
            let peers = self.peers.read();
            let peer = peers.get_peer_by_pubkey(&sender).ok_or_else(|| {
                FrostNetError::UntrustedPeer(format!("PSBT proposal from unknown peer: {sender}"))
            })?;
            peer.share_index
        };
        self.verify_peer_share_index(sender, sender_share_index)?;
        self.check_psbt_proposer_authorized(sender_share_index)?;
        self.check_psbt_proposer_session_budget(&sender)?;

        let expected_id = derive_psbt_session_id(
            &payload.group_pubkey,
            &payload.descriptor_hash,
            payload.tier_index,
            &payload.psbt,
            payload.created_at,
        );
        if payload.session_id != expected_id {
            return Err(FrostNetError::Session(
                "PSBT session_id does not match derived value".into(),
            ));
        }

        self.verify_descriptor_hash_against_stored(&payload.descriptor_hash)?;

        self.reject_dual_identity_signers(
            &payload.expected_signers,
            &payload.expected_fingerprints,
        )?;

        let signers: HashSet<SignerId> = payload
            .expected_signers
            .iter()
            .map(|idx| SignerId::Share(*idx))
            .chain(
                payload
                    .expected_fingerprints
                    .iter()
                    .map(|fp| SignerId::Fingerprint(fp.clone())),
            )
            .collect();

        let propose_timeout = match payload.timeout_secs {
            None => None,
            Some(t) if (1..=PSBT_SESSION_MAX_TIMEOUT_SECS).contains(&t) => {
                Some(std::time::Duration::from_secs(t))
            }
            Some(t) => {
                return Err(FrostNetError::Session(format!(
                    "Invalid PSBT proposal timeout {t}s, must be 1..={PSBT_SESSION_MAX_TIMEOUT_SECS}"
                )));
            }
        };

        let session_created = {
            let mut sessions = self.psbt_sessions.write();
            match sessions.create_session(
                payload.session_id,
                self.group_pubkey,
                payload.descriptor_hash,
                payload.tier_index,
                payload.psbt.clone(),
                payload.required_threshold,
                signers,
                propose_timeout,
            ) {
                Ok(session) => {
                    session.set_initiator(sender);
                    true
                }
                Err(e) => {
                    warn!(
                        session_id = %hex::encode(payload.session_id),
                        error = %e,
                        "PSBT session creation failed"
                    );
                    let _ = self.event_tx.send(KfpNodeEvent::PsbtAborted {
                        session_id: payload.session_id,
                        reason: format!("session creation failed: {e}"),
                    });
                    false
                }
            }
        };

        if !session_created {
            return Ok(());
        }

        let _ = self.event_tx.send(KfpNodeEvent::PsbtProposed {
            session_id: payload.session_id,
            tier_index: payload.tier_index,
        });

        let our_index = self.share.metadata.identifier;
        let our_fingerprints = self.own_recovery_fingerprints();
        let we_are_share_signer = payload.expected_signers.contains(&our_index);
        let we_are_external_signer = payload
            .expected_fingerprints
            .iter()
            .any(|fp| our_fingerprints.contains(fp));
        if we_are_share_signer || we_are_external_signer {
            let _ = self.event_tx.send(KfpNodeEvent::PsbtSignatureNeeded {
                session_id: payload.session_id,
                tier_index: payload.tier_index,
                initiator_pubkey: sender,
            });
        } else {
            debug!("We are not an expected signer for this PSBT tier");
        }

        Ok(())
    }

    /// Collect online peers we can both send to and receive from.
    fn bidirectional_online_peers(&self) -> Vec<PublicKey> {
        let peers = self.peers.read();
        peers
            .get_online_peers()
            .iter()
            .filter(|p| self.can_send_to(&p.pubkey) && self.can_receive_from(&p.pubkey))
            .map(|p| p.pubkey)
            .collect()
    }

    /// Encrypt and send a PSBT coordination message to each target peer.
    /// Attempts every target even if some fail. Returns the list of peers the
    /// event was successfully delivered to, alongside any aggregated error.
    /// Callers with initiator responsibilities may use the reached-peer list
    /// to best-effort abort partially-broadcast sessions.
    async fn broadcast_psbt_event_partial(
        &self,
        msg: &KfpMessage,
        session_id: &[u8; 32],
        msg_type: &'static str,
        targets: &[PublicKey],
    ) -> (Vec<PublicKey>, Option<FrostNetError>) {
        let mut reached: Vec<PublicKey> = Vec::new();
        let mut failures: Vec<(PublicKey, String)> = Vec::new();
        for pubkey in targets {
            let send_result: Result<()> = async {
                let event = KfpEventBuilder::psbt_event(
                    &self.keys,
                    pubkey,
                    &self.group_pubkey,
                    session_id,
                    msg_type,
                    msg,
                )?;
                self.client
                    .send_event(&event)
                    .await
                    .map_err(|e| FrostNetError::Transport(e.to_string()))?;
                Ok(())
            }
            .await;
            match send_result {
                Ok(()) => reached.push(*pubkey),
                Err(e) => {
                    warn!(
                        session_id = %hex::encode(session_id),
                        msg_type,
                        peer = %pubkey,
                        error = %e,
                        "PSBT broadcast to peer failed"
                    );
                    failures.push((*pubkey, e.to_string()));
                }
            }
        }
        let err = if failures.is_empty() {
            None
        } else {
            let detail = failures
                .iter()
                .map(|(pk, err)| format!("{pk}: {err}"))
                .collect::<Vec<_>>()
                .join("; ");
            Some(FrostNetError::Transport(format!(
                "PSBT {msg_type} broadcast failed for {}/{} peers: {detail}",
                failures.len(),
                targets.len()
            )))
        };
        (reached, err)
    }

    /// Thin wrapper over `broadcast_psbt_event_partial` that discards the
    /// reached-peer list and returns an error if any send failed.
    async fn broadcast_psbt_event(
        &self,
        msg: &KfpMessage,
        session_id: &[u8; 32],
        msg_type: &'static str,
        targets: &[PublicKey],
    ) -> Result<()> {
        let (_, err) = self
            .broadcast_psbt_event_partial(msg, session_id, msg_type, targets)
            .await;
        if let Some(e) = err {
            return Err(e);
        }
        Ok(())
    }

    /// Best-effort send `PsbtAbort` to the given peers. Errors are logged and
    /// swallowed since this runs as rollback from a failed broadcast and must
    /// not mask the original failure.
    async fn best_effort_abort(&self, session_id: &[u8; 32], peers: &[PublicKey], reason: &str) {
        if peers.is_empty() {
            return;
        }
        let payload = PsbtAbortPayload::new(*session_id, self.group_pubkey, reason);
        let msg = KfpMessage::PsbtAbort(payload);
        let (_, err) = self
            .broadcast_psbt_event_partial(&msg, session_id, "psbt_abort", peers)
            .await;
        if let Some(e) = err {
            warn!(
                session_id = %hex::encode(session_id),
                error = %e,
                "best-effort PSBT abort broadcast had failures",
            );
        }
    }

    fn check_psbt_proposer_session_budget(&self, proposer: &PublicKey) -> Result<()> {
        let active = self
            .psbt_sessions
            .read()
            .active_sessions_by_proposer(proposer);
        if active >= MAX_PSBT_SESSIONS_PER_PROPOSER {
            return Err(FrostNetError::Session(format!(
                "Proposer already has {active} active PSBT session(s); limit is {MAX_PSBT_SESSIONS_PER_PROPOSER}"
            )));
        }
        Ok(())
    }

    fn reject_dual_identity_signers(
        &self,
        expected_share_signers: &[u16],
        expected_fingerprints: &[String],
    ) -> Result<()> {
        let peers = self.peers.read();
        for idx in expected_share_signers {
            let Some(peer) = peers.get_peer(*idx) else {
                continue;
            };
            for xpub in &peer.recovery_xpubs {
                let fp_lc = xpub.fingerprint.to_ascii_lowercase();
                if expected_fingerprints.contains(&fp_lc) {
                    return Err(FrostNetError::Session(format!(
                        "Dual-identity signer rejected: share {idx} and fingerprint {fp_lc} resolve to the same peer"
                    )));
                }
            }
        }
        Ok(())
    }

    fn check_psbt_proposer_authorized(&self, share_index: u16) -> Result<()> {
        let proposers = self.psbt_proposers.read();
        if !proposers.is_empty() && !proposers.contains(&share_index) {
            return Err(FrostNetError::Session(format!(
                "Share {share_index} is not authorized to propose PSBTs"
            )));
        }
        Ok(())
    }

    /// Resolve the external descriptor string of the finalized descriptor whose
    /// canonical hash equals `descriptor_hash`, scanning in-memory sessions for
    /// this group. Returns `None` if no finalized descriptor matches.
    fn external_descriptor_for_hash(&self, descriptor_hash: &[u8; 32]) -> Result<Option<String>> {
        let sessions = self.descriptor_sessions.read();
        for (_, session) in sessions.iter_sessions() {
            if session.group_pubkey() != &self.group_pubkey {
                continue;
            }
            let Some(finalized) = session.descriptor() else {
                continue;
            };
            let expected = keep_core::wallet::canonical_descriptor_hash(
                &finalized.external,
                &finalized.internal,
                &finalized.policy_hash,
                session.policy().version,
            )
            .map_err(|e| {
                FrostNetError::Session(format!("canonical descriptor hash failed: {e}"))
            })?;
            if &expected == descriptor_hash {
                return Ok(Some(finalized.external.clone()));
            }
        }
        Ok(None)
    }

    fn verify_descriptor_hash_against_stored(&self, descriptor_hash: &[u8; 32]) -> Result<()> {
        let (in_memory_match, saw_any_finalized) = {
            let sessions = self.descriptor_sessions.read();
            let mut saw_any_finalized = false;
            let mut matched = false;
            for (_, session) in sessions.iter_sessions() {
                if session.group_pubkey() != &self.group_pubkey {
                    continue;
                }
                let Some(finalized) = session.descriptor() else {
                    continue;
                };
                saw_any_finalized = true;
                let expected = keep_core::wallet::canonical_descriptor_hash(
                    &finalized.external,
                    &finalized.internal,
                    &finalized.policy_hash,
                    session.policy().version,
                )
                .map_err(|e| {
                    FrostNetError::Session(format!("canonical descriptor hash failed: {e}"))
                })?;
                if &expected == descriptor_hash {
                    matched = true;
                    break;
                }
            }
            (matched, saw_any_finalized)
        };

        decide_descriptor_hash_verification(
            in_memory_match,
            saw_any_finalized,
            &self.group_pubkey,
            descriptor_hash,
            self.descriptor_lookup.as_deref(),
        )
    }

    fn own_recovery_fingerprints(&self) -> HashSet<String> {
        self.local_recovery_xpubs
            .read()
            .iter()
            .map(|x| x.fingerprint.clone())
            .collect()
    }

    /// Submit a partial signature for a PSBT session. The caller provides the
    /// PSBT with their signature merged in (e.g. via
    /// `RecoveryTxBuilder::sign_recovery`) and the local signer identity.
    pub async fn contribute_psbt_signature(
        &self,
        session_id: [u8; 32],
        initiator_pubkey: &PublicKey,
        signer: SignerId,
        merged_psbt: Vec<u8>,
    ) -> Result<()> {
        let (share_index, fingerprint) = match &signer {
            SignerId::Share(i) => (Some(*i), None),
            SignerId::Fingerprint(fp) => (None, Some(fp.clone())),
        };

        let payload = PsbtSignPayload::new(
            session_id,
            self.group_pubkey,
            share_index,
            fingerprint,
            merged_psbt.clone(),
        );

        let msg = KfpMessage::PsbtSign(payload);

        // SEC/cancel-safety: send the wire event FIRST, then commit to the
        // local session. The previous order (commit-then-send) leaked a
        // dangling local signature when the awaiting task was cancelled
        // between the two steps. Swapping the order means that on a
        // user-triggered retry of a cancelled `contribute_psbt_signature`
        // the local `add_signature` call may return "Duplicate signature",
        // which is the correct behavior since the peer has already counted
        // our contribution once.
        let event = KfpEventBuilder::psbt_event(
            &self.keys,
            initiator_pubkey,
            &self.group_pubkey,
            &session_id,
            "psbt_sign",
            &msg,
        )?;

        self.client
            .send_event(&event)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        {
            let mut sessions = self.psbt_sessions.write();
            let session = sessions
                .get_session_mut(&session_id)
                .ok_or_else(|| FrostNetError::Session("unknown PSBT session".into()))?;
            session.add_signature(signer.clone(), merged_psbt.clone())?;
        }

        info!(session_id = %hex::encode(session_id), "Sent PSBT signature contribution");
        Ok(())
    }

    pub(crate) async fn handle_psbt_sign(
        &self,
        sender: PublicKey,
        payload: PsbtSignPayload,
    ) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }
        if !self.can_receive_from(&sender) {
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {sender} not allowed to send PSBT signatures"
            )));
        }
        if !payload.is_within_replay_window(self.replay_window_secs) {
            return Err(FrostNetError::ReplayDetected(
                "PSBT signature outside replay window".into(),
            ));
        }

        let signer = match (
            payload.signer_share_index,
            payload.signer_fingerprint.clone(),
        ) {
            (Some(_), Some(_)) => {
                return Err(FrostNetError::Session(
                    "PsbtSign must set exactly one of signer_share_index or signer_fingerprint"
                        .into(),
                ));
            }
            (Some(idx), None) => {
                self.verify_peer_share_index(sender, idx)?;
                SignerId::Share(idx)
            }
            (None, Some(fp)) => {
                let fp = fp.to_ascii_lowercase();
                let sender_fingerprints = {
                    let peers = self.peers.read();
                    let peer = peers.get_peer_by_pubkey(&sender).ok_or_else(|| {
                        FrostNetError::UntrustedPeer(format!(
                            "PsbtSign from unknown peer: {sender}"
                        ))
                    })?;
                    peer.recovery_xpubs
                        .iter()
                        .map(|x| x.fingerprint.to_ascii_lowercase())
                        .collect::<HashSet<_>>()
                };
                if !sender_fingerprints.contains(&fp) {
                    return Err(FrostNetError::Session(format!(
                        "PsbtSign fingerprint {fp} is not owned by sender {sender}"
                    )));
                }
                SignerId::Fingerprint(fp)
            }
            (None, None) => {
                return Err(FrostNetError::Session(
                    "PsbtSign missing signer identity".into(),
                ));
            }
        };

        let (count, threshold, should_finalize, aggregated_psbt, aggregation_error) = {
            let mut sessions = self.psbt_sessions.write();
            let session = sessions
                .get_session_mut(&payload.session_id)
                .ok_or_else(|| FrostNetError::Session("unknown PSBT session".into()))?;

            session.add_signature(signer.clone(), payload.psbt)?;

            let is_initiator = session.initiator() == Some(&self.keys.public_key());
            // Defensive: only attempt to finalize once threshold is met.
            // `begin_finalize` already gates on threshold_met(), but spell
            // it out here so the invariant survives future refactors of
            // PsbtSession.
            let threshold_met = (session.signature_count() as u32) >= session.required_threshold();
            let should_finalize = is_initiator && threshold_met && session.begin_finalize();
            let (aggregated, agg_err) = if should_finalize {
                match aggregate_partial_psbts(
                    session.proposal_psbt(),
                    session.partial_psbts(),
                    session.required_threshold(),
                ) {
                    Ok(bytes) => (Some(bytes), None),
                    Err(e) => {
                        warn!(
                            session_id = %hex::encode(payload.session_id),
                            error = %e,
                            "Auto-finalize aggregation failed; aborting session"
                        );
                        session.clear_finalizing();
                        (None, Some(e.to_string()))
                    }
                }
            } else {
                (None, None)
            };
            (
                session.signature_count(),
                session.required_threshold(),
                should_finalize && aggregated.is_some(),
                aggregated,
                agg_err,
            )
        };

        if let Some(err) = aggregation_error {
            let reason = format!("aggregation failed: {err}");
            let _ = self.abort_psbt_session(payload.session_id, &reason).await;
        }

        let _ = self.event_tx.send(KfpNodeEvent::PsbtSignatureReceived {
            session_id: payload.session_id,
            signer,
            signature_count: count,
            threshold,
        });

        if should_finalize {
            if let Some(finalized_psbt) = aggregated_psbt {
                if let Err(e) = self
                    .finalize_psbt_session(payload.session_id, finalized_psbt, None)
                    .await
                {
                    warn!(
                        session_id = %hex::encode(payload.session_id),
                        error = %e,
                        "Initiator auto-finalize failed"
                    );
                }
            }
        }

        Ok(())
    }

    /// Mark the session Finalized and broadcast the finalized PSBT / signed tx
    /// to all participants. Typically called by the proposer once threshold is met.
    pub async fn finalize_psbt_session(
        &self,
        session_id: [u8; 32],
        finalized_psbt: Vec<u8>,
        final_tx: Option<(Vec<u8>, [u8; 32])>,
    ) -> Result<()> {
        let txid = final_tx.as_ref().map(|(_, id)| *id);

        let (expected_signers, initiator) = {
            let sessions = self.psbt_sessions.read();
            let session = sessions
                .get_session(&session_id)
                .ok_or_else(|| FrostNetError::Session("unknown PSBT session".into()))?;
            (
                session.expected_signers().clone(),
                session.initiator().copied(),
            )
        };

        if initiator != Some(self.keys.public_key()) {
            return Err(FrostNetError::PolicyViolation(
                "Only the session initiator may finalize the PSBT".into(),
            ));
        }

        let mut payload =
            PsbtFinalizePayload::new(session_id, self.group_pubkey, finalized_psbt.clone());
        if let Some((tx, id)) = final_tx.clone() {
            payload = payload.with_final_tx(tx, id);
        }
        let msg = KfpMessage::PsbtFinalize(payload);

        let online = self.bidirectional_online_peers();
        let target_peers: Vec<PublicKey> = {
            let peers = self.peers.read();
            online
                .into_iter()
                .filter(|pk| {
                    if Some(*pk) == initiator {
                        return true;
                    }
                    let Some(peer) = peers.get_peer_by_pubkey(pk) else {
                        return false;
                    };
                    expected_signers.iter().any(|sid| match sid {
                        SignerId::Share(idx) => peer.share_index == *idx,
                        SignerId::Fingerprint(fp) => {
                            peer.recovery_xpubs.iter().any(|x| &x.fingerprint == fp)
                        }
                    })
                })
                .collect()
        };

        // Broadcast before flipping local state so a broadcast failure doesn't
        // leave peers in the dark while we believe the session is finalized.
        let (_reached, broadcast_err) = self
            .broadcast_psbt_event_partial(&msg, &session_id, "psbt_finalize", &target_peers)
            .await;
        if let Some(e) = &broadcast_err {
            warn!(
                session_id = %hex::encode(session_id),
                error = %e,
                "finalize broadcast had failures; committing local state anyway so caller sees finalization",
            );
        }

        {
            let mut sessions = self.psbt_sessions.write();
            let session = sessions
                .get_session_mut(&session_id)
                .ok_or_else(|| FrostNetError::Session("unknown PSBT session".into()))?;
            session.set_finalized(finalized_psbt, final_tx)?;
        }

        let _ = self
            .event_tx
            .send(KfpNodeEvent::PsbtFinalized { session_id, txid });

        info!(session_id = %hex::encode(session_id), "PSBT session finalized");
        Ok(())
    }

    pub(crate) async fn handle_psbt_finalize(
        &self,
        sender: PublicKey,
        payload: PsbtFinalizePayload,
    ) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }
        if !self.can_receive_from(&sender) {
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {sender} not allowed to send PSBT finalize"
            )));
        }
        if !payload.is_within_replay_window(self.replay_window_secs) {
            return Err(FrostNetError::ReplayDetected(
                "PSBT finalize outside replay window".into(),
            ));
        }

        let final_tx = match (payload.final_tx, payload.txid) {
            (Some(tx), Some(id)) => {
                let decoded: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&tx)
                    .map_err(|e| FrostNetError::Session(format!("final_tx decode failed: {e}")))?;
                let computed_bytes: [u8; 32] = decoded.compute_txid().to_byte_array();
                if computed_bytes != id {
                    return Err(FrostNetError::Session(
                        "PsbtFinalize txid does not match final_tx bytes".into(),
                    ));
                }
                // SEC: bind the announced final_tx back to the proposal PSBT
                // we agreed to coordinate on. compute_txid() ignores witness
                // data by design, so this compares the input prevouts +
                // outputs the initiator originally proposed against the
                // ones in the broadcast tx; a swap is rejected.
                {
                    let proposal_psbt = {
                        let sessions = self.psbt_sessions.read();
                        sessions
                            .get_session(&payload.session_id)
                            .map(|s| s.proposal_psbt().to_vec())
                    };
                    if let Some(bytes) = proposal_psbt {
                        let proposal = bitcoin::psbt::Psbt::deserialize(&bytes).map_err(|e| {
                            FrostNetError::Session(format!(
                                "PsbtFinalize: cannot decode proposal PSBT: {e}"
                            ))
                        })?;
                        let proposal_txid: [u8; 32] =
                            proposal.unsigned_tx.compute_txid().to_byte_array();
                        if proposal_txid != id {
                            return Err(FrostNetError::Session(
                                "PsbtFinalize final_tx does not match the proposal's unsigned-tx txid".into(),
                            ));
                        }
                    }
                }
                Some((tx, id))
            }
            (None, None) => None,
            _ => {
                return Err(FrostNetError::Session(
                    "PsbtFinalize must include both final_tx and txid, or neither".into(),
                ));
            }
        };
        let txid = final_tx.as_ref().map(|(_, id)| *id);

        {
            let mut sessions = self.psbt_sessions.write();
            let Some(session) = sessions.get_session_mut(&payload.session_id) else {
                debug!(
                    session_id = %hex::encode(payload.session_id),
                    "PsbtFinalize for unknown session, ignoring"
                );
                return Ok(());
            };
            match session.initiator() {
                Some(initiator) if *initiator == sender => {}
                Some(_) => {
                    return Err(FrostNetError::Session(
                        "PsbtFinalize sender is not the session initiator".into(),
                    ));
                }
                None => {
                    return Err(FrostNetError::Session(
                        "PsbtFinalize for session with no recorded initiator".into(),
                    ));
                }
            }
            if let Err(e) = session.set_finalized(payload.psbt, final_tx) {
                warn!("Failed to mark PSBT session finalized: {e}");
                return Ok(());
            }
        }

        let _ = self.event_tx.send(KfpNodeEvent::PsbtFinalized {
            session_id: payload.session_id,
            txid,
        });

        Ok(())
    }

    /// Abort a PSBT session locally and notify peers.
    pub async fn abort_psbt_session(&self, session_id: [u8; 32], reason: &str) -> Result<()> {
        {
            let mut sessions = self.psbt_sessions.write();
            let Some(session) = sessions.get_session_mut(&session_id) else {
                debug!(
                    session_id = %hex::encode(session_id),
                    "abort_psbt_session: unknown session, not broadcasting"
                );
                return Ok(());
            };
            session.abort(reason.to_string());
        }

        let payload = PsbtAbortPayload::new(session_id, self.group_pubkey, reason);
        let msg = KfpMessage::PsbtAbort(payload);

        let target_peers = self.bidirectional_online_peers();
        self.broadcast_psbt_event(&msg, &session_id, "psbt_abort", &target_peers)
            .await?;

        let _ = self.event_tx.send(KfpNodeEvent::PsbtAborted {
            session_id,
            reason: reason.to_string(),
        });

        Ok(())
    }

    pub(crate) async fn handle_psbt_abort(
        &self,
        sender: PublicKey,
        payload: PsbtAbortPayload,
    ) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }
        if !self.can_receive_from(&sender) {
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {sender} not allowed to send PSBT abort"
            )));
        }
        if !payload.is_within_replay_window(self.replay_window_secs) {
            return Err(FrostNetError::ReplayDetected(
                "PSBT abort outside replay window".into(),
            ));
        }

        let sanitized = sanitize_reason(&payload.reason);

        let (sender_share_index, sender_fingerprints) = {
            let peers = self.peers.read();
            match peers.get_peer_by_pubkey(&sender) {
                Some(peer) => (
                    Some(peer.share_index),
                    peer.recovery_xpubs
                        .iter()
                        .map(|x| x.fingerprint.clone())
                        .collect::<HashSet<_>>(),
                ),
                None => (None, HashSet::new()),
            }
        };

        {
            let mut sessions = self.psbt_sessions.write();
            let Some(session) = sessions.get_session_mut(&payload.session_id) else {
                return Ok(());
            };
            let is_initiator = session.initiator().is_some_and(|init| *init == sender);
            let is_expected_signer = session.expected_signers().iter().any(|s| match s {
                SignerId::Share(idx) => Some(*idx) == sender_share_index,
                SignerId::Fingerprint(fp) => sender_fingerprints.contains(fp),
            });
            if !is_initiator && !is_expected_signer {
                return Err(FrostNetError::Session(format!(
                    "Peer {sender} is not an authorized aborter for this PSBT session"
                )));
            }
            session.abort(sanitized.clone());
        }

        let _ = self.event_tx.send(KfpNodeEvent::PsbtAborted {
            session_id: payload.session_id,
            reason: sanitized,
        });

        Ok(())
    }
}

/// Decode a PSBT and extract snapshot-safe fields. Returns `None` on decode
/// error (fail-closed).
fn decode_psbt_for_snapshot(psbt_bytes: &[u8]) -> Option<([u8; 32], u32, Option<u64>)> {
    let psbt = bitcoin::psbt::Psbt::deserialize(psbt_bytes).ok()?;

    let mut hasher = Sha256::new();
    hasher.update(psbt_bytes);
    let psbt_hash: [u8; 32] = hasher.finalize().into();

    let output_count = u32::try_from(psbt.unsigned_tx.output.len()).ok()?;

    let total_in: Option<u64> = psbt
        .inputs
        .iter()
        .zip(psbt.unsigned_tx.input.iter())
        .try_fold(0u64, |acc, (psbt_in, tx_in)| {
            let value_sat = if let Some(wu) = psbt_in.witness_utxo.as_ref() {
                wu.value.to_sat()
            } else if let Some(nwu) = psbt_in.non_witness_utxo.as_ref() {
                if nwu.compute_txid() != tx_in.previous_output.txid {
                    return None;
                }
                let vout = tx_in.previous_output.vout as usize;
                let out = nwu.output.get(vout)?;
                out.value.to_sat()
            } else {
                return None;
            };
            acc.checked_add(value_sat)
        });
    let total_out: Option<u64> = psbt
        .unsigned_tx
        .output
        .iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value.to_sat()));
    let fee_sats = match (total_in, total_out) {
        (Some(i), Some(o)) => i.checked_sub(o),
        _ => None,
    };

    Some((psbt_hash, output_count, fee_sats))
}

/// Decode each output of `psbt_bytes` into a `(display_string, value_sats)`
/// pair. Addresses are rendered for the canonical network when known; outputs
/// whose script does not resolve to a network-valid address fall back to
/// `script:<hex>` so the UI never silently drops a destination.
///
/// Returns an empty vector on decode failure (fail-closed; callers that need
/// destinations to gate approval must treat empty as "no preview available").
fn decode_psbt_outputs(psbt_bytes: &[u8], network_str: &str) -> Vec<(String, u64)> {
    use bitcoin::Address;
    let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(psbt_bytes) else {
        return Vec::new();
    };
    let network = bitcoin::Network::from_str(network_str).ok();
    psbt.unsigned_tx
        .output
        .iter()
        .map(|o| {
            let s = match network {
                Some(net) => match Address::from_script(&o.script_pubkey, net) {
                    Ok(addr) => addr.to_string(),
                    Err(_) => format!("script:{}", hex::encode(o.script_pubkey.as_bytes())),
                },
                None => format!("script:{}", hex::encode(o.script_pubkey.as_bytes())),
            };
            (s, o.value.to_sat())
        })
        .collect()
}

/// Combine every signer's merged PSBT with the proposal PSBT using
/// `Psbt::combine`. Fails if any partial is undecodable, combination fails,
/// or any input on the aggregated PSBT carries fewer than
/// `required_threshold` distinct `tap_script_sigs` entries for the same
/// leaf hash.
///
/// Signers are combined in a deterministic order (sorted by SignerId)
/// because `Psbt::combine` is order-sensitive for fields that aren't pure
/// set-union — sorting ensures the aggregated bytes are reproducible across
/// peers.
fn aggregate_partial_psbts(
    proposal_psbt: &[u8],
    partial_psbts: &std::collections::HashMap<SignerId, Vec<u8>>,
    required_threshold: u32,
) -> Result<Vec<u8>> {
    let mut aggregated = bitcoin::psbt::Psbt::deserialize(proposal_psbt)
        .map_err(|e| FrostNetError::Session(format!("proposal PSBT decode failed: {e}")))?;
    let mut sorted: Vec<(&SignerId, &Vec<u8>)> = partial_psbts.iter().collect();
    sorted.sort_by(|(a, _), (b, _)| signer_id_sort_key(a).cmp(&signer_id_sort_key(b)));
    for (signer, bytes) in sorted {
        let partial = bitcoin::psbt::Psbt::deserialize(bytes).map_err(|e| {
            FrostNetError::Session(format!("partial PSBT decode failed for {signer:?}: {e}"))
        })?;
        aggregated.combine(partial).map_err(|e| {
            FrostNetError::Session(format!("PSBT combine failed for {signer:?}: {e}"))
        })?;
    }
    // Threshold check for the recovery-tier (tap-script) path: each input
    // must carry `required_threshold` distinct tap_script_sigs for the same
    // leaf hash. Counting partial_sigs / tap_key_sig here would let a single
    // attacker satisfy the threshold via the wrong signature family
    // (e.g. one classic ECDSA partial_sig plus their own tap_script_sig).
    // FROST key-path spends produce a single aggregated tap_key_sig regardless
    // of threshold and must use a different aggregator.
    let prevouts: Vec<_> = aggregated
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            if let Some(txout) = input.witness_utxo.clone() {
                return Ok(txout);
            }
            if let Some(tx) = input.non_witness_utxo.as_ref() {
                let prevout = aggregated
                    .unsigned_tx
                    .input
                    .get(i)
                    .ok_or_else(|| {
                        FrostNetError::Session(format!(
                            "aggregated PSBT input {i} has no matching unsigned_tx input"
                        ))
                    })?
                    .previous_output;
                // Bind the non_witness_utxo to the input's previous_output.txid
                // before trusting its value/script. Without this a malicious
                // partial PSBT could supply an unrelated transaction whose
                // output at this vout carries an altered value/script, changing
                // the sighash recomputed below.
                if tx.compute_txid() != prevout.txid {
                    return Err(FrostNetError::Session(format!(
                        "aggregated PSBT input {i} non_witness_utxo txid does not match previous_output"
                    )));
                }
                let vout = prevout.vout as usize;
                return tx.output.get(vout).cloned().ok_or_else(|| {
                    FrostNetError::Session(format!(
                        "aggregated PSBT input {i} non_witness_utxo has no output at index {vout}"
                    ))
                });
            }
            Err(FrostNetError::Session(format!(
                "aggregated PSBT input {i} missing witness_utxo and non_witness_utxo"
            )))
        })
        .collect::<Result<Vec<_>>>()?;
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    for (idx, input) in aggregated.inputs.iter().enumerate() {
        let mut iter = input.tap_scripts.iter();
        let (_, (script, leaf_version)) = iter.next().ok_or_else(|| {
            FrostNetError::Session(format!(
                "aggregated PSBT input {idx} has no tap_scripts entry; cannot determine proposed leaf"
            ))
        })?;
        if iter.next().is_some() {
            return Err(FrostNetError::Session(format!(
                "aggregated PSBT input {idx} has more than one tap_scripts entry; ambiguous proposed leaf"
            )));
        }
        let proposed_leaf = bitcoin::taproot::TapLeafHash::from_script(script, *leaf_version);
        // Collect the x-only keys actually committed inside the leaf script so
        // that signatures for keys not present in the leaf cannot be counted
        // toward the threshold.
        let mut committed_keys = HashSet::new();
        for instr in script.instructions_minimal() {
            if let Ok(bitcoin::blockdata::script::Instruction::PushBytes(push)) = instr {
                if push.len() == 32 {
                    if let Ok(xonly) =
                        bitcoin::secp256k1::XOnlyPublicKey::from_slice(push.as_bytes())
                    {
                        committed_keys.insert(xonly);
                    }
                }
            }
        }
        // Count only signatures that actually verify against the proposed leaf's
        // sighash so a signer cannot pad its partial with bogus tap_script_sigs
        // for other committed keys to satisfy the threshold. The sighash is
        // recomputed per signature using that signature's own sighash_type so a
        // legitimate non-default sighash is verified rather than silently dropped.
        let mut matching = 0u32;
        let mut sighash_cache = bitcoin::sighash::SighashCache::new(&aggregated.unsigned_tx);
        for ((pk, leaf_hash), sig) in input.tap_script_sigs.iter() {
            if *leaf_hash != proposed_leaf || !committed_keys.contains(pk) {
                continue;
            }
            let sighash = sighash_cache
                .taproot_script_spend_signature_hash(
                    idx,
                    &bitcoin::sighash::Prevouts::All(&prevouts),
                    proposed_leaf,
                    sig.sighash_type,
                )
                .map_err(|e| {
                    FrostNetError::Session(format!(
                        "aggregated PSBT input {idx} sighash failed: {e}"
                    ))
                })?;
            let msg =
                bitcoin::secp256k1::Message::from_digest_slice(sighash.as_ref()).map_err(|e| {
                    FrostNetError::Session(format!(
                        "aggregated PSBT input {idx} invalid sighash: {e}"
                    ))
                })?;
            if secp.verify_schnorr(&sig.signature, &msg, pk).is_ok() {
                matching += 1;
            }
        }
        if matching < required_threshold {
            return Err(FrostNetError::Session(format!(
                "aggregated PSBT input {idx} has {matching} tap_script_sigs for the proposed leaf, below threshold {required_threshold}"
            )));
        }
    }
    Ok(aggregated.serialize())
}

/// Total ordering for `SignerId` so `aggregate_partial_psbts` combines in
/// a deterministic order. `Share` < `Fingerprint`; within each variant we
/// order by the numeric / lexicographic key.
fn signer_id_sort_key(s: &SignerId) -> (u8, u16, String) {
    match s {
        SignerId::Share(i) => (0u8, *i, String::new()),
        SignerId::Fingerprint(fp) => (1u8, 0u16, fp.clone()),
    }
}

/// Apply the descriptor_hash verification policy given an in-memory match
/// result and an optional persisted-descriptor fallback. Both the in-memory
/// path and the persisted-lookup path are equivalent in trust: either one
/// matching accepts the hash; otherwise the call fails closed.
fn decide_descriptor_hash_verification(
    in_memory_match: bool,
    saw_any_finalized_in_memory: bool,
    group: &[u8; 32],
    descriptor_hash: &[u8; 32],
    lookup: Option<&dyn super::PersistedDescriptorLookup>,
) -> Result<()> {
    if in_memory_match {
        return Ok(());
    }
    if let Some(lookup) = lookup {
        if lookup.find_by_hash(group, descriptor_hash) {
            return Ok(());
        }
    }
    if saw_any_finalized_in_memory {
        Err(FrostNetError::Session(
            "PSBT descriptor_hash does not match any finalized descriptor for this group".into(),
        ))
    } else {
        Err(FrostNetError::Session(
            "no finalized descriptor for group; cannot verify descriptor_hash".into(),
        ))
    }
}

#[cfg(test)]
mod descriptor_lookup_tests {
    use super::*;
    use crate::node::PersistedDescriptorLookup;

    struct MockLookup {
        responds_true: bool,
        expected_group: [u8; 32],
        expected_hash: [u8; 32],
    }

    impl PersistedDescriptorLookup for MockLookup {
        fn find_by_hash(&self, group: &[u8; 32], hash: &[u8; 32]) -> bool {
            assert_eq!(group, &self.expected_group);
            assert_eq!(hash, &self.expected_hash);
            self.responds_true
        }
        fn latest_version_for(
            &self,
            _group: &[u8; 32],
        ) -> std::result::Result<Option<u32>, crate::node::DescriptorLookupUnavailable> {
            Ok(None)
        }
    }

    fn fixture() -> ([u8; 32], [u8; 32]) {
        ([7u8; 32], [9u8; 32])
    }

    #[test]
    fn in_memory_empty_lookup_false_rejects() {
        let (group, hash) = fixture();
        let lookup = MockLookup {
            responds_true: false,
            expected_group: group,
            expected_hash: hash,
        };
        let result =
            decide_descriptor_hash_verification(false, false, &group, &hash, Some(&lookup));
        assert!(result.is_err());
    }

    #[test]
    fn in_memory_empty_lookup_true_accepts() {
        let (group, hash) = fixture();
        let lookup = MockLookup {
            responds_true: true,
            expected_group: group,
            expected_hash: hash,
        };
        let result =
            decide_descriptor_hash_verification(false, false, &group, &hash, Some(&lookup));
        assert!(
            result.is_ok(),
            "persisted lookup match should accept after restart"
        );
    }

    #[test]
    fn neither_matches_rejects() {
        let (group, hash) = fixture();
        let lookup = MockLookup {
            responds_true: false,
            expected_group: group,
            expected_hash: hash,
        };
        let result = decide_descriptor_hash_verification(false, true, &group, &hash, Some(&lookup));
        assert!(result.is_err());
        let result_no_lookup =
            decide_descriptor_hash_verification(false, true, &group, &hash, None);
        assert!(result_no_lookup.is_err());
    }

    #[test]
    fn in_memory_match_accepts_regardless_of_lookup() {
        let (group, hash) = fixture();
        let result_no_lookup = decide_descriptor_hash_verification(true, true, &group, &hash, None);
        assert!(result_no_lookup.is_ok());

        let lookup = MockLookup {
            responds_true: false,
            expected_group: group,
            expected_hash: hash,
        };
        // In-memory matched: lookup must not be consulted. We assert by giving
        // it different expected bytes so that if it were called the assertion
        // inside MockLookup would fire.
        let unused_lookup = MockLookup {
            responds_true: false,
            expected_group: [0u8; 32],
            expected_hash: [0u8; 32],
        };
        let result =
            decide_descriptor_hash_verification(true, true, &group, &hash, Some(&unused_lookup));
        assert!(result.is_ok());
        let _ = lookup; // silence unused
    }
}

#[cfg(test)]
mod snapshot_decode_tests {
    use super::decode_psbt_for_snapshot;
    use bitcoin::absolute::LockTime;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };

    fn fixture_psbt(include_witness_utxo: bool) -> Vec<u8> {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[1u8; 32]).unwrap();
        let (x_only_pubkey, _parity) = keypair.x_only_public_key();
        let tap_script = ScriptBuf::new_p2tr(&secp, x_only_pubkey, None);

        let prev_txid: Txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: tap_script.clone(),
            }],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        if include_witness_utxo {
            psbt.inputs[0].witness_utxo = Some(TxOut {
                value: Amount::from_sat(60_000),
                script_pubkey: tap_script,
            });
        }
        psbt.serialize()
    }

    #[test]
    fn decode_good_psbt_reports_fee_and_output_count() {
        let bytes = fixture_psbt(true);
        let (hash, outputs, fee) = decode_psbt_for_snapshot(&bytes).expect("decodes");
        assert_ne!(hash, [0u8; 32]);
        assert_eq!(outputs, 1);
        assert_eq!(fee, Some(10_000));
    }

    #[test]
    fn decode_psbt_without_witness_utxo_reports_none_fee() {
        let bytes = fixture_psbt(false);
        let (_, outputs, fee) = decode_psbt_for_snapshot(&bytes).expect("decodes");
        assert_eq!(outputs, 1);
        assert_eq!(fee, None);
    }

    #[test]
    fn decode_psbt_garbage_returns_none() {
        assert!(decode_psbt_for_snapshot(&[0u8, 1, 2, 3]).is_none());
        assert!(decode_psbt_for_snapshot(&[]).is_none());
    }

    #[test]
    fn decode_outputs_emits_address_per_output_on_known_network() {
        let bytes = fixture_psbt(true);
        let outs = super::decode_psbt_outputs(&bytes, "regtest");
        assert_eq!(outs.len(), 1);
        let (addr, sats) = &outs[0];
        assert_eq!(*sats, 50_000);
        assert!(
            addr.starts_with("bcrt1p"),
            "expected regtest p2tr bech32m address, got {addr}"
        );
    }

    #[test]
    fn decode_outputs_unknown_network_falls_back_to_script_hex() {
        let bytes = fixture_psbt(true);
        let outs = super::decode_psbt_outputs(&bytes, "no-such-network");
        assert_eq!(outs.len(), 1);
        assert!(outs[0].0.starts_with("script:"));
    }

    #[test]
    fn decode_outputs_garbage_returns_empty() {
        let outs = super::decode_psbt_outputs(&[0u8, 1, 2], "regtest");
        assert!(outs.is_empty());
    }
}
