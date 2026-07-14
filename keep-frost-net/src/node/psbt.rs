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

    /// Responder-side destination guard for automated migration sweeps (#414).
    ///
    /// If the PSBT session is keyed on an OLD descriptor whose successor (NEW
    /// descriptor) is persisted in this vault, the proposal is an automated
    /// migration sweep and `tx` must have exactly one output paying the NEW
    /// descriptor's address. The expected address is re-derived independently
    /// against the *successor's own* network, because the proposer-side
    /// re-derivation in `request_descriptor_migration_sweep` is not a security
    /// boundary. On desktop this is the only destination defense (no human
    /// confirmation on the sign path).
    ///
    /// Fails CLOSED: returns `Err` when a successor should exist but cannot be
    /// resolved (descriptor store unavailable, ambiguous lineage, or
    /// re-derivation failure). Returns `Ok(())` only when the session descriptor
    /// is the current tip (no successor) or when the single output matches the
    /// re-derived successor address. Mirrors the proposer-side precondition that
    /// the NEW descriptor be persisted before any spend keyed on an OLD hash is
    /// signable.
    pub fn validate_migration_sweep_destination(
        &self,
        session_descriptor_hash: &[u8; 32],
        tx: &bitcoin::Transaction,
    ) -> std::result::Result<(), String> {
        let lookup = self.descriptor_lookup.as_deref().ok_or_else(|| {
            "REFUSED: no descriptor lookup configured; cannot confirm migration sweep destination"
                .to_string()
        })?;
        validate_sweep_destination(
            lookup.successor_for(&self.group_pubkey, session_descriptor_hash),
            tx,
        )
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
    /// single output paying the address of the NEW (definite) descriptor of the
    /// completed migration `session_id`.
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
        //    finalized. Resolve the finalized OLD descriptor by hash through the
        //    same persisted lookup used for the new one, so the source of truth
        //    is consistent and survives session reaping/restart. Require its
        //    output script equal the recovery output's script_pubkey.
        let old_external = lookup
            .external_for(&self.group_pubkey, &old_descriptor_hash)
            .ok_or_else(|| {
                FrostNetError::Session(
                    "old_descriptor_hash does not resolve to a persisted descriptor for this group"
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
        if !old_recovery
            .address
            .as_unchecked()
            .is_valid_for_network(network)
        {
            return Err(FrostNetError::Session(format!(
                "old_recovery address is not valid for network {network}"
            )));
        }

        // 4. Derive the NEW destination address from the finalized descriptor.
        //    No-recovery FROST wallet descriptors are ranged BIP-86
        //    (`tr([fp/86'/coin']xpub/0/*)`), so the destination is the
        //    descriptor's `/0/0` external address (index 0). Both proposer and
        //    responder derive index 0 of the SAME persisted successor, so they
        //    agree on the expected destination. Reuse it for both the PSBT
        //    destination and the display output.
        //
        // NOTE: this destination derivation is proposer-side only. The sweep
        // rides the generic `request_psbt_spend` path keyed on the OLD
        // descriptor hash, and responders currently sign the proposed
        // destination without re-deriving/validating it against the NEW
        // descriptor. Responder-side destination re-derivation is a broader
        // change to the general signing path (keep-desktop/keep-cli signing
        // UIs) and is tracked separately.
        let dest_addr = keep_bitcoin::descriptor_address_at_index(&new_external, network, 0)
            .map_err(|e| FrostNetError::Session(format!("new receive address: {e}")))?;
        let destination = dest_addr.script_pubkey();

        // 5. Bound the fee relative to total input value before building, so a
        //    fee-griefing proposal is rejected ahead of the looser absolute cap
        //    enforced inside the builder.
        check_sweep_fee(utxos.iter().map(|u| u.value_sats), fee_sats)?;

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
            value_sats: psbt.unsigned_tx.output[0].value.to_sat(),
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

        reject_placeholder_policy_spend(
            &self.group_pubkey,
            &descriptor_hash,
            self.descriptor_lookup.as_deref(),
        )?;

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

        // Canonicalize the wire-supplied fingerprints to lowercase once, mirroring
        // the proposer path (propose_psbt) and the stored recovery fingerprints.
        // detect_dual_identity_signer, the session signers set, and our own
        // self-check below all expect lowercase; comparing against the raw wire
        // values would let a proposer send uppercase fingerprints to sidestep the
        // dual-identity (Sybil-toward-quorum) guard and desync the signer sets.
        let expected_fingerprints: Vec<String> = payload
            .expected_fingerprints
            .iter()
            .map(|fp| fp.to_ascii_lowercase())
            .collect();

        self.reject_dual_identity_signers(&payload.expected_signers, &expected_fingerprints)?;

        let signers: HashSet<SignerId> = payload
            .expected_signers
            .iter()
            .map(|idx| SignerId::Share(*idx))
            .chain(
                expected_fingerprints
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
        let we_are_external_signer = expected_fingerprints
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
        let resolved: Vec<(u16, Vec<String>)> = expected_share_signers
            .iter()
            .filter_map(|idx| {
                peers.get_peer(*idx).map(|peer| {
                    (
                        *idx,
                        peer.recovery_xpubs
                            .iter()
                            .map(|x| x.fingerprint.clone())
                            .collect(),
                    )
                })
            })
            .collect();
        detect_dual_identity_signer(
            resolved.iter().map(|(idx, fps)| (*idx, fps.as_slice())),
            expected_fingerprints,
        )
    }

    fn check_psbt_proposer_authorized(&self, share_index: u16) -> Result<()> {
        proposer_authorized(&self.psbt_proposers.read(), share_index)
    }

    fn verify_descriptor_hash_against_stored(&self, descriptor_hash: &[u8; 32]) -> Result<()> {
        // Responder-side half of the placeholder-policy invariant: refuse to sign
        // a spend keyed on a persisted descriptor whose policy_hash is the
        // placeholder, so the guard enforced when proposing also holds at the
        // boundary where this node actually signs. Fails open only when this
        // node's own lookup cannot resolve the hash (see the guard's docs).
        reject_placeholder_policy_spend(
            &self.group_pubkey,
            descriptor_hash,
            self.descriptor_lookup.as_deref(),
        )?;

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
                // A finalized descriptor from a completed coordination carries a
                // real policy_hash; treat a placeholder as no match so an
                // uncoordinated policy can never validate a spend.
                if finalized.policy_hash == [0u8; 32] {
                    continue;
                }
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
        // Fail closed under duress: a verified duress beacon freezes co-signing,
        // so a coerced holder does not contribute a PSBT signature toward a spend.
        if self.is_duress_frozen() {
            debug!("Refusing PSBT signature contribution: holder is duress-frozen");
            return Err(FrostNetError::PolicyViolation(
                "holder is duress-frozen; co-signing refused".into(),
            ));
        }

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
/// set-union; sorting ensures the aggregated bytes are reproducible across
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

/// Whether `share_index` may propose PSBTs given the configured proposer
/// allowlist. An empty allowlist is open (any share may propose); a non-empty
/// one restricts to its members. Pure so the allowlist boolean is directly
/// testable.
fn proposer_authorized(proposers: &HashSet<u16>, share_index: u16) -> Result<()> {
    if !proposers.is_empty() && !proposers.contains(&share_index) {
        return Err(FrostNetError::Session(format!(
            "Share {share_index} is not authorized to propose PSBTs"
        )));
    }
    Ok(())
}

/// Reject a peer that is counted as BOTH an expected share signer and an
/// expected fingerprint signer, which would let one identity satisfy the
/// threshold twice (Sybil toward quorum). `share_signers` supplies each
/// expected share signer's recovery-xpub fingerprints; a match against
/// `expected_fingerprints` (compared case-insensitively) is rejected. Both sides
/// are lowercased here so the guard holds even if a caller passes wire values
/// that were not pre-normalized. Pure so the overlap logic is directly testable.
fn detect_dual_identity_signer<'a>(
    share_signers: impl IntoIterator<Item = (u16, &'a [String])>,
    expected_fingerprints: &[String],
) -> Result<()> {
    let expected_lc: Vec<String> = expected_fingerprints
        .iter()
        .map(|fp| fp.to_ascii_lowercase())
        .collect();
    for (idx, fingerprints) in share_signers {
        for fp in fingerprints {
            let fp_lc = fp.to_ascii_lowercase();
            if expected_lc.contains(&fp_lc) {
                return Err(FrostNetError::Session(format!(
                    "Dual-identity signer rejected: share {idx} and fingerprint {fp_lc} resolve to the same peer"
                )));
            }
        }
    }
    Ok(())
}

/// Reject a migration sweep whose fee is disproportionate to the funds moved,
/// ahead of the builder's looser absolute cap (#502). Sums the input values
/// (failing closed on u64 overflow) and requires
/// `fee_sats <= total_in / MAX_SWEEP_FEE_FRACTION`. Pure so the fee-griefing
/// boundary is directly testable without building a PSBT.
fn check_sweep_fee(input_values: impl IntoIterator<Item = u64>, fee_sats: u64) -> Result<()> {
    let total_in = input_values
        .into_iter()
        .try_fold(0u64, |acc, v| acc.checked_add(v))
        .ok_or_else(|| FrostNetError::Session("sweep input value overflow".into()))?;
    let fee_cap = total_in / MAX_SWEEP_FEE_FRACTION;
    if fee_sats > fee_cap {
        return Err(FrostNetError::Session(format!(
            "sweep fee {fee_sats} exceeds 1/{MAX_SWEEP_FEE_FRACTION} of total input {total_in}"
        )));
    }
    Ok(())
}

/// Decide whether an automated migration sweep may sign, given the resolved
/// successor lookup and the proposed transaction (#414). Pure so the
/// destination-rebind defense is directly testable without a node/relay:
/// `validate_migration_sweep_destination` only supplies the `successor_for`
/// result. Fails closed on `Unavailable`/`Ambiguous`; for `Found`, re-derives
/// the successor's own address and requires the tx to pay exactly it.
fn validate_sweep_destination(
    lookup: super::SuccessorLookup,
    tx: &bitcoin::Transaction,
) -> std::result::Result<(), String> {
    let (external_descriptor, network_str) = match lookup {
        super::SuccessorLookup::Tip => return Ok(()),
        super::SuccessorLookup::Found {
            external_descriptor,
            network,
        } => (external_descriptor, network),
        super::SuccessorLookup::Unavailable => {
            return Err("REFUSED: descriptor store unavailable; cannot re-derive the migration sweep destination. Unlock the vault and retry.".to_string());
        }
        super::SuccessorLookup::Ambiguous => {
            return Err("REFUSED: ambiguous descriptor lineage; multiple successors back-point to the session descriptor and no single version+1 successor resolves. Refusing to sign.".to_string());
        }
    };
    // Re-derive against the successor's OWN network, not the OLD descriptor's,
    // so a (mis)matched network can never silently produce the wrong expected
    // script.
    let network = bitcoin::Network::from_str(&network_str).map_err(|e| {
        format!("REFUSED: successor descriptor has invalid network {network_str}: {e}")
    })?;
    let expected_addr =
        keep_bitcoin::descriptor_address_at_index(&external_descriptor, network, 0).map_err(
            |e| {
                format!(
                    "REFUSED: could not derive expected sweep destination from persisted successor descriptor: {e}"
                )
            },
        )?;
    let expected_script = expected_addr.script_pubkey();
    if tx.output.len() != 1 {
        return Err(format!(
            "REFUSED: session is keyed on an OLD descriptor whose successor (NEW descriptor) is persisted, so this is treated as an automated migration sweep; expected exactly 1 output paying the NEW descriptor address, got {} outputs. Refusing to sign.",
            tx.output.len()
        ));
    }
    if tx.output[0].script_pubkey != expected_script {
        return Err(format!(
            "REFUSED: PSBT output does not pay the persisted NEW descriptor address. Expected {expected_addr}; proposer-supplied script differs. This would route funds away from the group-controlled address; refusing to sign."
        ));
    }
    Ok(())
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

/// Refuse a spend bound to a descriptor whose `policy_hash` is the placeholder
/// all-zero value. Enforced at both trust boundaries: the proposer side
/// (`request_psbt_spend`) and the responder side
/// (`verify_descriptor_hash_against_stored`), so the invariant holds regardless
/// of who initiates the coordination.
///
/// A descriptor imported before its wallet policy is coordinated carries
/// `policy_hash == [0; 32]`, yet its canonical `descriptor_hash` is non-zero, so
/// the plain all-zero-hash check does not catch it, and a responder recomputes
/// the identical hash (policy_hash is committed into it) and would otherwise
/// accept. Binding a spend to such a descriptor would leave the coordination
/// cryptographically tied to no policy.
///
/// Only fires when the descriptor positively resolves via *this node's* lookup
/// to an all-zero policy_hash. A hash that does not resolve (no lookup, no
/// match, or the vault temporarily unreadable) is not a rejection here; the
/// per-caller CLI/desktop spend guards fail closed on their own loaded
/// descriptor, and the opposite boundary applies the same check. Defense in
/// depth, not the sole guard.
fn reject_placeholder_policy_spend(
    group: &[u8; 32],
    descriptor_hash: &[u8; 32],
    lookup: Option<&dyn super::PersistedDescriptorLookup>,
) -> Result<()> {
    if let Some(lookup) = lookup {
        if lookup.policy_hash_for(group, descriptor_hash) == Some([0u8; 32]) {
            return Err(FrostNetError::Session(
                "descriptor has placeholder (all-zero) policy_hash; coordinate the wallet policy before spending".into(),
            ));
        }
    }
    Ok(())
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

    struct PolicyMock {
        policy_hash: Option<[u8; 32]>,
    }

    impl PersistedDescriptorLookup for PolicyMock {
        fn find_by_hash(&self, _group: &[u8; 32], _hash: &[u8; 32]) -> bool {
            self.policy_hash.is_some()
        }
        fn policy_hash_for(&self, _group: &[u8; 32], _hash: &[u8; 32]) -> Option<[u8; 32]> {
            self.policy_hash
        }
        fn latest_version_for(
            &self,
            _group: &[u8; 32],
        ) -> std::result::Result<Option<u32>, crate::node::DescriptorLookupUnavailable> {
            Ok(None)
        }
    }

    #[test]
    fn placeholder_policy_hash_spend_is_rejected() {
        let (group, hash) = fixture();
        let lookup = PolicyMock {
            policy_hash: Some([0u8; 32]),
        };
        assert!(reject_placeholder_policy_spend(&group, &hash, Some(&lookup)).is_err());
    }

    #[test]
    fn coordinated_policy_hash_spend_is_allowed() {
        let (group, hash) = fixture();
        let lookup = PolicyMock {
            policy_hash: Some([0xABu8; 32]),
        };
        assert!(reject_placeholder_policy_spend(&group, &hash, Some(&lookup)).is_ok());
    }

    #[test]
    fn unresolved_or_absent_lookup_does_not_reject() {
        let (group, hash) = fixture();
        // No lookup configured: not our boundary to reject (responders verify).
        assert!(reject_placeholder_policy_spend(&group, &hash, None).is_ok());
        // Lookup present but the hash resolves to no descriptor.
        let lookup = PolicyMock { policy_hash: None };
        assert!(reject_placeholder_policy_spend(&group, &hash, Some(&lookup)).is_ok());
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

    // === #417 round 4b: targeted unit tests killing the surviving mutations ===

    /// `signer_id_sort_key` is what `aggregate_partial_psbts` uses to make
    /// the combine order deterministic across peers — without that, the
    /// aggregated PSBT bytes would diverge across peers and the consensus
    /// hash would break. Pin every dimension:
    ///
    /// 1. `Share` MUST sort before `Fingerprint` (variant tag 0 vs 1).
    /// 2. Within `Share`, indices sort ascending.
    /// 3. Within `Fingerprint`, fingerprints sort lexicographically.
    ///
    /// 6 mutations on the tuple's three components are killed by pinning
    /// these orderings.
    #[test]
    fn signer_id_sort_key_orders_share_before_fingerprint() {
        use super::signer_id_sort_key;
        use crate::psbt_session::SignerId;

        // Share(0) < Fingerprint("a") — variant tag dominates.
        assert!(
            signer_id_sort_key(&SignerId::Share(0))
                < signer_id_sort_key(&SignerId::Fingerprint("a".into()))
        );
        // Even Share(u16::MAX) < Fingerprint("") — variant tag still
        // dominates regardless of inner values.
        assert!(
            signer_id_sort_key(&SignerId::Share(u16::MAX))
                < signer_id_sort_key(&SignerId::Fingerprint(String::new()))
        );
    }

    #[test]
    fn signer_id_sort_key_orders_shares_by_ascending_index() {
        use super::signer_id_sort_key;
        use crate::psbt_session::SignerId;

        assert!(signer_id_sort_key(&SignerId::Share(1)) < signer_id_sort_key(&SignerId::Share(2)));
        assert!(signer_id_sort_key(&SignerId::Share(0)) < signer_id_sort_key(&SignerId::Share(1)));
        assert!(signer_id_sort_key(&SignerId::Share(2)) < signer_id_sort_key(&SignerId::Share(10)));
        // Same index hashes to equal keys.
        assert_eq!(
            signer_id_sort_key(&SignerId::Share(5)),
            signer_id_sort_key(&SignerId::Share(5))
        );
    }

    #[test]
    fn signer_id_sort_key_orders_fingerprints_lexicographically() {
        use super::signer_id_sort_key;
        use crate::psbt_session::SignerId;

        assert!(
            signer_id_sort_key(&SignerId::Fingerprint("aaaa".into()))
                < signer_id_sort_key(&SignerId::Fingerprint("bbbb".into()))
        );
        // Empty string sorts before any non-empty string.
        assert!(
            signer_id_sort_key(&SignerId::Fingerprint(String::new()))
                < signer_id_sort_key(&SignerId::Fingerprint("abc".into()))
        );
        // `signer_id_sort_key` returns `(u8, u16, String)`, so a
        // constant-return mutation (`Default::default()` → `(0, 0, "")`)
        // would collapse all fingerprints onto one key; pinning two
        // distinct fingerprints' distinctness catches it.
        assert_ne!(
            signer_id_sort_key(&SignerId::Fingerprint("alpha".into())),
            signer_id_sort_key(&SignerId::Fingerprint("beta".into()))
        );
    }

    /// `aggregate_partial_psbts` with an empty partials map and threshold=0
    /// is a no-op that returns the proposal PSBT verbatim. A `vec![0]` /
    /// `vec![1]` constant-return regression would emit bytes that fail to
    /// re-decode as a PSBT downstream.
    #[test]
    fn aggregate_partial_psbts_returns_proposal_bytes_when_no_partials_and_threshold_zero() {
        // Build a proposal PSBT with no inputs so the threshold-check loop
        // doesn't run.
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, Psbt, ScriptBuf, Transaction, TxOut};

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let proposal = Psbt::from_unsigned_tx(tx).unwrap().serialize();

        let result =
            super::aggregate_partial_psbts(&proposal, &std::collections::HashMap::new(), 0)
                .expect("empty partials + threshold 0 must succeed");

        // The constant-return regressions vec![0] / vec![1] would emit
        // tiny garbage bytes; the real result is a complete PSBT
        // serialisation that decodes back to the proposal.
        assert!(
            result.len() > 5,
            "result must be a real PSBT, got {} bytes",
            result.len()
        );
        let parsed = Psbt::deserialize(&result).expect("result must decode as a PSBT");
        assert_eq!(parsed.unsigned_tx.output.len(), 1);
        assert_eq!(parsed.unsigned_tx.output[0].value.to_sat(), 50_000);
    }

    /// `aggregate_partial_psbts` must error when an input carries a
    /// `witness_utxo` (so prevout collection succeeds) but no `tap_scripts`
    /// entry: with no leaf there is no way to determine which signatures
    /// count toward the threshold. Execution stops at the "no tap_scripts
    /// entry" guard before the threshold loop runs, so this test pins that
    /// guard only; a mutation dropping it would let an undecidable-leaf
    /// PSBT through. The threshold comparison itself is pinned separately by
    /// `aggregate_partial_psbts_rejects_input_below_threshold`.
    #[test]
    fn aggregate_partial_psbts_fails_when_input_has_no_tap_scripts_entry() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::{
            Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
        };

        let prev_txid: bitcoin::Txid =
            "0000000000000000000000000000000000000000000000000000000000000001"
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
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        // witness_utxo present so the prevouts-collection loop succeeds
        // and execution reaches the no-tap_scripts guard.
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new(),
        });
        let proposal = psbt.serialize();

        let err = super::aggregate_partial_psbts(&proposal, &std::collections::HashMap::new(), 1)
            .expect_err("no tap_scripts entry must error");
        let msg = err.to_string();
        assert!(
            msg.contains("no tap_scripts entry"),
            "expected the no-tap_scripts-entry error, got {msg}"
        );
    }

    /// Pins the threshold comparison `matching < required_threshold` in
    /// `aggregate_partial_psbts`. The input carries one valid `tap_scripts`
    /// entry (built via `TaprootBuilder`) so execution reaches the
    /// threshold check rather than the earlier leaf guard, but zero
    /// `tap_script_sigs`, leaving `matching == 0`. With threshold 1 the
    /// original code errors; the `< → >` mutation evaluates `0 > 1 == false`
    /// and would instead return `Ok`, so `expect_err` kills it.
    #[test]
    fn aggregate_partial_psbts_rejects_input_below_threshold() {
        let (proposal_psbt, _kp, _leaf, _prevout) = single_leaf_tapscript_psbt([7u8; 32]);
        let proposal = proposal_psbt.serialize();

        // No tap_script_sigs => matching == 0, below threshold 1 => error.
        let err = super::aggregate_partial_psbts(&proposal, &std::collections::HashMap::new(), 1)
            .expect_err("zero matching sigs below threshold 1 must error");
        let msg = err.to_string();
        assert!(
            msg.contains("below threshold"),
            "expected a below-threshold error, got {msg}"
        );
    }

    /// Build a single-leaf `<key> OP_CHECKSIG` taproot PSBT spending one input,
    /// returning the proposal PSBT, the committed leaf keypair, the leaf hash,
    /// and the prevout being spent. Exposes the pieces a positive-path
    /// aggregation test needs to produce real `tap_script_sigs`.
    fn single_leaf_tapscript_psbt(
        leaf_seed: [u8; 32],
    ) -> (
        bitcoin::psbt::Psbt,
        bitcoin::secp256k1::Keypair,
        bitcoin::taproot::TapLeafHash,
        bitcoin::TxOut,
    ) {
        use bitcoin::opcodes::all::OP_CHECKSIG;
        use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
        use std::collections::BTreeMap;

        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &leaf_seed).unwrap();
        let (xonly, _) = keypair.x_only_public_key();
        let leaf_script = ScriptBuf::builder()
            .push_x_only_key(&xonly)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let internal_kp = Keypair::from_seckey_slice(&secp, &[9u8; 32]).unwrap();
        let (internal, _) = internal_kp.x_only_public_key();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf_script.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let control_block = spend_info
            .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
            .unwrap();
        let spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

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
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: spk,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(prevout.clone());
        let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);
        let mut tap_scripts = BTreeMap::new();
        tap_scripts.insert(control_block, (leaf_script, LeafVersion::TapScript));
        psbt.inputs[0].tap_scripts = tap_scripts;
        (psbt, keypair, leaf_hash, prevout)
    }

    /// Produce a real tap-script Schnorr signature over `psbt`'s single input
    /// for `leaf` under `signer`, using the same sighash the aggregator
    /// recomputes. Deterministic (no aux rand) so the test is reproducible.
    fn sign_tap_leaf(
        psbt: &bitcoin::psbt::Psbt,
        prevout: &bitcoin::TxOut,
        leaf: bitcoin::taproot::TapLeafHash,
        signer: &bitcoin::secp256k1::Keypair,
    ) -> bitcoin::taproot::Signature {
        use bitcoin::secp256k1::Message;
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        let secp = Secp256k1::new();
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(prevout)),
                leaf,
                TapSighashType::Default,
            )
            .unwrap();
        let msg = Message::from_digest_slice(sighash.as_ref()).unwrap();
        let signature = secp.sign_schnorr_no_aux_rand(&msg, signer);
        bitcoin::taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        }
    }

    /// A partial carrying one valid `tap_script_sig` for the committed leaf key
    /// meets threshold 1, and the aggregated PSBT carries that signature. Pins
    /// the positive counting path (`verify_schnorr` success + `matching`
    /// increment) that the below-threshold test cannot reach.
    #[test]
    fn aggregate_partial_psbts_accepts_valid_sig_at_threshold() {
        use crate::psbt_session::SignerId;

        let (proposal_psbt, kp, leaf, prevout) = single_leaf_tapscript_psbt([7u8; 32]);
        let (xonly, _) = kp.x_only_public_key();
        let sig = sign_tap_leaf(&proposal_psbt, &prevout, leaf, &kp);

        let mut partial = proposal_psbt.clone();
        partial.inputs[0].tap_script_sigs.insert((xonly, leaf), sig);

        let mut map = std::collections::HashMap::new();
        map.insert(SignerId::Share(1), partial.serialize());

        let out = super::aggregate_partial_psbts(&proposal_psbt.serialize(), &map, 1)
            .expect("one valid tap_script_sig meets threshold 1");
        let decoded = Psbt::deserialize(&out).unwrap();
        assert_eq!(
            decoded.inputs[0].tap_script_sigs.get(&(xonly, leaf)),
            Some(&sig),
            "aggregated PSBT must carry the contributed signature unchanged"
        );
    }

    /// A valid signature for an x-only key that is NOT committed inside the leaf
    /// script must not count toward the threshold. Pins the committed-keys
    /// filter so a signer cannot pad with sigs for arbitrary keys.
    #[test]
    fn aggregate_partial_psbts_ignores_sig_for_uncommitted_key() {
        use crate::psbt_session::SignerId;

        let (proposal_psbt, _kp, leaf, prevout) = single_leaf_tapscript_psbt([7u8; 32]);
        // A different keypair whose x-only key is not pushed inside the leaf.
        let secp = Secp256k1::new();
        let other = Keypair::from_seckey_slice(&secp, &[11u8; 32]).unwrap();
        let (other_xonly, _) = other.x_only_public_key();
        let sig = sign_tap_leaf(&proposal_psbt, &prevout, leaf, &other);

        let mut partial = proposal_psbt.clone();
        partial.inputs[0]
            .tap_script_sigs
            .insert((other_xonly, leaf), sig);

        let mut map = std::collections::HashMap::new();
        map.insert(SignerId::Share(1), partial.serialize());

        let err = super::aggregate_partial_psbts(&proposal_psbt.serialize(), &map, 1)
            .expect_err("sig for an uncommitted key must not satisfy threshold");
        assert!(err.to_string().contains("below threshold"));
    }

    /// A valid signature tagged to a different leaf hash than the one proposed
    /// must not count. Pins the `leaf_hash != proposed_leaf` filter.
    #[test]
    fn aggregate_partial_psbts_ignores_sig_for_wrong_leaf() {
        use crate::psbt_session::SignerId;
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let (proposal_psbt, kp, leaf, prevout) = single_leaf_tapscript_psbt([7u8; 32]);
        let (xonly, _) = kp.x_only_public_key();
        let sig = sign_tap_leaf(&proposal_psbt, &prevout, leaf, &kp);
        // Same committed key, but file the sig under an unrelated leaf hash.
        let wrong_leaf =
            TapLeafHash::from_script(&ScriptBuf::from(vec![0x51]), LeafVersion::TapScript);

        let mut partial = proposal_psbt.clone();
        partial.inputs[0]
            .tap_script_sigs
            .insert((xonly, wrong_leaf), sig);

        let mut map = std::collections::HashMap::new();
        map.insert(SignerId::Share(1), partial.serialize());

        let err = super::aggregate_partial_psbts(&proposal_psbt.serialize(), &map, 1)
            .expect_err("sig for the wrong leaf must not satisfy threshold");
        assert!(err.to_string().contains("below threshold"));
    }

    /// A signature filed under the committed key and correct leaf but produced
    /// by a different key does not verify, so it must not count. Pins the
    /// `verify_schnorr` rejection branch.
    #[test]
    fn aggregate_partial_psbts_rejects_invalid_signature() {
        use crate::psbt_session::SignerId;

        let (proposal_psbt, kp, leaf, prevout) = single_leaf_tapscript_psbt([7u8; 32]);
        let (xonly, _) = kp.x_only_public_key();
        // Sign with the wrong key, then file it under the committed key.
        let secp = Secp256k1::new();
        let wrong = Keypair::from_seckey_slice(&secp, &[13u8; 32]).unwrap();
        let bogus = sign_tap_leaf(&proposal_psbt, &prevout, leaf, &wrong);

        let mut partial = proposal_psbt.clone();
        partial.inputs[0]
            .tap_script_sigs
            .insert((xonly, leaf), bogus);

        let mut map = std::collections::HashMap::new();
        map.insert(SignerId::Share(1), partial.serialize());

        let err = super::aggregate_partial_psbts(&proposal_psbt.serialize(), &map, 1)
            .expect_err("a signature that fails verification must not count");
        assert!(err.to_string().contains("below threshold"));
    }

    /// `decode_psbt_for_snapshot` binds the `non_witness_utxo` to the input's
    /// `previous_output.txid` before trusting its value: a mismatched tx
    /// MUST yield `fee = None`. The `!= → ==` mutation on the txid check
    /// would silently accept an attacker-supplied unrelated transaction
    /// whose vout-N output carries an altered value, producing a wrong fee
    /// in the snapshot. Pin both branches: matching txid → `Some(fee)`,
    /// mismatched txid → `None`.
    #[test]
    fn decode_psbt_for_snapshot_rejects_non_witness_utxo_with_mismatched_txid() {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[1u8; 32]).unwrap();
        let (x_only_pubkey, _parity) = keypair.x_only_public_key();
        let tap_script = ScriptBuf::new_p2tr(&secp, x_only_pubkey, None);

        // Build a "previous tx" we claim our input spends from.
        let real_prev = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(60_000),
                script_pubkey: tap_script.clone(),
            }],
        };
        let real_prev_txid = real_prev.compute_txid();

        // The new tx's input claims to spend from `real_prev_txid:0`.
        let our_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: real_prev_txid,
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

        // Case A: matching txid -> fee = Some(10_000).
        let mut psbt = Psbt::from_unsigned_tx(our_tx.clone()).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(real_prev.clone());
        let bytes = psbt.serialize();
        let (_hash, _outputs, fee) =
            decode_psbt_for_snapshot(&bytes).expect("matching txid must decode");
        assert_eq!(
            fee,
            Some(10_000),
            "matching non_witness_utxo txid must yield the correct fee"
        );

        // Case B: tamper with the non_witness_utxo so its computed txid no
        // longer matches `previous_output.txid`. With the `!= → ==`
        // mutation, the value `999_999_999` would be accepted and fee
        // would be `Some(999_949_999)`. Original code returns None.
        let mut tampered_prev = real_prev.clone();
        tampered_prev.output[0].value = Amount::from_sat(999_999_999);
        let tampered_txid = tampered_prev.compute_txid();
        assert_ne!(
            tampered_txid, real_prev_txid,
            "control: changing the output value must change the txid"
        );

        let mut psbt = Psbt::from_unsigned_tx(our_tx).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(tampered_prev);
        let bytes = psbt.serialize();
        let (_hash, _outputs, fee) =
            decode_psbt_for_snapshot(&bytes).expect("psbt itself is well-formed");
        assert_eq!(
            fee, None,
            "mismatched non_witness_utxo txid MUST yield fee = None; \
             SECURITY VIOLATION otherwise (proposer-supplied tampered tx accepted)"
        );
    }

    /// `aggregate_partial_psbts` binds the `non_witness_utxo` to the input's
    /// `previous_output.txid` before reading its value/script as the
    /// prevout. The `!= → ==` mutation on the `compute_txid() != txid` gate
    /// inverts that check; an
    /// attacker-supplied unrelated transaction whose vout-N output carries
    /// an altered value/script would change the sighash recomputed below
    /// without changing the signed commitment.
    ///
    /// Pin: a tampered `non_witness_utxo` whose computed txid differs from
    /// `previous_output.txid` MUST surface a "txid does not match" error.
    #[test]
    fn aggregate_partial_psbts_rejects_non_witness_utxo_with_mismatched_txid() {
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[1u8; 32]).unwrap();
        let (xonly, _parity) = keypair.x_only_public_key();
        let leaf_script = ScriptBuf::builder()
            .push_slice(xonly.serialize())
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKSIG)
            .into_script();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf_script.clone())
            .unwrap()
            .finalize(&secp, xonly)
            .unwrap();

        // Build a real previous tx whose vout 0 carries 60_000.
        let real_prev = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(60_000),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
            }],
        };
        let real_prev_txid = real_prev.compute_txid();

        // Tamper with the prev's output value so its txid changes.
        let mut tampered_prev = real_prev.clone();
        tampered_prev.output[0].value = Amount::from_sat(999_999_999);
        let tampered_txid = tampered_prev.compute_txid();
        assert_ne!(
            tampered_txid, real_prev_txid,
            "control: changing the prev output value must change the txid"
        );

        // The proposal claims to spend from `real_prev_txid:0` but carries
        // the tampered tx as non_witness_utxo (no witness_utxo).
        let our_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: real_prev_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(our_tx).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(tampered_prev);

        let control_block = spend_info
            .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
            .unwrap();
        let mut tap_scripts = std::collections::BTreeMap::new();
        tap_scripts.insert(control_block, (leaf_script, LeafVersion::TapScript));
        psbt.inputs[0].tap_scripts = tap_scripts;

        let proposal = psbt.serialize();
        let err = super::aggregate_partial_psbts(&proposal, &std::collections::HashMap::new(), 1)
            .expect_err("mismatched non_witness_utxo txid MUST be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("txid does not match"),
            "expected `txid does not match` error, got {msg}"
        );
    }
}

#[cfg(test)]
mod sweep_validation_tests {
    use super::{check_sweep_fee, validate_sweep_destination};
    use crate::node::SuccessorLookup;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };

    // A concrete ranged taproot descriptor whose /0/0 address is deterministic
    // (shared with keep-bitcoin's descriptor tests).
    const TEST_DESCRIPTOR: &str = "tr(xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz/0/*)";

    fn tx_paying(scripts: Vec<ScriptBuf>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: scripts
                .into_iter()
                .map(|script_pubkey| TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey,
                })
                .collect(),
        }
    }

    fn found() -> SuccessorLookup {
        SuccessorLookup::Found {
            external_descriptor: TEST_DESCRIPTOR.to_string(),
            network: "testnet".to_string(),
        }
    }

    fn expected_script() -> ScriptBuf {
        keep_bitcoin::descriptor_address_at_index(TEST_DESCRIPTOR, Network::Testnet, 0)
            .unwrap()
            .script_pubkey()
    }

    #[test]
    fn tip_needs_no_validation() {
        // No successor to validate: any tx is accepted.
        assert!(validate_sweep_destination(SuccessorLookup::Tip, &tx_paying(vec![])).is_ok());
    }

    #[test]
    fn unavailable_fails_closed() {
        let err = validate_sweep_destination(
            SuccessorLookup::Unavailable,
            &tx_paying(vec![expected_script()]),
        )
        .unwrap_err();
        assert!(err.contains("unavailable"), "{err}");
    }

    #[test]
    fn ambiguous_fails_closed() {
        let err = validate_sweep_destination(
            SuccessorLookup::Ambiguous,
            &tx_paying(vec![expected_script()]),
        )
        .unwrap_err();
        assert!(err.contains("ambiguous"), "{err}");
    }

    #[test]
    fn found_invalid_network_rejected() {
        let lookup = SuccessorLookup::Found {
            external_descriptor: TEST_DESCRIPTOR.to_string(),
            network: "notanetwork".to_string(),
        };
        let err =
            validate_sweep_destination(lookup, &tx_paying(vec![expected_script()])).unwrap_err();
        assert!(err.contains("invalid network"), "{err}");
    }

    #[test]
    fn found_valid_network_bad_descriptor_rejected() {
        // Valid network string but an unparseable successor descriptor: address
        // re-derivation fails closed rather than signing an unverified sweep.
        let lookup = SuccessorLookup::Found {
            external_descriptor: "notadescriptor".to_string(),
            network: "testnet".to_string(),
        };
        let err =
            validate_sweep_destination(lookup, &tx_paying(vec![expected_script()])).unwrap_err();
        assert!(err.contains("could not derive"), "{err}");
    }

    #[test]
    fn found_zero_output_rejected() {
        let err = validate_sweep_destination(found(), &tx_paying(vec![])).unwrap_err();
        assert!(err.contains("exactly 1 output"), "{err}");
    }

    #[test]
    fn found_multi_output_rejected() {
        let err = validate_sweep_destination(
            found(),
            &tx_paying(vec![expected_script(), expected_script()]),
        )
        .unwrap_err();
        assert!(err.contains("exactly 1 output"), "{err}");
    }

    #[test]
    fn found_wrong_destination_rejected() {
        // Single output paying an unrelated script must be refused (#414).
        let err =
            validate_sweep_destination(found(), &tx_paying(vec![ScriptBuf::from(vec![0x51])]))
                .unwrap_err();
        assert!(err.contains("does not pay"), "{err}");
    }

    #[test]
    fn found_correct_destination_accepted() {
        assert!(validate_sweep_destination(found(), &tx_paying(vec![expected_script()])).is_ok());
    }

    #[test]
    fn fee_at_cap_boundary_accepted() {
        // total_in = 40_000, cap = total_in / 4 = 10_000; fee == cap is allowed.
        assert!(check_sweep_fee([10_000u64, 30_000], 10_000).is_ok());
    }

    #[test]
    fn fee_above_cap_rejected() {
        let err = check_sweep_fee([40_000u64], 10_001).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn fee_cap_rounds_down_small_totals() {
        // total_in = 3, cap = 0; any positive fee is rejected, zero is allowed.
        assert!(check_sweep_fee([1u64, 2], 1).is_err());
        assert!(check_sweep_fee([1u64, 2], 0).is_ok());
    }

    #[test]
    fn input_value_overflow_rejected() {
        let err = check_sweep_fee([u64::MAX, 1], 0).unwrap_err();
        assert!(err.to_string().contains("overflow"), "{err}");
    }
}

#[cfg(test)]
mod proposer_and_identity_tests {
    use super::{detect_dual_identity_signer, proposer_authorized};
    use std::collections::HashSet;

    #[test]
    fn empty_allowlist_authorizes_any_proposer() {
        let proposers: HashSet<u16> = HashSet::new();
        assert!(proposer_authorized(&proposers, 7).is_ok());
    }

    #[test]
    fn nonempty_allowlist_authorizes_only_members() {
        let proposers: HashSet<u16> = HashSet::from([1, 2, 3]);
        assert!(proposer_authorized(&proposers, 2).is_ok());
        let err = proposer_authorized(&proposers, 4).unwrap_err();
        assert!(err.to_string().contains("not authorized"), "{err}");
    }

    #[test]
    fn dual_identity_overlap_rejected() {
        // Share 1's peer carries fingerprint "abcd", which is also an expected
        // fingerprint signer -> the same identity would count twice.
        let fps = vec!["ABCD".to_string()];
        let share_signers = vec![(1u16, fps.as_slice())];
        let expected = vec!["abcd".to_string()];
        let err = detect_dual_identity_signer(share_signers, &expected).unwrap_err();
        assert!(err.to_string().contains("Dual-identity"), "{err}");
    }

    #[test]
    fn dual_identity_match_is_case_insensitive_on_peer_side() {
        // Peer fingerprint upper-case, expected lower-case: still overlaps.
        let fps = vec!["DEADBEEF".to_string()];
        let share_signers = vec![(2u16, fps.as_slice())];
        let expected = vec!["deadbeef".to_string()];
        assert!(detect_dual_identity_signer(share_signers, &expected).is_err());
    }

    #[test]
    fn dual_identity_match_is_case_insensitive_on_expected_side() {
        // Expected (wire-supplied) fingerprint upper-case, peer lower-case: the
        // overlap must still be caught. Before the responder normalized wire
        // fingerprints and the guard lowercased its expected side, an uppercase
        // wire value slipped past this check, letting one identity count as both
        // a share signer and an external signer (dual-identity guard bypass).
        let fps = vec!["deadbeef".to_string()];
        let share_signers = vec![(2u16, fps.as_slice())];
        let expected = vec!["DEADBEEF".to_string()];
        assert!(detect_dual_identity_signer(share_signers, &expected).is_err());
    }

    #[test]
    fn disjoint_share_and_fingerprint_signers_accepted() {
        let fps = vec!["1111".to_string(), "2222".to_string()];
        let share_signers = vec![(1u16, fps.as_slice())];
        let expected = vec!["3333".to_string()];
        assert!(detect_dual_identity_signer(share_signers, &expected).is_ok());
    }

    #[test]
    fn no_share_signers_accepts() {
        let share_signers: Vec<(u16, &[String])> = Vec::new();
        let expected = vec!["abcd".to_string()];
        assert!(detect_dual_identity_signer(share_signers, &expected).is_ok());
    }

    #[test]
    fn dual_identity_match_on_later_fingerprint_rejected() {
        // A peer's second fingerprint overlaps: the inner loop must scan past
        // index 0, not just the first fingerprint.
        let fps = vec!["1111".to_string(), "2222".to_string()];
        let share_signers = vec![(3u16, fps.as_slice())];
        let expected = vec!["2222".to_string()];
        let err = detect_dual_identity_signer(share_signers, &expected).unwrap_err();
        assert!(err.to_string().contains("2222"), "{err}");
    }

    #[test]
    fn empty_expected_fingerprints_accepts_share_signers() {
        // No fingerprint signers means nothing can overlap, even with peers present.
        let fps = vec!["abcd".to_string()];
        let share_signers = vec![(1u16, fps.as_slice())];
        let expected: Vec<String> = Vec::new();
        assert!(detect_dual_identity_signer(share_signers, &expected).is_ok());
    }
}
