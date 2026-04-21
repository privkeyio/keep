// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! WDC PSBT coordination handlers (recovery tier / scriptpath spends).

use std::collections::HashSet;

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
}

impl KfpNode {
    /// Return a display-safe snapshot for the given PSBT session. Returns
    /// `None` if the session does not exist or the stored PSBT fails to
    /// decode.
    pub fn psbt_session_snapshot(&self, session_id: &[u8; 32]) -> Option<PsbtSessionSnapshot> {
        let sessions = self.psbt_sessions.read();
        let session = sessions.get_session(session_id)?;
        let initiator = *session.initiator()?;
        let descriptor_hash = *session.descriptor_hash();
        let (psbt_hash, output_count, fee_sats) = decode_psbt_for_snapshot(session.proposal_psbt())?;
        let network = self
            .descriptor_lookup
            .as_deref()
            .and_then(|l| l.network_for(&self.group_pubkey, &descriptor_hash))
            .unwrap_or_else(|| "unknown".to_string());
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
        })
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
                let mut hasher = Sha256::new();
                hasher.update((finalized.external.len() as u64).to_le_bytes());
                hasher.update(finalized.external.as_bytes());
                hasher.update((finalized.internal.len() as u64).to_le_bytes());
                hasher.update(finalized.internal.as_bytes());
                hasher.update(finalized.policy_hash);
                let expected: [u8; 32] = hasher.finalize().into();
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

        // Commit the signature to our local session before sending so we
        // reject duplicate local contributions on retry, but capture enough
        // information to roll back if the wire send fails.
        {
            let mut sessions = self.psbt_sessions.write();
            let session = sessions
                .get_session_mut(&session_id)
                .ok_or_else(|| FrostNetError::Session("unknown PSBT session".into()))?;
            session.add_signature(signer.clone(), merged_psbt.clone())?;
        }

        let event = match KfpEventBuilder::psbt_event(
            &self.keys,
            initiator_pubkey,
            &self.group_pubkey,
            &session_id,
            "psbt_sign",
            &msg,
        ) {
            Ok(e) => e,
            Err(e) => {
                self.rollback_local_signature(&session_id, &signer);
                return Err(e);
            }
        };

        if let Err(e) = self.client.send_event(&event).await {
            self.rollback_local_signature(&session_id, &signer);
            return Err(FrostNetError::Transport(e.to_string()));
        }

        info!(session_id = %hex::encode(session_id), "Sent PSBT signature contribution");
        Ok(())
    }

    fn rollback_local_signature(&self, session_id: &[u8; 32], signer: &SignerId) {
        let mut sessions = self.psbt_sessions.write();
        if let Some(session) = sessions.get_session_mut(session_id) {
            if !session.remove_signature(signer) {
                debug!(
                    session_id = %hex::encode(session_id),
                    "rollback_local_signature: no local signature to remove"
                );
            }
        }
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
            let should_finalize = is_initiator && session.begin_finalize();
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
                    .map_err(|e| {
                        FrostNetError::Session(format!("final_tx decode failed: {e}"))
                    })?;
                let computed_bytes: [u8; 32] = decoded.compute_txid().to_byte_array();
                if computed_bytes != id {
                    return Err(FrostNetError::Session(
                        "PsbtFinalize txid does not match final_tx bytes".into(),
                    ));
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

/// Combine every signer's merged PSBT with the proposal PSBT using
/// `Psbt::combine`. Fails if any partial is undecodable, combination fails,
/// or fewer than `required_threshold` distinct tap_script / partial
/// signatures are present on every input of the aggregated PSBT.
fn aggregate_partial_psbts(
    proposal_psbt: &[u8],
    partial_psbts: &std::collections::HashMap<SignerId, Vec<u8>>,
    required_threshold: u32,
) -> Result<Vec<u8>> {
    let mut aggregated = bitcoin::psbt::Psbt::deserialize(proposal_psbt)
        .map_err(|e| FrostNetError::Session(format!("proposal PSBT decode failed: {e}")))?;
    for (signer, bytes) in partial_psbts {
        let partial = bitcoin::psbt::Psbt::deserialize(bytes).map_err(|e| {
            FrostNetError::Session(format!("partial PSBT decode failed for {signer:?}: {e}"))
        })?;
        aggregated.combine(partial).map_err(|e| {
            FrostNetError::Session(format!("PSBT combine failed for {signer:?}: {e}"))
        })?;
    }
    // Threshold check assumes recovery-tier (tap_script_sigs) or classic multisig
    // (partial_sigs) semantics where each signer contributes a distinct signature.
    // FROST key-path spends produce a single aggregated tap_key_sig regardless of
    // threshold; this check must be revised before reuse on that path.
    for (idx, input) in aggregated.inputs.iter().enumerate() {
        let sig_count = input.partial_sigs.len()
            + input.tap_script_sigs.len()
            + usize::from(input.tap_key_sig.is_some());
        if (sig_count as u32) < required_threshold {
            return Err(FrostNetError::Session(format!(
                "aggregated PSBT input {idx} has {sig_count} signatures, below threshold {required_threshold}"
            )));
        }
    }
    Ok(aggregated.serialize())
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
}
