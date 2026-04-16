// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! WDC PSBT coordination handlers (recovery tier / scriptpath spends).

use std::collections::HashSet;

use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::error::{FrostNetError, Result};
use crate::event::KfpEventBuilder;
use crate::protocol::*;
use crate::psbt_session::{derive_psbt_session_id, SignerId};

use super::{KfpNode, KfpNodeEvent};

impl KfpNode {
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

        let our_index = self.share.metadata.identifier;
        self.check_psbt_proposer_authorized(our_index)?;

        let created_at = Timestamp::now().as_secs();
        let session_id = derive_psbt_session_id(
            &self.group_pubkey,
            &descriptor_hash,
            tier_index,
            &psbt,
            created_at,
        );

        let mut signers: HashSet<SignerId> = HashSet::new();
        for idx in &expected_share_signers {
            signers.insert(SignerId::Share(*idx));
        }
        for fp in &expected_fingerprints {
            signers.insert(SignerId::Fingerprint(fp.clone()));
        }

        let session_timeout = timeout_secs.map(std::time::Duration::from_secs);

        {
            let mut sessions = self.psbt_sessions.write();
            let session = sessions.create_session(
                session_id,
                self.group_pubkey,
                descriptor_hash,
                tier_index,
                psbt.clone(),
                required_threshold,
                signers,
                session_timeout,
            )?;
            session.set_initiator(self.keys.public_key());
        }

        let mut payload = PsbtProposePayload::new(
            session_id,
            self.group_pubkey,
            descriptor_hash,
            tier_index,
            psbt,
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

        let target_peers = self.bidirectional_online_peers();
        if target_peers.is_empty() {
            self.psbt_sessions.write().remove_session(&session_id);
            return Err(FrostNetError::Session(
                "No online peers to coordinate PSBT with".into(),
            ));
        }

        self.broadcast_psbt_event(&msg, &session_id, "psbt_propose", &target_peers)
            .await?;

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
                FrostNetError::UntrustedPeer(format!(
                    "PSBT proposal from unknown peer: {sender}"
                ))
            })?;
            peer.share_index
        };
        self.verify_peer_share_index(sender, sender_share_index)?;
        self.check_psbt_proposer_authorized(sender_share_index)?;

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

        let mut signers: HashSet<SignerId> = HashSet::new();
        for idx in &payload.expected_signers {
            signers.insert(SignerId::Share(*idx));
        }
        for fp in &payload.expected_fingerprints {
            signers.insert(SignerId::Fingerprint(fp.clone()));
        }

        let propose_timeout = match payload.timeout_secs {
            None => None,
            Some(t) if t > 0 && t <= PSBT_SESSION_MAX_TIMEOUT_SECS => {
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

    /// Encrypt and send a PSBT coordination message to each target peer. Any
    /// per-peer failure (encryption, signing, relay) aborts the broadcast with
    /// the first error.
    async fn broadcast_psbt_event(
        &self,
        msg: &KfpMessage,
        session_id: &[u8; 32],
        msg_type: &'static str,
        targets: &[PublicKey],
    ) -> Result<()> {
        for pubkey in targets {
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
        let sessions = self.descriptor_sessions.read();
        let mut saw_any_finalized = false;
        for (_, session) in sessions.iter_sessions() {
            if session.group_pubkey() != &self.group_pubkey {
                continue;
            }
            let Some(finalized) = session.descriptor() else {
                continue;
            };
            saw_any_finalized = true;
            let mut hasher = Sha256::new();
            hasher.update(finalized.external.as_bytes());
            hasher.update(finalized.internal.as_bytes());
            hasher.update(finalized.policy_hash);
            let expected: [u8; 32] = hasher.finalize().into();
            if &expected == descriptor_hash {
                return Ok(());
            }
        }
        if saw_any_finalized {
            return Err(FrostNetError::Session(
                "PSBT descriptor_hash does not match any finalized descriptor for this group"
                    .into(),
            ));
        }
        Ok(())
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
            session.add_signature(signer.clone(), merged_psbt, signer_marker(&signer))?;
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
            (Some(idx), _) => {
                self.verify_peer_share_index(sender, idx)?;
                SignerId::Share(idx)
            }
            (None, Some(fp)) => {
                let sender_fingerprints = {
                    let peers = self.peers.read();
                    let peer = peers.get_peer_by_pubkey(&sender).ok_or_else(|| {
                        FrostNetError::UntrustedPeer(format!(
                            "PsbtSign from unknown peer: {sender}"
                        ))
                    })?;
                    peer.recovery_xpubs
                        .iter()
                        .map(|x| x.fingerprint.clone())
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

        let (count, threshold, should_finalize, finalized_psbt) = {
            let mut sessions = self.psbt_sessions.write();
            let session = sessions
                .get_session_mut(&payload.session_id)
                .ok_or_else(|| FrostNetError::Session("unknown PSBT session".into()))?;

            session.add_signature(signer.clone(), payload.psbt, signer_marker(&signer))?;

            let threshold_met = session.threshold_met();
            let is_initiator = session.initiator() == Some(&self.keys.public_key());
            let already_finalized =
                matches!(session.state(), crate::psbt_session::PsbtSessionState::Finalized);
            let should_finalize = threshold_met && is_initiator && !already_finalized;
            let finalized_psbt = if should_finalize {
                session.current_psbt().to_vec()
            } else {
                Vec::new()
            };
            (
                session.signature_count(),
                session.required_threshold(),
                should_finalize,
                finalized_psbt,
            )
        };

        let _ = self.event_tx.send(KfpNodeEvent::PsbtSignatureReceived {
            session_id: payload.session_id,
            signer,
            signature_count: count,
            threshold,
        });

        if should_finalize {
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
        {
            let mut sessions = self.psbt_sessions.write();
            let session = sessions
                .get_session_mut(&session_id)
                .ok_or_else(|| FrostNetError::Session("unknown PSBT session".into()))?;
            session.set_finalized(finalized_psbt.clone(), final_tx.clone())?;
        }

        let mut payload = PsbtFinalizePayload::new(session_id, self.group_pubkey, finalized_psbt);
        if let Some((tx, id)) = final_tx {
            payload = payload.with_final_tx(tx, id);
        }
        let msg = KfpMessage::PsbtFinalize(payload);

        let target_peers = self.bidirectional_online_peers();
        self.broadcast_psbt_event(&msg, &session_id, "psbt_finalize", &target_peers)
            .await?;

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
            (Some(tx), Some(id)) => Some((tx, id)),
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
            let session = match sessions.get_session_mut(&payload.session_id) {
                Some(s) => s,
                None => {
                    debug!(
                        session_id = %hex::encode(payload.session_id),
                        "PsbtFinalize for unknown session, ignoring"
                    );
                    return Ok(());
                }
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
            if let Some(session) = sessions.get_session_mut(&session_id) {
                session.abort(reason.to_string());
            }
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
            let is_initiator = session
                .initiator()
                .map(|init| *init == sender)
                .unwrap_or(false);
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

fn signer_marker(signer: &SignerId) -> Vec<u8> {
    match signer {
        SignerId::Share(i) => {
            let mut v = Vec::with_capacity(3);
            v.push(0x01);
            v.extend_from_slice(&i.to_le_bytes());
            v
        }
        SignerId::Fingerprint(fp) => {
            let mut v = Vec::with_capacity(1 + fp.len());
            v.push(0x02);
            v.extend_from_slice(fp.as_bytes());
            v
        }
    }
}

fn sanitize_reason(reason: &str) -> String {
    let sanitized: String = reason
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NACK_REASON_LENGTH)
        .collect();
    if sanitized.is_empty() {
        "no reason given".to_string()
    } else {
        sanitized
    }
}
