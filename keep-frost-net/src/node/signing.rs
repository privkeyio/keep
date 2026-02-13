// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::time::Duration;

use frost_secp256k1_tr::rand_core::OsRng;
use nostr_sdk::prelude::*;
use tracing::{debug, info, warn};

use crate::audit::SigningOperation;
use crate::error::{FrostNetError, Result};
use crate::event::KfpEventBuilder;
use crate::protocol::*;
use crate::session::derive_session_id;

use super::{KfpNode, KfpNodeEvent, SessionInfo};

impl KfpNode {
    pub(crate) async fn handle_sign_request(
        &self,
        from: PublicKey,
        request: SignRequestPayload,
    ) -> Result<()> {
        if request.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        if !request
            .participants
            .contains(&self.share.metadata.identifier)
        {
            return Ok(());
        }

        if !request.is_within_replay_window(self.replay_window_secs) {
            warn!(
                session_id = %hex::encode(request.session_id),
                created_at = request.created_at,
                "Rejecting sign request: outside replay window"
            );
            return Err(FrostNetError::ReplayDetected(format!(
                "Request created_at {} outside {} second window",
                request.created_at, self.replay_window_secs
            )));
        }

        if !self.can_receive_from(&from) {
            debug!(from = %from, "Rejecting sign request: policy denies receive");
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {from} not allowed to send sign requests"
            )));
        }

        info!(
            session_id = %hex::encode(request.session_id),
            message_type = %request.message_type,
            "Received sign request"
        );

        let key_package = self.share.key_package()?;

        let existing_commitment = {
            let sessions = self.sessions.read();
            sessions
                .get_session(&request.session_id)
                .and_then(|s| s.our_commitment().copied())
        };

        if let Some(existing) = existing_commitment {
            debug!(
                session_id = %hex::encode(request.session_id),
                "Resending existing commitment for session"
            );
            let commit_bytes = existing
                .serialize()
                .map_err(|e| FrostNetError::Crypto(format!("Serialize commitment: {e}")))?;

            let payload = CommitmentPayload::new(
                request.session_id,
                self.share.metadata.identifier,
                commit_bytes.to_vec(),
            );

            let event = KfpEventBuilder::commitment(&self.keys, &from, payload)?;
            self.client
                .send_event(&event)
                .await
                .map_err(|e| FrostNetError::Transport(e.to_string()))?;

            debug!(
                session_id = %hex::encode(request.session_id),
                "Sent commitment"
            );

            return Ok(());
        }

        let requester = self
            .peers
            .read()
            .get_peer_by_pubkey(&from)
            .map(|p| p.share_index)
            .unwrap_or(0);

        let session_info = SessionInfo {
            session_id: request.session_id,
            message: request.message.clone(),
            threshold: self.share.metadata.threshold,
            participants: request.participants.clone(),
            requester,
        };

        let hooks = self.hooks.read().clone();
        hooks.pre_sign(&session_info)?;

        let commitment = {
            let mut sessions = self.sessions.write();

            let session = sessions.get_or_create_session(
                request.session_id,
                request.message.clone(),
                self.share.metadata.threshold,
                request.participants.clone(),
            )?;

            let (nonces, commitment) =
                frost_secp256k1_tr::round1::commit(key_package.signing_share(), &mut OsRng);

            session.set_our_nonces(nonces);
            session.set_our_commitment(commitment);
            session.add_commitment(self.share.metadata.identifier, commitment)?;

            sessions.record_nonce_consumption(&request.session_id)?;

            commitment
        };

        let commit_bytes = commitment
            .serialize()
            .map_err(|e| FrostNetError::Crypto(format!("Serialize commitment: {e}")))?;

        let payload = CommitmentPayload::new(
            request.session_id,
            self.share.metadata.identifier,
            commit_bytes.to_vec(),
        );

        let event = KfpEventBuilder::commitment(&self.keys, &from, payload)?;
        self.client
            .send_event(&event)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        debug!(
            session_id = %hex::encode(request.session_id),
            "Sent commitment"
        );

        self.audit_log.log_signing_operation(
            request.session_id,
            &request.message,
            None,
            request.participants,
            self.share.metadata.identifier,
            SigningOperation::CommitmentSent,
        );

        Ok(())
    }

    pub(crate) async fn handle_commitment(
        &self,
        from: PublicKey,
        payload: CommitmentPayload,
    ) -> Result<()> {
        self.verify_peer_share_index(from, payload.share_index)?;

        let commitment =
            frost_secp256k1_tr::round1::SigningCommitments::deserialize(&payload.commitment)
                .map_err(|e| FrostNetError::Crypto(format!("Invalid commitment: {e}")))?;

        let proceed_to_round2 = {
            let mut sessions = self.sessions.write();
            let session = match sessions.get_session_mut(&payload.session_id) {
                Some(s) => s,
                None => {
                    debug!(
                        session_id = %hex::encode(payload.session_id),
                        "No session for commitment"
                    );
                    return Ok(());
                }
            };

            session.add_commitment(payload.share_index, commitment)?;
            session.has_all_commitments()
        };

        self.peers.write().update_last_seen(payload.share_index);

        if proceed_to_round2 {
            self.generate_and_send_share(&payload.session_id).await?;
        }

        Ok(())
    }

    pub(crate) async fn generate_and_send_share(&self, session_id: &[u8; 32]) -> Result<()> {
        let key_package = self.share.key_package()?;

        let (signing_package, nonces) = {
            let mut sessions = self.sessions.write();
            let session = match sessions.get_session_mut(session_id) {
                Some(s) => s,
                None => return Err(FrostNetError::SessionNotFound(hex::encode(session_id))),
            };

            let signing_package = session.get_signing_package()?;
            let nonces = session
                .take_our_nonces()
                .ok_or_else(|| FrostNetError::Session("No nonces stored for session".into()))?;

            (signing_package, nonces)
        };

        let sig_share = frost_secp256k1_tr::round2::sign(&signing_package, &nonces, &key_package)
            .map_err(|e| FrostNetError::Crypto(format!("Signing failed: {e}")))?;

        {
            let mut sessions = self.sessions.write();
            if let Some(session) = sessions.get_session_mut(session_id) {
                session.add_signature_share(self.share.metadata.identifier, sig_share)?;
            }
        }

        let share_bytes = sig_share.serialize();
        let payload = SignatureSharePayload::new(
            *session_id,
            self.share.metadata.identifier,
            share_bytes.to_vec(),
        );

        let (session_participants, session_message): (Vec<u16>, Vec<u8>) = {
            let sessions = self.sessions.read();
            sessions
                .get_session(session_id)
                .map(|s| (s.participants().to_vec(), s.message().to_vec()))
                .unwrap_or_default()
        };

        let peer_pubkeys: Vec<PublicKey> = self
            .peers
            .read()
            .get_online_peers()
            .iter()
            .filter(|p| session_participants.contains(&p.share_index))
            .map(|p| p.pubkey)
            .collect();

        for pubkey in peer_pubkeys {
            let event = KfpEventBuilder::signature_share(&self.keys, &pubkey, payload.clone())?;
            self.client
                .send_event(&event)
                .await
                .map_err(|e| FrostNetError::Transport(e.to_string()))?;
        }

        debug!(session_id = %hex::encode(session_id), "Sent signature share");

        self.audit_log.log_signing_operation(
            *session_id,
            &session_message,
            None,
            session_participants,
            self.share.metadata.identifier,
            SigningOperation::SignatureShareSent,
        );

        Ok(())
    }

    pub(crate) async fn handle_signature_share(
        &self,
        from: PublicKey,
        payload: SignatureSharePayload,
    ) -> Result<()> {
        self.verify_peer_share_index(from, payload.share_index)?;

        let sig_share =
            frost_secp256k1_tr::round2::SignatureShare::deserialize(&payload.signature_share)
                .map_err(|e| FrostNetError::Crypto(format!("Invalid signature share: {e}")))?;

        self.peers.write().update_last_seen(payload.share_index);

        let (signature, session_message, session_participants) = {
            let mut sessions = self.sessions.write();
            let session = match sessions.get_session_mut(&payload.session_id) {
                Some(s) => s,
                None => return Ok(()),
            };

            let msg = session.message().to_vec();
            let parts = session.participants().to_vec();

            session.add_signature_share(payload.share_index, sig_share)?;

            let sig = if session.has_all_shares() {
                let pubkey_pkg = self.share.pubkey_package()?;
                session.try_aggregate(&pubkey_pkg)?
            } else {
                None
            };

            (sig, msg, parts)
        };

        if let Some(sig) = signature {
            info!(
                session_id = %hex::encode(payload.session_id),
                "Signature complete!"
            );

            self.audit_log.log_signing_operation(
                payload.session_id,
                &session_message,
                Some(&sig),
                session_participants,
                self.share.metadata.identifier,
                SigningOperation::SignatureCompleted,
            );

            self.invoke_post_sign_hook(&payload.session_id, &sig);

            let _ = self.event_tx.send(KfpNodeEvent::SignatureComplete {
                session_id: payload.session_id,
                signature: sig,
            });
        }

        Ok(())
    }

    pub(crate) async fn handle_signature_complete(
        &self,
        from: PublicKey,
        payload: SignatureCompletePayload,
    ) -> Result<()> {
        {
            let sessions = self.sessions.read();
            if let Some(session) = sessions.get_session(&payload.session_id) {
                let peers = self.peers.read();
                let is_participant = session.participants().iter().any(|&idx| {
                    peers
                        .get_peer(idx)
                        .map(|p| p.pubkey == from)
                        .unwrap_or(false)
                });
                if !is_participant {
                    return Err(FrostNetError::UntrustedPeer(
                        "Sender not a session participant".into(),
                    ));
                }
            }
        }

        info!(
            session_id = %hex::encode(payload.session_id),
            "Received completed signature"
        );

        let (session_message, session_participants) = {
            let sessions = self.sessions.read();
            sessions
                .get_session(&payload.session_id)
                .map(|s| (s.message().to_vec(), s.participants().to_vec()))
                .unwrap_or_default()
        };

        self.audit_log.log_signing_operation(
            payload.session_id,
            &session_message,
            Some(&payload.signature),
            session_participants,
            self.share.metadata.identifier,
            SigningOperation::SignatureReceived,
        );

        self.invoke_post_sign_hook(&payload.session_id, &payload.signature);

        let _ = self.event_tx.send(KfpNodeEvent::SignatureComplete {
            session_id: payload.session_id,
            signature: payload.signature,
        });

        Ok(())
    }

    pub async fn request_signature(
        &self,
        message: Vec<u8>,
        message_type: &str,
    ) -> Result<[u8; 64]> {
        let threshold = self.share.metadata.threshold;

        let (participants, participant_peers) = self.select_eligible_peers(threshold as usize)?;

        let session_id = derive_session_id(&message, &participants, threshold);

        info!(
            session_id = %hex::encode(session_id),
            participants = ?participants,
            "Initiating signing request"
        );

        self.audit_log.log_signing_operation(
            session_id,
            &message,
            None,
            participants.clone(),
            self.share.metadata.identifier,
            SigningOperation::SignRequestInitiated,
        );

        let request = SignRequestPayload::new(
            session_id,
            self.group_pubkey,
            message.clone(),
            message_type,
            participants.clone(),
        );

        let key_package = self.share.key_package()?;
        let (nonces, our_commitment) =
            frost_secp256k1_tr::round1::commit(key_package.signing_share(), &mut OsRng);

        {
            let mut sessions = self.sessions.write();
            let session = sessions.create_session(
                session_id,
                message,
                self.share.metadata.threshold,
                participants.clone(),
            )?;

            session.set_our_nonces(nonces);
            session.set_our_commitment(our_commitment);
            session.add_commitment(self.share.metadata.identifier, our_commitment)?;

            // Record consumption AFTER nonces are generated to prevent reuse across restarts
            sessions.record_nonce_consumption(&session_id)?;
        }

        let session_info = {
            let sessions = self.sessions.read();
            sessions
                .get_session(&session_id)
                .map(SessionInfo::from)
                .ok_or_else(|| FrostNetError::SessionNotFound(hex::encode(session_id)))?
        };
        let hooks = self.hooks.read().clone();
        if let Err(e) = hooks.pre_sign(&session_info) {
            self.cleanup_session_on_hook_failure(&session_id);
            return Err(e);
        }

        let our_commit_bytes = our_commitment
            .serialize()
            .map_err(|e| FrostNetError::Crypto(format!("Serialize commitment: {e}")))?;
        let our_commit_payload = CommitmentPayload::new(
            session_id,
            self.share.metadata.identifier,
            our_commit_bytes.to_vec(),
        );

        for (share_index, pubkey) in participant_peers {
            let event = KfpEventBuilder::sign_request(&self.keys, &pubkey, request.clone())?;
            self.client
                .send_event(&event)
                .await
                .map_err(|e| FrostNetError::Transport(e.to_string()))?;

            let commit_event =
                KfpEventBuilder::commitment(&self.keys, &pubkey, our_commit_payload.clone())?;
            self.client
                .send_event(&commit_event)
                .await
                .map_err(|e| FrostNetError::Transport(e.to_string()))?;

            debug!(share_index, "Sent sign request and commitment");
        }

        let mut rx = self.event_tx.subscribe();
        let timeout = Duration::from_secs(30);

        let result = tokio::time::timeout(timeout, async {
            loop {
                match rx.recv().await {
                    Ok(KfpNodeEvent::SignatureComplete {
                        session_id: sid,
                        signature,
                    }) => {
                        if sid == session_id {
                            return Ok(signature);
                        }
                    }
                    Ok(KfpNodeEvent::SigningFailed {
                        session_id: sid,
                        error,
                    }) => {
                        if sid == session_id {
                            return Err(FrostNetError::Session(error));
                        }
                    }
                    Err(_) => {
                        return Err(FrostNetError::Transport("Event channel closed".into()));
                    }
                    _ => {}
                }
            }
        })
        .await;

        match result {
            Ok(r) => r,
            Err(_) => Err(FrostNetError::Timeout("Signing request timed out".into())),
        }
    }
}
