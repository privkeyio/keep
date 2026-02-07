// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::time::Duration;

use nostr_sdk::prelude::*;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::ecdh::{compute_partial_ecdh, derive_ecdh_session_id};
use crate::error::{FrostNetError, Result};
use crate::event::KfpEventBuilder;
use crate::protocol::*;

use super::{KfpNode, KfpNodeEvent};

impl KfpNode {
    pub(crate) async fn handle_ecdh_request(
        &self,
        from: PublicKey,
        request: EcdhRequestPayload,
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
                "Rejecting ECDH request: outside replay window"
            );
            return Err(FrostNetError::ReplayDetected(format!(
                "ECDH request created_at {} outside {} second window",
                request.created_at, self.replay_window_secs
            )));
        }

        if !self.can_receive_from(&from) {
            debug!(from = %from, "Rejecting ECDH request: policy denies receive");
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {} not allowed to send ECDH requests",
                from
            )));
        }

        info!(
            session_id = %hex::encode(request.session_id),
            "Received ECDH request"
        );

        let key_package = self.share.key_package()?;
        let signing_share = key_package.signing_share();
        let signing_share_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
            signing_share
                .serialize()
                .as_slice()
                .try_into()
                .map_err(|_| FrostNetError::Crypto("Invalid signing share length".into()))?,
        );

        let partial = compute_partial_ecdh(&signing_share_bytes, &request.recipient_pubkey)?;

        {
            let mut ecdh_sessions = self.ecdh_sessions.write();
            let session = ecdh_sessions.get_or_create_session(
                request.session_id,
                request.recipient_pubkey,
                self.share.metadata.threshold,
                request.participants.clone(),
            )?;
            session.add_partial(self.share.metadata.identifier, partial)?;
        }

        let payload = EcdhSharePayload::new(
            request.session_id,
            self.share.metadata.identifier,
            partial.to_vec(),
        );

        let event = KfpEventBuilder::ecdh_share(&self.keys, &from, payload)?;
        self.client
            .send_event(&event)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        debug!(
            session_id = %hex::encode(request.session_id),
            "Sent ECDH share"
        );

        Ok(())
    }

    pub(crate) async fn handle_ecdh_share(
        &self,
        from: PublicKey,
        payload: EcdhSharePayload,
    ) -> Result<()> {
        self.verify_peer_share_index(from, payload.share_index)?;

        let partial: [u8; 33] = payload
            .partial_point
            .as_slice()
            .try_into()
            .map_err(|_| FrostNetError::Crypto("Invalid partial point length".into()))?;

        self.peers.write().update_last_seen(payload.share_index);

        let shared_secret = {
            let mut ecdh_sessions = self.ecdh_sessions.write();
            let session = match ecdh_sessions.get_session_mut(&payload.session_id) {
                Some(s) => s,
                None => {
                    debug!(
                        session_id = %hex::encode(payload.session_id),
                        "No ECDH session for share"
                    );
                    return Ok(());
                }
            };

            session.add_partial(payload.share_index, partial)?;

            if session.has_all_shares() {
                session.try_complete()?
            } else {
                None
            }
        };

        if let Some(secret) = shared_secret {
            info!(
                session_id = %hex::encode(payload.session_id),
                "ECDH complete!"
            );

            self.ecdh_sessions
                .write()
                .complete_session(&payload.session_id);

            let _ = self.event_tx.send(KfpNodeEvent::EcdhComplete {
                session_id: payload.session_id,
                shared_secret: secret,
            });
        }

        Ok(())
    }

    pub(crate) async fn handle_ecdh_complete(
        &self,
        from: PublicKey,
        payload: EcdhCompletePayload,
    ) -> Result<()> {
        {
            let ecdh_sessions = self.ecdh_sessions.read();
            if let Some(session) = ecdh_sessions.get_session(&payload.session_id) {
                let peers = self.peers.read();
                let is_participant = session.participants().iter().any(|&idx| {
                    peers
                        .get_peer(idx)
                        .map(|p| p.pubkey == from)
                        .unwrap_or(false)
                });
                if !is_participant {
                    return Err(FrostNetError::UntrustedPeer(
                        "Sender not an ECDH session participant".into(),
                    ));
                }
            }
        }

        let shared_secret: [u8; 32] = payload
            .shared_secret
            .as_slice()
            .try_into()
            .map_err(|_| FrostNetError::Crypto("Invalid shared secret length".into()))?;

        info!(
            session_id = %hex::encode(payload.session_id),
            "Received completed ECDH secret"
        );

        self.ecdh_sessions
            .write()
            .complete_session(&payload.session_id);

        let _ = self.event_tx.send(KfpNodeEvent::EcdhComplete {
            session_id: payload.session_id,
            shared_secret,
        });

        Ok(())
    }

    pub async fn request_ecdh(&self, recipient_pubkey: &[u8; 33]) -> Result<[u8; 32]> {
        let threshold = self.share.metadata.threshold;

        let (participants, participant_peers) = self.select_eligible_peers(threshold as usize)?;

        let session_id = derive_ecdh_session_id(recipient_pubkey, &participants);

        info!(
            session_id = %hex::encode(session_id),
            participants = ?participants,
            "Initiating ECDH request"
        );

        let key_package = self.share.key_package()?;
        let signing_share = key_package.signing_share();
        let signing_share_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
            signing_share
                .serialize()
                .as_slice()
                .try_into()
                .map_err(|_| FrostNetError::Crypto("Invalid signing share length".into()))?,
        );

        let our_partial = compute_partial_ecdh(&signing_share_bytes, recipient_pubkey)?;

        {
            let mut ecdh_sessions = self.ecdh_sessions.write();
            let session = ecdh_sessions.create_session(
                session_id,
                *recipient_pubkey,
                self.share.metadata.threshold,
                participants.clone(),
            )?;
            session.add_partial(self.share.metadata.identifier, our_partial)?;
        }

        let request = EcdhRequestPayload::new(
            session_id,
            self.group_pubkey,
            *recipient_pubkey,
            participants.clone(),
        );

        let our_share_payload = EcdhSharePayload::new(
            session_id,
            self.share.metadata.identifier,
            our_partial.to_vec(),
        );

        for (share_index, pubkey) in participant_peers {
            let event = KfpEventBuilder::ecdh_request(&self.keys, &pubkey, request.clone())?;
            self.client
                .send_event(&event)
                .await
                .map_err(|e| FrostNetError::Transport(e.to_string()))?;

            let share_event =
                KfpEventBuilder::ecdh_share(&self.keys, &pubkey, our_share_payload.clone())?;
            self.client
                .send_event(&share_event)
                .await
                .map_err(|e| FrostNetError::Transport(e.to_string()))?;

            debug!(share_index, "Sent ECDH request and share");
        }

        let mut rx = self.event_tx.subscribe();
        let timeout = Duration::from_secs(30);

        let result = tokio::time::timeout(timeout, async {
            loop {
                match rx.recv().await {
                    Ok(KfpNodeEvent::EcdhComplete {
                        session_id: sid,
                        shared_secret,
                    }) => {
                        if sid == session_id {
                            return Ok(shared_secret);
                        }
                    }
                    Ok(KfpNodeEvent::EcdhFailed {
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
            Err(_) => Err(FrostNetError::Timeout("ECDH request timed out".into())),
        }
    }
}
