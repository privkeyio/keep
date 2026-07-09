// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

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
                "Peer {from} not allowed to send ECDH requests"
            )));
        }

        // Attestation gate, matching the OPRF/enroll oracles (the #621 ship-gate
        // this responder was missing): a quorum of these partials combines to
        // the group's ECDH shared secret with an attacker-chosen recipient, so
        // answer only a requester whose measured boot is freshly Verified. A
        // stolen network identity replayed from un-attested hardware must not
        // extract group ECDH secrets, even though policy (`can_receive_from`)
        // still lists its pubkey. Fresh-Verified (not a bare `Verified`) so a
        // stale verdict is not honored on credit; see `is_attestation_fresh`.
        {
            let peers = self.peers.read();
            let peer = peers.get_peer_by_pubkey(&from).ok_or_else(|| {
                FrostNetError::UntrustedPeer(format!("ECDH requester {from} not announced"))
            })?;
            if !peer.is_attestation_fresh(peers.offline_threshold()) {
                return Err(FrostNetError::UntrustedPeer(format!(
                    "ECDH requester {from} attestation not fresh-Verified ({:?})",
                    peer.attestation_status
                )));
            }
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
                shared_secret: Zeroizing::new(*secret),
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
            let session = ecdh_sessions
                .get_session(&payload.session_id)
                .ok_or_else(|| {
                    FrostNetError::Session(format!(
                        "No ECDH session found for {}",
                        hex::encode(payload.session_id)
                    ))
                })?;
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

        let shared_secret: Zeroizing<[u8; 32]> = Zeroizing::new(
            payload
                .shared_secret
                .as_slice()
                .try_into()
                .map_err(|_| FrostNetError::Crypto("Invalid shared secret length".into()))?,
        );

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

    pub async fn request_ecdh(&self, recipient_pubkey: &[u8; 33]) -> Result<Zeroizing<[u8; 32]>> {
        let threshold = self.share.metadata.threshold;

        let (participants, participant_peers) =
            self.select_eligible_peers(threshold as usize, &[])?;

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

        // Subscribe BEFORE sending: a fast cosigner can respond, our run loop
        // can call `handle_ecdh_share`, and the resulting `EcdhComplete` can
        // fire on `event_tx` between the send loop and our `subscribe()`.
        // `tokio::sync::broadcast` does not replay past messages to late
        // subscribers, so a missed completion stalls the request until the
        // 30s coordination timeout — exactly the flake in #561.
        let mut rx = self.event_tx.subscribe();

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

        // For single-participant (threshold=1), our own partial is the only one needed.
        let single_party_secret = {
            let mut ecdh_sessions = self.ecdh_sessions.write();
            match ecdh_sessions.get_session_mut(&session_id) {
                Some(s) if s.has_all_shares() => match s.try_complete() {
                    Ok(secret) => secret,
                    Err(e) => {
                        // Drop the failed session instead of leaving it in
                        // active_sessions until cleanup_expired reaps it.
                        ecdh_sessions.complete_session(&session_id);
                        return Err(e);
                    }
                },
                _ => None,
            }
        };
        if let Some(secret) = single_party_secret {
            info!(
                session_id = %hex::encode(session_id),
                "ECDH complete (single-party)!"
            );
            self.ecdh_sessions.write().complete_session(&session_id);
            if let Err(e) = self.event_tx.send(KfpNodeEvent::EcdhComplete {
                session_id,
                shared_secret: Zeroizing::new(*secret),
            }) {
                warn!(
                    session_id = %hex::encode(session_id),
                    error = %e,
                    "Failed to send EcdhComplete event (single-party)"
                );
            }
        }

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
                    // `Lagged` is recoverable: the receiver stays live, so
                    // keep waiting rather than aborting a valid coordination.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err(FrostNetError::Transport("Event channel closed".into()));
                    }
                    _ => {}
                }
            }
        })
        .await;

        let result = match result {
            Ok(r) => r,
            Err(_) => Err(FrostNetError::Timeout("ECDH request timed out".into())),
        };
        // Tear down the session on any non-success exit so it doesn't linger in
        // active_sessions until cleanup_expired reaps it (matches the
        // single-party error path above and signing.rs).
        if result.is_err() {
            self.ecdh_sessions.write().complete_session(&session_id);
        }
        result
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    use crate::node::PeerPolicy;
    use keep_core::frost::{ThresholdConfig, TrustedDealer};
    use nostr_relay_builder::MockRelay;

    // Not a valid compressed point: if a responder gate is (incorrectly)
    // bypassed, the proceed path fails at `compute_partial_ecdh`, so asserting
    // `Ok` on an ignore-gate still kills the predicate mutation.
    const BAD_RECIPIENT: [u8; 33] = [0xFF; 33];

    // Returns the relay guard alongside the node; callers must keep it alive so
    // the node's client stays connected. The gate tests here all short-circuit
    // before sending, but a future proceed/send test through this helper would
    // fail confusingly if the relay were dropped early.
    async fn test_node() -> (KfpNode, MockRelay) {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
        let mock = MockRelay::run().await.unwrap();
        let relay = mock.url().await.to_string();
        let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
        let (mut shares, _) = dealer.generate("ecdh-gate-test").unwrap();
        // First share -> FROST identifier 1.
        let node = KfpNode::new(shares.remove(0), vec![relay]).await.unwrap();
        (node, mock)
    }

    /// A request for a different group is silently ignored (returns Ok without
    /// producing a share). Pins the group-membership early-return.
    #[tokio::test]
    async fn handle_ecdh_request_ignores_foreign_group() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let req = EcdhRequestPayload::new([1u8; 32], [0xAA; 32], BAD_RECIPIENT, vec![1]);
        assert!(node.handle_ecdh_request(from, req).await.is_ok());
    }

    /// A request whose participant set excludes our own identifier is ignored.
    #[tokio::test]
    async fn handle_ecdh_request_ignores_non_participant() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let group = *node.group_pubkey();
        let req = EcdhRequestPayload::new([1u8; 32], group, BAD_RECIPIENT, vec![2, 3]);
        assert!(node.handle_ecdh_request(from, req).await.is_ok());
    }

    /// A stale request (created_at outside the replay window) is rejected.
    #[tokio::test]
    async fn handle_ecdh_request_rejects_stale_replay() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let group = *node.group_pubkey();
        let req = EcdhRequestPayload {
            session_id: [1u8; 32],
            group_pubkey: group,
            recipient_pubkey: BAD_RECIPIENT,
            participants: vec![1],
            created_at: 1, // ancient -> outside the replay window
        };
        assert!(matches!(
            node.handle_ecdh_request(from, req).await,
            Err(FrostNetError::ReplayDetected(_))
        ));
    }

    /// A far-future request (created_at beyond the skew bound) is rejected.
    /// Pins the upper side of the replay window, distinct from the stale case.
    #[tokio::test]
    async fn handle_ecdh_request_rejects_future_skew() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let group = *node.group_pubkey();
        let req = EcdhRequestPayload {
            session_id: [1u8; 32],
            group_pubkey: group,
            recipient_pubkey: BAD_RECIPIENT,
            participants: vec![1],
            created_at: Timestamp::now().as_secs() + 3600, // beyond MAX_FUTURE_SKEW_SECS
        };
        assert!(matches!(
            node.handle_ecdh_request(from, req).await,
            Err(FrostNetError::ReplayDetected(_))
        ));
    }

    /// A peer denied by policy cannot open an ECDH request. Fresh `created_at`
    /// passes the replay gate so the policy gate is what trips.
    #[tokio::test]
    async fn handle_ecdh_request_rejects_denied_peer() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let group = *node.group_pubkey();
        node.set_peer_policy(PeerPolicy::new(from).allow_receive(false));
        let req = EcdhRequestPayload::new([1u8; 32], group, BAD_RECIPIENT, vec![1]);
        assert!(matches!(
            node.handle_ecdh_request(from, req).await,
            Err(FrostNetError::PolicyViolation(_))
        ));
    }
    /// A round2 share from a peer whose share index is not announced is
    /// rejected (`verify_peer_share_index`). Also pins the whole-function
    /// "replace with Ok(())" mutation, since the correct path returns Err.
    #[tokio::test]
    async fn handle_ecdh_share_rejects_unannounced_peer() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let payload = EcdhSharePayload::new([1u8; 32], 2, vec![0u8; 33]);
        assert!(matches!(
            node.handle_ecdh_share(from, payload).await,
            Err(FrostNetError::UntrustedPeer(_))
        ));
    }

    /// A completed-secret announcement for an unknown session is rejected
    /// (session-lookup gate) rather than silently accepted.
    #[tokio::test]
    async fn handle_ecdh_complete_rejects_unknown_session() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let payload = EcdhCompletePayload {
            session_id: [9u8; 32],
            shared_secret: Zeroizing::new(vec![0u8; 32]),
        };
        assert!(matches!(
            node.handle_ecdh_complete(from, payload).await,
            Err(FrostNetError::Session(_))
        ));
    }

    /// A requester that is not a known peer at all is refused: the ECDH oracle
    /// exposes the group's shared secret, so an unannounced pubkey cannot invoke
    /// it. Fresh `created_at` passes the replay gate so the attestation gate is
    /// what trips.
    #[tokio::test]
    async fn handle_ecdh_request_rejects_unannounced_requester() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let group = *node.group_pubkey();
        let req = EcdhRequestPayload::new([1u8; 32], group, BAD_RECIPIENT, vec![1]);
        assert!(matches!(
            node.handle_ecdh_request(from, req).await,
            Err(FrostNetError::UntrustedPeer(_))
        ));
    }

    /// A known but unattested (default `NotProvided`) requester is refused,
    /// matching the OPRF/enroll oracles. Reaching the attestation gate proves
    /// group/participant/replay/policy all passed first.
    #[tokio::test]
    async fn handle_ecdh_request_rejects_unattested_requester() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        node.test_inject_peer(crate::peer::Peer::new(from, 2));
        let group = *node.group_pubkey();
        let req = EcdhRequestPayload::new([1u8; 32], group, BAD_RECIPIENT, vec![1]);
        assert!(matches!(
            node.handle_ecdh_request(from, req).await,
            Err(FrostNetError::UntrustedPeer(_))
        ));
    }
}
