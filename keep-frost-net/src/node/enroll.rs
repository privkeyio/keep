// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Trusted-dealer OPRF enrollment wired over KFP.
//!
//! The "box" (dealer) has already generated an OPRF secret and Shamir-split it.
//! It distributes each remote FROST peer (holder) that peer's secret key share
//! inside a NIP-44-encrypted [`OprfEnrollPayload`] and collects an
//! [`OprfEnrollAckPayload`] from each. The dealer's OWN share is never sent (the
//! caller TPM-seals it). Mirrors [`super::oprf`] with the same #621 gate ordering
//! on the holder side; the share is the most sensitive payload in the system and
//! is never logged.

use std::time::Duration;

use nostr_sdk::prelude::*;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::enroll_session::derive_oprf_enroll_session_id;
use crate::error::{FrostNetError, Result};
use crate::event::KfpEventBuilder;
use crate::peer::AttestationStatus;
use crate::protocol::*;

use super::{KfpNode, KfpNodeEvent};

impl KfpNode {
    /// Dealer side: distribute each remote target's OPRF secret key share and
    /// await an ack from every target. `shares` maps a target FROST share index
    /// to the 64-byte `serialize_key_share` output for that target; it MUST NOT
    /// include the dealer's own share (the caller seals that locally). `threshold`
    /// and `total` are the OPRF Shamir parameters. Mirrors
    /// [`KfpNode::request_oprf_unlock`]'s subscribe-before-send + timeout shape.
    pub async fn distribute_oprf_shares(
        &self,
        shares: Vec<(u16, Zeroizing<Vec<u8>>)>,
        threshold: u16,
        total: u16,
    ) -> Result<()> {
        if shares.is_empty() {
            return Err(FrostNetError::Protocol(
                "No OPRF shares to distribute".into(),
            ));
        }
        if threshold < 2 || threshold > total {
            return Err(FrostNetError::Protocol(
                "OPRF enrollment requires 2 <= threshold <= total".into(),
            ));
        }
        if total as usize > MAX_PARTICIPANTS {
            return Err(FrostNetError::Protocol(
                "OPRF enrollment total exceeds maximum participants".into(),
            ));
        }

        let our_index = self.share.metadata.identifier;

        // Resolve every target peer up-front. A missing or non-sendable target,
        // or the dealer's own index, aborts before any share leaves the box.
        let mut deliveries: Vec<(u16, PublicKey, Zeroizing<Vec<u8>>)> =
            Vec::with_capacity(shares.len());
        let mut target_indices: Vec<u16> = Vec::with_capacity(shares.len());
        {
            let peers = self.peers.read();
            for (target_index, share_bytes) in shares {
                if target_index == 0 {
                    return Err(FrostNetError::Protocol(
                        "OPRF enrollment target index must be non-zero".into(),
                    ));
                }
                if target_index == our_index {
                    return Err(FrostNetError::Protocol(
                        "Dealer must not distribute its own OPRF share".into(),
                    ));
                }
                // Canonically validate every share (length, canonical scalars, non-zero id) by
                // deserializing it before anything leaves the box, so a single malformed share
                // aborts the whole round up front instead of being partially distributed and
                // failing on a holder. Scrub the decoded live scalar immediately.
                {
                    use zeroize::Zeroize;
                    let mut decoded =
                        keep_core::oprf::threshold::deserialize_key_share(&share_bytes).map_err(
                            |e| {
                                FrostNetError::Protocol(format!(
                                    "OPRF enrollment share {target_index} invalid: {e}"
                                ))
                            },
                        )?;
                    decoded.zeroize();
                }
                if target_indices.contains(&target_index) {
                    return Err(FrostNetError::Protocol(
                        "Duplicate OPRF enrollment target index".into(),
                    ));
                }
                let peer = peers.get_peer(target_index).ok_or_else(|| {
                    FrostNetError::UntrustedPeer(format!(
                        "OPRF enrollment target share {target_index} not announced"
                    ))
                })?;
                if !self.can_send_to(&peer.pubkey) {
                    return Err(FrostNetError::PolicyViolation(format!(
                        "Policy denies sending OPRF enrollment to share {target_index}"
                    )));
                }
                deliveries.push((target_index, peer.pubkey, share_bytes));
                target_indices.push(target_index);
            }
        }

        let nonce = Timestamp::now().as_secs();
        let session_id = derive_oprf_enroll_session_id(&self.group_pubkey, &target_indices, nonce);

        info!(
            session_id = %hex::encode(session_id),
            targets = ?target_indices,
            "Distributing OPRF enrollment shares"
        );

        {
            let mut sessions = self.enroll_sessions.write();
            sessions.create_session(
                session_id,
                self.group_pubkey,
                target_indices.iter().copied().collect(),
                threshold,
                total,
            )?;
        }

        // Subscribe BEFORE sending so a fast holder's ack, processed by our run
        // loop, cannot fire `OprfEnrollComplete` before we start listening
        // (broadcast does not replay to late subscribers).
        let mut rx = self.event_tx.subscribe();

        let send_result: Result<()> = async {
            for (target_index, pubkey, share_bytes) in deliveries {
                let payload = OprfEnrollPayload::new(
                    session_id,
                    self.group_pubkey,
                    our_index,
                    target_index,
                    threshold,
                    total,
                    share_bytes,
                );
                let event = KfpEventBuilder::oprf_enroll(&self.keys, &pubkey, payload)?;
                self.client
                    .send_event(&event)
                    .await
                    .map_err(|e| FrostNetError::Transport(e.to_string()))?;
                debug!(target_index, "Sent OPRF enrollment share");
            }
            Ok(())
        }
        .await;
        if let Err(e) = send_result {
            self.enroll_sessions.write().complete_session(&session_id);
            return Err(e);
        }

        let timeout = Duration::from_secs(30);
        let result = tokio::time::timeout(timeout, async {
            loop {
                match rx.recv().await {
                    Ok(KfpNodeEvent::OprfEnrollComplete { session_id: sid })
                        if sid == session_id =>
                    {
                        return Ok(());
                    }
                    Ok(KfpNodeEvent::OprfEnrollFailed {
                        session_id: sid,
                        error,
                    }) if sid == session_id => {
                        return Err(FrostNetError::Session(error));
                    }
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
            Err(_) => Err(FrostNetError::Timeout("OPRF enrollment timed out".into())),
        };
        // Tear the session down on any exit (success or failure) so it does not
        // linger until cleanup_expired reaps it.
        self.enroll_sessions.write().complete_session(&session_id);
        result
    }

    /// Holder side: take custody of an OPRF secret key share from a trusted
    /// dealer, after passing every #621 gate, in order: group / addressed-to-us /
    /// replay / policy, pubkey↔dealer-index binding, STRICT attestation of the
    /// dealer, then share validation. Only then is `OprfShareReceived` emitted
    /// (so the node/app seals it) and an ack returned. The share is never logged.
    pub(crate) async fn handle_oprf_enroll(
        &self,
        from: PublicKey,
        payload: OprfEnrollPayload,
    ) -> Result<()> {
        // 1. Group binding.
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        // 2. The share must be addressed to this node.
        if payload.target_index != self.share.metadata.identifier {
            return Ok(());
        }

        // 3. Replay window.
        if !payload.is_within_replay_window(self.replay_window_secs) {
            warn!(
                session_id = %hex::encode(payload.session_id),
                created_at = payload.created_at,
                "Rejecting OPRF enrollment: outside replay window"
            );
            return Err(FrostNetError::ReplayDetected(format!(
                "OPRF enrollment created_at {} outside {} second window",
                payload.created_at, self.replay_window_secs
            )));
        }

        // 4. Receive policy.
        if !self.can_receive_from(&from) {
            debug!(from = %from, "Rejecting OPRF enrollment: policy denies receive");
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {from} not allowed to send OPRF enrollment"
            )));
        }

        // 5. Bind the dealer's pubkey to its claimed share index.
        self.verify_peer_share_index(from, payload.dealer_index)?;

        // 5b. If a designated dealer is pinned, refuse enrollment from any other index, so a
        // compromised-but-attested group member cannot poison or overwrite this holder's share.
        if let Some(expected) = self.expected_oprf_dealer {
            if payload.dealer_index != expected {
                return Err(FrostNetError::UntrustedPeer(format!(
                    "OPRF enrollment from share {} but the designated dealer is {expected}",
                    payload.dealer_index
                )));
            }
        }

        // 6. Attestation gate: taking custody of a key share from an unattested
        // dealer is unsafe, so require VERIFIED attestation (STRICT, like the eval
        // oracle), not merely `is_attested()`.
        {
            let peers = self.peers.read();
            let peer = peers.get_peer(payload.dealer_index).ok_or_else(|| {
                FrostNetError::UntrustedPeer(format!(
                    "OPRF enrollment dealer share {} not announced",
                    payload.dealer_index
                ))
            })?;
            if !matches!(peer.attestation_status, AttestationStatus::Verified) {
                return Err(FrostNetError::UntrustedPeer(format!(
                    "OPRF enrollment dealer share {} attestation not Verified ({:?})",
                    payload.dealer_index, peer.attestation_status
                )));
            }
        }

        // 7. Validate the share itself (length / canonical scalars / non-zero id), then scrub the
        // decoded `KeyShare`: per the keep_core::oprf contract it is Copy + Zeroize but NOT
        // ZeroizeOnDrop, so the live secret scalar must be wiped once re-serialized rather than
        // left resident after custody is taken.
        use zeroize::Zeroize;
        let mut validated = keep_core::oprf::threshold::deserialize_key_share(&payload.share)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;
        let share_bytes = keep_core::oprf::threshold::serialize_key_share(&validated);
        validated.zeroize();

        info!(
            session_id = %hex::encode(payload.session_id),
            dealer = payload.dealer_index,
            "Received OPRF enrollment share"
        );

        // Hand the validated share to the node/app to seal (TPM or keystore); that
        // is not this protocol's job. The Debug impl redacts the share. A broadcast
        // send errors only when there are zero receivers: if nothing is subscribed
        // to take custody, the share would be silently dropped, so refuse to ack
        // rather than tell the dealer enrollment succeeded with no share sealed.
        if self
            .event_tx
            .send(KfpNodeEvent::OprfShareReceived {
                dealer_index: payload.dealer_index,
                threshold: payload.threshold,
                total: payload.total,
                share: Zeroizing::new(share_bytes.to_vec()),
            })
            .is_err()
        {
            return Err(FrostNetError::Session(
                "No subscriber to take custody of OPRF share; not acking".into(),
            ));
        }

        let ack = OprfEnrollAckPayload::new(payload.session_id, self.share.metadata.identifier);
        let event = KfpEventBuilder::oprf_enroll_ack(&self.keys, &from, ack)?;
        self.client
            .send_event(&event)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        debug!(
            session_id = %hex::encode(payload.session_id),
            "Sent OPRF enrollment ack"
        );

        Ok(())
    }

    /// Dealer side: record a holder ack, and on the full set emit
    /// [`KfpNodeEvent::OprfEnrollComplete`].
    pub(crate) async fn handle_oprf_enroll_ack(
        &self,
        from: PublicKey,
        payload: OprfEnrollAckPayload,
    ) -> Result<()> {
        self.verify_peer_share_index(from, payload.share_index)?;
        self.peers.write().update_last_seen(payload.share_index);

        let complete = {
            let mut sessions = self.enroll_sessions.write();
            let session = match sessions.get_session_mut(&payload.session_id) {
                Some(s) => s,
                None => {
                    debug!(
                        session_id = %hex::encode(payload.session_id),
                        "No OPRF enrollment session for ack"
                    );
                    return Ok(());
                }
            };
            session.record_ack(payload.share_index)?;
            session.has_all_acks()
        };

        if complete {
            info!(
                session_id = %hex::encode(payload.session_id),
                "OPRF enrollment complete!"
            );
            let _ = self.event_tx.send(KfpNodeEvent::OprfEnrollComplete {
                session_id: payload.session_id,
            });
        }

        Ok(())
    }
}
