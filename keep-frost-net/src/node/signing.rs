// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::time::Duration;

use frost_secp256k1_tr::rand_core::OsRng;
use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::audit::SigningOperation;
use crate::error::{FrostNetError, Result};
use crate::event::KfpEventBuilder;
use crate::protocol::*;
use crate::session::derive_session_id;

use super::{KfpNode, KfpNodeEvent, NonceId, SessionInfo};
use crate::nonce_pool::{serialize_commitment, NoncePool};

/// Restores peer commitments reserved from the [`NoncePool`] back into the pool
/// if a signing request aborts before the reservation is committed to a live
/// session. Disarm once the commitments are recorded so successful flows do not
/// re-insert consumed entries.
struct ReservationGuard<'a> {
    pool: &'a NoncePool,
    reserved: Option<Vec<(u16, NonceId, frost_secp256k1_tr::round1::SigningCommitments)>>,
}

impl<'a> ReservationGuard<'a> {
    fn new(
        pool: &'a NoncePool,
        reserved: Option<Vec<(u16, NonceId, frost_secp256k1_tr::round1::SigningCommitments)>>,
    ) -> Self {
        Self { pool, reserved }
    }

    fn disarm(&mut self) {
        self.reserved = None;
    }
}

impl Drop for ReservationGuard<'_> {
    fn drop(&mut self) {
        if let Some(entries) = self.reserved.take() {
            for (idx, nonce_id, commitment) in entries {
                self.pool.store_peer(idx, nonce_id, commitment);
            }
        }
    }
}

/// Content hash over a peer's nonce commitment batch, used to de-duplicate
/// repeated broadcasts without trusting the sender-controlled timestamp. The
/// set is sorted so reordering cannot bypass the dedup, and the length prefix
/// keeps distinct commitments from colliding under concatenation.
fn nonce_commitment_content_hash(
    share_index: u16,
    commitments: &[PreExchangedCommitment],
) -> [u8; 32] {
    let mut entries: Vec<&PreExchangedCommitment> = commitments.iter().collect();
    entries.sort_by(|a, b| {
        a.nonce_id
            .cmp(&b.nonce_id)
            .then(a.commitment.cmp(&b.commitment))
    });
    let mut hasher = Sha256::new();
    hasher.update(b"keep-nonce-commitment-dedup-v1");
    hasher.update(share_index.to_be_bytes());
    for entry in entries {
        hasher.update(entry.nonce_id);
        hasher.update((entry.commitment.len() as u32).to_be_bytes());
        hasher.update(&entry.commitment);
    }
    hasher.finalize().into()
}

impl KfpNode {
    /// Build a [`NonceCommitmentPayload`] from a set of pooled commitments,
    /// serializing each into wire bytes.
    fn build_nonce_commitment_payload(
        &self,
        commitments: impl IntoIterator<Item = (NonceId, frost_secp256k1_tr::round1::SigningCommitments)>,
    ) -> Result<NonceCommitmentPayload> {
        let commitments = commitments
            .into_iter()
            .map(|(nonce_id, commitment)| {
                Ok(PreExchangedCommitment {
                    nonce_id,
                    commitment: serialize_commitment(&commitment)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(NonceCommitmentPayload::new(
            self.group_pubkey,
            self.share.metadata.identifier,
            commitments,
        ))
    }

    /// Generate fresh round-1 nonces to top the local pool back up to its
    /// target and broadcast the matching commitments to online peers. Secret
    /// nonces are stored in memory only; only commitments leave this node.
    pub async fn replenish_nonce_pool(&self) -> Result<()> {
        let deficit = self.nonce_pool.own_deficit();
        if deficit == 0 {
            return Ok(());
        }

        let key_package = self.share.key_package()?;
        let mut fresh = Vec::with_capacity(deficit);
        for _ in 0..deficit {
            let nonce_id: NonceId = keep_core::crypto::random_bytes::<32>();
            let (nonces, commitment) =
                frost_secp256k1_tr::round1::commit(key_package.signing_share(), &mut OsRng);
            self.nonce_pool.store_own(nonce_id, nonces);
            fresh.push((nonce_id, commitment));
        }

        let payload = self.build_nonce_commitment_payload(fresh)?;

        let peer_pubkeys: Vec<PublicKey> = self
            .peers
            .read()
            .get_online_peers()
            .iter()
            .filter(|p| self.can_send_to(&p.pubkey))
            .map(|p| p.pubkey)
            .collect();

        for pubkey in peer_pubkeys {
            let event = KfpEventBuilder::nonce_commitment(&self.keys, &pubkey, payload.clone())?;
            if let Err(e) = self.client.send_event(&event).await {
                warn!(peer = %pubkey, error = %e, "Failed to broadcast nonce commitment to peer");
                continue;
            }
        }

        debug!(
            count = payload.commitments.len(),
            "Broadcast pre-exchanged nonce commitments"
        );

        Ok(())
    }

    /// Send all currently available own commitments directly to one peer. Used
    /// when a peer is newly discovered after the pool was already replenished,
    /// so it does not have to wait for the next replenish broadcast (which only
    /// carries freshly generated commitments) to enable instant signing.
    pub(crate) async fn send_nonce_pool_to(&self, pubkey: &PublicKey) -> Result<()> {
        let available = self.nonce_pool.own_commitments();
        if available.is_empty() {
            return Ok(());
        }

        let payload = self.build_nonce_commitment_payload(available)?;
        let event = KfpEventBuilder::nonce_commitment(&self.keys, pubkey, payload)?;
        self.client
            .send_event(&event)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        Ok(())
    }

    /// Build and send a session-scoped error event to a single peer.
    async fn send_session_error(
        &self,
        to: &PublicKey,
        code: &str,
        message: &str,
        session_id: [u8; 32],
    ) -> Result<()> {
        let event = KfpEventBuilder::error(&self.keys, to, code, message, Some(session_id))?;
        self.client
            .send_event(&event)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;
        Ok(())
    }

    pub(crate) async fn handle_nonce_commitment(
        &self,
        from: PublicKey,
        payload: NonceCommitmentPayload,
    ) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        // A NonceCommitment is an unsolicited fire-and-forget broadcast, so a
        // stale, off-policy, or spoofed one is dropped silently rather than
        // erroring. Gate order mirrors `handle_sign_request`: replay window and
        // receive policy before peer-identity verification.
        if !payload.is_within_replay_window(self.replay_window_secs) {
            debug!(
                share_index = payload.share_index,
                created_at = payload.created_at,
                "Dropping nonce commitment: outside replay window"
            );
            return Ok(());
        }

        if !self.can_receive_from(&from) {
            return Ok(());
        }

        if self
            .verify_peer_share_index(from, payload.share_index)
            .is_err()
        {
            return Ok(());
        }

        // De-duplicate repeated batches from a peer within the replay window so
        // a misbehaving peer cannot impose unbounded deserialization work by
        // re-sending the same commitments. Key on a content hash of the sorted
        // commitment set rather than the sender-controlled timestamp: distinct
        // same-second batches stay distinct, and perturbing `created_at` cannot
        // bypass the dedup to force repeated secp256k1 deserialization.
        let content_hash = nonce_commitment_content_hash(payload.share_index, &payload.commitments);
        if self
            .seen_nonce_commitments
            .write()
            .insert((payload.share_index, content_hash), payload.created_at)
            .is_some()
        {
            debug!(
                share_index = payload.share_index,
                "Dropping duplicate nonce commitment batch"
            );
            return Ok(());
        }

        let mut stored = 0usize;
        for entry in payload.commitments {
            if self
                .nonce_pool
                .contains_peer(payload.share_index, &entry.nonce_id)
            {
                if !self.nonce_pool.matches_peer(
                    payload.share_index,
                    &entry.nonce_id,
                    &entry.commitment,
                ) {
                    warn!(
                        share_index = payload.share_index,
                        nonce_id = %hex::encode(entry.nonce_id),
                        "Conflicting commitment for existing nonce_id; keeping first-write-wins value (possible equivocation)"
                    );
                }
                continue;
            }
            let commitment = match frost_secp256k1_tr::round1::SigningCommitments::deserialize(
                &entry.commitment,
            ) {
                Ok(c) => c,
                Err(e) => {
                    debug!(error = %e, "Skipping invalid pre-exchanged commitment");
                    continue;
                }
            };
            self.nonce_pool
                .store_peer(payload.share_index, entry.nonce_id, commitment);
            stored += 1;
        }

        self.peers.write().update_last_seen(payload.share_index);

        debug!(
            share_index = payload.share_index,
            stored, "Stored pre-exchanged commitments from peer"
        );

        Ok(())
    }

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
            let commit_bytes = serialize_commitment(&existing)?;

            let payload = CommitmentPayload::new(
                request.session_id,
                self.share.metadata.identifier,
                commit_bytes,
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
            .ok_or_else(|| {
                FrostNetError::UntrustedPeer(format!("Peer {from} not found in peer list"))
            })?;

        let session_info = SessionInfo {
            session_id: request.session_id,
            message: request.message.clone(),
            threshold: self.share.metadata.threshold,
            participants: request.participants.clone(),
            requester,
        };

        let hooks = self.hooks.read().clone();
        hooks.pre_sign(&session_info)?;

        // Locate the requester's reference to our own pre-exchanged nonce, if
        // any. The sentinel id ([0u8; 32]) marks the requester's echo-only
        // commitment, never our consumable nonce, so it is excluded here.
        // Pre-exchange applies only when we still hold the referenced single-use
        // secret nonce; check availability without consuming so the nonce_refs
        // can be fully validated before the nonce is burned.
        let own_nonce_id = request
            .nonce_refs
            .iter()
            .find(|nref| {
                nref.share_index == self.share.metadata.identifier && nref.nonce_id != [0u8; 32]
            })
            .map(|nref| nref.nonce_id);
        let used_pre_exchange = own_nonce_id
            .map(|id| self.nonce_pool.contains_own(&id))
            .unwrap_or(false);

        // The requester reserved one of our pooled commitments and already
        // embedded it in its own session, skipping the interactive commitment
        // round. If we no longer hold the referenced secret nonce (consumed,
        // evicted, or lost on restart), we cannot reproduce that commitment:
        // sending a fresh one would collide on the requester as a duplicate and
        // hang it until timeout. Signal the requester so it fails fast.
        if let Some(missing) = own_nonce_id {
            if !used_pre_exchange {
                warn!(
                    session_id = %hex::encode(request.session_id),
                    nonce_id = %hex::encode(missing),
                    "Referenced pre-exchanged nonce unavailable; signaling requester"
                );
                self.send_session_error(
                    &from,
                    "stale_nonce",
                    "Referenced pre-exchanged nonce no longer available",
                    request.session_id,
                )
                .await?;
                return Ok(());
            }
        }

        // When pre-exchange is used, the requester includes every participant's
        // commitment (including its own) in `nonce_refs`. Validate and
        // deserialize all of them BEFORE consuming our single-use own nonce, so
        // a malicious requester cannot drain our own-nonce pool by sending a
        // valid own_nonce_id alongside bogus peer commitments.
        //
        // Each non-self, non-sentinel commitment is cross-checked against our
        // own authenticated pool: the echoed bytes must match the commitment we
        // received directly from that peer via `handle_nonce_commitment`. The
        // requester's own commitment (sentinel nonce_id == [0u8; 32]) is
        // legitimately absent from the pool and accepted echo-only.
        let mut peer_refs: Vec<(u16, frost_secp256k1_tr::round1::SigningCommitments)> = Vec::new();
        if used_pre_exchange {
            for nref in &request.nonce_refs {
                if nref.share_index == self.share.metadata.identifier {
                    continue;
                }
                if !request.participants.contains(&nref.share_index) {
                    return Err(FrostNetError::Protocol(format!(
                        "Nonce ref for non-participant share_index {}",
                        nref.share_index
                    )));
                }
                // The sentinel (echo-only, unauthenticated against our pool) is
                // legitimate only for the requester's own commitment. Reject it
                // for any other share_index so a requester cannot substitute a
                // forged commitment for an honest peer by bypassing matches_peer.
                if nref.nonce_id == [0u8; 32] && nref.share_index != requester {
                    return Err(FrostNetError::Protocol(format!(
                        "Sentinel nonce ref allowed only for requester, got share_index {}",
                        nref.share_index
                    )));
                }
                let c =
                    frost_secp256k1_tr::round1::SigningCommitments::deserialize(&nref.commitment)
                        .map_err(|e| {
                        FrostNetError::Crypto(format!("Deserialize nonce ref commitment: {e}"))
                    })?;
                if nref.nonce_id != [0u8; 32]
                    && !self.nonce_pool.matches_peer(
                        nref.share_index,
                        &nref.nonce_id,
                        &nref.commitment,
                    )
                {
                    return Err(FrostNetError::Protocol(format!(
                        "Echoed commitment for share_index {} does not match our pooled commitment",
                        nref.share_index
                    )));
                }
                peer_refs.push((nref.share_index, c));
            }
        }

        // A pre-exchange request must carry the full commitment set. If the
        // validated refs plus our own commitment fall short of threshold we can
        // neither instant-sign nor safely fall back: the requester already
        // embedded our pooled commitment in its session and would reject a fresh
        // one as a duplicate. Signal it to fall back rather than letting it hang,
        // and avoid burning our pooled nonce on a session that cannot complete.
        if used_pre_exchange && peer_refs.len() + 1 < self.share.metadata.threshold as usize {
            warn!(
                session_id = %hex::encode(request.session_id),
                "Pre-exchange request below threshold; signaling requester"
            );
            self.send_session_error(
                &from,
                "incomplete_pre_exchange",
                "Pre-exchange request did not cover threshold participants",
                request.session_id,
            )
            .await?;
            return Ok(());
        }

        // `None` signals that the pre-exchange path required a pooled nonce that
        // vanished (consumed, evicted, or lost on restart) between validation
        // and consume, so the session cannot proceed and must be torn down.
        let commit_result = {
            let mut sessions = self.sessions.write();

            let session = sessions.get_or_create_session(
                request.session_id,
                request.message.clone(),
                self.share.metadata.threshold,
                request.participants.clone(),
            )?;

            // All nonce_refs have now been validated above, and a pre-exchange
            // request that reaches here covers the full threshold set. The
            // single-use own nonce is consumed only here, so neither session
            // creation nor a poisoned commitment set can burn it.
            let pooled_nonces = if used_pre_exchange {
                own_nonce_id.and_then(|nonce_id| self.nonce_pool.consume_own(&nonce_id))
            } else {
                None
            };

            // We cannot reproduce the commitment the requester already embedded,
            // so a fresh one would collide as a duplicate and hang it. Bail out
            // and signal stale_nonce after dropping the session lock.
            if used_pre_exchange && pooled_nonces.is_none() {
                // Drop the session we just created so a vanished-nonce request
                // cannot leave dead sessions filling the active slot cap. Not
                // marked completed so a legitimate retry is not flagged replay.
                sessions.abandon_session(&request.session_id);
                None
            } else {
                let used_pre_exchange = pooled_nonces.is_some();

                if used_pre_exchange {
                    debug!(
                        session_id = %hex::encode(request.session_id),
                        "Using pre-exchanged nonce for sign request"
                    );
                }

                let (nonces, commitment) = match pooled_nonces {
                    Some(nonces) => {
                        let commitment = *nonces.commitments();
                        (nonces, commitment)
                    }
                    None => {
                        frost_secp256k1_tr::round1::commit(key_package.signing_share(), &mut OsRng)
                    }
                };

                session.set_our_nonces(nonces);
                session.set_our_commitment(commitment);
                session.add_commitment(self.share.metadata.identifier, commitment)?;

                if used_pre_exchange {
                    for (share_index, c) in &peer_refs {
                        session.add_commitment(*share_index, *c)?;
                    }
                }

                let proceed = used_pre_exchange && session.has_all_commitments();

                sessions.record_nonce_consumption(&request.session_id)?;

                Some((commitment, proceed))
            }
        };

        let (commitment, proceed_to_round2) = match commit_result {
            Some(ready) => ready,
            None => {
                warn!(
                    session_id = %hex::encode(request.session_id),
                    "Referenced pre-exchanged nonce vanished before consume; signaling requester"
                );
                self.send_session_error(
                    &from,
                    "stale_nonce",
                    "Referenced pre-exchanged nonce no longer available",
                    request.session_id,
                )
                .await?;
                return Ok(());
            }
        };

        let commit_bytes = serialize_commitment(&commitment)?;

        let payload = CommitmentPayload::new(
            request.session_id,
            self.share.metadata.identifier,
            commit_bytes,
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

        // With pre-exchange, the full commitment set arrived in this request, so
        // we can move straight to round 2 without waiting for commitment events.
        if proceed_to_round2 {
            info!(
                session_id = %hex::encode(request.session_id),
                "Instant-signing: full commitment set pre-exchanged, proceeding to round 2"
            );
            // The own nonce was already consumed (single-use) and used to
            // compute the signature share, which may have been partially sent.
            // Do NOT restore it on send failure: reusing a nonce that produced
            // a share is a key-leak risk. Tear down the session instead.
            if let Err(e) = self.generate_and_send_share(&request.session_id).await {
                self.sessions.write().complete_session(&request.session_id);
                return Err(e);
            }
        }

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
            if let Err(e) = self.generate_and_send_share(&payload.session_id).await {
                self.sessions.write().complete_session(&payload.session_id);
                return Err(e);
            }
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

        let self_aggregated = {
            let mut sessions = self.sessions.write();
            if let Some(session) = sessions.get_session_mut(session_id) {
                session.add_signature_share(self.share.metadata.identifier, sig_share)?;
                if session.has_all_shares() {
                    let pubkey_pkg = self.share.pubkey_package()?;
                    let sig = session.try_aggregate(&pubkey_pkg)?;
                    sig.map(|s| {
                        (
                            s,
                            session.message().to_vec(),
                            session.participants().to_vec(),
                        )
                    })
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some((sig, session_message, session_participants)) = self_aggregated {
            info!(
                session_id = %hex::encode(session_id),
                "Signature complete (single-participant)!"
            );

            self.audit_log.log_signing_operation(
                *session_id,
                &session_message,
                Some(&sig),
                session_participants,
                self.share.metadata.identifier,
                SigningOperation::SignatureCompleted,
            );

            self.invoke_post_sign_hook(session_id, &sig);

            let _ = self.event_tx.send(KfpNodeEvent::SignatureComplete {
                session_id: *session_id,
                signature: sig,
            });

            return Ok(());
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
            let session = match sessions.get_session(&payload.session_id) {
                Some(s) => s,
                None => {
                    debug!(
                        session_id = %hex::encode(payload.session_id),
                        "Ignoring signature complete for unknown session"
                    );
                    return Ok(());
                }
            };
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

        let key_package = self.share.key_package()?;
        let (nonces, our_commitment) =
            frost_secp256k1_tr::round1::commit(key_package.signing_share(), &mut OsRng);

        // Try to use pre-exchanged commitments for the selected peers. If every
        // peer has a pooled commitment, reserve them (single-use; removed from
        // the pool) so the interactive commitment round can be skipped.
        let peer_indices: Vec<u16> = participant_peers.iter().map(|(idx, _)| *idx).collect();
        let reserved = self.nonce_pool.reserve_for(&peer_indices);
        // If any step below fails after reservation, the reserved commitments
        // must go back into the pool so they are not leaked permanently.
        let mut reservation_guard = ReservationGuard::new(&self.nonce_pool, reserved.clone());

        let our_commit_bytes = serialize_commitment(&our_commitment)?;

        let mut nonce_refs: Vec<NonceRef> = Vec::new();
        let mut reserved_commitments: Vec<(u16, frost_secp256k1_tr::round1::SigningCommitments)> =
            Vec::new();
        if let Some(entries) = &reserved {
            for (idx, nonce_id, commitment) in entries {
                let commit_bytes = serialize_commitment(commitment)?;
                nonce_refs.push(NonceRef {
                    share_index: *idx,
                    nonce_id: *nonce_id,
                    commitment: commit_bytes,
                });
                reserved_commitments.push((*idx, *commitment));
            }
            // Include the requester's own commitment so each participant has the
            // complete commitment set from the single sign request, removing any
            // dependence on commitment-event ordering. The zero `nonce_id` is a
            // sentinel: participants never consume the requester's nonce, they
            // only read the commitment.
            nonce_refs.push(NonceRef {
                share_index: self.share.metadata.identifier,
                nonce_id: [0u8; 32],
                commitment: our_commit_bytes.clone(),
            });
        }

        let request = SignRequestPayload::new(
            session_id,
            self.group_pubkey,
            message.clone(),
            message_type,
            participants.clone(),
        )
        .with_nonce_refs(nonce_refs);

        let session_info = SessionInfo {
            session_id,
            message: message.clone(),
            threshold: self.share.metadata.threshold,
            participants: participants.clone(),
            requester: self.share.metadata.identifier,
        };
        let hooks = self.hooks.read().clone();
        hooks.pre_sign(&session_info)?;

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

            for (idx, commitment) in &reserved_commitments {
                session.add_commitment(*idx, *commitment)?;
            }

            sessions.record_nonce_consumption(&session_id)?;
        }

        // Reserved commitments are now committed into the live session; they are
        // no longer the pool's responsibility, so the guard must not restore
        // them if a later send fails.
        reservation_guard.disarm();

        // When pre-exchange is used the sign request already carries the full
        // commitment set, so the separate interactive commitment is redundant.
        let using_pre_exchange = reserved.is_some();
        let our_commit_payload = CommitmentPayload::new(
            session_id,
            self.share.metadata.identifier,
            our_commit_bytes.clone(),
        );

        // Reservations are already consumed and committed to the live session,
        // so on a send failure tear the session down (matching the timeout and
        // share-generation paths below) rather than leaving it active until it
        // expires.
        let send_result: Result<()> = async {
            for (share_index, pubkey) in participant_peers {
                let event = KfpEventBuilder::sign_request(&self.keys, &pubkey, request.clone())?;
                self.client
                    .send_event(&event)
                    .await
                    .map_err(|e| FrostNetError::Transport(e.to_string()))?;

                if !using_pre_exchange {
                    let commit_event = KfpEventBuilder::commitment(
                        &self.keys,
                        &pubkey,
                        our_commit_payload.clone(),
                    )?;
                    self.client
                        .send_event(&commit_event)
                        .await
                        .map_err(|e| FrostNetError::Transport(e.to_string()))?;
                }

                debug!(share_index, using_pre_exchange, "Sent sign request");
            }
            Ok(())
        }
        .await;
        if let Err(e) = send_result {
            self.sessions.write().complete_session(&session_id);
            return Err(e);
        }

        let mut rx = self.event_tx.subscribe();

        // All commitments may already be present: for single-participant
        // (threshold=1), or when peer commitments were pre-exchanged and
        // reserved above. Must subscribe before generating share so we don't
        // miss SignatureComplete.
        let all_committed = {
            let sessions = self.sessions.read();
            sessions
                .get_session(&session_id)
                .map(|s| s.has_all_commitments())
                .unwrap_or(false)
        };
        if all_committed {
            if let Err(e) = self.generate_and_send_share(&session_id).await {
                self.sessions.write().complete_session(&session_id);
                return Err(e);
            }
        }

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
            Err(_) => {
                self.sessions.write().complete_session(&session_id);
                Err(FrostNetError::Timeout("Signing request timed out".into()))
            }
        }
    }
}
