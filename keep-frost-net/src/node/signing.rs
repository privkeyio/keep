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
use crate::session::{derive_session_id, derive_session_id_salted};
use keep_core::frost::taproot::{self, TaprootTweak};

use super::{KfpNode, KfpNodeEvent, NonceId, SessionInfo};
use crate::nonce_pool::{serialize_commitment, NoncePool};

/// Per-round wait for the aggregated signature. Below the 20s peer announce
/// interval so a round resolves within one announce cycle, and comfortably
/// above honest co-signer response time including TEE attestation latency.
pub(crate) const SIGNING_ROUND_TIMEOUT: Duration = Duration::from_secs(15);

/// Upper bound on failover retries for a single signing request. Caps the
/// worst-case wall-clock cost of repeated round timeouts (each up to
/// `SIGNING_ROUND_TIMEOUT`) under a partition or latency event.
pub(crate) const MAX_FAILOVER_ATTEMPTS: usize = 3;

/// Wait for the pre-round liveness ping. A co-signer that dropped since its last
/// announce is excluded after at most this long, instead of burning a full
/// `SIGNING_ROUND_TIMEOUT` round. The ping returns as soon as every co-signer
/// pongs, so the all-online path is bounded by one round-trip, not this value.
const LIVENESS_PING_TIMEOUT: Duration = Duration::from_secs(3);

/// Error from a single signing round. `attempted` lists the non-self peers that
/// failed to respond in this round, so a timed-out round can exclude them and
/// fail over to other live co-signers.
struct SigningRoundError {
    error: FrostNetError,
    attempted: Vec<u16>,
}

impl SigningRoundError {
    fn fatal(error: FrostNetError) -> Self {
        Self {
            error,
            attempted: Vec::new(),
        }
    }
}

impl From<FrostNetError> for SigningRoundError {
    fn from(error: FrostNetError) -> Self {
        Self::fatal(error)
    }
}

/// A peer-reported failure for the in-flight signing session, carried out of the
/// round receive loop with the structured error code and offending share index
/// so the failover logic can decide whether the failure is recoverable in place
/// or whether the peer should be excluded and the round retried.
struct PeerRoundFailure {
    error: String,
    code: String,
    offending_index: Option<u16>,
}

/// Peer-reported error codes that the requester handles in place (clearing the
/// offending peer's pooled commitments and falling back to an interactive round
/// on the next request) rather than excluding the peer and failing over. Any
/// other code is treated like an unresponsive peer so a faulty or malicious
/// co-signer cannot reliably block signing.
fn is_recoverable_peer_error(code: &str) -> bool {
    code == "stale_nonce" || code == "incomplete_pre_exchange"
}

/// Extract the offending peer's share index from a peer-reported session error,
/// which the message handler annotates with a trailing "(peer N)". Returns
/// `None` when the index is absent or unparseable so the caller can fall back
/// to clearing the whole pool.
fn parse_offending_peer(msg: &str) -> Option<u16> {
    let start = msg.rfind("(peer ")? + "(peer ".len();
    let rest = &msg[start..];
    let end = rest.find(')')?;
    rest[..end].trim().parse().ok()
}

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

    /// Build the complete group [`PublicKeyPackage`] for `participants`.
    ///
    /// A share imported from a transport export carries only its own verifying
    /// share (the export does not include the other members' shares), so
    /// `self.share.pubkey_package()` alone is missing the co-signers' verifying
    /// shares that `frost::aggregate` needs to validate their signature shares,
    /// without them aggregation fails with "Unknown identifier". Fill the gaps
    /// from the verifying share each peer announced (authenticated via
    /// proof-of-share on discovery), reconstructing the dealer's full package.
    fn aggregation_pubkey_package(
        &self,
        participants: &[u16],
    ) -> Result<frost_secp256k1_tr::keys::PublicKeyPackage> {
        let base = self.share.pubkey_package()?;
        let mut verifying_shares = base.verifying_shares().clone();
        let peers = self.peers.read();
        for &idx in participants {
            let id = frost_secp256k1_tr::Identifier::try_from(idx)
                .map_err(|e| FrostNetError::Crypto(format!("Invalid identifier {idx}: {e}")))?;
            if verifying_shares.contains_key(&id) {
                continue;
            }
            let vs_bytes = peers
                .get_peer(idx)
                .and_then(|p| p.verifying_share)
                .ok_or_else(|| {
                    FrostNetError::Session(format!(
                        "No announced verifying share for participant {idx}"
                    ))
                })?;
            let vs =
                frost_secp256k1_tr::keys::VerifyingShare::deserialize(&vs_bytes).map_err(|e| {
                    FrostNetError::Crypto(format!("Invalid verifying share {idx}: {e}"))
                })?;
            verifying_shares.insert(id, vs);
        }
        Ok(frost_secp256k1_tr::keys::PublicKeyPackage::new(
            verifying_shares,
            *base.verifying_key(),
            Some(self.share.metadata.threshold),
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

        // A latched node stops refilling. Otherwise it keeps drawing from the
        // degraded source and broadcasting the results every interval, which
        // under a stuck source means publishing the same commitment repeatedly
        // and advertising the failure to the whole group.
        if self.is_entropy_degraded() {
            return Err(FrostNetError::PolicyViolation(
                "OS RNG health check failed; not replenishing nonces".into(),
            ));
        }

        let key_package = self.share.key_package()?;
        let mut fresh = Vec::with_capacity(deficit);
        for _ in 0..deficit {
            // Drawn through the entropy module rather than the crypto wrapper
            // so the health failure keeps its own type. The wrapper flattens it
            // into a stringly-typed encryption error, and deciding to stop
            // signing on a string match is exactly the guess this refuses to make.
            let nonce_id: NonceId = keep_core::entropy::try_random_bytes::<32>().map_err(|e| {
                if Self::latches_signing(e) {
                    self.mark_entropy_degraded();
                }
                FrostNetError::Session(format!("nonce id: {e}"))
            })?;
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
            .filter(|p| self.can_send_to_index(p.share_index))
            .map(|p| p.pubkey)
            .collect();

        for pubkey in peer_pubkeys {
            let event = KfpEventBuilder::nonce_commitment(&self.keys, &pubkey, payload.clone())?;
            if let Err(e) = self.transport.send_event(&event).await {
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
    /// Publishes this node's pooled commitments to a peer.
    ///
    /// Refuses once latched: the pool can still hold commitments drawn in the
    /// window before detection, and handing those to a newly discovered peer
    /// advertises exactly what the replenish gate stops broadcasting.
    pub(crate) async fn send_nonce_pool_to(&self, pubkey: &PublicKey) -> Result<()> {
        if self.is_entropy_degraded() {
            return Ok(());
        }

        let available = self.nonce_pool.own_commitments();
        if available.is_empty() {
            return Ok(());
        }

        let payload = self.build_nonce_commitment_payload(available)?;
        let event = KfpEventBuilder::nonce_commitment(&self.keys, pubkey, payload)?;
        self.transport.send_event(&event).await?;

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
        self.transport.send_event(&event).await?;
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

    /// Record a refusal of `request` that the requester is being told about.
    ///
    /// Both notified refusal paths go through here so they cannot drift into
    /// recording different things. A warning is not evidence: a holder asking
    /// later whether anyone sent requests this node declined has nothing to
    /// consult otherwise.
    ///
    /// Called before the notification is sent, deliberately. The fact recorded
    /// is that we refused, which holds whether or not the peer could be told,
    /// and a refusal that could not be delivered is the one most worth keeping.
    /// That differs from the accept path, which logs after its send because
    /// there the recorded fact is the send itself.
    fn record_refusal(&self, request: &SignRequestPayload, requester: Option<u16>) {
        self.audit_log.log_signing_operation(
            request.session_id,
            &request.message,
            None,
            request.participants.clone(),
            self.share.metadata.identifier,
            SigningOperation::SignRequestRefused,
            requester,
        );
    }

    /// The scriptPubKey a key-path spend at `path` with `tweak` signs for,
    /// from the group's verifying key in this share's public key package rather
    /// than group metadata.
    fn taproot_script_pubkey(
        &self,
        path: &[u32],
        tweak: TaprootTweakPayload,
    ) -> Result<bitcoin::ScriptBuf> {
        let group = taproot::x_only(self.share.pubkey_package()?.verifying_key())?;
        let internal = taproot::internal_key(&group, path)?;
        Ok(TaprootTweak::from(tweak).script_pubkey(&internal)?)
    }

    /// The checks every party runs on a key-path spend before committing: a
    /// bitcoin-sighash request with its PSBT payload, whose signed input spends
    /// this group's output for `path` and `tweak` under SIGHASH_DEFAULT or ALL.
    /// The payload must already be proven to hash to the message. Returns the
    /// spent scriptPubKey.
    fn check_key_path_spend(
        &self,
        message_type: &str,
        structured_payload: Option<&[u8]>,
        path: &[u32],
        tweak: TaprootTweakPayload,
    ) -> Result<bitcoin::ScriptBuf> {
        let payload = structured_payload
            .filter(|_| message_type == crate::MSG_TYPE_BITCOIN_SIGHASH)
            .ok_or_else(|| {
                FrostNetError::PolicyViolation(
                    "a taproot tweak needs a bitcoin-sighash request with its PSBT payload".into(),
                )
            })?;
        let spk = self.taproot_script_pubkey(path, tweak)?;
        crate::verify_taproot_key_spend(payload, &spk)?;
        Ok(spk)
    }

    pub(crate) async fn handle_sign_request(
        &self,
        from: PublicKey,
        request: SignRequestPayload,
    ) -> Result<()> {
        if request.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        // Fail closed on a degraded RNG. Round 1 draws this node's nonce from
        // OsRng, which is not health-checked at the point of use, so once the
        // source is known bad the only safe move is to stop signing: two shares
        // over one nonce recover the key.
        if self.is_entropy_degraded() {
            debug!("Rejecting sign request: OS RNG degraded");
            return Err(FrostNetError::PolicyViolation(
                "OS RNG health check failed; co-signing refused".into(),
            ));
        }

        // Fail closed under duress: a verified duress beacon freezes co-signing
        // too, so a coerced holder cannot be forced to co-sign a spend.
        if self.is_duress_frozen() {
            debug!("Rejecting sign request: holder is duress-frozen");
            return Err(FrostNetError::PolicyViolation(
                "holder is duress-frozen; co-signing refused".into(),
            ));
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

        // The session id is validated against the transmitted salt, so the salt
        // must encode the key this request signs with: otherwise one session id
        // could be reused for a different path or taproot tweak.
        if !crate::session::salt_binds(
            &request.session_salt,
            &request.derivation_path,
            request.taproot_tweak.as_ref(),
        ) {
            warn!(
                session_id = %hex::encode(request.session_id),
                "Rejecting sign request: session salt does not bind its path and taproot tweak"
            );
            return Err(FrostNetError::PolicyViolation(
                "Session salt does not bind the request's derivation path and taproot tweak".into(),
            ));
        }

        info!(
            session_id = %hex::encode(request.session_id),
            message_type = %request.message_type,
            "Received sign request"
        );

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
            self.transport.send_event(&event).await?;

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
            message_type: request.message_type.clone(),
            structured_payload: request.structured_payload.clone(),
            derivation_path: request.derivation_path.clone(),
            taproot_tweak: request.taproot_tweak,
        };

        // Recompute the digest from the structured payload BEFORE the pre-sign
        // hook fires (#529). This closes the cross-domain label spoof where a
        // requester relabels a Bitcoin sighash as `"nostr-event"` (or the
        // mirror): the Nostr-canonical hash of the supplied event body would
        // not equal the sighash bytes, so the responder refuses without
        // signing. When no structured payload is attached this is a no-op;
        // enforcement of presence is a policy choice owned by
        // `RequireStructuredPayloadHooks`.
        if let Some(sp) = request.structured_payload.as_ref() {
            if let Err(e) =
                crate::verify_structured_payload(&request.message_type, &request.message, sp)
            {
                warn!(
                    session_id = %hex::encode(request.session_id),
                    error = %e,
                    "Sign request refused: structured payload does not match digest"
                );
                // Audited with more cause than the policy refusal below: this
                // fires when a requester's structured body does not produce the
                // digest it asked us to sign, which is an attempted
                // cross-domain relabel rather than a configuration saying no.
                self.record_refusal(&request, Some(requester));
                self.send_session_error(
                    &from,
                    "policy_violation",
                    &e.to_string(),
                    request.session_id,
                )
                .await?;
                return Ok(());
            }
        }

        // A key-path spend: the input must spend this group's output for the
        // path and tweak, under SIGHASH_DEFAULT or ALL, before anything is
        // committed. The structured payload is present (protocol validation)
        // and already proven to hash to `message` above.
        let hooks = self.hooks.read().clone();
        if let Some(tweak) = request.taproot_tweak {
            let check = self
                .check_key_path_spend(
                    &request.message_type,
                    request.structured_payload.as_deref(),
                    &request.derivation_path,
                    tweak,
                )
                .and_then(|_| {
                    if hooks.approve_key_path_spend(&session_info) {
                        Ok(())
                    } else {
                        Err(FrostNetError::PolicyViolation(
                            "this co-signer does not approve key-path spends".into(),
                        ))
                    }
                });
            if let Err(e) = check {
                warn!(
                    session_id = %hex::encode(request.session_id),
                    error = %e,
                    "Sign request refused: key-path spend check failed"
                );
                self.record_refusal(&request, Some(requester));
                self.send_session_error(
                    &from,
                    "policy_violation",
                    &e.to_string(),
                    request.session_id,
                )
                .await?;
                return Ok(());
            }
        }

        if let Err(e) = hooks.pre_sign(&session_info) {
            // Notify the requester so it fails fast instead of hanging until
            // timeout/failover exhaustion, mirroring the stale-nonce path below.
            warn!(
                session_id = %hex::encode(request.session_id),
                error = %e,
                "Sign request refused by pre-sign policy; signaling requester"
            );
            // Covers the kill switch and the desktop approval prompt too: both
            // refuse by returning an error from this same hook.
            self.record_refusal(&request, Some(requester));
            self.send_session_error(
                &from,
                "policy_violation",
                &e.to_string(),
                request.session_id,
            )
            .await?;
            return Ok(());
        }

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

        // #487 PR3: apply the composite BIP-32 tweak for the requester's
        // derivation path before we commit. Every subsequent step in this
        // session (round2 sign, aggregation) must use the SAME tweaked package
        // for the aggregate signature to verify, so we persist the path on the
        // session at the same time as the commitment below. Computed here, after
        // the resend early-return, so a duplicate request that just re-echoes our
        // cached commitment never recomputes the derivation.
        let key_package = keep_core::frost::bip32_signing::tweak_key_package_at_path(
            &self.share.key_package()?,
            &self.group_pubkey,
            &request.derivation_path,
        )
        .map_err(|e| {
            FrostNetError::Crypto(format!("BIP-32 tweak on responder key package failed: {e}"))
        })?;

        // `None` signals that the pre-exchange path required a pooled nonce that
        // vanished (consumed, evicted, or lost on restart) between validation
        // and consume, so the session cannot proceed and must be torn down.
        let commit_result = {
            let mut sessions = self.sessions.write();

            let session = sessions.get_or_create_session_salted(
                request.session_id,
                request.message.clone(),
                self.share.metadata.threshold,
                request.participants.clone(),
                &request.session_salt,
            )?;
            session.set_message_type(request.message_type.clone());
            session.set_derivation_path(request.derivation_path.clone());
            session.set_taproot_tweak(request.taproot_tweak);

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
                let early = self
                    .early_commitments
                    .write()
                    .remove(&request.session_id)
                    .map(|(_, held)| held)
                    .unwrap_or_default();
                for (share_index, c) in early {
                    if let Err(e) = session.add_commitment(share_index, c) {
                        debug!(share_index, error = %e, "Skipping held commitment");
                    }
                }

                let proceed = session.has_all_commitments();

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

        // Every participant needs every commitment before it can produce its
        // share, so co-signers also send theirs to each other, not only to the
        // requester (which would otherwise leave rounds of three or more stuck
        // without pre-exchanged nonces).
        let mut recipients = vec![from];
        {
            let peers = self.peers.read();
            for &idx in &request.participants {
                if idx == self.share.metadata.identifier || idx == requester {
                    continue;
                }
                if let Some(peer) = peers.get_peer(idx) {
                    if self.can_send_to_index(idx) {
                        recipients.push(peer.pubkey);
                    }
                }
            }
        }
        for (n, recipient) in recipients.iter().enumerate() {
            let event = KfpEventBuilder::commitment(&self.keys, recipient, payload.clone())?;
            match self.transport.send_event(&event).await {
                Ok(_) => {}
                // The requester must have it; another co-signer can still get it
                // through its own sign request path, so keep the round going.
                Err(e) if n > 0 => {
                    warn!(error = %e, "Failed to send commitment to a co-signer");
                }
                Err(e) => return Err(e),
            }
        }

        debug!(
            session_id = %hex::encode(request.session_id),
            recipients = recipients.len(),
            "Sent commitment"
        );

        self.audit_log.log_signing_operation(
            request.session_id,
            &request.message,
            None,
            request.participants,
            self.share.metadata.identifier,
            SigningOperation::CommitmentSent,
            Some(requester),
        );

        // The full commitment set is already here (pre-exchanged in the request,
        // or held from participants whose commitments arrived first), so move
        // straight to round 2 without waiting for commitment events.
        if proceed_to_round2 {
            info!(
                session_id = %hex::encode(request.session_id),
                "Full commitment set present, proceeding to round 2"
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

    /// Keep a commitment from an admitted participant whose session this node
    /// has not created yet, for [`Self::handle_sign_request`] to apply. Bounded
    /// in sessions, entries per session and age.
    fn hold_early_commitment(
        &self,
        session_id: [u8; 32],
        share_index: u16,
        commitment: frost_secp256k1_tr::round1::SigningCommitments,
    ) {
        const MAX_SESSIONS: usize = 64;
        const MAX_SESSIONS_PER_SENDER: usize = 4;
        const MAX_AGE: Duration = Duration::from_secs(120);
        let max_entries = usize::from(self.share.metadata.total_shares);
        let mut held = self.early_commitments.write();
        held.retain(|_, (since, _)| since.elapsed() < MAX_AGE);
        let from_sender = held
            .iter()
            .filter(|(id, (_, entries))| {
                **id != session_id && entries.iter().any(|(i, _)| *i == share_index)
            })
            .count();
        if from_sender >= MAX_SESSIONS_PER_SENDER
            || (!held.contains_key(&session_id) && held.len() >= MAX_SESSIONS)
        {
            debug!(
                session_id = %hex::encode(session_id),
                "Dropping commitment for an unknown session: too many pending"
            );
            return;
        }
        let (_, entries) = held
            .entry(session_id)
            .or_insert_with(|| (std::time::Instant::now(), Vec::new()));
        if entries.len() < max_entries && entries.iter().all(|(i, _)| *i != share_index) {
            entries.push((share_index, commitment));
            debug!(
                session_id = %hex::encode(session_id),
                share_index,
                "Holding commitment until its sign request arrives"
            );
        }
    }

    pub(crate) async fn handle_commitment(
        &self,
        from: PublicKey,
        payload: CommitmentPayload,
    ) -> Result<()> {
        // Gated as well as torn down. `mark_entropy_degraded` abandons active
        // sessions, so this is normally unreachable, but it makes the property
        // local: no commitment advances a round to round 2 while the latch
        // holds, whatever raced with the teardown.
        if self.is_entropy_degraded() {
            debug!("Dropping commitment: OS RNG degraded");
            return Ok(());
        }

        self.verify_peer_share_index(from, payload.share_index)?;

        let commitment =
            frost_secp256k1_tr::round1::SigningCommitments::deserialize(&payload.commitment)
                .map_err(|e| FrostNetError::Crypto(format!("Invalid commitment: {e}")))?;

        let proceed_to_round2 = {
            let mut sessions = self.sessions.write();
            let session = match sessions.get_session_mut(&payload.session_id) {
                Some(s) => s,
                None => {
                    self.hold_early_commitment(payload.session_id, payload.share_index, commitment);
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

        // A commitment can arrive after every signature share (relay reordering).
        // In that case the share handler skipped aggregation because
        // `ready_to_aggregate()` was still false; now that the last commitment is
        // here, re-attempt aggregation so the session does not stall to timeout.
        self.try_complete_signature(&payload.session_id)?;

        Ok(())
    }

    /// Attempt aggregation and emit `SignatureComplete` if every participant has
    /// supplied both a commitment and a signature share. Safe to call from any
    /// handler; it is a no-op while `ready_to_aggregate()` is false.
    fn try_complete_signature(&self, session_id: &[u8; 32]) -> Result<()> {
        let completed = {
            let mut sessions = self.sessions.write();
            let session = match sessions.get_session_mut(session_id) {
                Some(s) => s,
                None => return Ok(()),
            };

            // Idempotent: once aggregation has produced the signature the session
            // is Complete. `ready_to_aggregate()` stays true (commitments/shares
            // are never cleared), so without this guard a second call would
            // re-aggregate and re-emit SignatureComplete / re-run the post-sign
            // hook (e.g. broadcast the tx twice).
            if session.is_complete() || !session.ready_to_aggregate() {
                return Ok(());
            }

            // #487 PR3: aggregate under the composite-tweaked pubkey
            // package when the session is signing at a derivation path, so
            // signature-share validation and the aggregate signature line
            // up under the derived child key.
            let base_pubkey_pkg = self.aggregation_pubkey_package(session.participants())?;
            // A key-path spend aggregates under the output key, so the
            // self-check in `try_aggregate` verifies against the key the spent
            // scriptPubKey commits to.
            let pubkey_pkg = taproot::spend_public_key_package(
                &base_pubkey_pkg,
                &self.group_pubkey,
                session.derivation_path(),
                session.taproot_tweak().map(TaprootTweak::from),
            )
            .map_err(|e| {
                FrostNetError::Crypto(format!("tweak on aggregation pubkey package failed: {e}"))
            })?;
            session.try_aggregate(&pubkey_pkg)?.map(|sig| {
                (
                    sig,
                    session.message().to_vec(),
                    session.participants().to_vec(),
                )
            })
        };

        if let Some((sig, session_message, session_participants)) = completed {
            info!(
                session_id = %hex::encode(session_id),
                "Signature complete!"
            );

            self.audit_log.log_signing_operation(
                *session_id,
                &session_message,
                Some(&sig),
                session_participants,
                self.share.metadata.identifier,
                SigningOperation::SignatureCompleted,
                None,
            );

            self.invoke_post_sign_hook(session_id, &sig);

            let _ = self.event_tx.send(KfpNodeEvent::SignatureComplete {
                session_id: *session_id,
                signature: sig,
            });
        }

        Ok(())
    }

    pub(crate) async fn generate_and_send_share(&self, session_id: &[u8; 32]) -> Result<()> {
        // The last check before a share exists, and the one that has to be here
        // rather than only at the entry points.
        //
        // Every caller gates on entry, but time passes between that gate and
        // this call: the requester path draws its nonce and then runs the
        // pre-sign hook, which on desktop blocks on a human for up to a minute
        // against a thirty-second probe. The latch can trip inside that window,
        // the teardown can run, and this would still emit a share over a nonce
        // drawn before detection. An entry gate cannot cover a wait it precedes.
        if self.is_entropy_degraded() {
            debug!("Refusing to produce a signature share: OS RNG degraded");
            return Ok(());
        }

        let (signing_package, nonces, derivation_path, taproot_tweak) = {
            let mut sessions = self.sessions.write();
            let session = match sessions.get_session_mut(session_id) {
                Some(s) => s,
                None => return Err(FrostNetError::SessionNotFound(hex::encode(session_id))),
            };

            let signing_package = session.get_signing_package()?;
            // Single-use nonces: if they are already gone, another invocation for
            // this session has produced and sent our share (e.g. a peer's
            // commitment arriving after the pre-exchanged set already drove us
            // into round 2). Treat the repeat as a no-op rather than failing the
            // whole request on the consumed nonce; aggregation is still driven
            // by the inbound signature-share handler.
            let nonces = match session.take_our_nonces() {
                Some(n) => n,
                None => return Ok(()),
            };

            let derivation_path = session.derivation_path().to_vec();
            let taproot_tweak = session.taproot_tweak();
            (signing_package, nonces, derivation_path, taproot_tweak)
        };

        // #487 PR3: sign under the composite-tweaked key package when the
        // session carries a derivation path, so the sig share aggregates to
        // a signature under the derived child pubkey rather than the group.
        let key_package = taproot::spend_key_package(
            &self.share.key_package()?,
            &self.group_pubkey,
            &derivation_path,
            taproot_tweak.map(TaprootTweak::from),
        )
        .map_err(|e| {
            FrostNetError::Crypto(format!("tweak on responder key package failed: {e}"))
        })?;

        let sig_share = frost_secp256k1_tr::round2::sign(&signing_package, &nonces, &key_package)
            .map_err(|e| FrostNetError::Crypto(format!("Signing failed: {e}")))?;

        {
            let mut sessions = self.sessions.write();
            if let Some(session) = sessions.get_session_mut(session_id) {
                session.add_signature_share(self.share.metadata.identifier, sig_share)?;
            }
        }

        // Our own share may complete the set (e.g. single-participant, or we were
        // the last to commit+sign). Gate on `ready_to_aggregate()` so we never
        // aggregate over a mismatched commitment/share id set under reordering.
        self.try_complete_signature(session_id)?;
        {
            let sessions = self.sessions.read();
            if let Some(session) = sessions.get_session(session_id) {
                if session.is_complete() {
                    return Ok(());
                }
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

        // Our nonces are spent, so a failure for one participant must not keep
        // the share from the others.
        let mut last_err = None;
        let mut sent = 0usize;
        for pubkey in &peer_pubkeys {
            let event = KfpEventBuilder::signature_share(&self.keys, pubkey, payload.clone())?;
            match self.transport.send_event(&event).await {
                Ok(()) => sent += 1,
                Err(e) => {
                    warn!(peer = %pubkey, error = %e, "Failed to send signature share");
                    last_err = Some(e);
                }
            }
        }
        if sent == 0 {
            if let Some(e) = last_err {
                return Err(e);
            }
        }

        debug!(session_id = %hex::encode(session_id), "Sent signature share");

        self.audit_log.log_signing_operation(
            *session_id,
            &session_message,
            None,
            session_participants,
            self.share.metadata.identifier,
            SigningOperation::SignatureShareSent,
            None,
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

        {
            let mut sessions = self.sessions.write();
            let session = match sessions.get_session_mut(&payload.session_id) {
                Some(s) => s,
                None => return Ok(()),
            };
            session.add_signature_share(payload.share_index, sig_share)?;
        }

        // Aggregate only once every participant has both a commitment and a
        // share; `try_complete_signature` gates on `ready_to_aggregate()` so a
        // share arriving before its commitment is buffered rather than dropped.
        self.try_complete_signature(&payload.session_id)?;

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
            None,
        );

        self.invoke_post_sign_hook(&payload.session_id, &payload.signature);

        let _ = self.event_tx.send(KfpNodeEvent::SignatureComplete {
            session_id: payload.session_id,
            signature: payload.signature,
        });

        Ok(())
    }

    /// Pings every eligible co-signer before the first round and returns the
    /// ones that fail to pong, so a peer that dropped since its last announce is
    /// excluded up front instead of being selected and burning a full round
    /// timeout before failover kicks in (the slow case in issue #412). The ping
    /// resolves as soon as all co-signers answer, so the all-online happy path
    /// only pays one round-trip. It is skipped entirely when the group has no
    /// spare co-signers (single-peer / exactly-threshold), and its result is
    /// ignored if too few peers answer to still reach threshold, since then the
    /// normal round and failover should decide rather than a flaky ping.
    async fn prune_unresponsive_cosigners(&self, capability: Option<&str>) -> Vec<u16> {
        let needed = (self.share.metadata.threshold as usize).saturating_sub(1);
        let snapshot = self.liveness_candidates(capability);
        if snapshot.len() <= needed {
            return Vec::new();
        }

        let responsive = match self
            .ping_peers_snapshot(&snapshot, LIVENESS_PING_TIMEOUT, Some(snapshot.len()))
            .await
        {
            Ok(responsive) => responsive,
            Err(e) => {
                warn!(error = %e, "liveness ping failed; proceeding without pre-exclusion");
                return Vec::new();
            }
        };
        if responsive.len() < needed {
            return Vec::new();
        }

        let unresponsive: Vec<u16> = snapshot
            .iter()
            .map(|(idx, _, _)| *idx)
            .filter(|idx| !responsive.contains(idx))
            .collect();
        if !unresponsive.is_empty() {
            warn!(
                excluded = ?unresponsive,
                "excluding co-signers that failed the pre-round liveness ping"
            );
        }
        unresponsive
    }

    /// The co-signers a round could select, which are the ones the liveness
    /// ping judges: a peer that could not take part (no `capability`) must not
    /// count toward the spare co-signers that justify excluding a slow one.
    fn liveness_candidates(
        &self,
        capability: Option<&str>,
    ) -> Vec<(u16, PublicKey, Option<std::time::Instant>)> {
        self.peers
            .read()
            .get_signing_peers()
            .into_iter()
            .filter(|p| capability.is_none_or(|c| p.has_capability(c)))
            .filter(|p| {
                self.can_send_to_index(p.share_index) && self.can_receive_from_index(p.share_index)
            })
            .map(|p| (p.share_index, p.pubkey, p.last_pong))
            .collect()
    }

    pub async fn request_signature(
        &self,
        message: Vec<u8>,
        message_type: &str,
    ) -> Result<[u8; 64]> {
        self.request_signature_structured(message, message_type, None)
            .await
    }

    /// Request a threshold signature and attach a domain-specific structured
    /// payload the co-signers recompute the digest from (#529). See
    /// [`crate::NostrEventPayload`] / [`crate::BitcoinSighashPayload`] for the
    /// wire schemas. Callers that hold the structured body (nip46 sign_event,
    /// PSBT signing) MUST use this variant so co-signers can catch a
    /// cross-domain label spoof before signing.
    pub async fn request_signature_structured(
        &self,
        message: Vec<u8>,
        message_type: &str,
        structured_payload: Option<Vec<u8>>,
    ) -> Result<[u8; 64]> {
        self.request_signature_at_path(message, message_type, structured_payload, Vec::new())
            .await
    }

    /// Request a threshold signature under a BIP-32 unhardened child of the
    /// group pubkey. Every participant tweaks its FROST KeyPackage by the
    /// composite BIP-32 scalar for `derivation_path` before running the
    /// standard round1/round2, and the aggregated BIP-340 signature verifies
    /// under the derived child pubkey rather than the group pubkey.
    ///
    /// Empty `derivation_path` is equivalent to
    /// [`Self::request_signature_structured`] and signs under the group
    /// pubkey; non-empty paths are the entry point for HD spending
    /// (`/0/*` receive, `/1/*` change) once #487 PR 4 wires the descriptor.
    /// Hardened indexes are refused at protocol validation.
    pub async fn request_signature_at_path(
        &self,
        message: Vec<u8>,
        message_type: &str,
        structured_payload: Option<Vec<u8>>,
        derivation_path: Vec<u32>,
    ) -> Result<[u8; 64]> {
        self.request_signature_inner(
            message,
            message_type,
            structured_payload,
            derivation_path,
            None,
        )
        .await
    }

    /// Request a key-path spend of a taproot output (BIP-341): the aggregate
    /// verifies under the output key of `tr(<child at derivation_path>)` (BIP-86,
    /// no merkle root) or `tr(<group>, <tree>)` (the tree's merkle root, empty
    /// path). `sighash` is the input's key-spend sighash and `psbt_payload` the
    /// [`crate::BitcoinSighashPayload`] it is recomputed from. The spent
    /// scriptPubKey is checked against the group's output here and by every
    /// co-signer, and only co-signers announcing
    /// [`crate::CAPABILITY_TAPROOT_TWEAK`] are asked.
    pub async fn request_key_path_spend(
        &self,
        sighash: Vec<u8>,
        psbt_payload: Vec<u8>,
        derivation_path: Vec<u32>,
        tweak: crate::TaprootTweakPayload,
    ) -> Result<[u8; 64]> {
        crate::verify_structured_payload(crate::MSG_TYPE_BITCOIN_SIGHASH, &sighash, &psbt_payload)?;
        let spk = self.check_key_path_spend(
            crate::MSG_TYPE_BITCOIN_SIGHASH,
            Some(&psbt_payload),
            &derivation_path,
            tweak,
        )?;
        let digest: [u8; 32] = sighash
            .as_slice()
            .try_into()
            .map_err(|_| FrostNetError::Protocol("a sighash is 32 bytes".into()))?;
        let signature = self
            .request_signature_inner(
                sighash,
                crate::MSG_TYPE_BITCOIN_SIGHASH,
                Some(psbt_payload),
                derivation_path,
                Some(tweak),
            )
            .await?;
        // A co-signer may report the signature instead of this node aggregating
        // it, so check it the way consensus will before handing it back.
        taproot::verify_key_path_signature(&signature, &digest, &spk)?;
        Ok(signature)
    }

    async fn request_signature_inner(
        &self,
        mut message: Vec<u8>,
        message_type: &str,
        structured_payload: Option<Vec<u8>>,
        derivation_path: Vec<u32>,
        taproot_tweak: Option<crate::TaprootTweakPayload>,
    ) -> Result<[u8; 64]> {
        // Reject an oversized or hardened path locally, mirroring the wire-side
        // check in `KfpMessage::validate`, so a bad path fails fast with a clear
        // message instead of after a network round-trip.
        if derivation_path.len() > crate::protocol::MAX_DERIVATION_PATH_DEPTH {
            return Err(FrostNetError::Protocol(format!(
                "Derivation path depth {} exceeds maximum {}",
                derivation_path.len(),
                crate::protocol::MAX_DERIVATION_PATH_DEPTH
            )));
        }
        if derivation_path
            .iter()
            .any(|&i| i >= crate::protocol::BIP32_HARDENED_INDEX_START)
        {
            return Err(FrostNetError::Protocol(
                "Derivation path contains a hardened index; only unhardened indexes are \
                 meaningful for FROST groups"
                    .into(),
            ));
        }
        // On a round timeout the co-signers that failed to commit are treated as
        // unresponsive and excluded, then we re-select from the remaining online
        // peers and retry. This fails over to other live co-signers in seconds
        // instead of surfacing the timeout to the caller. The session id is
        // rederived per attempt from the (changed) participant set, so each retry
        // is a fresh session with a fresh nonce.
        //
        // The retry count is capped by MAX_FAILOVER_ATTEMPTS so a partition or
        // latency event cannot stall the caller for round_timeout × eligible
        // peers; the final attempt surfaces its error to the caller.
        //
        // Log-correlation id ONLY, not a cryptographic session id: it ties the
        // failover attempts of one logical request together in the audit log and
        // is independent of the per-attempt participant set. It is never used to
        // gate the replay guard or index the nonce store (each attempt derives a
        // real per-participant session id for that). Two requests for the same
        // message intentionally share this id; do not treat it as unique.
        let logical_id = derive_session_id(&message, &[], self.share.metadata.threshold);
        // On the requester side, verify our own structured payload once before
        // any round: if it does not recompute to `message` the co-signers will
        // reject the request anyway, so we fail fast locally with the same
        // error path (#529).
        if let Some(sp) = structured_payload.as_ref() {
            crate::verify_structured_payload(message_type, &message, sp)?;
        }
        // Drop co-signers that are already unreachable before committing, so the
        // first round goes straight to live peers instead of timing out on a
        // dead one. Peers that drop mid-round are still caught by the failover
        // exclusion below.
        let capability = taproot_tweak.map(|_| crate::CAPABILITY_TAPROOT_TWEAK);
        let mut excluded: Vec<u16> = self.prune_unresponsive_cosigners(capability).await;
        for attempt in 0..MAX_FAILOVER_ATTEMPTS {
            let last = attempt + 1 == MAX_FAILOVER_ATTEMPTS;
            let round_message = if last {
                std::mem::take(&mut message)
            } else {
                message.clone()
            };
            let result = self
                .signing_round(
                    round_message,
                    message_type,
                    structured_payload.clone(),
                    derivation_path.clone(),
                    taproot_tweak,
                    &excluded,
                    logical_id,
                    attempt,
                )
                .await;

            match result {
                Ok(sig) => return Ok(sig),
                Err(SigningRoundError {
                    error: FrostNetError::Timeout(_),
                    attempted,
                }) if !last => {
                    // Fail over on ANY round timeout while retries remain. The
                    // unresponsive set only decides WHICH peers to drop: when it
                    // is non-empty exclude those peers, otherwise (e.g. everyone
                    // committed/responded but aggregation never produced a
                    // SignatureComplete) retry without excluding anyone so the
                    // next attempt re-samples a fresh participant set.
                    if attempted.is_empty() {
                        warn!(
                            attempt = attempt,
                            "signing round timed out with no unresponsive peers; re-sampling and retrying"
                        );
                    } else {
                        warn!(
                            excluded = ?attempted,
                            attempt = attempt,
                            "signing round timed out; excluding unresponsive peers and retrying"
                        );
                        excluded.extend(attempted);
                    }
                }
                Err(SigningRoundError {
                    error: FrostNetError::InsufficientPeers { .. },
                    ..
                }) if !excluded.is_empty() => {
                    // Failover has exhausted the eligible set: each retry after
                    // the first excludes more peers until fewer than threshold
                    // remain. Surfacing InsufficientPeers here would mislead the
                    // caller into thinking the group was undersized, when the
                    // real cause is co-signers timing out during failover. Break
                    // to surface the aggregate failover timeout instead.
                    warn!(
                        attempt = attempt,
                        "failover exhausted the eligible peer set; surfacing aggregate timeout"
                    );
                    break;
                }
                Err(e) => {
                    // If a peer reported a stale pre-exchanged nonce (it
                    // rotated/restarted, so a pooled commitment we referenced no
                    // longer maps to a live secret), drop the suspect pooled
                    // commitments so the *next* request falls back to a fresh
                    // interactive round. We deliberately do NOT retry this request
                    // in place: our single-use nonce was already spent on a share
                    // bound to the stale commitment, the session id is fixed by the
                    // message, and the replay guard would reject re-signing it;
                    // retrying would risk nonce reuse. This is a fatal Session error
                    // (not a Timeout), so it returns to the caller rather than
                    // failing over. The signing session is torn down on failure, so
                    // the next request starts clean.
                    if let FrostNetError::Session(ref msg) = e.error {
                        if msg.contains("stale_nonce") || msg.contains("incomplete_pre_exchange") {
                            // Scope the cleanup to the offending peer when its
                            // index is identifiable from the error (the handler
                            // appends "(peer N)"), so other peers keep their
                            // pooled commitments and don't fall back to slow
                            // interactive rounds. Only when the peer cannot be
                            // identified do we clear the whole pool.
                            match parse_offending_peer(msg) {
                                Some(idx) => {
                                    self.nonce_pool.clear_peer(idx);
                                    warn!(
                                        peer = idx,
                                        "peer reported stale pre-exchanged nonce; cleared its pooled commitments"
                                    );
                                }
                                None => {
                                    self.nonce_pool.clear_all_peers();
                                    warn!(
                                        "peer reported stale pre-exchanged nonce (peer unidentified); cleared pool, next round is interactive"
                                    );
                                }
                            }
                        }
                    }
                    return Err(e.error);
                }
            }
        }
        Err(FrostNetError::Timeout(
            "Signing request timed out after failover".into(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn signing_round(
        &self,
        message: Vec<u8>,
        message_type: &str,
        structured_payload: Option<Vec<u8>>,
        derivation_path: Vec<u32>,
        taproot_tweak: Option<crate::TaprootTweakPayload>,
        exclude: &[u16],
        logical_id: [u8; 32],
        attempt: usize,
    ) -> std::result::Result<[u8; 64], SigningRoundError> {
        // Fatal, not retryable: failover re-samples the participant set, and no
        // set can be signed for while this node's own nonce source is degraded.
        if self.is_entropy_degraded() {
            return Err(SigningRoundError::fatal(FrostNetError::PolicyViolation(
                "OS RNG health check failed; signing refused".into(),
            )));
        }

        let threshold = self.share.metadata.threshold;

        // A peer that predates the taproot tweak drops it and signs untweaked,
        // so a key-path spend only goes to peers that announced support.
        let capability = taproot_tweak.map(|_| crate::CAPABILITY_TAPROOT_TWEAK);
        let (participants, participant_peers) = self
            .select_eligible_peers_with(threshold as usize, exclude, capability)
            .map_err(SigningRoundError::fatal)?;

        let attempted: Vec<u16> = participant_peers.iter().map(|(idx, _)| *idx).collect();

        // Salt the session id with the attempt index so a re-sample over an
        // unchanged participant set (everyone responded but no signature was
        // produced) derives a distinct id and fresh nonce instead of colliding
        // with the just-completed attempt and tripping the replay guard. Attempt
        // 0 with an empty path uses an empty salt to keep the common
        // single-attempt id stable and wire-compatible with peers that predate
        // salted failover. The derivation path is folded in so two requests over
        // the same digest + participant set at DISTINCT child paths derive
        // distinct session ids: otherwise they collide at attempt 0 and a
        // responder resends its cached commitment for the first path, never
        // adopting the second. The responder recomputes and validates the id
        // from the transmitted salt, so this binds the path on both sides.
        let session_salt =
            crate::session::session_salt(attempt as u64, &derivation_path, taproot_tweak.as_ref());
        let session_id =
            derive_session_id_salted(&message, &participants, threshold, &session_salt);

        info!(
            logical_id = %hex::encode(logical_id),
            session_id = %hex::encode(session_id),
            participants = ?participants,
            attempt = attempt,
            "Initiating signing request"
        );

        self.audit_log.log_signing_operation(
            session_id,
            &message,
            None,
            participants.clone(),
            self.share.metadata.identifier,
            SigningOperation::SignRequestInitiated,
            None,
        );

        // #487 PR3: apply the composite BIP-32 tweak to our own key package
        // for the requested path before generating round1 nonces, so the
        // commitment we announce matches what co-signers will validate
        // against their own tweaked packages.
        let key_package = taproot::spend_key_package(
            &self
                .share
                .key_package()
                .map_err(|e| SigningRoundError::fatal(e.into()))?,
            &self.group_pubkey,
            &derivation_path,
            taproot_tweak.map(TaprootTweak::from),
        )
        .map_err(|e| {
            SigningRoundError::fatal(FrostNetError::Crypto(format!(
                "tweak on requester key package failed: {e}"
            )))
        })?;
        let (nonces, our_commitment) =
            frost_secp256k1_tr::round1::commit(key_package.signing_share(), &mut OsRng);

        // Try to use pre-exchanged commitments for the selected peers. If every
        // peer has a pooled commitment, reserve them (single-use; removed from
        // the pool) so the interactive commitment round can be skipped.
        let reserved = self.nonce_pool.reserve_for(&attempted);
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

        let mut request = SignRequestPayload::new(
            session_id,
            self.group_pubkey,
            message.clone(),
            message_type,
            participants.clone(),
        )
        .with_nonce_refs(nonce_refs)
        .with_session_salt(session_salt.clone());
        if let Some(sp) = structured_payload.as_ref() {
            request = request.with_structured_payload(sp.clone());
        }
        if !derivation_path.is_empty() {
            request = request.with_derivation_path(derivation_path.clone());
        }
        if let Some(tweak) = taproot_tweak {
            request = request.with_taproot_tweak(tweak);
        }

        let session_info = SessionInfo {
            session_id,
            message: message.clone(),
            threshold: self.share.metadata.threshold,
            participants: participants.clone(),
            requester: self.share.metadata.identifier,
            message_type: message_type.to_string(),
            structured_payload: structured_payload.clone(),
            derivation_path: derivation_path.clone(),
            taproot_tweak,
        };
        let hooks = self.hooks.read().clone();
        hooks.pre_sign(&session_info)?;

        // Re-checked after the hook, not just before it. The hook can block on a
        // human, so this is the point where the latch is most likely to have
        // tripped underneath the round. Returning here leaves the reserved peer
        // commitments to the still-armed reservation guard instead of building a
        // session on top of a nonce drawn before detection.
        if self.is_entropy_degraded() {
            return Err(SigningRoundError::fatal(FrostNetError::PolicyViolation(
                "OS RNG health check failed during approval; signing refused".into(),
            )));
        }

        {
            let mut sessions = self.sessions.write();
            let session = sessions.create_session_salted(
                session_id,
                message,
                self.share.metadata.threshold,
                participants.clone(),
                &session_salt,
            )?;
            session.set_message_type(message_type.to_string());
            session.set_derivation_path(derivation_path.clone());
            session.set_taproot_tweak(taproot_tweak);

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

        // Subscribe BEFORE sending: a fast cosigner can respond, our run loop
        // can process its share, and the resulting `SignatureComplete` can
        // fire on `event_tx` between the send loop and our `subscribe()`.
        // `tokio::sync::broadcast` does not replay past messages to late
        // subscribers, so a missed completion stalls the request until the
        // coordination timeout. Same race shape as #561 (ECDH) fixed in #562.
        let mut rx = self.event_tx.subscribe();

        // Reservations are already consumed and committed to the live session,
        // so on a send failure tear the session down (matching the timeout and
        // share-generation paths below) rather than leaving it active until it
        // expires.
        let send_result: Result<()> = async {
            for (share_index, pubkey) in participant_peers {
                let event = KfpEventBuilder::sign_request(&self.keys, &pubkey, request.clone())?;
                self.transport.send_event(&event).await?;

                if !using_pre_exchange {
                    let commit_event = KfpEventBuilder::commitment(
                        &self.keys,
                        &pubkey,
                        our_commit_payload.clone(),
                    )?;
                    self.transport.send_event(&commit_event).await?;
                }

                debug!(share_index, using_pre_exchange, "Sent sign request");
            }
            Ok(())
        }
        .await;
        if let Err(e) = send_result {
            self.sessions.write().complete_session(&session_id);
            return Err(e.into());
        }

        // All commitments may already be present: for single-participant
        // (threshold=1), or when peer commitments were pre-exchanged and
        // reserved above. We already subscribed above (before the send loop),
        // so generating the share here can't miss SignatureComplete.
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
                return Err(e.into());
            }
        }

        let result = tokio::time::timeout(SIGNING_ROUND_TIMEOUT, async {
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
                        code,
                        offending_index,
                    }) => {
                        if sid == session_id {
                            return Err(PeerRoundFailure {
                                error,
                                code,
                                offending_index,
                            });
                        }
                    }
                    // `Lagged` is recoverable: the receiver stays live, so keep
                    // waiting rather than aborting a valid signing round. Mirrors
                    // the ECDH recv loop (#562).
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err(PeerRoundFailure {
                            error: "Event channel closed".into(),
                            code: "channel_closed".into(),
                            offending_index: None,
                        });
                    }
                    _ => {}
                }
            }
        })
        .await;

        // Tear the session down on any non-success exit (peer-reported failure,
        // closed channel, or timeout) so a lingering session doesn't block a later
        // request and our consumed nonce can't be reused.
        match result {
            Ok(Ok(signature)) => Ok(signature),
            Ok(Err(failure)) => {
                self.sessions.write().complete_session(&session_id);
                if failure.code == "channel_closed" {
                    // The event channel closed (node shutting down); not a peer
                    // fault, so surface it fatally rather than burning failover
                    // attempts re-subscribing to a dead channel.
                    Err(SigningRoundError::fatal(FrostNetError::Transport(
                        failure.error,
                    )))
                } else if is_recoverable_peer_error(&failure.code) {
                    // Recoverable pre-exchange miss: keep the fatal Session error
                    // so `request_signature` clears the offending peer's pooled
                    // commitments and the next request falls back to interactive.
                    Err(SigningRoundError::fatal(FrostNetError::Session(
                        failure.error,
                    )))
                } else {
                    // A peer actively errored on this session for a
                    // non-recoverable reason. Treat it like an unresponsive peer:
                    // exclude it (by share index when known, else the whole
                    // attempted set) and fail over instead of returning fatally,
                    // so the offender cannot reliably block signing.
                    let attempted = match failure.offending_index {
                        Some(idx) => vec![idx],
                        None => attempted.clone(),
                    };
                    warn!(
                        code = %failure.code,
                        offending = ?failure.offending_index,
                        "peer reported non-recoverable signing error; excluding and failing over"
                    );
                    Err(SigningRoundError {
                        error: FrostNetError::Timeout(failure.error),
                        attempted,
                    })
                }
            }
            Err(_) => {
                // Exclude only peers that never responded; responsive peers stay
                // eligible for the failover retry so we don't drain the eligible
                // set or waste healthy peers' single-use nonces. A peer is
                // unresponsive if it failed to deliver either its commitment or
                // its signature share -- the latter matters when commitments were
                // pre-exchanged, so `uncommitted_participants` would be empty even
                // though shares never arrived. If the session is already gone,
                // fall back to excluding the whole attempted set.
                let unresponsive = {
                    let sessions = self.sessions.read();
                    sessions
                        .get_session(&session_id)
                        .map(|s| {
                            let our = self.share.metadata.identifier;
                            let mut idxs = s.uncommitted_participants(our);
                            for idx in s.participants_missing_shares(our) {
                                if !idxs.contains(&idx) {
                                    idxs.push(idx);
                                }
                            }
                            idxs
                        })
                        .unwrap_or_else(|| attempted.clone())
                };
                self.sessions.write().complete_session(&session_id);
                Err(SigningRoundError {
                    error: FrostNetError::Timeout("Signing request timed out".into()),
                    attempted: unresponsive,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the pure helpers in this module. Mutation testing
    //! (`cargo mutants -p keep-frost-net --file
    //! keep-frost-net/src/node/signing.rs`) on the failover/dedup logic
    //! surfaces these as obvious gaps without dedicated coverage; see #417.

    use super::*;

    /// `is_recoverable_peer_error` gates the failover decision: when a
    /// remote returns one of the two recoverable codes, the requester
    /// drops the offending peer's pooled commitments and falls back to a
    /// fresh interactive round on the NEXT request rather than failing
    /// over and excluding the peer. Mutating the `||`, either `==`, or
    /// the return-bool flips this entire policy.
    #[test]
    fn is_recoverable_peer_error_pins_exact_recoverable_codes() {
        assert!(is_recoverable_peer_error("stale_nonce"));
        assert!(is_recoverable_peer_error("incomplete_pre_exchange"));
        // Anything else MUST fall through to the exclude-and-failover
        // branch — a true return on these would let a faulty/malicious
        // peer block signing by repeatedly emitting recoverable-looking
        // errors that the requester never excludes them for.
        assert!(!is_recoverable_peer_error(""));
        assert!(!is_recoverable_peer_error("stale_nonces"));
        assert!(!is_recoverable_peer_error("STALE_NONCE"));
        assert!(!is_recoverable_peer_error("incomplete_pre_exchange "));
        assert!(!is_recoverable_peer_error("rate_limited"));
        assert!(!is_recoverable_peer_error("malformed_request"));
    }

    /// `parse_offending_peer` extracts the share index from the trailing
    /// "(peer N)" annotation the handler appends. The parsed index is only
    /// trustworthy because the handler appends the resolved sender index
    /// LAST, so `rfind` picks it over any `(peer N)` an attacker embeds in
    /// the free-form `code` (verified by the "last occurrence wins" case
    /// below). This test pins the parser, not the trust boundary: scoping
    /// cleanup safely depends on the suffix being appended at the call site.
    /// A regression returning `None` for every input would force a full
    /// pool wipe every time; a regression returning a wrong index would
    /// scope cleanup at the wrong peer.
    #[test]
    fn parse_offending_peer_extracts_index_from_trailing_annotation() {
        assert_eq!(parse_offending_peer("error (peer 3)"), Some(3));
        assert_eq!(parse_offending_peer("error (peer 42)"), Some(42));
        // Multi-digit and the last occurrence wins (rfind).
        assert_eq!(
            parse_offending_peer("error (peer 9) more (peer 7)"),
            Some(7)
        );
        // Whitespace inside the parentheses is trimmed by .trim().
        assert_eq!(parse_offending_peer("error (peer   5)"), Some(5));
    }

    #[test]
    fn parse_offending_peer_returns_none_when_annotation_absent_or_malformed() {
        // No annotation at all.
        assert_eq!(parse_offending_peer(""), None);
        assert_eq!(parse_offending_peer("plain error message"), None);
        // Missing closing paren.
        assert_eq!(parse_offending_peer("error (peer 5"), None);
        // Non-numeric index.
        assert_eq!(parse_offending_peer("error (peer abc)"), None);
        // Overflow.
        assert_eq!(parse_offending_peer("error (peer 99999999)"), None);
        // Negative index (u16 has no signed parse).
        assert_eq!(parse_offending_peer("error (peer -1)"), None);
    }

    /// The content hash for the nonce-commitment dedup MUST be order- and
    /// position-independent across the commitment set. Pin the
    /// equivalence so a future mutation that drops the primary sort is
    /// caught: it would otherwise let an adversary re-broadcast the same
    /// set under a reordered payload and bypass dedup. The secondary
    /// (commitment) sort key is exercised separately by
    /// `nonce_commitment_content_hash_orders_by_commitment_on_tie`.
    #[test]
    fn nonce_commitment_content_hash_is_order_independent() {
        let a = PreExchangedCommitment {
            nonce_id: [1u8; 32],
            commitment: b"alpha".to_vec(),
        };
        let b = PreExchangedCommitment {
            nonce_id: [2u8; 32],
            commitment: b"beta".to_vec(),
        };
        let c = PreExchangedCommitment {
            nonce_id: [3u8; 32],
            commitment: b"gamma".to_vec(),
        };

        let h1 = nonce_commitment_content_hash(7, &[a.clone(), b.clone(), c.clone()]);
        let h2 = nonce_commitment_content_hash(7, &[c.clone(), a.clone(), b.clone()]);
        assert_eq!(h1, h2, "reordering must not change the dedup hash");
    }

    /// Distinct `share_index` MUST produce a distinct hash. Without this
    /// the dedup would collide commitments contributed by different
    /// peers, defeating the per-peer rebroadcast filter.
    #[test]
    fn nonce_commitment_content_hash_depends_on_share_index() {
        let item = PreExchangedCommitment {
            nonce_id: [9u8; 32],
            commitment: b"x".to_vec(),
        };
        let h1 = nonce_commitment_content_hash(1, std::slice::from_ref(&item));
        let h2 = nonce_commitment_content_hash(2, std::slice::from_ref(&item));
        assert_ne!(h1, h2);
    }

    /// When two entries share a `nonce_id`, the secondary `.then(commitment
    /// .cmp(..))` sort key decides their order, and the hash MUST still be
    /// reorder-independent. This is the case the all-distinct-`nonce_id`
    /// order test cannot reach: dropping or swapping the secondary key lets
    /// the two orderings serialize differently and the hash diverge, so
    /// `assert_eq` here kills that mutant.
    #[test]
    fn nonce_commitment_content_hash_orders_by_commitment_on_tie() {
        let lo = PreExchangedCommitment {
            nonce_id: [5u8; 32],
            commitment: b"aaa".to_vec(),
        };
        let hi = PreExchangedCommitment {
            nonce_id: [5u8; 32],
            commitment: b"bbb".to_vec(),
        };
        let h1 = nonce_commitment_content_hash(3, &[lo.clone(), hi.clone()]);
        let h2 = nonce_commitment_content_hash(3, &[hi, lo]);
        assert_eq!(
            h1, h2,
            "tied nonce_ids must order by commitment, independent of input order"
        );
    }

    /// The per-entry `(len as u32)` length prefix MUST disambiguate where one
    /// commitment ends and the next begins. Without it the serialization is
    /// `nonce_id || commitment` per entry, so a two-entry set and a crafted
    /// single entry whose commitment is `"AB" || nonce_id || "C"` produce an
    /// identical byte stream and collide, opening a dedup-bypass. Construct
    /// exactly that ambiguity: the two hashes differ ONLY because of the
    /// length prefix, so deleting line `:140` makes this `assert_ne` fail and
    /// kills the mutant (the prior all-distinct fixture could not).
    #[test]
    fn nonce_commitment_content_hash_length_prefix_prevents_concatenation_collision() {
        let nid = [4u8; 32];
        let split_a = PreExchangedCommitment {
            nonce_id: nid,
            commitment: b"AB".to_vec(),
        };
        let split_b = PreExchangedCommitment {
            nonce_id: nid,
            commitment: b"C".to_vec(),
        };
        // "AB" || nonce_id || "C": equals the split stream once the length
        // prefix is removed (nonce_id is fixed-width and interleaved).
        let mut merged = b"AB".to_vec();
        merged.extend_from_slice(&nid);
        merged.extend_from_slice(b"C");
        let single = PreExchangedCommitment {
            nonce_id: nid,
            commitment: merged,
        };
        let h_split = nonce_commitment_content_hash(0, &[split_a, split_b]);
        let h_single = nonce_commitment_content_hash(0, &[single]);
        assert_ne!(
            h_split, h_single,
            "length-prefixing must prevent concatenation collisions"
        );
    }

    /// Golden vector pinning the exact serialization end-to-end. One absolute
    /// digest locks the domain separator, the big-endian `share_index` and
    /// length encodings, and the entry layout in a single assertion, killing
    /// the endianness, domain-string, and length-prefix mutants that the
    /// relative eq/ne tests leave alive. Recompute deliberately if the wire
    /// format changes (and bump the `-v1` domain).
    #[test]
    fn nonce_commitment_content_hash_matches_golden_vector() {
        let entries = [
            PreExchangedCommitment {
                nonce_id: [1u8; 32],
                commitment: b"abc".to_vec(),
            },
            PreExchangedCommitment {
                nonce_id: [2u8; 32],
                commitment: b"de".to_vec(),
            },
        ];
        let expected: [u8; 32] = [
            0xa3, 0x41, 0x2c, 0xec, 0x4f, 0x37, 0x4c, 0xd6, 0xaa, 0x34, 0xad, 0x14, 0x3a, 0x9a,
            0xd1, 0xeb, 0xb8, 0x96, 0x22, 0x4f, 0xbc, 0xa9, 0x19, 0xfd, 0x0b, 0x45, 0x5f, 0xc6,
            0x6c, 0x4f, 0x9e, 0x9f,
        ];
        assert_eq!(nonce_commitment_content_hash(7, &entries), expected);
    }
}

#[cfg(test)]
mod gate_tests {
    //! Deterministic responder-gate coverage for the sign-path ingress
    //! handlers (#541 lineage). Each handler runs its early-return gates
    //! before any session work, so the outcome is observable from the return
    //! value alone: build a real node, call the handler directly, no relay
    //! run loop or event-timing.

    use super::*;
    use crate::node::PeerPolicy;
    use keep_core::frost::{ThresholdConfig, TrustedDealer};
    use nostr_relay_builder::MockRelay;

    async fn test_node() -> (KfpNode, MockRelay) {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
        let mock = MockRelay::run().await.unwrap();
        let relay = mock.url().await.to_string();
        let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
        let (mut shares, _) = dealer.generate("signing-gate-test").unwrap();
        // First share -> FROST identifier 1.
        let node = KfpNode::new(shares.remove(0), vec![relay]).await.unwrap();
        (node, mock)
    }

    /// A sign request for a different group is silently ignored (returns Ok
    /// without opening a session). Pins the group-membership early-return: if
    /// the gate were bypassed the request would fall through to the peer lookup
    /// and return `UntrustedPeer` (the random `from` is not an announced peer),
    /// so asserting `Ok` still kills the predicate mutation.
    #[tokio::test]
    async fn handle_sign_request_ignores_foreign_group() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let req = SignRequestPayload::new([1u8; 32], [0xAA; 32], vec![0u8; 32], "test", vec![1]);
        assert!(node.handle_sign_request(from, req).await.is_ok());
    }

    /// A refused request leaves a durable record.
    ///
    /// Every other audit operation records something that happened, so before
    /// this the log answered "what did we sign" but not "what were we asked to
    /// sign and declined". A peer probing a co-signer left only a warning, and
    /// a warning is not something a holder still has to consult later.
    #[tokio::test]
    async fn a_refused_sign_request_is_recorded_in_the_audit_log() {
        let (node, _relay) = test_node().await;
        node.set_hooks(std::sync::Arc::new(crate::RefuseRawSignatureHooks));

        let peer = Keys::generate().public_key();
        node.peers.write().add_peer(crate::peer::Peer::new(peer, 2));

        let session_id = [0x33u8; 32];
        let group = *node.group_pubkey();
        let req = SignRequestPayload::new(session_id, group, vec![0u8; 32], "raw", vec![1, 2]);
        node.handle_sign_request(peer, req)
            .await
            .expect("a refusal is reported to the requester, not surfaced as an error here");

        let entries = node.audit_log().get_entries_for_session(&session_id);
        assert!(
            entries
                .iter()
                .any(|e| matches!(e.operation, SigningOperation::SignRequestRefused)),
            "the refusal must be recorded; got {:?}",
            entries.iter().map(|e| &e.operation).collect::<Vec<_>>()
        );
        assert!(
            node.audit_log().verify_all(),
            "the new operation must be covered by the entry HMAC like every other one"
        );
        assert_eq!(
            entries
                .iter()
                .find(|e| matches!(e.operation, SigningOperation::SignRequestRefused))
                .and_then(|e| e.requester),
            Some(2),
            "the refusal must name the peer that sent it; without this the call \
             site could pass None and nothing would fail"
        );
    }

    /// The structured-payload refusal is attributed too.
    ///
    /// It fires when a requester's body does not produce the digest it asked us
    /// to sign, which is the entry most worth attributing, and it was recorded
    /// unattributed while the index sat in scope a few lines above.
    #[tokio::test]
    async fn a_structured_payload_mismatch_names_the_peer_that_sent_it() {
        let (node, _relay) = test_node().await;

        let peer = Keys::generate().public_key();
        node.peers.write().add_peer(crate::peer::Peer::new(peer, 2));

        let session_id = [0x44u8; 32];
        let group = *node.group_pubkey();
        // A body that cannot produce the digest being signed.
        let req = SignRequestPayload::new(
            session_id,
            group,
            vec![0u8; 32],
            crate::MSG_TYPE_NOSTR_EVENT,
            vec![1, 2],
        )
        .with_structured_payload(b"not a nostr event".to_vec());

        node.handle_sign_request(peer, req)
            .await
            .expect("a refusal is reported to the requester, not surfaced here");

        let entries = node.audit_log().get_entries_for_session(&session_id);
        assert_eq!(
            entries
                .iter()
                .find(|e| matches!(e.operation, SigningOperation::SignRequestRefused))
                .and_then(|e| e.requester),
            Some(2),
            "a relabel attempt must record which peer attempted it"
        );
    }

    /// A key-path spend request from peer 2 to this node (identifier 1) over the
    /// output `spent`, salted as an honest requester would.
    fn key_spend_request(
        node: &KfpNode,
        spent: &bitcoin::ScriptBuf,
        sighash_type: u8,
        path: &[u32],
        tweak: TaprootTweakPayload,
    ) -> SignRequestPayload {
        let (sighash, payload) = crate::test_support::key_spend_payload(spent, sighash_type);
        let salt = crate::session::session_salt(0, path, Some(&tweak));
        let session_id = derive_session_id_salted(&sighash, &[1, 2], 2, &salt);
        SignRequestPayload::new(
            session_id,
            *node.group_pubkey(),
            sighash.to_vec(),
            crate::MSG_TYPE_BITCOIN_SIGHASH,
            vec![1, 2],
        )
        .with_structured_payload(payload)
        .with_derivation_path(path.to_vec())
        .with_taproot_tweak(tweak)
        .with_session_salt(salt)
    }

    fn refused(node: &KfpNode, session_id: &[u8; 32]) -> bool {
        node.audit_log()
            .get_entries_for_session(session_id)
            .iter()
            .any(|e| matches!(e.operation, SigningOperation::SignRequestRefused))
    }

    async fn node_with_requester() -> (KfpNode, MockRelay, PublicKey) {
        let (node, relay) = test_node().await;
        let peer = Keys::generate().public_key();
        node.peers.write().add_peer(crate::peer::Peer::new(peer, 2));
        (node, relay, peer)
    }

    fn own_output(node: &KfpNode, path: &[u32], tweak: TaprootTweakPayload) -> bitcoin::ScriptBuf {
        node.taproot_script_pubkey(path, tweak).unwrap()
    }

    /// A co-signer checks the output itself rather than trusting the requester:
    /// a key-path spend of anything but this group's output for the path and
    /// tweak, or under a sighash narrower than ALL, is refused before any
    /// commitment, while its own output under DEFAULT is accepted and the tweak
    /// is kept for round 2.
    #[tokio::test]
    async fn a_co_signer_checks_the_key_path_spend_itself() {
        let (node, _relay, peer) = node_with_requester().await;
        node.set_hooks(std::sync::Arc::new(RecordingHooks::approving(true)));
        let path = [0u32, 2];
        let bip86 = TaprootTweakPayload::default();
        let rooted = TaprootTweakPayload {
            merkle_root: Some([3; 32]),
        };
        let ours = own_output(&node, &path, bip86);
        let cases = [
            (own_output(&node, &[0, 9], bip86), 0x00, bip86, true),
            (own_output(&node, &path, rooted), 0x00, bip86, true),
            (ours.clone(), 0x02, bip86, true),
            (ours.clone(), 0x81, bip86, true),
            (ours.clone(), 0x00, rooted, true),
            (ours.clone(), 0x00, bip86, false),
            (own_output(&node, &path, rooted), 0x01, rooted, false),
        ];
        for (i, (spent, sighash_type, tweak, refuse)) in cases.into_iter().enumerate() {
            let req = key_spend_request(&node, &spent, sighash_type, &path, tweak);
            let session_id = req.session_id;
            node.handle_sign_request(peer, req).await.unwrap();
            assert_eq!(refused(&node, &session_id), refuse, "case {i}");
            let session_tweak = node
                .sessions
                .read()
                .get_session(&session_id)
                .map(|s| s.taproot_tweak());
            assert_eq!(session_tweak, (!refuse).then_some(Some(tweak)), "case {i}");
        }
    }

    /// A peer that predates the tweak drops it and would sign untweaked, so a
    /// key-path spend only selects peers announcing the capability.
    #[tokio::test]
    async fn a_key_path_spend_only_selects_peers_announcing_the_tweak() {
        let (node, _relay) = test_node().await;
        let capability = Some(crate::CAPABILITY_TAPROOT_TWEAK);
        node.peers
            .write()
            .add_peer(crate::peer::Peer::new(Keys::generate().public_key(), 2));
        assert!(node.select_eligible_peers(2, &[]).is_ok());
        assert!(matches!(
            node.select_eligible_peers_with(2, &[], capability),
            Err(FrostNetError::InsufficientPeers { .. })
        ));

        node.peers.write().add_peer(
            crate::peer::Peer::new(Keys::generate().public_key(), 3)
                .with_capabilities(vec!["sign".into(), crate::CAPABILITY_TAPROOT_TWEAK.into()]),
        );
        for _ in 0..16 {
            let (participants, _) = node.select_eligible_peers_with(2, &[], capability).unwrap();
            assert_eq!(participants, vec![1, 3]);
        }
    }

    /// The requester asks for the capability too: with only a co-signer that
    /// predates the tweak, a key-path spend fails for want of peers instead of
    /// starting a round that peer would sign untweaked.
    #[tokio::test]
    async fn a_key_path_spend_is_not_sent_to_peers_without_the_tweak() {
        let (node, _relay) = test_node().await;
        node.peers
            .write()
            .add_peer(crate::peer::Peer::new(Keys::generate().public_key(), 2));
        let path = [0u32, 1];
        let tweak = TaprootTweakPayload::default();
        let spent = own_output(&node, &path, tweak);
        let (sighash, payload) = crate::test_support::key_spend_payload(&spent, 0x00);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            node.request_key_path_spend(sighash.to_vec(), payload, path.to_vec(), tweak),
        )
        .await
        .expect("refused at selection, before any round could time out");
        assert!(
            matches!(result, Err(FrostNetError::InsufficientPeers { .. })),
            "{result:?}"
        );
    }

    /// Records what the key-path spend approval saw and whether `pre_sign` ran.
    struct RecordingHooks {
        approve: bool,
        approvals: parking_lot::Mutex<Vec<Option<TaprootTweakPayload>>>,
        pre_signs: std::sync::atomic::AtomicUsize,
    }

    impl RecordingHooks {
        fn approving(approve: bool) -> Self {
            Self {
                approve,
                approvals: Default::default(),
                pre_signs: Default::default(),
            }
        }
    }

    impl crate::SigningHooks for RecordingHooks {
        fn pre_sign(&self, _session: &SessionInfo) -> Result<()> {
            self.pre_signs
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        fn post_sign(&self, _session: &SessionInfo, _signature: &[u8; 64]) {}
        fn approve_key_path_spend(&self, session: &SessionInfo) -> bool {
            self.approvals.lock().push(session.taproot_tweak);
            self.approve
        }
    }

    /// A key-path spend needs the hooks' explicit approval, which is asked only
    /// after the node's own checks pass and before `pre_sign` (a human prompt
    /// never sees a spend the policy already refused). The default hooks refuse.
    #[tokio::test]
    async fn a_key_path_spend_needs_the_hooks_approval() {
        let path = [0u32, 2];
        let tweak = TaprootTweakPayload {
            merkle_root: Some([8; 32]),
        };
        for approve in [false, true] {
            let (node, _relay, peer) = node_with_requester().await;
            let hooks = std::sync::Arc::new(RecordingHooks::approving(approve));
            node.set_hooks(hooks.clone());
            let req =
                key_spend_request(&node, &own_output(&node, &path, tweak), 0x00, &path, tweak);
            let session_id = req.session_id;
            node.handle_sign_request(peer, req).await.unwrap();
            assert_eq!(refused(&node, &session_id), !approve);
            assert_eq!(*hooks.approvals.lock(), vec![Some(tweak)]);
            assert_eq!(
                hooks.pre_signs.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(approve)
            );
        }

        let (node, _relay, peer) = node_with_requester().await;
        let req = key_spend_request(&node, &own_output(&node, &path, tweak), 0x00, &path, tweak);
        let session_id = req.session_id;
        node.handle_sign_request(peer, req).await.unwrap();
        assert!(refused(&node, &session_id), "the default hooks refuse");

        // A spend failing the node's own checks never reaches the hooks.
        let (node, _relay, peer) = node_with_requester().await;
        let hooks = std::sync::Arc::new(RecordingHooks::approving(true));
        node.set_hooks(hooks.clone());
        let other = own_output(&node, &[0, 9], tweak);
        node.handle_sign_request(peer, key_spend_request(&node, &other, 0x00, &path, tweak))
            .await
            .unwrap();
        assert!(hooks.approvals.lock().is_empty());
    }

    /// The liveness prune judges only peers a round could select, so an old peer
    /// that cannot take part in a key-path spend is not counted as a spare.
    #[tokio::test]
    async fn liveness_candidates_follow_the_capability() {
        let (node, _relay) = test_node().await;
        node.peers.write().add_peer(
            crate::peer::Peer::new(Keys::generate().public_key(), 2)
                .with_capabilities(vec!["sign".into(), crate::CAPABILITY_TAPROOT_TWEAK.into()]),
        );
        node.peers
            .write()
            .add_peer(crate::peer::Peer::new(Keys::generate().public_key(), 3));
        let indexes = |c| {
            let mut v: Vec<u16> = node.liveness_candidates(c).iter().map(|p| p.0).collect();
            v.sort_unstable();
            v
        };
        assert_eq!(indexes(None), vec![2, 3]);
        assert_eq!(indexes(Some(crate::CAPABILITY_TAPROOT_TWEAK)), vec![2]);
    }

    /// A participant can report a finished signature instead of this node
    /// aggregating it. A key-path spend checks it against the output key before
    /// returning it, so a bogus one fails the request rather than being handed
    /// back as a spend signature.
    #[tokio::test]
    async fn a_reported_key_path_signature_is_checked_before_it_is_returned() {
        let (node, _relay) = test_node().await;
        let node = std::sync::Arc::new(node);
        let peer = Keys::generate().public_key();
        node.peers.write().add_peer(
            crate::peer::Peer::new(peer, 2)
                .with_capabilities(vec!["sign".into(), crate::CAPABILITY_TAPROOT_TWEAK.into()]),
        );
        let path = [0u32, 1];
        let tweak = TaprootTweakPayload::default();
        let spent = own_output(&node, &path, tweak);
        let (sighash, payload) = crate::test_support::key_spend_payload(&spent, 0x00);
        let salt = crate::session::session_salt(0, &path, Some(&tweak));
        let session_id = derive_session_id_salted(&sighash, &[1, 2], 2, &salt);

        let requester = std::sync::Arc::clone(&node);
        let request = tokio::spawn(async move {
            requester
                .request_key_path_spend(sighash.to_vec(), payload, path.to_vec(), tweak)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while node.sessions.read().get_session(&session_id).is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the request opens its session");
        node.handle_signature_complete(
            peer,
            SignatureCompletePayload::new(session_id, [0xab; 64], sighash),
        )
        .await
        .unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), request)
            .await
            .expect("the reported signature ends the request")
            .unwrap();
        let e = result.expect_err("a signature that does not spend the output is refused");
        assert!(e.to_string().contains("output key"), "{e}");
    }

    /// The session id is validated against the transmitted salt, so a salt that
    /// does not encode the request's path and tweak is refused outright.
    #[tokio::test]
    async fn a_salt_that_does_not_bind_the_tweak_is_refused() {
        let (node, _relay, peer) = node_with_requester().await;
        let path = [0u32, 2];
        let tweak = TaprootTweakPayload::default();
        let spent = own_output(&node, &path, tweak);
        let honest = key_spend_request(&node, &spent, 0x00, &path, tweak);
        for salt in [
            crate::session::session_salt(0, &path, None),
            crate::session::session_salt(
                1,
                &path,
                Some(&TaprootTweakPayload {
                    merkle_root: Some([1; 32]),
                }),
            ),
            crate::session::session_salt(0, &[0, 3], Some(&tweak)),
            Vec::new(),
        ] {
            let session_id = derive_session_id_salted(&honest.message, &[1, 2], 2, &salt);
            let mut req = honest.clone().with_session_salt(salt);
            req.session_id = session_id;
            let e = node
                .handle_sign_request(peer, req)
                .await
                .expect_err("an unbound salt must be refused");
            assert!(e.to_string().contains("does not bind"), "{e}");
            assert!(node.sessions.read().get_session(&session_id).is_none());
        }
    }

    /// A sign request whose participant set excludes our own identifier is
    /// ignored. Same mutation-kill property as the foreign-group case.
    #[tokio::test]
    async fn handle_sign_request_ignores_non_participant() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let group = *node.group_pubkey();
        let req = SignRequestPayload::new([1u8; 32], group, vec![0u8; 32], "test", vec![2, 3]);
        assert!(node.handle_sign_request(from, req).await.is_ok());
    }

    /// A duress-frozen holder refuses to co-sign: a fresh sign request for its
    /// own group is rejected with a `PolicyViolation`. The freeze check sits
    /// before the participant/replay/policy gates, so it trips first (fail
    /// closed) , a coerced holder cannot be forced to contribute a signature.
    #[tokio::test]
    async fn handle_sign_request_refused_when_duress_frozen() {
        let (mut node, _relay) = test_node().await;
        let group = *node.group_pubkey();
        let beacon = Keys::generate();
        node.set_duress_beacon_pins(vec![beacon.public_key()]);
        let ev = crate::event::KfpEventBuilder::duress_beacon(
            &beacon,
            &group,
            &[8u8; 32],
            &node.keys.public_key(),
        )
        .await
        .unwrap();
        node.handle_gift_wrap(&ev).await.unwrap();
        assert!(node.is_duress_frozen(), "node must be frozen");

        let from = Keys::generate().public_key();
        let req = SignRequestPayload::new([1u8; 32], group, vec![0u8; 32], "test", vec![1]);
        assert!(matches!(
            node.handle_sign_request(from, req).await,
            Err(FrostNetError::PolicyViolation(_))
        ));
    }

    /// A node whose RNG failed its health check refuses to co-sign. Round 1
    /// draws this node's nonce from `OsRng`, which is not health-checked where
    /// it is used, so the latch is the only thing standing between a degraded
    /// source and a signature. Two shares over one nonce recover the key, which
    /// is why this refuses rather than degrades.
    #[tokio::test]
    async fn handle_sign_request_refused_when_entropy_degraded() {
        let (node, _relay) = test_node().await;
        let group = *node.group_pubkey();
        assert!(!node.is_entropy_degraded(), "must start healthy");

        node.mark_entropy_degraded();
        assert!(node.is_entropy_degraded(), "the latch must hold");

        let from = Keys::generate().public_key();
        let req = SignRequestPayload::new([1u8; 32], group, vec![0u8; 32], "test", vec![1]);
        assert!(matches!(
            node.handle_sign_request(from, req).await,
            Err(FrostNetError::PolicyViolation(_))
        ));
    }

    /// The latch also stops this node initiating a round of its own. Refusing
    /// only inbound requests would leave the path that draws a nonce at
    /// `signing_round` wide open, which is the same nonce from the same source.
    #[tokio::test]
    async fn signing_round_refused_when_entropy_degraded() {
        let (node, _relay) = test_node().await;
        node.mark_entropy_degraded();

        let err = node
            .signing_round(vec![0u8; 32], "test", None, vec![], None, &[], [0u8; 32], 0)
            .await
            .expect_err("a degraded node must not start a round");
        // A PolicyViolation, specifically. The retry loop above only fails over
        // on Timeout and InsufficientPeers, so this variant ends the attempt
        // instead of re-sampling a participant set that cannot help: the
        // degraded source is local, and every candidate set draws from it.
        assert!(
            matches!(err.error, FrostNetError::PolicyViolation(_)),
            "expected a policy refusal, got {:?}",
            err.error
        );
    }

    /// Latching twice alerts once. The probe runs on a timer, so an unguarded
    /// mark would emit an event per tick for as long as the node stays up and
    /// push the rest of the signing history out of any bounded consumer.
    #[tokio::test]
    async fn marking_entropy_degraded_twice_alerts_once() {
        let (node, _relay) = test_node().await;
        let mut rx = node.subscribe();

        node.mark_entropy_degraded();
        node.mark_entropy_degraded();

        assert!(matches!(
            rx.try_recv(),
            Ok(crate::node::KfpNodeEvent::EntropyDegraded)
        ));
        assert!(rx.try_recv().is_err(), "the second mark must not re-alert");
    }

    /// A latched node stops refilling its pool. Left running it would keep
    /// drawing from the degraded source and broadcasting the results, which
    /// under a stuck source publishes the same commitment over and over.
    #[tokio::test]
    async fn replenish_refused_when_entropy_degraded() {
        let (node, _relay) = test_node().await;
        node.mark_entropy_degraded();

        assert!(matches!(
            node.replenish_nonce_pool().await,
            Err(FrostNetError::PolicyViolation(_))
        ));
    }

    /// A source that could not be read is not a source that answered badly.
    /// Latching on the former turns a transient fault, an exhausted descriptor
    /// table or a container with no `/dev`, into an outage only an operator can
    /// clear. Only the statistical verdict is permanent.
    #[test]
    fn only_a_degraded_source_latches_signing() {
        use keep_core::entropy::EntropyHealthError;

        assert!(KfpNode::latches_signing(EntropyHealthError::Degraded));
        assert!(!KfpNode::latches_signing(EntropyHealthError::Unavailable));
    }

    /// A latched node stops handing its pooled commitments to newly discovered
    /// peers. The pool can still hold nonces drawn in the window before
    /// detection, and publishing those is what the replenish gate exists to stop.
    #[tokio::test]
    async fn nonce_pool_is_not_published_when_entropy_degraded() {
        let (node, _relay) = test_node().await;
        node.mark_entropy_degraded();

        assert!(node
            .send_nonce_pool_to(&Keys::generate().public_key())
            .await
            .is_ok());
    }

    /// Latching tears down what was already running, not just what arrives next.
    ///
    /// Detection lags the degradation by up to one probe interval, so a session
    /// created before the latch may hold nonces drawn inside that window, and a
    /// round that reaches round 2 emits a signature share over one. Refusing new
    /// work while letting those finish would leave the exact shares this exists
    /// to prevent.
    #[tokio::test]
    async fn latching_abandons_in_flight_sessions_and_pooled_nonces() {
        let (node, _relay) = test_node().await;
        let participants = vec![1u16, 2u16];
        let message = vec![0u8; 32];

        {
            let mut sessions = node.sessions.write();
            let id = crate::session::derive_session_id(&message, &participants, 2);
            sessions
                .create_session(id, message.clone(), 2, participants.clone())
                .expect("session fixture");
            assert!(sessions.get_session_mut(&id).is_some());
        }
        node.replenish_nonce_pool().await.expect("pool fixture");
        assert!(
            node.nonce_pool.own_available() > 0,
            "the pool must hold nonces before the latch"
        );

        node.mark_entropy_degraded();

        assert_eq!(
            node.nonce_pool.own_available(),
            0,
            "pooled nonces drawn before detection must be discarded"
        );
        let id = crate::session::derive_session_id(&message, &participants, 2);
        assert!(
            node.sessions.write().get_session_mut(&id).is_none(),
            "an in-flight session must be abandoned, not left to expire"
        );
    }

    /// The share chokepoint refuses even when the session survived the teardown.
    ///
    /// Entry gates cannot cover the requester path: it draws its nonce, then
    /// runs the pre-sign hook, which on desktop blocks on a human for up to a
    /// minute against a thirty-second probe. A latch trip inside that window
    /// tears down the pool and the sessions, and the round then builds a fresh
    /// session and reaches this call anyway. Asserted against a session created
    /// after the latch, which is the state that window produces.
    #[tokio::test]
    async fn share_generation_refuses_after_the_latch_even_for_a_live_session() {
        let (node, _relay) = test_node().await;
        let participants = vec![1u16, 2u16];
        let message = vec![0u8; 32];
        let id = crate::session::derive_session_id(&message, &participants, 2);

        node.mark_entropy_degraded();

        {
            let mut sessions = node.sessions.write();
            sessions
                .create_session(id, message, 2, participants)
                .expect("session fixture");
        }

        // Ok, not Err: the refusal is a no-op for the caller, and the property
        // that matters is that no share was produced. A SessionNotFound error
        // would mean it got past the gate and failed for an unrelated reason.
        assert!(
            node.generate_and_send_share(&id).await.is_ok(),
            "the refusal must be a clean no-op"
        );
        assert!(
            node.sessions
                .write()
                .get_session_mut(&id)
                .expect("the fixture session is still present")
                .take_our_nonces()
                .is_none(),
            "refusing must not have consumed nonce material"
        );
    }

    /// A stale sign request (created_at outside the replay window) is rejected.
    #[tokio::test]
    async fn handle_sign_request_rejects_stale_replay() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let group = *node.group_pubkey();
        let mut req = SignRequestPayload::new([1u8; 32], group, vec![0u8; 32], "test", vec![1]);
        req.created_at = 1; // ancient -> outside the replay window
        assert!(matches!(
            node.handle_sign_request(from, req).await,
            Err(FrostNetError::ReplayDetected(_))
        ));
    }

    /// A far-future sign request (created_at beyond the skew bound) is rejected.
    /// Pins the upper side of the replay window, distinct from the stale case.
    #[tokio::test]
    async fn handle_sign_request_rejects_future_skew() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let group = *node.group_pubkey();
        let mut req = SignRequestPayload::new([1u8; 32], group, vec![0u8; 32], "test", vec![1]);
        req.created_at = Timestamp::now().as_secs() + 3600; // beyond MAX_FUTURE_SKEW_SECS
        assert!(matches!(
            node.handle_sign_request(from, req).await,
            Err(FrostNetError::ReplayDetected(_))
        ));
    }

    /// A peer denied by policy cannot open a sign request. Fresh `created_at`
    /// passes the replay gate so the policy gate is what trips.
    #[tokio::test]
    async fn handle_sign_request_rejects_denied_peer() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let group = *node.group_pubkey();
        node.test_inject_peer(crate::peer::Peer::new(from, 2));
        node.set_peer_policy(PeerPolicy::new(2).allow_receive(false));
        let req = SignRequestPayload::new([1u8; 32], group, vec![0u8; 32], "test", vec![1]);
        assert!(matches!(
            node.handle_sign_request(from, req).await,
            Err(FrostNetError::PolicyViolation(_))
        ));
    }

    /// A co-signer's commitment that arrives before the sign request is held
    /// and applied when the session is created, so the round proceeds.
    #[tokio::test]
    async fn commitment_before_its_sign_request_is_applied() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
        let mock = MockRelay::run().await.unwrap();
        let relay = mock.url().await.to_string();
        let (mut shares, _) = TrustedDealer::new(ThresholdConfig::two_of_three())
            .generate("early-commitment")
            .unwrap();
        let node = KfpNode::new(shares.remove(0), vec![relay]).await.unwrap();
        let requester_share = shares.remove(0);
        let from = Keys::generate().public_key();
        node.test_inject_peer(crate::peer::Peer::new(from, 2));

        let message = vec![7u8; 32];
        let session_id = crate::session::derive_session_id(&message, &[1, 2], 2);
        let (_nonces, commitment) = frost_secp256k1_tr::round1::commit(
            requester_share.key_package().unwrap().signing_share(),
            &mut frost_secp256k1_tr::rand_core::OsRng,
        );
        let early = CommitmentPayload::new(session_id, 2, commitment.serialize().unwrap());
        node.handle_commitment(from, early).await.unwrap();
        assert!(node.early_commitments.read().contains_key(&session_id));

        let request =
            SignRequestPayload::new(session_id, *node.group_pubkey(), message, "raw", vec![1, 2]);
        node.handle_sign_request(from, request).await.unwrap();
        assert!(!node.early_commitments.read().contains_key(&session_id));
        let sessions = node.sessions.read();
        let session = sessions.get_session(&session_id).expect("session");
        assert!(session.has_all_commitments());
        assert!(
            matches!(
                session.state(),
                crate::session::SessionState::AwaitingShares
            ),
            "round 2 must have started"
        );
    }

    /// One participant cannot fill the held-commitment buffer for everyone.
    #[tokio::test]
    async fn held_commitments_are_capped_per_sender() {
        let (node, _relay) = test_node().await;
        let (_, commitment) = frost_secp256k1_tr::round1::commit(
            node.share.key_package().unwrap().signing_share(),
            &mut frost_secp256k1_tr::rand_core::OsRng,
        );
        for i in 0..10u8 {
            node.hold_early_commitment([i; 32], 2, commitment);
        }
        assert_eq!(node.early_commitments.read().len(), 4);
        node.hold_early_commitment([99u8; 32], 3, commitment);
        assert_eq!(node.early_commitments.read().len(), 5);
    }

    /// A nonce commitment from a peer whose share index is not announced is
    /// rejected (`verify_peer_share_index`).
    #[tokio::test]
    async fn handle_commitment_rejects_unannounced_peer() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let payload = CommitmentPayload::new([1u8; 32], 2, vec![0u8; 33]);
        assert!(matches!(
            node.handle_commitment(from, payload).await,
            Err(FrostNetError::UntrustedPeer(_))
        ));
    }

    /// A signature share from an unannounced peer is rejected.
    #[tokio::test]
    async fn handle_signature_share_rejects_unannounced_peer() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let payload = SignatureSharePayload::new([1u8; 32], 2, vec![0u8; 32]);
        assert!(matches!(
            node.handle_signature_share(from, payload).await,
            Err(FrostNetError::UntrustedPeer(_))
        ));
    }
}
