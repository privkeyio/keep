// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Threshold-OPRF unlock session wired over KFP.
//!
//! The "box" (initiator) blinds a fixed unlock input, asks a quorum of holders
//! to evaluate it with their dedicated OPRF key shares, and combines the partial
//! evaluations locally into a 32-byte LUKS key. The OPRF key is NEVER
//! reconstructed and the derived key NEVER crosses the wire. Mirrors the ECDH
//! session in [`super::ecdh`], with the holder-side asymmetry and the #621
//! ship-gate (attestation + rate limit + approval) on the eval oracle.

use nostr_sdk::prelude::*;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::error::{FrostNetError, Result};
use crate::event::KfpEventBuilder;
use crate::oprf_session::derive_oprf_session_id;
use crate::protocol::*;

use super::signing::MAX_FAILOVER_ATTEMPTS;
use super::{KfpNode, KfpNodeEvent};

/// Failure of a single OPRF unlock round. `non_responders` carries the sampled
/// holders that never deposited a partial (populated only on a timeout), so the
/// failover loop can exclude them from the next round.
struct OprfRoundError {
    error: FrostNetError,
    non_responders: Vec<u16>,
}

impl OprfRoundError {
    /// A fatal round error with no failover hint (not a holder-silence timeout).
    fn fatal(error: FrostNetError) -> Self {
        Self {
            error,
            non_responders: Vec::new(),
        }
    }
}

impl From<FrostNetError> for OprfRoundError {
    fn from(error: FrostNetError) -> Self {
        Self::fatal(error)
    }
}

impl KfpNode {
    /// Holder side: evaluate a box's blinded element with this node's dedicated
    /// OPRF key share, after passing every #621 gate, in order:
    /// group/participant/replay/policy, pubkey↔share binding, attestation,
    /// rate limit, then the operator approval hook. Only then is the eval oracle
    /// invoked and the partial returned.
    pub(crate) async fn handle_oprf_eval_request(
        &self,
        from: PublicKey,
        request: OprfEvalRequestPayload,
    ) -> Result<()> {
        if request.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        // Fail closed under duress: a verified duress beacon freezes this holder,
        // so it answers NO evaluations until an out-of-band operator clear
        // (inc2c). This is the load-bearing coercion behavior , withholding the
        // OPRF share drops the box below threshold.
        if self.is_duress_frozen() {
            debug!("Refusing OPRF eval request: holder is duress-frozen");
            return Err(FrostNetError::PolicyViolation(
                "holder is duress-frozen; OPRF evaluations refused".into(),
            ));
        }

        if !request
            .participants
            .contains(&self.share.metadata.identifier)
        {
            return Ok(());
        }

        // A node with no OPRF key share is not an OPRF holder; ignore silently.
        let oprf_share = match &self.oprf_key_share {
            Some(s) => s,
            None => return Ok(()),
        };

        if !request.is_within_replay_window(self.replay_window_secs) {
            warn!(
                session_id = %hex::encode(request.session_id),
                created_at = request.created_at,
                "Rejecting OPRF eval request: outside replay window"
            );
            return Err(FrostNetError::ReplayDetected(format!(
                "OPRF eval request created_at {} outside {} second window",
                request.created_at, self.replay_window_secs
            )));
        }

        if !self.can_receive_from(&from) {
            debug!(from = %from, "Rejecting OPRF eval request: policy denies receive");
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {from} not allowed to send OPRF eval requests"
            )));
        }

        // Bind the requester's pubkey to its claimed share index.
        self.verify_peer_share_index(from, request.requester_share_index)?;

        // Attestation gate: the eval oracle requires VERIFIED attestation of the
        // requester, not merely `is_attested()`. `is_attested()` also accepts
        // `NotConfigured` (this node set no expected PCRs); for the OPRF oracle
        // that would be fail-open, so a node guarding a real vault MUST configure
        // expected PCRs and only answer a requester whose measured boot verified.
        {
            let peers = self.peers.read();
            let peer = peers
                .get_peer(request.requester_share_index)
                .ok_or_else(|| {
                    FrostNetError::UntrustedPeer(format!(
                        "OPRF requester share {} not announced",
                        request.requester_share_index
                    ))
                })?;
            // Require a Verified status that is still FRESH: an attested
            // announce within the offline window. A bare `Verified` is sticky
            // (a failing re-announce is rejected before it can downgrade the
            // entry), so gating on freshness stops a stolen network identity
            // replayed from un-attested hardware from trading on a stale verdict.
            if !peer.is_attestation_fresh(peers.offline_threshold()) {
                return Err(FrostNetError::UntrustedPeer(format!(
                    "OPRF requester share {} attestation not fresh-Verified ({:?})",
                    request.requester_share_index, peer.attestation_status
                )));
            }
        }

        // DoS-hygiene rate limit on the oracle. This is NOT the anti-grinding control (the fresh
        // attestation gate just above is): the unlock input is fixed, so one eval per holder yields
        // the key and a rate cap adds no offline-guessing resistance. See OprfEvalRateLimiter's doc.
        if !self.oprf_rate_limiter.write().check_and_record(from) {
            warn!(from = %from, "Rejecting OPRF eval request: rate limit exceeded");
            return Err(FrostNetError::RateLimited(format!(
                "OPRF eval rate limit exceeded for {from}"
            )));
        }

        info!(
            session_id = %hex::encode(request.session_id),
            requester = request.requester_share_index,
            "Received OPRF eval request"
        );

        let _ = self.event_tx.send(KfpNodeEvent::OprfEvalRequested {
            session_id: request.session_id,
            requester_index: request.requester_share_index,
        });

        // Operator approval hook (default-DENY; a holder must opt in with an
        // explicit policy). Clone the Arc so the read guard is dropped before
        // awaiting.
        let hooks = self.hooks.read().clone();
        if !hooks
            .approve_oprf_eval(request.requester_share_index, request.session_id)
            .await
        {
            info!(
                session_id = %hex::encode(request.session_id),
                "OPRF eval declined by approval hook"
            );
            return Ok(());
        }

        let partial = keep_core::oprf::unlock::evaluate(oprf_share, &request.blinded)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        let payload = OprfEvalSharePayload::new(
            request.session_id,
            self.share.metadata.identifier,
            partial.to_vec(),
        );

        let event = KfpEventBuilder::oprf_eval_share(&self.keys, &from, payload)?;
        self.client
            .send_event(&event)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        debug!(
            session_id = %hex::encode(request.session_id),
            "Sent OPRF eval share"
        );

        Ok(())
    }

    /// Box side: collect a holder partial, and on quorum derive the LUKS key
    /// locally and emit [`KfpNodeEvent::OprfUnlockComplete`].
    pub(crate) async fn handle_oprf_eval_share(
        &self,
        from: PublicKey,
        payload: OprfEvalSharePayload,
    ) -> Result<()> {
        self.verify_peer_share_index(from, payload.share_index)?;

        self.peers.write().update_last_seen(payload.share_index);

        let luks_key = {
            let mut oprf_sessions = self.oprf_sessions.write();
            let session = match oprf_sessions.get_session_mut(&payload.session_id) {
                Some(s) => s,
                None => {
                    debug!(
                        session_id = %hex::encode(payload.session_id),
                        "No OPRF unlock session for share"
                    );
                    return Ok(());
                }
            };

            session.add_partial(payload.share_index, payload.partial.clone())?;

            if session.has_quorum() {
                // On a finalize failure (e.g. a wrong partial from a misbehaving
                // holder) emit OprfUnlockFailed so the box fails fast instead of
                // blocking on its 30s timeout.
                match session.try_finalize() {
                    Ok(key) => key,
                    Err(e) => {
                        // Use the already-held write guard; re-locking would
                        // deadlock (parking_lot is not reentrant).
                        oprf_sessions.complete_session(&payload.session_id);
                        let _ = self.event_tx.send(KfpNodeEvent::OprfUnlockFailed {
                            session_id: payload.session_id,
                            error: e.to_string(),
                        });
                        return Err(e);
                    }
                }
            } else {
                None
            }
        };

        if let Some(key) = luks_key {
            info!(
                session_id = %hex::encode(payload.session_id),
                "OPRF unlock complete!"
            );

            self.oprf_sessions
                .write()
                .complete_session(&payload.session_id);

            let _ = self.event_tx.send(KfpNodeEvent::OprfUnlockComplete {
                session_id: payload.session_id,
                luks_key: key,
            });
        }

        Ok(())
    }

    /// Box public API: blind `input`, gather a quorum of holder partial
    /// evaluations, and derive the 32-byte LUKS key. The node must hold an OPRF
    /// key share. Mirrors [`KfpNode::request_ecdh`].
    ///
    /// PROVISIONING CONTRACT: eligible peers are the FROST signing peers, and a
    /// selected peer with no OPRF key share silently does not answer (it is not a
    /// holder), so the box would miss quorum and time out. Therefore every
    /// signing peer MUST be issued an OPRF key share 1:1, and the OPRF key MUST be
    /// split with the SAME threshold `t` as the FROST group (this method passes
    /// the FROST threshold to `finalize_luks_key`); a mismatch makes every
    /// finalize fail. The node with FROST identifier `i` must hold the OPRF share
    /// at vsss index `i`.
    /// Threshold OPRF unlock with in-attempt holder failover.
    ///
    /// A single unlock samples `threshold-1` holders and waits one timeout for
    /// their partials. On timeout with fewer than `threshold` partials, the
    /// holders that never answered are excluded and a fresh round re-samples
    /// from the remaining eligible holders, up to `MAX_FAILOVER_ATTEMPTS`. This
    /// fails over to a live holder in seconds instead of failing the boot closed
    /// when one holder is momentarily unreachable (the real target: a
    /// geo-distributed holder on a flaky network). Mirrors the FROST signing
    /// failover (`signing.rs`).
    ///
    /// Failover keys off a `Timeout` (silence) ONLY. A holder that answers but
    /// rejects (duress-frozen, unattested, rate-limited, or approval-denied)
    /// simply sends nothing, so it is indistinguishable from unreachable and is
    /// correctly excluded. A holder whose partial reaches the box but fails to
    /// combine surfaces as `Session`/`OprfUnlockFailed`, which is a real
    /// cryptographic rejection and is surfaced to the caller unchanged (retrying
    /// a different holder would combine to the same key, so it cannot help and
    /// must not mask a misbehaving holder). Re-sampling never re-hits an
    /// *excluded* (non-responding) holder; a holder that did respond may be
    /// re-sampled in a later round, but the loop is capped at
    /// `MAX_FAILOVER_ATTEMPTS` and every holder independently enforces its
    /// per-requester rate limit and attestation gate on each eval, so failover
    /// cannot drive a holder past its budget. Not a grinding vector.
    pub async fn request_oprf_unlock(
        &self,
        input: &[u8],
        volume_id: &str,
        epoch: u32,
    ) -> Result<Zeroizing<[u8; 32]>> {
        // Fail fast once if this node holds no OPRF share, before any round.
        if self.oprf_key_share.is_none() {
            return Err(FrostNetError::Crypto(
                "Node has no OPRF key share; cannot initiate unlock".into(),
            ));
        }

        let mut excluded: Vec<u16> = Vec::new();
        for attempt in 0..MAX_FAILOVER_ATTEMPTS {
            let last = attempt + 1 == MAX_FAILOVER_ATTEMPTS;
            match self
                .oprf_unlock_round(input, volume_id, epoch, &excluded)
                .await
            {
                Ok(key) => return Ok(key),
                Err(OprfRoundError {
                    error: FrostNetError::Timeout(_),
                    non_responders,
                }) if !last => {
                    if non_responders.is_empty() {
                        warn!(
                            attempt,
                            "OPRF unlock round timed out with no identifiable non-responders; re-sampling and retrying"
                        );
                    } else {
                        warn!(
                            excluded = ?non_responders,
                            attempt,
                            "OPRF unlock round timed out; excluding unresponsive holders and retrying"
                        );
                        excluded.extend(non_responders);
                    }
                }
                Err(OprfRoundError {
                    error: FrostNetError::InsufficientPeers { .. },
                    ..
                }) if !excluded.is_empty() => {
                    // Failover exhausted the eligible holder set (each retry
                    // excludes more until fewer than threshold remain). Surface
                    // the aggregate timeout, not InsufficientPeers, which would
                    // wrongly suggest the group was undersized.
                    warn!(
                        attempt,
                        "OPRF failover exhausted the eligible holder set; surfacing aggregate timeout"
                    );
                    break;
                }
                Err(OprfRoundError { error, .. }) => return Err(error),
            }
        }
        Err(FrostNetError::Timeout(
            "OPRF unlock request timed out after failover".into(),
        ))
    }

    /// Derive the quorum key that seals/unseals a threshold **secret**, by running
    /// the OPRF unlock flow with the dedicated secrets input
    /// ([`keep_core::oprf::SECRET_SEAL_INPUT`]) instead of the LUKS one. `oprf_id`
    /// is the secret's id (its `ThresholdSeal.oprf_id`, used as the OPRF `volume_id`)
    /// and `epoch` its rotation counter, so every secret derives a distinct key from
    /// the SAME provisioned OPRF root the vault already uses for LUKS unlock, with no
    /// per-secret provisioning. Requires a t-of-n quorum: a single device cannot
    /// assemble the partials, so it cannot derive the key. The 32 bytes are the
    /// `oprf_key` fed to `keep_core::secret::{seal_value, unseal_value}`.
    ///
    /// DESIGN PROPERTY: the OPRF eval is oblivious, so a holder's `approve_oprf_eval`
    /// hook sees only `(requester_share_index, session_id)` -- it cannot tell a
    /// secret-seal eval from a LUKS-unlock eval, nor which secret. Any authorized
    /// quorum eval therefore grants derivation across both domains; an operator
    /// cannot approve "this one secret only". Acceptable because both domains already
    /// demand the identical quorum + fresh attestation, so this crosses no new
    /// authority boundary.
    pub async fn request_secret_seal_key(
        &self,
        oprf_id: &str,
        epoch: u32,
    ) -> Result<Zeroizing<[u8; 32]>> {
        self.request_oprf_unlock(keep_core::oprf::SECRET_SEAL_INPUT, oprf_id, epoch)
            .await
    }

    /// One OPRF unlock round: sample (excluding `excluded`), blind, send, and
    /// wait one timeout. On timeout, the returned `non_responders` are the
    /// sampled holders that never deposited a partial, so the caller can exclude
    /// them and fail over.
    async fn oprf_unlock_round(
        &self,
        input: &[u8],
        volume_id: &str,
        epoch: u32,
        excluded: &[u16],
    ) -> std::result::Result<Zeroizing<[u8; 32]>, OprfRoundError> {
        let oprf_share = self
            .oprf_key_share
            .as_ref()
            .expect("caller checked oprf_key_share is present");

        let threshold = self.share.metadata.threshold;

        let (participants, participant_peers) = self
            .select_eligible_peers(threshold as usize, excluded)
            .map_err(OprfRoundError::fatal)?;

        let (client, blinded) = keep_core::oprf::unlock::blind(input)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;
        let blinded_arr: [u8; 33] = blinded
            .as_slice()
            .try_into()
            .map_err(|_| FrostNetError::Crypto("Invalid blinded element length".into()))?;

        let session_id = derive_oprf_session_id(&blinded_arr, &participants);

        info!(
            session_id = %hex::encode(session_id),
            participants = ?participants,
            "Initiating OPRF unlock request"
        );

        let our_partial = keep_core::oprf::unlock::evaluate(oprf_share, &blinded)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        {
            let mut oprf_sessions = self.oprf_sessions.write();
            let session = oprf_sessions.create_session(
                session_id,
                client,
                threshold as usize,
                participants.clone(),
                volume_id.to_string(),
                epoch,
            )?;
            session.add_partial(self.share.metadata.identifier, our_partial.to_vec())?;
        }

        let request = OprfEvalRequestPayload::new(
            session_id,
            self.group_pubkey,
            blinded_arr,
            participants.clone(),
            self.share.metadata.identifier,
        );

        // Subscribe BEFORE sending so a fast holder's share, processed by our run
        // loop, cannot fire `OprfUnlockComplete` before we start listening
        // (broadcast does not replay to late subscribers). Same flake class as
        // ECDH #561.
        let mut rx = self.event_tx.subscribe();

        // Tear the just-created session down on any send failure, instead of
        // letting it linger until cleanup_expired reaps it (matches the teardown
        // on the timeout/error path below).
        let send_result: Result<()> = async {
            for (share_index, pubkey) in participant_peers {
                let event =
                    KfpEventBuilder::oprf_eval_request(&self.keys, &pubkey, request.clone())?;
                self.client
                    .send_event(&event)
                    .await
                    .map_err(|e| FrostNetError::Transport(e.to_string()))?;
                debug!(share_index, "Sent OPRF eval request");
            }
            Ok(())
        }
        .await;
        if let Err(e) = send_result {
            self.oprf_sessions.write().complete_session(&session_id);
            return Err(OprfRoundError::fatal(e));
        }

        // Single-participant (threshold=1) or quorum already met by our own
        // partial: finalize locally without waiting on the network.
        let immediate = {
            let mut oprf_sessions = self.oprf_sessions.write();
            match oprf_sessions.get_session_mut(&session_id) {
                Some(s) if s.has_quorum() => match s.try_finalize() {
                    Ok(key) => key,
                    Err(e) => {
                        oprf_sessions.complete_session(&session_id);
                        return Err(OprfRoundError::fatal(e));
                    }
                },
                _ => None,
            }
        };
        if let Some(key) = immediate {
            info!(
                session_id = %hex::encode(session_id),
                "OPRF unlock complete (single-party)!"
            );
            self.oprf_sessions.write().complete_session(&session_id);
            if let Err(e) = self.event_tx.send(KfpNodeEvent::OprfUnlockComplete {
                session_id,
                luks_key: key,
            }) {
                warn!(
                    session_id = %hex::encode(session_id),
                    error = %e,
                    "Failed to send OprfUnlockComplete event (single-party)"
                );
            }
        }

        let timeout = self.dealer_wait_timeout();

        let result = tokio::time::timeout(timeout, async {
            loop {
                match rx.recv().await {
                    Ok(KfpNodeEvent::OprfUnlockComplete {
                        session_id: sid,
                        luks_key,
                    }) => {
                        if sid == session_id {
                            return Ok(luks_key);
                        }
                    }
                    Ok(KfpNodeEvent::OprfUnlockFailed {
                        session_id: sid,
                        error,
                    }) => {
                        if sid == session_id {
                            return Err(FrostNetError::Session(error));
                        }
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
            Err(_) => Err(FrostNetError::Timeout(
                "OPRF unlock request timed out".into(),
            )),
        };
        match result {
            Ok(key) => Ok(key),
            Err(error) => {
                // On a timeout, identify the sampled holders that never
                // deposited a partial so the caller can exclude them and fail
                // over to other eligible holders. Read responders BEFORE tearing
                // the session down. A non-timeout error (a real cryptographic
                // rejection or a transport fault) carries no non-responders, so
                // the caller surfaces it unchanged.
                let non_responders = if matches!(error, FrostNetError::Timeout(_)) {
                    let sessions = self.oprf_sessions.read();
                    match sessions.get_session(&session_id) {
                        Some(s) => {
                            let responded: std::collections::HashSet<u16> =
                                s.responders().into_iter().collect();
                            participants
                                .iter()
                                .copied()
                                .filter(|p| {
                                    *p != self.share.metadata.identifier && !responded.contains(p)
                                })
                                .collect()
                        }
                        None => Vec::new(),
                    }
                } else {
                    Vec::new()
                };
                // Tear the session down on any non-success exit so it does not
                // linger until cleanup_expired reaps it (matches request_ecdh).
                self.oprf_sessions.write().complete_session(&session_id);
                Err(OprfRoundError {
                    error,
                    non_responders,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Single-node gate tests for the OPRF eval oracle: build a real node, call
    //! the handler directly, no relay run loop.

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
        let (mut shares, _) = dealer.generate("oprf-eval-gate-test").unwrap();
        // First share -> FROST identifier 1.
        (
            KfpNode::new(shares.remove(0), vec![relay]).await.unwrap(),
            mock,
        )
    }

    fn oprf_share() -> keep_core::oprf::threshold::KeyShare {
        use k256::elliptic_curve::rand_core::OsRng;
        use k256::{elliptic_curve::Field, Scalar};
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        keep_core::oprf::threshold::split_key(&secret, 2, 3, rng)
            .unwrap()
            .remove(0)
    }

    // participants = [1] so the "addressed to us" membership gate passes and the
    // request reaches the later replay/policy gates. requester_share_index 2 is
    // only consulted after those gates.
    fn eval_req(group: [u8; 32]) -> OprfEvalRequestPayload {
        OprfEvalRequestPayload::new([1u8; 32], group, [0x02u8; 33], vec![1], 2)
    }

    #[tokio::test]
    async fn handle_oprf_eval_request_ignores_foreign_group() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        // Foreign group short-circuits (Ok) before any later gate.
        assert!(node
            .handle_oprf_eval_request(from, eval_req([0xAAu8; 32]))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn handle_oprf_eval_request_ignores_non_participant() {
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let mut req = eval_req(*node.group_pubkey());
        req.participants = vec![2, 3]; // excludes our identifier (1) -> ignored
        assert!(node.handle_oprf_eval_request(from, req).await.is_ok());
    }

    #[tokio::test]
    async fn handle_oprf_eval_request_refused_when_duress_frozen() {
        let (mut node, _relay) = test_node().await;
        let group = *node.group_pubkey();
        let beacon = Keys::generate();
        node.set_duress_beacon_pins(vec![beacon.public_key()]);
        let ev =
            KfpEventBuilder::duress_beacon(&beacon, &group, &[8u8; 32], &node.keys.public_key())
                .await
                .unwrap();
        node.handle_gift_wrap(&ev).await.unwrap();
        assert!(node.is_duress_frozen(), "node must be frozen");

        // The duress gate sits before the participant/share/replay/policy gates,
        // so it trips first (fail closed) even with no OPRF share configured.
        let from = Keys::generate().public_key();
        assert!(matches!(
            node.handle_oprf_eval_request(from, eval_req(group)).await,
            Err(FrostNetError::PolicyViolation(_))
        ));
    }

    #[tokio::test]
    async fn handle_oprf_eval_request_rejects_stale_replay() {
        let (mut node, _relay) = test_node().await;
        node.set_oprf_key_share(oprf_share());
        let from = Keys::generate().public_key();
        let mut req = eval_req(*node.group_pubkey());
        req.created_at = 1; // ancient -> outside the replay window
        assert!(matches!(
            node.handle_oprf_eval_request(from, req).await,
            Err(FrostNetError::ReplayDetected(_))
        ));
    }

    #[tokio::test]
    async fn handle_oprf_eval_request_rejects_denied_peer() {
        let (mut node, _relay) = test_node().await;
        node.set_oprf_key_share(oprf_share());
        let from = Keys::generate().public_key();
        node.set_peer_policy(PeerPolicy::new(from).allow_receive(false));
        // Fresh created_at passes the replay gate; policy denial trips next.
        let group = *node.group_pubkey();
        assert!(matches!(
            node.handle_oprf_eval_request(from, eval_req(group)).await,
            Err(FrostNetError::PolicyViolation(_))
        ));
    }

    #[tokio::test]
    async fn handle_oprf_eval_share_rejects_unannounced_peer() {
        // The share-ingestion handler binds the sender's pubkey to its claimed
        // share index first, so a partial from an unannounced peer is rejected
        // rather than fed into a session.
        let (node, _relay) = test_node().await;
        let from = Keys::generate().public_key();
        let payload = OprfEvalSharePayload::new([1u8; 32], 2, vec![0u8; 32]);
        assert!(matches!(
            node.handle_oprf_eval_share(from, payload).await,
            Err(FrostNetError::UntrustedPeer(_))
        ));
    }
}
