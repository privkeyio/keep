// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::collections::HashSet;

use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::descriptor_session::{
    derive_descriptor_session_id, derive_policy_hash, participant_indices, reconstruct_descriptor,
    FinalizedDescriptor,
};
use crate::error::{FrostNetError, Result};
use crate::protocol::*;
use keep_core::relay::TIMESTAMP_TWEAK_RANGE;

use super::{sanitize_reason, KfpNode, KfpNodeEvent};

impl KfpNode {
    pub async fn request_descriptor(
        &self,
        policy: WalletPolicy,
        network: &str,
        own_xpub: &str,
        own_fingerprint: &str,
    ) -> Result<[u8; 32]> {
        self.request_descriptor_with_timeout(policy, network, own_xpub, own_fingerprint, None)
            .await
    }

    /// Orchestrate a descriptor migration. This is a thin wrapper over
    /// [`request_descriptor`] that asserts `policy.version > 1` so the
    /// resulting descriptor records its monotonic bump. After the session
    /// completes (the caller observes `DescriptorComplete`), the caller is
    /// responsible for:
    ///   1. Building a `WalletDescriptor` with `previous_descriptor_hash`
    ///      set to the predecessor's `canonical_hash()`.
    ///   2. Persisting it via `Keep::store_wallet_descriptor`.
    ///   3. Broadcasting the link via [`send_descriptor_migrate`].
    ///
    /// There is no automatic on-chain sweep; that remains an explicit
    /// follow-up via `request_psbt_propose`.
    pub async fn request_descriptor_migrate(
        &self,
        old_group_pubkey: [u8; 32],
        policy: WalletPolicy,
        network: &str,
        own_xpub: &str,
        own_fingerprint: &str,
    ) -> Result<[u8; 32]> {
        if policy.version < MIN_DESCRIPTOR_MIGRATION_VERSION {
            return Err(FrostNetError::Session(
                "request_descriptor_migrate requires policy.version >= 2".into(),
            ));
        }
        // A descriptor migration stays on the same FROST group; only the
        // policy/descriptor bumps. Reject calls that look like they intended
        // to rotate the group (which is not supported by this helper) so the
        // caller's expectations and what we coordinate cannot drift apart.
        if old_group_pubkey != self.group_pubkey {
            return Err(FrostNetError::Session(
                "request_descriptor_migrate: old_group_pubkey must equal this node's group_pubkey (descriptor migration does not rotate the FROST group)".into(),
            ));
        }
        debug!(
            old_group = %hex::encode(old_group_pubkey),
            new_version = policy.version,
            "Starting descriptor migration"
        );
        self.request_descriptor(policy, network, own_xpub, own_fingerprint)
            .await
    }

    /// Broadcast a `DescriptorMigrate` link message announcing that the
    /// new descriptor (identified by `new_descriptor_hash` at version
    /// `new_version`) supersedes the descriptor identified by
    /// `old_descriptor_hash`.
    pub async fn send_descriptor_migrate(
        &self,
        session_id: [u8; 32],
        old_descriptor_hash: [u8; 32],
        new_descriptor_hash: [u8; 32],
        new_version: u32,
    ) -> Result<()> {
        let payload = DescriptorMigratePayload::new(
            session_id,
            self.group_pubkey,
            old_descriptor_hash,
            new_descriptor_hash,
            new_version,
        );
        payload
            .validate()
            .map_err(|e| FrostNetError::Session(e.to_string()))?;
        let msg = KfpMessage::DescriptorMigrate(payload);
        let json = msg.to_json()?;

        let target_peers: Vec<PublicKey> = {
            let peers = self.peers.read();
            peers
                .get_online_peers()
                .iter()
                .filter(|p| self.can_send_to(&p.pubkey) && self.can_receive_from(&p.pubkey))
                .map(|p| p.pubkey)
                .collect()
        };

        for pubkey in &target_peers {
            let encrypted =
                nip44::encrypt(self.keys.secret_key(), pubkey, &json, nip44::Version::V2)
                    .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

            let event = EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
                .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
                .tag(Tag::public_key(*pubkey))
                .tag(Tag::custom(
                    TagKind::custom("g"),
                    [hex::encode(self.group_pubkey)],
                ))
                .tag(Tag::custom(TagKind::custom("s"), [hex::encode(session_id)]))
                .tag(Tag::custom(TagKind::custom("t"), ["descriptor_migrate"]))
                .sign_with_keys(&self.keys)
                .map_err(|e| FrostNetError::Nostr(e.to_string()))?;

            self.client
                .send_event(&event)
                .await
                .map_err(|e| FrostNetError::Transport(e.to_string()))?;
        }

        info!(
            session_id = %hex::encode(session_id),
            new_version,
            "Broadcast descriptor migrate link"
        );
        Ok(())
    }

    pub(crate) async fn handle_descriptor_migrate(
        &self,
        sender: PublicKey,
        payload: DescriptorMigratePayload,
    ) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        if !self.can_receive_from(&sender) {
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {sender} not allowed to send descriptor migrate"
            )));
        }

        if !payload.is_within_replay_window(self.replay_window_secs) {
            return Err(FrostNetError::ReplayDetected(
                "Descriptor migrate outside replay window".into(),
            ));
        }

        let sender_share_index = {
            let peers = self.peers.read();
            peers
                .get_peer_by_pubkey(&sender)
                .map(|p| p.share_index)
                .ok_or_else(|| FrostNetError::UntrustedPeer(sender.to_string()))?
        };
        self.check_proposer_authorized(sender_share_index)?;

        // Per-session de-duplication: drop replays of the same (session,
        // new_descriptor_hash) link, even when each instance is individually
        // within the replay window. Checked BEFORE binding validation so a
        // duplicate can short-circuit, but the entry is only INSERTED after
        // validation succeeds; otherwise an attacker could pre-poison the
        // set with forged tuples to suppress a legitimate later message.
        // Bounded prune happens in the main loop.
        {
            let seen = self.seen_descriptor_migrates.read();
            let key = (payload.session_id, payload.new_descriptor_hash);
            if seen.contains_key(&key) {
                debug!(
                    session_id = %hex::encode(payload.session_id),
                    "Dropping duplicate descriptor migrate link"
                );
                return Ok(());
            }
        }

        // Bind `new_descriptor_hash` to a session we observed completing for
        // this `session_id`. Without this, the link could announce any pair
        // of hashes the sender chose.
        {
            let sessions = self.descriptor_sessions.read();
            match sessions.get_session(&payload.session_id) {
                Some(session) => {
                    if session.group_pubkey() != &payload.group_pubkey {
                        return Err(FrostNetError::Session(
                            "Descriptor migrate group_pubkey does not match session".into(),
                        ));
                    }
                    if session.policy().version != payload.new_version {
                        return Err(FrostNetError::Session(
                            "Descriptor migrate new_version does not match session policy".into(),
                        ));
                    }
                    // Bind sender to the session initiator: only the proposer
                    // who drove the session to completion may announce its
                    // migrate link. Without this any authorized proposer could
                    // hijack the announcement. Both `sender` and the stored
                    // initiator are `nostr_sdk::PublicKey` (x-only schnorr,
                    // 32 bytes) sourced from event signers, so equality is on
                    // the same key form by construction; no projection or
                    // re-derivation is involved.
                    match session.initiator() {
                        Some(init) if init == &sender => {}
                        Some(_) => {
                            return Err(FrostNetError::Session(
                                "Descriptor migrate sender is not the session initiator".into(),
                            ));
                        }
                        None => {
                            return Err(FrostNetError::Session(
                                "Descriptor migrate session has no recorded initiator".into(),
                            ));
                        }
                    }
                    // Require the session to be in Complete state. A merely
                    // Finalized session has not received the full ACK quorum,
                    // so its descriptor must not be promoted as authoritative
                    // via a migrate link yet.
                    if !session.is_complete() {
                        return Err(FrostNetError::Session(
                            "Descriptor migrate references a session that is not complete".into(),
                        ));
                    }
                    let finalized = session.descriptor().ok_or_else(|| {
                        FrostNetError::Session(
                            "Descriptor migrate references a session that has not finalized".into(),
                        )
                    })?;
                    let expected = keep_core::wallet::canonical_descriptor_hash(
                        &finalized.external,
                        &finalized.internal,
                        &finalized.policy_hash,
                        session.policy().version,
                    )
                    .map_err(|e| FrostNetError::Session(e.to_string()))?;
                    if expected != payload.new_descriptor_hash {
                        return Err(FrostNetError::Session(
                            "Descriptor migrate new_descriptor_hash does not match session".into(),
                        ));
                    }
                }
                None => {
                    // The session is no longer held in memory. Fall back to
                    // the persisted descriptor lookup; if that also misses,
                    // refuse to act on an unauthenticated link.
                    let known = self
                        .descriptor_lookup
                        .as_ref()
                        .map(|l| {
                            l.find_by_hash(&payload.group_pubkey, &payload.new_descriptor_hash)
                        })
                        .unwrap_or(false);
                    if !known {
                        return Err(FrostNetError::Session(
                            "Descriptor migrate references unknown session and unknown new descriptor".into(),
                        ));
                    }
                }
            }
        }

        // Bind `old_descriptor_hash` to a descriptor we already hold for
        // this group. Without this, the link could supersede any record.
        // `descriptor_lookup` is also mandatory to enforce the monotonic
        // version invariant below; refusing to handle the message when it is
        // unconfigured avoids a silent bypass of those checks.
        let Some(lookup) = self.descriptor_lookup.as_ref() else {
            return Err(FrostNetError::Session(
                "Descriptor migrate cannot be processed without a configured descriptor lookup; refusing to bypass version/binding checks".into(),
            ));
        };
        {
            if !lookup.find_by_hash(&payload.group_pubkey, &payload.old_descriptor_hash) {
                return Err(FrostNetError::Session(
                    "Descriptor migrate old_descriptor_hash does not match any local descriptor"
                        .into(),
                ));
            }
            // Enforce monotonic version bump above whatever we currently have
            // persisted for this group. Equality is permitted only when the
            // persisted descriptor at that version is the exact one being
            // announced (already stored via DescriptorComplete, so this link
            // is just attaching `previous_descriptor_hash` lineage). Vault
            // failure fails closed.
            match lookup.latest_version_for(&payload.group_pubkey) {
                Ok(Some(current)) => {
                    if payload.new_version < current {
                        return Err(FrostNetError::Session(format!(
                            "Descriptor migrate new_version {} is below current {}",
                            payload.new_version, current
                        )));
                    }
                    if payload.new_version == current
                        && !lookup.find_by_hash(&payload.group_pubkey, &payload.new_descriptor_hash)
                    {
                        return Err(FrostNetError::Session(format!(
                            "Descriptor migrate new_version {} equals current but new_descriptor_hash does not match a persisted descriptor",
                            payload.new_version
                        )));
                    }
                    // Cap to the immediate next version: a migrate that
                    // skips intermediate versions would deny-of-future-
                    // migrations by jumping the counter forward. Receivers
                    // must process migrations one step at a time so the
                    // `previous_descriptor_hash` chain stays contiguous.
                    let max_allowed = current.saturating_add(1);
                    if payload.new_version > max_allowed {
                        return Err(FrostNetError::Session(format!(
                            "Descriptor migrate new_version {} exceeds current+1 ({})",
                            payload.new_version, max_allowed
                        )));
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    return Err(FrostNetError::Session(
                        "Descriptor migrate could not query persisted descriptors (vault unavailable); refusing to proceed".into(),
                    ));
                }
            }
        }

        // Record only after binding checks succeeded so a forged tuple
        // cannot suppress a legitimate future message. Use a single write
        // guard for the check-then-insert: dropping the read lock before
        // acquiring the write lock would let two concurrent handlers both
        // pass the earlier `contains_key` probe and both proceed.
        {
            let mut seen = self.seen_descriptor_migrates.write();
            let key = (payload.session_id, payload.new_descriptor_hash);
            if seen.contains_key(&key) {
                debug!(
                    session_id = %hex::encode(payload.session_id),
                    "Dropping duplicate descriptor migrate link (race on insert)"
                );
                return Ok(());
            }
            // Store local receive time, not attacker-supplied
            // `payload.created_at`, so eviction ordering and replay-window
            // pruning cannot be skewed by a peer backdating their links.
            let now = Timestamp::now().as_secs();
            seen.insert(key, now);
            const MAX_SEEN_DESCRIPTOR_MIGRATES: usize = 10_000;
            if seen.len() > MAX_SEEN_DESCRIPTOR_MIGRATES {
                let window = self
                    .replay_window_secs
                    .saturating_add(super::MAX_FUTURE_SKEW_SECS);
                seen.retain(|_, ts| now.saturating_sub(window) <= *ts);
                // If pruning by replay window still leaves the map oversized,
                // evict the oldest entries (by local receive time) rather
                // than clearing the whole set: a `clear()` would discard
                // every previously-seen tuple and re-enable replays of links
                // that were already observed within the replay window.
                if seen.len() > MAX_SEEN_DESCRIPTOR_MIGRATES {
                    let evict = seen.len() - MAX_SEEN_DESCRIPTOR_MIGRATES;
                    let mut by_ts: Vec<_> = seen.iter().map(|(k, v)| (*k, *v)).collect();
                    by_ts.sort_unstable_by_key(|&(_, ts)| ts);
                    for (k, _) in by_ts.into_iter().take(evict) {
                        seen.remove(&k);
                    }
                }
            }
        }

        info!(
            session_id = %hex::encode(payload.session_id),
            new_version = payload.new_version,
            "Received descriptor migrate link"
        );

        let _ = self.event_tx.send(KfpNodeEvent::DescriptorMigrateReceived {
            session_id: payload.session_id,
            group_pubkey: payload.group_pubkey,
            old_descriptor_hash: payload.old_descriptor_hash,
            new_descriptor_hash: payload.new_descriptor_hash,
            new_version: payload.new_version,
        });

        Ok(())
    }

    pub async fn request_descriptor_with_timeout(
        &self,
        policy: WalletPolicy,
        network: &str,
        own_xpub: &str,
        own_fingerprint: &str,
        timeout_secs: Option<u64>,
    ) -> Result<[u8; 32]> {
        if !VALID_NETWORKS.contains(&network) {
            return Err(FrostNetError::Session(format!(
                "Invalid network: {network}"
            )));
        }

        let our_index = self.share.metadata.identifier;

        self.check_proposer_authorized(our_index)?;

        let created_at = Timestamp::now().as_secs();
        let session_id = derive_descriptor_session_id(&self.group_pubkey, &policy, created_at);
        let expected_contributors = participant_indices(&policy);
        let we_are_contributor = expected_contributors.contains(&our_index);

        let expected_acks: HashSet<u16> = {
            let peers = self.peers.read();
            peers
                .get_online_peers()
                .iter()
                .filter(|p| self.can_send_to(&p.pubkey) && self.can_receive_from(&p.pubkey))
                .map(|p| p.share_index)
                .filter(|idx| *idx != our_index && expected_contributors.contains(idx))
                .collect()
        };

        let session_timeout = timeout_secs.map(std::time::Duration::from_secs);

        {
            let mut sessions = self.descriptor_sessions.write();
            let session = sessions.create_session_with_timeout(
                session_id,
                self.group_pubkey,
                policy.clone(),
                network.to_string(),
                expected_contributors,
                expected_acks,
                session_timeout,
            )?;
            session.set_initiator(self.keys.public_key());

            if we_are_contributor {
                if let Err(e) = session.add_contribution(
                    our_index,
                    own_xpub.to_string(),
                    own_fingerprint.to_string(),
                ) {
                    sessions.remove_session(&session_id);
                    return Err(e);
                }
            }
            sessions.persist_session(&session_id);
        }

        let mut payload = DescriptorProposePayload::new(
            session_id,
            self.group_pubkey,
            created_at,
            network,
            policy,
            own_xpub,
            own_fingerprint,
        );
        if let Some(t) = timeout_secs {
            payload = payload.with_timeout(t);
        }

        let msg = KfpMessage::DescriptorPropose(payload);
        let json = msg.to_json()?;

        let target_peers: Vec<PublicKey> = {
            let peers = self.peers.read();
            peers
                .get_online_peers()
                .iter()
                .filter(|p| self.can_send_to(&p.pubkey) && self.can_receive_from(&p.pubkey))
                .map(|p| p.pubkey)
                .collect()
        };

        if target_peers.is_empty() {
            self.descriptor_sessions.write().remove_session(&session_id);
            return Err(FrostNetError::Session(
                "No online peers to coordinate with".into(),
            ));
        }

        for pubkey in &target_peers {
            let encrypted =
                nip44::encrypt(self.keys.secret_key(), pubkey, &json, nip44::Version::V2)
                    .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

            let event = EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
                .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
                .tag(Tag::public_key(*pubkey))
                .tag(Tag::custom(
                    TagKind::custom("g"),
                    [hex::encode(self.group_pubkey)],
                ))
                .tag(Tag::custom(TagKind::custom("s"), [hex::encode(session_id)]))
                .tag(Tag::custom(TagKind::custom("t"), ["descriptor_propose"]))
                .sign_with_keys(&self.keys)
                .map_err(|e| FrostNetError::Nostr(e.to_string()))?;

            self.client
                .send_event(&event)
                .await
                .map_err(|e| FrostNetError::Transport(e.to_string()))?;
        }

        let _ = self
            .event_tx
            .send(KfpNodeEvent::DescriptorProposed { session_id });

        info!(session_id = %hex::encode(session_id), "Descriptor coordination started");
        Ok(session_id)
    }

    pub(crate) async fn handle_descriptor_propose(
        &self,
        sender: PublicKey,
        payload: DescriptorProposePayload,
    ) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        if !self.can_receive_from(&sender) {
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {sender} not allowed to send descriptor proposals"
            )));
        }

        if !payload.is_within_replay_window(self.replay_window_secs) {
            return Err(FrostNetError::ReplayDetected(
                "Descriptor proposal outside replay window".into(),
            ));
        }

        let expected_id = derive_descriptor_session_id(
            &payload.group_pubkey,
            &payload.policy,
            payload.created_at,
        );
        if payload.session_id != expected_id {
            return Err(FrostNetError::Session(
                "session_id does not match derived value".into(),
            ));
        }

        let sender_share_index = {
            let peers = self.peers.read();
            let peer = peers.get_peer_by_pubkey(&sender).ok_or_else(|| {
                FrostNetError::UntrustedPeer(format!(
                    "Descriptor proposal from unknown peer: {sender}"
                ))
            })?;
            peer.share_index
        };

        self.verify_peer_share_index(sender, sender_share_index)?;
        self.check_proposer_authorized(sender_share_index)?;

        info!(
            session_id = %hex::encode(payload.session_id),
            network = %payload.network,
            tiers = payload.policy.recovery_tiers.len(),
            "Received descriptor proposal"
        );

        let expected_contributors = participant_indices(&payload.policy);
        let our_index = self.share.metadata.identifier;
        let we_are_contributor = expected_contributors.contains(&our_index);

        let propose_timeout = match payload.timeout_secs {
            None => None,
            Some(t) if t > 0 && t <= DESCRIPTOR_SESSION_MAX_TIMEOUT_SECS => {
                Some(std::time::Duration::from_secs(t))
            }
            Some(t) => {
                return Err(FrostNetError::Session(format!(
                    "Invalid proposal timeout {t}s, must be 1..={DESCRIPTOR_SESSION_MAX_TIMEOUT_SECS}"
                )));
            }
        };

        let session_created = {
            let mut sessions = self.descriptor_sessions.write();
            match sessions.create_session_with_timeout(
                payload.session_id,
                self.group_pubkey,
                payload.policy.clone(),
                payload.network.clone(),
                expected_contributors,
                HashSet::new(),
                propose_timeout,
            ) {
                Ok(session) => {
                    session.set_initiator(sender);

                    if let Err(e) = session.add_contribution(
                        sender_share_index,
                        payload.initiator_xpub.clone(),
                        payload.initiator_fingerprint.clone(),
                    ) {
                        warn!("Failed to store initiator contribution: {e}");
                    }
                    sessions.persist_session(&payload.session_id);
                    true
                }
                Err(e) => {
                    debug!("Descriptor session creation failed: {e}");
                    false
                }
            }
        };

        if !session_created {
            return Ok(());
        }

        let _ = self.event_tx.send(KfpNodeEvent::DescriptorProposed {
            session_id: payload.session_id,
        });

        if !we_are_contributor {
            debug!("We are not a recovery key contributor in this policy");
            return Ok(());
        }

        let _ = self
            .event_tx
            .send(KfpNodeEvent::DescriptorContributionNeeded {
                session_id: payload.session_id,
                policy: payload.policy,
                network: payload.network,
                initiator_pubkey: sender,
            });

        Ok(())
    }

    pub fn derive_account_xpub(&self, network: &str) -> Result<(String, String)> {
        let signing_share_bytes = self.signing_share_bytes()?;
        let net = crate::descriptor_session::parse_network(network)?;

        let derivation = keep_bitcoin::AddressDerivation::new(&signing_share_bytes, net)
            .map_err(|e| FrostNetError::Crypto(format!("address derivation: {e}")))?;

        let xpub = derivation
            .account_xpub(0)
            .map_err(|e| FrostNetError::Crypto(format!("account xpub: {e}")))?;
        let fingerprint = derivation
            .master_fingerprint()
            .map_err(|e| FrostNetError::Crypto(format!("fingerprint: {e}")))?;

        Ok((xpub.to_string(), fingerprint.to_string()))
    }

    pub async fn contribute_descriptor(
        &self,
        session_id: [u8; 32],
        initiator_pubkey: &PublicKey,
        account_xpub: &str,
        fingerprint: &str,
    ) -> Result<()> {
        let our_index = self.share.metadata.identifier;

        {
            let mut sessions = self.descriptor_sessions.write();
            let session = sessions
                .get_session_mut(&session_id)
                .ok_or_else(|| FrostNetError::Session("unknown descriptor session".into()))?;
            session.add_contribution(
                our_index,
                account_xpub.to_string(),
                fingerprint.to_string(),
            )?;
            sessions.persist_session(&session_id);
        }

        let payload = DescriptorContributePayload::new(
            session_id,
            self.group_pubkey,
            our_index,
            account_xpub,
            fingerprint,
        );

        let msg = KfpMessage::DescriptorContribute(payload);
        let json = msg.to_json()?;

        let encrypted = nip44::encrypt(
            self.keys.secret_key(),
            initiator_pubkey,
            &json,
            nip44::Version::V2,
        )
        .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        let event = EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(*initiator_pubkey))
            .tag(Tag::custom(
                TagKind::custom("g"),
                [hex::encode(self.group_pubkey)],
            ))
            .tag(Tag::custom(TagKind::custom("s"), [hex::encode(session_id)]))
            .tag(Tag::custom(TagKind::custom("t"), ["descriptor_contribute"]))
            .sign_with_keys(&self.keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))?;

        self.client
            .send_event(&event)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        info!(session_id = %hex::encode(session_id), "Sent descriptor contribution");
        Ok(())
    }

    pub(crate) async fn handle_descriptor_contribute(
        &self,
        sender: PublicKey,
        payload: DescriptorContributePayload,
    ) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        if !self.can_receive_from(&sender) {
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {sender} not allowed to send descriptor contributions"
            )));
        }

        if !payload.is_within_replay_window(self.replay_window_secs) {
            return Err(FrostNetError::ReplayDetected(
                "Descriptor contribution outside replay window".into(),
            ));
        }

        self.verify_peer_share_index(sender, payload.share_index)?;

        info!(
            session_id = %hex::encode(payload.session_id),
            share_index = payload.share_index,
            "Received descriptor contribution"
        );

        let all_contributions = {
            let mut sessions = self.descriptor_sessions.write();
            let session = sessions
                .get_session_mut(&payload.session_id)
                .ok_or_else(|| FrostNetError::Session("unknown descriptor session".into()))?;

            session.add_contribution(
                payload.share_index,
                payload.account_xpub,
                payload.fingerprint,
            )?;

            let _ = self.event_tx.send(KfpNodeEvent::DescriptorContributed {
                session_id: payload.session_id,
                share_index: payload.share_index,
            });

            let all = session.has_all_contributions();
            sessions.persist_session(&payload.session_id);
            all
        };

        if all_contributions {
            let _ = self.event_tx.send(KfpNodeEvent::DescriptorReady {
                session_id: payload.session_id,
            });
        }

        Ok(())
    }

    pub async fn finalize_descriptor(
        &self,
        session_id: [u8; 32],
        external_descriptor: &str,
        internal_descriptor: &str,
        policy_hash: [u8; 32],
    ) -> Result<()> {
        let contributions = {
            let mut sessions = self.descriptor_sessions.write();
            let session = sessions
                .get_session_mut(&session_id)
                .ok_or_else(|| FrostNetError::Session("unknown descriptor session".into()))?;

            session.set_finalized(FinalizedDescriptor {
                external: external_descriptor.to_string(),
                internal: internal_descriptor.to_string(),
                policy_hash,
            })?;

            let contribs = session.contributions().clone();
            sessions.persist_session(&session_id);
            contribs
        };

        let payload = DescriptorFinalizePayload::new(
            session_id,
            self.group_pubkey,
            external_descriptor,
            internal_descriptor,
            policy_hash,
            contributions,
        );

        let msg = KfpMessage::DescriptorFinalize(payload);
        let json = msg.to_json()?;

        let target_peers: Vec<PublicKey> = {
            let peers = self.peers.read();
            peers
                .get_online_peers()
                .iter()
                .filter(|p| self.can_send_to(&p.pubkey) && self.can_receive_from(&p.pubkey))
                .map(|p| p.pubkey)
                .collect()
        };

        if target_peers.is_empty() {
            self.descriptor_sessions.write().remove_session(&session_id);
            return Err(FrostNetError::Session(
                "No online peers to send finalize to".into(),
            ));
        }

        for pubkey in &target_peers {
            let encrypted =
                nip44::encrypt(self.keys.secret_key(), pubkey, &json, nip44::Version::V2)
                    .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

            let event = EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
                .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
                .tag(Tag::public_key(*pubkey))
                .tag(Tag::custom(
                    TagKind::custom("g"),
                    [hex::encode(self.group_pubkey)],
                ))
                .tag(Tag::custom(TagKind::custom("s"), [hex::encode(session_id)]))
                .tag(Tag::custom(TagKind::custom("t"), ["descriptor_finalize"]))
                .sign_with_keys(&self.keys)
                .map_err(|e| FrostNetError::Nostr(e.to_string()))?;

            self.client
                .send_event(&event)
                .await
                .map_err(|e| FrostNetError::Transport(e.to_string()))?;
        }

        info!(session_id = %hex::encode(session_id), "Sent finalized descriptor");
        Ok(())
    }

    pub(crate) async fn handle_descriptor_finalize(
        &self,
        sender: PublicKey,
        payload: DescriptorFinalizePayload,
    ) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        if !self.can_receive_from(&sender) {
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {sender} not allowed to send descriptor finalizations"
            )));
        }

        if !payload.is_within_replay_window(self.replay_window_secs) {
            return Err(FrostNetError::ReplayDetected(
                "Descriptor finalize outside replay window".into(),
            ));
        }

        for (name, desc) in [
            ("External", &payload.external_descriptor),
            ("Internal", &payload.internal_descriptor),
        ] {
            if desc.len() > MAX_DESCRIPTOR_LENGTH {
                return Err(FrostNetError::Session(format!(
                    "{name} descriptor exceeds maximum length"
                )));
            }
        }

        let sender_share_index = {
            let peers = self.peers.read();
            let peer = peers
                .get_peer_by_pubkey(&sender)
                .ok_or_else(|| FrostNetError::UntrustedPeer(sender.to_string()))?;
            peer.share_index
        };

        self.check_proposer_authorized(sender_share_index)?;

        let our_index = self.share.metadata.identifier;

        let (
            reconstruction_result,
            session_network,
            our_xpub,
            session_policy_version,
            session_policy,
        ) = {
            let sessions = self.descriptor_sessions.read();
            let session = sessions
                .get_session(&payload.session_id)
                .ok_or_else(|| FrostNetError::Session("unknown descriptor session".into()))?;

            let network = session.network().to_string();
            let policy_version = session.policy().version;
            let policy = session.policy().clone();

            let initiator = session.initiator().ok_or_else(|| {
                let _ = self.event_tx.send(KfpNodeEvent::DescriptorFailed {
                    session_id: payload.session_id,
                    error: "Missing initiator".into(),
                });
                FrostNetError::Session("DescriptorFinalize missing session initiator".into())
            })?;
            if *initiator != sender {
                return Err(FrostNetError::Session(
                    "DescriptorFinalize sender is not the session initiator".into(),
                ));
            }

            let own_xpub_tampered = match session.contributions().get(&our_index) {
                Some(our_stored) => {
                    let forwarded = payload.contributions.get(&our_index);
                    !matches!(forwarded, Some(fwd)
                        if fwd.account_xpub == our_stored.account_xpub
                            && fwd.fingerprint == our_stored.fingerprint)
                }
                None => session.is_participant(our_index),
            };

            let our_xpub = session
                .contributions()
                .get(&our_index)
                .map(|c| c.account_xpub.clone());

            let result = if own_xpub_tampered {
                Err("Own xpub contribution was tampered with in finalize".into())
            } else if payload.policy_hash != derive_policy_hash(session.policy()) {
                Err("Policy hash does not match proposal".into())
            } else {
                reconstruct_descriptor(
                    session.group_pubkey(),
                    session.policy(),
                    &payload.contributions,
                    session.network(),
                )
                .map_err(|e| format!("Descriptor reconstruction failed: {e}"))
            };
            (result, network, our_xpub, policy_version, policy)
        };

        let (expected_external, expected_internal) = match reconstruction_result {
            Ok(result) => result,
            Err(reason) => {
                self.descriptor_sessions
                    .write()
                    .remove_session(&payload.session_id);
                self.send_descriptor_nack(payload.session_id, &sender, &reason)
                    .await;
                let _ = self.event_tx.send(KfpNodeEvent::DescriptorFailed {
                    session_id: payload.session_id,
                    error: reason.clone(),
                });
                return Err(FrostNetError::Session(reason));
            }
        };

        if payload.external_descriptor != expected_external
            || payload.internal_descriptor != expected_internal
        {
            let reason = "Descriptor mismatch: independent reconstruction differs";
            self.descriptor_sessions
                .write()
                .remove_session(&payload.session_id);
            self.send_descriptor_nack(payload.session_id, &sender, reason)
                .await;
            let _ = self.event_tx.send(KfpNodeEvent::DescriptorFailed {
                session_id: payload.session_id,
                error: reason.into(),
            });
            return Err(FrostNetError::Session(reason.into()));
        }

        info!(
            session_id = %hex::encode(payload.session_id),
            "Received finalized descriptor"
        );

        // We captured `session_policy_version` under the earlier session read
        // so an eviction between reads cannot silently regress to the v1
        // formula and produce a mismatch.
        let descriptor_hash = keep_core::wallet::canonical_descriptor_hash(
            &payload.external_descriptor,
            &payload.internal_descriptor,
            &payload.policy_hash,
            session_policy_version,
        )
        .map_err(|e| FrostNetError::Session(e.to_string()))?;

        // #423: only contributing peers need to prove ownership of an xpub and
        // ACK; peers not selected as contributors (`our_xpub == None`) have no
        // xpub to prove and the proposer's `expected_acks` already excludes
        // them (see `cmd_frost_network_propose_descriptor`'s contributor-filtered
        // expected_acks construction). Without this gate, the excluded peer
        // tried to build a key-proof, failed with "Missing own xpub
        // contribution for key proof", sent a NACK, removed its session, and
        // surfaced a `DescriptorFailed` event — even though the proposer's view
        // was successful. Now: skip the ACK round entirely when we're not a
        // contributor and proceed straight to local finalization.
        let we_are_contributor = our_xpub.is_some();
        if we_are_contributor {
            let key_proof_psbt_bytes = match self.build_key_proof(
                &payload.session_id,
                our_index,
                our_xpub.as_deref(),
                &session_network,
            ) {
                Ok(bytes) => bytes,
                Err(e) => {
                    let reason = format!("Key proof failed: {e}");
                    self.descriptor_sessions
                        .write()
                        .remove_session(&payload.session_id);
                    self.send_descriptor_nack(payload.session_id, &sender, &reason)
                        .await;
                    let _ = self.event_tx.send(KfpNodeEvent::DescriptorFailed {
                        session_id: payload.session_id,
                        error: reason.clone(),
                    });
                    return Err(FrostNetError::Session(reason));
                }
            };

            let ack = DescriptorAckPayload::new(
                payload.session_id,
                self.group_pubkey,
                descriptor_hash,
                key_proof_psbt_bytes,
            );
            let msg = KfpMessage::DescriptorAck(ack);
            let json = msg.to_json()?;

            let encrypted =
                nip44::encrypt(self.keys.secret_key(), &sender, &json, nip44::Version::V2)
                    .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

            let event = EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
                .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
                .tag(Tag::public_key(sender))
                .tag(Tag::custom(
                    TagKind::custom("g"),
                    [hex::encode(self.group_pubkey)],
                ))
                .tag(Tag::custom(
                    TagKind::custom("s"),
                    [hex::encode(payload.session_id)],
                ))
                .tag(Tag::custom(TagKind::custom("t"), ["descriptor_ack"]))
                .sign_with_keys(&self.keys)
                .map_err(|e| FrostNetError::Nostr(e.to_string()))?;

            self.client
                .send_event(&event)
                .await
                .map_err(|e| FrostNetError::Transport(e.to_string()))?;
        } else {
            let _ = descriptor_hash; // silence unused-variable warning when no ACK is sent
            debug!(
                session_id = %hex::encode(payload.session_id),
                our_index,
                "not a contributor for this tier; skipping key-proof and ACK"
            );
        }

        {
            let mut sessions = self.descriptor_sessions.write();
            let Some(session) = sessions.get_session_mut(&payload.session_id) else {
                return Err(FrostNetError::Session(
                    "Session not found for finalize".into(),
                ));
            };

            for (idx, contrib) in &payload.contributions {
                if !session.contributions().contains_key(idx) {
                    session
                        .add_contribution(
                            *idx,
                            contrib.account_xpub.clone(),
                            contrib.fingerprint.clone(),
                        )
                        .map_err(|e| {
                            FrostNetError::Session(format!(
                                "Failed to add contribution for share {idx}: {e}"
                            ))
                        })?;
                }
            }

            session.set_finalized(FinalizedDescriptor {
                external: payload.external_descriptor.clone(),
                internal: payload.internal_descriptor.clone(),
                policy_hash: payload.policy_hash,
            })?;
            sessions.persist_session(&payload.session_id);
        }

        let _ = self.event_tx.send(KfpNodeEvent::DescriptorComplete {
            session_id: payload.session_id,
            external_descriptor: payload.external_descriptor,
            internal_descriptor: payload.internal_descriptor,
            network: session_network,
            policy_hash: payload.policy_hash,
            version: session_policy_version,
            policy: session_policy,
        });

        Ok(())
    }

    async fn send_descriptor_nack(
        &self,
        session_id: [u8; 32],
        recipient: &PublicKey,
        reason: &str,
    ) {
        let nack = DescriptorNackPayload::new(session_id, self.group_pubkey, reason);
        let msg = KfpMessage::DescriptorNack(nack);
        let json = match msg.to_json() {
            Ok(j) => j,
            Err(e) => {
                debug!("Failed to serialize descriptor nack: {e}");
                return;
            }
        };

        let encrypted =
            match nip44::encrypt(self.keys.secret_key(), recipient, &json, nip44::Version::V2) {
                Ok(e) => e,
                Err(e) => {
                    debug!("Failed to encrypt descriptor nack: {e}");
                    return;
                }
            };

        let event = match EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(*recipient))
            .tag(Tag::custom(
                TagKind::custom("g"),
                [hex::encode(self.group_pubkey)],
            ))
            .tag(Tag::custom(TagKind::custom("s"), [hex::encode(session_id)]))
            .tag(Tag::custom(TagKind::custom("t"), ["descriptor_nack"]))
            .sign_with_keys(&self.keys)
        {
            Ok(e) => e,
            Err(e) => {
                debug!("Failed to sign descriptor nack: {e}");
                return;
            }
        };

        if let Err(e) = self.client.send_event(&event).await {
            debug!("Failed to send descriptor nack: {e}");
        }
    }

    pub(crate) async fn handle_descriptor_nack(
        &self,
        sender: PublicKey,
        payload: DescriptorNackPayload,
    ) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        if !self.can_receive_from(&sender) {
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {sender} not allowed to send descriptor nacks"
            )));
        }

        if !payload.is_within_replay_window(self.replay_window_secs) {
            return Err(FrostNetError::ReplayDetected(
                "Descriptor NACK outside replay window".into(),
            ));
        }

        let share_index = {
            let peers = self.peers.read();
            peers
                .get_peer_by_pubkey(&sender)
                .map(|p| p.share_index)
                .ok_or_else(|| FrostNetError::UntrustedPeer(sender.to_string()))?
        };

        let reason = sanitize_reason(&payload.reason);

        let mut sessions = self.descriptor_sessions.write();
        let Some(session) = sessions.get_session_mut(&payload.session_id) else {
            return Ok(());
        };

        if !session.is_participant(share_index) {
            return Err(FrostNetError::Session(format!(
                "Share {share_index} is not a session participant"
            )));
        }

        if session.is_complete() || session.has_nacked(share_index) {
            return Ok(());
        }

        session.add_nack(share_index);

        if !session.is_failed() {
            session.fail(format!("Peer {share_index} rejected descriptor: {reason}"));
        }

        sessions.persist_session(&payload.session_id);
        drop(sessions);

        info!(
            session_id = %hex::encode(payload.session_id),
            share_index,
            reason = %reason,
            "Received descriptor NACK"
        );

        let _ = self.event_tx.send(KfpNodeEvent::DescriptorNacked {
            session_id: payload.session_id,
            share_index,
            reason,
        });

        Ok(())
    }

    pub(crate) async fn handle_descriptor_ack(
        &self,
        sender: PublicKey,
        payload: DescriptorAckPayload,
    ) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        if !self.can_receive_from(&sender) {
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {sender} not allowed to send descriptor acks"
            )));
        }

        if !payload.is_within_replay_window(self.replay_window_secs) {
            return Err(FrostNetError::ReplayDetected(
                "Descriptor ACK outside replay window".into(),
            ));
        }

        let share_index = {
            let peers = self.peers.read();
            peers
                .get_peer_by_pubkey(&sender)
                .map(|p| p.share_index)
                .ok_or_else(|| FrostNetError::UntrustedPeer(sender.to_string()))?
        };

        let (is_new, is_complete, ack_count, expected_acks) = {
            let mut sessions = self.descriptor_sessions.write();
            let session = sessions
                .get_session_mut(&payload.session_id)
                .ok_or_else(|| FrostNetError::Session("unknown descriptor session".into()))?;

            let is_new = session.add_ack(
                share_index,
                payload.descriptor_hash,
                &payload.key_proof_psbt,
            )?;
            let result = (
                is_new,
                session.is_complete(),
                session.ack_count(),
                session.expected_ack_count(),
            );
            sessions.persist_session(&payload.session_id);
            result
        };

        info!(
            session_id = %hex::encode(payload.session_id),
            share_index,
            ack_count,
            expected_acks,
            complete = is_complete,
            "Received descriptor ACK"
        );

        if is_new {
            let _ = self.event_tx.send(KfpNodeEvent::DescriptorAcked {
                session_id: payload.session_id,
                share_index,
                ack_count,
                expected_acks,
            });
        }

        if is_new && is_complete {
            let sessions = self.descriptor_sessions.read();
            if let Some(session) = sessions.get_session(&payload.session_id) {
                if let Some(desc) = session.descriptor() {
                    let _ = self.event_tx.send(KfpNodeEvent::DescriptorComplete {
                        session_id: payload.session_id,
                        external_descriptor: desc.external.clone(),
                        internal_descriptor: desc.internal.clone(),
                        network: session.network().to_string(),
                        policy_hash: desc.policy_hash,
                        version: session.policy().version,
                        policy: session.policy().clone(),
                    });
                }
            }
        }

        Ok(())
    }

    pub async fn build_and_finalize_descriptor(&self, session_id: [u8; 32]) -> Result<usize> {
        let (external, internal, policy_hash, expected_acks) = {
            let sessions = self.descriptor_sessions.read();
            let session = sessions
                .get_session(&session_id)
                .ok_or_else(|| FrostNetError::Session("unknown descriptor session".into()))?;

            let policy_hash = derive_policy_hash(session.policy());
            let expected_acks = session.expected_ack_count();
            let (external, internal) = reconstruct_descriptor(
                session.group_pubkey(),
                session.policy(),
                session.contributions(),
                session.network(),
            )?;
            (external, internal, policy_hash, expected_acks)
        };

        self.finalize_descriptor(session_id, &external, &internal, policy_hash)
            .await?;
        Ok(expected_acks)
    }

    pub fn cancel_descriptor_session(&self, session_id: &[u8; 32]) {
        self.descriptor_sessions.write().remove_session(session_id);
    }

    pub(crate) async fn handle_xpub_announce(
        &self,
        sender: PublicKey,
        payload: XpubAnnouncePayload,
    ) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        if !self.can_receive_from(&sender) {
            return Err(FrostNetError::PolicyViolation(format!(
                "Peer {sender} not allowed to announce recovery xpubs"
            )));
        }

        if !payload.is_within_replay_window(self.replay_window_secs) {
            return Err(FrostNetError::ReplayDetected(
                "XpubAnnounce timestamp outside replay window".into(),
            ));
        }

        self.verify_peer_share_index(sender, payload.share_index)?;

        {
            let mut hasher = Sha256::new();
            for xpub in &payload.recovery_xpubs {
                hasher.update(xpub.xpub.as_bytes());
                hasher.update(xpub.fingerprint.as_bytes());
                if let Some(ref label) = xpub.label {
                    hasher.update(label.as_bytes());
                }
            }
            let digest: [u8; 32] = hasher.finalize().into();
            let dedup_key = (payload.share_index, payload.created_at, digest);
            let mut seen = self.seen_xpub_announces.write();
            if !seen.insert(dedup_key) {
                return Ok(());
            }
            const MAX_SEEN_XPUB_ANNOUNCES: usize = 10_000;
            if seen.len() > MAX_SEEN_XPUB_ANNOUNCES {
                let now = Timestamp::now().as_secs();
                let window = self
                    .replay_window_secs
                    .saturating_add(super::MAX_FUTURE_SKEW_SECS);
                seen.retain(|&(_, ts, _)| now.saturating_sub(window) <= ts);
                if seen.len() > MAX_SEEN_XPUB_ANNOUNCES {
                    seen.clear();
                    seen.insert(dedup_key);
                }
            }
        }

        {
            let mut peers = self.peers.write();
            let Some(peer) = peers.get_peer_mut(payload.share_index) else {
                return Ok(());
            };
            peer.touch();
            peer.set_recovery_xpubs(payload.recovery_xpubs.clone());
        }

        info!(
            share_index = payload.share_index,
            xpub_count = payload.recovery_xpubs.len(),
            "Received recovery xpub announcement"
        );

        let _ = self.event_tx.send(KfpNodeEvent::XpubAnnounced {
            share_index: payload.share_index,
            recovery_xpubs: payload.recovery_xpubs,
        });

        Ok(())
    }

    fn check_proposer_authorized(&self, share_index: u16) -> Result<()> {
        let proposers = self.descriptor_proposers.read();
        if !proposers.is_empty() && !proposers.contains(&share_index) {
            return Err(FrostNetError::Session(format!(
                "Share {share_index} is not authorized to propose descriptors"
            )));
        }
        Ok(())
    }

    fn build_key_proof(
        &self,
        session_id: &[u8; 32],
        share_index: u16,
        xpub: Option<&str>,
        network_str: &str,
    ) -> Result<Vec<u8>> {
        let xpub = xpub.ok_or_else(|| {
            FrostNetError::Session("Missing own xpub contribution for key proof".into())
        })?;
        let net = crate::descriptor_session::parse_network(network_str)?;
        let signing_share_bytes = self.signing_share_bytes()?;
        let mut proof_psbt = keep_bitcoin::build_key_proof_psbt(session_id, share_index, xpub, net)
            .map_err(|e| FrostNetError::Crypto(format!("key proof build: {e}")))?;
        keep_bitcoin::sign_key_proof(&mut proof_psbt, &signing_share_bytes, net)
            .map_err(|e| FrostNetError::Crypto(format!("key proof sign: {e}")))
    }

    fn signing_share_bytes(&self) -> Result<Zeroizing<[u8; 32]>> {
        let key_package = self
            .share
            .key_package()
            .map_err(|e| FrostNetError::Crypto(format!("key package: {e}")))?;
        let signing_share = key_package.signing_share();
        let serialized = Zeroizing::new(signing_share.serialize());
        let bytes = <[u8; 32]>::try_from(serialized.as_slice())
            .map_err(|_| FrostNetError::Crypto("Invalid signing share length".into()))?;
        Ok(Zeroizing::new(bytes))
    }
}
