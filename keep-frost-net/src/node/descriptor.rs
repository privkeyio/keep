// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::HashSet;

use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use tracing::{debug, info};
use zeroize::Zeroizing;

use crate::descriptor_session::{
    derive_descriptor_session_id, derive_policy_hash, participant_indices, reconstruct_descriptor,
    FinalizedDescriptor,
};
use crate::error::{FrostNetError, Result};
use crate::protocol::*;

use super::{KfpNode, KfpNodeEvent};

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

        let created_at = chrono::Utc::now().timestamp().max(0) as u64;
        let session_id = derive_descriptor_session_id(&self.group_pubkey, &policy, created_at);
        let expected_contributors = participant_indices(&policy);
        let we_are_contributor = expected_contributors.contains(&our_index);

        let expected_acks: HashSet<u16> = {
            let peers = self.peers.read();
            peers
                .get_online_peers()
                .iter()
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
                .filter(|p| self.can_receive_from(&p.pubkey))
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
                        debug!("Failed to store initiator contribution: {e}");
                    }
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

            session.has_all_contributions()
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

            session.contributions().clone()
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
                .filter(|p| self.can_receive_from(&p.pubkey))
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

        let (reconstruction_result, session_network, our_xpub) = {
            let sessions = self.descriptor_sessions.read();
            let session = sessions
                .get_session(&payload.session_id)
                .ok_or_else(|| FrostNetError::Session("unknown descriptor session".into()))?;

            let network = session.network().to_string();

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
            (result, network, our_xpub)
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

        let descriptor_hash: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(payload.external_descriptor.as_bytes());
            hasher.update(payload.internal_descriptor.as_bytes());
            hasher.update(payload.policy_hash);
            hasher.finalize().into()
        };

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

        let encrypted = nip44::encrypt(self.keys.secret_key(), &sender, &json, nip44::Version::V2)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        let event = EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
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

        {
            let mut sessions = self.descriptor_sessions.write();
            let Some(session) = sessions.get_session_mut(&payload.session_id) else {
                return Err(FrostNetError::Session(
                    "Session not found for finalize".into(),
                ));
            };
            session.set_finalized(FinalizedDescriptor {
                external: payload.external_descriptor.clone(),
                internal: payload.internal_descriptor.clone(),
                policy_hash: payload.policy_hash,
            })?;
        }

        self.client
            .send_event(&event)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        let _ = self.event_tx.send(KfpNodeEvent::DescriptorComplete {
            session_id: payload.session_id,
            external_descriptor: payload.external_descriptor,
            internal_descriptor: payload.internal_descriptor,
            network: session_network,
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
            (
                is_new,
                session.is_complete(),
                session.ack_count(),
                session.expected_ack_count(),
            )
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

        if is_complete {
            let sessions = self.descriptor_sessions.read();
            if let Some(session) = sessions.get_session(&payload.session_id) {
                if let Some(desc) = session.descriptor() {
                    let _ = self.event_tx.send(KfpNodeEvent::DescriptorComplete {
                        session_id: payload.session_id,
                        external_descriptor: desc.external.clone(),
                        internal_descriptor: desc.internal.clone(),
                        network: session.network().to_string(),
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
                let now = chrono::Utc::now().timestamp().max(0) as u64;
                let window = self.replay_window_secs + super::MAX_FUTURE_SKEW_SECS;
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
