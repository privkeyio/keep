// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::HashSet;

use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::descriptor_session::{derive_descriptor_session_id, FinalizedDescriptor};
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
        let created_at = chrono::Utc::now().timestamp() as u64;
        let session_id = derive_descriptor_session_id(&self.group_pubkey, &policy, created_at);

        let our_index = self.share.metadata.identifier;

        let expected_contributors: HashSet<u16> = policy
            .recovery_tiers
            .iter()
            .flat_map(|t| t.key_slots.iter())
            .filter_map(|s| match s {
                KeySlot::Participant { share_index } => Some(*share_index),
                _ => None,
            })
            .collect();

        let expected_acks: HashSet<u16> = {
            let peers = self.peers.read();
            peers
                .get_online_peers()
                .iter()
                .map(|p| p.share_index)
                .collect()
        };

        {
            let mut sessions = self.descriptor_sessions.write();
            sessions.create_session(
                session_id,
                self.group_pubkey,
                policy.clone(),
                network.to_string(),
                expected_contributors,
                expected_acks,
            )?;
        }

        let we_are_contributor = policy
            .recovery_tiers
            .iter()
            .flat_map(|t| t.key_slots.iter())
            .any(
                |s| matches!(s, KeySlot::Participant { share_index } if *share_index == our_index),
            );

        if we_are_contributor {
            let mut sessions = self.descriptor_sessions.write();
            if let Some(session) = sessions.get_session_mut(&session_id) {
                session.add_contribution(
                    our_index,
                    own_xpub.to_string(),
                    own_fingerprint.to_string(),
                )?;
            }
        }

        let payload = DescriptorProposePayload::new(
            session_id,
            self.group_pubkey,
            network,
            policy,
            own_xpub,
            own_fingerprint,
        );

        let msg = KfpMessage::DescriptorPropose(payload);
        let json = msg.to_json()?;

        let peers = self.peers.read();
        for peer in peers.get_online_peers() {
            if self.can_receive_from(&peer.pubkey) {
                let encrypted = nip44::encrypt(
                    self.keys.secret_key(),
                    &peer.pubkey,
                    &json,
                    nip44::Version::V2,
                )
                .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

                let event = EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
                    .tag(Tag::public_key(peer.pubkey))
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
        }

        let _ = self
            .event_tx
            .send(KfpNodeEvent::DescriptorProposed { session_id });

        info!(session_id = %hex::encode(session_id), "Descriptor coordination started");
        Ok(session_id)
    }

    pub(crate) async fn handle_descriptor_propose(
        &self,
        _sender: PublicKey,
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

        info!(
            session_id = %hex::encode(payload.session_id),
            network = %payload.network,
            tiers = payload.policy.recovery_tiers.len(),
            "Received descriptor proposal"
        );

        let _ = self.event_tx.send(KfpNodeEvent::DescriptorProposed {
            session_id: payload.session_id,
        });

        let our_index = self.share.metadata.identifier;
        let we_are_contributor = payload
            .policy
            .recovery_tiers
            .iter()
            .flat_map(|t| t.key_slots.iter())
            .any(
                |s| matches!(s, KeySlot::Participant { share_index } if *share_index == our_index),
            );

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
            });

        Ok(())
    }

    pub async fn contribute_descriptor(
        &self,
        session_id: [u8; 32],
        initiator_pubkey: &PublicKey,
        account_xpub: &str,
        fingerprint: &str,
    ) -> Result<()> {
        let payload = DescriptorContributePayload::new(
            session_id,
            self.group_pubkey,
            self.share.metadata.identifier,
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
        _sender: PublicKey,
        payload: DescriptorContributePayload,
    ) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        info!(
            session_id = %hex::encode(payload.session_id),
            share_index = payload.share_index,
            "Received descriptor contribution"
        );

        let all_contributions;
        {
            let mut sessions = self.descriptor_sessions.write();
            let session = sessions
                .get_session_mut(&payload.session_id)
                .ok_or_else(|| FrostNetError::Session("unknown descriptor session".into()))?;

            session.add_contribution(
                payload.share_index,
                payload.account_xpub,
                payload.fingerprint,
            )?;

            all_contributions = session.has_all_contributions();

            let _ = self.event_tx.send(KfpNodeEvent::DescriptorContributed {
                session_id: payload.session_id,
                share_index: payload.share_index,
            });
        }

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
        {
            let mut sessions = self.descriptor_sessions.write();
            let session = sessions
                .get_session_mut(&session_id)
                .ok_or_else(|| FrostNetError::Session("unknown descriptor session".into()))?;

            session.set_finalized(FinalizedDescriptor {
                external: external_descriptor.to_string(),
                internal: internal_descriptor.to_string(),
                policy_hash,
            })?;
        }

        let payload = DescriptorFinalizePayload::new(
            session_id,
            self.group_pubkey,
            external_descriptor,
            internal_descriptor,
            policy_hash,
        );

        let msg = KfpMessage::DescriptorFinalize(payload);
        let json = msg.to_json()?;

        let peers = self.peers.read();
        for peer in peers.get_online_peers() {
            if self.can_receive_from(&peer.pubkey) {
                let encrypted = nip44::encrypt(
                    self.keys.secret_key(),
                    &peer.pubkey,
                    &json,
                    nip44::Version::V2,
                )
                .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

                let event = EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
                    .tag(Tag::public_key(peer.pubkey))
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

        info!(
            session_id = %hex::encode(payload.session_id),
            "Received finalized descriptor"
        );

        let descriptor_hash: [u8; 32] =
            Sha256::digest(payload.external_descriptor.as_bytes()).into();

        let ack = DescriptorAckPayload::new(payload.session_id, self.group_pubkey, descriptor_hash);
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

        self.client
            .send_event(&event)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        let _ = self.event_tx.send(KfpNodeEvent::DescriptorComplete {
            session_id: payload.session_id,
            external_descriptor: payload.external_descriptor,
            internal_descriptor: payload.internal_descriptor,
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

        let share_index = {
            let peers = self.peers.read();
            peers
                .get_peer_by_pubkey(&sender)
                .map(|p| p.share_index)
                .ok_or_else(|| FrostNetError::UntrustedPeer(sender.to_string()))?
        };

        let is_complete;
        {
            let mut sessions = self.descriptor_sessions.write();
            let session = sessions
                .get_session_mut(&payload.session_id)
                .ok_or_else(|| FrostNetError::Session("unknown descriptor session".into()))?;

            session.add_ack(share_index, payload.descriptor_hash)?;
            is_complete = session.is_complete();
        }

        info!(
            session_id = %hex::encode(payload.session_id),
            share_index,
            complete = is_complete,
            "Received descriptor ACK"
        );

        if is_complete {
            let sessions = self.descriptor_sessions.read();
            if let Some(session) = sessions.get_session(&payload.session_id) {
                if let Some(desc) = session.descriptor() {
                    let _ = self.event_tx.send(KfpNodeEvent::DescriptorComplete {
                        session_id: payload.session_id,
                        external_descriptor: desc.external.clone(),
                        internal_descriptor: desc.internal.clone(),
                    });
                }
            }
        }

        Ok(())
    }
}
