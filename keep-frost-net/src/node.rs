// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use frost_secp256k1_tr::rand_core::OsRng;
use nostr_sdk::prelude::*;
use parking_lot::RwLock;
use rand_09::seq::IndexedRandom;
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, mpsc, Mutex as TokioMutex};
use tracing::{debug, error, info, warn};

use keep_core::frost::SharePackage;

use crate::attestation::{verify_peer_attestation, ExpectedPcrs};
use crate::audit::{SigningAuditLog, SigningOperation};
use crate::ecdh::{compute_partial_ecdh, derive_ecdh_session_id, EcdhSessionManager};
use crate::error::{FrostNetError, Result};
use crate::event::KfpEventBuilder;
use crate::nonce_store::{FileNonceStore, NonceStore};
use crate::peer::{AttestationStatus, Peer, PeerManager, PeerStatus};
use crate::protocol::*;
use crate::session::{derive_session_id, NetworkSession, SessionManager};

#[derive(Clone, Debug)]
pub struct PeerPolicy {
    pub pubkey: PublicKey,
    pub allow_send: bool,
    pub allow_receive: bool,
}

impl PeerPolicy {
    pub fn new(pubkey: PublicKey) -> Self {
        Self {
            pubkey,
            allow_send: true,
            allow_receive: true,
        }
    }

    pub fn allow_send(mut self, allow: bool) -> Self {
        self.allow_send = allow;
        self
    }

    pub fn allow_receive(mut self, allow: bool) -> Self {
        self.allow_receive = allow;
        self
    }
}

#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub session_id: [u8; 32],
    pub message: Vec<u8>,
    pub threshold: u16,
    pub participants: Vec<u16>,
}

impl From<&NetworkSession> for SessionInfo {
    fn from(session: &NetworkSession) -> Self {
        Self {
            session_id: *session.session_id(),
            message: session.message().to_vec(),
            threshold: session.threshold(),
            participants: session.participants().to_vec(),
        }
    }
}

/// Hooks for observing and controlling the signing process.
///
/// Implementations should be non-blocking and return quickly to avoid
/// delaying the signing protocol. To prevent deadlocks, hook implementations
/// must not call `KfpNode::set_hooks` from within a hook.
pub trait SigningHooks: Send + Sync {
    /// Called before a node participates in a signing session.
    ///
    /// Returning an `Err` will abort the signing session.
    fn pre_sign(&self, session: &SessionInfo) -> Result<()>;

    /// Called after a signature has been successfully generated.
    ///
    /// This is for notification purposes and cannot fail. Long-running
    /// operations should be offloaded to a separate task.
    fn post_sign(&self, session: &SessionInfo, signature: &[u8; 64]);
}

pub struct NoOpHooks;

impl SigningHooks for NoOpHooks {
    fn pre_sign(&self, _session: &SessionInfo) -> Result<()> {
        Ok(())
    }
    fn post_sign(&self, _session: &SessionInfo, _signature: &[u8; 64]) {}
}

/// Maximum age for announcement timestamps (5 minutes)
pub(crate) const ANNOUNCE_MAX_AGE_SECS: u64 = 300;
/// Maximum clock skew tolerance for future timestamps (30 seconds)
pub(crate) const ANNOUNCE_MAX_FUTURE_SECS: u64 = 30;

#[derive(Clone, Debug)]
pub enum KfpNodeEvent {
    PeerDiscovered {
        share_index: u16,
        name: Option<String>,
    },
    PeerOffline {
        share_index: u16,
    },
    SigningStarted {
        session_id: [u8; 32],
    },
    SignatureComplete {
        session_id: [u8; 32],
        signature: [u8; 64],
    },
    SigningFailed {
        session_id: [u8; 32],
        error: String,
    },
    EcdhComplete {
        session_id: [u8; 32],
        shared_secret: [u8; 32],
    },
    EcdhFailed {
        session_id: [u8; 32],
        error: String,
    },
}

pub struct KfpNode {
    keys: Keys,
    client: Client,
    share: SharePackage,
    group_pubkey: [u8; 32],
    sessions: Arc<RwLock<SessionManager>>,
    ecdh_sessions: Arc<RwLock<EcdhSessionManager>>,
    peers: Arc<RwLock<PeerManager>>,
    policies: Arc<RwLock<HashMap<PublicKey, PeerPolicy>>>,
    hooks: RwLock<Arc<dyn SigningHooks>>,
    event_tx: broadcast::Sender<KfpNodeEvent>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    shutdown_rx: TokioMutex<Option<mpsc::Receiver<()>>>,
    replay_window_secs: u64,
    audit_log: Arc<SigningAuditLog>,
    expected_pcrs: Option<ExpectedPcrs>,
}

impl KfpNode {
    pub async fn new(share: SharePackage, relays: Vec<String>) -> Result<Self> {
        Self::with_nonce_store(share, relays, None).await
    }

    pub async fn with_nonce_store_path(
        share: SharePackage,
        relays: Vec<String>,
        nonce_store_path: &Path,
    ) -> Result<Self> {
        let store = FileNonceStore::new(nonce_store_path)?;
        Self::with_nonce_store(share, relays, Some(Arc::new(store) as Arc<dyn NonceStore>)).await
    }

    pub async fn with_nonce_store(
        share: SharePackage,
        relays: Vec<String>,
        nonce_store: Option<Arc<dyn NonceStore>>,
    ) -> Result<Self> {
        let keys = derive_keys_from_share(&share)?;
        let client = Client::new(keys.clone());

        for relay in &relays {
            client.add_relay(relay).await.map_err(|e| {
                FrostNetError::Transport(format!("Failed to add relay {}: {}", relay, e))
            })?;
        }

        client.connect().await;

        tokio::time::sleep(Duration::from_millis(500)).await;
        let connected_relays = client.relays().await;
        if connected_relays.is_empty() {
            return Err(FrostNetError::Transport(
                "Failed to connect to any relays".into(),
            ));
        }

        let group_pubkey = *share.group_pubkey();
        let our_index = share.metadata.identifier;
        let (event_tx, _) = broadcast::channel(1000);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let session_manager = match nonce_store {
            Some(store) => {
                info!(
                    consumed_count = store.count(),
                    "Loaded nonce consumption store"
                );
                SessionManager::new().with_nonce_store(store)
            }
            None => SessionManager::new(),
        };

        let audit_hmac_key = derive_audit_hmac_key(&keys, &group_pubkey);
        let audit_log = Arc::new(SigningAuditLog::new(audit_hmac_key));

        Ok(Self {
            keys,
            client,
            share,
            group_pubkey,
            sessions: Arc::new(RwLock::new(session_manager)),
            ecdh_sessions: Arc::new(RwLock::new(EcdhSessionManager::new())),
            peers: Arc::new(RwLock::new(PeerManager::new(our_index))),
            policies: Arc::new(RwLock::new(HashMap::new())),
            hooks: RwLock::new(Arc::new(NoOpHooks)),
            event_tx,
            shutdown_tx: Some(shutdown_tx),
            shutdown_rx: TokioMutex::new(Some(shutdown_rx)),
            replay_window_secs: DEFAULT_REPLAY_WINDOW_SECS,
            audit_log,
            expected_pcrs: None,
        })
    }

    pub fn with_expected_pcrs(mut self, pcrs: ExpectedPcrs) -> Self {
        self.expected_pcrs = Some(pcrs);
        self
    }

    pub fn set_expected_pcrs(&mut self, pcrs: ExpectedPcrs) {
        self.expected_pcrs = Some(pcrs);
    }

    pub fn require_attestation(&self) -> bool {
        self.expected_pcrs.is_some()
    }

    pub fn pubkey(&self) -> PublicKey {
        self.keys.public_key()
    }

    pub fn group_pubkey(&self) -> &[u8; 32] {
        &self.group_pubkey
    }

    pub fn share_index(&self) -> u16 {
        self.share.metadata.identifier
    }

    pub fn set_replay_window(&mut self, secs: u64) {
        self.replay_window_secs = secs;
    }

    pub fn subscribe(&self) -> broadcast::Receiver<KfpNodeEvent> {
        self.event_tx.subscribe()
    }

    pub fn audit_log(&self) -> &SigningAuditLog {
        &self.audit_log
    }

    pub fn online_peers(&self) -> usize {
        self.peers.read().online_count()
    }

    pub fn peer_status(&self) -> Vec<(u16, PeerStatus, Option<String>)> {
        self.peers
            .read()
            .all_peers()
            .iter()
            .map(|p| (p.share_index, p.status.clone(), p.name.clone()))
            .collect()
    }

    pub fn set_peer_policy(&self, policy: PeerPolicy) {
        self.policies.write().insert(policy.pubkey, policy);
    }

    pub fn remove_peer_policy(&self, pubkey: &PublicKey) {
        self.policies.write().remove(pubkey);
    }

    pub fn get_peer_policy(&self, pubkey: &PublicKey) -> Option<PeerPolicy> {
        self.policies.read().get(pubkey).cloned()
    }

    pub fn set_hooks(&self, hooks: Arc<dyn SigningHooks>) {
        *self.hooks.write() = hooks;
    }

    fn can_receive_from(&self, pubkey: &PublicKey) -> bool {
        self.policies
            .read()
            .get(pubkey)
            .map(|p| p.allow_receive)
            .unwrap_or(true)
    }

    fn cleanup_session_on_hook_failure(&self, session_id: &[u8; 32]) {
        self.sessions.write().complete_session(session_id);
    }

    fn invoke_post_sign_hook(&self, session_id: &[u8; 32], signature: &[u8; 64]) {
        let info = {
            let mut sessions = self.sessions.write();
            let info = sessions.get_session(session_id).map(SessionInfo::from);
            if info.is_some() {
                sessions.complete_session(session_id);
            }
            info
        };

        if let Some(info) = info {
            let hooks = self.hooks.read().clone();
            hooks.post_sign(&info, signature);
        }
    }

    #[allow(clippy::type_complexity)]
    fn select_eligible_peers(&self, threshold: usize) -> Result<(Vec<u16>, Vec<(u16, PublicKey)>)> {
        let selected_peers: Vec<Peer> = {
            let peers = self.peers.read();
            let policies = self.policies.read();
            let eligible_peers: Vec<_> = peers
                .get_signing_peers()
                .into_iter()
                .filter(|p| policies.get(&p.pubkey).map_or(true, |pol| pol.allow_send))
                .collect();

            if eligible_peers.len() + 1 < threshold {
                return Err(FrostNetError::InsufficientPeers {
                    needed: threshold - 1,
                    available: eligible_peers.len(),
                });
            }

            eligible_peers
                .choose_multiple(&mut rand_09::rng(), threshold - 1)
                .copied()
                .cloned()
                .collect()
        };

        let participant_peers = selected_peers
            .iter()
            .map(|p| (p.share_index, p.pubkey))
            .collect();

        let mut participants: Vec<u16> = selected_peers.iter().map(|p| p.share_index).collect();
        participants.push(self.share.metadata.identifier);
        participants.sort();

        Ok((participants, participant_peers))
    }

    pub async fn announce(&self) -> Result<()> {
        let key_package = self
            .share
            .key_package()
            .map_err(|e| FrostNetError::Crypto(format!("Failed to get key package: {}", e)))?;

        let signing_share = key_package.signing_share();
        let signing_share_serialized = signing_share.serialize();
        let signing_share_bytes: [u8; 32] = signing_share_serialized
            .as_slice()
            .try_into()
            .map_err(|_| FrostNetError::Crypto("Invalid signing share length".into()))?;

        let verifying_share = key_package.verifying_share();
        let verifying_share_serialized = verifying_share.serialize().map_err(|e| {
            FrostNetError::Crypto(format!("Failed to serialize verifying share: {}", e))
        })?;
        let verifying_share_bytes: [u8; 33] = verifying_share_serialized
            .as_slice()
            .try_into()
            .map_err(|_| FrostNetError::Crypto("Invalid verifying share length".into()))?;

        let event = KfpEventBuilder::announcement(
            &self.keys,
            &self.group_pubkey,
            self.share.metadata.identifier,
            &signing_share_bytes,
            &verifying_share_bytes,
            Some(&self.share.metadata.name),
        )?;

        self.client
            .send_event(&event)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        info!(
            share_index = self.share.metadata.identifier,
            "Announced presence"
        );
        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        let mut shutdown_rx = self
            .shutdown_rx
            .lock()
            .await
            .take()
            .ok_or_else(|| FrostNetError::Session("run() has already been started".into()))?;
        let mut notifications = self.client.notifications();

        let since = Timestamp::now() - Duration::from_secs(300);

        let group_filter = Filter::new()
            .kind(Kind::Custom(KFP_EVENT_KIND))
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::G),
                hex::encode(self.group_pubkey),
            )
            .since(since);

        let direct_filter = Filter::new()
            .kind(Kind::Custom(KFP_EVENT_KIND))
            .pubkey(self.keys.public_key())
            .since(since);

        self.client
            .subscribe(group_filter.clone(), None)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        self.client
            .subscribe(direct_filter, None)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        let fetch_filter = Filter::new()
            .kind(Kind::Custom(KFP_EVENT_KIND))
            .since(since);

        match self
            .client
            .fetch_events(fetch_filter, Duration::from_secs(5))
            .await
        {
            Ok(events) => {
                let group_hex = hex::encode(self.group_pubkey);
                let matching: Vec<_> = events
                    .into_iter()
                    .filter(|e| {
                        e.tags.iter().any(|t| {
                            t.kind() == TagKind::custom("g")
                                && t.content().map(|c| c == group_hex).unwrap_or(false)
                        })
                    })
                    .collect();
                debug!(count = matching.len(), "Fetched historical events");
                for event in matching {
                    let _ = self.handle_event(&event).await;
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to fetch historical events");
            }
        }

        self.announce().await?;

        let mut announce_interval = tokio::time::interval(Duration::from_secs(60));
        announce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(120));
        cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    break;
                }
                _ = announce_interval.tick() => {
                    if let Err(e) = self.announce().await {
                        warn!(error = %e, "Failed to re-announce");
                    }
                }
                _ = cleanup_interval.tick() => {
                    self.sessions.write().cleanup_expired();
                }
                notification = notifications.recv() => {
                    match notification {
                        Ok(RelayPoolNotification::Event { event, .. }) => {
                            if let Err(e) = self.handle_event(&event).await {
                                warn!(error = %e, "Failed to handle event");
                            }
                        }
                        Ok(RelayPoolNotification::Shutdown) => {
                            info!("Relay pool shutdown");
                            break;
                        }
                        Err(e) => {
                            error!(error = %e, "Notification error");
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.try_send(());
        }
    }

    pub fn take_shutdown_handle(&mut self) -> Option<mpsc::Sender<()>> {
        self.shutdown_tx.take()
    }

    async fn handle_event(&self, event: &Event) -> Result<()> {
        if event.pubkey == self.keys.public_key() {
            return Ok(());
        }

        let msg_type = KfpEventBuilder::get_message_type(event);
        debug!(msg_type = ?msg_type, from = %event.pubkey, "Received event");

        let msg = match KfpEventBuilder::decrypt_message(&self.keys, event) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Failed to decrypt/parse message");
                return Ok(());
            }
        };

        if !matches!(
            msg,
            KfpMessage::Announce(_) | KfpMessage::SignRequest(_) | KfpMessage::EcdhRequest(_)
        ) && !self.peers.read().is_trusted_peer(&event.pubkey)
        {
            debug!(from = %event.pubkey, "Rejecting message from untrusted peer");
            return Err(FrostNetError::UntrustedPeer(event.pubkey.to_string()));
        }

        match msg {
            KfpMessage::Announce(payload) => {
                self.handle_announce(event.pubkey, payload).await?;
            }
            KfpMessage::SignRequest(payload) => {
                self.handle_sign_request(event.pubkey, payload).await?;
            }
            KfpMessage::Commitment(payload) => {
                self.handle_commitment(event.pubkey, payload).await?;
            }
            KfpMessage::SignatureShare(payload) => {
                self.handle_signature_share(event.pubkey, payload).await?;
            }
            KfpMessage::SignatureComplete(payload) => {
                self.handle_signature_complete(event.pubkey, payload)
                    .await?;
            }
            KfpMessage::EcdhRequest(payload) => {
                self.handle_ecdh_request(event.pubkey, payload).await?;
            }
            KfpMessage::EcdhShare(payload) => {
                self.handle_ecdh_share(event.pubkey, payload).await?;
            }
            KfpMessage::EcdhComplete(payload) => {
                self.handle_ecdh_complete(event.pubkey, payload).await?;
            }
            KfpMessage::Ping(payload) => {
                self.handle_ping(event.pubkey, payload).await?;
            }
            KfpMessage::Pong(payload) => {
                self.handle_pong(event.pubkey, payload).await?;
            }
            KfpMessage::Error(payload) => {
                warn!(
                    code = %payload.code,
                    message = %payload.message,
                    "Received error from peer"
                );
            }
        }

        Ok(())
    }

    async fn handle_announce(&self, pubkey: PublicKey, payload: AnnouncePayload) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        let now = chrono::Utc::now().timestamp() as u64;
        if payload.timestamp + ANNOUNCE_MAX_AGE_SECS < now {
            debug!(
                timestamp = payload.timestamp,
                now, "Rejecting stale announcement"
            );
            return Err(FrostNetError::Protocol(
                "Announcement timestamp too old".into(),
            ));
        }
        if payload.timestamp > now + ANNOUNCE_MAX_FUTURE_SECS {
            debug!(
                timestamp = payload.timestamp,
                now, "Rejecting future-dated announcement"
            );
            return Err(FrostNetError::Protocol(
                "Announcement timestamp in future".into(),
            ));
        }

        crate::proof::verify_proof(
            &payload.verifying_share,
            &payload.proof_signature,
            &payload.group_pubkey,
            payload.share_index,
            payload.timestamp,
        )?;

        let attestation_status = self.verify_announce_attestation(&payload);

        if self.expected_pcrs.is_some() {
            if let AttestationStatus::Failed(ref reason) = attestation_status {
                warn!(
                    share_index = payload.share_index,
                    reason = %reason,
                    "Rejecting peer with failed attestation"
                );
                return Err(FrostNetError::Attestation(format!(
                    "Peer {} attestation failed: {}",
                    payload.share_index, reason
                )));
            }
            if attestation_status == AttestationStatus::NotProvided {
                warn!(
                    share_index = payload.share_index,
                    "Rejecting peer without attestation (attestation required)"
                );
                return Err(FrostNetError::Attestation(format!(
                    "Peer {} did not provide attestation",
                    payload.share_index
                )));
            }
        }

        let mut peer = Peer::new(pubkey, payload.share_index)
            .with_capabilities(payload.capabilities)
            .with_verifying_share(payload.verifying_share);

        if let Some(name) = payload.name {
            peer = peer.with_name(&name);
        }

        peer = peer.with_attestation_status(attestation_status);

        let name_clone = peer.name.clone();
        self.peers.write().add_peer(peer);

        info!(
            share_index = payload.share_index,
            name = ?name_clone,
            "Peer discovered with valid proof-of-share"
        );

        let _ = self.event_tx.send(KfpNodeEvent::PeerDiscovered {
            share_index: payload.share_index,
            name: name_clone,
        });

        Ok(())
    }

    fn verify_announce_attestation(&self, payload: &AnnouncePayload) -> AttestationStatus {
        let attestation = match &payload.attestation {
            Some(att) => att,
            None => return AttestationStatus::NotProvided,
        };

        let expected = match &self.expected_pcrs {
            Some(pcrs) => pcrs,
            None => return AttestationStatus::NotConfigured,
        };

        match verify_peer_attestation(attestation, expected, &self.group_pubkey) {
            Ok(()) => AttestationStatus::Verified,
            Err(e) => AttestationStatus::Failed(e.to_string()),
        }
    }

    async fn handle_sign_request(
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
                "Peer {} not allowed to send sign requests",
                from
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
                .map_err(|e| FrostNetError::Crypto(format!("Serialize commitment: {}", e)))?;

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

        let session_info = SessionInfo {
            session_id: request.session_id,
            message: request.message.clone(),
            threshold: self.share.metadata.threshold,
            participants: request.participants.clone(),
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
            .map_err(|e| FrostNetError::Crypto(format!("Serialize commitment: {}", e)))?;

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

    fn verify_peer_share_index(&self, from: PublicKey, share_index: u16) -> Result<()> {
        let peers = self.peers.read();
        let peer = peers.get_peer(share_index).ok_or_else(|| {
            FrostNetError::UntrustedPeer(format!("Share index {} not announced", share_index))
        })?;
        if peer.pubkey != from {
            return Err(FrostNetError::UntrustedPeer(format!(
                "Sender {} doesn't match share index {}",
                from, share_index
            )));
        }
        Ok(())
    }

    async fn handle_commitment(&self, from: PublicKey, payload: CommitmentPayload) -> Result<()> {
        self.verify_peer_share_index(from, payload.share_index)?;

        let commitment =
            frost_secp256k1_tr::round1::SigningCommitments::deserialize(&payload.commitment)
                .map_err(|e| FrostNetError::Crypto(format!("Invalid commitment: {}", e)))?;

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

    async fn generate_and_send_share(&self, session_id: &[u8; 32]) -> Result<()> {
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
            .map_err(|e| FrostNetError::Crypto(format!("Signing failed: {}", e)))?;

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

    async fn handle_signature_share(
        &self,
        from: PublicKey,
        payload: SignatureSharePayload,
    ) -> Result<()> {
        self.verify_peer_share_index(from, payload.share_index)?;

        let sig_share =
            frost_secp256k1_tr::round2::SignatureShare::deserialize(&payload.signature_share)
                .map_err(|e| FrostNetError::Crypto(format!("Invalid signature share: {}", e)))?;

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

    async fn handle_signature_complete(
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

    async fn handle_ping(&self, from: PublicKey, payload: PingPayload) -> Result<()> {
        let event = KfpEventBuilder::pong(&self.keys, &from, payload.challenge)?;
        self.client
            .send_event(&event)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        if let Some(peer) = self.peers.read().get_peer_by_pubkey(&from) {
            self.peers.write().update_last_seen(peer.share_index);
        }

        Ok(())
    }

    async fn handle_pong(&self, from: PublicKey, _payload: PongPayload) -> Result<()> {
        if let Some(peer) = self.peers.read().get_peer_by_pubkey(&from) {
            self.peers.write().update_last_seen(peer.share_index);
        }
        Ok(())
    }

    async fn handle_ecdh_request(
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
        let signing_share_bytes: [u8; 32] = signing_share
            .serialize()
            .as_slice()
            .try_into()
            .map_err(|_| FrostNetError::Crypto("Invalid signing share length".into()))?;

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

    async fn handle_ecdh_share(&self, from: PublicKey, payload: EcdhSharePayload) -> Result<()> {
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

    async fn handle_ecdh_complete(
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
            .map_err(|e| FrostNetError::Crypto(format!("Serialize commitment: {}", e)))?;
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
        let signing_share_bytes: [u8; 32] = signing_share
            .serialize()
            .as_slice()
            .try_into()
            .map_err(|_| FrostNetError::Crypto("Invalid signing share length".into()))?;

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

    pub async fn ping_peers(&self, timeout: Duration) -> Result<Vec<u16>> {
        let peers_snapshot: Vec<(u16, PublicKey, std::time::Instant)> = self
            .peers
            .read()
            .all_peers()
            .iter()
            .map(|p| (p.share_index, p.pubkey, p.last_seen))
            .collect();

        if peers_snapshot.is_empty() {
            return Ok(Vec::new());
        }

        for (_, pubkey, _) in &peers_snapshot {
            if let Ok(event) = KfpEventBuilder::ping(&self.keys, pubkey) {
                let _ = self.client.send_event(&event).await;
            }
        }

        tokio::time::sleep(timeout).await;

        let responsive: Vec<u16> = peers_snapshot
            .iter()
            .filter_map(|(share_index, _, initial_last_seen)| {
                self.peers
                    .read()
                    .get_peer(*share_index)
                    .filter(|p| p.last_seen > *initial_last_seen)
                    .map(|_| *share_index)
            })
            .collect();

        Ok(responsive)
    }
}

fn derive_keys_from_share(share: &SharePackage) -> Result<Keys> {
    let key_package = share
        .key_package()
        .map_err(|e| FrostNetError::Crypto(format!("Failed to get key package: {}", e)))?;
    let verifying_share = key_package.verifying_share();
    let vs_bytes = verifying_share.serialize().map_err(|e| {
        FrostNetError::Crypto(format!("Failed to serialize verifying share: {}", e))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"keep-frost-node-identity-v1");
    hasher.update(share.metadata.group_pubkey);
    hasher.update(vs_bytes.as_slice());
    let derived: [u8; 32] = hasher.finalize().into();
    let secret_key = SecretKey::from_slice(&derived)
        .map_err(|e| FrostNetError::Crypto(format!("Failed to create secret key: {}", e)))?;
    Ok(Keys::new(secret_key))
}

fn derive_audit_hmac_key(keys: &Keys, group_pubkey: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"keep-frost-audit-hmac-v1");
    hasher.update(keys.secret_key().secret_bytes());
    hasher.update(group_pubkey);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keep_core::frost::{ThresholdConfig, TrustedDealer};

    #[tokio::test]
    async fn test_node_creation() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (mut shares, _) = dealer.generate("test").unwrap();

        let share = shares.remove(0);
        let result = KfpNode::new(share, vec!["wss://relay.damus.io".into()]).await;
        assert!(result.is_ok());

        let node = result.unwrap();
        assert_eq!(node.share_index(), 1);
    }
}
