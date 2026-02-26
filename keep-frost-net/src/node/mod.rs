// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
mod descriptor;
mod ecdh;
mod signing;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ::rand::seq::IndexedRandom;
use nostr_sdk::prelude::*;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, mpsc, Mutex as TokioMutex};
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use keep_core::frost::SharePackage;
use keep_core::relay::{
    validate_relay_url, validate_relay_url_allow_internal, ALLOW_INTERNAL_HOSTS,
};

use crate::attestation::{verify_peer_attestation, ExpectedPcrs};
use crate::audit::SigningAuditLog;
use crate::descriptor_session::DescriptorSessionManager;
use crate::ecdh::EcdhSessionManager;
use crate::error::{FrostNetError, Result};
use crate::event::KfpEventBuilder;
use crate::nonce_store::{FileNonceStore, NonceStore};
use crate::peer::{AttestationStatus, Peer, PeerManager, PeerStatus};
use crate::protocol::*;
use crate::session::{NetworkSession, SessionManager};

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
    pub requester: u16,
}

impl From<&NetworkSession> for SessionInfo {
    fn from(session: &NetworkSession) -> Self {
        Self {
            session_id: *session.session_id(),
            message: session.message().to_vec(),
            threshold: session.threshold(),
            participants: session.participants().to_vec(),
            requester: 0,
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

#[derive(Clone, Debug)]
pub struct HealthCheckResult {
    pub responsive: Vec<u16>,
    pub unresponsive: Vec<u16>,
}

/// Maximum age for announcement timestamps (5 minutes)
pub(crate) const ANNOUNCE_MAX_AGE_SECS: u64 = 300;
/// Maximum clock skew tolerance for future timestamps (30 seconds)
pub(crate) const ANNOUNCE_MAX_FUTURE_SECS: u64 = 30;

#[derive(Clone)]
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
        shared_secret: Zeroizing<[u8; 32]>,
    },
    EcdhFailed {
        session_id: [u8; 32],
        error: String,
    },
    DescriptorProposed {
        session_id: [u8; 32],
    },
    DescriptorContributionNeeded {
        session_id: [u8; 32],
        policy: WalletPolicy,
        network: String,
        initiator_pubkey: PublicKey,
    },
    DescriptorContributed {
        session_id: [u8; 32],
        share_index: u16,
    },
    DescriptorReady {
        session_id: [u8; 32],
    },
    DescriptorComplete {
        session_id: [u8; 32],
        external_descriptor: String,
        internal_descriptor: String,
        network: String,
    },
    DescriptorAcked {
        session_id: [u8; 32],
        share_index: u16,
        ack_count: usize,
        expected_acks: usize,
    },
    DescriptorNacked {
        session_id: [u8; 32],
        share_index: u16,
        reason: String,
    },
    DescriptorFailed {
        session_id: [u8; 32],
        error: String,
    },
    XpubAnnounced {
        share_index: u16,
        recovery_xpubs: Vec<AnnouncedXpub>,
    },
    HealthCheckComplete {
        group_pubkey: [u8; 32],
        responsive: Vec<u16>,
        unresponsive: Vec<u16>,
    },
}

impl std::fmt::Debug for KfpNodeEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EcdhComplete { session_id, .. } => f
                .debug_struct("EcdhComplete")
                .field("session_id", &hex::encode(session_id))
                .field("shared_secret", &"[REDACTED]")
                .finish(),
            Self::PeerDiscovered { share_index, name } => f
                .debug_struct("PeerDiscovered")
                .field("share_index", share_index)
                .field("name", name)
                .finish(),
            Self::PeerOffline { share_index } => f
                .debug_struct("PeerOffline")
                .field("share_index", share_index)
                .finish(),
            Self::SigningStarted { session_id } => f
                .debug_struct("SigningStarted")
                .field("session_id", &hex::encode(session_id))
                .finish(),
            Self::SignatureComplete {
                session_id,
                signature,
            } => f
                .debug_struct("SignatureComplete")
                .field("session_id", &hex::encode(session_id))
                .field("signature", &hex::encode(signature))
                .finish(),
            Self::SigningFailed { session_id, error } => f
                .debug_struct("SigningFailed")
                .field("session_id", &hex::encode(session_id))
                .field("error", error)
                .finish(),
            Self::EcdhFailed { session_id, error } => f
                .debug_struct("EcdhFailed")
                .field("session_id", &hex::encode(session_id))
                .field("error", error)
                .finish(),
            Self::DescriptorProposed { session_id } => f
                .debug_struct("DescriptorProposed")
                .field("session_id", &hex::encode(session_id))
                .finish(),
            Self::DescriptorContributionNeeded { session_id, .. } => f
                .debug_struct("DescriptorContributionNeeded")
                .field("session_id", &hex::encode(session_id))
                .finish(),
            Self::DescriptorContributed {
                session_id,
                share_index,
            } => f
                .debug_struct("DescriptorContributed")
                .field("session_id", &hex::encode(session_id))
                .field("share_index", share_index)
                .finish(),
            Self::DescriptorReady { session_id } => f
                .debug_struct("DescriptorReady")
                .field("session_id", &hex::encode(session_id))
                .finish(),
            Self::DescriptorComplete { session_id, .. } => f
                .debug_struct("DescriptorComplete")
                .field("session_id", &hex::encode(session_id))
                .finish(),
            Self::DescriptorAcked {
                session_id,
                share_index,
                ack_count,
                expected_acks,
            } => f
                .debug_struct("DescriptorAcked")
                .field("session_id", &hex::encode(session_id))
                .field("share_index", share_index)
                .field("ack_count", ack_count)
                .field("expected_acks", expected_acks)
                .finish(),
            Self::DescriptorNacked {
                session_id,
                share_index,
                reason,
            } => f
                .debug_struct("DescriptorNacked")
                .field("session_id", &hex::encode(session_id))
                .field("share_index", share_index)
                .field("reason", reason)
                .finish(),
            Self::DescriptorFailed { session_id, error } => f
                .debug_struct("DescriptorFailed")
                .field("session_id", &hex::encode(session_id))
                .field("error", error)
                .finish(),
            Self::XpubAnnounced {
                share_index,
                recovery_xpubs,
            } => f
                .debug_struct("XpubAnnounced")
                .field("share_index", share_index)
                .field("xpub_count", &recovery_xpubs.len())
                .finish(),
            Self::HealthCheckComplete {
                group_pubkey,
                responsive,
                unresponsive,
            } => f
                .debug_struct("HealthCheckComplete")
                .field("group_pubkey", &hex::encode(group_pubkey))
                .field("responsive", responsive)
                .field("unresponsive", unresponsive)
                .finish(),
        }
    }
}

pub struct KfpNode {
    pub(crate) keys: Keys,
    pub(crate) client: Client,
    pub(crate) share: SharePackage,
    pub(crate) group_pubkey: [u8; 32],
    pub(crate) sessions: Arc<RwLock<SessionManager>>,
    pub(crate) ecdh_sessions: Arc<RwLock<EcdhSessionManager>>,
    pub(crate) descriptor_sessions: Arc<RwLock<DescriptorSessionManager>>,
    pub(crate) peers: Arc<RwLock<PeerManager>>,
    pub(crate) policies: Arc<RwLock<HashMap<PublicKey, PeerPolicy>>>,
    pub(crate) hooks: RwLock<Arc<dyn SigningHooks>>,
    pub(crate) event_tx: broadcast::Sender<KfpNodeEvent>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    shutdown_rx: TokioMutex<Option<mpsc::Receiver<()>>>,
    pub(crate) replay_window_secs: u64,
    pub(crate) audit_log: Arc<SigningAuditLog>,
    expected_pcrs: Option<ExpectedPcrs>,
    pub(crate) seen_xpub_announces: RwLock<HashSet<(u16, u64, [u8; 32])>>,
    pub(crate) descriptor_proposers: RwLock<HashSet<u16>>,
}

impl KfpNode {
    pub async fn new(share: SharePackage, relays: Vec<String>) -> Result<Self> {
        Self::with_nonce_store(share, relays, None, None, None).await
    }

    pub async fn new_with_proxy(
        share: SharePackage,
        relays: Vec<String>,
        proxy: SocketAddr,
    ) -> Result<Self> {
        Self::with_nonce_store(share, relays, None, Some(proxy), None).await
    }

    pub async fn with_nonce_store_path(
        share: SharePackage,
        relays: Vec<String>,
        nonce_store_path: &Path,
    ) -> Result<Self> {
        let store = FileNonceStore::new(nonce_store_path)?;
        Self::with_nonce_store(
            share,
            relays,
            Some(Arc::new(store) as Arc<dyn NonceStore>),
            None,
            None,
        )
        .await
    }

    pub async fn with_nonce_store(
        share: SharePackage,
        relays: Vec<String>,
        nonce_store: Option<Arc<dyn NonceStore>>,
        proxy: Option<SocketAddr>,
        session_timeout: Option<Duration>,
    ) -> Result<Self> {
        let descriptor_manager = match session_timeout {
            Some(t) => DescriptorSessionManager::with_timeout(t)?,
            None => DescriptorSessionManager::new(),
        };

        for relay in &relays {
            let validate = if ALLOW_INTERNAL_HOSTS {
                validate_relay_url_allow_internal
            } else {
                validate_relay_url
            };
            validate(relay).map_err(|e| {
                FrostNetError::Transport(format!("Rejected relay URL {relay}: {e}"))
            })?;
        }

        let keys = derive_keys_from_share(&share)?;
        let client = match proxy {
            Some(addr) => {
                let connection = Connection::new().proxy(addr).target(ConnectionTarget::All);
                let opts = ClientOptions::new().connection(connection);
                Client::builder().signer(keys.clone()).opts(opts).build()
            }
            None => Client::new(keys.clone()),
        };

        for relay in &relays {
            client.add_relay(relay).await.map_err(|e| {
                FrostNetError::Transport(format!("Failed to add relay {relay}: {e}"))
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

        let mut session_manager = match nonce_store {
            Some(store) => {
                info!(
                    consumed_count = store.count(),
                    "Loaded nonce consumption store"
                );
                SessionManager::new().with_nonce_store(store)
            }
            None => SessionManager::new(),
        };
        if let Some(t) = session_timeout {
            session_manager = session_manager.with_timeout(t);
        }

        let ecdh_manager = match session_timeout {
            Some(t) => EcdhSessionManager::new().with_timeout(t),
            None => EcdhSessionManager::new(),
        };

        let audit_hmac_key = derive_audit_hmac_key(&keys, &group_pubkey);
        let audit_log = Arc::new(SigningAuditLog::new(audit_hmac_key));

        Ok(Self {
            keys,
            client,
            share,
            group_pubkey,
            sessions: Arc::new(RwLock::new(session_manager)),
            ecdh_sessions: Arc::new(RwLock::new(ecdh_manager)),
            descriptor_sessions: Arc::new(RwLock::new(descriptor_manager)),
            peers: Arc::new(RwLock::new(PeerManager::new(our_index))),
            policies: Arc::new(RwLock::new(HashMap::new())),
            hooks: RwLock::new(Arc::new(NoOpHooks)),
            event_tx,
            shutdown_tx: Some(shutdown_tx),
            shutdown_rx: TokioMutex::new(Some(shutdown_rx)),
            replay_window_secs: DEFAULT_REPLAY_WINDOW_SECS,
            audit_log,
            expected_pcrs: None,
            seen_xpub_announces: RwLock::new(HashSet::new()),
            descriptor_proposers: RwLock::new(HashSet::new()),
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

    pub async fn announce_xpubs(&self, recovery_xpubs: Vec<AnnouncedXpub>) -> Result<()> {
        let peer_pubkeys: Vec<PublicKey> = {
            let peers = self.peers.read();
            let policies = self.policies.read();
            peers
                .get_online_peers()
                .iter()
                .filter(|p| policies.get(&p.pubkey).is_none_or(|pol| pol.allow_send))
                .map(|p| p.pubkey)
                .collect()
        };

        let xpub_count = recovery_xpubs.len();
        let payload = XpubAnnouncePayload::new(
            self.group_pubkey,
            self.share.metadata.identifier,
            recovery_xpubs,
        );

        KfpMessage::XpubAnnounce(payload.clone())
            .validate()
            .map_err(|e| FrostNetError::Protocol(e.to_string()))?;

        let mut fail_count = 0usize;
        for pubkey in &peer_pubkeys {
            let event = KfpEventBuilder::xpub_announce(&self.keys, pubkey, payload.clone())?;
            if let Err(e) = self.client.send_event(&event).await {
                warn!(peer = %pubkey, error = %e, "Failed to send xpub announcement");
                fail_count += 1;
            }
        }
        if fail_count == peer_pubkeys.len() && !peer_pubkeys.is_empty() {
            return Err(FrostNetError::Transport(
                "Failed to send xpub announcement to any peer".into(),
            ));
        }

        info!(
            share_index = self.share.metadata.identifier,
            xpub_count,
            peer_count = peer_pubkeys.len(),
            "Announced recovery xpubs"
        );
        Ok(())
    }

    pub fn get_peer_recovery_xpubs(&self, share_index: u16) -> Option<Vec<AnnouncedXpub>> {
        self.peers
            .read()
            .get_peer_recovery_xpubs(share_index)
            .map(|xpubs| xpubs.to_vec())
    }

    pub fn set_descriptor_proposers(&self, indices: HashSet<u16>) {
        *self.descriptor_proposers.write() = indices;
    }

    pub fn descriptor_proposers(&self) -> HashSet<u16> {
        self.descriptor_proposers.read().clone()
    }

    pub fn set_hooks(&self, hooks: Arc<dyn SigningHooks>) {
        *self.hooks.write() = hooks;
    }

    pub(crate) fn can_receive_from(&self, pubkey: &PublicKey) -> bool {
        self.policies
            .read()
            .get(pubkey)
            .map(|p| p.allow_receive)
            .unwrap_or(true)
    }

    pub(crate) fn cleanup_session_on_hook_failure(&self, session_id: &[u8; 32]) {
        self.sessions.write().complete_session(session_id);
    }

    pub(crate) fn invoke_post_sign_hook(&self, session_id: &[u8; 32], signature: &[u8; 64]) {
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
    pub(crate) fn select_eligible_peers(
        &self,
        threshold: usize,
    ) -> Result<(Vec<u16>, Vec<(u16, PublicKey)>)> {
        let selected_peers: Vec<Peer> = {
            let peers = self.peers.read();
            let policies = self.policies.read();
            let eligible_peers: Vec<_> = peers
                .get_signing_peers()
                .into_iter()
                .filter(|p| policies.get(&p.pubkey).is_none_or(|pol| pol.allow_send))
                .collect();

            if eligible_peers.len() + 1 < threshold {
                return Err(FrostNetError::InsufficientPeers {
                    needed: threshold - 1,
                    available: eligible_peers.len(),
                });
            }

            eligible_peers
                .sample(&mut ::rand::rng(), threshold - 1)
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
            .map_err(|e| FrostNetError::Crypto(format!("Failed to get key package: {e}")))?;

        let signing_share = key_package.signing_share();
        let signing_share_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
            signing_share
                .serialize()
                .as_slice()
                .try_into()
                .map_err(|_| FrostNetError::Crypto("Invalid signing share length".into()))?,
        );

        let verifying_share = key_package.verifying_share();
        let verifying_share_serialized = verifying_share.serialize().map_err(|e| {
            FrostNetError::Crypto(format!("Failed to serialize verifying share: {e}"))
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
                    self.ecdh_sessions.write().cleanup_expired();
                    let expired = self.descriptor_sessions.write().cleanup_expired();
                    for (session_id, reason) in expired {
                        let _ = self.event_tx.send(KfpNodeEvent::DescriptorFailed {
                            session_id,
                            error: reason,
                        });
                    }
                    {
                        let now = chrono::Utc::now().timestamp().max(0) as u64;
                        let window = self.replay_window_secs + MAX_FUTURE_SKEW_SECS;
                        self.seen_xpub_announces.write().retain(|&(_, ts, _)| {
                            now.saturating_sub(window) <= ts
                        });
                    }
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
            KfpMessage::RefreshRequest(_)
            | KfpMessage::RefreshRound1(_)
            | KfpMessage::RefreshRound2(_)
            | KfpMessage::RefreshComplete(_) => {
                if let Some(sid) = msg.session_id() {
                    warn!(session_id = %hex::encode(sid), "Distributed refresh not yet implemented");
                }
            }
            KfpMessage::DescriptorPropose(payload) => {
                self.handle_descriptor_propose(event.pubkey, payload)
                    .await?;
            }
            KfpMessage::DescriptorContribute(payload) => {
                self.handle_descriptor_contribute(event.pubkey, payload)
                    .await?;
            }
            KfpMessage::DescriptorFinalize(payload) => {
                self.handle_descriptor_finalize(event.pubkey, payload)
                    .await?;
            }
            KfpMessage::DescriptorAck(payload) => {
                self.handle_descriptor_ack(event.pubkey, payload).await?;
            }
            KfpMessage::DescriptorNack(payload) => {
                self.handle_descriptor_nack(event.pubkey, payload).await?;
            }
            KfpMessage::XpubAnnounce(payload) => {
                self.handle_xpub_announce(event.pubkey, payload).await?;
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

    pub(crate) fn verify_peer_share_index(&self, from: PublicKey, share_index: u16) -> Result<()> {
        let peers = self.peers.read();
        let peer = peers.get_peer(share_index).ok_or_else(|| {
            FrostNetError::UntrustedPeer(format!("Share index {share_index} not announced"))
        })?;
        if peer.pubkey != from {
            return Err(FrostNetError::UntrustedPeer(format!(
                "Sender {from} doesn't match share index {share_index}"
            )));
        }
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

    pub async fn health_check(&self, timeout: Duration) -> Result<HealthCheckResult> {
        if timeout < Duration::from_secs(1) || timeout > Duration::from_secs(300) {
            return Err(FrostNetError::Session(format!(
                "Health check timeout must be between 1s and 300s, got {}s",
                timeout.as_secs()
            )));
        }
        let peers_snapshot: Vec<(u16, PublicKey, std::time::Instant)> = self
            .peers
            .read()
            .all_peers()
            .iter()
            .map(|p| (p.share_index, p.pubkey, p.last_seen))
            .collect();

        let responsive = self.ping_peers_snapshot(&peers_snapshot, timeout).await?;
        let unresponsive: Vec<u16> = peers_snapshot
            .iter()
            .map(|(idx, _, _)| *idx)
            .filter(|idx| !responsive.contains(idx))
            .collect();

        let result = HealthCheckResult {
            responsive,
            unresponsive,
        };

        let _ = self.event_tx.send(KfpNodeEvent::HealthCheckComplete {
            group_pubkey: self.group_pubkey,
            responsive: result.responsive.clone(),
            unresponsive: result.unresponsive.clone(),
        });

        Ok(result)
    }

    pub async fn ping_peers(&self, timeout: Duration) -> Result<Vec<u16>> {
        let peers_snapshot: Vec<(u16, PublicKey, std::time::Instant)> = self
            .peers
            .read()
            .all_peers()
            .iter()
            .map(|p| (p.share_index, p.pubkey, p.last_seen))
            .collect();

        self.ping_peers_snapshot(&peers_snapshot, timeout).await
    }

    async fn ping_peers_snapshot(
        &self,
        peers_snapshot: &[(u16, PublicKey, std::time::Instant)],
        timeout: Duration,
    ) -> Result<Vec<u16>> {
        if peers_snapshot.is_empty() {
            return Ok(Vec::new());
        }

        for (share_index, pubkey, _) in peers_snapshot {
            match KfpEventBuilder::ping(&self.keys, pubkey) {
                Ok(event) => {
                    if let Err(e) = self.client.send_event(&event).await {
                        warn!(
                            peer = %pubkey,
                            share_index,
                            error = %e,
                            "Failed to send ping"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        peer = %pubkey,
                        share_index,
                        error = %e,
                        "Failed to build ping event"
                    );
                }
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
        .map_err(|e| FrostNetError::Crypto(format!("Failed to get key package: {e}")))?;
    let signing_share_bytes = key_package.signing_share().serialize();

    let mut hasher = Sha256::new();
    hasher.update(b"keep-frost-node-identity-v2");
    hasher.update(share.metadata.group_pubkey);
    hasher.update(share.metadata.identifier.to_be_bytes());
    hasher.update(signing_share_bytes.as_slice());
    let derived: Zeroizing<[u8; 32]> = Zeroizing::new(hasher.finalize().into());
    let secret_key = SecretKey::from_slice(&*derived)
        .map_err(|e| FrostNetError::Crypto(format!("Failed to create secret key: {e}")))?;
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
