// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

mod audit;
mod dkg;
mod error;
mod nip46;
mod nip55;
mod storage;
mod types;

pub use audit::{AuditEntry, AuditEventType, AuditLog, AuditStorage};
pub use dkg::{DkgResult, DkgRound1Package, DkgRound2Package, DkgSession};
pub use error::KeepMobileError;
pub use nip46::{
    BunkerApprovalRequest, BunkerCallbacks, BunkerHandler, BunkerLogEvent, BunkerStatus,
};
pub use nip55::{Nip55Handler, Nip55Request, Nip55RequestType, Nip55Response};
pub use storage::{SecureStorage, ShareInfo, ShareMetadataInfo, StoredShareInfo};
pub use types::{
    DkgConfig, DkgStatus, FrostGenerationResult, GeneratedShareInfo, PeerInfo, PeerStatus,
    SignRequest, SignRequestMetadata, ThresholdConfig,
};

use keep_core::frost::{
    ShareExport, SharePackage, ThresholdConfig as CoreThresholdConfig, TrustedDealer,
};
use keep_frost_net::{KfpNode, KfpNodeEvent, SessionInfo, SigningHooks};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

const MAX_PENDING_REQUESTS: usize = 100;
const SIGNING_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_IMPORT_DATA_SIZE: usize = 64 * 1024;
const MAX_STORED_SHARES: usize = 100;
const MAX_SHARE_NAME_LENGTH: usize = 64;

#[derive(Serialize, Deserialize)]
struct StoredShareData {
    metadata_json: String,
    key_package_bytes: Vec<u8>,
    pubkey_package_bytes: Vec<u8>,
}

struct MobileSigningHooks {
    request_tx: mpsc::Sender<(SessionInfo, mpsc::Sender<bool>)>,
}

impl SigningHooks for MobileSigningHooks {
    fn pre_sign(&self, session: &SessionInfo) -> keep_frost_net::Result<()> {
        let (response_tx, mut response_rx) = mpsc::channel(1);
        if self
            .request_tx
            .blocking_send((session.clone(), response_tx))
            .is_err()
        {
            return Err(keep_frost_net::FrostNetError::Session(
                "Channel closed".into(),
            ));
        }

        let owned_rt;
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => {
                owned_rt = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                    .map_err(|_| keep_frost_net::FrostNetError::Session("No runtime".into()))?;
                owned_rt.handle().clone()
            }
        };

        let result = handle.block_on(async {
            tokio::time::timeout(SIGNING_RESPONSE_TIMEOUT, response_rx.recv()).await
        });

        match result {
            Ok(Some(true)) => Ok(()),
            Ok(Some(false)) => Err(keep_frost_net::FrostNetError::Session(
                "Request rejected".into(),
            )),
            Ok(None) => Err(keep_frost_net::FrostNetError::Session("No response".into())),
            Err(_) => Err(keep_frost_net::FrostNetError::Session("Timeout".into())),
        }
    }

    fn post_sign(&self, _session: &SessionInfo, _signature: &[u8; 64]) {}
}

#[derive(uniffi::Object)]
pub struct KeepMobile {
    pub(crate) node: Arc<RwLock<Option<Arc<KfpNode>>>>,
    storage: Arc<dyn SecureStorage>,
    pending_requests: Arc<Mutex<Vec<PendingRequest>>>,
    dkg_session: DkgSession,
    pub(crate) runtime: tokio::runtime::Runtime,
}

struct PendingRequest {
    info: SignRequest,
    response_tx: mpsc::Sender<bool>,
}

#[uniffi::export]
impl KeepMobile {
    #[uniffi::constructor]
    pub fn new(storage: Arc<dyn SecureStorage>) -> Result<Self, KeepMobileError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| KeepMobileError::InitializationFailed {
                msg: format!("Runtime: {}", e),
            })?;

        Ok(Self {
            node: Arc::new(RwLock::new(None)),
            storage,
            pending_requests: Arc::new(Mutex::new(Vec::new())),
            dkg_session: DkgSession::new(),
            runtime,
        })
    }

    pub fn initialize(&self, relays: Vec<String>) -> Result<(), KeepMobileError> {
        for relay in &relays {
            validate_relay_url(relay)?;
        }

        let share = self.load_share_package()?;

        self.runtime.block_on(async {
            let node = KfpNode::new(share, relays).await?;

            let (request_tx, request_rx) = mpsc::channel(32);
            let hooks = Arc::new(MobileSigningHooks { request_tx });
            node.set_hooks(hooks);

            let event_rx = node.subscribe();
            let node = Arc::new(node);
            let pending = self.pending_requests.clone();
            tokio::spawn(async move {
                Self::event_listener(event_rx, request_rx, pending).await;
            });

            *self.node.write().await = Some(node);
            Ok(())
        })
    }

    pub fn import_share(
        &self,
        data: String,
        passphrase: String,
        name: String,
    ) -> Result<ShareInfo, KeepMobileError> {
        if data.len() > MAX_IMPORT_DATA_SIZE {
            return Err(KeepMobileError::InvalidShare {
                msg: "Import data exceeds maximum size".into(),
            });
        }

        Self::validate_share_name(&name)?;

        let share_count = self.storage.list_all_shares().len();
        if share_count >= MAX_STORED_SHARES {
            return Err(KeepMobileError::StorageError {
                msg: "Maximum number of shares reached".into(),
            });
        }

        let passphrase = Zeroizing::new(passphrase);
        let export = ShareExport::parse(&data)
            .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;

        let share = export
            .to_share(&passphrase, &name)
            .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;

        let metadata = ShareMetadataInfo {
            name: share.metadata.name.clone(),
            identifier: share.metadata.identifier,
            threshold: share.metadata.threshold,
            total_shares: share.metadata.total_shares,
            group_pubkey: share.metadata.group_pubkey.to_vec(),
        };

        let stored = StoredShareData {
            metadata_json: serde_json::to_string(&share.metadata)
                .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?,
            key_package_bytes: share
                .key_package()
                .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?
                .serialize()
                .map_err(|e| KeepMobileError::FrostError {
                    msg: format!("Serialization failed: {}", e),
                })?,
            pubkey_package_bytes: share
                .pubkey_package()
                .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?
                .serialize()
                .map_err(|e| KeepMobileError::FrostError {
                    msg: format!("Serialization failed: {}", e),
                })?,
        };

        let serialized = serde_json::to_vec(&stored)
            .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?;

        let group_pubkey_hex = hex::encode(&metadata.group_pubkey);
        self.storage
            .store_share_by_key(group_pubkey_hex.clone(), serialized, metadata.clone())?;
        self.storage
            .set_active_share_key(Some(group_pubkey_hex.clone()))?;

        Ok(ShareInfo {
            name: metadata.name,
            share_index: metadata.identifier,
            threshold: metadata.threshold,
            total_shares: metadata.total_shares,
            group_pubkey: group_pubkey_hex,
        })
    }

    pub fn get_pending_requests(&self) -> Vec<SignRequest> {
        self.runtime.block_on(async {
            self.pending_requests
                .lock()
                .await
                .iter()
                .map(|r| r.info.clone())
                .collect()
        })
    }

    pub fn approve_request(&self, request_id: String) -> Result<(), KeepMobileError> {
        self.runtime.block_on(async {
            let mut pending = self.pending_requests.lock().await;
            let idx = pending
                .iter()
                .position(|r| r.info.id == request_id)
                .ok_or(KeepMobileError::RequestNotFound)?;

            let request = pending.remove(idx);
            let _ = request.response_tx.send(true).await;
            Ok(())
        })
    }

    pub fn reject_request(&self, request_id: String) {
        self.runtime.block_on(async {
            let mut pending = self.pending_requests.lock().await;
            if let Some(idx) = pending.iter().position(|r| r.info.id == request_id) {
                let request = pending.remove(idx);
                let _ = request.response_tx.send(false).await;
            }
        });
    }

    pub fn get_peers(&self) -> Vec<PeerInfo> {
        self.runtime.block_on(async {
            let node_guard = self.node.read().await;
            let Some(node) = node_guard.as_ref() else {
                return Vec::new();
            };

            node.peer_status()
                .into_iter()
                .map(|(share_index, status, name)| PeerInfo {
                    share_index,
                    name,
                    status: convert_peer_status(status),
                })
                .collect()
        })
    }

    pub fn has_share(&self) -> bool {
        self.storage.has_share()
    }

    pub fn get_share_info(&self) -> Option<ShareInfo> {
        self.storage.get_share_metadata().map(|m| ShareInfo {
            name: m.name,
            share_index: m.identifier,
            threshold: m.threshold,
            total_shares: m.total_shares,
            group_pubkey: hex::encode(&m.group_pubkey),
        })
    }

    pub fn delete_share(&self) -> Result<(), KeepMobileError> {
        self.storage.delete_share()
    }

    pub fn export_share(&self, passphrase: String) -> Result<String, KeepMobileError> {
        let passphrase = Zeroizing::new(passphrase);
        let share = self.load_share_package()?;
        let export = ShareExport::from_share(&share, &passphrase)
            .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?;
        export
            .to_bech32()
            .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })
    }

    pub fn list_shares(&self) -> Vec<StoredShareInfo> {
        self.storage
            .list_all_shares()
            .into_iter()
            .filter_map(|m| self.load_stored_share_info(hex::encode(&m.group_pubkey)))
            .collect()
    }

    pub fn get_active_share(&self) -> Option<StoredShareInfo> {
        let key = self.storage.get_active_share_key()?;
        self.load_stored_share_info(key)
    }

    pub fn set_active_share(&self, group_pubkey: String) -> Result<(), KeepMobileError> {
        validate_hex_pubkey(&group_pubkey)?;

        self.storage.load_share_by_key(group_pubkey.clone())?;
        self.storage.set_active_share_key(Some(group_pubkey))?;

        self.runtime.block_on(async {
            self.pending_requests.lock().await.clear();
            *self.node.write().await = None;
        });

        Ok(())
    }

    pub fn delete_share_by_key(&self, group_pubkey: String) -> Result<(), KeepMobileError> {
        validate_hex_pubkey(&group_pubkey)?;

        let is_active = self
            .storage
            .get_active_share_key()
            .is_some_and(|k| constant_time_eq(k.as_bytes(), group_pubkey.as_bytes()));

        self.storage.delete_share_by_key(group_pubkey)?;

        if is_active {
            self.runtime.block_on(async {
                *self.node.write().await = None;
            });
            self.storage.set_active_share_key(None)?;
        }

        Ok(())
    }

    pub fn frost_generate(
        &self,
        threshold: u16,
        total_shares: u16,
        name: String,
        passphrase: String,
    ) -> Result<FrostGenerationResult, KeepMobileError> {
        Self::validate_share_name(&name)?;

        let config = CoreThresholdConfig::new(threshold, total_shares)?;
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate(&name)?;

        let passphrase = Zeroizing::new(passphrase);
        Self::build_generation_result(&shares, &passphrase)
    }

    pub fn frost_split(
        &self,
        existing_key: String,
        threshold: u16,
        total_shares: u16,
        name: String,
        passphrase: String,
    ) -> Result<FrostGenerationResult, KeepMobileError> {
        Self::validate_share_name(&name)?;

        let key_bytes = hex::decode(&existing_key).map_err(|_| KeepMobileError::InvalidShare {
            msg: "Invalid hex encoding for existing key".into(),
        })?;

        if key_bytes.len() != 32 {
            return Err(KeepMobileError::InvalidShare {
                msg: "Existing key must be exactly 32 bytes".into(),
            });
        }

        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&key_bytes);
        drop(key_bytes);

        let config = CoreThresholdConfig::new(threshold, total_shares)?;
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.split_existing(&secret, &name)?;

        let passphrase = Zeroizing::new(passphrase);
        Self::build_generation_result(&shares, &passphrase)
    }

    pub fn frost_start_dkg(&self, config: DkgConfig) -> Result<Vec<u8>, KeepMobileError> {
        self.runtime.block_on(async {
            let round1_pkg = self.dkg_session.start(config).await?;
            Ok(round1_pkg.package_bytes)
        })
    }

    pub fn frost_dkg_round1_packages(
        &self,
        packages: Vec<Vec<u8>>,
        participant_indices: Vec<u16>,
    ) -> Result<Vec<Vec<u8>>, KeepMobileError> {
        if packages.len() != participant_indices.len() {
            return Err(KeepMobileError::FrostError {
                msg: "Packages and indices must have same length".into(),
            });
        }

        let round1_packages: Vec<DkgRound1Package> = packages
            .into_iter()
            .zip(participant_indices)
            .map(|(pkg, idx)| DkgRound1Package {
                participant_index: idx,
                package_bytes: pkg,
            })
            .collect();

        self.runtime.block_on(async {
            let round2_packages = self
                .dkg_session
                .receive_round1_packages(round1_packages)
                .await?;
            Ok(round2_packages
                .into_iter()
                .map(|p| p.package_bytes)
                .collect())
        })
    }

    pub fn frost_dkg_round2_packages(
        &self,
        packages: Vec<Vec<u8>>,
        sender_indices: Vec<u16>,
        name: String,
        passphrase: String,
    ) -> Result<String, KeepMobileError> {
        if packages.len() != sender_indices.len() {
            return Err(KeepMobileError::FrostError {
                msg: "Packages and indices must have same length".into(),
            });
        }

        self.runtime.block_on(async {
            let round2_packages: Vec<DkgRound2Package> = packages
                .into_iter()
                .zip(sender_indices)
                .map(|(pkg, idx)| DkgRound2Package {
                    sender_index: idx,
                    package_bytes: pkg,
                })
                .collect();

            let result = self
                .dkg_session
                .receive_round2_packages(round2_packages, &name, &passphrase)
                .await?;
            Ok(result.share_export)
        })
    }

    pub fn frost_dkg_status(&self) -> DkgStatus {
        self.runtime.block_on(self.dkg_session.status())
    }

    pub fn frost_dkg_reset(&self) {
        self.runtime.block_on(self.dkg_session.reset())
    }
}

impl KeepMobile {
    fn validate_share_name(name: &str) -> Result<(), KeepMobileError> {
        if name.chars().count() > MAX_SHARE_NAME_LENGTH {
            return Err(KeepMobileError::InvalidShare {
                msg: format!(
                    "Share name exceeds maximum length of {} characters",
                    MAX_SHARE_NAME_LENGTH
                ),
            });
        }
        Ok(())
    }

    fn build_generation_result(
        shares: &[SharePackage],
        passphrase: &Zeroizing<String>,
    ) -> Result<FrostGenerationResult, KeepMobileError> {
        let mut share_infos = Vec::with_capacity(shares.len());

        for share in shares {
            let export = ShareExport::from_share(share, passphrase)?;
            let export_data = export.to_bech32()?;

            share_infos.push(GeneratedShareInfo {
                share_index: share.metadata.identifier,
                threshold: share.metadata.threshold,
                total_shares: share.metadata.total_shares,
                group_pubkey: hex::encode(share.metadata.group_pubkey),
                export_data,
            });
        }

        let group_pubkey = shares
            .first()
            .map(|s| hex::encode(s.metadata.group_pubkey))
            .unwrap_or_default();

        Ok(FrostGenerationResult {
            group_pubkey,
            shares: share_infos,
        })
    }

    async fn event_listener(
        mut event_rx: broadcast::Receiver<KfpNodeEvent>,
        mut request_rx: mpsc::Receiver<(SessionInfo, mpsc::Sender<bool>)>,
        pending: Arc<Mutex<Vec<PendingRequest>>>,
    ) {
        loop {
            tokio::select! {
                result = event_rx.recv() => {
                    match result {
                        Ok(KfpNodeEvent::SignatureComplete { session_id, .. })
                        | Ok(KfpNodeEvent::SigningFailed { session_id, .. }) => {
                            let id = hex::encode(session_id);
                            pending.lock().await.retain(|r| r.info.id != id);
                        }
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                result = request_rx.recv() => {
                    let Some((session, response_tx)) = result else {
                        break;
                    };
                    let mut guard = pending.lock().await;
                    if guard.len() >= MAX_PENDING_REQUESTS {
                        let _ = response_tx.send(false).await;
                        continue;
                    }
                    guard.push(PendingRequest {
                        info: SignRequest {
                            id: hex::encode(session.session_id),
                            session_id: session.session_id.to_vec(),
                            message_type: String::new(),
                            message_preview: hex::encode(&session.message[..session.message.len().min(8)]),
                            from_peer: 0,
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            metadata: None,
                        },
                        response_tx,
                    });
                }
            }
        }
    }

    fn load_share_package(&self) -> Result<SharePackage, KeepMobileError> {
        let key = match self.storage.get_active_share_key() {
            Some(k) => k,
            None => self.migrate_legacy_share()?,
        };
        let data = self.storage.load_share_by_key(key)?;
        let stored: StoredShareData = serde_json::from_slice(&data)
            .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;

        let metadata: keep_core::frost::ShareMetadata = serde_json::from_str(&stored.metadata_json)
            .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;

        let key_package = frost_secp256k1_tr::keys::KeyPackage::deserialize(
            &stored.key_package_bytes,
        )
        .map_err(|e| KeepMobileError::InvalidShare {
            msg: format!("Invalid key package: {}", e),
        })?;

        let pubkey_package =
            frost_secp256k1_tr::keys::PublicKeyPackage::deserialize(&stored.pubkey_package_bytes)
                .map_err(|e| KeepMobileError::InvalidShare {
                msg: format!("Invalid pubkey package: {}", e),
            })?;

        SharePackage::new(metadata, &key_package, &pubkey_package)
            .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })
    }

    fn load_stored_share_info(&self, key: String) -> Option<StoredShareInfo> {
        let data = self.storage.load_share_by_key(key.clone()).ok()?;
        let stored: StoredShareData = serde_json::from_slice(&data).ok()?;
        let metadata: keep_core::frost::ShareMetadata =
            serde_json::from_str(&stored.metadata_json).ok()?;

        Some(StoredShareInfo {
            group_pubkey: key,
            name: metadata.name,
            share_index: metadata.identifier,
            threshold: metadata.threshold,
            total_shares: metadata.total_shares,
            created_at: metadata.created_at,
            last_used: metadata.last_used,
            sign_count: metadata.sign_count,
        })
    }

    fn migrate_legacy_share(&self) -> Result<String, KeepMobileError> {
        if !self.storage.has_share() {
            return Err(KeepMobileError::StorageError {
                msg: "No active share set".into(),
            });
        }

        let legacy_data = self.storage.load_share()?;
        let legacy_metadata =
            self.storage
                .get_share_metadata()
                .ok_or(KeepMobileError::StorageError {
                    msg: "Legacy share missing metadata".into(),
                })?;

        let key = hex::encode(&legacy_metadata.group_pubkey);

        self.storage
            .store_share_by_key(key.clone(), legacy_data, legacy_metadata)?;
        self.storage.set_active_share_key(Some(key.clone()))?;

        Ok(key)
    }
}

pub(crate) fn validate_relay_url(relay_url: &str) -> Result<(), KeepMobileError> {
    let parsed = url::Url::parse(relay_url).map_err(|_| KeepMobileError::InvalidRelayUrl {
        msg: "Invalid URL format".into(),
    })?;

    if parsed.scheme() != "wss" {
        return Err(KeepMobileError::InvalidRelayUrl {
            msg: "Must use wss:// protocol".into(),
        });
    }

    let host = parsed.host_str().ok_or(KeepMobileError::InvalidRelayUrl {
        msg: "Missing host".into(),
    })?;

    if is_internal_host(host) {
        return Err(KeepMobileError::InvalidRelayUrl {
            msg: "Internal addresses not allowed".into(),
        });
    }

    Ok(())
}

fn convert_peer_status(status: keep_frost_net::PeerStatus) -> PeerStatus {
    match status {
        keep_frost_net::PeerStatus::Online => PeerStatus::Online,
        keep_frost_net::PeerStatus::Offline => PeerStatus::Offline,
        keep_frost_net::PeerStatus::Unknown => PeerStatus::Unknown,
    }
}

fn is_internal_host(host: &str) -> bool {
    let host = host.to_lowercase();

    const FORBIDDEN_EXACT: &[&str] = &[
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "[::1]",
        "169.254.169.254",
    ];

    FORBIDDEN_EXACT.contains(&host.as_str())
        || host.ends_with(".local")
        || host.ends_with(".localhost")
        || host.starts_with("127.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("169.254.")
        || is_private_ipv4_range(&host, "100.", 64..=127)
        || is_private_ipv4_range(&host, "172.", 16..=31)
        || is_private_ipv6(&host)
}

fn is_private_ipv4_range(host: &str, prefix: &str, range: std::ops::RangeInclusive<u8>) -> bool {
    host.strip_prefix(prefix)
        .and_then(|rest| rest.split('.').next())
        .and_then(|s| s.parse::<u8>().ok())
        .is_some_and(|octet| range.contains(&octet))
}

fn is_private_ipv6(host: &str) -> bool {
    let normalized = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    if let Ok(addr) = normalized.parse::<std::net::Ipv6Addr>() {
        if let Some(mapped_v4) = addr.to_ipv4_mapped() {
            return mapped_v4.is_loopback() || mapped_v4.is_private() || mapped_v4.is_link_local();
        }
    }

    normalized.starts_with("fc")
        || normalized.starts_with("fd")
        || normalized.starts_with("fe80:")
        || normalized.starts_with("fe80%")
}

fn validate_hex_pubkey(key: &str) -> Result<(), KeepMobileError> {
    if key.len() != 64 {
        return Err(KeepMobileError::InvalidShare {
            msg: "Group pubkey must be 64 hex characters".into(),
        });
    }
    if !key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(KeepMobileError::InvalidShare {
            msg: "Group pubkey must be valid hex".into(),
        });
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}
