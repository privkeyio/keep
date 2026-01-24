// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

mod error;
mod nip55;
mod storage;
mod types;

pub use error::KeepMobileError;
pub use nip55::{Nip55Handler, Nip55Request, Nip55RequestType, Nip55Response};
pub use storage::{SecureStorage, ShareInfo, ShareMetadataInfo};
pub use types::{PeerInfo, PeerStatus, SignRequest, SignRequestMetadata};

use keep_core::frost::{ShareExport, SharePackage};
use keep_frost_net::{KfpNode, KfpNodeEvent, SessionInfo, SigningHooks};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};

uniffi::setup_scaffolding!();

const MAX_PENDING_REQUESTS: usize = 100;
const SIGNING_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

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
    pub(crate) node: Arc<RwLock<Option<KfpNode>>>,
    storage: Arc<dyn SecureStorage>,
    pending_requests: Arc<Mutex<Vec<PendingRequest>>>,
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
                message: format!("Runtime: {}", e),
            })?;

        Ok(Self {
            node: Arc::new(RwLock::new(None)),
            storage,
            pending_requests: Arc::new(Mutex::new(Vec::new())),
            runtime,
        })
    }

    pub fn initialize(&self, relays: Vec<String>) -> Result<(), KeepMobileError> {
        for relay in &relays {
            Self::validate_relay_url(relay)?;
        }

        let share = self.load_share_package()?;

        self.runtime.block_on(async {
            let node = KfpNode::new(share, relays).await?;

            let (request_tx, request_rx) = mpsc::channel(32);
            let hooks = Arc::new(MobileSigningHooks { request_tx });
            node.set_hooks(hooks);

            let event_rx = node.subscribe();
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
        let export = if data.starts_with("kshare") {
            ShareExport::from_bech32(&data)
        } else {
            ShareExport::from_json(&data)
        }
        .map_err(|e| KeepMobileError::InvalidShare {
            message: e.to_string(),
        })?;

        let share =
            export
                .to_share(&passphrase, &name)
                .map_err(|e| KeepMobileError::InvalidShare {
                    message: e.to_string(),
                })?;

        let metadata = ShareMetadataInfo {
            name: share.metadata.name.clone(),
            identifier: share.metadata.identifier,
            threshold: share.metadata.threshold,
            total_shares: share.metadata.total_shares,
            group_pubkey: share.metadata.group_pubkey.to_vec(),
        };

        let stored = StoredShareData {
            metadata_json: serde_json::to_string(&share.metadata).map_err(|e| {
                KeepMobileError::StorageError {
                    message: e.to_string(),
                }
            })?,
            key_package_bytes: share
                .key_package()
                .map_err(|e| KeepMobileError::FrostError {
                    message: e.to_string(),
                })?
                .serialize()
                .map_err(|e| KeepMobileError::FrostError {
                    message: format!("Serialization failed: {}", e),
                })?,
            pubkey_package_bytes: share
                .pubkey_package()
                .map_err(|e| KeepMobileError::FrostError {
                    message: e.to_string(),
                })?
                .serialize()
                .map_err(|e| KeepMobileError::FrostError {
                    message: format!("Serialization failed: {}", e),
                })?,
        };

        let serialized =
            serde_json::to_vec(&stored).map_err(|e| KeepMobileError::StorageError {
                message: e.to_string(),
            })?;

        self.storage.store_share(serialized, metadata.clone())?;

        Ok(ShareInfo {
            name: metadata.name,
            share_index: metadata.identifier,
            threshold: metadata.threshold,
            total_shares: metadata.total_shares,
            group_pubkey: hex::encode(&metadata.group_pubkey),
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
        let share = self.load_share_package()?;
        let export = ShareExport::from_share(&share, &passphrase).map_err(|e| {
            KeepMobileError::FrostError {
                message: e.to_string(),
            }
        })?;
        export.to_bech32().map_err(|e| KeepMobileError::FrostError {
            message: e.to_string(),
        })
    }
}

impl KeepMobile {
    async fn event_listener(
        mut event_rx: broadcast::Receiver<KfpNodeEvent>,
        mut request_rx: mpsc::Receiver<(SessionInfo, mpsc::Sender<bool>)>,
        pending: Arc<Mutex<Vec<PendingRequest>>>,
    ) {
        let mut event_closed = false;
        let mut request_closed = false;

        loop {
            if event_closed && request_closed {
                break;
            }

            tokio::select! {
                result = event_rx.recv(), if !event_closed => {
                    match result {
                        Ok(event) => {
                            let session_id = match event {
                                KfpNodeEvent::SignatureComplete { session_id, .. }
                                | KfpNodeEvent::SigningFailed { session_id, .. } => Some(session_id),
                                _ => None,
                            };
                            if let Some(session_id) = session_id {
                                let id = hex::encode(session_id);
                                pending.lock().await.retain(|r| r.info.id != id);
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            event_closed = true;
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {}
                    }
                }
                result = request_rx.recv(), if !request_closed => {
                    match result {
                        Some((session, response_tx)) => {
                            let mut guard = pending.lock().await;
                            if guard.len() >= MAX_PENDING_REQUESTS {
                                let _ = response_tx.send(false).await;
                                continue;
                            }
                            let request = SignRequest {
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
                            };
                            guard.push(PendingRequest {
                                info: request,
                                response_tx,
                            });
                        }
                        None => {
                            request_closed = true;
                        }
                    }
                }
            }
        }
    }

    fn load_share_package(&self) -> Result<SharePackage, KeepMobileError> {
        let data = self.storage.load_share()?;
        let stored: StoredShareData =
            serde_json::from_slice(&data).map_err(|e| KeepMobileError::InvalidShare {
                message: e.to_string(),
            })?;

        let metadata: keep_core::frost::ShareMetadata = serde_json::from_str(&stored.metadata_json)
            .map_err(|e| KeepMobileError::InvalidShare {
                message: e.to_string(),
            })?;

        let key_package = frost_secp256k1_tr::keys::KeyPackage::deserialize(
            &stored.key_package_bytes,
        )
        .map_err(|e| KeepMobileError::InvalidShare {
            message: format!("Invalid key package: {}", e),
        })?;

        let pubkey_package =
            frost_secp256k1_tr::keys::PublicKeyPackage::deserialize(&stored.pubkey_package_bytes)
                .map_err(|e| KeepMobileError::InvalidShare {
                message: format!("Invalid pubkey package: {}", e),
            })?;

        SharePackage::new(metadata, &key_package, &pubkey_package).map_err(|e| {
            KeepMobileError::FrostError {
                message: e.to_string(),
            }
        })
    }

    fn validate_relay_url(relay_url: &str) -> Result<(), KeepMobileError> {
        let parsed = url::Url::parse(relay_url).map_err(|_| KeepMobileError::InvalidRelayUrl {
            message: "Invalid URL format".into(),
        })?;

        if parsed.scheme() != "wss" {
            return Err(KeepMobileError::InvalidRelayUrl {
                message: "Must use wss:// protocol".into(),
            });
        }

        let host = parsed.host_str().ok_or(KeepMobileError::InvalidRelayUrl {
            message: "Missing host".into(),
        })?;

        if is_internal_host(host) {
            return Err(KeepMobileError::InvalidRelayUrl {
                message: "Internal addresses not allowed".into(),
            });
        }

        Ok(())
    }
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
