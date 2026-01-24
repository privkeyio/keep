// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

mod error;
mod storage;
mod types;

pub use error::KeepMobileError;
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
        match self.request_tx.try_send((session.clone(), response_tx)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(keep_frost_net::FrostNetError::Session(
                    "Request queue full".into(),
                ));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(keep_frost_net::FrostNetError::Session(
                    "Channel closed".into(),
                ));
            }
        }

        let rt = tokio::runtime::Handle::try_current()
            .or_else(|_| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                    .map(|rt| rt.handle().clone())
            })
            .map_err(|_| keep_frost_net::FrostNetError::Session("No runtime".into()))?;

        let result = rt.block_on(async {
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
    node: Arc<RwLock<Option<KfpNode>>>,
    storage: Arc<dyn SecureStorage>,
    pending_requests: Arc<Mutex<Vec<PendingRequest>>>,
    runtime: tokio::runtime::Runtime,
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
        let export = match ShareExport::from_bech32(&data) {
            Ok(exp) => exp,
            Err(bech32_err) => ShareExport::from_json(&data).map_err(|json_err| {
                KeepMobileError::InvalidShare {
                    message: format!("bech32: {}, json: {}", bech32_err, json_err),
                }
            })?,
        };

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
            group_pubkey: hex::encode(share.metadata.group_pubkey),
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
            group_pubkey: metadata.group_pubkey,
        })
    }

    pub fn get_pending_requests(&self) -> Result<Vec<SignRequest>, KeepMobileError> {
        Ok(self.runtime.block_on(async {
            self.pending_requests
                .lock()
                .await
                .iter()
                .map(|r| r.info.clone())
                .collect()
        }))
    }

    pub fn approve_request(&self, request_id: String) -> Result<(), KeepMobileError> {
        self.runtime.block_on(async {
            let mut pending = self.pending_requests.lock().await;
            let idx = pending
                .iter()
                .position(|r| r.info.id == request_id)
                .ok_or(KeepMobileError::RequestNotFound)?;

            let request = pending.remove(idx);
            request
                .response_tx
                .send(true)
                .await
                .map_err(|_| KeepMobileError::Timeout)
        })
    }

    pub fn reject_request(&self, request_id: String) -> Result<(), KeepMobileError> {
        self.runtime.block_on(async {
            let mut pending = self.pending_requests.lock().await;
            let idx = pending
                .iter()
                .position(|r| r.info.id == request_id)
                .ok_or(KeepMobileError::RequestNotFound)?;

            let request = pending.remove(idx);
            request
                .response_tx
                .send(false)
                .await
                .map_err(|_| KeepMobileError::Timeout)
        })
    }

    pub fn get_peers(&self) -> Result<Vec<PeerInfo>, KeepMobileError> {
        Ok(self.runtime.block_on(async {
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
        }))
    }

    pub fn has_share(&self) -> Result<bool, KeepMobileError> {
        Ok(self.storage.has_share())
    }

    pub fn get_share_info(&self) -> Result<Option<ShareInfo>, KeepMobileError> {
        Ok(self.storage.get_share_metadata().map(|m| ShareInfo {
            name: m.name,
            share_index: m.identifier,
            threshold: m.threshold,
            total_shares: m.total_shares,
            group_pubkey: m.group_pubkey,
        }))
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
        loop {
            tokio::select! {
                Ok(event) = event_rx.recv() => {
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
                Some((session, response_tx)) = request_rx.recv() => {
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

    fn validate_relay_url(url_str: &str) -> Result<(), KeepMobileError> {
        let parsed = url::Url::parse(url_str).map_err(|e| KeepMobileError::InvalidRelayUrl {
            message: format!("Invalid URL: {}", e),
        })?;

        if parsed.scheme() != "wss" {
            return Err(KeepMobileError::InvalidRelayUrl {
                message: "Must use wss:// protocol".into(),
            });
        }

        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(KeepMobileError::InvalidRelayUrl {
                message: "Userinfo not allowed in relay URL".into(),
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
    use std::net::IpAddr;

    const FORBIDDEN_EXACT: &[&str] = &["localhost"];

    if FORBIDDEN_EXACT.contains(&host) {
        return true;
    }

    let stripped = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);

    if let Ok(addr) = stripped.parse::<IpAddr>() {
        return match addr {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || is_unique_local(&v6)
                    || is_unicast_link_local(&v6)
            }
        };
    }

    false
}

fn is_unique_local(addr: &std::net::Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

fn is_unicast_link_local(addr: &std::net::Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}
