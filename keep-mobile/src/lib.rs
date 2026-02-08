// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

mod audit;
mod dkg;
mod error;
mod nip46;
mod nip55;
mod policy;
mod psbt;
mod storage;
mod types;
mod velocity;

pub use audit::{AuditEntry, AuditEventType, AuditLog, AuditStorage};
pub use dkg::{DkgResult, DkgRound1Package, DkgRound2Package, DkgSession};
pub use error::KeepMobileError;
pub use nip46::{
    BunkerApprovalRequest, BunkerCallbacks, BunkerHandler, BunkerLogEvent, BunkerStatus,
};
pub use nip55::{Nip55Handler, Nip55Request, Nip55RequestType, Nip55Response};
pub use policy::{PolicyDecision, PolicyInfo, TransactionContext};
pub use psbt::{PsbtInfo, PsbtInputSighash, PsbtOutputInfo, PsbtParser};
pub use storage::{SecureStorage, ShareInfo, ShareMetadataInfo, StoredShareInfo};
pub use types::{
    DkgConfig, DkgStatus, FrostGenerationResult, GeneratedShareInfo, PeerInfo, PeerStatus,
    SignRequest, SignRequestMetadata, ThresholdConfig,
};

use keep_core::frost::{
    ShareExport, ShareMetadata, SharePackage, ThresholdConfig as CoreThresholdConfig, TrustedDealer,
};
use keep_frost_net::{KfpNode, KfpNodeEvent, SessionInfo, SigningHooks};
use policy::{PolicyBundle, PolicyEvaluator, POLICY_PUBKEY_LEN};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use velocity::VelocityTracker;
use zeroize::{Zeroize, Zeroizing};

uniffi::setup_scaffolding!();

fn init_android_logging() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag("KeepRust"),
        );
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let _ = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(|| LogWriter))
            .try_init();
    });
}

struct LogWriter;
impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(buf);
        log::debug!(target: "KeepFrost", "{}", s.trim_end());
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const MAX_PENDING_REQUESTS: usize = 100;
const SIGNING_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_IMPORT_DATA_SIZE: usize = 64 * 1024;
const MAX_STORED_SHARES: usize = 100;
const MAX_SHARE_NAME_LENGTH: usize = 64;

const POLICY_STORAGE_KEY: &str = "__keep_policy_v1";
const VELOCITY_STORAGE_KEY: &str = "__keep_velocity_v1";
const TRUSTED_WARDENS_KEY: &str = "__keep_trusted_wardens_v1";
const CERT_PINS_STORAGE_KEY: &str = "__keep_cert_pins_v1";

#[derive(uniffi::Record)]
pub struct CertificatePin {
    pub hostname: String,
    pub spki_hash: String,
}

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
    policy: Arc<std::sync::RwLock<PolicyEvaluator>>,
    velocity: Arc<std::sync::Mutex<VelocityTracker>>,
}

struct PendingRequest {
    info: SignRequest,
    response_tx: mpsc::Sender<bool>,
}

#[uniffi::export]
impl KeepMobile {
    #[uniffi::constructor]
    pub fn new(storage: Arc<dyn SecureStorage>) -> Result<Self, KeepMobileError> {
        init_android_logging();
        keep_frost_net::install_default_crypto_provider();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| KeepMobileError::InitializationFailed {
                msg: format!("Runtime: {e}"),
            })?;

        let velocity = Self::load_velocity(&storage)?;
        let velocity = Arc::new(std::sync::Mutex::new(velocity));

        let mut evaluator = PolicyEvaluator::new(velocity.clone());

        if let Ok(wardens) = Self::load_trusted_wardens(&storage) {
            evaluator.set_trusted_wardens(wardens);
        }

        if let Ok(bundle) = Self::load_policy(&storage) {
            if bundle.verify_signature().is_ok()
                && bundle.verify_hash().is_ok()
                && bundle.verify_timestamp().is_ok()
                && bundle
                    .verify_trusted_warden(evaluator.trusted_wardens())
                    .is_ok()
            {
                evaluator.set_policy(bundle);
            }
        }

        let policy = Arc::new(std::sync::RwLock::new(evaluator));

        Ok(Self {
            node: Arc::new(RwLock::new(None)),
            storage,
            pending_requests: Arc::new(Mutex::new(Vec::new())),
            dkg_session: DkgSession::new(),
            runtime,
            policy,
            velocity,
        })
    }

    pub fn initialize(&self, relays: Vec<String>) -> Result<(), KeepMobileError> {
        self.do_initialize(relays, None)
    }

    pub fn initialize_with_proxy(
        &self,
        relays: Vec<String>,
        proxy_host: String,
        proxy_port: u16,
    ) -> Result<(), KeepMobileError> {
        let proxy = parse_loopback_proxy(&proxy_host, proxy_port)?;
        self.do_initialize(relays, Some(proxy))
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
                    msg: format!("Serialization failed: {e}"),
                })?,
            pubkey_package_bytes: share
                .pubkey_package()
                .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?
                .serialize()
                .map_err(|e| KeepMobileError::FrostError {
                    msg: format!("Serialization failed: {e}"),
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

    pub fn import_nsec(
        &self,
        mut hex_key: String,
        name: String,
    ) -> Result<ShareInfo, KeepMobileError> {
        if hex_key.len() != 64 {
            hex_key.zeroize();
            return Err(KeepMobileError::InvalidShare {
                msg: "Key must be exactly 64 hex characters".into(),
            });
        }
        let result = self.do_import_nsec(&hex_key, name);
        hex_key.zeroize();
        result
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
        mut existing_key: String,
        threshold: u16,
        total_shares: u16,
        name: String,
        passphrase: String,
    ) -> Result<FrostGenerationResult, KeepMobileError> {
        Self::validate_share_name(&name)?;

        let mut key_bytes =
            hex::decode(&existing_key).map_err(|e| {
                existing_key.zeroize();
                KeepMobileError::InvalidShare {
                    msg: format!("Invalid hex encoding for existing key: {e}"),
                }
            })?;
        existing_key.zeroize();

        if key_bytes.len() != 32 {
            key_bytes.zeroize();
            return Err(KeepMobileError::InvalidShare {
                msg: "Existing key must be exactly 32 bytes".into(),
            });
        }

        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&key_bytes);
        key_bytes.zeroize();

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
    ) -> Result<Vec<DkgRound2Package>, KeepMobileError> {
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
            self.dkg_session
                .receive_round1_packages(round1_packages)
                .await
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
                    recipient_index: 0,
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

    pub fn import_policy(&self, bundle_hex: String) -> Result<PolicyInfo, KeepMobileError> {
        const MAX_BUNDLE_HEX_LEN: usize = 8192;
        if bundle_hex.len() > MAX_BUNDLE_HEX_LEN {
            return Err(KeepMobileError::InvalidPolicy {
                msg: format!(
                    "Bundle hex too large: {} bytes (max {})",
                    bundle_hex.len(),
                    MAX_BUNDLE_HEX_LEN
                ),
            });
        }

        let bundle_bytes =
            hex::decode(&bundle_hex).map_err(|e| KeepMobileError::InvalidPolicy {
                msg: format!("Invalid hex: {e}"),
            })?;

        let bundle = PolicyBundle::from_bytes(&bundle_bytes)?;
        bundle.verify_signature()?;
        bundle.verify_hash()?;
        bundle.verify_timestamp()?;

        let mut policy = self.policy_write_lock()?;
        bundle.verify_trusted_warden(policy.trusted_wardens())?;
        bundle.verify_version_upgrade(policy.policy())?;

        let info = bundle.to_policy_info();
        policy.set_policy(bundle.clone());
        Self::persist_policy(&self.storage, &bundle)?;

        Ok(info)
    }

    pub fn get_policy_info(&self) -> Option<PolicyInfo> {
        self.policy
            .read()
            .ok()?
            .policy()
            .map(|b| b.to_policy_info())
    }

    pub fn delete_policy(&self) -> Result<(), KeepMobileError> {
        self.policy_write_lock()?.clear_policy();
        let _ = self.storage.delete_share_by_key(POLICY_STORAGE_KEY.into());
        Ok(())
    }

    pub fn evaluate_policy(
        &self,
        ctx: TransactionContext,
    ) -> Result<PolicyDecision, KeepMobileError> {
        self.policy_read_lock()?.evaluate(&ctx)
    }

    pub fn record_policy_transaction(&self, amount_sats: u64) -> Result<(), KeepMobileError> {
        self.policy_read_lock()?.record_transaction(amount_sats)?;
        Self::persist_velocity(&self.storage, &*self.velocity_lock()?)
    }

    pub fn clear_velocity_tracker(&self) -> Result<(), KeepMobileError> {
        let mut velocity = self.velocity_lock()?;
        velocity.clear();
        Self::persist_velocity(&self.storage, &velocity)
    }

    pub fn add_trusted_warden(&self, pubkey_hex: String) -> Result<(), KeepMobileError> {
        let pubkey = parse_warden_pubkey(&pubkey_hex)?;
        let mut policy = self.policy_write_lock()?;
        policy.add_trusted_warden(pubkey);
        Self::persist_trusted_wardens(&self.storage, policy.trusted_wardens())
    }

    pub fn remove_trusted_warden(&self, pubkey_hex: String) -> Result<(), KeepMobileError> {
        let pubkey = parse_warden_pubkey(&pubkey_hex)?;
        let mut policy = self.policy_write_lock()?;
        policy.remove_trusted_warden(&pubkey);
        Self::persist_trusted_wardens(&self.storage, policy.trusted_wardens())
    }

    pub fn list_trusted_wardens(&self) -> Result<Vec<String>, KeepMobileError> {
        let policy = self.policy_read_lock()?;
        Ok(policy.trusted_wardens().iter().map(hex::encode).collect())
    }

    pub fn get_certificate_pins(&self) -> Result<Vec<CertificatePin>, KeepMobileError> {
        Ok(Self::load_cert_pins(&self.storage)?
            .unwrap_or_default()
            .pins()
            .iter()
            .map(|(hostname, hash)| CertificatePin {
                hostname: hostname.clone(),
                spki_hash: hex::encode(hash),
            })
            .collect())
    }

    pub fn clear_certificate_pins(&self) -> Result<(), KeepMobileError> {
        self.storage
            .delete_share_by_key(CERT_PINS_STORAGE_KEY.into())
    }

    pub fn clear_certificate_pin(&self, hostname: String) -> Result<(), KeepMobileError> {
        let mut pins = Self::load_cert_pins(&self.storage)?.unwrap_or_default();
        pins.remove_pin(&hostname);
        Self::persist_cert_pins(&self.storage, &pins)
    }
}

impl KeepMobile {
    fn do_initialize(
        &self,
        relays: Vec<String>,
        proxy: Option<std::net::SocketAddr>,
    ) -> Result<(), KeepMobileError> {
        for relay in &relays {
            validate_relay_url(relay)?;
        }

        let share = self.load_share_package()?;

        self.runtime.block_on(async {
            let mut pins = Self::load_cert_pins(&self.storage)?.unwrap_or_default();
            for relay in &relays {
                keep_frost_net::verify_relay_certificate(relay, &mut pins).await?;
            }
            Self::persist_cert_pins(&self.storage, &pins)?;

            let node = match proxy {
                Some(addr) => KfpNode::new_with_proxy(share, relays, addr).await?,
                None => KfpNode::new(share, relays).await?,
            };

            let (request_tx, request_rx) = mpsc::channel(32);
            let hooks = Arc::new(MobileSigningHooks { request_tx });
            node.set_hooks(hooks);

            let event_rx = node.subscribe();
            let node = Arc::new(node);
            let pending = self.pending_requests.clone();
            tokio::spawn(async move {
                Self::event_listener(event_rx, request_rx, pending).await;
            });

            let run_node = node.clone();
            tokio::spawn(async move {
                if let Err(e) = run_node.run().await {
                    log::error!(target: "KeepFrost", "Node run failed: {e}");
                }
            });

            *self.node.write().await = Some(node);
            Ok(())
        })
    }

    fn do_import_nsec(&self, hex_key: &str, name: String) -> Result<ShareInfo, KeepMobileError> {
        Self::validate_share_name(&name)?;

        let share_count = self.storage.list_all_shares().len();
        if share_count >= MAX_STORED_SHARES {
            return Err(KeepMobileError::StorageError {
                msg: "Maximum number of shares reached".into(),
            });
        }

        let key_bytes =
            Zeroizing::new(
                hex::decode(hex_key).map_err(|_| KeepMobileError::InvalidShare {
                    msg: "Invalid hex encoding".into(),
                })?,
            );

        if key_bytes.len() != 32 {
            return Err(KeepMobileError::InvalidShare {
                msg: "Key must be exactly 32 bytes".into(),
            });
        }

        let signing_key =
            frost_secp256k1_tr::SigningKey::deserialize(&key_bytes).map_err(|e| {
                KeepMobileError::FrostError {
                    msg: format!("Invalid signing key: {e}"),
                }
            })?;
        let vk = frost_secp256k1_tr::VerifyingKey::from(&signing_key);
        let vk_bytes = vk.serialize().map_err(|e| KeepMobileError::FrostError {
            msg: format!("Failed to serialize verifying key: {e}"),
        })?;
        let signing_key_bytes = signing_key.serialize();

        let identifier = frost_secp256k1_tr::Identifier::try_from(1u16).map_err(|e| {
            KeepMobileError::FrostError {
                msg: format!("Failed to create identifier: {e}"),
            }
        })?;

        let signing_share =
            frost_secp256k1_tr::keys::SigningShare::deserialize(&signing_key_bytes).map_err(
                |e| KeepMobileError::FrostError {
                    msg: format!("Failed to create signing share: {e}"),
                },
            )?;

        let verifying_share = frost_secp256k1_tr::keys::VerifyingShare::deserialize(&vk_bytes)
            .map_err(|e| KeepMobileError::FrostError {
                msg: format!("Failed to create verifying share: {e}"),
            })?;

        let key_package = frost_secp256k1_tr::keys::KeyPackage::new(
            identifier,
            signing_share,
            verifying_share,
            frost_secp256k1_tr::VerifyingKey::deserialize(&vk_bytes).map_err(|e| {
                KeepMobileError::FrostError {
                    msg: format!("Serialization failed: {e}"),
                }
            })?,
            1,
        );

        let mut verifying_shares = std::collections::BTreeMap::new();
        verifying_shares.insert(identifier, verifying_share);
        let pubkey_package = frost_secp256k1_tr::keys::PublicKeyPackage::new(verifying_shares, vk);

        let group_pubkey: [u8; 32] = match vk_bytes.len() {
            33 => vk_bytes[1..33].try_into().map_err(|_| KeepMobileError::FrostError {
                msg: "Failed to extract group pubkey from verifying key".into(),
            })?,
            len => {
                return Err(KeepMobileError::FrostError {
                    msg: format!("Invalid group pubkey length: {len}"),
                })
            }
        };

        let metadata = ShareMetadata::new(1, 1, 1, group_pubkey, name);

        let metadata_info = ShareMetadataInfo {
            name: metadata.name.clone(),
            identifier: metadata.identifier,
            threshold: metadata.threshold,
            total_shares: metadata.total_shares,
            group_pubkey: metadata.group_pubkey.to_vec(),
        };

        let stored = StoredShareData {
            metadata_json: serde_json::to_string(&metadata)
                .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?,
            key_package_bytes: key_package.serialize().map_err(|e| {
                KeepMobileError::FrostError {
                    msg: format!("Serialization failed: {e}"),
                }
            })?,
            pubkey_package_bytes: pubkey_package.serialize().map_err(|e| {
                KeepMobileError::FrostError {
                    msg: format!("Serialization failed: {e}"),
                }
            })?,
        };

        let serialized = serde_json::to_vec(&stored)
            .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?;

        let group_pubkey_hex = hex::encode(&metadata_info.group_pubkey);
        self.storage.store_share_by_key(
            group_pubkey_hex.clone(),
            serialized,
            metadata_info.clone(),
        )?;
        self.storage
            .set_active_share_key(Some(group_pubkey_hex.clone()))?;

        Ok(ShareInfo {
            name: metadata_info.name,
            share_index: metadata_info.identifier,
            threshold: metadata_info.threshold,
            total_shares: metadata_info.total_shares,
            group_pubkey: group_pubkey_hex,
        })
    }

    fn policy_read_lock(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, PolicyEvaluator>, KeepMobileError> {
        self.policy
            .read()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "Policy lock poisoned".into(),
            })
    }

    fn policy_write_lock(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, PolicyEvaluator>, KeepMobileError> {
        self.policy
            .write()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "Policy lock poisoned".into(),
            })
    }

    fn velocity_lock(&self) -> Result<std::sync::MutexGuard<'_, VelocityTracker>, KeepMobileError> {
        self.velocity
            .lock()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "Velocity lock poisoned".into(),
            })
    }
}

impl KeepMobile {
    fn validate_share_name(name: &str) -> Result<(), KeepMobileError> {
        if name.chars().count() > MAX_SHARE_NAME_LENGTH {
            return Err(KeepMobileError::InvalidShare {
                msg: format!(
                    "Share name exceeds maximum length of {MAX_SHARE_NAME_LENGTH} characters"
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

    fn load_cert_pins(
        storage: &Arc<dyn SecureStorage>,
    ) -> Result<Option<keep_frost_net::CertificatePinSet>, KeepMobileError> {
        let data = match storage.load_share_by_key(CERT_PINS_STORAGE_KEY.into()) {
            Ok(data) => data,
            Err(KeepMobileError::StorageNotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        let map: HashMap<String, String> =
            serde_json::from_slice(&data).map_err(|e| KeepMobileError::StorageError {
                msg: format!("Failed to deserialize cert pins: {e}"),
            })?;

        let mut pins = keep_frost_net::CertificatePinSet::new();
        let mut malformed = Vec::new();
        for (hostname, hash_hex) in map {
            match hex::decode(&hash_hex) {
                Ok(bytes) => match <[u8; 32]>::try_from(bytes) {
                    Ok(hash) => pins.add_pin(hostname, hash),
                    Err(bytes) => {
                        malformed.push(format!("{}: invalid length {}", hostname, bytes.len()))
                    }
                },
                Err(e) => malformed.push(format!("{hostname}: hex decode failed: {e}")),
            }
        }
        if malformed.is_empty() {
            Ok(Some(pins))
        } else {
            Err(KeepMobileError::StorageError {
                msg: format!(
                    "{}: malformed pins: {}",
                    CERT_PINS_STORAGE_KEY,
                    malformed.join(", ")
                ),
            })
        }
    }

    fn persist_cert_pins(
        storage: &Arc<dyn SecureStorage>,
        pins: &keep_frost_net::CertificatePinSet,
    ) -> Result<(), KeepMobileError> {
        let map: HashMap<String, String> = pins
            .pins()
            .iter()
            .map(|(k, v)| (k.clone(), hex::encode(v)))
            .collect();
        let data = serde_json::to_vec(&map).map_err(|e| KeepMobileError::StorageError {
            msg: format!("Failed to serialize cert pins: {e}"),
        })?;
        let metadata = ShareMetadataInfo {
            name: "cert_pins".into(),
            identifier: 0,
            threshold: 0,
            total_shares: 0,
            group_pubkey: vec![],
        };
        storage.store_share_by_key(CERT_PINS_STORAGE_KEY.into(), data, metadata)
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
            msg: format!("Invalid key package: {e}"),
        })?;

        let pubkey_package =
            frost_secp256k1_tr::keys::PublicKeyPackage::deserialize(&stored.pubkey_package_bytes)
                .map_err(|e| KeepMobileError::InvalidShare {
                msg: format!("Invalid pubkey package: {e}"),
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

    fn load_policy(storage: &Arc<dyn SecureStorage>) -> Result<PolicyBundle, KeepMobileError> {
        let data = storage.load_share_by_key(POLICY_STORAGE_KEY.into())?;
        serde_json::from_slice(&data).map_err(|e| KeepMobileError::InvalidPolicy {
            msg: format!("Failed to deserialize policy: {e}"),
        })
    }

    fn persist_policy(
        storage: &Arc<dyn SecureStorage>,
        bundle: &PolicyBundle,
    ) -> Result<(), KeepMobileError> {
        let data = serde_json::to_vec(bundle).map_err(|e| KeepMobileError::StorageError {
            msg: format!("Failed to serialize policy: {e}"),
        })?;
        let metadata = ShareMetadataInfo {
            name: "policy".into(),
            identifier: 0,
            threshold: 0,
            total_shares: 0,
            group_pubkey: vec![],
        };
        storage.store_share_by_key(POLICY_STORAGE_KEY.into(), data, metadata)
    }

    fn load_velocity(storage: &Arc<dyn SecureStorage>) -> Result<VelocityTracker, KeepMobileError> {
        match storage.load_share_by_key(VELOCITY_STORAGE_KEY.into()) {
            Ok(data) => {
                VelocityTracker::from_bytes(&data).map_err(|e| KeepMobileError::StorageError {
                    msg: format!("Failed to deserialize velocity: {e}"),
                })
            }
            Err(_) => Ok(VelocityTracker::new()),
        }
    }

    fn persist_velocity(
        storage: &Arc<dyn SecureStorage>,
        tracker: &VelocityTracker,
    ) -> Result<(), KeepMobileError> {
        let data = tracker
            .to_bytes()
            .map_err(|e| KeepMobileError::StorageError {
                msg: format!("Failed to serialize velocity: {e}"),
            })?;
        let metadata = ShareMetadataInfo {
            name: "velocity".into(),
            identifier: 0,
            threshold: 0,
            total_shares: 0,
            group_pubkey: vec![],
        };
        storage.store_share_by_key(VELOCITY_STORAGE_KEY.into(), data, metadata)
    }

    fn load_trusted_wardens(
        storage: &Arc<dyn SecureStorage>,
    ) -> Result<HashSet<[u8; POLICY_PUBKEY_LEN]>, KeepMobileError> {
        let data = storage.load_share_by_key(TRUSTED_WARDENS_KEY.into())?;
        let hex_list: Vec<String> =
            serde_json::from_slice(&data).map_err(|e| KeepMobileError::StorageError {
                msg: format!("Failed to deserialize trusted wardens: {e}"),
            })?;

        let mut wardens = HashSet::new();
        for hex_str in hex_list {
            let bytes = hex::decode(&hex_str).map_err(|e| KeepMobileError::StorageError {
                msg: format!("Invalid warden pubkey hex: {e}"),
            })?;
            if bytes.len() == POLICY_PUBKEY_LEN {
                let mut arr = [0u8; POLICY_PUBKEY_LEN];
                arr.copy_from_slice(&bytes);
                wardens.insert(arr);
            }
        }
        Ok(wardens)
    }

    fn persist_trusted_wardens(
        storage: &Arc<dyn SecureStorage>,
        wardens: &HashSet<[u8; POLICY_PUBKEY_LEN]>,
    ) -> Result<(), KeepMobileError> {
        let hex_list: Vec<String> = wardens.iter().map(hex::encode).collect();
        let data = serde_json::to_vec(&hex_list).map_err(|e| KeepMobileError::StorageError {
            msg: format!("Failed to serialize trusted wardens: {e}"),
        })?;
        let metadata = ShareMetadataInfo {
            name: "trusted_wardens".into(),
            identifier: 0,
            threshold: 0,
            total_shares: 0,
            group_pubkey: vec![],
        };
        storage.store_share_by_key(TRUSTED_WARDENS_KEY.into(), data, metadata)
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

fn parse_loopback_proxy(host: &str, port: u16) -> Result<std::net::SocketAddr, KeepMobileError> {
    let ip: std::net::IpAddr = match host {
        "localhost" => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        _ => host.parse().map_err(|_| KeepMobileError::InvalidRelayUrl {
            msg: "Invalid proxy host".into(),
        })?,
    };

    if !ip.is_loopback() {
        return Err(KeepMobileError::InvalidRelayUrl {
            msg: "Proxy must be a loopback address".into(),
        });
    }

    Ok(std::net::SocketAddr::new(ip, port))
}

fn parse_warden_pubkey(pubkey_hex: &str) -> Result<[u8; POLICY_PUBKEY_LEN], KeepMobileError> {
    let pubkey_bytes = hex::decode(pubkey_hex).map_err(|e| KeepMobileError::InvalidPolicy {
        msg: format!("Invalid hex: {e}"),
    })?;

    pubkey_bytes
        .try_into()
        .map_err(|_| KeepMobileError::InvalidPolicy {
            msg: format!("Warden pubkey must be {POLICY_PUBKEY_LEN} bytes"),
        })
}
