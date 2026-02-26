// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

mod audit;
mod dkg;
mod error;
mod network;
mod nip46;
mod nip55;
mod persistence;
mod policy;
mod psbt;
mod storage;
mod types;
mod velocity;

pub use audit::{AuditEntry, AuditEventType, AuditLog, AuditStorage};
pub use dkg::{DkgResult, DkgRound1Package, DkgRound2Package, DkgSession};
pub use error::KeepMobileError;
pub use nip46::{
    parse_bunker_url, BunkerApprovalRequest, BunkerCallbacks, BunkerHandler, BunkerLogEvent,
    BunkerStatus, ParsedBunkerUrl,
};
pub use nip55::{Nip55Handler, Nip55Request, Nip55RequestType, Nip55Response};
pub use policy::{PolicyDecision, PolicyInfo, TransactionContext};
pub use psbt::{PsbtInfo, PsbtInputSighash, PsbtOutputInfo, PsbtParser};
pub use storage::{SecureStorage, ShareInfo, ShareMetadataInfo, StoredShareInfo};
pub use types::{
    AnnouncedXpubInfo, DescriptorProposal, DkgConfig, DkgStatus, FrostGenerationResult,
    GeneratedShareInfo, KeyHealthStatusInfo, PeerInfo, PeerStatus, RecoveryTierConfig, SignRequest,
    SignRequestMetadata, ThresholdConfig, WalletDescriptorInfo,
};

use keep_core::frost::{
    ShareExport, ShareMetadata, SharePackage, ThresholdConfig as CoreThresholdConfig, TrustedDealer,
};
use keep_frost_net::{KfpNode, KfpNodeEvent, SessionInfo, SigningHooks};
use network::{constant_time_eq, convert_peer_status, parse_loopback_proxy, validate_hex_pubkey};
use policy::{PolicyBundle, PolicyEvaluator};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use velocity::VelocityTracker;
use zeroize::{Zeroize, Zeroizing};

uniffi::setup_scaffolding!();

fn init_logging() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        #[cfg(target_os = "android")]
        let _ = tracing_subscriber::registry()
            .with(tracing_android::layer("KeepRust").unwrap())
            .try_init();

        #[cfg(not(target_os = "android"))]
        let _ = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .try_init();
    });
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
const DESCRIPTOR_INDEX_KEY: &str = "__keep_descriptor_index_v1";
const DESCRIPTOR_KEY_PREFIX: &str = "__keep_descriptor_";
const HEALTH_STATUS_INDEX_KEY: &str = "__keep_health_index_v1";
const HEALTH_STATUS_KEY_PREFIX: &str = "__keep_health_";
const DESCRIPTOR_SESSION_TIMEOUT: Duration = Duration::from_secs(600);

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

#[uniffi::export(with_foreign)]
pub trait HealthCallbacks: Send + Sync {
    fn on_health_check_complete(
        &self,
        responsive: Vec<u16>,
        unresponsive: Vec<u16>,
    ) -> Result<(), KeepMobileError>;
}

#[uniffi::export(with_foreign)]
pub trait DescriptorCallbacks: Send + Sync {
    fn on_proposed(&self, session_id: String) -> Result<(), KeepMobileError>;
    fn on_contribution_needed(&self, proposal: DescriptorProposal) -> Result<(), KeepMobileError>;
    fn on_contributed(&self, session_id: String, share_index: u16) -> Result<(), KeepMobileError>;
    fn on_complete(
        &self,
        session_id: String,
        external_descriptor: String,
        internal_descriptor: String,
    ) -> Result<(), KeepMobileError>;
    fn on_failed(&self, session_id: String, error: String) -> Result<(), KeepMobileError>;
    fn on_xpub_announced(
        &self,
        share_index: u16,
        xpubs: Vec<AnnouncedXpubInfo>,
    ) -> Result<(), KeepMobileError>;
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
    descriptor_callbacks: Arc<RwLock<Option<Arc<dyn DescriptorCallbacks>>>>,
    health_callbacks: Arc<RwLock<Option<Arc<dyn HealthCallbacks>>>>,
    descriptor_networks: Arc<std::sync::Mutex<HashMap<[u8; 32], String>>>,
    pending_contributions: Arc<std::sync::Mutex<HashMap<[u8; 32], PendingContribution>>>,
}

struct PendingRequest {
    info: SignRequest,
    response_tx: mpsc::Sender<bool>,
}

#[derive(Clone)]
struct PendingContribution {
    network: String,
    initiator_pubkey: nostr_sdk::PublicKey,
    created_at: std::time::Instant,
}

struct DescriptorContext {
    callbacks: Arc<RwLock<Option<Arc<dyn DescriptorCallbacks>>>>,
    storage: Arc<dyn SecureStorage>,
    node: Arc<KfpNode>,
    networks: Arc<std::sync::Mutex<HashMap<[u8; 32], String>>>,
    pending: Arc<std::sync::Mutex<HashMap<[u8; 32], PendingContribution>>>,
}

#[uniffi::export]
impl KeepMobile {
    #[uniffi::constructor]
    pub fn new(storage: Arc<dyn SecureStorage>) -> Result<Self, KeepMobileError> {
        init_logging();
        keep_frost_net::install_default_crypto_provider();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| KeepMobileError::InitializationFailed {
                msg: format!("Runtime: {e}"),
            })?;

        let velocity = persistence::load_velocity(&storage)?;
        let velocity = Arc::new(std::sync::Mutex::new(velocity));

        let mut evaluator = PolicyEvaluator::new(velocity.clone());

        if let Ok(wardens) = persistence::load_trusted_wardens(&storage) {
            evaluator.set_trusted_wardens(wardens);
        }

        if let Ok(bundle) = persistence::load_policy(&storage) {
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
            descriptor_callbacks: Arc::new(RwLock::new(None)),
            health_callbacks: Arc::new(RwLock::new(None)),
            descriptor_networks: Arc::new(std::sync::Mutex::new(HashMap::new())),
            pending_contributions: Arc::new(std::sync::Mutex::new(HashMap::new())),
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

        self.store_share_package(&share)
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

        if is_active {
            self.storage.set_active_share_key(None)?;
            self.runtime.block_on(async {
                *self.node.write().await = None;
            });
        }

        self.storage.delete_share_by_key(group_pubkey)?;

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
        let passphrase = Zeroizing::new(passphrase);
        let name_result = Self::validate_share_name(&name);
        let key_result = hex::decode(&existing_key).map_err(|_| KeepMobileError::InvalidShare {
            msg: "Invalid hex encoding for existing key".into(),
        });
        existing_key.zeroize();
        name_result?;
        let mut key_bytes = key_result?;

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
        let passphrase = Zeroizing::new(passphrase);
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
        persistence::persist_policy(&self.storage, &bundle)?;

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
        persistence::persist_velocity(&self.storage, &*self.velocity_lock()?)
    }

    pub fn clear_velocity_tracker(&self) -> Result<(), KeepMobileError> {
        let mut velocity = self.velocity_lock()?;
        velocity.clear();
        persistence::persist_velocity(&self.storage, &velocity)
    }

    pub fn add_trusted_warden(&self, pubkey_hex: String) -> Result<(), KeepMobileError> {
        let pubkey = network::parse_warden_pubkey(&pubkey_hex)?;
        let mut policy = self.policy_write_lock()?;
        policy.add_trusted_warden(pubkey);
        persistence::persist_trusted_wardens(&self.storage, policy.trusted_wardens())
    }

    pub fn remove_trusted_warden(&self, pubkey_hex: String) -> Result<(), KeepMobileError> {
        let pubkey = network::parse_warden_pubkey(&pubkey_hex)?;
        let mut policy = self.policy_write_lock()?;
        policy.remove_trusted_warden(&pubkey);
        persistence::persist_trusted_wardens(&self.storage, policy.trusted_wardens())
    }

    pub fn list_trusted_wardens(&self) -> Result<Vec<String>, KeepMobileError> {
        let policy = self.policy_read_lock()?;
        Ok(policy.trusted_wardens().iter().map(hex::encode).collect())
    }

    pub fn get_certificate_pins(&self) -> Result<Vec<CertificatePin>, KeepMobileError> {
        Ok(persistence::load_cert_pins(&self.storage)?
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
        let mut pins = persistence::load_cert_pins(&self.storage)?.unwrap_or_default();
        pins.remove_pin(&hostname);
        persistence::persist_cert_pins(&self.storage, &pins)
    }

    pub fn wallet_descriptor_list(&self) -> Vec<WalletDescriptorInfo> {
        persistence::load_descriptors(&self.storage)
    }

    pub fn wallet_descriptor_export(
        &self,
        group_pubkey: String,
        format: String,
    ) -> Result<String, KeepMobileError> {
        validate_hex_pubkey(&group_pubkey)?;

        let desc = persistence::load_descriptor(&self.storage, &group_pubkey)?;

        match format.as_str() {
            "sparrow" => {
                let json = serde_json::json!({
                    "descriptor": desc.external_descriptor,
                    "internal_descriptor": desc.internal_descriptor,
                    "network": desc.network,
                });
                serde_json::to_string_pretty(&json)
                    .map_err(|e| KeepMobileError::Serialization { msg: e.to_string() })
            }
            "raw" => Ok(desc.external_descriptor),
            _ => Err(KeepMobileError::NotSupported {
                msg: format!("Unknown export format: {format}"),
            }),
        }
    }

    pub fn wallet_descriptor_delete(&self, group_pubkey: String) -> Result<(), KeepMobileError> {
        validate_hex_pubkey(&group_pubkey)?;
        persistence::delete_descriptor(&self.storage, &group_pubkey)
    }

    pub fn wallet_descriptor_set_callbacks(&self, callbacks: Arc<dyn DescriptorCallbacks>) {
        self.runtime.block_on(async {
            *self.descriptor_callbacks.write().await = Some(callbacks);
        });
    }

    pub fn set_health_callbacks(&self, callbacks: Arc<dyn HealthCallbacks>) {
        self.runtime.block_on(async {
            *self.health_callbacks.write().await = Some(callbacks);
        });
    }

    pub fn health_check(&self, timeout_secs: u64) -> Result<Vec<u16>, KeepMobileError> {
        if timeout_secs == 0 || timeout_secs > 300 {
            return Err(KeepMobileError::InvalidInput {
                msg: format!("timeout_secs must be between 1 and 300, got {timeout_secs}"),
            });
        }
        self.runtime.block_on(async {
            let node_guard = self.node.read().await;
            let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;

            let group_pubkey = hex::encode(node.group_pubkey());

            let result = node
                .health_check(Duration::from_secs(timeout_secs))
                .await
                .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?;

            if let Some(cb) = self.health_callbacks.read().await.as_ref() {
                if let Err(e) = cb.on_health_check_complete(
                    result.responsive.clone(),
                    result.unresponsive.clone(),
                ) {
                    tracing::warn!("Health check callback failed: {e}");
                }
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            for (idx, responsive) in result
                .responsive
                .iter()
                .map(|&idx| (idx, true))
                .chain(result.unresponsive.iter().map(|&idx| (idx, false)))
            {
                let existing_created_at =
                    persistence::existing_created_at(&self.storage, &group_pubkey, idx);
                if let Err(e) = persistence::persist_health_status(
                    &self.storage,
                    &KeyHealthStatusInfo {
                        group_pubkey: group_pubkey.clone(),
                        share_index: idx,
                        last_check_timestamp: now,
                        responsive,
                        created_at: existing_created_at.unwrap_or(now),
                        is_stale: false,
                        is_critical: false,
                    },
                ) {
                    tracing::warn!(
                        group_pubkey = %group_pubkey,
                        share_index = %idx,
                        error = %e,
                        "Failed to persist health status"
                    );
                }
            }

            Ok(result.responsive)
        })
    }

    pub fn health_status_list(&self) -> Vec<KeyHealthStatusInfo> {
        persistence::load_health_statuses(&self.storage)
    }

    pub fn wallet_descriptor_propose(
        &self,
        network: String,
        tiers: Vec<RecoveryTierConfig>,
    ) -> Result<String, KeepMobileError> {
        self.wallet_descriptor_propose_with_timeout(network, tiers, None)
    }

    pub fn wallet_descriptor_propose_with_timeout(
        &self,
        network: String,
        tiers: Vec<RecoveryTierConfig>,
        timeout_secs: Option<u64>,
    ) -> Result<String, KeepMobileError> {
        if !keep_frost_net::VALID_NETWORKS.contains(&network.as_str()) {
            return Err(KeepMobileError::NetworkError {
                msg: format!("Invalid network: {network}"),
            });
        }

        self.runtime.block_on(async {
            let node_guard = self.node.read().await;
            let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;

            let share_info = self
                .storage
                .get_share_metadata()
                .ok_or(KeepMobileError::NotInitialized)?;

            let policy = build_wallet_policy(&tiers, share_info.total_shares)?;

            let (xpub, fingerprint) = node
                .derive_account_xpub(&network)
                .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?;

            validate_xpub_network(&xpub, &network)?;

            let session_id = node
                .request_descriptor_with_timeout(
                    policy,
                    &network,
                    &xpub,
                    &fingerprint,
                    timeout_secs,
                )
                .await
                .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?;

            self.descriptor_networks
                .lock()
                .map_err(|_| KeepMobileError::StorageError {
                    msg: "Descriptor networks lock poisoned".into(),
                })?
                .insert(session_id, network);

            Ok(hex::encode(session_id))
        })
    }

    pub fn wallet_descriptor_cancel(&self, session_id: String) -> Result<(), KeepMobileError> {
        let id = parse_session_id(&session_id)?;
        clear_descriptor_state(&self.descriptor_networks, &self.pending_contributions, &id);

        self.runtime.block_on(async {
            let node_guard = self.node.read().await;
            if let Some(node) = node_guard.as_ref() {
                node.cancel_descriptor_session(&id);
            }
        });
        Ok(())
    }

    pub fn wallet_descriptor_approve_contribution(
        &self,
        session_id: String,
    ) -> Result<(), KeepMobileError> {
        let id = parse_session_id(&session_id)?;

        let pending = {
            let guard =
                self.pending_contributions
                    .lock()
                    .map_err(|_| KeepMobileError::StorageError {
                        msg: "Pending contributions lock poisoned".into(),
                    })?;
            guard
                .get(&id)
                .filter(|c| c.created_at.elapsed() < DESCRIPTOR_SESSION_TIMEOUT)
                .cloned()
                .ok_or(KeepMobileError::Timeout)?
        };

        self.runtime.block_on(async {
            let node_guard = self.node.read().await;
            let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;

            let (xpub, fingerprint) = node
                .derive_account_xpub(&pending.network)
                .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?;

            validate_xpub_network(&xpub, &pending.network)?;

            node.contribute_descriptor(id, &pending.initiator_pubkey, &xpub, &fingerprint)
                .await
                .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?;

            Ok::<(), KeepMobileError>(())
        })?;

        self.pending_contributions
            .lock()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "Pending contributions lock poisoned".into(),
            })?
            .remove(&id);

        Ok(())
    }

    pub fn wallet_announce_xpubs(
        &self,
        xpubs: Vec<AnnouncedXpubInfo>,
    ) -> Result<(), KeepMobileError> {
        if xpubs.is_empty() {
            return Err(KeepMobileError::InvalidPolicy {
                msg: "empty xpub list".into(),
            });
        }
        let announced: Vec<keep_frost_net::AnnouncedXpub> = xpubs
            .into_iter()
            .map(|x| keep_frost_net::AnnouncedXpub {
                xpub: x.xpub,
                fingerprint: x.fingerprint,
                label: x.label,
            })
            .collect();

        self.runtime.block_on(async {
            let node_guard = self.node.read().await;
            let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;
            node.announce_xpubs(announced)
                .await
                .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?;
            Ok(())
        })
    }

    pub fn wallet_get_peer_recovery_xpubs(
        &self,
        share_index: u16,
    ) -> Result<Option<Vec<AnnouncedXpubInfo>>, KeepMobileError> {
        self.runtime.block_on(async {
            let node_guard = self.node.read().await;
            let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;
            Ok(node.get_peer_recovery_xpubs(share_index).map(|xpubs| {
                xpubs
                    .into_iter()
                    .map(|x| AnnouncedXpubInfo {
                        xpub: x.xpub,
                        fingerprint: x.fingerprint,
                        label: x.label,
                    })
                    .collect()
            }))
        })
    }
}

fn clear_descriptor_state(
    nets: &std::sync::Mutex<HashMap<[u8; 32], String>>,
    pending: &std::sync::Mutex<HashMap<[u8; 32], PendingContribution>>,
    session_id: &[u8; 32],
) {
    if let Ok(mut n) = nets.lock() {
        n.remove(session_id);
    }
    if let Ok(mut p) = pending.lock() {
        p.remove(session_id);
    }
}

fn parse_session_id(hex: &str) -> Result<[u8; 32], KeepMobileError> {
    let bytes = hex::decode(hex).map_err(|_| KeepMobileError::InvalidSession)?;
    bytes
        .try_into()
        .map_err(|_| KeepMobileError::InvalidSession)
}

fn validate_xpub_network(xpub: &str, network: &str) -> Result<(), KeepMobileError> {
    let expected_prefix = match network {
        "bitcoin" => "xpub",
        "testnet" | "signet" | "regtest" => "tpub",
        _ => return Ok(()),
    };
    if !xpub.starts_with(expected_prefix) {
        return Err(KeepMobileError::FrostError {
            msg: format!("xpub prefix mismatch: expected {expected_prefix}* for network {network}"),
        });
    }
    Ok(())
}

fn build_wallet_policy(
    tiers: &[RecoveryTierConfig],
    total_shares: u16,
) -> Result<keep_frost_net::WalletPolicy, KeepMobileError> {
    use keep_frost_net::{KeySlot, PolicyTier, WalletPolicy};

    if tiers.is_empty() {
        return Err(KeepMobileError::FrostError {
            msg: "At least one recovery tier is required".into(),
        });
    }

    for tier in tiers {
        if tier.threshold == 0 {
            return Err(KeepMobileError::FrostError {
                msg: "Recovery tier threshold must be > 0".into(),
            });
        }
        if tier.threshold > u32::from(total_shares) {
            return Err(KeepMobileError::FrostError {
                msg: format!(
                    "Recovery tier threshold {} exceeds total shares {}",
                    tier.threshold, total_shares
                ),
            });
        }
        if tier.timelock_months == 0 {
            return Err(KeepMobileError::FrostError {
                msg: "Recovery tier timelock_months must be > 0".into(),
            });
        }
    }

    let recovery_tiers = tiers
        .iter()
        .map(|tier| {
            let key_slots = (1..=total_shares)
                .map(|i| KeySlot::Participant { share_index: i })
                .collect();
            PolicyTier {
                threshold: tier.threshold,
                key_slots,
                timelock_months: tier.timelock_months,
            }
        })
        .collect();

    Ok(WalletPolicy { recovery_tiers })
}

impl KeepMobile {
    fn do_initialize(
        &self,
        relays: Vec<String>,
        proxy: Option<std::net::SocketAddr>,
    ) -> Result<(), KeepMobileError> {
        for relay in &relays {
            network::validate_relay_url(relay)?;
        }

        let share = self.load_share_package()?;

        self.runtime.block_on(async {
            let mut pins = persistence::load_cert_pins(&self.storage)?.unwrap_or_default();
            let mut pins_changed = false;
            for relay in &relays {
                match keep_frost_net::verify_relay_certificate(relay, &pins).await {
                    Ok((_hash, new_pin)) => {
                        if let Some((hostname, hash)) = new_pin {
                            if pins.get_pin(&hostname).is_none() {
                                pins.add_pin(hostname, hash);
                                pins_changed = true;
                            }
                        }
                    }
                    Err(e @ keep_frost_net::FrostNetError::CertificatePinMismatch { .. }) => {
                        return Err(e.into());
                    }
                    Err(e) => {
                        tracing::warn!(relay = %relay, error = %e, "TLS certificate verification failed, skipping relay");
                    }
                }
            }
            if pins_changed {
                persistence::persist_cert_pins(&self.storage, &pins)?;
            }

            let verified_relays: Vec<String> = relays
                .iter()
                .filter(|r| {
                    let url = match url::Url::parse(r) {
                        Ok(u) => u,
                        Err(_) => return false,
                    };
                    if url.scheme() != "wss" {
                        return true;
                    }
                    url.host_str()
                        .map(|h| pins.get_pin(h).is_some())
                        .unwrap_or(false)
                })
                .cloned()
                .collect();

            if verified_relays.is_empty() {
                return Err(keep_frost_net::FrostNetError::Transport(
                    "No relays passed TLS certificate verification".into(),
                )
                .into());
            }

            let node = match proxy {
                Some(addr) => KfpNode::new_with_proxy(share, verified_relays, addr).await?,
                None => KfpNode::new(share, verified_relays).await?,
            };

            let (request_tx, request_rx) = mpsc::channel(32);
            let hooks = Arc::new(MobileSigningHooks { request_tx });
            node.set_hooks(hooks);

            let event_rx = node.subscribe();
            let node = Arc::new(node);
            let pending = self.pending_requests.clone();
            let desc_ctx = DescriptorContext {
                callbacks: self.descriptor_callbacks.clone(),
                storage: self.storage.clone(),
                node: node.clone(),
                networks: self.descriptor_networks.clone(),
                pending: self.pending_contributions.clone(),
            };
            tokio::spawn(async move {
                Self::event_listener(event_rx, request_rx, pending, desc_ctx).await;
            });

            let run_node = node.clone();
            tokio::spawn(async move {
                if let Err(e) = run_node.run().await {
                    tracing::error!("Node run failed: {e}");
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

        let (key_package, pubkey_package, vk_bytes) = Self::build_nsec_packages(&key_bytes)?;
        let (metadata_info, stored) =
            Self::build_nsec_share_data(key_package, pubkey_package, vk_bytes, name)?;

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

    fn build_nsec_packages(
        key_bytes: &[u8],
    ) -> Result<
        (
            frost_secp256k1_tr::keys::KeyPackage,
            frost_secp256k1_tr::keys::PublicKeyPackage,
            Vec<u8>,
        ),
        KeepMobileError,
    > {
        // SigningKey doesn't implement Zeroize; deserialize, extract what we need,
        // and drop it promptly to minimize the window secret material is on the stack.
        let (vk, vk_bytes, signing_key_bytes) = {
            let signing_key =
                frost_secp256k1_tr::SigningKey::deserialize(key_bytes).map_err(|e| {
                    KeepMobileError::FrostError {
                        msg: format!("Invalid signing key: {e}"),
                    }
                })?;
            let vk = frost_secp256k1_tr::VerifyingKey::from(&signing_key);
            let vk_bytes = vk.serialize().map_err(|e| KeepMobileError::FrostError {
                msg: format!("Failed to serialize verifying key: {e}"),
            })?;
            let skb = Zeroizing::new(signing_key.serialize());
            (vk, vk_bytes, skb)
        };

        let identifier = frost_secp256k1_tr::Identifier::try_from(1u16).map_err(|e| {
            KeepMobileError::FrostError {
                msg: format!("Failed to create identifier: {e}"),
            }
        })?;

        let signing_share = frost_secp256k1_tr::keys::SigningShare::deserialize(&signing_key_bytes)
            .map_err(|e| KeepMobileError::FrostError {
                msg: format!("Failed to create signing share: {e}"),
            })?;

        let verifying_share = frost_secp256k1_tr::keys::VerifyingShare::deserialize(&vk_bytes)
            .map_err(|e| KeepMobileError::FrostError {
                msg: format!("Failed to create verifying share: {e}"),
            })?;

        let key_package = frost_secp256k1_tr::keys::KeyPackage::new(
            identifier,
            signing_share,
            verifying_share,
            vk,
            1,
        );

        let mut verifying_shares = std::collections::BTreeMap::new();
        verifying_shares.insert(identifier, verifying_share);
        let pubkey_package = frost_secp256k1_tr::keys::PublicKeyPackage::new(verifying_shares, vk);

        Ok((key_package, pubkey_package, vk_bytes))
    }

    fn build_nsec_share_data(
        key_package: frost_secp256k1_tr::keys::KeyPackage,
        pubkey_package: frost_secp256k1_tr::keys::PublicKeyPackage,
        vk_bytes: Vec<u8>,
        name: String,
    ) -> Result<(ShareMetadataInfo, StoredShareData), KeepMobileError> {
        let group_pubkey: [u8; 32] = match vk_bytes.len() {
            33 => vk_bytes[1..33]
                .try_into()
                .map_err(|_| KeepMobileError::FrostError {
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

        Ok((metadata_info, stored))
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

    fn store_share_package(&self, share: &SharePackage) -> Result<ShareInfo, KeepMobileError> {
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

    async fn event_listener(
        mut event_rx: broadcast::Receiver<KfpNodeEvent>,
        mut request_rx: mpsc::Receiver<(SessionInfo, mpsc::Sender<bool>)>,
        pending: Arc<Mutex<Vec<PendingRequest>>>,
        desc: DescriptorContext,
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
                        Ok(KfpNodeEvent::DescriptorContributionNeeded {
                            session_id,
                            policy,
                            network,
                            initiator_pubkey,
                        }) => {
                            let nets_ok = match desc.networks.lock() {
                                Ok(mut nets) => {
                                    nets.insert(session_id, network.clone());
                                    true
                                }
                                Err(e) => {
                                    tracing::error!("Descriptor networks lock poisoned: {e}");
                                    false
                                }
                            };
                            if nets_ok {
                                match desc.pending.lock() {
                                    Ok(mut p) => {
                                        p.retain(|_, c| c.created_at.elapsed() < DESCRIPTOR_SESSION_TIMEOUT);
                                        p.insert(session_id, PendingContribution {
                                            network: network.clone(),
                                            initiator_pubkey,
                                            created_at: std::time::Instant::now(),
                                        });
                                    }
                                    Err(e) => {
                                        tracing::error!("Pending contributions lock poisoned: {e}");
                                    }
                                }
                            }
                            if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                let tiers = policy.recovery_tiers.iter().map(|t| {
                                    RecoveryTierConfig {
                                        threshold: t.threshold,
                                        timelock_months: t.timelock_months,
                                    }
                                }).collect();
                                if let Err(e) = cb.on_contribution_needed(DescriptorProposal {
                                    session_id: hex::encode(session_id),
                                    network,
                                    tiers,
                                }) {
                                    tracing::error!("Descriptor callback error: {e}");
                                }
                            }
                        }
                        Ok(KfpNodeEvent::DescriptorProposed { session_id }) => {
                            if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                if let Err(e) = cb.on_proposed(hex::encode(session_id)) {
                                    tracing::error!("Descriptor callback error: {e}");
                                }
                            }
                        }
                        Ok(KfpNodeEvent::DescriptorContributed {
                            session_id,
                            share_index,
                        }) => {
                            if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                if let Err(e) = cb.on_contributed(hex::encode(session_id), share_index) {
                                    tracing::error!("Descriptor callback error: {e}");
                                }
                            }
                        }
                        Ok(KfpNodeEvent::DescriptorReady { session_id }) => {
                            if let Err(e) = desc.node.build_and_finalize_descriptor(session_id).await {
                                tracing::error!("Failed to finalize descriptor: {e}");
                                clear_descriptor_state(&desc.networks, &desc.pending, &session_id);
                                if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                    if let Err(e2) = cb.on_failed(hex::encode(session_id), e.to_string()) {
                                        tracing::error!("Descriptor callback error: {e2}");
                                    }
                                }
                            }
                        }
                        Ok(KfpNodeEvent::DescriptorComplete {
                            session_id,
                            external_descriptor,
                            internal_descriptor,
                            network,
                        }) => {
                            if let Ok(mut p) = desc.pending.lock() {
                                p.remove(&session_id);
                            }
                            let network = match Some(network).filter(|n| !n.is_empty()) {
                                Some(n) => n,
                                _ => {
                                    tracing::error!("Missing network for descriptor session");
                                    if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                        if let Err(e) = cb.on_failed(
                                            hex::encode(session_id),
                                            "Missing network for descriptor session".into(),
                                        ) {
                                            tracing::error!("Descriptor callback error: {e}");
                                        }
                                    }
                                    continue;
                                }
                            };
                            Self::handle_descriptor_complete(
                                &desc.storage,
                                &desc.callbacks,
                                &desc.node,
                                network,
                                session_id,
                                external_descriptor,
                                internal_descriptor,
                            )
                            .await;
                        }
                        Ok(KfpNodeEvent::DescriptorNacked {
                            session_id,
                            share_index,
                            reason,
                        }) => {
                            clear_descriptor_state(&desc.networks, &desc.pending, &session_id);
                            let error =
                                format!("Peer {share_index} rejected descriptor: {reason}");
                            if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                if let Err(e) = cb.on_failed(hex::encode(session_id), error) {
                                    tracing::error!("Descriptor callback error: {e}");
                                }
                            }
                        }
                        Ok(KfpNodeEvent::DescriptorFailed { session_id, error }) => {
                            clear_descriptor_state(&desc.networks, &desc.pending, &session_id);
                            if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                if let Err(e) = cb.on_failed(hex::encode(session_id), error) {
                                    tracing::error!("Descriptor callback error: {e}");
                                }
                            }
                        }
                        Ok(KfpNodeEvent::XpubAnnounced {
                            share_index,
                            recovery_xpubs,
                        }) => {
                            if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                let xpubs = recovery_xpubs
                                    .into_iter()
                                    .map(|x| AnnouncedXpubInfo {
                                        xpub: x.xpub,
                                        fingerprint: x.fingerprint,
                                        label: x.label,
                                    })
                                    .collect();
                                if let Err(e) = cb.on_xpub_announced(share_index, xpubs) {
                                    tracing::error!("Descriptor callback error: {e}");
                                }
                            }
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

    async fn handle_descriptor_complete(
        storage: &Arc<dyn SecureStorage>,
        cbs: &Arc<RwLock<Option<Arc<dyn DescriptorCallbacks>>>>,
        node: &Arc<KfpNode>,
        network: String,
        session_id: [u8; 32],
        external_descriptor: String,
        internal_descriptor: String,
    ) {
        let group_pubkey = hex::encode(node.group_pubkey());
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let info = WalletDescriptorInfo {
            group_pubkey,
            external_descriptor: external_descriptor.clone(),
            internal_descriptor: internal_descriptor.clone(),
            network,
            created_at,
        };

        if let Err(e) = persistence::persist_descriptor(storage, &info) {
            tracing::error!("Failed to persist descriptor: {e}");
            if let Some(cb) = cbs.read().await.as_ref() {
                if let Err(e2) = cb.on_failed(
                    hex::encode(session_id),
                    format!("Failed to persist descriptor: {e}"),
                ) {
                    tracing::error!("Descriptor callback error: {e2}");
                }
            }
            return;
        }

        if let Some(cb) = cbs.read().await.as_ref() {
            if let Err(e) = cb.on_complete(
                hex::encode(session_id),
                external_descriptor,
                internal_descriptor,
            ) {
                tracing::error!("Descriptor callback error: {e}");
            }
        }
    }

    fn load_share_package(&self) -> Result<SharePackage, KeepMobileError> {
        let key = match self.storage.get_active_share_key() {
            Some(k) => k,
            None => self.resolve_active_share()?,
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

    fn resolve_active_share(&self) -> Result<String, KeepMobileError> {
        let shares = self.storage.list_all_shares();
        match shares.len() {
            1 => {
                let key = hex::encode(&shares[0].group_pubkey);
                self.storage.set_active_share_key(Some(key.clone()))?;
                Ok(key)
            }
            0 => self.migrate_legacy_share(),
            _ => Err(KeepMobileError::StorageError {
                msg: "Multiple shares found, please select one".into(),
            }),
        }
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
