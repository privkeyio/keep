// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::KeepMobileError;
use crate::policy::{PolicyBundle, POLICY_PUBKEY_LEN};
use crate::storage::{SecureStorage, ShareMetadataInfo};
use crate::types::{KeyHealthStatusInfo, WalletDescriptorInfo};
use crate::velocity::VelocityTracker;
use crate::{
    CERT_PINS_STORAGE_KEY, DESCRIPTOR_INDEX_KEY, DESCRIPTOR_KEY_PREFIX, HEALTH_STATUS_INDEX_KEY,
    HEALTH_STATUS_KEY_PREFIX, POLICY_STORAGE_KEY, TRUSTED_WARDENS_KEY, VELOCITY_STORAGE_KEY,
};

pub(crate) fn load_policy(
    storage: &Arc<dyn SecureStorage>,
) -> Result<PolicyBundle, KeepMobileError> {
    let data = storage.load_share_by_key(POLICY_STORAGE_KEY.into())?;
    serde_json::from_slice(&data).map_err(|e| KeepMobileError::InvalidPolicy {
        msg: format!("Failed to deserialize policy: {e}"),
    })
}

pub(crate) fn persist_policy(
    storage: &Arc<dyn SecureStorage>,
    bundle: &PolicyBundle,
) -> Result<(), KeepMobileError> {
    let data = serde_json::to_vec(bundle).map_err(|e| KeepMobileError::StorageError {
        msg: format!("Failed to serialize policy: {e}"),
    })?;
    storage.store_share_by_key(POLICY_STORAGE_KEY.into(), data, storage_metadata("policy"))
}

pub(crate) fn load_velocity(
    storage: &Arc<dyn SecureStorage>,
) -> Result<VelocityTracker, KeepMobileError> {
    match storage.load_share_by_key(VELOCITY_STORAGE_KEY.into()) {
        Ok(data) => VelocityTracker::from_bytes(&data).map_err(|e| KeepMobileError::StorageError {
            msg: format!("Failed to deserialize velocity: {e}"),
        }),
        Err(KeepMobileError::StorageNotFound) => Ok(VelocityTracker::new()),
        Err(e) => Err(KeepMobileError::StorageError {
            msg: format!("Failed to load velocity tracker: {e}"),
        }),
    }
}

pub(crate) fn persist_velocity(
    storage: &Arc<dyn SecureStorage>,
    tracker: &VelocityTracker,
) -> Result<(), KeepMobileError> {
    let data = tracker
        .to_bytes()
        .map_err(|e| KeepMobileError::StorageError {
            msg: format!("Failed to serialize velocity: {e}"),
        })?;
    storage.store_share_by_key(
        VELOCITY_STORAGE_KEY.into(),
        data,
        storage_metadata("velocity"),
    )
}

pub(crate) fn load_trusted_wardens(
    storage: &Arc<dyn SecureStorage>,
) -> Result<HashSet<[u8; POLICY_PUBKEY_LEN]>, KeepMobileError> {
    let data = storage.load_share_by_key(TRUSTED_WARDENS_KEY.into())?;
    let hex_list: Vec<String> =
        serde_json::from_slice(&data).map_err(|e| KeepMobileError::StorageError {
            msg: format!("Failed to deserialize trusted wardens: {e}"),
        })?;

    let mut wardens = HashSet::new();
    let mut malformed = Vec::new();
    for hex_str in &hex_list {
        match hex::decode(hex_str) {
            Ok(bytes) if bytes.len() == POLICY_PUBKEY_LEN => {
                let mut arr = [0u8; POLICY_PUBKEY_LEN];
                arr.copy_from_slice(&bytes);
                wardens.insert(arr);
            }
            Ok(bytes) => {
                malformed.push(format!("{hex_str}: invalid length {}", bytes.len()));
            }
            Err(e) => {
                malformed.push(format!("{hex_str}: hex decode failed: {e}"));
            }
        }
    }
    if malformed.is_empty() {
        Ok(wardens)
    } else {
        Err(KeepMobileError::StorageError {
            msg: format!(
                "{}: malformed wardens: {}",
                TRUSTED_WARDENS_KEY,
                malformed.join(", ")
            ),
        })
    }
}

pub(crate) fn persist_trusted_wardens(
    storage: &Arc<dyn SecureStorage>,
    wardens: &HashSet<[u8; POLICY_PUBKEY_LEN]>,
) -> Result<(), KeepMobileError> {
    let hex_list: Vec<String> = wardens.iter().map(hex::encode).collect();
    let data = serde_json::to_vec(&hex_list).map_err(|e| KeepMobileError::StorageError {
        msg: format!("Failed to serialize trusted wardens: {e}"),
    })?;
    storage.store_share_by_key(
        TRUSTED_WARDENS_KEY.into(),
        data,
        storage_metadata("trusted_wardens"),
    )
}

pub(crate) fn load_cert_pins(
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

pub(crate) fn persist_cert_pins(
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
    storage.store_share_by_key(
        CERT_PINS_STORAGE_KEY.into(),
        data,
        storage_metadata("cert_pins"),
    )
}

#[derive(Serialize, Deserialize)]
struct StoredDescriptor {
    group_pubkey: String,
    external_descriptor: String,
    internal_descriptor: String,
    network: String,
    created_at: u64,
}

fn descriptor_key(group_pubkey_hex: &str) -> String {
    format!("{DESCRIPTOR_KEY_PREFIX}{group_pubkey_hex}")
}

fn storage_metadata(name: &str) -> ShareMetadataInfo {
    ShareMetadataInfo {
        name: name.into(),
        identifier: 0,
        threshold: 0,
        total_shares: 0,
        group_pubkey: vec![],
    }
}

fn load_descriptor_index(storage: &Arc<dyn SecureStorage>) -> Vec<String> {
    match storage.load_share_by_key(DESCRIPTOR_INDEX_KEY.into()) {
        Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn persist_descriptor_index(
    storage: &Arc<dyn SecureStorage>,
    index: &[String],
) -> Result<(), KeepMobileError> {
    let data = serde_json::to_vec(index).map_err(|e| KeepMobileError::StorageError {
        msg: format!("Failed to serialize descriptor index: {e}"),
    })?;
    storage.store_share_by_key(
        DESCRIPTOR_INDEX_KEY.into(),
        data,
        storage_metadata("descriptor_index"),
    )
}

pub(crate) fn load_descriptors(storage: &Arc<dyn SecureStorage>) -> Vec<WalletDescriptorInfo> {
    let index = load_descriptor_index(storage);
    let mut result = Vec::with_capacity(index.len());
    let mut stale = Vec::new();
    for group_hex in &index {
        match storage.load_share_by_key(descriptor_key(group_hex)) {
            Ok(data) => match serde_json::from_slice::<StoredDescriptor>(&data) {
                Ok(stored) => {
                    result.push(WalletDescriptorInfo {
                        group_pubkey: stored.group_pubkey,
                        external_descriptor: stored.external_descriptor,
                        internal_descriptor: stored.internal_descriptor,
                        network: stored.network,
                        created_at: stored.created_at,
                    });
                }
                Err(e) => {
                    tracing::warn!("Corrupt descriptor for {group_hex}: {e}");
                    stale.push(group_hex.clone());
                }
            },
            Err(e) => {
                tracing::warn!("Missing descriptor for {group_hex}: {e}");
                stale.push(group_hex.clone());
            }
        }
    }
    if !stale.is_empty() {
        let cleaned: Vec<String> = index.into_iter().filter(|k| !stale.contains(k)).collect();
        let _ = persist_descriptor_index(storage, &cleaned);
    }
    result
}

pub(crate) fn load_descriptor(
    storage: &Arc<dyn SecureStorage>,
    group_pubkey_hex: &str,
) -> Result<WalletDescriptorInfo, KeepMobileError> {
    let data = storage.load_share_by_key(descriptor_key(group_pubkey_hex))?;
    let stored: StoredDescriptor =
        serde_json::from_slice(&data).map_err(|e| KeepMobileError::StorageError {
            msg: format!("Failed to deserialize descriptor: {e}"),
        })?;
    Ok(WalletDescriptorInfo {
        group_pubkey: stored.group_pubkey,
        external_descriptor: stored.external_descriptor,
        internal_descriptor: stored.internal_descriptor,
        network: stored.network,
        created_at: stored.created_at,
    })
}

pub(crate) fn persist_descriptor(
    storage: &Arc<dyn SecureStorage>,
    info: &WalletDescriptorInfo,
) -> Result<(), KeepMobileError> {
    let stored = StoredDescriptor {
        group_pubkey: info.group_pubkey.clone(),
        external_descriptor: info.external_descriptor.clone(),
        internal_descriptor: info.internal_descriptor.clone(),
        network: info.network.clone(),
        created_at: info.created_at,
    };
    let data = serde_json::to_vec(&stored).map_err(|e| KeepMobileError::StorageError {
        msg: format!("Failed to serialize descriptor: {e}"),
    })?;
    storage.store_share_by_key(
        descriptor_key(&info.group_pubkey),
        data,
        storage_metadata("descriptor"),
    )?;

    let mut index = load_descriptor_index(storage);
    if !index.contains(&info.group_pubkey) {
        index.push(info.group_pubkey.clone());
        persist_descriptor_index(storage, &index)?;
    }
    Ok(())
}

pub(crate) fn delete_descriptor(
    storage: &Arc<dyn SecureStorage>,
    group_pubkey_hex: &str,
) -> Result<(), KeepMobileError> {
    storage.delete_share_by_key(descriptor_key(group_pubkey_hex))?;

    let mut index = load_descriptor_index(storage);
    if let Some(pos) = index.iter().position(|k| k == group_pubkey_hex) {
        index.swap_remove(pos);
        persist_descriptor_index(storage, &index)?;
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct StoredHealthStatus {
    group_pubkey: String,
    share_index: u16,
    last_check_timestamp: u64,
    responsive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_at: Option<u64>,
}

fn health_status_key(group_pubkey_hex: &str, share_index: u16) -> String {
    format!("{HEALTH_STATUS_KEY_PREFIX}{group_pubkey_hex}_{share_index}")
}

fn load_health_index(storage: &Arc<dyn SecureStorage>) -> Vec<String> {
    match storage.load_share_by_key(HEALTH_STATUS_INDEX_KEY.into()) {
        Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn persist_health_index(
    storage: &Arc<dyn SecureStorage>,
    index: &[String],
) -> Result<(), KeepMobileError> {
    let data = serde_json::to_vec(index).map_err(|e| KeepMobileError::StorageError {
        msg: format!("Failed to serialize health index: {e}"),
    })?;
    storage.store_share_by_key(
        HEALTH_STATUS_INDEX_KEY.into(),
        data,
        storage_metadata("health_index"),
    )
}

pub(crate) fn existing_created_at(
    storage: &Arc<dyn SecureStorage>,
    group_pubkey_hex: &str,
    share_index: u16,
) -> Option<u64> {
    load_stored_health_status(storage, group_pubkey_hex, share_index).and_then(|s| s.created_at)
}

fn load_stored_health_status(
    storage: &Arc<dyn SecureStorage>,
    group_pubkey_hex: &str,
    share_index: u16,
) -> Option<StoredHealthStatus> {
    let key = health_status_key(group_pubkey_hex, share_index);
    storage
        .load_share_by_key(key)
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok())
}

pub(crate) fn persist_health_status(
    storage: &Arc<dyn SecureStorage>,
    info: &KeyHealthStatusInfo,
) -> Result<(), KeepMobileError> {
    let stored = StoredHealthStatus {
        group_pubkey: info.group_pubkey.clone(),
        share_index: info.share_index,
        last_check_timestamp: info.last_check_timestamp,
        responsive: info.responsive,
        created_at: Some(info.created_at),
    };
    let data = serde_json::to_vec(&stored).map_err(|e| KeepMobileError::StorageError {
        msg: format!("Failed to serialize health status: {e}"),
    })?;
    let key = health_status_key(&info.group_pubkey, info.share_index);
    storage.store_share_by_key(key.clone(), data, storage_metadata("health_status"))?;

    let mut index = load_health_index(storage);
    if !index.contains(&key) {
        index.push(key);
        persist_health_index(storage, &index)?;
    }
    Ok(())
}

pub(crate) fn load_health_statuses(storage: &Arc<dyn SecureStorage>) -> Vec<KeyHealthStatusInfo> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let index = load_health_index(storage);
    let mut results = Vec::new();
    let mut live_keys = Vec::with_capacity(index.len());
    for key in &index {
        let Some(data) = storage.load_share_by_key(key.clone()).ok() else {
            continue;
        };
        let Some(stored) = serde_json::from_slice::<StoredHealthStatus>(&data).ok() else {
            continue;
        };
        live_keys.push(key.clone());
        let stale_age = now.saturating_sub(stored.last_check_timestamp);
        results.push(KeyHealthStatusInfo {
            group_pubkey: stored.group_pubkey,
            share_index: stored.share_index,
            last_check_timestamp: stored.last_check_timestamp,
            responsive: stored.responsive,
            created_at: stored.created_at.unwrap_or(stored.last_check_timestamp),
            is_stale: stale_age >= keep_core::wallet::KEY_HEALTH_STALE_THRESHOLD_SECS,
            is_critical: stale_age >= keep_core::wallet::KEY_HEALTH_CRITICAL_THRESHOLD_SECS,
        });
    }
    if live_keys.len() < index.len() {
        let _ = persist_health_index(storage, &live_keys);
    }
    results
}
