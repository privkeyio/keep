// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::error::KeepMobileError;
use crate::policy::{PolicyBundle, POLICY_PUBKEY_LEN};
use crate::storage::{SecureStorage, ShareMetadataInfo};
use crate::velocity::VelocityTracker;
use crate::{
    CERT_PINS_STORAGE_KEY, POLICY_STORAGE_KEY, TRUSTED_WARDENS_KEY, VELOCITY_STORAGE_KEY,
};

pub(crate) fn load_policy(storage: &Arc<dyn SecureStorage>) -> Result<PolicyBundle, KeepMobileError> {
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
    let metadata = ShareMetadataInfo {
        name: "policy".into(),
        identifier: 0,
        threshold: 0,
        total_shares: 0,
        group_pubkey: vec![],
    };
    storage.store_share_by_key(POLICY_STORAGE_KEY.into(), data, metadata)
}

pub(crate) fn load_velocity(
    storage: &Arc<dyn SecureStorage>,
) -> Result<VelocityTracker, KeepMobileError> {
    match storage.load_share_by_key(VELOCITY_STORAGE_KEY.into()) {
        Ok(data) => {
            VelocityTracker::from_bytes(&data).map_err(|e| KeepMobileError::StorageError {
                msg: format!("Failed to deserialize velocity: {e}"),
            })
        }
        Err(_) => Ok(VelocityTracker::new()),
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
    let metadata = ShareMetadataInfo {
        name: "velocity".into(),
        identifier: 0,
        threshold: 0,
        total_shares: 0,
        group_pubkey: vec![],
    };
    storage.store_share_by_key(VELOCITY_STORAGE_KEY.into(), data, metadata)
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

pub(crate) fn persist_trusted_wardens(
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
    let metadata = ShareMetadataInfo {
        name: "cert_pins".into(),
        identifier: 0,
        threshold: 0,
        total_shares: 0,
        group_pubkey: vec![],
    };
    storage.store_share_by_key(CERT_PINS_STORAGE_KEY.into(), data, metadata)
}
