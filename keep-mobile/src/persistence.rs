// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::collections::HashSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::clock_floor::ClockFloor;
use crate::error::KeepMobileError;
use crate::policy::{PolicyBundle, POLICY_MAX_RULES_LEN, POLICY_PUBKEY_LEN, POLICY_VERSION};
use crate::storage::{SecureStorage, ShareMetadataInfo};
use crate::types::{DeviceRegistrationInfo, KeyHealthStatusInfo, WalletDescriptorInfo};
use crate::velocity::{VelocityTracker, MAX_TRACKED_TRANSACTIONS};
use crate::{
    CERT_PINS_STORAGE_KEY, CLOCK_FLOOR_STORAGE_KEY, DESCRIPTOR_INDEX_KEY, DESCRIPTOR_KEY_PREFIX,
    HEALTH_STATUS_INDEX_KEY, HEALTH_STATUS_KEY_PREFIX, POLICY_STORAGE_KEY, TRUSTED_WARDENS_KEY,
    VELOCITY_STORAGE_KEY,
};

#[derive(Serialize, Deserialize, Default)]
pub(crate) struct StoredRelayConfig {
    pub(crate) frost_relays: Vec<String>,
    pub(crate) profile_relays: Vec<String>,
    #[serde(default)]
    pub(crate) bunker_relays: Vec<String>,
    #[serde(default, rename = "share_peer_policies")]
    pub(crate) peer_policies: Vec<keep_core::relay::PeerPolicyEntry>,
    #[serde(
        default,
        rename = "peer_policies",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub(crate) kfp_v1_peer_policies: Vec<keep_core::relay::KfpV1PeerPolicyEntry>,
    #[serde(default)]
    pub(crate) bunker_permissions: Vec<keep_core::relay::StoredBunkerPermission>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct StoredProxyConfig {
    pub(crate) enabled: bool,
    pub(crate) port: u16,
}

impl Default for StoredProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 9050,
        }
    }
}

/// Loose ceiling on the stored policy record, applied before it is parsed.
///
/// The rules are the only variable-length field, so this is their cap plus
/// slack for the JSON envelope: the fixed fields, the hex for the 32-byte
/// pubkey and hash, and the field names.
const POLICY_RECORD_MAX_LEN: usize = POLICY_MAX_RULES_LEN + 1024;

pub(crate) fn load_policy(
    storage: &Arc<dyn SecureStorage>,
) -> Result<PolicyBundle, KeepMobileError> {
    let data = storage.load_share_by_key(POLICY_STORAGE_KEY.into())?;
    // Ahead of the parse, so the cap bounds what serde is asked to allocate
    // rather than only what it produced. The JSON carries the fixed fields plus
    // hex for the pubkey and hash, so the record cannot be smaller than the
    // rules it holds; this bounds it loosely and the exact field check below
    // still applies.
    if data.len() > POLICY_RECORD_MAX_LEN {
        return Err(KeepMobileError::InvalidPolicy {
            msg: "Stored policy record exceeds the maximum length".into(),
        });
    }
    // Deliberately without serde's message, for the same reason load_velocity
    // drops it: serde quotes the value it tripped on, the record is attacker
    // controlled before it has verified, and this error reaches a log.
    let bundle: PolicyBundle =
        serde_json::from_slice(&data).map_err(|_| KeepMobileError::InvalidPolicy {
            msg: "Failed to deserialize policy".into(),
        })?;
    // The wire format caps the rules and checks the version, and the import
    // path caps its input, but a record read straight out of storage has been
    // through neither. The version is covered by `signed_data`, so a mismatch
    // here is not forgeable; without the check a warden-signed v2 record would
    // be enforced under v1 rule semantics instead of faulting.
    if bundle.version != POLICY_VERSION {
        return Err(KeepMobileError::InvalidPolicy {
            msg: "Stored policy has an unsupported version".into(),
        });
    }
    if bundle.rules_json.len() > POLICY_MAX_RULES_LEN {
        return Err(KeepMobileError::InvalidPolicy {
            msg: "Stored policy rules exceed the maximum length".into(),
        });
    }
    Ok(bundle)
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

/// Loose ceiling on the stored counters, applied before they are parsed.
///
/// `record` is the only place the entry cap is enforced, and it evicts one
/// entry per call, so a record that arrives over the cap would be loaded whole
/// and would not come back under it for thousands of spends. The count is
/// checked after the parse; this bounds what serde is asked to allocate first,
/// at a generous 128 bytes per entry against a worst case nearer 75.
const VELOCITY_RECORD_MAX_LEN: usize = 128 * MAX_TRACKED_TRANSACTIONS + 1024;

const CLOCK_FLOOR_RECORD_MAX_LEN: usize = 256;

/// What reading the stored time floor found.
///
/// A record that is there and will not parse is a different statement from one
/// that could not be read. A read failure may clear on the next attempt, so it
/// refuses and is retried. A corrupt record will not, and treating it as a read
/// failure left it in place forever: nothing rewrites it, so a device that hit
/// it could never install a policy again, even after deleting the old one.
/// Reporting it apart lets the caller replace it where that is safe.
pub(crate) enum ClockFloorRead {
    Found(ClockFloor),
    Absent,
    Corrupt,
}

/// Reads the stored time floor. `Err` is a read that did not complete, which
/// the caller refuses on.
pub(crate) fn load_clock_floor(
    storage: &Arc<dyn SecureStorage>,
) -> Result<ClockFloorRead, KeepMobileError> {
    match storage.load_share_by_key(CLOCK_FLOOR_STORAGE_KEY.into()) {
        // Bounded before the parse, as the policy and counter records are. Two
        // integer fields, so anything this long is not this record.
        Ok(data) if data.len() > CLOCK_FLOOR_RECORD_MAX_LEN => Ok(ClockFloorRead::Corrupt),
        Ok(data) => Ok(serde_json::from_slice(&data)
            .map(ClockFloorRead::Found)
            .unwrap_or(ClockFloorRead::Corrupt)),
        Err(KeepMobileError::StorageNotFound) => Ok(ClockFloorRead::Absent),
        Err(e) => Err(e),
    }
}

pub(crate) fn persist_clock_floor(
    storage: &Arc<dyn SecureStorage>,
    floor: &ClockFloor,
) -> Result<(), KeepMobileError> {
    let data = serde_json::to_vec(floor).map_err(|e| KeepMobileError::StorageError {
        msg: format!("Failed to serialize the clock floor: {e}"),
    })?;
    storage.store_share_by_key(
        CLOCK_FLOOR_STORAGE_KEY.into(),
        data,
        storage_metadata("clock_floor"),
    )
}

pub(crate) fn load_velocity(
    storage: &Arc<dyn SecureStorage>,
) -> Result<VelocityTracker, KeepMobileError> {
    match storage.load_share_by_key(VELOCITY_STORAGE_KEY.into()) {
        Ok(data) if data.len() > VELOCITY_RECORD_MAX_LEN => Err(KeepMobileError::StorageError {
            msg: "Velocity record exceeds the maximum length".into(),
        }),
        // Deliberately without serde's message. It quotes the value it tripped
        // on, which here is an amount or a timestamp out of the record, and this
        // error reaches a log. What a caller can act on is that the record did
        // not parse, which is the same either way.
        Ok(data) => {
            let tracker =
                VelocityTracker::from_bytes(&data).map_err(|_| KeepMobileError::StorageError {
                    msg: "Failed to deserialize velocity".into(),
                })?;
            // Refused, not trimmed. Trimming here would put a destructive write
            // back on the read path, which is the shape that made a moved clock
            // erase the history in the first place; see the note on
            // `load_descriptors`. Refusing leaves the counters unknown, and
            // unknown already denies every rule that depends on them.
            if tracker.over_capacity() {
                return Err(KeepMobileError::StorageError {
                    msg: "Velocity record holds more entries than the cap allows".into(),
                });
            }
            Ok(tracker)
        }
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

/// The trusted warden set and the epoch that orders changes to it.
///
/// Kept in one record so a change to the set and the advance of the epoch land
/// in a single write. Two records would let a failure between them leave the
/// set changed with the epoch unmoved, which is exactly the window a replayed
/// authorization needs.
///
/// The device id lives here too, because it scopes the epoch: an authorization
/// names both, so one signed for another device at the same epoch does not
/// verify here.
pub(crate) struct WardenSet {
    pub(crate) wardens: HashSet<[u8; POLICY_PUBKEY_LEN]>,
    pub(crate) epoch: u64,
    pub(crate) device: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
struct StoredWardenSet {
    epoch: u64,
    wardens: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device: Option<String>,
}

pub(crate) fn load_warden_set(
    storage: &Arc<dyn SecureStorage>,
) -> Result<WardenSet, KeepMobileError> {
    let data = storage.load_share_by_key(TRUSTED_WARDENS_KEY.into())?;
    // The record was a bare list of keys before the epoch existed. It is read
    // as epoch 0, which is what a device that never authorized a change holds.
    let (epoch, hex_list, device_hex) = match serde_json::from_slice::<StoredWardenSet>(&data) {
        Ok(stored) => (stored.epoch, stored.wardens, stored.device),
        Err(_) => (
            0,
            serde_json::from_slice::<Vec<String>>(&data).map_err(|e| {
                KeepMobileError::StorageError {
                    msg: format!("Failed to deserialize trusted wardens: {e}"),
                }
            })?,
            None,
        ),
    };
    let device = device_hex
        .map(|hex_str| {
            hex::decode(&hex_str)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .ok_or_else(|| KeepMobileError::StorageError {
                    msg: format!("{TRUSTED_WARDENS_KEY}: malformed device id"),
                })
        })
        .transpose()?;

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
        Ok(WardenSet {
            wardens,
            epoch,
            device,
        })
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

pub(crate) fn load_trusted_wardens(
    storage: &Arc<dyn SecureStorage>,
) -> Result<HashSet<[u8; POLICY_PUBKEY_LEN]>, KeepMobileError> {
    load_warden_set(storage).map(|set| set.wardens)
}

pub(crate) fn persist_warden_set(
    storage: &Arc<dyn SecureStorage>,
    set: &WardenSet,
) -> Result<(), KeepMobileError> {
    let stored = StoredWardenSet {
        epoch: set.epoch,
        wardens: set.wardens.iter().map(hex::encode).collect(),
        device: set.device.map(hex::encode),
    };
    let data = serde_json::to_vec(&stored).map_err(|e| KeepMobileError::StorageError {
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
    let (pins, malformed) =
        keep_frost_net::CertificatePinSet::from_json_bytes(&data).map_err(|e| {
            KeepMobileError::StorageError {
                msg: format!("Failed to deserialize cert pins: {e}"),
            }
        })?;
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
    let data =
        serde_json::to_vec(&pins.to_hex_map()).map_err(|e| KeepMobileError::StorageError {
            msg: format!("Failed to serialize cert pins: {e}"),
        })?;
    storage.store_share_by_key(
        CERT_PINS_STORAGE_KEY.into(),
        data,
        storage_metadata("cert_pins"),
    )
}

/// At-rest schema for a persisted wallet descriptor.
///
/// `SecureStorage` implementations **must** back this record with platform
/// secure storage (iOS Keychain, Android Keystore-backed) because
/// `device_registrations` contains device-returned authentication material
/// (the HMAC/registration token).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDescriptor {
    group_pubkey: String,
    external_descriptor: String,
    internal_descriptor: String,
    network: String,
    created_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    device_registrations: Vec<StoredDeviceRegistration>,
    /// Hex-encoded 32-byte canonical policy hash. `None` for legacy records
    /// written before the field was introduced; new records always set it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_hash_hex: Option<String>,
    /// Monotonic descriptor version. Defaults to `1` for records written
    /// before versioning was introduced.
    #[serde(default = "default_stored_version")]
    version: u32,
    /// Hex-encoded 32-byte canonical hash of the descriptor this one
    /// supersedes. `None` for initial descriptors and legacy records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_descriptor_hash_hex: Option<String>,
    /// JSON-encoded `WalletPolicy`. Persisted as a string for FFI simplicity;
    /// older records deserialize with `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_json: Option<String>,
}

fn default_stored_version() -> u32 {
    1
}

/// At-rest schema for a hardware-signer registration record.
///
/// See [`StoredDescriptor`] for secure-storage requirements. The `hmac` field,
/// when present, must be exactly `HMAC_SHA256_HEX_LEN` hex characters; entries
/// that fail this shape are dropped with a warning at load time.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredDeviceRegistration {
    pub signer_pubkey: String,
    pub wallet_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
    pub registered_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_kind: Option<String>,
    /// Hex-encoded 8 chars (4-byte BIP32 master fingerprint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<String>,
}

const HMAC_SHA256_HEX_LEN: usize = 64;
const POLICY_HASH_HEX_LEN: usize = 64;

fn descriptor_key(group_pubkey_hex: &str) -> String {
    format!("{DESCRIPTOR_KEY_PREFIX}{group_pubkey_hex}")
}

pub(crate) fn storage_metadata(name: &str) -> ShareMetadataInfo {
    ShareMetadataInfo {
        name: name.into(),
        identifier: 0,
        threshold: 0,
        total_shares: 0,
        group_pubkey: vec![],
        did_backup: false,
    }
}

/// A descriptor index read that is safe to rewrite, or the reason it is not.
///
/// `WalletDescriptorInfo` has a hand-written `Debug` that redacts the
/// descriptors, so deriving here does not widen what a log can carry.
#[derive(Debug)]
pub(crate) struct DescriptorLoad {
    pub(crate) loaded: Vec<WalletDescriptorInfo>,
    /// Group hexes the index references whose record could not be read. Their
    /// index entries are kept and they are absent from `loaded`, so `loaded` is
    /// not the whole set whenever this is non-empty.
    pub(crate) unreadable: Vec<String>,
}

/// Read the descriptor index, yielding a value only when it is safe for a
/// caller to rewrite the index from it.
///
/// Every caller rewrites the index from what this returns, so anything short of
/// a cleanly parsed index has to be refused: a rewrite from a partial read
/// drops every reference the read did not produce, and the records it dropped
/// are then unreachable, because nothing enumerates keys.
///
/// The one case that cannot be refused is `StorageNotFound`, because a device
/// on its first run has to be able to write its first descriptor, and this
/// layer has no way to tell that apart from an index it merely cannot read.
/// The Android implementation reads metadata through a path that collapses "key
/// absent" and "value unreadable" into the same `null` (`KeystoreEncryptedPrefs`
/// `getTypedValue`), so an index that exists but will not decrypt arrives here
/// as `StorageNotFound` and is believed. Closing that needs the platform to
/// report the two cases apart; there is no sound check on this side, because
/// every independent signal available here reads through the same collapsing
/// getter, and probing for a surviving descriptor record would route through
/// `loadMetadata`, which destroys the record it cannot decrypt.
///
/// So what this function guarantees is narrower than "no reference is ever
/// lost": a corrupt index is never parsed as empty, and no read on this side
/// writes. The backend is a separate matter: the index key is itself a metadata
/// key, so a read of it that cannot decrypt destroys it before reporting, and
/// the next read then answers `StorageNotFound` and is believed empty. That
/// chain starts in a read this layer performs and ends in a write it cannot
/// see, and only the platform can break it.
fn load_descriptor_index(storage: &Arc<dyn SecureStorage>) -> Result<Vec<String>, KeepMobileError> {
    match storage.load_share_by_key(DESCRIPTOR_INDEX_KEY.into()) {
        Ok(data) => serde_json::from_slice(&data).map_err(|e| KeepMobileError::StorageError {
            msg: format!("{DESCRIPTOR_INDEX_CORRUPT_MSG}: {e}"),
        }),
        Err(KeepMobileError::StorageNotFound) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Prefix of the error a corrupt index blob produces. A corrupt index refuses
/// every descriptor write, and recovering needs an explicit user-confirmed
/// reset rather than a rebuild from a list that can under-report, so the
/// message has to be recognizable to the layer that offers it.
pub(crate) const DESCRIPTOR_INDEX_CORRUPT_MSG: &str = "Descriptor index is unreadable";

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

/// Load every descriptor the index references, without ever writing to it.
///
/// A read path must not prune. Pruning is a write that makes an absence
/// permanent, and nothing available here proves absence: `StorageNotFound` also
/// covers a record the platform cannot decrypt, and on Android a metadata
/// decrypt failure wipes the entry outright, so a kept reference is not even a
/// reliable path back to the record. An entry whose record is gone therefore
/// stays, costing one failed read per call, which is the cheap half of the
/// trade. `delete_descriptor` is the one place an entry is removed, because it
/// is the one place a descriptor is known to be going away.
pub(crate) fn load_descriptors(
    storage: &Arc<dyn SecureStorage>,
) -> Result<DescriptorLoad, KeepMobileError> {
    let index = load_descriptor_index(storage)?;
    let mut loaded = Vec::with_capacity(index.len());
    let mut unreadable = Vec::new();
    for group_hex in index {
        match storage.load_share_by_key(descriptor_key(&group_hex)) {
            Ok(data) => match serde_json::from_slice::<StoredDescriptor>(&data) {
                Ok(stored) => loaded.push(stored_to_info(stored)),
                Err(e) => {
                    tracing::warn!("Descriptor for {group_hex} will not deserialize: {e}");
                    unreadable.push(group_hex);
                }
            },
            Err(e) => {
                tracing::warn!("Cannot read the descriptor for {group_hex}: {e}");
                unreadable.push(group_hex);
            }
        }
    }
    Ok(DescriptorLoad { loaded, unreadable })
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
    Ok(stored_to_info(stored))
}

pub(crate) fn persist_descriptor(
    storage: &Arc<dyn SecureStorage>,
    info: &WalletDescriptorInfo,
) -> Result<(), KeepMobileError> {
    if info.version == 0 {
        return Err(KeepMobileError::StorageError {
            msg: "refusing to persist descriptor with version 0 (versions start at 1)".into(),
        });
    }
    match info.policy_hash_hex.as_deref() {
        Some(h) if h.len() == POLICY_HASH_HEX_LEN && h.chars().all(|c| c.is_ascii_hexdigit()) => {
            if h.chars().all(|c| c == '0') {
                return Err(KeepMobileError::StorageError {
                    msg: "refusing to persist descriptor with placeholder all-zero policy_hash"
                        .into(),
                });
            }
        }
        Some(_) => {
            return Err(KeepMobileError::StorageError {
                msg: format!("policy_hash_hex must be {POLICY_HASH_HEX_LEN} hex characters"),
            });
        }
        None => {}
    }
    let stored = info_to_stored(info);
    let data = serde_json::to_vec(&stored).map_err(|e| KeepMobileError::StorageError {
        msg: format!("Failed to serialize descriptor: {e}"),
    })?;

    // Index first, then the record. Both orders can fail in between, so the
    // choice is which half-applied state to leave. An index entry with no
    // record is benign and self-correcting: the load path reports it as
    // unreadable without pruning it, and a retry finds the entry already
    // present and just writes the record. A record with no index entry is not:
    // it is invisible to every list, and on a device whose index did not exist
    // yet it is indistinguishable from the index being unreadable, which the
    // read below refuses, so a retry would stay refused.
    // For a group already in the index this read is a pure gate: nothing below
    // writes the index. A transient index fault therefore refuses an update
    // that would have been safe, which costs the caller its work (a device
    // registration discards the HMAC it just obtained from the signer and has
    // to repeat the exchange). Accepted because the alternative is another
    // metadata read to decide, carrying the same wipe-on-decrypt-failure
    // hazard, to save a retry rather than any data.
    let mut index = load_descriptor_index(storage)?;
    if !index.contains(&info.group_pubkey) {
        index.push(info.group_pubkey.clone());
        persist_descriptor_index(storage, &index)?;
    }
    storage.store_share_by_key(
        descriptor_key(&info.group_pubkey),
        data,
        storage_metadata("descriptor"),
    )?;
    Ok(())
}

pub(crate) fn is_valid_hmac_hex(s: &str) -> bool {
    s.len() == HMAC_SHA256_HEX_LEN && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn stored_to_info(stored: StoredDescriptor) -> WalletDescriptorInfo {
    let device_registrations = stored
        .device_registrations
        .into_iter()
        .filter_map(|r| {
            if let Some(h) = r.hmac.as_deref() {
                if !is_valid_hmac_hex(h) {
                    tracing::warn!(
                        signer = %r.signer_pubkey,
                        hmac_len = h.len(),
                        "dropping device_registration with malformed hmac"
                    );
                    return None;
                }
            }
            Some(DeviceRegistrationInfo {
                signer_pubkey: r.signer_pubkey,
                wallet_name: r.wallet_name,
                hmac: r.hmac,
                registered_at: r.registered_at,
                device_kind: r.device_kind,
                fingerprint_hex: r.fingerprint_hex,
                firmware_version: r.firmware_version,
            })
        })
        .collect();
    WalletDescriptorInfo {
        group_pubkey: stored.group_pubkey,
        external_descriptor: stored.external_descriptor,
        internal_descriptor: stored.internal_descriptor,
        network: stored.network,
        created_at: stored.created_at,
        device_registrations,
        policy_hash_hex: stored.policy_hash_hex,
        version: stored.version,
        previous_descriptor_hash_hex: stored.previous_descriptor_hash_hex,
        policy_json: stored.policy_json,
    }
}

fn info_to_stored(info: &WalletDescriptorInfo) -> StoredDescriptor {
    StoredDescriptor {
        group_pubkey: info.group_pubkey.clone(),
        external_descriptor: info.external_descriptor.clone(),
        internal_descriptor: info.internal_descriptor.clone(),
        network: info.network.clone(),
        created_at: info.created_at,
        policy_hash_hex: info.policy_hash_hex.clone(),
        policy_json: info.policy_json.clone(),
        device_registrations: info
            .device_registrations
            .iter()
            .map(|r| StoredDeviceRegistration {
                signer_pubkey: r.signer_pubkey.clone(),
                wallet_name: r.wallet_name.clone(),
                hmac: r.hmac.clone(),
                registered_at: r.registered_at,
                device_kind: r.device_kind.clone(),
                fingerprint_hex: r.fingerprint_hex.clone(),
                firmware_version: r.firmware_version.clone(),
            })
            .collect(),
        version: info.version,
        previous_descriptor_hash_hex: info.previous_descriptor_hash_hex.clone(),
    }
}

pub(crate) fn delete_descriptor(
    storage: &Arc<dyn SecureStorage>,
    group_pubkey_hex: &str,
) -> Result<(), KeepMobileError> {
    // Read the index before deleting the record, or a refusal here reports a
    // failure for a descriptor that is already gone and that no list can show.
    let mut index = load_descriptor_index(storage)?;
    storage.delete_share_by_key(descriptor_key(group_pubkey_hex))?;

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
        let stale_age = now
            .checked_sub(stored.last_check_timestamp)
            .unwrap_or(u64::MAX);
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

pub(crate) fn load_relay_config(
    storage: &Arc<dyn SecureStorage>,
    key: &str,
) -> Result<Option<StoredRelayConfig>, KeepMobileError> {
    match storage.load_share_by_key(key.into()) {
        Ok(data) => {
            let config: StoredRelayConfig =
                serde_json::from_slice(&data).map_err(|e| KeepMobileError::StorageError {
                    msg: format!("failed to deserialize relay config: {e}"),
                })?;
            Ok(Some(config))
        }
        Err(KeepMobileError::StorageNotFound) => Ok(None),
        Err(e) => {
            tracing::warn!("failed to load relay config for key {key}: {e}");
            Err(e)
        }
    }
}

pub(crate) fn persist_relay_config(
    storage: &Arc<dyn SecureStorage>,
    key: &str,
    config: &StoredRelayConfig,
) -> Result<(), KeepMobileError> {
    let data = serde_json::to_vec(config).map_err(|e| KeepMobileError::StorageError {
        msg: format!("failed to serialize relay config: {e}"),
    })?;
    storage.store_share_by_key(key.into(), data, storage_metadata("relay_config"))
}

pub(crate) fn load_proxy_config(
    storage: &Arc<dyn SecureStorage>,
    key: &str,
) -> Result<Option<StoredProxyConfig>, KeepMobileError> {
    match storage.load_share_by_key(key.into()) {
        Ok(data) => {
            let config: StoredProxyConfig =
                serde_json::from_slice(&data).map_err(|e| KeepMobileError::StorageError {
                    msg: format!("failed to deserialize proxy config: {e}"),
                })?;
            Ok(Some(config))
        }
        Err(KeepMobileError::StorageNotFound) => Ok(None),
        Err(e) => {
            tracing::warn!("failed to load proxy config: {e}");
            Err(e)
        }
    }
}

pub(crate) fn persist_proxy_config(
    storage: &Arc<dyn SecureStorage>,
    key: &str,
    config: &StoredProxyConfig,
) -> Result<(), KeepMobileError> {
    let data = serde_json::to_vec(config).map_err(|e| KeepMobileError::StorageError {
        msg: format!("failed to serialize proxy config: {e}"),
    })?;
    storage.store_share_by_key(key.into(), data, storage_metadata("proxy_config"))
}

/// Opt-in strict certificate pinning. When enabled, a relay with no
/// pre-provisioned pin is rejected at connect (fail-closed) instead of
/// trusted-on-first-use, closing the first-connection MitM window. Defaults to
/// disabled so existing deployments are not broken until the operator has staged
/// each relay's pin.
#[derive(Serialize, Deserialize, Default)]
pub(crate) struct StoredStrictPinConfig {
    pub(crate) enabled: bool,
}

pub(crate) fn load_strict_pin_config(
    storage: &Arc<dyn SecureStorage>,
    key: &str,
) -> Result<Option<StoredStrictPinConfig>, KeepMobileError> {
    match storage.load_share_by_key(key.into()) {
        Ok(data) => {
            let config: StoredStrictPinConfig =
                serde_json::from_slice(&data).map_err(|e| KeepMobileError::StorageError {
                    msg: format!("failed to deserialize strict pin config: {e}"),
                })?;
            Ok(Some(config))
        }
        Err(KeepMobileError::StorageNotFound) => Ok(None),
        Err(e) => {
            tracing::warn!("failed to load strict pin config: {e}");
            Err(e)
        }
    }
}

pub(crate) fn persist_strict_pin_config(
    storage: &Arc<dyn SecureStorage>,
    key: &str,
    config: &StoredStrictPinConfig,
) -> Result<(), KeepMobileError> {
    let data = serde_json::to_vec(config).map_err(|e| KeepMobileError::StorageError {
        msg: format!("failed to serialize strict pin config: {e}"),
    })?;
    storage.store_share_by_key(key.into(), data, storage_metadata("strict_pin_config"))
}

#[derive(Serialize, Deserialize, Default)]
pub(crate) struct StoredBunkerConfig {
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) authorized_clients: Vec<String>,
    /// Hex-encoded 32-byte transport secret key. The bunker:// pubkey is derived
    /// from this key, so persisting it keeps the bunker URL stable across service
    /// restarts. Stored in the same SQLCipher-backed SecureStorage as the FROST
    /// share material. `Option` + `serde(default)` keeps pre-existing configs
    /// (written before this field existed) deserializable.
    #[serde(default)]
    pub(crate) transport_secret: Option<String>,
    /// Connect secret embedded in the bunker:// URL. Persisted alongside the
    /// transport key so saved client sessions keep authenticating after a restart.
    #[serde(default)]
    pub(crate) connect_secret: Option<String>,
}

pub(crate) fn load_bunker_config(
    storage: &Arc<dyn SecureStorage>,
    key: &str,
) -> Result<Option<StoredBunkerConfig>, KeepMobileError> {
    match storage.load_share_by_key(key.into()) {
        Ok(data) => {
            let config: StoredBunkerConfig =
                serde_json::from_slice(&data).map_err(|e| KeepMobileError::StorageError {
                    msg: format!("failed to deserialize bunker config: {e}"),
                })?;
            Ok(Some(config))
        }
        Err(KeepMobileError::StorageNotFound) => Ok(None),
        Err(e) => {
            tracing::warn!("failed to load bunker config: {e}");
            Err(e)
        }
    }
}

pub(crate) fn persist_bunker_config(
    storage: &Arc<dyn SecureStorage>,
    key: &str,
    config: &StoredBunkerConfig,
) -> Result<(), KeepMobileError> {
    let data = serde_json::to_vec(config).map_err(|e| KeepMobileError::StorageError {
        msg: format!("failed to serialize bunker config: {e}"),
    })?;
    storage.store_share_by_key(key.into(), data, storage_metadata("bunker_config"))
}

pub(crate) fn load_kill_switch(
    storage: &Arc<dyn SecureStorage>,
    key: &str,
) -> Result<bool, KeepMobileError> {
    match storage.load_share_by_key(key.into()) {
        Ok(data) => {
            let enabled: bool =
                serde_json::from_slice(&data).map_err(|e| KeepMobileError::StorageError {
                    msg: format!("failed to deserialize kill switch: {e}"),
                })?;
            Ok(enabled)
        }
        Err(KeepMobileError::StorageNotFound) => Ok(false),
        Err(e) => {
            tracing::warn!("failed to load kill switch: {e}");
            Err(e)
        }
    }
}

pub(crate) fn persist_kill_switch(
    storage: &Arc<dyn SecureStorage>,
    key: &str,
    enabled: bool,
) -> Result<(), KeepMobileError> {
    let data = serde_json::to_vec(&enabled).map_err(|e| KeepMobileError::StorageError {
        msg: format!("failed to serialize kill switch: {e}"),
    })?;
    storage.store_share_by_key(key.into(), data, storage_metadata("kill_switch"))
}

/// The current DKG stash schema. Bumped when the wire shape of the marker or
/// secret changes so a reader can branch on format instead of guessing.
pub(crate) const DKG_STASH_SCHEMA_VERSION: u8 = 1;

/// The non-sensitive half of a pending DKG stash: enough to answer "is a share
/// waiting to be recovered, and how?" without touching the auth-gated secret.
/// Lives under the `__keep_` metadata namespace so `pending_dkg_share` and the
/// `frost_run_dkg` pre-flight can read it with no biometric prompt. Every added
/// field carries `#[serde(default)]` so widening the schema can never turn an
/// older marker into a fail-closed brick.
#[derive(Serialize, Deserialize)]
pub(crate) struct PendingDkgMarker {
    #[serde(default)]
    pub(crate) schema_version: u8,
    pub(crate) name: String,
    pub(crate) group_pubkey_hex: String,
    /// `true` for the on-device DKG path: the ceremony passphrase is ephemeral,
    /// so the secret's at-rest protection is bound to the device vault
    /// (auth-gated Keystore alias) and the passphrase is stashed inside it —
    /// recovery needs only a vault unlock. `false` for the manual QR-import path,
    /// where the user knows the passphrase and supplies it to `recover_dkg_share`.
    #[serde(default)]
    pub(crate) vault_protected: bool,
}

/// The sensitive half of a pending DKG stash: the passphrase-encrypted share
/// export and, for the vault-protected DKG path, the ephemeral ceremony
/// passphrase needed to decrypt it. Stored under a dedicated key the platform
/// routes to an auth-gated (`requireUserAuth`) alias, so at rest it is not
/// app-uid-readable and loading it costs a vault unlock. Read only by
/// `recover_dkg_share`.
#[derive(Serialize, Deserialize)]
pub(crate) struct PendingDkgSecret {
    #[serde(default)]
    pub(crate) schema_version: u8,
    pub(crate) share_export: Zeroizing<String>,
    /// The ephemeral ceremony passphrase, present only for the vault-protected
    /// DKG path. Absent for QR import, where the user supplies it. Never leaves
    /// the auth-gated blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) vault_passphrase: Option<Zeroizing<String>>,
}

pub(crate) fn persist_pending_dkg_marker(
    storage: &Arc<dyn SecureStorage>,
    key: &str,
    marker: &PendingDkgMarker,
) -> Result<(), KeepMobileError> {
    let data = serde_json::to_vec(marker).map_err(|e| KeepMobileError::StorageError {
        msg: format!("failed to serialize pending DKG marker: {e}"),
    })?;
    storage.store_share_by_key(key.into(), data, storage_metadata("dkg_pending"))
}

pub(crate) fn load_pending_dkg_marker(
    storage: &Arc<dyn SecureStorage>,
    key: &str,
) -> Result<Option<PendingDkgMarker>, KeepMobileError> {
    match storage.load_share_by_key(key.into()) {
        Ok(data) => {
            let marker =
                serde_json::from_slice(&data).map_err(|e| KeepMobileError::StorageError {
                    msg: format!("failed to deserialize pending DKG marker: {e}"),
                })?;
            Ok(Some(marker))
        }
        Err(KeepMobileError::StorageNotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn persist_pending_dkg_secret(
    storage: &Arc<dyn SecureStorage>,
    key: &str,
    secret: &PendingDkgSecret,
) -> Result<(), KeepMobileError> {
    // The serialized blob holds the plaintext share export and ceremony
    // passphrase; scrub the local copy once storage has taken its own.
    let data =
        Zeroizing::new(
            serde_json::to_vec(secret).map_err(|e| KeepMobileError::StorageError {
                msg: format!("failed to serialize pending DKG secret: {e}"),
            })?,
        );
    storage.store_share_by_key(key.into(), data.to_vec(), storage_metadata("dkg_secret"))
}

pub(crate) fn load_pending_dkg_secret(
    storage: &Arc<dyn SecureStorage>,
    key: &str,
) -> Result<Option<PendingDkgSecret>, KeepMobileError> {
    match storage.load_share_by_key(key.into()) {
        Ok(data) => {
            // The loaded blob is plaintext secret material; scrub it after parse.
            let data = Zeroizing::new(data);
            let secret =
                serde_json::from_slice(&data).map_err(|e| KeepMobileError::StorageError {
                    msg: format!("failed to deserialize pending DKG secret: {e}"),
                })?;
            Ok(Some(secret))
        }
        Err(KeepMobileError::StorageNotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn delete_pending_dkg_stash(
    storage: &Arc<dyn SecureStorage>,
    marker_key: &str,
    secret_key: &str,
) -> Result<(), KeepMobileError> {
    // Delete the secret first: the marker is what gates "is anything pending?",
    // so an orphaned secret (marker gone, secret left) is the safe failure — it
    // is invisible and overwritten by the next run — whereas an orphaned marker
    // would refuse new runs while pointing at a secret that is already gone.
    match storage.delete_share_by_key(secret_key.into()) {
        Ok(()) | Err(KeepMobileError::StorageNotFound) => {}
        Err(e) => return Err(e),
    }
    match storage.delete_share_by_key(marker_key.into()) {
        Ok(()) | Err(KeepMobileError::StorageNotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod descriptor_index_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    /// Keyed storage reproducing the fault modes the Android backend actually
    /// produces, which are not the same as "the read returns an error".
    #[derive(Default)]
    struct FaultyStorage {
        records: Mutex<HashMap<String, Vec<u8>>>,
        /// Reads of these keys fail with `StorageError`, the record intact.
        unreadable: Mutex<HashSet<String>>,
        /// Reads of these keys answer `StorageNotFound` while the record is
        /// still there. This is what Android does for a value it cannot
        /// decrypt: `KeystoreEncryptedPrefs::getTypedValue` collapses absent
        /// and unreadable into the same `null`, and `loadMetadata` turns that
        /// `null` into `StorageNotFound`.
        unreadable_as_not_found: Mutex<HashSet<String>>,
        /// Reads of these keys delete the record and then fail, which is what
        /// Android's `loadMetadata` does on a metadata decrypt failure: it
        /// clears the per-key prefs file before throwing, and only the DKG
        /// marker is exempt.
        wipe_on_read: Mutex<HashSet<String>>,
        /// Writes to these keys fail, the previous contents intact.
        unwritable: Mutex<HashSet<String>>,
    }

    impl FaultyStorage {
        fn raw(&self, key: &str) -> Option<Vec<u8>> {
            self.records.lock().unwrap().get(key).cloned()
        }

        fn index(&self) -> Vec<String> {
            let data = self
                .raw(DESCRIPTOR_INDEX_KEY)
                .expect("index was never written");
            serde_json::from_slice(&data).expect("index is not valid json")
        }

        fn fault(&self, field: &Mutex<HashSet<String>>, key: &str) {
            field.lock().unwrap().insert(key.into());
        }

        fn clear_faults(&self) {
            self.unwritable.lock().unwrap().clear();
            self.unreadable.lock().unwrap().clear();
            self.unreadable_as_not_found.lock().unwrap().clear();
            self.wipe_on_read.lock().unwrap().clear();
        }
    }

    impl SecureStorage for FaultyStorage {
        fn store_share(&self, _: Vec<u8>, _: ShareMetadataInfo) -> Result<(), KeepMobileError> {
            unimplemented!()
        }
        fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
            unimplemented!()
        }
        fn has_share(&self) -> bool {
            false
        }
        fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
            None
        }
        fn delete_share(&self) -> Result<(), KeepMobileError> {
            unimplemented!()
        }
        fn store_share_by_key(
            &self,
            key: String,
            data: Vec<u8>,
            _: ShareMetadataInfo,
        ) -> Result<(), KeepMobileError> {
            if self.unwritable.lock().unwrap().contains(&key) {
                return Err(KeepMobileError::StorageError {
                    msg: "cannot write right now".into(),
                });
            }
            self.records.lock().unwrap().insert(key, data);
            Ok(())
        }
        fn load_share_by_key(&self, key: String) -> Result<Vec<u8>, KeepMobileError> {
            if self.wipe_on_read.lock().unwrap().contains(&key) {
                self.records.lock().unwrap().remove(&key);
                return Err(KeepMobileError::StorageError {
                    msg: "decrypt failed, entry wiped".into(),
                });
            }
            if self.unreadable_as_not_found.lock().unwrap().contains(&key) {
                return Err(KeepMobileError::StorageNotFound);
            }
            if self.unreadable.lock().unwrap().contains(&key) {
                return Err(KeepMobileError::StorageError {
                    msg: "cannot decrypt right now".into(),
                });
            }
            self.records
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .ok_or(KeepMobileError::StorageNotFound)
        }
        fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
            vec![]
        }
        fn delete_share_by_key(&self, key: String) -> Result<(), KeepMobileError> {
            self.records.lock().unwrap().remove(&key);
            Ok(())
        }
        fn get_active_share_key(&self) -> Option<String> {
            None
        }
        fn set_active_share_key(&self, _: Option<String>) -> Result<(), KeepMobileError> {
            Ok(())
        }
    }

    const AA: &str = "aa";
    const BB: &str = "bb";
    const CC: &str = "cc";

    fn descriptor(group_hex: &str) -> WalletDescriptorInfo {
        WalletDescriptorInfo {
            group_pubkey: group_hex.into(),
            external_descriptor: "wpkh(xpub.../0/*)".into(),
            internal_descriptor: "wpkh(xpub.../1/*)".into(),
            network: "bitcoin".into(),
            created_at: 1_700_000_000,
            device_registrations: vec![],
            policy_hash_hex: None,
            version: 1,
            previous_descriptor_hash_hex: None,
            policy_json: None,
        }
    }

    fn storage_with(groups: &[&str]) -> (Arc<FaultyStorage>, Arc<dyn SecureStorage>) {
        let faulty = Arc::new(FaultyStorage::default());
        let storage: Arc<dyn SecureStorage> = faulty.clone();
        for group in groups {
            persist_descriptor(&storage, &descriptor(group)).unwrap();
        }
        assert_eq!(faulty.index().len(), groups.len());
        (faulty, storage)
    }

    // One prefs key that will not decrypt fails every descriptor in a single
    // pass, so pruning on a read failure emptied the index and left every
    // surviving record unreferenced.
    #[test]
    fn an_unreadable_descriptor_keeps_its_index_entry() {
        let (faulty, storage) = storage_with(&[AA, BB]);
        faulty.fault(&faulty.unreadable, &descriptor_key(AA));
        faulty.fault(&faulty.unreadable, &descriptor_key(BB));

        let load = load_descriptors(&storage).unwrap();
        assert!(load.loaded.is_empty());
        assert_eq!(load.unreadable, vec![AA.to_string(), BB.to_string()]);
        assert_eq!(faulty.index().len(), 2, "a read path must not prune");

        faulty.clear_faults();
        assert_eq!(
            load_descriptors(&storage).unwrap().loaded.len(),
            2,
            "both descriptors come back once storage recovers"
        );
    }

    // The fault Android actually produces for a record it cannot decrypt: the
    // read answers `StorageNotFound` while the record is still on disk. Pruning
    // on `StorageNotFound` treated this as proof of absence.
    #[test]
    fn a_descriptor_that_reads_as_absent_keeps_its_index_entry() {
        let (faulty, storage) = storage_with(&[AA, BB]);
        faulty.fault(&faulty.unreadable_as_not_found, &descriptor_key(AA));

        let load = load_descriptors(&storage).unwrap();
        assert_eq!(load.loaded.len(), 1);
        assert_eq!(load.unreadable, vec![AA.to_string()]);
        assert_eq!(faulty.index(), vec![AA.to_string(), BB.to_string()]);

        faulty.clear_faults();
        assert_eq!(load_descriptors(&storage).unwrap().loaded.len(), 2);
    }

    // A record that reads but will not deserialize is kept too: a version skew
    // looks the same as corruption from here.
    #[test]
    fn a_descriptor_that_will_not_deserialize_keeps_its_index_entry() {
        let (faulty, storage) = storage_with(&[AA, BB]);
        storage
            .store_share_by_key(
                descriptor_key(AA),
                b"not json".to_vec(),
                storage_metadata("descriptor"),
            )
            .unwrap();

        let load = load_descriptors(&storage).unwrap();
        assert_eq!(load.loaded.len(), 1);
        assert_eq!(load.unreadable, vec![AA.to_string()]);
        assert_eq!(faulty.index(), vec![AA.to_string(), BB.to_string()]);
    }

    // Even a record that is genuinely gone keeps its entry, because nothing
    // available here proves absence and the entry costs one failed read.
    // `delete_descriptor` is the one place an entry is removed.
    #[test]
    fn a_read_path_never_prunes_the_index() {
        let (faulty, storage) = storage_with(&[AA, BB]);
        storage.delete_share_by_key(descriptor_key(AA)).unwrap();

        let load = load_descriptors(&storage).unwrap();
        assert_eq!(load.loaded.len(), 1);
        assert_eq!(load.loaded[0].group_pubkey, BB);
        assert_eq!(load.unreadable, vec![AA.to_string()]);
        assert_eq!(faulty.index(), vec![AA.to_string(), BB.to_string()]);
    }

    // Android wipes the entry before it reports the failure, so keeping the
    // index entry is not a path back to the record. What it does buy is that
    // the reference is still there to be refused over, instead of a later save
    // silently rebuilding the index without it.
    #[test]
    fn a_wiped_descriptor_still_keeps_its_index_entry() {
        let (faulty, storage) = storage_with(&[AA, BB]);
        faulty.fault(&faulty.wipe_on_read, &descriptor_key(AA));

        let load = load_descriptors(&storage).unwrap();
        assert_eq!(load.unreadable, vec![AA.to_string()]);
        assert!(
            faulty.raw(&descriptor_key(AA)).is_none(),
            "the backend destroyed the record on the failed read"
        );
        assert_eq!(faulty.index(), vec![AA.to_string(), BB.to_string()]);
    }

    // Characterization, not an endorsement: an index that reads as absent is
    // treated as a first run, which is what lets a genuine first device save its
    // first descriptor. On Android that same read is what an index it cannot
    // decrypt produces, so this is the path by which a fault can still cost
    // references, and it is deliberately not defended here: every independent
    // signal available to this layer reads through the same collapsing getter,
    // and probing for a surviving record would route through the platform call
    // that destroys the record it cannot decrypt. This test exists so the
    // behavior is visible and fails loudly when the platform starts reporting
    // absent and unreadable apart.
    #[test]
    fn an_index_that_reads_as_absent_is_treated_as_a_first_run() {
        let (faulty, storage) = storage_with(&[AA]);
        faulty.fault(&faulty.unreadable_as_not_found, DESCRIPTOR_INDEX_KEY);

        assert!(
            load_descriptors(&storage).unwrap().loaded.is_empty(),
            "the surviving reference is not reported"
        );
        persist_descriptor(&storage, &descriptor(BB)).expect("and the save proceeds");

        faulty.clear_faults();
        assert_eq!(
            faulty.index(),
            vec![BB.to_string()],
            "losing the reference the unreadable index held, which only the \
             platform can prevent"
        );
        assert!(
            faulty.raw(&descriptor_key(AA)).is_some(),
            "the record itself survives, so the platform fix recovers it"
        );
    }

    // The one fault-to-destructive-write chain this layer cannot break, start to
    // finish. The index key is itself a metadata key, so a platform read of it
    // that cannot decrypt destroys it before reporting; the next read then
    // answers `StorageNotFound`, which is indistinguishable from a first run,
    // and the save after that writes an index holding only the new descriptor.
    // Every step after the first is this code behaving exactly as documented,
    // which is why the break has to come from the platform reporting absent and
    // unreadable apart. This test fails loudly when it does.
    #[test]
    fn a_wiped_index_read_leads_to_a_truncated_index_on_the_next_save() {
        let (faulty, storage) = storage_with(&[AA, BB]);
        faulty.fault(&faulty.wipe_on_read, DESCRIPTOR_INDEX_KEY);

        load_descriptors(&storage).expect_err("the read refuses, having destroyed the index");
        assert!(
            faulty.raw(DESCRIPTOR_INDEX_KEY).is_none(),
            "the backend wiped the index on the failed read"
        );

        faulty.clear_faults();
        assert!(
            load_descriptors(&storage).unwrap().loaded.is_empty(),
            "the index is now genuinely gone, so it reads as a first run"
        );
        persist_descriptor(&storage, &descriptor(CC)).unwrap();
        assert_eq!(
            faulty.index(),
            vec![CC.to_string()],
            "and the next save writes only the new descriptor"
        );
        for group in [AA, BB] {
            assert!(
                faulty.raw(&descriptor_key(group)).is_some(),
                "while both records survive, now unreferenced and unreachable"
            );
        }
    }

    // The worst of the index writers: persist read the index, got an empty vec
    // from the swallowed failure, and wrote back an index holding only the new
    // descriptor, dropping every other wallet reference on the device.
    #[test]
    fn persisting_a_descriptor_refuses_an_unreadable_index() {
        let (faulty, storage) = storage_with(&[AA, BB]);
        faulty.fault(&faulty.unreadable, DESCRIPTOR_INDEX_KEY);

        let err = persist_descriptor(&storage, &descriptor(CC))
            .expect_err("an unreadable index must not be rewritten");
        assert!(
            matches!(&err, KeepMobileError::StorageError { msg } if msg.contains("cannot decrypt")),
            "the index read is what refused, not a validation check: {err}"
        );
        assert!(
            faulty.raw(&descriptor_key(CC)).is_none(),
            "the index is read before the record is written, so a refusal leaves no orphan"
        );

        faulty.clear_faults();
        assert_eq!(faulty.index(), vec![AA.to_string(), BB.to_string()]);
    }

    #[test]
    fn deleting_a_descriptor_refuses_an_unreadable_index() {
        let (faulty, storage) = storage_with(&[AA, BB]);
        faulty.fault(&faulty.unreadable, DESCRIPTOR_INDEX_KEY);

        delete_descriptor(&storage, AA).expect_err("an unreadable index must not be rewritten");
        assert!(
            faulty.raw(&descriptor_key(AA)).is_some(),
            "the index is read before the delete, so a refused delete destroys nothing"
        );

        faulty.clear_faults();
        assert_eq!(faulty.index(), vec![AA.to_string(), BB.to_string()]);
    }

    // A first run has no index and no descriptor records, so the first save
    // still works.
    #[test]
    fn a_missing_index_reads_as_empty_on_a_first_run() {
        let faulty = Arc::new(FaultyStorage::default());
        let storage: Arc<dyn SecureStorage> = faulty.clone();

        assert!(load_descriptors(&storage).unwrap().loaded.is_empty());
        persist_descriptor(&storage, &descriptor(AA)).unwrap();
        assert_eq!(faulty.index(), vec![AA.to_string()]);
    }

    // A corrupt index is not an empty one, and its error is recognizable so the
    // layer above can offer an explicit reset.
    #[test]
    fn a_corrupt_index_is_not_treated_as_empty() {
        let faulty = Arc::new(FaultyStorage::default());
        let storage: Arc<dyn SecureStorage> = faulty.clone();
        storage
            .store_share_by_key(
                DESCRIPTOR_INDEX_KEY.into(),
                b"not json".to_vec(),
                storage_metadata("descriptor_index"),
            )
            .unwrap();

        let err = load_descriptors(&storage)
            .expect_err("a corrupt index must surface, not read as empty");
        assert!(
            matches!(&err, KeepMobileError::StorageError { msg } if msg.contains(DESCRIPTOR_INDEX_CORRUPT_MSG)),
            "a corrupt index needs a recognizable error: {err}"
        );
        persist_descriptor(&storage, &descriptor(AA))
            .expect_err("a corrupt index must not be overwritten");
        assert_eq!(
            faulty.raw(DESCRIPTOR_INDEX_KEY).unwrap(),
            b"not json".to_vec()
        );
    }

    // The half-applied state the write order is chosen for. An index entry whose
    // record never landed is reported, never pruned, and a retry completes the
    // save; the reverse order would leave a record no list can see, on a device
    // whose absent index the read path then refuses, so the retry stays refused.
    #[test]
    fn an_index_entry_whose_record_failed_to_write_is_recoverable() {
        let (faulty, storage) = storage_with(&[AA]);
        faulty.fault(&faulty.unwritable, &descriptor_key(BB));

        persist_descriptor(&storage, &descriptor(BB)).expect_err("the record write fails");
        assert_eq!(
            faulty.index(),
            vec![AA.to_string(), BB.to_string()],
            "the index entry landed first"
        );
        assert!(
            faulty.raw(&descriptor_key(BB)).is_none(),
            "the record did not"
        );

        let load = load_descriptors(&storage).unwrap();
        assert_eq!(load.loaded.len(), 1);
        assert_eq!(load.unreadable, vec![BB.to_string()]);
        assert_eq!(
            faulty.index(),
            vec![AA.to_string(), BB.to_string()],
            "and the read path still does not prune it"
        );

        faulty.clear_faults();
        persist_descriptor(&storage, &descriptor(BB)).expect("the retry completes the save");
        assert_eq!(
            faulty.index(),
            vec![AA.to_string(), BB.to_string()],
            "with no duplicate entry"
        );
        assert_eq!(load_descriptors(&storage).unwrap().loaded.len(), 2);
    }
}
