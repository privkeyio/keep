// SPDX-FileCopyrightText: (C) 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Health status of a key share from a liveness check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyHealthStatus {
    /// The FROST group public key.
    pub group_pubkey: [u8; 32],
    /// The share index that was checked.
    pub share_index: u16,
    /// Unix timestamp of the last health check.
    pub last_check_timestamp: u64,
    /// Whether the share was responsive.
    pub responsive: bool,
    /// Unix timestamp when this record was first created (None for legacy records).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

/// 24 hours - key not checked in this period is considered stale.
pub const KEY_HEALTH_STALE_THRESHOLD_SECS: u64 = 86400;
/// 7 days - key not checked in this period is critically stale.
pub const KEY_HEALTH_CRITICAL_THRESHOLD_SECS: u64 = 604800;

impl KeyHealthStatus {
    /// Returns true if the last check is older than the stale threshold (24h).
    pub fn is_stale(&self, now: u64) -> bool {
        now.saturating_sub(self.last_check_timestamp) >= KEY_HEALTH_STALE_THRESHOLD_SECS
    }

    /// Returns true if the last check is older than the critical threshold (7d).
    pub fn is_critical(&self, now: u64) -> bool {
        now.saturating_sub(self.last_check_timestamp) >= KEY_HEALTH_CRITICAL_THRESHOLD_SECS
    }
}

/// Record of a hardware signer that has registered this wallet via NIP-46.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRegistration {
    /// The NIP-46 signer pubkey (x-only, 32 bytes).
    pub signer_pubkey: [u8; 32],
    /// The wallet name sent to the device at registration time.
    pub wallet_name: String,
    /// Opaque registration token returned by the device, if any.
    ///
    /// This value is **not** cryptographically verified by keep-core; it is
    /// an arbitrary byte string the device returned at registration time and
    /// must not be treated as an authenticator unless a verification protocol
    /// is added. The inner `Vec<u8>` is wrapped in `Zeroizing` so in-memory
    /// copies are wiped on drop even when the enclosing descriptor is cloned.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "zeroizing_vec_opt"
    )]
    pub hmac: Option<Zeroizing<Vec<u8>>>,
    /// Unix timestamp of the successful registration.
    pub registered_at: u64,
    /// Device kind reported by the signer (e.g. "Coldcard", "Ledger"), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_kind: Option<String>,
    /// BIP32 master key fingerprint reported by the signer, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<[u8; 4]>,
    /// Firmware version string reported by the signer, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<String>,
}

mod zeroizing_vec_opt {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<Zeroizing<Vec<u8>>>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match value {
            Some(v) => serializer.serialize_some(&v[..]),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, D::Error> {
        let opt: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        Ok(opt.map(Zeroizing::new))
    }
}

impl std::fmt::Debug for DeviceRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRegistration")
            .field("signer_pubkey", &self.signer_pubkey)
            .field("wallet_name", &self.wallet_name)
            .field(
                "hmac",
                &self
                    .hmac
                    .as_ref()
                    .map(|h| format!("<redacted; {} bytes>", h.len())),
            )
            .field("registered_at", &self.registered_at)
            .field("device_kind", &self.device_kind)
            .field("fingerprint", &self.fingerprint.map(hex::encode))
            .field("firmware_version", &self.firmware_version)
            .finish()
    }
}

/// A finalized wallet descriptor associated with a FROST group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletDescriptor {
    /// The FROST group public key this descriptor belongs to.
    pub group_pubkey: [u8; 32],
    /// The external (receive) descriptor string.
    pub external_descriptor: String,
    /// The internal (change) descriptor string.
    pub internal_descriptor: String,
    /// The Bitcoin network (e.g. "bitcoin", "testnet", "signet", "regtest").
    pub network: String,
    /// Unix timestamp when the descriptor was created.
    pub created_at: u64,
    /// Hardware signers that have registered this wallet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_registrations: Vec<DeviceRegistration>,
    /// Hash of the wallet policy that produced this descriptor. Required for
    /// canonical descriptor hashing (matches the on-wire `descriptor_hash`
    /// computed as length-framed
    /// `sha256(len(ext) || ext || len(int) || int || policy_hash)`).
    #[serde(default)]
    pub policy_hash: [u8; 32],
    /// Monotonic version of the descriptor for this group. Starts at 1 for the
    /// initial descriptor and increments on each migration. Records persisted
    /// before versioning materialize as `1` via `#[serde(default)]` +
    /// [`default_descriptor_version`].
    #[serde(
        default = "default_descriptor_version",
        deserialize_with = "deserialize_nonzero_version"
    )]
    pub version: u32,
    /// Canonical hash of the descriptor this one supersedes, when this is a
    /// migration. `None` for the initial descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_descriptor_hash: Option<[u8; 32]>,
    /// The wallet policy that produced this descriptor, persisted as an opaque
    /// JSON value so `keep-core` does not depend on `keep-frost-net`. Callers
    /// reconstruct `WalletPolicy` via `serde_json::from_value`. Older records
    /// without this field deserialize with `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<serde_json::Value>,
}

/// The version assigned to the initial wallet descriptor for a group.
/// Subsequent migrations increment this monotonically.
pub const INITIAL_DESCRIPTOR_VERSION: u32 = 1;

/// Default value for [`WalletDescriptor::version`] when deserializing legacy
/// records that predate the versioning field.
pub fn default_descriptor_version() -> u32 {
    INITIAL_DESCRIPTOR_VERSION
}

fn deserialize_nonzero_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let v = u32::deserialize(deserializer)?;
    if v == 0 {
        return Err(serde::de::Error::custom(
            "descriptor version must be >= 1 (versions start at INITIAL_DESCRIPTOR_VERSION)",
        ));
    }
    Ok(v)
}

/// Domain-separated version suffix folded into the canonical descriptor hash
/// for v2+ descriptors. v1 hashes intentionally omit this suffix to remain
/// bit-identical to records written before descriptor versioning existed.
///
/// Centralizing the fold keeps every site that recomputes the descriptor hash
/// (initiator, ack verifier, migrate verifier, persisted hash) in lockstep.
/// TODO: drop the conditional in vN+1 once all v1 records are migrated.
pub fn fold_descriptor_version_suffix(hasher: &mut sha2::Sha256, version: u32) {
    use sha2::Digest;
    if version > INITIAL_DESCRIPTOR_VERSION {
        hasher.update(b"keep/descriptor/version");
        hasher.update(version.to_le_bytes());
    }
}

/// Compute the canonical descriptor hash from its constituent parts.
/// Centralizing this avoids drift between sites that recompute the hash
/// (initiator, ack verifier, migrate verifier, persisted descriptor, mobile
/// completion handler). Must match [`WalletDescriptor::canonical_hash`] and the
/// on-wire `descriptor_hash` used by the FROST PSBT coordination protocol.
///
/// Returns an error if `version == 0`, which is invalid by construction
/// (descriptor versions start at 1 and increment monotonically). A
/// zero-version hash cannot match any other code path's computation since the
/// v2+ fold and v1 omission diverge, so producing one would silently corrupt
/// lineage.
pub fn canonical_descriptor_hash(
    external_descriptor: &str,
    internal_descriptor: &str,
    policy_hash: &[u8; 32],
    version: u32,
) -> std::result::Result<[u8; 32], CanonicalHashError> {
    use sha2::{Digest, Sha256};
    if version == 0 {
        return Err(CanonicalHashError::ZeroVersion);
    }
    let mut h = Sha256::new();
    h.update((external_descriptor.len() as u64).to_le_bytes());
    h.update(external_descriptor.as_bytes());
    h.update((internal_descriptor.len() as u64).to_le_bytes());
    h.update(internal_descriptor.as_bytes());
    h.update(policy_hash);
    fold_descriptor_version_suffix(&mut h, version);
    Ok(h.finalize().into())
}

/// Error produced when [`canonical_descriptor_hash`] is given invalid inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalHashError {
    /// `version == 0` was supplied (versions start at 1).
    ZeroVersion,
}

impl std::fmt::Display for CanonicalHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonicalHashError::ZeroVersion => f.write_str(
                "canonical descriptor hash requested for version 0 (versions start at 1)",
            ),
        }
    }
}

impl std::error::Error for CanonicalHashError {}

impl WalletDescriptor {
    /// Return the registration record for a signer pubkey, if any.
    pub fn device_registration(&self, signer_pubkey: &[u8; 32]) -> Option<&DeviceRegistration> {
        self.device_registrations
            .iter()
            .find(|r| &r.signer_pubkey == signer_pubkey)
    }

    /// Insert or update the registration for a signer pubkey.
    pub fn upsert_device_registration(&mut self, reg: DeviceRegistration) {
        if let Some(slot) = self
            .device_registrations
            .iter_mut()
            .find(|r| r.signer_pubkey == reg.signer_pubkey)
        {
            *slot = reg;
        } else {
            self.device_registrations.push(reg);
        }
    }

    /// Canonical descriptor hash with length framing to avoid collisions
    /// when the split between external/internal shifts:
    /// `sha256(u64_le(ext.len) || ext || u64_le(int.len) || int || policy_hash
    ///   [|| "keep/descriptor/version" || u32_le(version) when version > 1])`.
    ///
    /// The version suffix is only folded in for v2+ so v1 hashes remain
    /// bit-identical to records written before descriptor versioning existed
    /// (mirroring the conditional fold in `hash_policy`).
    /// TODO: drop the conditional suffix in vN+1 once all v1 records are
    /// migrated.
    ///
    /// Must match the on-wire `descriptor_hash` used by the FROST PSBT
    /// coordination protocol.
    pub fn canonical_hash(&self) -> [u8; 32] {
        // `WalletDescriptor::version` is enforced non-zero by
        // `deserialize_nonzero_version` and by every in-process constructor, so
        // this unwrap is unreachable. `try_canonical_hash` is the fallible
        // entry point for callers that handle raw byte buffers directly.
        self.try_canonical_hash()
            .expect("WalletDescriptor::canonical_hash: version invariant (>= 1) violated")
    }

    /// Fallible variant of [`canonical_hash`] that returns an error rather
    /// than panicking when `version == 0`. Prefer this in code paths that
    /// hash freshly-deserialized inputs without re-validating the version
    /// invariant.
    pub fn try_canonical_hash(&self) -> std::result::Result<[u8; 32], CanonicalHashError> {
        canonical_descriptor_hash(
            &self.external_descriptor,
            &self.internal_descriptor,
            &self.policy_hash,
            self.version,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_descriptor_back_compat_deserializes_without_registrations() {
        let json = r#"{
            "group_pubkey": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "external_descriptor": "tr(xpub.../0/*)#abc",
            "internal_descriptor": "tr(xpub.../1/*)#def",
            "network": "testnet",
            "created_at": 1700000000
        }"#;
        let desc: WalletDescriptor = serde_json::from_str(json).expect("back-compat deserialize");
        assert!(desc.device_registrations.is_empty());
        assert_eq!(desc.version, 1);
        assert!(desc.previous_descriptor_hash.is_none());
    }

    #[test]
    fn test_upsert_device_registration_inserts_then_replaces() {
        let mut desc = WalletDescriptor {
            group_pubkey: [0u8; 32],
            external_descriptor: String::new(),
            internal_descriptor: String::new(),
            network: "testnet".into(),
            created_at: 0,
            device_registrations: Vec::new(),
            policy_hash: [0u8; 32],
            version: 1,
            previous_descriptor_hash: None,
            policy: None,
        };
        let signer = [7u8; 32];
        desc.upsert_device_registration(DeviceRegistration {
            signer_pubkey: signer,
            wallet_name: "first".into(),
            hmac: Some(Zeroizing::new(vec![1, 2, 3])),
            registered_at: 1,
            device_kind: None,
            fingerprint: None,
            firmware_version: None,
        });
        desc.upsert_device_registration(DeviceRegistration {
            signer_pubkey: signer,
            wallet_name: "second".into(),
            hmac: Some(Zeroizing::new(vec![9, 9, 9])),
            registered_at: 2,
            device_kind: None,
            fingerprint: None,
            firmware_version: None,
        });
        assert_eq!(desc.device_registrations.len(), 1);
        let reg = desc.device_registration(&signer).unwrap();
        assert_eq!(reg.wallet_name, "second");
        assert_eq!(
            reg.hmac.as_ref().map(|v| v.as_slice()),
            Some(&[9, 9, 9][..])
        );
    }

    #[test]
    fn test_device_registration_back_compat_without_metadata_fields() {
        // Existing on-disk shape, no device_kind/fingerprint/firmware_version
        let json = r#"{
            "signer_pubkey": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "wallet_name": "legacy",
            "registered_at": 1700000000
        }"#;
        let reg: DeviceRegistration =
            serde_json::from_str(json).expect("legacy DeviceRegistration deserializes");
        assert!(reg.device_kind.is_none());
        assert!(reg.fingerprint.is_none());
        assert!(reg.firmware_version.is_none());
        assert!(reg.hmac.is_none());
        let json_out = serde_json::to_string(&reg).unwrap();
        assert!(!json_out.contains("device_kind"));
        assert!(!json_out.contains("fingerprint"));
        assert!(!json_out.contains("firmware_version"));
        assert!(!json_out.contains("hmac"));
    }

    #[test]
    fn test_device_registration_roundtrip_with_metadata_fields() {
        let reg = DeviceRegistration {
            signer_pubkey: [1u8; 32],
            wallet_name: "treasury".into(),
            hmac: None,
            registered_at: 42,
            device_kind: Some("Coldcard".into()),
            fingerprint: Some([0xde, 0xad, 0xbe, 0xef]),
            firmware_version: Some("1.2.3".into()),
        };
        let json = serde_json::to_string(&reg).unwrap();
        let back: DeviceRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(back.device_kind.as_deref(), Some("Coldcard"));
        assert_eq!(back.fingerprint, Some([0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(back.firmware_version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn test_wallet_descriptor_roundtrip_preserves_device_registrations() {
        let reg = DeviceRegistration {
            signer_pubkey: [7u8; 32],
            wallet_name: "primary".into(),
            hmac: Some(Zeroizing::new(vec![0xaa; 32])),
            registered_at: 1234,
            device_kind: Some("Ledger".into()),
            fingerprint: Some([0x01, 0x02, 0x03, 0x04]),
            firmware_version: Some("2.1.0".into()),
        };
        let desc = WalletDescriptor {
            group_pubkey: [9u8; 32],
            external_descriptor: "tr(xpub.../0/*)".into(),
            internal_descriptor: "tr(xpub.../1/*)".into(),
            network: "bitcoin".into(),
            created_at: 1700000000,
            device_registrations: vec![reg],
            policy_hash: [0u8; 32],
            version: 1,
            previous_descriptor_hash: None,
            policy: None,
        };
        let json = serde_json::to_string(&desc).unwrap();
        let back: WalletDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(back.device_registrations.len(), 1);
        let r = &back.device_registrations[0];
        assert_eq!(r.signer_pubkey, [7u8; 32]);
        assert_eq!(r.wallet_name, "primary");
        assert_eq!(r.device_kind.as_deref(), Some("Ledger"));
        assert_eq!(r.fingerprint, Some([0x01, 0x02, 0x03, 0x04]));
        assert_eq!(r.firmware_version.as_deref(), Some("2.1.0"));
        assert_eq!(r.hmac.as_deref().map(|h| h.to_vec()), Some(vec![0xaa; 32]));
    }

    #[test]
    fn test_canonical_hash_v1_matches_legacy_pre_upgrade_bytes() {
        // Regression: a descriptor with the default version (1) and no
        // previous_descriptor_hash must produce the same canonical_hash as
        // before descriptor versioning was introduced. The expected hash is
        // pinned here so any change to the v1 hashing path is caught.
        let desc = WalletDescriptor {
            group_pubkey: [0u8; 32],
            external_descriptor: "tr(xpub.../0/*)#abc".into(),
            internal_descriptor: "tr(xpub.../1/*)#def".into(),
            network: "testnet".into(),
            created_at: 0,
            device_registrations: Vec::new(),
            policy_hash: [0xAAu8; 32],
            version: 1,
            previous_descriptor_hash: None,
        };
        // Pinned bytes computed against the legacy formula:
        // sha256(le_u64(len(ext)) || ext || le_u64(len(int)) || int || policy_hash)
        let expected = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update((desc.external_descriptor.len() as u64).to_le_bytes());
            h.update(desc.external_descriptor.as_bytes());
            h.update((desc.internal_descriptor.len() as u64).to_le_bytes());
            h.update(desc.internal_descriptor.as_bytes());
            h.update(desc.policy_hash);
            let out: [u8; 32] = h.finalize().into();
            out
        };
        assert_eq!(desc.canonical_hash(), expected);
    }

    #[test]
    fn test_canonical_hash_differs_for_v2() {
        let mut v1 = WalletDescriptor {
            group_pubkey: [0u8; 32],
            external_descriptor: "ext".into(),
            internal_descriptor: "int".into(),
            network: "testnet".into(),
            created_at: 0,
            device_registrations: Vec::new(),
            policy_hash: [0u8; 32],
            version: 1,
            previous_descriptor_hash: None,
        };
        let h1 = v1.canonical_hash();
        v1.version = 2;
        let h2 = v1.canonical_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_empty_registrations_roundtrip_omits_field() {
        let desc = WalletDescriptor {
            group_pubkey: [0u8; 32],
            external_descriptor: "a".into(),
            internal_descriptor: "b".into(),
            network: "testnet".into(),
            created_at: 1,
            device_registrations: Vec::new(),
            policy_hash: [0u8; 32],
            version: 1,
            previous_descriptor_hash: None,
            policy: None,
        };
        let json = serde_json::to_string(&desc).unwrap();
        assert!(!json.contains("device_registrations"));
        assert!(!json.contains("\"policy\""));
    }

    #[test]
    fn test_descriptor_back_compat_deserializes_without_policy() {
        let json = r#"{
            "group_pubkey": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "external_descriptor": "tr(xpub.../0/*)#abc",
            "internal_descriptor": "tr(xpub.../1/*)#def",
            "network": "testnet",
            "created_at": 1700000000
        }"#;
        let desc: WalletDescriptor = serde_json::from_str(json).expect("back-compat deserialize");
        assert!(desc.policy.is_none());
    }

    #[test]
    fn test_descriptor_policy_roundtrips() {
        let policy = serde_json::json!({
            "recovery_tiers": [{
                "threshold": 2,
                "timelock_months": 6,
                "key_slots": [
                    {"type": "participant", "share_index": 1},
                    {"type": "external", "xpub": "xpub6...", "fingerprint": "abcdef01"}
                ]
            }]
        });
        let desc = WalletDescriptor {
            group_pubkey: [0u8; 32],
            external_descriptor: "a".into(),
            internal_descriptor: "b".into(),
            network: "testnet".into(),
            created_at: 1,
            device_registrations: Vec::new(),
            policy_hash: [0u8; 32],
            policy: Some(policy.clone()),
        };
        let json = serde_json::to_string(&desc).unwrap();
        let parsed: WalletDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.policy.as_ref(), Some(&policy));
    }
}
