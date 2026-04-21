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
}

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
    /// `sha256(u64_le(ext.len) || ext || u64_le(int.len) || int || policy_hash)`.
    ///
    /// Must match the on-wire `descriptor_hash` used by the FROST PSBT
    /// coordination protocol.
    pub fn canonical_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update((self.external_descriptor.len() as u64).to_le_bytes());
        h.update(self.external_descriptor.as_bytes());
        h.update((self.internal_descriptor.len() as u64).to_le_bytes());
        h.update(self.internal_descriptor.as_bytes());
        h.update(self.policy_hash);
        h.finalize().into()
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
        };
        let signer = [7u8; 32];
        desc.upsert_device_registration(DeviceRegistration {
            signer_pubkey: signer,
            wallet_name: "first".into(),
            hmac: Some(Zeroizing::new(vec![1, 2, 3])),
            registered_at: 1,
        });
        desc.upsert_device_registration(DeviceRegistration {
            signer_pubkey: signer,
            wallet_name: "second".into(),
            hmac: Some(Zeroizing::new(vec![9, 9, 9])),
            registered_at: 2,
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
    fn test_empty_registrations_roundtrip_omits_field() {
        let desc = WalletDescriptor {
            group_pubkey: [0u8; 32],
            external_descriptor: "a".into(),
            internal_descriptor: "b".into(),
            network: "testnet".into(),
            created_at: 1,
            device_registrations: Vec::new(),
            policy_hash: [0u8; 32],
        };
        let json = serde_json::to_string(&desc).unwrap();
        assert!(!json.contains("device_registrations"));
    }
}
