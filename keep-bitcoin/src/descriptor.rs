// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::str::FromStr;

use bitcoin::bip32::Xpub;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::{Network, XOnlyPublicKey};
use miniscript::{Descriptor, DescriptorPublicKey};

use crate::address::AddressDerivation;
use crate::error::{BitcoinError, Result};
use crate::recovery::RecoveryConfig;

pub fn xpub_to_x_only(xpub: &str, network: Network) -> Result<[u8; 32]> {
    let parsed =
        Xpub::from_str(xpub).map_err(|e| BitcoinError::Descriptor(format!("invalid xpub: {e}")))?;

    let is_mainnet = network == Network::Bitcoin;
    let is_mainnet_xpub = xpub.starts_with("xpub");
    if is_mainnet != is_mainnet_xpub {
        let (expected, got) = if is_mainnet {
            ("mainnet xpub", "testnet tpub")
        } else {
            ("testnet tpub", "mainnet xpub")
        };
        return Err(BitcoinError::Descriptor(format!(
            "expected {expected} but got {got}"
        )));
    }

    Ok(parsed.to_x_only_pub().serialize())
}

pub struct DescriptorExport {
    pub descriptor: String,
    pub checksum: String,
    pub fingerprint: String,
    pub network: Network,
}

impl DescriptorExport {
    pub fn from_derivation(derivation: &AddressDerivation, account: u32) -> Result<Self> {
        let network = derivation.network();
        let fingerprint = derivation.master_fingerprint()?;
        let xpub = derivation.account_xpub(account)?;

        let coin_type = if network == Network::Bitcoin { 0 } else { 1 };

        let descriptor = format!("tr([{fingerprint}/86'/{coin_type}'/{account}']{xpub}/0/*)");

        let (descriptor, checksum) = canonicalize_descriptor(&descriptor)?;

        Ok(Self {
            descriptor,
            checksum,
            fingerprint: fingerprint.to_string(),
            network,
        })
    }

    pub fn from_frost_wallet(
        group_pubkey: &[u8; 32],
        recovery: Option<&RecoveryConfig>,
        network: Network,
    ) -> Result<Self> {
        let xonly = XOnlyPublicKey::from_slice(group_pubkey)
            .map_err(|e| BitcoinError::Descriptor(format!("invalid group pubkey: {e}")))?;
        let fingerprint = Self::pubkey_fingerprint(group_pubkey);

        let (descriptor, checksum) = match recovery {
            None => canonicalize_descriptor(&format!("tr({xonly})"))?,
            Some(config) => {
                let output = config.build_with_internal_key(&xonly)?;
                canonicalize_descriptor(&output.descriptor)?
            }
        };

        Ok(Self {
            descriptor,
            checksum,
            fingerprint,
            network,
        })
    }

    pub fn pubkey_fingerprint(pubkey: &[u8; 32]) -> String {
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(pubkey);
        let h = hash160::Hash::hash(&compressed);
        hex::encode(&h[..4])
    }

    pub fn external_descriptor(&self) -> &str {
        &self.descriptor
    }

    pub fn internal_descriptor(&self) -> Result<String> {
        let body = keep_core::descriptor::rewrite_trailing_zero_to_one(self.descriptor_body());
        let (canonical, _) = canonicalize_descriptor(&body)?;
        Ok(canonical)
    }

    pub fn is_single_chain(&self) -> bool {
        let body = self.descriptor_body();
        !keep_core::descriptor::has_single_path_tail(body)
            && !keep_core::descriptor::has_multipath_marker(body)
    }

    fn descriptor_body(&self) -> &str {
        self.descriptor
            .split('#')
            .next()
            .unwrap_or(&self.descriptor)
    }

    pub fn multipath_descriptor(&self) -> Result<String> {
        multipath_from_external(&self.descriptor)
    }

    pub fn to_sparrow_json(&self, name: &str) -> Result<String> {
        if self.is_single_chain() {
            return Err(BitcoinError::Descriptor(
                "single-chain descriptor cannot be exported to Sparrow: external and change paths would collide causing address reuse".into(),
            ));
        }
        let internal = self.internal_descriptor()?;

        let json = serde_json::json!({
            "name": name,
            "network": match self.network {
                Network::Bitcoin => "mainnet",
                Network::Testnet => "testnet",
                Network::Signet => "signet",
                Network::Regtest => "regtest",
                _ => "unknown",
            },
            "keystore": {
                "type": "bip39",
                "derivation": format!("m/86'/{}'/0'", if self.network == Network::Bitcoin { 0 } else { 1 }),
            },
            "outputDescriptor": self.descriptor,
            "changeDescriptor": internal,
        });

        serde_json::to_string_pretty(&json).map_err(|e| BitcoinError::Descriptor(e.to_string()))
    }
}

/// Build a BIP-389 multipath descriptor from a single-path external descriptor.
///
/// Rewrites every trailing `/0/*` key derivation to `/<0;1>/*`. Matching is
/// anchored so only a `/0/*` that terminates a key expression (immediately
/// followed by `,` or `)`, and preceded by a non-`/` character) is rewritten;
/// occurrences inside longer paths or origin info are left alone. Descriptors
/// containing a terminating `/1/*` (internal) path, or already holding
/// `<1;0>` (reverse-order multipath), are rejected rather than silently
/// coerced: swapping external and change order would produce divergent
/// receive/change mappings across co-signers.
pub fn multipath_from_external(external: &str) -> Result<String> {
    let body = external.split('#').next().unwrap_or(external);

    if keep_core::descriptor::contains_tail(body, '1') {
        return Err(BitcoinError::Descriptor(
            "descriptor contains /1/* internal path; expected external /0/* or multipath".into(),
        ));
    }
    if body.contains("<1;0>") {
        return Err(BitcoinError::Descriptor(
            "descriptor uses <1;0> multipath order; reorder to <0;1> before building".into(),
        ));
    }

    let normalized = keep_core::descriptor::rewrite_trailing_zero_star(body);

    let (canonical, _) = canonicalize_descriptor(&normalized)?;
    Ok(canonical)
}

fn canonicalize_descriptor(body: &str) -> Result<(String, String)> {
    let body = body.split('#').next().unwrap_or(body);
    let parsed: Descriptor<DescriptorPublicKey> = body
        .parse()
        .map_err(|e| BitcoinError::Descriptor(format!("invalid descriptor: {e}")))?;
    let canonical = parsed.to_string();
    let (_, checksum) = canonical.rsplit_once('#').ok_or_else(|| {
        BitcoinError::Descriptor("rust-miniscript returned descriptor without checksum".into())
    })?;
    let checksum = checksum.to_string();
    Ok((canonical, checksum))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_descriptor_export() {
        let secret = [1u8; 32];
        let derivation = AddressDerivation::new(&secret, Network::Testnet).unwrap();

        let export = DescriptorExport::from_derivation(&derivation, 0).unwrap();

        assert!(export.descriptor.contains("tr("));
        assert!(export.descriptor.contains("86'/1'/0'"));
        assert!(export.descriptor.contains("#"));
    }

    #[test]
    fn test_internal_descriptor() {
        let secret = [2u8; 32];
        let derivation = AddressDerivation::new(&secret, Network::Testnet).unwrap();

        let export = DescriptorExport::from_derivation(&derivation, 0).unwrap();
        let internal = export.internal_descriptor().unwrap();

        assert!(internal.contains("/1/*)"));
    }

    #[test]
    fn test_sparrow_export() {
        let secret = [3u8; 32];
        let derivation = AddressDerivation::new(&secret, Network::Testnet).unwrap();

        let export = DescriptorExport::from_derivation(&derivation, 0).unwrap();
        let json = export.to_sparrow_json("test-wallet").unwrap();

        assert!(json.contains("test-wallet"));
        assert!(json.contains("testnet"));
    }

    fn test_group_pubkey() -> [u8; 32] {
        use bitcoin::secp256k1::{Keypair, Secp256k1};
        let secp = Secp256k1::new();
        let secret = [42u8; 32];
        let kp = Keypair::from_seckey_slice(&secp, &secret).unwrap();
        kp.x_only_public_key().0.serialize()
    }

    fn test_keypair(seed: u8) -> [u8; 32] {
        use bitcoin::secp256k1::{Keypair, Secp256k1};
        let secp = Secp256k1::new();
        let mut secret = [seed; 32];
        secret[0] = seed.wrapping_add(1);
        let kp = Keypair::from_seckey_slice(&secp, &secret).unwrap();
        kp.x_only_public_key().0.serialize()
    }

    #[test]
    fn test_frost_wallet_simple_descriptor() {
        let group_pk = test_group_pubkey();
        let export =
            DescriptorExport::from_frost_wallet(&group_pk, None, Network::Testnet).unwrap();

        let xonly = XOnlyPublicKey::from_slice(&group_pk).unwrap();
        let expected_prefix = format!("tr({xonly})#");
        assert!(export.descriptor.starts_with(&expected_prefix));
        assert!(export.descriptor.contains("tr("));
        assert!(!export.descriptor.contains(','));
    }

    #[test]
    fn test_frost_wallet_with_recovery() {
        use crate::recovery::{RecoveryTier, SpendingTier};

        let group_pk = test_group_pubkey();
        let pk1 = test_keypair(1);
        let pk2 = test_keypair(2);

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![pk1],
                threshold: 1,
            },
            recovery_tiers: vec![RecoveryTier {
                keys: vec![pk2],
                threshold: 1,
                timelock_months: 6,
            }],
            network: Network::Testnet,
        };

        let export =
            DescriptorExport::from_frost_wallet(&group_pk, Some(&config), Network::Testnet)
                .unwrap();

        let xonly = XOnlyPublicKey::from_slice(&group_pk).unwrap();
        assert!(export.descriptor.starts_with(&format!("tr({xonly},")));
        assert!(export.descriptor.contains("older("));
        assert!(export.descriptor.contains('#'));
    }

    #[test]
    fn test_xpub_to_x_only_testnet() {
        use bitcoin::bip32::{Xpriv, Xpub};
        use bitcoin::secp256k1::Secp256k1;
        let secp = Secp256k1::new();
        let secret = [42u8; 32];

        let xpriv = Xpriv::new_master(Network::Testnet, &secret).unwrap();
        let xpub = Xpub::from_priv(&secp, &xpriv);
        let xpub_str = xpub.to_string();

        let result = xpub_to_x_only(&xpub_str, Network::Testnet).unwrap();
        let result_xonly = XOnlyPublicKey::from_slice(&result).unwrap();

        assert_eq!(result_xonly, xpub.to_x_only_pub());
    }

    #[test]
    fn test_xpub_to_x_only_invalid() {
        assert!(xpub_to_x_only("not-an-xpub", Network::Testnet).is_err());
    }

    #[test]
    fn test_xpub_to_x_only_network_mismatch() {
        use bitcoin::bip32::{Xpriv, Xpub};
        use bitcoin::secp256k1::Secp256k1;
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(Network::Testnet, &[42u8; 32]).unwrap();
        let xpub = Xpub::from_priv(&secp, &xpriv);
        let xpub_str = xpub.to_string();

        assert!(xpub_to_x_only(&xpub_str, Network::Bitcoin).is_err());
    }

    #[test]
    fn test_multipath_rewrites_single_key() {
        let out = multipath_from_external("tr(xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz/0/*)").unwrap();
        let body = out.split('#').next().unwrap();
        assert!(body.ends_with("/<0;1>/*)"));
        assert!(!body.contains("/0/*)"));
    }

    #[test]
    fn test_multipath_preserves_already_multipath() {
        let out = multipath_from_external(
            "tr(xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz/<0;1>/*)",
        )
        .unwrap();
        let body = out.split('#').next().unwrap();
        assert!(body.ends_with("/<0;1>/*)"));
        assert_eq!(body.matches("<0;1>").count(), 1);
    }

    #[test]
    fn test_multipath_normalizes_mixed_multisig() {
        let xpub = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz";
        let input = format!("wsh(sortedmulti(2,{xpub}/<0;1>/*,{xpub}/0/*))");
        let out = multipath_from_external(&input).unwrap();
        let body = out.split('#').next().unwrap();
        assert_eq!(body.matches("<0;1>").count(), 2);
        assert!(!body.contains("/0/*,"));
        assert!(!body.contains("/0/*)"));
    }

    #[test]
    fn test_multipath_leaves_origin_info_alone() {
        let out = multipath_from_external(
            "tr([deadbeef/86'/0'/0']xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz/0/*)",
        )
        .unwrap();
        let body = out.split('#').next().unwrap();
        assert!(body.contains("[deadbeef/86'/0'/0']"));
        assert!(body.ends_with("/<0;1>/*)"));
    }

    #[test]
    fn test_multipath_does_not_mangle_nested_paths() {
        // xpub/0/0/*) must become xpub/0/<0;1>/*), not xpub/<0;1>/*.
        let input = "tr(xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz/0/0/*)";
        let out = multipath_from_external(input).unwrap();
        let body = out.split('#').next().unwrap();
        assert!(body.ends_with("/0/<0;1>/*)"));
    }

    #[test]
    fn test_multipath_no_derivation_tail_unchanged() {
        // Bare descriptor with no /0/* tail: body should be unchanged aside
        // from the appended checksum.
        let xpub = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz";
        let input = format!("tr({xpub})");
        let out = multipath_from_external(&input).unwrap();
        let body = out.split('#').next().unwrap();
        assert_eq!(body, input);
    }

    #[test]
    fn test_multipath_rejects_internal_only_descriptor() {
        let err = multipath_from_external("tr(xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz/1/*)");
        assert!(err.is_err());
    }

    #[test]
    fn test_multipath_rejects_reverse_order_marker() {
        let xpub = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz";
        let input = format!("wsh(sortedmulti(2,{xpub}/<1;0>/*,{xpub}/<0;1>/*))");
        let err = multipath_from_external(&input).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("<1;0>"), "unexpected error: {msg}");
    }

    #[test]
    fn test_descriptor_round_trips_through_miniscript() {
        use crate::recovery::{RecoveryTier, SpendingTier};
        use bitcoin::secp256k1::{Keypair, Secp256k1};
        use miniscript::{Descriptor, DescriptorPublicKey};

        let secp = Secp256k1::new();
        let seeded = |seed: u8| -> [u8; 32] {
            let kp = Keypair::from_seckey_slice(&secp, &[seed; 32]).unwrap();
            kp.x_only_public_key().0.serialize()
        };

        let group_pk = seeded(0x42);
        let primary_pk = seeded(0x10);
        let recovery1_pk = seeded(0x20);
        let recovery2_pk = seeded(0x30);

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![primary_pk, group_pk],
                threshold: 2,
            },
            recovery_tiers: vec![
                RecoveryTier {
                    keys: vec![recovery1_pk],
                    threshold: 1,
                    timelock_months: 6,
                },
                RecoveryTier {
                    keys: vec![recovery2_pk],
                    threshold: 1,
                    timelock_months: 12,
                },
            ],
            network: Network::Signet,
        };

        let export =
            DescriptorExport::from_frost_wallet(&group_pk, Some(&config), Network::Signet).unwrap();

        let external = export.external_descriptor().to_string();

        let external_roundtrip = Descriptor::<DescriptorPublicKey>::from_str(&external)
            .unwrap()
            .to_string();
        assert_eq!(external, external_roundtrip);

        let (_, emitted_checksum) = external.rsplit_once('#').unwrap();
        assert_eq!(emitted_checksum.len(), 8);
        assert!(
            emitted_checksum
                .chars()
                .all(|c| "qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(c)),
            "checksum {emitted_checksum} contains non-BIP-380 charset chars"
        );
    }

    #[test]
    fn test_reference_descriptor_canonical_form() {
        // Guards against accidental miniscript version bumps that shift
        // canonical descriptor formatting. The emitted descriptor string is a
        // consensus value across FROST peers; if this literal changes, mixed
        // miniscript versions will break descriptor coordination.
        // secp256k1 generator point G x-coordinate; stable, known-valid x-only key.
        let xonly = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let expected =
            "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#gxjkeue2";
        let (canonical, _) = canonicalize_descriptor(&format!("tr({xonly})")).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn test_frost_wallet_descriptor_has_checksum() {
        let group_pk = test_group_pubkey();
        let export =
            DescriptorExport::from_frost_wallet(&group_pk, None, Network::Testnet).unwrap();

        assert!(export.descriptor.contains('#'));
        assert_eq!(export.checksum.len(), 8);

        let parts: Vec<&str> = export.descriptor.split('#').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1], export.checksum);
    }
}
