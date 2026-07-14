// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::str::FromStr;

use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bitcoin::hashes::{hash160, Hash};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Network, NetworkKind, XOnlyPublicKey};
use keep_core::frost_bip32::deterministic_chaincode;
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
            None => {
                // #487 PR 4/4: emit a BIP-86-style HD taproot descriptor over
                // the FROST group's own xpub (built from the deterministic
                // chaincode in PR 1) so `/0/*` and `/1/*` derive distinct
                // receive- and change-address chains. Downstream wallets
                // walk the xpub with the standard BIP-32 rules, and the
                // FROST signing loop applies the matching composite tweak
                // (PR 2 + PR 3) at spend time.
                let xpub = group_xpub_string(group_pubkey, network)?;
                let coin_type = if network == Network::Bitcoin { 0 } else { 1 };
                canonicalize_descriptor(&format!(
                    "tr([{fingerprint}/86'/{coin_type}'/0']{xpub}/0/*)"
                ))?
            }
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

    /// Return the raw Base58Check-encoded xpub string that
    /// [`Self::from_frost_wallet`] wraps into its BIP-86 descriptor. Exposed
    /// so callers exporting to other wallets (Sparrow, Electrum, BDK) can
    /// hand off just the xpub without also parsing back the wrapping
    /// descriptor.
    pub fn frost_group_xpub(group_pubkey: &[u8; 32], network: Network) -> Result<String> {
        group_xpub_string(group_pubkey, network)
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

/// Derive the `script_pubkey` for a definite (non-ranged) descriptor string.
/// Used to bind a supplied [`crate::RecoveryOutput`] to the descriptor
/// identified by a canonical hash before sweeping its coins. A recovery output
/// is by definition a single, non-ranged output, so a ranged descriptor is
/// rejected rather than silently resolved at an arbitrary index.
pub fn descriptor_script_pubkey(descriptor: &str) -> Result<bitcoin::ScriptBuf> {
    let parsed = parse_definite_descriptor(descriptor)?;
    Ok(parsed.script_pubkey())
}

/// Derive the address for a definite (non-ranged) descriptor string on
/// `network`. Used to pick the sweep destination from a finalized FROST wallet
/// descriptor, which is definite (`tr(<xonly>,<tree>)`, no wildcard).
pub fn descriptor_address(descriptor: &str, network: Network) -> Result<bitcoin::Address> {
    let parsed = parse_definite_descriptor(descriptor)?;
    parsed
        .address(network)
        .map_err(|e| BitcoinError::Descriptor(format!("address derivation failed: {e}")))
}

/// Resolve a ranged OR definite descriptor at a concrete derivation `index` and
/// return its address on `network`. Unlike [`descriptor_address`], this accepts
/// a ranged descriptor (`.../0/*`) by resolving it at `index` rather than
/// rejecting it. Used to pick the single deterministic migration-sweep
/// destination for a successor FROST wallet descriptor: `index` 0 is the first
/// external `/0/0` receive address, which both proposer and responder derive
/// identically from the same persisted descriptor.
pub fn descriptor_address_at_index(
    descriptor: &str,
    network: Network,
    index: u32,
) -> Result<bitcoin::Address> {
    let parsed = parse_descriptor_body(descriptor)?;
    parsed
        .at_derivation_index(index)
        .map_err(|e| BitcoinError::Descriptor(format!("definite descriptor: {e}")))?
        .address(network)
        .map_err(|e| BitcoinError::Descriptor(format!("address derivation failed: {e}")))
}

/// Derive the change (internal, `/1/*`) `script_pubkey` at `index` from a
/// BIP-86 external descriptor (`.../0/*`), applying the same `/0/* -> /1/*`
/// rewrite as [`DescriptorExport::internal_descriptor`].
///
/// This is the single source of truth for "does this output pay to the
/// wallet's own change branch". Callers compare the returned script against a
/// PSBT output's `script_pubkey` (which is consensus-committed) rather than
/// trusting the attacker-suppliable key-origin metadata in a PSBT output, which
/// otherwise lets a payment to an attacker's address masquerade as change.
pub fn change_script_at_index(
    external_descriptor: &str,
    network: Network,
    index: u32,
) -> Result<bitcoin::ScriptBuf> {
    let parsed = parse_descriptor_body(external_descriptor)?;
    if parsed.is_multipath() {
        // BIP-389 multipath (`<0;1>`): the change branch is the second
        // single-path descriptor. keep only builds/accepts external-first
        // (`<0;1>`) order (see `multipath_from_external`).
        let singles = parsed
            .into_single_descriptors()
            .map_err(|e| BitcoinError::Descriptor(format!("multipath descriptor: {e}")))?;
        let change = singles.get(1).ok_or_else(|| {
            BitcoinError::Descriptor("multipath descriptor missing change branch".into())
        })?;
        return Ok(change
            .at_derivation_index(index)
            .map_err(|e| BitcoinError::Descriptor(format!("definite descriptor: {e}")))?
            .script_pubkey());
    }
    let body = external_descriptor
        .split('#')
        .next()
        .unwrap_or(external_descriptor);
    let internal_body = keep_core::descriptor::rewrite_trailing_zero_to_one(body);
    let (internal, _) = canonicalize_descriptor(&internal_body)?;
    Ok(descriptor_address_at_index(&internal, network, index)?.script_pubkey())
}

/// Build the raw Base58Check-encoded xpub for a FROST group by combining its
/// x-only pubkey (lifted to its +even secp256k1 point) with the deterministic
/// chaincode from #487 PR1. Depth 0, no parent, child number 0: this is the
/// group's own xpub, not a derivation of anything above it.
///
/// Downstream wallets consume the xpub through the normal BIP-32 rules, and
/// keep-frost-net's sign path applies the matching composite tweak (PR 2 +
/// PR 3) so a `/0/N` receive-address spend produces a signature that BIP-340
/// verifies against the address's key.
fn group_xpub_string(group_pubkey: &[u8; 32], network: Network) -> Result<String> {
    let network_kind = if network == Network::Bitcoin {
        NetworkKind::Main
    } else {
        NetworkKind::Test
    };
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(group_pubkey);
    let public_key = PublicKey::from_slice(&compressed)
        .map_err(|e| BitcoinError::Descriptor(format!("group pubkey not on curve: {e}")))?;
    let chain_code = ChainCode::from(deterministic_chaincode(group_pubkey));
    let xpub = Xpub {
        network: network_kind,
        depth: 0,
        parent_fingerprint: Fingerprint::from([0u8; 4]),
        child_number: ChildNumber::from_normal_idx(0)
            .map_err(|e| BitcoinError::Descriptor(format!("child number 0: {e}")))?,
        public_key,
        chain_code,
    };
    Ok(xpub.to_string())
}

fn parse_definite_descriptor(
    descriptor: &str,
) -> Result<Descriptor<miniscript::DefiniteDescriptorKey>> {
    let parsed = parse_descriptor_body(descriptor)?;
    if parsed.has_wildcard() {
        return Err(BitcoinError::Descriptor(
            "descriptor is ranged; expected a definite output".into(),
        ));
    }
    parsed
        .at_derivation_index(0)
        .map_err(|e| BitcoinError::Descriptor(format!("definite descriptor: {e}")))
}

fn parse_descriptor_body(descriptor: &str) -> Result<Descriptor<DescriptorPublicKey>> {
    let body = descriptor.split('#').next().unwrap_or(descriptor);
    body.parse()
        .map_err(|e| BitcoinError::Descriptor(format!("invalid descriptor: {e}")))
}

fn canonicalize_descriptor(body: &str) -> Result<(String, String)> {
    let parsed = parse_descriptor_body(body)?;
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
    fn test_descriptor_address_for_definite_frost_wallet() {
        use crate::recovery::{RecoveryTier, SpendingTier};

        let group = test_group_pubkey();
        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![test_keypair(1)],
                threshold: 1,
            },
            recovery_tiers: vec![RecoveryTier {
                keys: vec![test_keypair(2)],
                threshold: 1,
                timelock_months: 6,
            }],
            network: Network::Testnet,
        };
        // Real wallet descriptors are definite: tr(<xonly>,<tree>), no wildcard.
        let export =
            DescriptorExport::from_frost_wallet(&group, Some(&config), Network::Testnet).unwrap();

        let addr = descriptor_address(&export.descriptor, Network::Testnet).unwrap();
        assert!(addr.to_string().starts_with("tb1p"));

        let spk = descriptor_script_pubkey(&export.descriptor).unwrap();
        assert_eq!(addr.script_pubkey(), spk);
    }

    #[test]
    fn test_descriptor_address_rejects_ranged_descriptor() {
        let secret = [7u8; 32];
        let derivation = AddressDerivation::new(&secret, Network::Testnet).unwrap();
        let export = DescriptorExport::from_derivation(&derivation, 0).unwrap();
        let err = descriptor_address(&export.descriptor, Network::Testnet).unwrap_err();
        assert!(err.to_string().contains("ranged"));
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

    /// #487 PR 4: the address a downstream wallet derives from the emitted
    /// descriptor at `/0/N` MUST have the x-only pubkey that
    /// `keep_core::frost::bip32_signing::derive_child(group, &[0, N])`
    /// produces. If these ever drift, wallets receive to addresses that
    /// keep cannot sign for. Cross-check by pinning the descriptor and
    /// deriving both sides for a few leaves.
    #[test]
    fn descriptor_addresses_match_bip32_signing_derivation() {
        use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
        use bitcoin::secp256k1::Secp256k1;
        use keep_core::frost::bip32_signing::derive_child;

        let group = test_group_pubkey();
        let export = DescriptorExport::from_frost_wallet(&group, None, Network::Testnet).unwrap();

        // Extract the xpub embedded in the descriptor.
        let xpub_str = DescriptorExport::frost_group_xpub(&group, Network::Testnet).unwrap();
        let xpub: Xpub = xpub_str.parse().unwrap();
        assert!(
            export.descriptor.contains(xpub_str.as_str()),
            "descriptor must embed the exact frost_group_xpub value"
        );

        let secp = Secp256k1::verification_only();
        for leaf in [0u32, 1, 5, 100] {
            let child_pubkey_bip32_signing = derive_child(&group, &[0, leaf]).unwrap().child_pubkey;

            let path = DerivationPath::from(vec![
                ChildNumber::from_normal_idx(0).unwrap(),
                ChildNumber::from_normal_idx(leaf).unwrap(),
            ]);
            let derived_xpub = xpub.derive_pub(&secp, &path).unwrap();
            let child_pubkey_descriptor = derived_xpub.public_key.x_only_public_key().0.serialize();

            assert_eq!(
                child_pubkey_descriptor, child_pubkey_bip32_signing,
                "leaf {leaf}: descriptor-derived key MUST equal FROST-signing child"
            );

            let change_pubkey_bip32_signing =
                derive_child(&group, &[1, leaf]).unwrap().child_pubkey;

            let change_path = DerivationPath::from(vec![
                ChildNumber::from_normal_idx(1).unwrap(),
                ChildNumber::from_normal_idx(leaf).unwrap(),
            ]);
            let derived_change_xpub = xpub.derive_pub(&secp, &change_path).unwrap();
            let change_pubkey_descriptor = derived_change_xpub
                .public_key
                .x_only_public_key()
                .0
                .serialize();

            assert_eq!(
                change_pubkey_descriptor, change_pubkey_bip32_signing,
                "leaf {leaf}: CHANGE-chain descriptor-derived key MUST equal FROST-signing child"
            );
        }
    }

    #[test]
    fn change_script_at_index_uses_internal_branch() {
        let group = test_group_pubkey();
        let export = DescriptorExport::from_frost_wallet(&group, None, Network::Testnet).unwrap();
        let external = export.external_descriptor();
        let net = Network::Testnet;

        let change0 = change_script_at_index(external, net, 0).unwrap();
        // Change (`/1/0`) must differ from the external receive script (`/0/0`).
        let recv0 = descriptor_address_at_index(external, net, 0)
            .unwrap()
            .script_pubkey();
        assert_ne!(change0, recv0, "change /1/0 must differ from receive /0/0");
        // And must equal the internal descriptor derived at the same index.
        let internal = export.internal_descriptor().unwrap();
        let internal0 = descriptor_address_at_index(&internal, net, 0)
            .unwrap()
            .script_pubkey();
        assert_eq!(change0, internal0);
        // Distinct indices produce distinct change scripts.
        assert_ne!(change0, change_script_at_index(external, net, 1).unwrap());

        // A BIP-389 multipath (`<0;1>`) descriptor resolves the same change
        // branch as the single-path external form.
        let multipath = export.multipath_descriptor().unwrap();
        assert_eq!(change0, change_script_at_index(&multipath, net, 0).unwrap());
        assert_eq!(
            change_script_at_index(external, net, 3).unwrap(),
            change_script_at_index(&multipath, net, 3).unwrap()
        );
    }

    #[test]
    fn change_script_at_index_accepts_definite_descriptor() {
        // A definite (non-ranged) taproot descriptor has no /0/* tail: it reuses
        // one script, so change is index-independent. It must be accepted, not
        // rejected, and never index-dependent.
        let group = test_group_pubkey();
        let xonly_hex: String = group.iter().map(|b| format!("{b:02x}")).collect();
        let definite = format!("tr({xonly_hex})");
        let net = Network::Testnet;
        let s0 = change_script_at_index(&definite, net, 0).unwrap();
        let s7 = change_script_at_index(&definite, net, 7).unwrap();
        assert_eq!(s0, s7, "definite descriptor is index-independent");
    }

    /// #487 PR 4: the mainnet output users actually ship uses BIP-86
    /// `coin_type` 0 and an `xpub` (not tpub) prefix. Testnet/Signet tests
    /// exercise `coin_type` 1 only, so pin the mainnet branch explicitly.
    #[test]
    fn frost_wallet_mainnet_descriptor_uses_coin_type_0() {
        let group = test_group_pubkey();
        let export = DescriptorExport::from_frost_wallet(&group, None, Network::Bitcoin).unwrap();

        let fingerprint = export.fingerprint;
        assert!(
            export
                .descriptor
                .starts_with(&format!("tr([{fingerprint}/86'/0'/0']")),
            "mainnet descriptor must use coin_type 0: {}",
            export.descriptor
        );
        assert!(
            export.descriptor.contains("xpub"),
            "mainnet descriptor must embed an xpub, not a tpub: {}",
            export.descriptor
        );
        assert!(
            export.descriptor.contains("/0/*)"),
            "mainnet descriptor must be a ranged external chain: {}",
            export.descriptor
        );
    }

    /// #487 PR 4: the external chain (`/0/*`) and internal chain (`/1/*`)
    /// produce distinct addresses at every leaf. This is the property that
    /// justified the whole issue (address diversity for receive vs change).
    #[test]
    fn external_and_internal_leaves_produce_distinct_addresses() {
        use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
        use bitcoin::secp256k1::Secp256k1;

        let group = test_group_pubkey();
        let xpub_str = DescriptorExport::frost_group_xpub(&group, Network::Testnet).unwrap();
        let xpub: Xpub = xpub_str.parse().unwrap();
        let secp = Secp256k1::verification_only();

        for leaf in 0u32..8 {
            let ext = xpub
                .derive_pub(
                    &secp,
                    &DerivationPath::from(vec![
                        ChildNumber::from_normal_idx(0).unwrap(),
                        ChildNumber::from_normal_idx(leaf).unwrap(),
                    ]),
                )
                .unwrap()
                .public_key
                .x_only_public_key()
                .0
                .serialize();
            let int = xpub
                .derive_pub(
                    &secp,
                    &DerivationPath::from(vec![
                        ChildNumber::from_normal_idx(1).unwrap(),
                        ChildNumber::from_normal_idx(leaf).unwrap(),
                    ]),
                )
                .unwrap()
                .public_key
                .x_only_public_key()
                .0
                .serialize();
            assert_ne!(ext, int, "leaf {leaf}: external and internal must differ");
        }
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
        // #487 PR 4: non-recovery FROST descriptor is now an xpub-shaped
        // BIP-86 descriptor (`tr([fp/86'/coin_type'/0']xpub/0/*)`) rather
        // than a static `tr(xonly)`, so `/0/*` and `/1/*` derive distinct
        // receive- and change-address chains.
        let group_pk = test_group_pubkey();
        let export =
            DescriptorExport::from_frost_wallet(&group_pk, None, Network::Testnet).unwrap();

        // Fingerprint is the same lift-then-hash rule as always.
        let fingerprint = DescriptorExport::pubkey_fingerprint(&group_pk);
        assert!(
            export
                .descriptor
                .starts_with(&format!("tr([{fingerprint}/86'/1'/0']")),
            "descriptor must open with the expected BIP-86 origin: got {}",
            export.descriptor
        );
        // Wraps an xpub (tpub for testnet) followed by the receive path.
        assert!(export.descriptor.contains("tpub"));
        assert!(export.descriptor.contains("/0/*)"));
        // A canonicalized checksum is appended after the descriptor body.
        assert!(export.descriptor.contains('#'));
        // #487 whole point: internal and external are no longer equal.
        assert_ne!(
            export.internal_descriptor().unwrap(),
            export.descriptor,
            "external `/0/*` and internal `/1/*` chains MUST differ (#487)"
        );
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
