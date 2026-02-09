// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::address::AddressDerivation;
use crate::error::{BitcoinError, Result};
use crate::recovery::RecoveryConfig;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::{Network, XOnlyPublicKey};

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

        let checksum = compute_checksum(&descriptor)?;

        Ok(Self {
            descriptor: format!("{descriptor}#{checksum}"),
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

        let descriptor = match recovery {
            None => {
                let desc = format!("tr({xonly})");
                let checksum = compute_checksum(&desc)?;
                format!("{desc}#{checksum}")
            }
            Some(config) => {
                let output = config.build_with_internal_key(&xonly)?;
                let checksum = compute_checksum(&output.descriptor)?;
                format!("{}#{checksum}", output.descriptor)
            }
        };

        let checksum = descriptor.split('#').nth(1).unwrap_or("").to_string();

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
        let desc = self
            .descriptor
            .split('#')
            .next()
            .unwrap_or(&self.descriptor);
        let internal = desc.replace("/0/*)", "/1/*)");
        let checksum = compute_checksum(&internal)?;
        Ok(format!("{internal}#{checksum}"))
    }

    pub fn to_sparrow_json(&self, name: &str) -> Result<String> {
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

fn compute_checksum(descriptor: &str) -> Result<String> {
    const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const GENERATOR: [u64; 5] = [
        0xf5dee51989,
        0xa9fdca3312,
        0x1bab10e32d,
        0x3706b1677a,
        0x644d626ffd,
    ];

    fn polymod(c: u64, val: u64) -> u64 {
        let mut c = c;
        let c0 = c >> 35;
        c = ((c & 0x7ffffffff) << 5) ^ val;
        for (i, gen) in GENERATOR.iter().enumerate() {
            if (c0 >> i) & 1 == 1 {
                c ^= gen;
            }
        }
        c
    }

    let mut c: u64 = 1;
    let mut cls: u64 = 0;
    let mut clscount = 0;

    for ch in descriptor.chars() {
        if ch == '#' {
            break;
        }

        let pos = match ch {
            'a'..='z' => (ch as u64) - ('a' as u64),
            'A'..='Z' => (ch as u64) - ('A' as u64),
            '0'..='9' => (ch as u64) - ('0' as u64) + 26,
            '&' | '\'' | '(' | ')' | '*' | '+' | ',' | '-' | '.' | '/' => {
                (ch as u64) - ('&' as u64) + 36
            }
            ':' | ';' | '<' | '=' | '>' | '?' | '@' => (ch as u64) - (':' as u64) + 46,
            '[' | '\\' | ']' | '^' | '_' | '`' => (ch as u64) - ('[' as u64) + 53,
            '{' | '|' | '}' | '~' => (ch as u64) - ('{' as u64) + 59,
            _ => continue,
        };

        c = polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        clscount += 1;

        if clscount == 3 {
            c = polymod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }

    if clscount > 0 {
        c = polymod(c, cls);
    }

    for _ in 0..8 {
        c = polymod(c, 0);
    }

    c ^= 1;

    let mut checksum = String::with_capacity(8);
    for i in 0..8 {
        checksum.push(CHECKSUM_CHARSET[((c >> (5 * (7 - i))) & 31) as usize] as char);
    }

    Ok(checksum)
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
        assert!(export.descriptor.contains("csv="));
        assert!(export.descriptor.contains('#'));
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
