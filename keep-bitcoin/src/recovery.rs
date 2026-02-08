// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::error::{BitcoinError, Result};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::All;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{Address, Network, ScriptBuf, Sequence, TapLeafHash, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const BLOCKS_PER_DAY: u32 = 144;
const BLOCKS_PER_MONTH: u32 = BLOCKS_PER_DAY * 30;
const MAX_KEYS_PER_TIER: usize = 20;
const MAX_RECOVERY_TIERS: usize = 10;
const MAX_CSV_BLOCKS: u32 = 0xFFFF;

// BIP-341 unspendable internal key (no known discrete log).
const NUMS_POINT: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryConfig {
    pub primary: SpendingTier,
    pub recovery_tiers: Vec<RecoveryTier>,
    pub network: Network,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendingTier {
    pub keys: Vec<[u8; 32]>,
    pub threshold: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryTier {
    pub keys: Vec<[u8; 32]>,
    pub threshold: u32,
    pub timelock_months: u32,
}

#[derive(Clone, Debug)]
pub struct RecoveryOutput {
    pub address: Address,
    pub spend_info: TaprootSpendInfo,
    pub descriptor: String,
    pub tiers: Vec<TierInfo>,
}

#[derive(Clone, Debug)]
pub struct TierInfo {
    pub name: String,
    pub script: ScriptBuf,
    pub leaf_hash: TapLeafHash,
    pub timelock_blocks: Option<u32>,
    pub threshold: u32,
    pub keys: Vec<XOnlyPublicKey>,
}

impl RecoveryConfig {
    pub fn validate(&self) -> Result<()> {
        if self.primary.keys.is_empty() {
            return Err(BitcoinError::Recovery("primary tier has no keys".into()));
        }
        if self.primary.keys.len() > MAX_KEYS_PER_TIER {
            return Err(BitcoinError::Recovery(format!(
                "primary tier exceeds {} keys",
                MAX_KEYS_PER_TIER
            )));
        }
        if self.primary.threshold == 0 || self.primary.threshold > self.primary.keys.len() as u32 {
            return Err(BitcoinError::Recovery("invalid primary threshold".into()));
        }
        check_duplicate_keys("primary", &self.primary.keys)?;

        if self.recovery_tiers.is_empty() {
            return Err(BitcoinError::Recovery(
                "at least one recovery tier is required".into(),
            ));
        }
        if self.recovery_tiers.len() > MAX_RECOVERY_TIERS {
            return Err(BitcoinError::Recovery(format!(
                "recovery tier count {} exceeds maximum {}",
                self.recovery_tiers.len(),
                MAX_RECOVERY_TIERS
            )));
        }

        let mut all_keys: HashSet<[u8; 32]> = self.primary.keys.iter().copied().collect();

        for (i, tier) in self.recovery_tiers.iter().enumerate() {
            if tier.keys.is_empty() {
                return Err(BitcoinError::Recovery(format!(
                    "recovery tier {} has no keys",
                    i
                )));
            }
            if tier.keys.len() > MAX_KEYS_PER_TIER {
                return Err(BitcoinError::Recovery(format!(
                    "recovery tier {} exceeds {} keys",
                    i, MAX_KEYS_PER_TIER
                )));
            }
            if tier.threshold == 0 || tier.threshold > tier.keys.len() as u32 {
                return Err(BitcoinError::Recovery(format!(
                    "invalid threshold for recovery tier {}",
                    i
                )));
            }
            if tier.timelock_months == 0 {
                return Err(BitcoinError::Recovery(format!(
                    "recovery tier {} must have nonzero timelock",
                    i
                )));
            }
            let timelock_blocks = months_to_blocks(tier.timelock_months)?;
            if timelock_blocks > MAX_CSV_BLOCKS {
                return Err(BitcoinError::Recovery(format!(
                    "recovery tier {} timelock {} months ({} blocks) exceeds CSV maximum {}",
                    i, tier.timelock_months, timelock_blocks, MAX_CSV_BLOCKS
                )));
            }
            check_duplicate_keys(&format!("recovery tier {}", i), &tier.keys)?;
            for key in &tier.keys {
                if !all_keys.insert(*key) {
                    return Err(BitcoinError::Recovery(format!(
                        "duplicate key across tiers: {}",
                        hex::encode(key)
                    )));
                }
            }
        }
        for w in self.recovery_tiers.windows(2) {
            if w[1].timelock_months <= w[0].timelock_months {
                return Err(BitcoinError::Recovery(
                    "recovery tiers must have increasing timelocks".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn build(&self) -> Result<RecoveryOutput> {
        self.validate()?;
        let secp = Secp256k1::new();
        let tiers = self.build_tier_infos()?;
        let internal_key = self.internal_key()?;
        let spend_info = self.build_taproot(&secp, internal_key, &tiers)?;
        let address = Address::p2tr_tweaked(spend_info.output_key(), self.network);
        let descriptor = self.format_descriptor(internal_key, &tiers);

        Ok(RecoveryOutput {
            address,
            spend_info,
            descriptor,
            tiers,
        })
    }

    fn internal_key(&self) -> Result<XOnlyPublicKey> {
        if self.primary.keys.len() == 1 && self.primary.threshold == 1 {
            return parse_xonly(&self.primary.keys[0]);
        }
        XOnlyPublicKey::from_slice(&NUMS_POINT)
            .map_err(|e| BitcoinError::Recovery(format!("NUMS point: {}", e)))
    }

    fn build_tier_infos(&self) -> Result<Vec<TierInfo>> {
        let mut tiers = Vec::new();

        if self.primary.keys.len() > 1 || self.primary.threshold > 1 {
            let pubkeys = parse_xonly_keys(&self.primary.keys)?;
            let script = build_multisig_script(&self.primary.keys, self.primary.threshold)?;
            tiers.push(TierInfo {
                name: "primary".to_string(),
                leaf_hash: TapLeafHash::from_script(&script, LeafVersion::TapScript),
                script,
                timelock_blocks: None,
                threshold: self.primary.threshold,
                keys: pubkeys,
            });
        }

        for (i, tier) in self.recovery_tiers.iter().enumerate() {
            let timelock_blocks = months_to_blocks(tier.timelock_months)?;
            let pubkeys = parse_xonly_keys(&tier.keys)?;
            let script = build_timelocked_multisig(&tier.keys, tier.threshold, timelock_blocks)?;
            tiers.push(TierInfo {
                name: format!("recovery_{}", i + 1),
                leaf_hash: TapLeafHash::from_script(&script, LeafVersion::TapScript),
                script,
                timelock_blocks: Some(timelock_blocks),
                threshold: tier.threshold,
                keys: pubkeys,
            });
        }

        Ok(tiers)
    }

    fn build_taproot(
        &self,
        secp: &Secp256k1<All>,
        internal_key: XOnlyPublicKey,
        tiers: &[TierInfo],
    ) -> Result<TaprootSpendInfo> {
        if tiers.is_empty() {
            return TaprootBuilder::new()
                .finalize(secp, internal_key)
                .map_err(|e| BitcoinError::Recovery(format!("taproot finalize: {:?}", e)));
        }

        let mut builder = TaprootBuilder::new();
        let depths = optimal_depth(tiers.len());

        for (i, tier) in tiers.iter().enumerate() {
            builder = builder
                .add_leaf(depths[i], tier.script.clone())
                .map_err(|e| BitcoinError::Recovery(format!("add leaf: {:?}", e)))?;
        }

        builder
            .finalize(secp, internal_key)
            .map_err(|e| BitcoinError::Recovery(format!("taproot finalize: {:?}", e)))
    }

    fn format_descriptor(&self, internal_key: XOnlyPublicKey, tiers: &[TierInfo]) -> String {
        let mut desc = format!("tr({}", internal_key);
        if !tiers.is_empty() {
            desc.push_str(",{");
            for (i, tier) in tiers.iter().enumerate() {
                if i > 0 {
                    desc.push(',');
                }
                match tier.timelock_blocks {
                    Some(blocks) => {
                        desc.push_str(&format!("{}(csv={})", tier.name, blocks));
                    }
                    None => {
                        desc.push_str(&tier.name);
                    }
                }
            }
            desc.push('}');
        }
        desc.push(')');
        desc
    }
}

fn build_multisig_script(keys: &[[u8; 32]], threshold: u32) -> Result<ScriptBuf> {
    let pubkeys: Vec<XOnlyPublicKey> = keys.iter().map(parse_xonly).collect::<Result<Vec<_>>>()?;

    let mut builder = ScriptBuf::builder();
    builder = push_checksig_chain(builder, &pubkeys);

    if needs_threshold_check(threshold, pubkeys.len()) {
        builder = builder
            .push_int(threshold as i64)
            .push_opcode(bitcoin::opcodes::all::OP_NUMEQUAL);
    }

    Ok(builder.into_script())
}

fn build_timelocked_multisig(
    keys: &[[u8; 32]],
    threshold: u32,
    timelock_blocks: u32,
) -> Result<ScriptBuf> {
    let seq_u16 = u16::try_from(timelock_blocks).map_err(|_| {
        BitcoinError::Recovery(format!(
            "timelock {} exceeds CSV maximum {}",
            timelock_blocks, MAX_CSV_BLOCKS
        ))
    })?;

    let pubkeys: Vec<XOnlyPublicKey> = keys.iter().map(parse_xonly).collect::<Result<Vec<_>>>()?;

    let mut builder = ScriptBuf::builder()
        .push_sequence(Sequence::from_height(seq_u16))
        .push_opcode(bitcoin::opcodes::all::OP_CSV)
        .push_opcode(bitcoin::opcodes::all::OP_DROP);

    builder = push_checksig_chain(builder, &pubkeys);

    if needs_threshold_check(threshold, pubkeys.len()) {
        builder = builder
            .push_int(threshold as i64)
            .push_opcode(bitcoin::opcodes::all::OP_NUMEQUAL);
    }

    Ok(builder.into_script())
}

fn push_checksig_chain(
    mut builder: bitcoin::script::Builder,
    pubkeys: &[XOnlyPublicKey],
) -> bitcoin::script::Builder {
    for (i, pk) in pubkeys.iter().enumerate() {
        builder = builder.push_x_only_key(pk);
        if i == 0 {
            builder = builder.push_opcode(bitcoin::opcodes::all::OP_CHECKSIG);
        } else {
            builder = builder.push_opcode(bitcoin::opcodes::all::OP_CHECKSIGADD);
        }
    }
    builder
}

fn parse_xonly(bytes: &[u8; 32]) -> Result<XOnlyPublicKey> {
    XOnlyPublicKey::from_slice(bytes).map_err(|e| BitcoinError::InvalidPublicKey(e.to_string()))
}

fn parse_xonly_keys(keys: &[[u8; 32]]) -> Result<Vec<XOnlyPublicKey>> {
    keys.iter().map(parse_xonly).collect()
}

fn needs_threshold_check(threshold: u32, key_count: usize) -> bool {
    threshold > 1 || key_count > 1
}

fn check_duplicate_keys(tier_name: &str, keys: &[[u8; 32]]) -> Result<()> {
    let mut seen = HashSet::with_capacity(keys.len());
    for key in keys {
        if !seen.insert(key) {
            return Err(BitcoinError::Recovery(format!(
                "duplicate key in {}: {}",
                tier_name,
                hex::encode(key)
            )));
        }
    }
    Ok(())
}

fn optimal_depth(count: usize) -> Vec<u8> {
    match count {
        0 => vec![],
        1 => vec![0],
        _ => {
            let depth = (usize::BITS - (count - 1).leading_zeros()) as u8;
            let full_capacity = 1usize << depth;
            let shallow_count = full_capacity - count;
            (0..count)
                .map(|i| if i < shallow_count { depth - 1 } else { depth })
                .collect()
        }
    }
}

pub fn recovery_sequence(timelock_blocks: u32) -> Result<Sequence> {
    let blocks_u16 = u16::try_from(timelock_blocks).map_err(|_| {
        BitcoinError::Recovery(format!(
            "timelock {} exceeds maximum relative lock height 65535",
            timelock_blocks
        ))
    })?;
    Ok(Sequence::from_height(blocks_u16))
}

pub fn months_to_blocks(months: u32) -> Result<u32> {
    months.checked_mul(BLOCKS_PER_MONTH).ok_or_else(|| {
        BitcoinError::Recovery(format!("timelock {} months overflows block count", months))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1};

    fn test_keypair(seed: u8) -> [u8; 32] {
        let secp = Secp256k1::new();
        let mut secret = [seed; 32];
        secret[0] = seed.wrapping_add(1);
        let kp = Keypair::from_seckey_slice(&secp, &secret).unwrap();
        kp.x_only_public_key().0.serialize()
    }

    #[test]
    fn test_single_key_primary_with_recovery() {
        let pk1 = test_keypair(1);
        let pk2 = test_keypair(2);
        let pk3 = test_keypair(3);

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![pk1],
                threshold: 1,
            },
            recovery_tiers: vec![RecoveryTier {
                keys: vec![pk2, pk3],
                threshold: 1,
                timelock_months: 6,
            }],
            network: Network::Testnet,
        };

        let output = config.build().unwrap();
        assert!(output.address.to_string().starts_with("tb1p"));
        assert_eq!(output.tiers.len(), 1);
        assert_eq!(output.tiers[0].timelock_blocks, Some(6 * BLOCKS_PER_MONTH));
    }

    #[test]
    fn test_multisig_primary_with_two_recovery_tiers() {
        let keys: Vec<[u8; 32]> = (1..=9).map(test_keypair).collect();

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![keys[0], keys[1], keys[2]],
                threshold: 2,
            },
            recovery_tiers: vec![
                RecoveryTier {
                    keys: vec![keys[3], keys[4], keys[5], keys[6], keys[7]],
                    threshold: 3,
                    timelock_months: 6,
                },
                RecoveryTier {
                    keys: vec![keys[8]],
                    threshold: 1,
                    timelock_months: 12,
                },
            ],
            network: Network::Testnet,
        };

        let output = config.build().unwrap();
        assert!(output.address.to_string().starts_with("tb1p"));
        assert_eq!(output.tiers.len(), 3);
        assert!(output.tiers[0].timelock_blocks.is_none());
        assert_eq!(output.tiers[1].timelock_blocks, Some(6 * BLOCKS_PER_MONTH));
        assert_eq!(output.tiers[2].timelock_blocks, Some(12 * BLOCKS_PER_MONTH));
    }

    #[test]
    fn test_validation_errors() {
        let pk = test_keypair(1);
        let pk2 = test_keypair(2);
        let pk3 = test_keypair(3);
        let pk4 = test_keypair(4);

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![],
                threshold: 1,
            },
            recovery_tiers: vec![],
            network: Network::Testnet,
        };
        assert!(config.validate().is_err());

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![pk],
                threshold: 1,
            },
            recovery_tiers: vec![RecoveryTier {
                keys: vec![pk2],
                threshold: 1,
                timelock_months: 0,
            }],
            network: Network::Testnet,
        };
        assert!(config.validate().is_err());

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![pk],
                threshold: 1,
            },
            recovery_tiers: vec![
                RecoveryTier {
                    keys: vec![pk3],
                    threshold: 1,
                    timelock_months: 12,
                },
                RecoveryTier {
                    keys: vec![pk4],
                    threshold: 1,
                    timelock_months: 6,
                },
            ],
            network: Network::Testnet,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_descriptor_format() {
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

        let output = config.build().unwrap();
        assert!(output.descriptor.starts_with("tr("));
        assert!(output.descriptor.contains("csv="));
    }

    #[test]
    fn test_timelock_script_structure() {
        let pk = test_keypair(1);
        let blocks = months_to_blocks(6).unwrap();

        let script = build_timelocked_multisig(&[pk], 1, blocks).unwrap();

        let asm = script.to_asm_string();
        assert!(asm.contains("OP_CSV"));
        assert!(asm.contains("OP_DROP"));
        assert!(asm.contains("OP_CHECKSIG"));
    }

    #[test]
    fn test_months_to_blocks() {
        assert_eq!(months_to_blocks(6).unwrap(), 6 * 144 * 30);
        assert_eq!(months_to_blocks(12).unwrap(), 12 * 144 * 30);
    }

    #[test]
    fn test_months_to_blocks_overflow() {
        assert!(months_to_blocks(u32::MAX).is_err());
    }

    #[test]
    fn test_recovery_sequence() {
        let seq = recovery_sequence(25920).unwrap();
        assert!(seq.is_relative_lock_time());
    }

    #[test]
    fn test_recovery_sequence_overflow() {
        assert!(recovery_sequence(70000).is_err());
    }

    #[test]
    fn test_optimal_depth_valid_trees() {
        for count in 1..=10 {
            let depths = optimal_depth(count);
            assert_eq!(depths.len(), count);

            let mut builder = TaprootBuilder::new();
            let secp = Secp256k1::new();
            let pk = test_keypair(1);
            let xonly = XOnlyPublicKey::from_slice(&pk).unwrap();
            let script = ScriptBuf::builder()
                .push_x_only_key(&xonly)
                .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
                .into_script();

            for &d in &depths {
                builder = builder.add_leaf(d, script.clone()).unwrap();
            }
            let internal = XOnlyPublicKey::from_slice(&NUMS_POINT).unwrap();
            assert!(builder.finalize(&secp, internal).is_ok());
        }
    }

    #[test]
    fn test_nums_internal_key_for_multisig() {
        let pk1 = test_keypair(1);
        let pk2 = test_keypair(2);
        let pk3 = test_keypair(3);

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![pk1, pk2],
                threshold: 2,
            },
            recovery_tiers: vec![RecoveryTier {
                keys: vec![pk3],
                threshold: 1,
                timelock_months: 6,
            }],
            network: Network::Testnet,
        };

        let output = config.build().unwrap();
        assert!(output.address.to_string().starts_with("tb1p"));
        assert_eq!(output.tiers.len(), 2);
        assert_eq!(output.tiers[0].name, "primary");
    }

    #[test]
    fn test_multisig_script_uses_numequal() {
        let pk1 = test_keypair(1);
        let pk2 = test_keypair(2);
        let pk3 = test_keypair(3);

        let script = build_multisig_script(&[pk1, pk2, pk3], 2).unwrap();
        let asm = script.to_asm_string();
        assert!(asm.contains("OP_NUMEQUAL"));
        assert!(!asm.contains("OP_NUMEQUALVERIFY"));
    }

    #[test]
    fn test_key_count_limit() {
        let keys: Vec<[u8; 32]> = (1..=21).map(|i| test_keypair(i as u8)).collect();
        let recovery_pk = test_keypair(100);

        let config = RecoveryConfig {
            primary: SpendingTier { keys, threshold: 1 },
            recovery_tiers: vec![RecoveryTier {
                keys: vec![recovery_pk],
                threshold: 1,
                timelock_months: 6,
            }],
            network: Network::Testnet,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_tier_info_has_threshold_and_keys() {
        let pk1 = test_keypair(1);
        let pk2 = test_keypair(2);
        let pk3 = test_keypair(3);

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![pk1],
                threshold: 1,
            },
            recovery_tiers: vec![RecoveryTier {
                keys: vec![pk2, pk3],
                threshold: 2,
                timelock_months: 6,
            }],
            network: Network::Testnet,
        };

        let output = config.build().unwrap();
        assert_eq!(output.tiers[0].threshold, 2);
        assert_eq!(output.tiers[0].keys.len(), 2);
    }

    #[test]
    fn test_duplicate_keys_within_tier() {
        let pk = test_keypair(1);
        let pk2 = test_keypair(2);

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![pk, pk],
                threshold: 2,
            },
            recovery_tiers: vec![RecoveryTier {
                keys: vec![pk2],
                threshold: 1,
                timelock_months: 6,
            }],
            network: Network::Testnet,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_duplicate_keys_across_tiers() {
        let pk = test_keypair(1);

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![pk],
                threshold: 1,
            },
            recovery_tiers: vec![RecoveryTier {
                keys: vec![pk],
                threshold: 1,
                timelock_months: 6,
            }],
            network: Network::Testnet,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_empty_recovery_tiers_rejected() {
        let pk = test_keypair(1);

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![pk],
                threshold: 1,
            },
            recovery_tiers: vec![],
            network: Network::Testnet,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_max_recovery_tiers_exceeded() {
        let pk = test_keypair(1);
        let tiers: Vec<RecoveryTier> = (0..11)
            .map(|i| RecoveryTier {
                keys: vec![test_keypair((i + 2) as u8)],
                threshold: 1,
                timelock_months: (i + 1) as u32,
            })
            .collect();

        let config = RecoveryConfig {
            primary: SpendingTier {
                keys: vec![pk],
                threshold: 1,
            },
            recovery_tiers: tiers,
            network: Network::Testnet,
        };
        assert!(config.validate().is_err());
    }
}
