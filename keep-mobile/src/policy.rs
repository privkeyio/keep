// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::error::KeepMobileError;
use crate::velocity::VelocityTracker;
use chrono::{Datelike, Timelike, Utc};
use k256::schnorr::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;

pub const POLICY_VERSION: u8 = 1;
pub const POLICY_MAX_RULES_LEN: usize = 2048;
pub const POLICY_SIGNATURE_LEN: usize = 64;
pub const POLICY_PUBKEY_LEN: usize = 32;
pub const POLICY_HASH_LEN: usize = 32;

const POLICY_HEADER_LEN: usize = 1 + POLICY_PUBKEY_LEN + POLICY_HASH_LEN + 4;
const POLICY_MIN_LEN: usize = POLICY_HEADER_LEN + 8 + POLICY_SIGNATURE_LEN;

#[derive(Clone, Debug)]
pub struct PolicyBundle {
    pub version: u8,
    pub warden_pubkey: [u8; POLICY_PUBKEY_LEN],
    pub policy_hash: [u8; POLICY_HASH_LEN],
    pub rules_json: String,
    pub created_at: u64,
    pub signature: [u8; POLICY_SIGNATURE_LEN],
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PolicyInfo {
    pub has_policy: bool,
    pub version: u8,
    pub policy_hash: String,
    pub warden_pubkey: String,
    pub rules_summary: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PolicyRules {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daily_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weekly_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_hours: Option<HourRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_days: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whitelist: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blacklist: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HourRange {
    pub start: u8,
    pub end: u8,
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct TransactionContext {
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub destinations: Vec<String>,
}

impl PolicyBundle {
    pub fn from_bytes(data: &[u8]) -> Result<Self, KeepMobileError> {
        if data.len() < POLICY_MIN_LEN {
            return Err(KeepMobileError::InvalidPolicy {
                msg: format!(
                    "Bundle too short: {} bytes (minimum {})",
                    data.len(),
                    POLICY_MIN_LEN
                ),
            });
        }

        let version = data[0];
        if version != POLICY_VERSION {
            return Err(KeepMobileError::InvalidPolicy {
                msg: format!("Unsupported policy version: {}", version),
            });
        }

        let mut offset = 1;

        let mut warden_pubkey = [0u8; POLICY_PUBKEY_LEN];
        warden_pubkey.copy_from_slice(&data[offset..offset + POLICY_PUBKEY_LEN]);
        offset += POLICY_PUBKEY_LEN;

        let mut policy_hash = [0u8; POLICY_HASH_LEN];
        policy_hash.copy_from_slice(&data[offset..offset + POLICY_HASH_LEN]);
        offset += POLICY_HASH_LEN;

        let rules_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        if rules_len > POLICY_MAX_RULES_LEN {
            return Err(KeepMobileError::InvalidPolicy {
                msg: format!(
                    "Rules too large: {} bytes (max {})",
                    rules_len, POLICY_MAX_RULES_LEN
                ),
            });
        }

        if offset + rules_len + 8 + POLICY_SIGNATURE_LEN > data.len() {
            return Err(KeepMobileError::InvalidPolicy {
                msg: "Bundle truncated".into(),
            });
        }

        let rules_json =
            String::from_utf8(data[offset..offset + rules_len].to_vec()).map_err(|_| {
                KeepMobileError::InvalidPolicy {
                    msg: "Invalid UTF-8 in rules".into(),
                }
            })?;
        offset += rules_len;

        let created_at = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;

        let mut signature = [0u8; POLICY_SIGNATURE_LEN];
        signature.copy_from_slice(&data[offset..offset + POLICY_SIGNATURE_LEN]);

        Ok(Self {
            version,
            warden_pubkey,
            policy_hash,
            rules_json,
            created_at,
            signature,
        })
    }

    #[allow(dead_code)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let rules_bytes = self.rules_json.as_bytes();
        let mut result = Vec::with_capacity(POLICY_MIN_LEN + rules_bytes.len());

        result.push(self.version);
        result.extend_from_slice(&self.warden_pubkey);
        result.extend_from_slice(&self.policy_hash);
        result.extend_from_slice(&(rules_bytes.len() as u32).to_le_bytes());
        result.extend_from_slice(rules_bytes);
        result.extend_from_slice(&self.created_at.to_le_bytes());
        result.extend_from_slice(&self.signature);

        result
    }

    fn signed_data(&self) -> Vec<u8> {
        let rules_bytes = self.rules_json.as_bytes();
        let mut data = Vec::with_capacity(POLICY_HEADER_LEN + rules_bytes.len() + 8);

        data.push(self.version);
        data.extend_from_slice(&self.warden_pubkey);
        data.extend_from_slice(&self.policy_hash);
        data.extend_from_slice(&(rules_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(rules_bytes);
        data.extend_from_slice(&self.created_at.to_le_bytes());

        data
    }

    pub fn verify_signature(&self) -> Result<(), KeepMobileError> {
        let verifying_key = VerifyingKey::from_bytes(&self.warden_pubkey).map_err(|e| {
            KeepMobileError::InvalidPolicy {
                msg: format!("Invalid warden pubkey: {}", e),
            }
        })?;

        let signature = Signature::try_from(self.signature.as_slice()).map_err(|e| {
            KeepMobileError::InvalidPolicy {
                msg: format!("Invalid signature format: {}", e),
            }
        })?;

        let signed_data = self.signed_data();
        let mut hasher = Sha256::new();
        hasher.update(&signed_data);
        let message: [u8; 32] = hasher.finalize().into();

        verifying_key
            .verify(&message, &signature)
            .map_err(|_| KeepMobileError::PolicySignatureInvalid)
    }

    pub fn verify_hash(&self) -> Result<(), KeepMobileError> {
        let mut hasher = Sha256::new();
        hasher.update(self.rules_json.as_bytes());
        let computed: [u8; 32] = hasher.finalize().into();

        if !bool::from(computed.ct_eq(&self.policy_hash)) {
            return Err(KeepMobileError::InvalidPolicy {
                msg: "Policy hash mismatch".into(),
            });
        }

        Ok(())
    }

    pub fn parse_rules(&self) -> Result<PolicyRules, KeepMobileError> {
        serde_json::from_str(&self.rules_json).map_err(|e| KeepMobileError::InvalidPolicy {
            msg: format!("Invalid rules JSON: {}", e),
        })
    }

    pub fn to_policy_info(&self) -> PolicyInfo {
        let rules_summary = match self.parse_rules() {
            Ok(rules) => {
                let mut parts = Vec::new();
                if let Some(max) = rules.max_amount {
                    parts.push(format!("max_amount: {} sats", max));
                }
                if let Some(max) = rules.max_fee {
                    parts.push(format!("max_fee: {} sats", max));
                }
                if let Some(daily) = rules.daily_limit {
                    parts.push(format!("daily_limit: {} sats", daily));
                }
                if let Some(weekly) = rules.weekly_limit {
                    parts.push(format!("weekly_limit: {} sats", weekly));
                }
                if rules.allowed_hours.is_some() {
                    parts.push("time_restricted".to_string());
                }
                if rules.allowed_days.is_some() {
                    parts.push("day_restricted".to_string());
                }
                if rules.whitelist.is_some() {
                    parts.push("whitelist".to_string());
                }
                if rules.blacklist.is_some() {
                    parts.push("blacklist".to_string());
                }
                if parts.is_empty() {
                    "no restrictions".to_string()
                } else {
                    parts.join(", ")
                }
            }
            Err(_) => "invalid rules".to_string(),
        };

        PolicyInfo {
            has_policy: true,
            version: self.version,
            policy_hash: hex::encode(self.policy_hash),
            warden_pubkey: hex::encode(self.warden_pubkey),
            rules_summary,
            created_at: self.created_at,
        }
    }
}

pub struct PolicyEvaluator {
    policy: Option<PolicyBundle>,
    velocity: Arc<Mutex<VelocityTracker>>,
}

impl PolicyEvaluator {
    pub fn new(velocity: Arc<Mutex<VelocityTracker>>) -> Self {
        Self {
            policy: None,
            velocity,
        }
    }

    pub fn set_policy(&mut self, bundle: PolicyBundle) {
        self.policy = Some(bundle);
    }

    pub fn clear_policy(&mut self) {
        self.policy = None;
    }

    pub fn policy(&self) -> Option<&PolicyBundle> {
        self.policy.as_ref()
    }

    pub fn evaluate(&self, ctx: &TransactionContext) -> Result<PolicyDecision, KeepMobileError> {
        let Some(bundle) = &self.policy else {
            return Ok(PolicyDecision::Allow);
        };

        let rules = bundle.parse_rules()?;

        if let Some(max_amount) = rules.max_amount {
            if ctx.amount_sats > max_amount {
                return Ok(PolicyDecision::Deny {
                    reason: format!(
                        "Amount {} sats exceeds maximum {} sats",
                        ctx.amount_sats, max_amount
                    ),
                });
            }
        }

        if let Some(max_fee) = rules.max_fee {
            if ctx.fee_sats > max_fee {
                return Ok(PolicyDecision::Deny {
                    reason: format!("Fee {} sats exceeds maximum {} sats", ctx.fee_sats, max_fee),
                });
            }
        }

        if let Some(daily_limit) = rules.daily_limit {
            let velocity = self
                .velocity
                .lock()
                .map_err(|_| KeepMobileError::StorageError {
                    msg: "Velocity lock poisoned".into(),
                })?;
            let daily_total = velocity.daily_total();
            if daily_total + ctx.amount_sats > daily_limit {
                return Ok(PolicyDecision::Deny {
                    reason: format!(
                        "Would exceed daily limit: {} + {} > {} sats",
                        daily_total, ctx.amount_sats, daily_limit
                    ),
                });
            }
        }

        if let Some(weekly_limit) = rules.weekly_limit {
            let velocity = self
                .velocity
                .lock()
                .map_err(|_| KeepMobileError::StorageError {
                    msg: "Velocity lock poisoned".into(),
                })?;
            let weekly_total = velocity.weekly_total();
            if weekly_total + ctx.amount_sats > weekly_limit {
                return Ok(PolicyDecision::Deny {
                    reason: format!(
                        "Would exceed weekly limit: {} + {} > {} sats",
                        weekly_total, ctx.amount_sats, weekly_limit
                    ),
                });
            }
        }

        if let Some(hour_range) = &rules.allowed_hours {
            let now = Utc::now();
            let hour = now.hour() as u8;
            let allowed = if hour_range.start <= hour_range.end {
                hour >= hour_range.start && hour < hour_range.end
            } else {
                hour >= hour_range.start || hour < hour_range.end
            };
            if !allowed {
                return Ok(PolicyDecision::Deny {
                    reason: format!(
                        "Current hour {} outside allowed range {:02}:00-{:02}:00",
                        hour, hour_range.start, hour_range.end
                    ),
                });
            }
        }

        if let Some(allowed_days) = &rules.allowed_days {
            let now = Utc::now();
            let day_name = match now.weekday() {
                chrono::Weekday::Mon => "mon",
                chrono::Weekday::Tue => "tue",
                chrono::Weekday::Wed => "wed",
                chrono::Weekday::Thu => "thu",
                chrono::Weekday::Fri => "fri",
                chrono::Weekday::Sat => "sat",
                chrono::Weekday::Sun => "sun",
            };
            let allowed = allowed_days.iter().any(|d| d.to_lowercase() == day_name);
            if !allowed {
                return Ok(PolicyDecision::Deny {
                    reason: format!("Transactions not allowed on {}", day_name.to_uppercase()),
                });
            }
        }

        if let Some(whitelist) = &rules.whitelist {
            for dest in &ctx.destinations {
                if !whitelist.contains(dest) {
                    return Ok(PolicyDecision::Deny {
                        reason: format!("Destination {} not in whitelist", dest),
                    });
                }
            }
        }

        if let Some(blacklist) = &rules.blacklist {
            for dest in &ctx.destinations {
                if blacklist.contains(dest) {
                    return Ok(PolicyDecision::Deny {
                        reason: format!("Destination {} is blacklisted", dest),
                    });
                }
            }
        }

        Ok(PolicyDecision::Allow)
    }

    pub fn record_transaction(&self, amount_sats: u64) -> Result<(), KeepMobileError> {
        let mut velocity = self
            .velocity
            .lock()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "Velocity lock poisoned".into(),
            })?;
        velocity.record(amount_sats);
        Ok(())
    }
}

impl TransactionContext {
    pub fn from_psbt_info(info: &crate::PsbtInfo) -> Self {
        let amount_sats = info
            .outputs
            .iter()
            .filter(|o| !o.is_change)
            .map(|o| o.amount_sats)
            .sum();

        let destinations = info
            .outputs
            .iter()
            .filter(|o| !o.is_change)
            .filter_map(|o| o.address.clone())
            .collect();

        Self {
            amount_sats,
            fee_sats: info.fee_sats,
            destinations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::{signature::Signer, SigningKey};

    fn create_test_bundle(rules: &PolicyRules) -> PolicyBundle {
        let rules_json = serde_json::to_string(rules).unwrap();
        let mut rules_hasher = Sha256::new();
        rules_hasher.update(rules_json.as_bytes());
        let policy_hash: [u8; 32] = rules_hasher.finalize().into();

        let signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let mut warden_pubkey = [0u8; 32];
        warden_pubkey.copy_from_slice(&verifying_key.to_bytes());

        let created_at = Utc::now().timestamp() as u64;

        let mut bundle = PolicyBundle {
            version: POLICY_VERSION,
            warden_pubkey,
            policy_hash,
            rules_json,
            created_at,
            signature: [0u8; 64],
        };

        let signed_data = bundle.signed_data();
        let mut hasher = Sha256::new();
        hasher.update(&signed_data);
        let message: [u8; 32] = hasher.finalize().into();
        let signature = signing_key.sign(&message);
        bundle.signature.copy_from_slice(&signature.to_bytes());

        bundle
    }

    #[test]
    fn test_bundle_roundtrip() {
        let rules = PolicyRules {
            max_amount: Some(1_000_000),
            max_fee: Some(10_000),
            ..Default::default()
        };
        let bundle = create_test_bundle(&rules);

        let bytes = bundle.to_bytes();
        let parsed = PolicyBundle::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, bundle.version);
        assert_eq!(parsed.warden_pubkey, bundle.warden_pubkey);
        assert_eq!(parsed.policy_hash, bundle.policy_hash);
        assert_eq!(parsed.rules_json, bundle.rules_json);
        assert_eq!(parsed.created_at, bundle.created_at);
        assert_eq!(parsed.signature, bundle.signature);
    }

    #[test]
    fn test_signature_verification() {
        let rules = PolicyRules::default();
        let bundle = create_test_bundle(&rules);
        assert!(bundle.verify_signature().is_ok());
    }

    #[test]
    fn test_signature_verification_fails_on_tamper() {
        let rules = PolicyRules::default();
        let mut bundle = create_test_bundle(&rules);
        bundle.created_at += 1;
        assert!(bundle.verify_signature().is_err());
    }

    #[test]
    fn test_hash_verification() {
        let rules = PolicyRules {
            max_amount: Some(100_000),
            ..Default::default()
        };
        let bundle = create_test_bundle(&rules);
        assert!(bundle.verify_hash().is_ok());
    }

    #[test]
    fn test_hash_verification_fails_on_tamper() {
        let rules = PolicyRules {
            max_amount: Some(100_000),
            ..Default::default()
        };
        let mut bundle = create_test_bundle(&rules);
        bundle.rules_json = r#"{"max_amount":999999}"#.to_string();
        assert!(bundle.verify_hash().is_err());
    }

    #[test]
    fn test_max_amount_evaluation() {
        let rules = PolicyRules {
            max_amount: Some(100_000),
            ..Default::default()
        };
        let bundle = create_test_bundle(&rules);

        let velocity = Arc::new(Mutex::new(VelocityTracker::new()));
        let mut evaluator = PolicyEvaluator::new(velocity);
        evaluator.set_policy(bundle);

        let ctx = TransactionContext {
            amount_sats: 50_000,
            fee_sats: 500,
            destinations: vec![],
        };
        assert_eq!(evaluator.evaluate(&ctx).unwrap(), PolicyDecision::Allow);

        let ctx = TransactionContext {
            amount_sats: 150_000,
            fee_sats: 500,
            destinations: vec![],
        };
        assert!(matches!(
            evaluator.evaluate(&ctx).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_max_fee_evaluation() {
        let rules = PolicyRules {
            max_fee: Some(1_000),
            ..Default::default()
        };
        let bundle = create_test_bundle(&rules);

        let velocity = Arc::new(Mutex::new(VelocityTracker::new()));
        let mut evaluator = PolicyEvaluator::new(velocity);
        evaluator.set_policy(bundle);

        let ctx = TransactionContext {
            amount_sats: 50_000,
            fee_sats: 500,
            destinations: vec![],
        };
        assert_eq!(evaluator.evaluate(&ctx).unwrap(), PolicyDecision::Allow);

        let ctx = TransactionContext {
            amount_sats: 50_000,
            fee_sats: 5_000,
            destinations: vec![],
        };
        assert!(matches!(
            evaluator.evaluate(&ctx).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_whitelist_evaluation() {
        let rules = PolicyRules {
            whitelist: Some(vec!["bc1allowed".to_string()]),
            ..Default::default()
        };
        let bundle = create_test_bundle(&rules);

        let velocity = Arc::new(Mutex::new(VelocityTracker::new()));
        let mut evaluator = PolicyEvaluator::new(velocity);
        evaluator.set_policy(bundle);

        let ctx = TransactionContext {
            amount_sats: 50_000,
            fee_sats: 500,
            destinations: vec!["bc1allowed".to_string()],
        };
        assert_eq!(evaluator.evaluate(&ctx).unwrap(), PolicyDecision::Allow);

        let ctx = TransactionContext {
            amount_sats: 50_000,
            fee_sats: 500,
            destinations: vec!["bc1blocked".to_string()],
        };
        assert!(matches!(
            evaluator.evaluate(&ctx).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_blacklist_evaluation() {
        let rules = PolicyRules {
            blacklist: Some(vec!["bc1blocked".to_string()]),
            ..Default::default()
        };
        let bundle = create_test_bundle(&rules);

        let velocity = Arc::new(Mutex::new(VelocityTracker::new()));
        let mut evaluator = PolicyEvaluator::new(velocity);
        evaluator.set_policy(bundle);

        let ctx = TransactionContext {
            amount_sats: 50_000,
            fee_sats: 500,
            destinations: vec!["bc1allowed".to_string()],
        };
        assert_eq!(evaluator.evaluate(&ctx).unwrap(), PolicyDecision::Allow);

        let ctx = TransactionContext {
            amount_sats: 50_000,
            fee_sats: 500,
            destinations: vec!["bc1blocked".to_string()],
        };
        assert!(matches!(
            evaluator.evaluate(&ctx).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_no_policy_allows_all() {
        let velocity = Arc::new(Mutex::new(VelocityTracker::new()));
        let evaluator = PolicyEvaluator::new(velocity);

        let ctx = TransactionContext {
            amount_sats: u64::MAX,
            fee_sats: u64::MAX,
            destinations: vec!["any".to_string()],
        };
        assert_eq!(evaluator.evaluate(&ctx).unwrap(), PolicyDecision::Allow);
    }

    #[test]
    fn test_policy_info() {
        let rules = PolicyRules {
            max_amount: Some(1_000_000),
            max_fee: Some(10_000),
            daily_limit: Some(5_000_000),
            ..Default::default()
        };
        let bundle = create_test_bundle(&rules);
        let info = bundle.to_policy_info();

        assert!(info.has_policy);
        assert_eq!(info.version, POLICY_VERSION);
        assert!(info.rules_summary.contains("max_amount"));
        assert!(info.rules_summary.contains("max_fee"));
        assert!(info.rules_summary.contains("daily_limit"));
    }
}
