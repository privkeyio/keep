// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::error::KeepMobileError;
use crate::velocity::VelocityTracker;
use chrono::{Datelike, Timelike, Utc};
use k256::schnorr::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;

pub const POLICY_VERSION: u8 = 1;
pub const POLICY_MAX_RULES_LEN: usize = 2048;
pub const POLICY_SIGNATURE_LEN: usize = 64;
pub const POLICY_PUBKEY_LEN: usize = 32;
pub const POLICY_HASH_LEN: usize = 32;

const POLICY_HEADER_LEN: usize = 1 + POLICY_PUBKEY_LEN + POLICY_HASH_LEN + 4;
const POLICY_MIN_LEN: usize = POLICY_HEADER_LEN + 8 + POLICY_SIGNATURE_LEN;

const MAX_POLICY_AGE_SECS: u64 = 365 * 24 * 60 * 60;
const MAX_POLICY_FUTURE_SECS: u64 = 60 * 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub version: u8,
    #[serde(with = "hex_array_32")]
    pub warden_pubkey: [u8; POLICY_PUBKEY_LEN],
    #[serde(with = "hex_array_32")]
    pub policy_hash: [u8; POLICY_HASH_LEN],
    pub rules_json: String,
    pub created_at: u64,
    #[serde(with = "hex_array_64")]
    pub signature: [u8; POLICY_SIGNATURE_LEN],
}

macro_rules! hex_array_serde {
    ($mod_name:ident, $size:expr) => {
        mod $mod_name {
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S>(data: &[u8; $size], serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&hex::encode(data))
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; $size], D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("invalid length"))
            }
        }
    };
}

hex_array_serde!(hex_array_32, 32);
hex_array_serde!(hex_array_64, 64);

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

impl PolicyRules {
    fn summary(&self) -> String {
        let mut parts = Vec::new();

        if let Some(max) = self.max_amount {
            parts.push(format!("max_amount: {max} sats"));
        }
        if let Some(max) = self.max_fee {
            parts.push(format!("max_fee: {max} sats"));
        }
        if let Some(daily) = self.daily_limit {
            parts.push(format!("daily_limit: {daily} sats"));
        }
        if let Some(weekly) = self.weekly_limit {
            parts.push(format!("weekly_limit: {weekly} sats"));
        }
        if self.allowed_hours.is_some() {
            parts.push("time_restricted".to_string());
        }
        if self.allowed_days.is_some() {
            parts.push("day_restricted".to_string());
        }
        if self.whitelist.is_some() {
            parts.push("whitelist".to_string());
        }
        if self.blacklist.is_some() {
            parts.push("blacklist".to_string());
        }

        if parts.is_empty() {
            "no restrictions".to_string()
        } else {
            parts.join(", ")
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct HourRange {
    pub start: u8,
    pub end: u8,
}

impl<'de> Deserialize<'de> for HourRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawHourRange {
            start: u8,
            end: u8,
        }

        let raw = RawHourRange::deserialize(deserializer)?;

        if raw.start > 23 {
            return Err(serde::de::Error::custom(format!(
                "invalid start hour {}: must be 0-23",
                raw.start
            )));
        }
        if raw.end > 23 {
            return Err(serde::de::Error::custom(format!(
                "invalid end hour {}: must be 0-23",
                raw.end
            )));
        }

        Ok(HourRange {
            start: raw.start,
            end: raw.end,
        })
    }
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
    pub has_unknown_destination: bool,
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
                msg: format!("Unsupported policy version: {version}"),
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
                msg: format!("Rules too large: {rules_len} bytes (max {POLICY_MAX_RULES_LEN})"),
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
                msg: format!("Invalid warden pubkey: {e}"),
            }
        })?;

        let signature = Signature::try_from(self.signature.as_slice()).map_err(|e| {
            KeepMobileError::InvalidPolicy {
                msg: format!("Invalid signature format: {e}"),
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

    pub fn verify_trusted_warden(
        &self,
        trusted_wardens: &HashSet<[u8; POLICY_PUBKEY_LEN]>,
    ) -> Result<(), KeepMobileError> {
        if trusted_wardens.is_empty() {
            return Err(KeepMobileError::InvalidPolicy {
                msg: "No trusted wardens configured".into(),
            });
        }

        if !trusted_wardens.contains(&self.warden_pubkey) {
            return Err(KeepMobileError::InvalidPolicy {
                msg: "Policy signed by untrusted warden".into(),
            });
        }

        Ok(())
    }

    pub fn verify_timestamp(&self) -> Result<(), KeepMobileError> {
        let now = Utc::now().timestamp() as u64;

        if self.created_at > now + MAX_POLICY_FUTURE_SECS {
            return Err(KeepMobileError::InvalidPolicy {
                msg: "Policy timestamp is in the future".into(),
            });
        }

        if now > self.created_at + MAX_POLICY_AGE_SECS {
            return Err(KeepMobileError::InvalidPolicy {
                msg: "Policy has expired".into(),
            });
        }

        Ok(())
    }

    pub fn verify_version_upgrade(
        &self,
        current: Option<&PolicyBundle>,
    ) -> Result<(), KeepMobileError> {
        if let Some(current) = current {
            if self.created_at < current.created_at {
                return Err(KeepMobileError::InvalidPolicy {
                    msg: "Cannot downgrade to older policy".into(),
                });
            }
        }
        Ok(())
    }

    pub fn parse_rules(&self) -> Result<PolicyRules, KeepMobileError> {
        serde_json::from_str(&self.rules_json).map_err(|e| KeepMobileError::InvalidPolicy {
            msg: format!("Invalid rules JSON: {e}"),
        })
    }

    pub fn to_policy_info(&self) -> PolicyInfo {
        let rules_summary = match self.parse_rules() {
            Ok(rules) => rules.summary(),
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
    trusted_wardens: HashSet<[u8; POLICY_PUBKEY_LEN]>,
}

impl PolicyEvaluator {
    pub fn new(velocity: Arc<Mutex<VelocityTracker>>) -> Self {
        Self {
            policy: None,
            velocity,
            trusted_wardens: HashSet::new(),
        }
    }

    pub fn add_trusted_warden(&mut self, pubkey: [u8; POLICY_PUBKEY_LEN]) {
        self.trusted_wardens.insert(pubkey);
    }

    pub fn remove_trusted_warden(&mut self, pubkey: &[u8; POLICY_PUBKEY_LEN]) {
        self.trusted_wardens.remove(pubkey);
    }

    pub fn trusted_wardens(&self) -> &HashSet<[u8; POLICY_PUBKEY_LEN]> {
        &self.trusted_wardens
    }

    pub fn set_trusted_wardens(&mut self, wardens: HashSet<[u8; POLICY_PUBKEY_LEN]>) {
        self.trusted_wardens = wardens;
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
                    reason: "Amount exceeds policy limit".into(),
                });
            }
        }

        if let Some(max_fee) = rules.max_fee {
            if ctx.fee_sats > max_fee {
                return Ok(PolicyDecision::Deny {
                    reason: "Fee exceeds policy limit".into(),
                });
            }
        }

        if rules.daily_limit.is_some() || rules.weekly_limit.is_some() {
            let velocity = self
                .velocity
                .lock()
                .map_err(|_| KeepMobileError::StorageError {
                    msg: "Velocity lock poisoned".into(),
                })?;

            if let Some(daily_limit) = rules.daily_limit {
                if velocity.daily_total().saturating_add(ctx.amount_sats) > daily_limit {
                    return Ok(PolicyDecision::Deny {
                        reason: "Would exceed daily spending limit".into(),
                    });
                }
            }

            if let Some(weekly_limit) = rules.weekly_limit {
                if velocity.weekly_total().saturating_add(ctx.amount_sats) > weekly_limit {
                    return Ok(PolicyDecision::Deny {
                        reason: "Would exceed weekly spending limit".into(),
                    });
                }
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
                    reason: "Transaction outside allowed hours".into(),
                });
            }
        }

        if let Some(allowed_days) = &rules.allowed_days {
            let day_name = weekday_abbrev(Utc::now().weekday());
            if !allowed_days
                .iter()
                .any(|d| d.eq_ignore_ascii_case(day_name))
            {
                return Ok(PolicyDecision::Deny {
                    reason: "Transaction not allowed on this day".into(),
                });
            }
        }

        if let Some(whitelist) = &rules.whitelist {
            if ctx.has_unknown_destination {
                return Ok(PolicyDecision::Deny {
                    reason: "Transaction has unknown destination".into(),
                });
            }
            for dest in &ctx.destinations {
                if !whitelist.iter().any(|w| w.eq_ignore_ascii_case(dest)) {
                    return Ok(PolicyDecision::Deny {
                        reason: "Destination not in whitelist".into(),
                    });
                }
            }
        }

        if let Some(blacklist) = &rules.blacklist {
            for dest in &ctx.destinations {
                if blacklist.iter().any(|b| b.eq_ignore_ascii_case(dest)) {
                    return Ok(PolicyDecision::Deny {
                        reason: "Destination is blacklisted".into(),
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
        let non_change_outputs: Vec<_> = info.outputs.iter().filter(|o| !o.is_change).collect();

        let amount_sats = non_change_outputs.iter().map(|o| o.amount_sats).sum();

        let has_unknown_destination = non_change_outputs.iter().any(|o| o.address.is_none());

        let destinations = non_change_outputs
            .iter()
            .filter_map(|o| o.address.clone())
            .collect();

        Self {
            amount_sats,
            fee_sats: info.fee_sats,
            destinations,
            has_unknown_destination,
        }
    }
}

fn weekday_abbrev(weekday: chrono::Weekday) -> &'static str {
    match weekday {
        chrono::Weekday::Mon => "mon",
        chrono::Weekday::Tue => "tue",
        chrono::Weekday::Wed => "wed",
        chrono::Weekday::Thu => "thu",
        chrono::Weekday::Fri => "fri",
        chrono::Weekday::Sat => "sat",
        chrono::Weekday::Sun => "sun",
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
            has_unknown_destination: false,
        };
        assert_eq!(evaluator.evaluate(&ctx).unwrap(), PolicyDecision::Allow);

        let ctx = TransactionContext {
            amount_sats: 150_000,
            fee_sats: 500,
            destinations: vec![],
            has_unknown_destination: false,
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
            has_unknown_destination: false,
        };
        assert_eq!(evaluator.evaluate(&ctx).unwrap(), PolicyDecision::Allow);

        let ctx = TransactionContext {
            amount_sats: 50_000,
            fee_sats: 5_000,
            destinations: vec![],
            has_unknown_destination: false,
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
            has_unknown_destination: false,
        };
        assert_eq!(evaluator.evaluate(&ctx).unwrap(), PolicyDecision::Allow);

        let ctx = TransactionContext {
            amount_sats: 50_000,
            fee_sats: 500,
            destinations: vec!["bc1blocked".to_string()],
            has_unknown_destination: false,
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
            has_unknown_destination: false,
        };
        assert_eq!(evaluator.evaluate(&ctx).unwrap(), PolicyDecision::Allow);

        let ctx = TransactionContext {
            amount_sats: 50_000,
            fee_sats: 500,
            destinations: vec!["bc1blocked".to_string()],
            has_unknown_destination: false,
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
            has_unknown_destination: false,
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

    #[test]
    fn test_trusted_warden_verification() {
        let rules = PolicyRules::default();
        let bundle = create_test_bundle(&rules);

        let mut trusted = HashSet::new();
        assert!(bundle.verify_trusted_warden(&trusted).is_err());

        trusted.insert(bundle.warden_pubkey);
        assert!(bundle.verify_trusted_warden(&trusted).is_ok());

        let mut untrusted = HashSet::new();
        untrusted.insert([0u8; 32]);
        assert!(bundle.verify_trusted_warden(&untrusted).is_err());
    }

    #[test]
    fn test_timestamp_validation() {
        let rules = PolicyRules::default();
        let mut bundle = create_test_bundle(&rules);

        assert!(bundle.verify_timestamp().is_ok());

        bundle.created_at = Utc::now().timestamp() as u64 + MAX_POLICY_FUTURE_SECS + 3600;
        assert!(bundle.verify_timestamp().is_err());

        bundle.created_at = Utc::now().timestamp() as u64 - MAX_POLICY_AGE_SECS - 3600;
        assert!(bundle.verify_timestamp().is_err());
    }

    #[test]
    fn test_version_rollback_protection() {
        let rules = PolicyRules::default();
        let bundle1 = create_test_bundle(&rules);
        let mut bundle2 = create_test_bundle(&rules);

        assert!(bundle2.verify_version_upgrade(Some(&bundle1)).is_ok());

        bundle2.created_at = bundle1.created_at - 1;
        assert!(bundle2.verify_version_upgrade(Some(&bundle1)).is_err());
    }

    #[test]
    fn test_case_insensitive_whitelist() {
        let rules = PolicyRules {
            whitelist: Some(vec!["BC1QALLOWED".to_string()]),
            ..Default::default()
        };
        let bundle = create_test_bundle(&rules);

        let velocity = Arc::new(Mutex::new(VelocityTracker::new()));
        let mut evaluator = PolicyEvaluator::new(velocity);
        evaluator.set_policy(bundle);

        let ctx = TransactionContext {
            amount_sats: 50_000,
            fee_sats: 500,
            destinations: vec!["bc1qallowed".to_string()],
            has_unknown_destination: false,
        };
        assert_eq!(evaluator.evaluate(&ctx).unwrap(), PolicyDecision::Allow);

        let ctx = TransactionContext {
            amount_sats: 50_000,
            fee_sats: 500,
            destinations: vec!["BC1QALLOWED".to_string()],
            has_unknown_destination: false,
        };
        assert_eq!(evaluator.evaluate(&ctx).unwrap(), PolicyDecision::Allow);
    }

    #[test]
    fn test_case_insensitive_blacklist() {
        let rules = PolicyRules {
            blacklist: Some(vec!["bc1qblocked".to_string()]),
            ..Default::default()
        };
        let bundle = create_test_bundle(&rules);

        let velocity = Arc::new(Mutex::new(VelocityTracker::new()));
        let mut evaluator = PolicyEvaluator::new(velocity);
        evaluator.set_policy(bundle);

        let ctx = TransactionContext {
            amount_sats: 50_000,
            fee_sats: 500,
            destinations: vec!["BC1QBLOCKED".to_string()],
            has_unknown_destination: false,
        };
        assert!(matches!(
            evaluator.evaluate(&ctx).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_policy_serialization() {
        let rules = PolicyRules {
            max_amount: Some(100_000),
            ..Default::default()
        };
        let bundle = create_test_bundle(&rules);

        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: PolicyBundle = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, bundle.version);
        assert_eq!(parsed.warden_pubkey, bundle.warden_pubkey);
        assert_eq!(parsed.policy_hash, bundle.policy_hash);
        assert_eq!(parsed.created_at, bundle.created_at);
        assert_eq!(parsed.signature, bundle.signature);
    }
}
