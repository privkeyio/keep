// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use crate::rate_limit::RateLimiter;
use serde::{Deserialize, Serialize};

const MAX_POLICY_DEPTH: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub rules: Vec<PolicyRule>,
    pub action: PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyRule {
    MaxAmountSats(u64),
    MaxPerMinute(u32),
    MaxPerHour(u32),
    MaxPerDay(u32),
    AddressAllowlist(Vec<String>),
    AddressBlocklist(Vec<String>),
    AllowedHours { start: u8, end: u8 },
    BlockWeekends,
    AllowedEventKinds(Vec<u32>),
    And(Vec<PolicyRule>),
    Or(Vec<PolicyRule>),
    MaxFeeSats(u64),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny(PolicyDenyReason),
    RequireApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDenyReason {
    AmountExceeded,
    FeeExceeded,
    RateLimitExceeded,
    AddressNotAllowed,
    AddressBlocked,
    TimeRestriction,
    EventKindNotAllowed,
    ExplicitDeny,
    PolicyDepthExceeded,
}

impl std::fmt::Display for PolicyDenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AmountExceeded => write!(f, "amount exceeds limit"),
            Self::FeeExceeded => write!(f, "fee exceeds limit"),
            Self::RateLimitExceeded => write!(f, "rate limit exceeded"),
            Self::AddressNotAllowed => write!(f, "address not in allowlist"),
            Self::AddressBlocked => write!(f, "address is blocked"),
            Self::TimeRestriction => write!(f, "time restriction"),
            Self::EventKindNotAllowed => write!(f, "event kind not allowed"),
            Self::ExplicitDeny => write!(f, "policy denies request"),
            Self::PolicyDepthExceeded => write!(f, "policy nesting depth exceeded"),
        }
    }
}

pub struct SigningContext<'a> {
    pub key_id: &'a str,
    pub amount_sats: Option<u64>,
    pub fee_sats: Option<u64>,
    pub destination: Option<&'a str>,
    pub event_kind: Option<u32>,
    pub timestamp: u64,
}

pub struct PolicyEngine {
    policies: Vec<Policy>,
    rate_limiter: RateLimiter,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            rate_limiter: RateLimiter::new(),
        }
    }

    pub fn set_policies(&mut self, config: PolicyConfig) {
        self.policies = config.policies;
        // A bucket keeps the capacity from its first use, so a loose host
        // policy would otherwise survive the sealed rules.
        self.rate_limiter.clear();
    }

    /// A fee is bounded when no rule sequence can allow it. An amount cap counts
    /// only under Deny or RequireApproval. Under Allow, a failed rule is skipped
    /// and a later policy can still sign.
    pub fn bounds_fee(&self) -> bool {
        self.policies.iter().any(|policy| !policy_allows_unbounded_fee(policy))
    }

    pub fn evaluate(&mut self, ctx: &SigningContext<'_>) -> PolicyDecision {
        if self.policies.is_empty() {
            return PolicyDecision::Deny(PolicyDenyReason::ExplicitDeny);
        }
        for i in 0..self.policies.len() {
            let policy = self.policies[i].clone();
            let decision = self.check_policy(&policy, ctx);
            if decision != PolicyDecision::Allow {
                return decision;
            }
        }
        PolicyDecision::Allow
    }

    fn check_policy(&mut self, policy: &Policy, ctx: &SigningContext<'_>) -> PolicyDecision {
        for rule in &policy.rules {
            match self.check_rule(rule, ctx, MAX_POLICY_DEPTH) {
                Ok(true) => continue,
                Ok(false) => {
                    return match policy.action {
                        PolicyAction::Deny => PolicyDecision::Deny(PolicyDenyReason::ExplicitDeny),
                        PolicyAction::RequireApproval => PolicyDecision::RequireApproval,
                        PolicyAction::Allow => PolicyDecision::Allow,
                    };
                }
                Err(reason) => return PolicyDecision::Deny(reason),
            }
        }
        PolicyDecision::Allow
    }

    fn check_rule(
        &mut self,
        rule: &PolicyRule,
        ctx: &SigningContext<'_>,
        depth: usize,
    ) -> Result<bool, PolicyDenyReason> {
        if depth == 0 {
            return Err(PolicyDenyReason::PolicyDepthExceeded);
        }

        let result = match rule {
            PolicyRule::MaxAmountSats(max) => {
                ctx.amount_sats.map(|a| a <= *max).unwrap_or(true)
            }

            PolicyRule::MaxFeeSats(max) => match ctx.fee_sats {
                Some(fee) if fee > *max => return Err(PolicyDenyReason::FeeExceeded),
                _ => true,
            },

            PolicyRule::MaxPerMinute(max) => {
                self.rate_limiter.check_minute(ctx.key_id, *max)
            }

            PolicyRule::MaxPerHour(max) => {
                self.rate_limiter.check_hour(ctx.key_id, *max)
            }

            PolicyRule::MaxPerDay(max) => {
                self.rate_limiter.check_day(ctx.key_id, *max)
            }

            PolicyRule::AddressAllowlist(allowed) => {
                ctx.destination
                    .map(|d| allowed.iter().any(|a| a == d))
                    .unwrap_or(true)
            }

            PolicyRule::AddressBlocklist(blocked) => {
                ctx.destination
                    .map(|d| !blocked.iter().any(|b| b == d))
                    .unwrap_or(true)
            }

            PolicyRule::AllowedHours { start, end } => {
                if *start > 23 || *end > 23 {
                    return Ok(false);
                }
                let hour = ((ctx.timestamp / 3600) % 24) as u8;
                if start <= end {
                    hour >= *start && hour < *end
                } else {
                    hour >= *start || hour < *end
                }
            }

            PolicyRule::BlockWeekends => {
                let day = (ctx.timestamp / 86400 + 4) % 7;
                day != 0 && day != 6
            }

            PolicyRule::AllowedEventKinds(kinds) => {
                ctx.event_kind
                    .map(|k| kinds.contains(&k))
                    .unwrap_or(true)
            }

            PolicyRule::And(rules) => {
                for r in rules {
                    if !self.check_rule(r, ctx, depth - 1)? {
                        return Ok(false);
                    }
                }
                true
            }

            PolicyRule::Or(rules) => {
                for r in rules {
                    if self.check_rule(r, ctx, depth - 1)? {
                        return Ok(true);
                    }
                }
                false
            }
        };
        Ok(result)
    }

    pub fn record_operation(&mut self, key_id: &str) {
        self.rate_limiter.record(key_id);
    }
}

struct FeeEffect {
    pass: bool,
    fail: bool,
}

fn policy_allows_unbounded_fee(policy: &Policy) -> bool {
    for rule in &policy.rules {
        let effect = rule_fee_effect(rule);
        if effect.fail && matches!(policy.action, PolicyAction::Allow) {
            return true;
        }
        if !effect.pass {
            return false;
        }
    }
    true
}

fn rule_fee_effect(rule: &PolicyRule) -> FeeEffect {
    match rule {
        PolicyRule::MaxFeeSats(_) => FeeEffect {
            pass: false,
            fail: false,
        },
        PolicyRule::MaxAmountSats(_) => FeeEffect {
            pass: false,
            fail: true,
        },
        PolicyRule::And(rules) => and_fee_effect(rules),
        PolicyRule::Or(rules) => or_fee_effect(rules),
        _ => FeeEffect {
            pass: true,
            fail: true,
        },
    }
}

fn and_fee_effect(rules: &[PolicyRule]) -> FeeEffect {
    let mut effect = FeeEffect {
        pass: true,
        fail: false,
    };
    for rule in rules {
        if !effect.pass {
            break;
        }
        let child = rule_fee_effect(rule);
        effect.fail |= child.fail;
        effect.pass = child.pass;
    }
    effect
}

fn or_fee_effect(rules: &[PolicyRule]) -> FeeEffect {
    let mut effect = FeeEffect {
        pass: false,
        fail: false,
    };
    let mut open = true;
    for rule in rules {
        if !open {
            break;
        }
        let child = rule_fee_effect(rule);
        effect.pass |= child.pass;
        open = child.fail;
    }
    if open {
        effect.fail = true;
    }
    effect
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> u64 {
        1703001600
    }

    #[test]
    fn an_empty_policy_denies() {
        let mut engine = PolicyEngine::new();
        let ctx = SigningContext {
            key_id: "test",
            amount_sats: Some(1),
            fee_sats: None,
            destination: None,
            event_kind: None,
            timestamp: now(),
        };
        assert_eq!(
            engine.evaluate(&ctx),
            PolicyDecision::Deny(PolicyDenyReason::ExplicitDeny)
        );
    }

    #[test]
    fn test_max_amount() {
        let mut engine = PolicyEngine::new();
        engine.set_policies(PolicyConfig {
            policies: vec![Policy {
                name: "limit".into(),
                rules: vec![PolicyRule::MaxAmountSats(1000)],
                action: PolicyAction::Deny,
            }],
        });

        let ctx_ok = SigningContext {
            key_id: "test",
            amount_sats: Some(500),
            fee_sats: None,
            destination: None,
            event_kind: None,
            timestamp: now(),
        };
        assert_eq!(engine.evaluate(&ctx_ok), PolicyDecision::Allow);

        let ctx_fail = SigningContext {
            key_id: "test",
            amount_sats: Some(2000),
            fee_sats: None,
            destination: None,
            event_kind: None,
            timestamp: now(),
        };
        assert!(matches!(
            engine.evaluate(&ctx_fail),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn test_address_allowlist() {
        let mut engine = PolicyEngine::new();
        engine.set_policies(PolicyConfig {
            policies: vec![Policy {
                name: "allowlist".into(),
                rules: vec![PolicyRule::AddressAllowlist(vec![
                    "bc1allowed".into(),
                ])],
                action: PolicyAction::Deny,
            }],
        });

        let ctx_ok = SigningContext {
            key_id: "test",
            amount_sats: None,
            fee_sats: None,
            destination: Some("bc1allowed"),
            event_kind: None,
            timestamp: now(),
        };
        assert_eq!(engine.evaluate(&ctx_ok), PolicyDecision::Allow);

        let ctx_fail = SigningContext {
            key_id: "test",
            amount_sats: None,
            fee_sats: None,
            destination: Some("bc1blocked"),
            event_kind: None,
            timestamp: now(),
        };
        assert!(matches!(
            engine.evaluate(&ctx_fail),
            PolicyDecision::Deny(_)
        ));
    }

    fn policy(action: PolicyAction, rules: Vec<PolicyRule>) -> Policy {
        Policy {
            name: "p".into(),
            rules,
            action,
        }
    }

    fn engine(policies: Vec<Policy>) -> PolicyEngine {
        let mut engine = PolicyEngine::new();
        engine.set_policies(PolicyConfig { policies });
        engine
    }

    #[test]
    fn an_amount_cap_bounds_the_fee_only_when_breaking_it_stops_the_spend() {
        let cap = PolicyRule::MaxAmountSats(1_000);
        assert!(!engine(vec![policy(PolicyAction::Allow, vec![cap.clone()])]).bounds_fee());
        assert!(engine(vec![policy(PolicyAction::Deny, vec![cap.clone()])]).bounds_fee());
        assert!(engine(vec![policy(PolicyAction::RequireApproval, vec![cap])]).bounds_fee());
    }

    #[test]
    fn a_fee_cap_bounds_the_fee_only_when_evaluation_reaches_it() {
        let fee = PolicyRule::MaxFeeSats(1_000);
        let listed = PolicyRule::AddressAllowlist(vec!["bc1".into()]);
        assert!(engine(vec![policy(PolicyAction::Allow, vec![fee.clone()])]).bounds_fee());
        assert!(!engine(vec![policy(
            PolicyAction::Allow,
            vec![listed.clone(), fee.clone()],
        )])
        .bounds_fee());
        assert!(engine(vec![policy(PolicyAction::Allow, vec![fee, listed.clone()])]).bounds_fee());
        assert!(!engine(vec![
            policy(PolicyAction::Allow, vec![PolicyRule::MaxAmountSats(1_000)]),
            policy(PolicyAction::Deny, vec![listed]),
        ])
        .bounds_fee());
    }

    #[test]
    fn max_fee_keeps_the_previous_rule_indexes() {
        let allow = postcard::to_allocvec(&PolicyRule::AddressAllowlist(vec!["a".into()])).unwrap();
        assert_eq!(allow[0], 4);
        match postcard::from_bytes::<PolicyRule>(&[4, 1, 1, b'a']).unwrap() {
            PolicyRule::AddressAllowlist(list) => assert_eq!(list, ["a"]),
            other => panic!("expected an allowlist, got {other:?}"),
        }
        let fee = postcard::to_allocvec(&PolicyRule::MaxFeeSats(9)).unwrap();
        assert_eq!(fee[0], 11);
    }
}
