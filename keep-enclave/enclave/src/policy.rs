use crate::rate_limit::RateLimiter;
use serde::{Deserialize, Serialize};

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
    RateLimitExceeded,
    AddressNotAllowed,
    AddressBlocked,
    TimeRestriction,
    EventKindNotAllowed,
    ExplicitDeny,
}

impl std::fmt::Display for PolicyDenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AmountExceeded => write!(f, "amount exceeds limit"),
            Self::RateLimitExceeded => write!(f, "rate limit exceeded"),
            Self::AddressNotAllowed => write!(f, "address not in allowlist"),
            Self::AddressBlocked => write!(f, "address is blocked"),
            Self::TimeRestriction => write!(f, "time restriction"),
            Self::EventKindNotAllowed => write!(f, "event kind not allowed"),
            Self::ExplicitDeny => write!(f, "policy denies request"),
        }
    }
}

pub struct SigningContext<'a> {
    pub key_id: &'a str,
    pub amount_sats: Option<u64>,
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
    }

    pub fn evaluate(&mut self, ctx: &SigningContext<'_>) -> PolicyDecision {
        for policy in &self.policies {
            let decision = self.check_policy(policy, ctx);
            if decision != PolicyDecision::Allow {
                return decision;
            }
        }
        PolicyDecision::Allow
    }

    fn check_policy(&mut self, policy: &Policy, ctx: &SigningContext<'_>) -> PolicyDecision {
        for rule in &policy.rules {
            if !self.check_rule(rule, ctx) {
                return match policy.action {
                    PolicyAction::Deny => PolicyDecision::Deny(PolicyDenyReason::ExplicitDeny),
                    PolicyAction::RequireApproval => PolicyDecision::RequireApproval,
                    PolicyAction::Allow => PolicyDecision::Allow,
                };
            }
        }
        PolicyDecision::Allow
    }

    fn check_rule(&mut self, rule: &PolicyRule, ctx: &SigningContext<'_>) -> bool {
        match rule {
            PolicyRule::MaxAmountSats(max) => {
                ctx.amount_sats.map(|a| a <= *max).unwrap_or(true)
            }

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
                let hour = ((ctx.timestamp / 3600) % 24) as u8;
                hour >= *start && hour < *end
            }

            PolicyRule::BlockWeekends => {
                let day = (ctx.timestamp / 86400 + 4) % 7;
                day < 5
            }

            PolicyRule::AllowedEventKinds(kinds) => {
                ctx.event_kind
                    .map(|k| kinds.contains(&k))
                    .unwrap_or(true)
            }

            PolicyRule::And(rules) => {
                rules.iter().all(|r| self.check_rule(r, ctx))
            }

            PolicyRule::Or(rules) => {
                rules.iter().any(|r| self.check_rule(r, ctx))
            }
        }
    }

    pub fn record_operation(&mut self, key_id: &str) {
        self.rate_limiter.record(key_id);
    }
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
            destination: None,
            event_kind: None,
            timestamp: now(),
        };
        assert_eq!(engine.evaluate(&ctx_ok), PolicyDecision::Allow);

        let ctx_fail = SigningContext {
            key_id: "test",
            amount_sats: Some(2000),
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
            destination: Some("bc1allowed"),
            event_kind: None,
            timestamp: now(),
        };
        assert_eq!(engine.evaluate(&ctx_ok), PolicyDecision::Allow);

        let ctx_fail = SigningContext {
            key_id: "test",
            amount_sats: None,
            destination: Some("bc1blocked"),
            event_kind: None,
            timestamp: now(),
        };
        assert!(matches!(
            engine.evaluate(&ctx_fail),
            PolicyDecision::Deny(_)
        ));
    }
}
