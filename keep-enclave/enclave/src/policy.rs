// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use crate::rate_limit::{RateLimiter, Window};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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
    /// What a PSBT takes out of the wallet, fee included, at most this. A raw
    /// `Sign` message or a FROST share fails it, since the enclave cannot read
    /// what they spend, and the address rules fail them the same way. A
    /// `MaxFeeSats` anywhere in the policy refuses them outright, and
    /// `AllowedEventKinds` fails every request.
    MaxAmountSats(u64),
    /// Sign or SignPsbt requests signed and FROST shares made by the key, this
    /// many a minute on average with bursts of up to this many, a PSBT counting
    /// once however many inputs it signs. A full burst followed by the minute's
    /// refill can come to nearly twice this within one minute. Every such request
    /// counts, including one a policy let through without reaching this rule. The
    /// enclave keeps no count across restarts, so it starts with none left when a
    /// policy is loaded and refills from there: the first signature waits a
    /// minute divided by the maximum. The hour and day rules work the same way.
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
    FeeUnknown,
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
            Self::FeeUnknown => write!(f, "fee cannot be read from the request"),
        }
    }
}

pub struct SigningContext<'a> {
    /// The signing key's public key, which rate limits count against, so a
    /// secret imported under several names shares its limits.
    pub pubkey: [u8; 32],
    pub contents: Contents<'a>,
    pub timestamp: u64,
}

/// What the enclave itself read from the request being judged. Nothing the
/// host says about a request counts, since the host is not trusted.
#[derive(Debug, Clone, Copy)]
pub enum Contents<'a> {
    /// A raw `Sign` message or a FROST share. The enclave cannot tell what it
    /// spends or which event it signs, so a rule on either fails it, and the
    /// policy's action decides what that means.
    Unread,
    /// A PSBT the enclave analyzed: what leaves the wallet, the fee, and one
    /// output it pays, or none when only the fee leaves.
    Spend {
        amount_sats: u64,
        fee_sats: u64,
        destination: Option<&'a str>,
    },
}

pub struct PolicyEngine {
    policies: Vec<Policy>,
    /// Whether any policy holds a `MaxFeeSats`, nested or not.
    caps_fee: bool,
    rate_limiter: RateLimiter,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            caps_fee: false,
            rate_limiter: RateLimiter::new(),
        }
    }

    pub fn set_policies(&mut self, config: PolicyConfig) {
        self.caps_fee = holds_fee_cap(&config.policies);
        self.policies = config.policies;
        // What was signed under a looser policy the host loaded first is not
        // carried over, so the new rules start with nothing left, as at launch.
        self.rate_limiter.drain();
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
        // A fee cap holds under any action and wherever it sits, and a message
        // the enclave cannot read may pay any fee, so any cap refuses it.
        if self.caps_fee && matches!(ctx.contents, Contents::Unread) {
            return PolicyDecision::Deny(PolicyDenyReason::FeeUnknown);
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
            PolicyRule::MaxAmountSats(max) => match ctx.contents {
                Contents::Spend { amount_sats, .. } => amount_sats <= *max,
                Contents::Unread => false,
            },

            PolicyRule::MaxFeeSats(max) => match ctx.contents {
                Contents::Spend { fee_sats, .. } if fee_sats > *max => {
                    return Err(PolicyDenyReason::FeeExceeded)
                }
                Contents::Spend { .. } => true,
                // `evaluate` refuses an unread request before any rule when a
                // fee cap is loaded, so this only backs that up.
                Contents::Unread => return Err(PolicyDenyReason::FeeUnknown),
            },

            PolicyRule::MaxPerMinute(max) => {
                self.rate_limiter.allows(Window::Minute, &ctx.pubkey, *max)
            }

            PolicyRule::MaxPerHour(max) => {
                self.rate_limiter.allows(Window::Hour, &ctx.pubkey, *max)
            }

            PolicyRule::MaxPerDay(max) => {
                self.rate_limiter.allows(Window::Day, &ctx.pubkey, *max)
            }

            PolicyRule::AddressAllowlist(allowed) => match ctx.contents {
                Contents::Spend {
                    destination: Some(d),
                    ..
                } => allowed.iter().any(|a| a == d),
                Contents::Spend {
                    destination: None, ..
                } => true,
                Contents::Unread => false,
            },

            PolicyRule::AddressBlocklist(blocked) => match ctx.contents {
                Contents::Spend {
                    destination: Some(d),
                    ..
                } => !blocked.iter().any(|b| b == d),
                Contents::Spend {
                    destination: None, ..
                } => true,
                Contents::Unread => false,
            },

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

            // The enclave reads no event kind from any request, so nothing can
            // pass this rule, a PSBT included: passing would let an `Or` sign a
            // spend past the caps beside it.
            PolicyRule::AllowedEventKinds(_) => false,

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

    /// Count a signature made by `pubkey` against every rate rule in every
    /// policy, nested ones included as deep as evaluation goes.
    pub fn record_operation(&mut self, pubkey: &[u8; 32]) {
        let mut limits = BTreeSet::new();
        for policy in &self.policies {
            for rule in &policy.rules {
                collect_rate_limits(rule, MAX_POLICY_DEPTH, &mut limits);
            }
        }
        self.rate_limiter.record(pubkey, limits);
    }

    #[cfg(test)]
    pub fn advance_clock(&mut self, by: std::time::Duration) {
        self.rate_limiter.advance(by);
    }
}

/// Whether any rule in `policies` is a `MaxFeeSats`, at any depth. It walks
/// the rules without recursion, so no nesting can overflow the stack.
fn holds_fee_cap(policies: &[Policy]) -> bool {
    let mut rules: Vec<&PolicyRule> = policies.iter().flat_map(|p| &p.rules).collect();
    while let Some(rule) = rules.pop() {
        match rule {
            PolicyRule::MaxFeeSats(_) => return true,
            PolicyRule::And(nested) | PolicyRule::Or(nested) => rules.extend(nested),
            _ => {}
        }
    }
    false
}

fn collect_rate_limits(rule: &PolicyRule, depth: usize, limits: &mut BTreeSet<(Window, u32)>) {
    if depth == 0 {
        return;
    }
    match rule {
        PolicyRule::MaxPerMinute(max) => {
            limits.insert((Window::Minute, *max));
        }
        PolicyRule::MaxPerHour(max) => {
            limits.insert((Window::Hour, *max));
        }
        PolicyRule::MaxPerDay(max) => {
            limits.insert((Window::Day, *max));
        }
        PolicyRule::And(rules) | PolicyRule::Or(rules) => {
            for rule in rules {
                collect_rate_limits(rule, depth - 1, limits);
            }
        }
        PolicyRule::MaxAmountSats(_)
        | PolicyRule::MaxFeeSats(_)
        | PolicyRule::AddressAllowlist(_)
        | PolicyRule::AddressBlocklist(_)
        | PolicyRule::AllowedHours { .. }
        | PolicyRule::BlockWeekends
        | PolicyRule::AllowedEventKinds(_) => {}
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
        PolicyRule::MaxAmountSats(_) | PolicyRule::AllowedEventKinds(_) => FeeEffect {
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

    fn spend(amount_sats: u64, destination: Option<&str>) -> SigningContext<'_> {
        SigningContext {
            pubkey: [7u8; 32],
            contents: Contents::Spend {
                amount_sats,
                fee_sats: 100,
                destination,
            },
            timestamp: now(),
        }
    }

    fn unread() -> SigningContext<'static> {
        SigningContext {
            pubkey: [7u8; 32],
            contents: Contents::Unread,
            timestamp: now(),
        }
    }

    fn denies(engine: &mut PolicyEngine, ctx: &SigningContext<'_>) -> bool {
        matches!(engine.evaluate(ctx), PolicyDecision::Deny(_))
    }

    #[test]
    fn an_empty_policy_denies() {
        let mut engine = PolicyEngine::new();
        assert_eq!(
            engine.evaluate(&spend(1, None)),
            PolicyDecision::Deny(PolicyDenyReason::ExplicitDeny)
        );
    }

    #[test]
    fn test_max_amount() {
        let mut engine = engine(vec![policy(
            PolicyAction::Deny,
            vec![PolicyRule::MaxAmountSats(1000)],
        )]);
        assert_eq!(engine.evaluate(&spend(500, None)), PolicyDecision::Allow);
        assert!(denies(&mut engine, &spend(2000, None)));
    }

    #[test]
    fn test_address_allowlist() {
        let mut engine = engine(vec![policy(
            PolicyAction::Deny,
            vec![PolicyRule::AddressAllowlist(vec!["bc1allowed".into()])],
        )]);
        assert_eq!(
            engine.evaluate(&spend(1, Some("bc1allowed"))),
            PolicyDecision::Allow
        );
        assert!(denies(&mut engine, &spend(1, Some("bc1blocked"))));
    }

    #[test]
    fn an_unread_request_fails_every_rule_on_what_it_spends_or_signs() {
        for rule in [
            PolicyRule::MaxAmountSats(u64::MAX),
            PolicyRule::AddressAllowlist(vec!["bc1allowed".into()]),
            PolicyRule::AddressBlocklist(vec!["bc1blocked".into()]),
            PolicyRule::AllowedEventKinds(vec![1]),
        ] {
            let mut deny = engine(vec![policy(PolicyAction::Deny, vec![rule.clone()])]);
            assert_eq!(
                deny.evaluate(&unread()),
                PolicyDecision::Deny(PolicyDenyReason::ExplicitDeny),
                "{rule:?}"
            );
            let mut approve = engine(vec![policy(
                PolicyAction::RequireApproval,
                vec![rule.clone()],
            )]);
            assert_eq!(approve.evaluate(&unread()), PolicyDecision::RequireApproval);
            let mut skip = engine(vec![
                policy(PolicyAction::Allow, vec![rule.clone()]),
                policy(PolicyAction::Deny, vec![PolicyRule::BlockWeekends]),
            ]);
            assert_eq!(skip.evaluate(&unread()), PolicyDecision::Allow);
            let mut next = engine(vec![
                policy(PolicyAction::Allow, vec![rule]),
                policy(PolicyAction::Deny, vec![PolicyRule::MaxPerMinute(0)]),
            ]);
            assert!(denies(&mut next, &unread()));
        }
    }

    #[test]
    fn an_unread_request_is_refused_by_a_fee_cap_under_any_action() {
        for action in [
            PolicyAction::Allow,
            PolicyAction::Deny,
            PolicyAction::RequireApproval,
        ] {
            let mut engine = engine(vec![policy(action, vec![PolicyRule::MaxFeeSats(u64::MAX)])]);
            assert_eq!(
                engine.evaluate(&unread()),
                PolicyDecision::Deny(PolicyDenyReason::FeeUnknown)
            );
        }
    }

    #[test]
    fn an_unread_request_passes_a_branch_that_needs_nothing_read() {
        let mut engine = engine(vec![policy(
            PolicyAction::Deny,
            vec![PolicyRule::Or(vec![
                PolicyRule::MaxAmountSats(u64::MAX),
                PolicyRule::BlockWeekends,
            ])],
        )]);
        // now() is a Tuesday.
        assert_eq!(engine.evaluate(&unread()), PolicyDecision::Allow);
    }

    #[test]
    fn a_spend_paying_nothing_but_the_fee_passes_the_address_rules() {
        let mut engine = engine(vec![policy(
            PolicyAction::Deny,
            vec![
                PolicyRule::AddressAllowlist(vec!["bc1allowed".into()]),
                PolicyRule::AddressBlocklist(vec!["bc1blocked".into()]),
            ],
        )]);
        assert_eq!(engine.evaluate(&spend(1, None)), PolicyDecision::Allow);
        assert!(denies(&mut engine, &spend(1, Some("bc1blocked"))));
    }

    #[test]
    fn a_fee_cap_refuses_an_unread_request_wherever_it_sits() {
        let unreached = [
            policy(
                PolicyAction::Allow,
                vec![
                    PolicyRule::MaxAmountSats(1),
                    PolicyRule::MaxFeeSats(u64::MAX),
                ],
            ),
            policy(
                PolicyAction::Deny,
                vec![PolicyRule::Or(vec![
                    PolicyRule::BlockWeekends,
                    PolicyRule::MaxFeeSats(u64::MAX),
                ])],
            ),
            policy(
                PolicyAction::Deny,
                vec![(0..MAX_POLICY_DEPTH * 2)
                    .fold(PolicyRule::MaxFeeSats(u64::MAX), |rule, _| {
                        PolicyRule::Or(vec![PolicyRule::BlockWeekends, rule])
                    })],
            ),
        ];
        for p in unreached {
            let mut engine = engine(vec![p]);
            assert_eq!(
                engine.evaluate(&unread()),
                PolicyDecision::Deny(PolicyDenyReason::FeeUnknown)
            );
        }
    }

    #[test]
    fn the_event_kind_rule_fails_a_spend_too() {
        let mut alone = engine(vec![policy(
            PolicyAction::Deny,
            vec![PolicyRule::AllowedEventKinds(vec![1])],
        )]);
        assert!(denies(&mut alone, &spend(1, Some("bc1"))));
        let mut either = engine(vec![policy(
            PolicyAction::Deny,
            vec![PolicyRule::Or(vec![
                PolicyRule::AllowedEventKinds(vec![1]),
                PolicyRule::MaxAmountSats(100),
            ])],
        )]);
        assert_eq!(
            either.evaluate(&spend(50, Some("bc1"))),
            PolicyDecision::Allow
        );
        assert!(denies(&mut either, &spend(1_000, Some("bc1"))));
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
    fn a_fee_cap_beside_the_event_kind_rule_bounds_the_fee() {
        let kinds = PolicyRule::AllowedEventKinds(vec![1]);
        let fee = PolicyRule::MaxFeeSats(1_000);
        assert!(engine(vec![policy(
            PolicyAction::Deny,
            vec![PolicyRule::Or(vec![kinds.clone(), fee])],
        )])
        .bounds_fee());
        assert!(!engine(vec![policy(PolicyAction::Allow, vec![kinds])]).bounds_fee());
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
