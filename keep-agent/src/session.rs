#![forbid(unsafe_code)]

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{AgentError, Result};
use crate::rate_limit::{RateLimitConfig, RateLimitStatus, RateLimiter};
use crate::scope::{Operation, SessionScope};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub scope: SessionScope,
    pub rate_limit: RateLimitConfig,
    pub duration_hours: u32,
    pub policy: Option<String>,
}

impl SessionConfig {
    pub fn new(scope: SessionScope) -> Self {
        Self {
            scope,
            rate_limit: RateLimitConfig::default(),
            duration_hours: 24,
            policy: None,
        }
    }

    pub fn with_rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit = config;
        self
    }

    pub fn with_duration_hours(mut self, hours: u32) -> Self {
        self.duration_hours = hours.min(168);
        self
    }

    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policy = Some(policy.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SessionToken(String);

impl SessionToken {
    pub fn generate() -> Self {
        let bytes: [u8; 32] = rand::rng().random();
        Self(format!("keep_sess_{}", hex::encode(bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for SessionToken {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for SessionToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub agent_name: Option<String>,
    pub agent_framework: Option<String>,
    pub agent_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub scope: SessionScope,
    pub rate_limit: RateLimitConfig,
    pub requests_today: u32,
    pub requests_remaining: u32,
}

#[derive(Clone)]
pub struct AgentSession {
    id: String,
    token_hash: [u8; 32],
    pubkey: [u8; 32],
    scope: SessionScope,
    rate_limiter: RateLimiter,
    policy: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    metadata: SessionMetadata,
}

impl AgentSession {
    pub fn new(
        token: &SessionToken,
        pubkey: [u8; 32],
        config: SessionConfig,
        metadata: SessionMetadata,
    ) -> Self {
        let now = Utc::now();
        let expires = now + Duration::hours(config.duration_hours as i64);

        let id = token
            .as_str()
            .strip_prefix("keep_sess_")
            .and_then(|s| s.get(..8))
            .map(|s| format!("sess_{}", s))
            .unwrap_or_else(|| {
                let hash = keep_core::crypto::blake2b_256(token.as_str().as_bytes());
                format!("sess_{}", hex::encode(&hash[..4]))
            });
        let token_hash = keep_core::crypto::blake2b_256(token.as_str().as_bytes());

        Self {
            id,
            token_hash,
            pubkey,
            scope: config.scope,
            rate_limiter: RateLimiter::new(config.rate_limit),
            policy: config.policy,
            created_at: now,
            expires_at: expires,
            metadata,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn pubkey(&self) -> &[u8; 32] {
        &self.pubkey
    }

    pub fn scope(&self) -> &SessionScope {
        &self.scope
    }

    pub fn policy(&self) -> Option<&str> {
        self.policy.as_deref()
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn metadata(&self) -> &SessionMetadata {
        &self.metadata
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    pub fn validate_token(&self, token: &SessionToken) -> bool {
        let hash = keep_core::crypto::blake2b_256(token.as_str().as_bytes());
        subtle::ConstantTimeEq::ct_eq(&self.token_hash[..], &hash[..]).into()
    }

    pub fn check_operation(&self, op: &Operation) -> Result<()> {
        if self.is_expired() {
            return Err(AgentError::SessionExpired);
        }

        if !self.scope.allows_operation(op) {
            return Err(AgentError::OperationNotAllowed(op.as_str().to_string()));
        }

        match self.rate_limiter.check() {
            RateLimitStatus::Allowed { .. } => Ok(()),
            RateLimitStatus::Exceeded {
                window,
                limit,
                current,
                ..
            } => Err(AgentError::RateLimitExceeded(format!(
                "{} requests in {} (limit: {})",
                current, window, limit
            ))),
        }
    }

    pub fn check_and_record_operation(&mut self, op: &Operation) -> Result<()> {
        if self.is_expired() {
            return Err(AgentError::SessionExpired);
        }

        if !self.scope.allows_operation(op) {
            return Err(AgentError::OperationNotAllowed(op.as_str().to_string()));
        }

        match self.rate_limiter.check_and_record() {
            RateLimitStatus::Allowed { .. } => Ok(()),
            RateLimitStatus::Exceeded {
                window,
                limit,
                current,
                ..
            } => Err(AgentError::RateLimitExceeded(format!(
                "{} requests in {} (limit: {})",
                current, window, limit
            ))),
        }
    }

    pub fn check_event_kind(&self, kind: u16) -> Result<()> {
        if !self.scope.allows_event_kind(kind) {
            return Err(AgentError::EventKindNotAllowed(kind));
        }
        Ok(())
    }

    pub fn check_amount(&self, sats: u64) -> Result<()> {
        if let Some(max) = self.scope.max_amount_sats {
            if sats > max {
                return Err(AgentError::AmountExceeded {
                    requested: sats,
                    limit: max,
                });
            }
        }
        Ok(())
    }

    pub fn check_address(&self, address: &str) -> Result<()> {
        if !self.scope.allows_address(address) {
            return Err(AgentError::AddressNotAllowed(address.to_string()));
        }
        Ok(())
    }

    pub fn record_request(&mut self) {
        self.rate_limiter.record();
    }

    pub fn info(&self) -> SessionInfo {
        SessionInfo {
            session_id: self.id.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            scope: self.scope.clone(),
            rate_limit: self.rate_limiter.config().clone(),
            requests_today: self.rate_limiter.requests_today(),
            requests_remaining: self.rate_limiter.remaining_today(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session() -> AgentSession {
        let token = SessionToken::generate();
        let pubkey = [0u8; 32];
        let config = SessionConfig::new(SessionScope::nostr_only());
        AgentSession::new(&token, pubkey, config, SessionMetadata::default())
    }

    #[test]
    fn test_session_creation() {
        let session = test_session();
        assert!(!session.is_expired());
        assert!(session.id().starts_with("sess_"));
    }

    #[test]
    fn test_token_validation() {
        let token = SessionToken::generate();
        let pubkey = [0u8; 32];
        let config = SessionConfig::new(SessionScope::nostr_only());
        let session = AgentSession::new(&token, pubkey, config, SessionMetadata::default());

        assert!(session.validate_token(&token));

        let wrong_token = SessionToken::generate();
        assert!(!session.validate_token(&wrong_token));
    }

    #[test]
    fn test_operation_checks() {
        let session = test_session();
        assert!(session.check_operation(&Operation::SignNostrEvent).is_ok());
        assert!(session.check_operation(&Operation::SignPsbt).is_err());
    }

    #[test]
    fn test_event_kind_checks() {
        let token = SessionToken::generate();
        let pubkey = [0u8; 32];
        let scope = SessionScope::nostr_only().with_event_kinds([1, 4, 7]);
        let config = SessionConfig::new(scope);
        let session = AgentSession::new(&token, pubkey, config, SessionMetadata::default());

        assert!(session.check_event_kind(1).is_ok());
        assert!(session.check_event_kind(30023).is_err());
    }

    #[test]
    fn test_amount_checks() {
        let token = SessionToken::generate();
        let pubkey = [0u8; 32];
        let scope = SessionScope::bitcoin_only().with_max_amount(100_000);
        let config = SessionConfig::new(scope);
        let session = AgentSession::new(&token, pubkey, config, SessionMetadata::default());

        assert!(session.check_amount(50_000).is_ok());
        assert!(session.check_amount(100_001).is_err());
    }

    #[test]
    fn test_session_info() {
        let session = test_session();
        let info = session.info();
        assert!(info.requests_today == 0);
        assert!(info.requests_remaining > 0);
    }
}
