// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::error::{AgentError, Result};
use crate::scope::Operation;
use crate::session::{AgentSession, SessionConfig, SessionMetadata, SessionToken};

const MAX_SESSIONS: usize = 128;

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, AgentSession>>>,
    pubkey: [u8; 32],
}

impl SessionManager {
    pub fn new(pubkey: [u8; 32]) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            pubkey,
        }
    }

    pub fn create_session(
        &self,
        mut config: SessionConfig,
        metadata: SessionMetadata,
    ) -> Result<(SessionToken, String)> {
        config.scope = config.scope.validated()?;
        let token = SessionToken::generate();
        let session = AgentSession::new(&token, self.pubkey, config, metadata);
        let session_id = session.id().to_string();

        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| AgentError::Other("Failed to acquire session lock".into()))?;

        sessions.retain(|_, s| !s.is_expired());

        if sessions.len() >= MAX_SESSIONS {
            return Err(AgentError::Other(format!(
                "Maximum session count ({MAX_SESSIONS}) reached"
            )));
        }

        sessions.insert(session_id.clone(), session);
        Ok((token, session_id))
    }

    pub fn get_session(&self, session_id: &str) -> Result<AgentSession> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| AgentError::Other("Failed to acquire session lock".into()))?;

        sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| AgentError::SessionNotFound(session_id.to_string()))
    }

    pub fn validate_and_get(&self, token: &SessionToken, session_id: &str) -> Result<AgentSession> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| AgentError::Other("Failed to acquire session lock".into()))?;

        let session = sessions
            .get(session_id)
            .ok_or_else(|| AgentError::SessionNotFound(session_id.to_string()))?;

        if !session.validate_token(token) {
            return Err(AgentError::InvalidToken);
        }

        if session.is_expired() {
            return Err(AgentError::SessionExpired);
        }

        Ok(session.clone())
    }

    pub fn record_request(&self, session_id: &str) -> Result<()> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| AgentError::Other("Failed to acquire session lock".into()))?;

        if let Some(session) = sessions.get_mut(session_id) {
            session.record_request();
        }

        Ok(())
    }

    pub fn check_and_record(
        &self,
        token: &SessionToken,
        session_id: &str,
        op: &Operation,
    ) -> Result<crate::session::SessionInfo> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| AgentError::Other("Failed to acquire session lock".into()))?;

        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| AgentError::SessionNotFound(session_id.to_string()))?;

        if !session.validate_token(token) {
            return Err(AgentError::InvalidToken);
        }

        session.check_and_record_operation(op)?;
        Ok(session.info())
    }

    /// Validate the token, check `op` and then `check`, and record the
    /// request, all under one lock, so concurrent calls cannot all pass the
    /// rate limit before any is recorded. Nothing is recorded unless both
    /// checks pass. Errors from `check` come back as the inner result.
    pub fn check_and_record_with<T, E>(
        &self,
        token: &SessionToken,
        session_id: &str,
        op: &Operation,
        check: impl FnOnce(&AgentSession) -> std::result::Result<T, E>,
    ) -> Result<std::result::Result<T, E>> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| AgentError::Other("Failed to acquire session lock".into()))?;

        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| AgentError::SessionNotFound(session_id.to_string()))?;

        if !session.validate_token(token) {
            return Err(AgentError::InvalidToken);
        }

        session.check_operation(op)?;
        let checked = check(session);
        if checked.is_ok() {
            session.record_request();
        }
        Ok(checked)
    }

    pub fn revoke_session(&self, session_id: &str) -> Result<bool> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| AgentError::Other("Failed to acquire session lock".into()))?;

        Ok(sessions.remove(session_id).is_some())
    }

    pub fn cleanup_expired(&self) -> Result<usize> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| AgentError::Other("Failed to acquire session lock".into()))?;

        let before = sessions.len();
        sessions.retain(|_, s| !s.is_expired());
        Ok(before - sessions.len())
    }

    pub fn list_sessions(&self) -> Result<Vec<crate::session::SessionInfo>> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| AgentError::Other("Failed to acquire session lock".into()))?;

        Ok(sessions.values().map(|s| s.info()).collect())
    }

    pub fn active_session_count(&self) -> Result<usize> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| AgentError::Other("Failed to acquire session lock".into()))?;

        Ok(sessions.values().filter(|s| !s.is_expired()).count())
    }
}

impl Clone for SessionManager {
    fn clone(&self) -> Self {
        Self {
            sessions: Arc::clone(&self.sessions),
            pubkey: self.pubkey,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::SessionScope;

    #[test]
    fn test_create_and_get_session() {
        let manager = SessionManager::new([0u8; 32]);
        let config = SessionConfig::new(SessionScope::nostr_only());
        let (token, session_id) = manager
            .create_session(config, SessionMetadata::default())
            .unwrap();

        let session = manager.validate_and_get(&token, &session_id).unwrap();
        assert!(!session.is_expired());
    }

    #[test]
    fn test_invalid_token_rejected() {
        let manager = SessionManager::new([0u8; 32]);
        let config = SessionConfig::new(SessionScope::nostr_only());
        let (_, session_id) = manager
            .create_session(config, SessionMetadata::default())
            .unwrap();

        let wrong_token = SessionToken::generate();
        let result = manager.validate_and_get(&wrong_token, &session_id);
        assert!(matches!(result, Err(AgentError::InvalidToken)));
    }

    #[test]
    fn concurrent_calls_cannot_pass_the_rate_limit_together() {
        use crate::rate_limit::RateLimitConfig;
        let manager = Arc::new(SessionManager::new([0u8; 32]));
        let config = SessionConfig::new(SessionScope::nostr_only())
            .with_rate_limit(RateLimitConfig::new(5, 100, 1000));
        let (token, session_id) = manager
            .create_session(config, SessionMetadata::default())
            .unwrap();
        let start = Arc::new(std::sync::Barrier::new(32));
        let passed: usize = (0..32)
            .map(|_| {
                let (manager, token, id, start) = (
                    manager.clone(),
                    token.clone(),
                    session_id.clone(),
                    start.clone(),
                );
                std::thread::spawn(move || {
                    start.wait();
                    manager
                        .check_and_record_with(&token, &id, &Operation::SignNostrEvent, |_| {
                            std::thread::yield_now();
                            Ok::<_, ()>(())
                        })
                        .is_ok()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap() as usize)
            .sum();
        assert_eq!(passed, 5);
    }

    #[test]
    fn a_refused_check_records_nothing() {
        use crate::rate_limit::RateLimitConfig;
        let manager = SessionManager::new([0u8; 32]);
        let config = SessionConfig::new(SessionScope::nostr_only().with_event_kinds([1]))
            .with_rate_limit(RateLimitConfig::new(1, 100, 1000));
        let (token, id) = manager
            .create_session(config, SessionMetadata::default())
            .unwrap();
        let op = Operation::SignNostrEvent;
        for _ in 0..3 {
            let refused =
                manager.check_and_record_with(&token, &id, &op, |s| s.check_event_kind(4));
            assert!(matches!(
                refused,
                Ok(Err(AgentError::EventKindNotAllowed(4)))
            ));
        }
        assert!(matches!(
            manager.check_and_record_with(&token, &id, &op, |_| Ok::<_, ()>(())),
            Ok(Ok(()))
        ));
        assert!(matches!(
            manager.check_and_record_with(&token, &id, &op, |_| Ok::<_, ()>(())),
            Err(AgentError::RateLimitExceeded(_))
        ));
        assert!(matches!(
            manager.check_and_record_with(&SessionToken::generate(), &id, &op, |_| Ok::<_, ()>(())),
            Err(AgentError::InvalidToken)
        ));
    }

    #[test]
    fn test_revoke_session() {
        let manager = SessionManager::new([0u8; 32]);
        let config = SessionConfig::new(SessionScope::nostr_only());
        let (_, session_id) = manager
            .create_session(config, SessionMetadata::default())
            .unwrap();

        assert!(manager.revoke_session(&session_id).unwrap());
        assert!(!manager.revoke_session(&session_id).unwrap());
    }

    #[test]
    fn test_list_sessions() {
        let manager = SessionManager::new([0u8; 32]);

        for _ in 0..3 {
            let config = SessionConfig::new(SessionScope::nostr_only());
            manager
                .create_session(config, SessionMetadata::default())
                .unwrap();
        }

        let sessions = manager.list_sessions().unwrap();
        assert_eq!(sessions.len(), 3);
    }
}
