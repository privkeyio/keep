// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Credentials for AI agents served by the agent gateway.
//!
//! An agent presents a bearer token; the vault keeps only its hash, the local
//! user the token is bound to, an expiry and the credential's grant. The grant
//! is opaque here: the gateway serializes it and validates it again whenever it
//! loads a credential.

use std::fmt::Write;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::blake2b_256;
use crate::entropy;
use crate::error::{KeepError, Result};

/// Prefix of every agent token.
pub const TOKEN_PREFIX: &str = "keep_agt_";

/// The most credentials a vault holds, revoked ones included.
pub const MAX_AGENT_CREDENTIALS: usize = 64;

/// The longest a credential may live.
pub const MAX_CREDENTIAL_TTL_SECS: u64 = 365 * 24 * 60 * 60;

/// The uid the kernel reports for a peer outside the reader's user namespace.
/// No credential is bound to it, nor to root.
pub const OVERFLOW_UID: u32 = 65_534;

const MAX_NAME_LEN: usize = 64;
const TOKEN_HASH_DOMAIN: &[u8] = b"keep-agent-token-v1";

/// A credential an agent authenticates with. Stored encrypted under the vault
/// data key; the token itself is never stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCredential {
    /// Random identifier, shown to the owner and recorded in the audit log.
    pub id: [u8; 16],
    /// The owner's label for the agent.
    pub name: String,
    /// Domain-separated hash of the token. The token carries 256 random bits, so
    /// a keyed hash would add nothing, and one keyed by the data key would void
    /// every token when the data key rotates.
    token_hash: [u8; 32],
    /// The local user the token is bound to; the gateway refuses it from any
    /// other peer uid.
    pub uid: u32,
    /// Unix time the credential was issued.
    pub created_at: u64,
    /// Unix time from which the credential is refused.
    pub expires_at: u64,
    /// Revoked for good; kept so the owner can see it until deleted.
    pub revoked: bool,
    /// Refused until unfrozen.
    pub frozen: bool,
    /// The gateway's serialized grant.
    pub grant: Vec<u8>,
}

impl AgentCredential {
    /// A new credential and the token for it, shown to the owner once.
    pub fn issue(
        name: &str,
        uid: u32,
        grant: Vec<u8>,
        now: u64,
        ttl_secs: u64,
    ) -> Result<(Self, Zeroizing<String>)> {
        if name.is_empty() || name.len() > MAX_NAME_LEN || name.chars().any(char::is_control) {
            return Err(KeepError::invalid_input(format!(
                "an agent name is 1 to {MAX_NAME_LEN} bytes without control characters"
            )));
        }
        if uid == 0 || uid == OVERFLOW_UID {
            return Err(KeepError::invalid_input(format!(
                "an agent credential cannot be bound to uid {uid}"
            )));
        }
        if ttl_secs == 0 || ttl_secs > MAX_CREDENTIAL_TTL_SECS {
            return Err(KeepError::invalid_input(format!(
                "an agent credential lives 1 to {MAX_CREDENTIAL_TTL_SECS} seconds"
            )));
        }
        let secret: Zeroizing<[u8; 32]> = Zeroizing::new(entropy::try_random_bytes()?);
        // Written into one buffer so no unwiped copy of the token is left behind.
        let mut token = Zeroizing::new(String::with_capacity(TOKEN_PREFIX.len() + 64));
        token.push_str(TOKEN_PREFIX);
        for byte in secret.iter() {
            write!(token, "{byte:02x}").map_err(|e| KeepError::Other(e.to_string()))?;
        }
        let credential = Self {
            id: entropy::try_random_bytes()?,
            name: name.to_string(),
            token_hash: token_hash(&token),
            uid,
            created_at: now,
            expires_at: now.saturating_add(ttl_secs),
            revoked: false,
            frozen: false,
            grant,
        };
        Ok((credential, token))
    }

    /// Whether `token` is this credential's, compared in constant time.
    pub fn matches(&self, token: &str) -> bool {
        bool::from(self.token_hash.ct_eq(&token_hash(token)))
    }

    /// Refuses the credential unless it is live, unfrozen and presented by its
    /// own uid. `all_frozen` is the vault-wide agent freeze.
    pub fn check_usable(&self, peer_uid: u32, now: u64, all_frozen: bool) -> Result<()> {
        let refuse = |why: &str| {
            Err(KeepError::permission_denied(format!(
                "agent credential {why}"
            )))
        };
        if self.revoked {
            return refuse("is revoked");
        }
        if now >= self.expires_at {
            return refuse("has expired");
        }
        if self.frozen || all_frozen {
            return refuse("is frozen");
        }
        if peer_uid != self.uid {
            return refuse("is bound to another user");
        }
        Ok(())
    }

    /// The credential id as hex.
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }
}

fn token_hash(token: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(TOKEN_HASH_DOMAIN.len() + token.len());
    input.extend_from_slice(TOKEN_HASH_DOMAIN);
    input.extend_from_slice(token.as_bytes());
    let hash = blake2b_256(&input);
    zeroize::Zeroize::zeroize(&mut input);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 24 * 60 * 60;

    fn issue() -> (AgentCredential, Zeroizing<String>) {
        AgentCredential::issue("claude", 1000, b"grant".to_vec(), NOW, DAY).unwrap()
    }

    #[test]
    fn a_token_matches_only_its_own_credential() {
        let (a, token_a) = issue();
        let (b, token_b) = issue();
        assert!(token_a.starts_with(TOKEN_PREFIX));
        assert_eq!(token_a.len(), TOKEN_PREFIX.len() + 64);
        assert_ne!(a.id, b.id);
        assert!(a.matches(&token_a));
        assert!(!a.matches(&token_b));
        assert!(!b.matches(&token_a));
        assert!(!a.matches(""));
        let mut altered = token_a.to_string();
        let last = altered.pop().unwrap();
        altered.push(if last == '0' { '1' } else { '0' });
        assert!(!a.matches(&altered));
    }

    #[test]
    fn the_token_is_not_stored() {
        let (credential, token) = issue();
        let stored = serde_json::to_string(&credential).unwrap();
        assert!(!stored.contains(&token[TOKEN_PREFIX.len()..]));
    }

    #[test]
    fn issuing_refuses_bad_names_uids_and_lifetimes() {
        let refused = |name: &str, uid: u32, ttl: u64| {
            AgentCredential::issue(name, uid, Vec::new(), NOW, ttl).unwrap_err()
        };
        assert!(refused("", 1000, DAY).to_string().contains("agent name"));
        assert!(refused(&"a".repeat(65), 1000, DAY)
            .to_string()
            .contains("agent name"));
        assert!(refused("a\nb", 1000, DAY)
            .to_string()
            .contains("agent name"));
        assert!(refused("ok", 0, DAY).to_string().contains("uid 0"));
        assert!(refused("ok", OVERFLOW_UID, DAY)
            .to_string()
            .contains("uid 65534"));
        assert!(refused("ok", 1000, 0).to_string().contains("seconds"));
        assert!(refused("ok", 1000, MAX_CREDENTIAL_TTL_SECS + 1)
            .to_string()
            .contains("seconds"));
        let (credential, _) = AgentCredential::issue(
            &"a".repeat(64),
            1000,
            Vec::new(),
            NOW,
            MAX_CREDENTIAL_TTL_SECS,
        )
        .unwrap();
        assert_eq!(credential.expires_at, NOW + MAX_CREDENTIAL_TTL_SECS);
    }

    #[test]
    fn only_a_live_unfrozen_credential_from_its_uid_is_usable() {
        let (credential, _) = issue();
        assert!(credential.check_usable(1000, NOW, false).is_ok());
        assert!(credential.check_usable(1000, NOW + DAY - 1, false).is_ok());
        let refusal = |c: &AgentCredential, uid, now, all| {
            c.check_usable(uid, now, all).unwrap_err().to_string()
        };
        assert!(refusal(&credential, 1000, NOW + DAY, false).contains("expired"));
        assert!(refusal(&credential, 1001, NOW, false).contains("another user"));
        assert!(refusal(&credential, 1000, NOW, true).contains("frozen"));
        let mut frozen = credential.clone();
        frozen.frozen = true;
        assert!(refusal(&frozen, 1000, NOW, false).contains("frozen"));
        let mut revoked = credential;
        revoked.revoked = true;
        assert!(refusal(&revoked, 1000, NOW, false).contains("revoked"));
    }
}
