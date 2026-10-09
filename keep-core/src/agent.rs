// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Credentials for AI agents served by the agent gateway.
//!
//! An agent presents a bearer token; the vault keeps only its hash, the local
//! user the token is bound to, an expiry and the credential's grant. The grant
//! is opaque here: the gateway serializes it and validates it again whenever it
//! loads a credential.

use std::fmt::{self, Write};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::blake2b_256;
use crate::entropy;
use crate::error::{KeepError, Result};

/// Prefix of every agent token.
pub const TOKEN_PREFIX: &str = "keep_agt_";

/// Length of a token: the prefix and 64 lowercase hex digits.
pub const TOKEN_LEN: usize = TOKEN_PREFIX.len() + 64;

/// The most credentials a vault holds, revoked ones included.
pub const MAX_AGENT_CREDENTIALS: usize = 64;

/// The longest a credential may live.
pub const MAX_CREDENTIAL_TTL_SECS: u64 = 365 * 24 * 60 * 60;

/// The largest grant a credential carries.
pub const MAX_GRANT_BYTES: usize = 64 * 1024;

/// The kernel's default uid for a peer outside the reader's user namespace
/// (`/proc/sys/kernel/overflowuid`). No credential is bound to it.
pub const OVERFLOW_UID: u32 = 65_534;

const MAX_NAME_LEN: usize = 64;
const TOKEN_HASH_DOMAIN: &[u8] = b"keep-agent-token-v1";

/// A credential an agent authenticates with. Stored encrypted under the vault
/// data key; the token itself is never stored.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCredential {
    /// Random identifier, shown to the owner and recorded in the audit log.
    pub id: [u8; 16],
    /// The owner's label for the agent: printable ASCII without leading or
    /// trailing spaces.
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

impl fmt::Debug for AgentCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentCredential")
            .field("id", &self.id_hex())
            .field("name", &self.name)
            .field("uid", &self.uid)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .field("frozen", &self.frozen)
            .field("grant_len", &self.grant.len())
            .finish_non_exhaustive()
    }
}

/// Why a presented token was refused. The gateway records it, but answers the
/// agent with one uniform refusal, so a token's state never leaks to whoever
/// holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRefusal {
    /// The token is malformed or matches no credential.
    Unknown,
    /// The credential is revoked.
    Revoked,
    /// The credential has expired.
    Expired,
    /// The credential, or every credential, is frozen.
    Frozen,
    /// The token was presented by a uid other than the one it is bound to.
    WrongUid,
    /// The clock reads earlier than the credential was issued.
    ClockBehind,
}

impl fmt::Display for AgentRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unknown => "unknown token",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Frozen => "frozen",
            Self::WrongUid => "presented by another user",
            Self::ClockBehind => "clock reads before issue",
        })
    }
}

/// A refused token: why, and which credential it matched, if any. The
/// credential is known for every refusal except an unknown token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentRefused {
    /// Why the token was refused.
    pub reason: AgentRefusal,
    /// The credential the token matched.
    pub credential: Option<[u8; 16]>,
}

/// The longest label the gateway gives an agent audit entry: its own fixed
/// text, printable ASCII.
pub const MAX_AUDIT_LABEL: usize = 64;

/// Whether `label` is a gateway audit label: 1 to [`MAX_AUDIT_LABEL`] bytes of
/// printable ASCII.
pub fn valid_audit_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_AUDIT_LABEL
        && label.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}

/// The most bytes of caller-supplied text an agent audit entry keeps.
pub const MAX_AUDIT_TEXT: usize = 256;

/// `text` made safe for an audit entry: cut to [`MAX_AUDIT_TEXT`] bytes at a
/// character boundary, then with control and invisible characters, quotes and
/// backslashes escaped (which can lengthen it, to at most a few times the
/// cap), so it cannot run on, break a line or pose as other text.
pub fn audit_text(text: &str) -> String {
    cap_text(text).escape_debug().to_string()
}

/// `text` cut to [`MAX_AUDIT_TEXT`] bytes at a character boundary.
pub fn cap_text(text: &str) -> &str {
    let mut end = text.len().min(MAX_AUDIT_TEXT);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Whether a credential may be bound to `uid`: never root, the overflow uid or
/// `(uid_t)-1`.
pub fn bindable_uid(uid: u32) -> bool {
    uid != 0 && uid != OVERFLOW_UID && uid != u32::MAX
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
        if name.is_empty()
            || name.len() > MAX_NAME_LEN
            || name.trim() != name
            || !name.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
        {
            return Err(KeepError::invalid_input(format!(
                "an agent name is 1 to {MAX_NAME_LEN} printable ASCII characters"
            )));
        }
        if !bindable_uid(uid) {
            return Err(KeepError::invalid_input(format!(
                "an agent credential cannot be bound to uid {uid}"
            )));
        }
        if ttl_secs == 0 || ttl_secs > MAX_CREDENTIAL_TTL_SECS {
            return Err(KeepError::invalid_input(format!(
                "an agent credential lives 1 to {MAX_CREDENTIAL_TTL_SECS} seconds"
            )));
        }
        if grant.len() > MAX_GRANT_BYTES {
            return Err(KeepError::invalid_input(format!(
                "an agent grant is at most {MAX_GRANT_BYTES} bytes"
            )));
        }
        let secret: Zeroizing<[u8; 32]> = Zeroizing::new(entropy::try_random_bytes()?);
        // Written into one buffer so no unwiped copy of the token is left behind.
        let mut token = Zeroizing::new(String::with_capacity(TOKEN_LEN));
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

    /// Whether this credential's token hashes to `hash`, compared in constant
    /// time.
    pub fn matches_hash(&self, hash: &[u8; 32]) -> bool {
        bool::from(self.token_hash.ct_eq(hash))
    }

    /// Refuses the credential unless it is live, unfrozen and presented by its
    /// own uid at a time not before it was issued. `all_frozen` is the
    /// vault-wide agent freeze.
    pub fn check_usable(
        &self,
        peer_uid: u32,
        now: u64,
        all_frozen: bool,
    ) -> std::result::Result<(), AgentRefusal> {
        if self.revoked {
            return Err(AgentRefusal::Revoked);
        }
        if now < self.created_at {
            return Err(AgentRefusal::ClockBehind);
        }
        if now >= self.expires_at {
            return Err(AgentRefusal::Expired);
        }
        if self.frozen || all_frozen {
            return Err(AgentRefusal::Frozen);
        }
        if peer_uid != self.uid || !bindable_uid(peer_uid) {
            return Err(AgentRefusal::WrongUid);
        }
        Ok(())
    }

    /// Refuses `self` as the stored replacement for `existing` unless it only
    /// revokes, freezes or unfreezes it, or shortens its life: its identity,
    /// token, uid and grant never change, and a revocation is never undone.
    pub(crate) fn check_replaces(&self, existing: &Self) -> Result<()> {
        let unchanged = self.id == existing.id
            && self.name == existing.name
            && self.token_hash == existing.token_hash
            && self.uid == existing.uid
            && self.created_at == existing.created_at
            && self.grant == existing.grant;
        if !unchanged {
            return Err(KeepError::invalid_input(
                "an agent credential's identity, token, uid and grant cannot change",
            ));
        }
        if existing.revoked && !self.revoked {
            return Err(KeepError::invalid_input(
                "a revoked agent credential cannot be reinstated",
            ));
        }
        if self.expires_at > existing.expires_at {
            return Err(KeepError::invalid_input(
                "an agent credential's life cannot be extended",
            ));
        }
        Ok(())
    }

    /// The credential id as hex.
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }
}

/// Whether `token` has the form of an agent token: the prefix and 64
/// lowercase hex digits.
pub fn well_formed_token(token: &str) -> bool {
    token.len() == TOKEN_LEN
        && token.starts_with(TOKEN_PREFIX)
        && token[TOKEN_PREFIX.len()..]
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The stored hash of a well-formed token, or `None` for anything else, so a
/// malformed or oversized token is refused before any hashing.
pub fn hash_presented_token(token: &str) -> Option<[u8; 32]> {
    well_formed_token(token).then(|| token_hash(token))
}

fn token_hash(token: &str) -> [u8; 32] {
    let mut input = Zeroizing::new(Vec::with_capacity(TOKEN_HASH_DOMAIN.len() + token.len()));
    input.extend_from_slice(TOKEN_HASH_DOMAIN);
    input.extend_from_slice(token.as_bytes());
    blake2b_256(&input)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 24 * 60 * 60;

    fn issue() -> (AgentCredential, Zeroizing<String>) {
        AgentCredential::issue("claude", 1000, b"grant".to_vec(), NOW, DAY).unwrap()
    }

    fn matches(c: &AgentCredential, token: &str) -> bool {
        hash_presented_token(token).is_some_and(|h| c.matches_hash(&h))
    }

    #[test]
    fn a_token_matches_only_its_own_credential() {
        let (a, token_a) = issue();
        let (b, token_b) = issue();
        assert!(token_a.starts_with(TOKEN_PREFIX));
        assert_eq!(token_a.len(), TOKEN_LEN);
        assert_ne!(a.id, b.id);
        assert!(matches(&a, &token_a));
        assert!(!matches(&a, &token_b));
        assert!(!matches(&b, &token_a));
        let mut altered = token_a.to_string();
        let last = altered.pop().unwrap();
        altered.push(if last == '0' { '1' } else { '0' });
        assert!(!matches(&a, &altered));
    }

    #[test]
    fn audit_text_is_capped_and_escaped() {
        assert_eq!(audit_text("kind 4"), "kind 4");
        assert_eq!(audit_text("a\nOK agent_unfreeze"), "a\\nOK agent_unfreeze");
        assert_eq!(audit_text("\u{1b}[2J\"x\""), "\\u{1b}[2J\\\"x\\\"");
        assert_eq!(audit_text(&"a".repeat(1 << 20)).len(), MAX_AUDIT_TEXT);
        let cut = audit_text(&format!("{}\u{e9}", "a".repeat(MAX_AUDIT_TEXT - 1)));
        assert_eq!(
            cut,
            "a".repeat(MAX_AUDIT_TEXT - 1),
            "never splits a character"
        );
    }

    #[test]
    fn only_a_well_formed_token_is_hashed() {
        let (_, token) = issue();
        assert!(hash_presented_token(&token).is_some());
        let hex = &token[TOKEN_PREFIX.len()..];
        for bad in [
            String::new(),
            hex.to_string(),
            format!("{TOKEN_PREFIX}{}", &hex[1..]),
            format!("{}0", token.as_str()),
            format!("{TOKEN_PREFIX}{}", hex.to_uppercase()),
            format!("{TOKEN_PREFIX}{}g", &hex[1..]),
            format!("keep_xxx_{hex}"),
            format!("{TOKEN_PREFIX}{}", "0".repeat(1 << 20)),
        ] {
            assert!(hash_presented_token(&bad).is_none(), "{:.40}", bad);
        }
    }

    #[test]
    fn neither_the_token_nor_its_hash_is_shown() {
        let (credential, token) = issue();
        let hex = &token[TOKEN_PREFIX.len()..];
        let stored = serde_json::to_string(&credential).unwrap();
        assert!(!stored.contains(hex));
        let shown = format!("{credential:?}");
        assert!(!shown.contains(hex));
        assert!(!shown.contains(&hex::encode(credential.token_hash)));
        assert!(shown.contains("grant_len: 5"));
    }

    #[test]
    fn issuing_refuses_bad_names_uids_lifetimes_and_grants() {
        let refused = |name: &str, uid: u32, ttl: u64, grant: usize| {
            AgentCredential::issue(name, uid, vec![0; grant], NOW, ttl).unwrap_err()
        };
        let long = "a".repeat(65);
        for name in [
            "",
            long.as_str(),
            "a\nb",
            "a\u{202e}b",
            "caf\u{e9}",
            "a\u{200b}b",
            "   ",
            " lead",
            "trail ",
        ] {
            assert!(
                refused(name, 1000, DAY, 0)
                    .to_string()
                    .contains("agent name"),
                "{name:?}"
            );
        }
        for uid in [0, OVERFLOW_UID, u32::MAX] {
            assert!(refused("ok", uid, DAY, 0)
                .to_string()
                .contains(&format!("uid {uid}")));
        }
        assert!(refused("ok", 1000, 0, 0).to_string().contains("seconds"));
        assert!(refused("ok", 1000, MAX_CREDENTIAL_TTL_SECS + 1, 0)
            .to_string()
            .contains("seconds"));
        assert!(refused("ok", 1000, DAY, MAX_GRANT_BYTES + 1)
            .to_string()
            .contains("grant"));
        let (credential, _) = AgentCredential::issue(
            "my agent 1",
            1000,
            vec![0; MAX_GRANT_BYTES],
            NOW,
            MAX_CREDENTIAL_TTL_SECS,
        )
        .unwrap();
        assert_eq!(credential.expires_at, NOW + MAX_CREDENTIAL_TTL_SECS);
    }

    #[test]
    fn a_replacement_may_only_revoke_freeze_or_shorten() {
        let (credential, _) = issue();
        let replaced = |f: fn(&mut AgentCredential)| {
            let mut next = credential.clone();
            f(&mut next);
            next.check_replaces(&credential)
        };
        assert!(replaced(|c| c.revoked = true).is_ok());
        assert!(replaced(|c| c.frozen = true).is_ok());
        assert!(replaced(|c| c.expires_at -= 1).is_ok());
        assert!(replaced(|c| c.expires_at += 1).is_err());
        assert!(replaced(|c| c.uid += 1).is_err());
        assert!(replaced(|c| c.grant.push(0)).is_err());
        assert!(replaced(|c| c.name.push('x')).is_err());
        assert!(replaced(|c| c.created_at -= 1).is_err());
        assert!(replaced(|c| c.token_hash[0] ^= 1).is_err());
        assert!(replaced(|c| c.id[0] ^= 1).is_err());
        let mut revoked = credential.clone();
        revoked.revoked = true;
        assert!(credential.check_replaces(&revoked).is_err());
    }

    #[test]
    fn only_a_live_unfrozen_credential_from_its_uid_is_usable() {
        let (credential, _) = issue();
        assert_eq!(credential.check_usable(1000, NOW, false), Ok(()));
        assert_eq!(credential.check_usable(1000, NOW + DAY - 1, false), Ok(()));
        let refusal =
            |c: &AgentCredential, uid, now, all| c.check_usable(uid, now, all).unwrap_err();
        assert_eq!(
            refusal(&credential, 1000, NOW + DAY, false),
            AgentRefusal::Expired
        );
        assert_eq!(
            refusal(&credential, 1000, NOW - 1, false),
            AgentRefusal::ClockBehind
        );
        assert_eq!(
            refusal(&credential, 1000, 0, false),
            AgentRefusal::ClockBehind
        );
        assert_eq!(
            refusal(&credential, 1001, NOW, false),
            AgentRefusal::WrongUid
        );
        assert_eq!(refusal(&credential, 1000, NOW, true), AgentRefusal::Frozen);
        let mut frozen = credential.clone();
        frozen.frozen = true;
        assert_eq!(refusal(&frozen, 1000, NOW, false), AgentRefusal::Frozen);
        let mut tampered = credential.clone();
        tampered.uid = 0;
        assert_eq!(refusal(&tampered, 0, NOW, false), AgentRefusal::WrongUid);
        let mut revoked = credential;
        revoked.revoked = true;
        assert_eq!(refusal(&revoked, 1000, NOW, false), AgentRefusal::Revoked);
    }
}
