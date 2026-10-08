// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use keep_core::agent::{AgentCredential, AgentRefusal};
use keep_core::Keep;
use zeroize::Zeroizing;

use crate::error::{AgentError, Result};
use crate::policy::Grant;

/// A credential with its grant decoded and validated.
#[derive(Debug, Clone)]
pub struct GrantedCredential {
    pub credential: AgentCredential,
    pub grant: Grant,
}

impl GrantedCredential {
    /// Decode and validate a stored credential's grant. A grant that does not
    /// decode, fails validation, or is not stored exactly as validation leaves
    /// it is refused, so nothing but a validated grant is ever enforced.
    pub fn new(credential: AgentCredential) -> Result<Self> {
        let refuse = |why: String| {
            AgentError::ScopeViolation(format!("agent {} grant {why}", credential.id_hex()))
        };
        let stored: Grant = serde_json::from_slice(&credential.grant)
            .map_err(|e| refuse(format!("does not decode: {e}")))?;
        let grant = stored.clone().validated()?;
        if grant != stored {
            return Err(refuse("is not in validated form".into()));
        }
        Ok(Self { credential, grant })
    }
}

/// Issue a credential carrying `grant`, validated first, valid from `now` (the
/// gateway's clock) for `ttl_secs`. Returns it with the token for the agent.
pub fn issue_credential(
    keep: &mut Keep,
    name: &str,
    uid: u32,
    grant: Grant,
    now: u64,
    ttl_secs: u64,
) -> Result<(GrantedCredential, Zeroizing<String>)> {
    let grant = grant.validated()?;
    let bytes = serde_json::to_vec(&grant).map_err(|e| AgentError::Serialization(e.to_string()))?;
    let (credential, token) = keep.issue_agent_credential(name, uid, bytes, now, ttl_secs)?;
    Ok((GrantedCredential { credential, grant }, token))
}

/// Authenticate a token presented by `peer_uid` at `now` and decode its grant.
/// An `Err` (a vault fault, or a grant that will not load) is as much a refusal
/// as an `Ok(Err(_))`; the gateway answers the agent the same way for both.
pub fn authenticate(
    keep: &Keep,
    token: &str,
    peer_uid: u32,
    now: u64,
) -> Result<std::result::Result<GrantedCredential, AgentRefusal>> {
    match keep.authenticate_agent(token, peer_uid, now)? {
        Ok(credential) => Ok(Ok(GrantedCredential::new(credential)?)),
        Err(refusal) => Ok(Err(refusal)),
    }
}
