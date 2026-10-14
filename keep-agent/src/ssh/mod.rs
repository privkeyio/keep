// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! SSH keys an agent uses without holding them: Ed25519 keys generated
//! inside keep, what a grant lets each one sign, and the checks a signature
//! request passes before the gateway signs it.
//!
//! A login signature is made only over a user authentication request inside
//! an SSH session whose key exchange a granted host key signed. The client
//! binds its agent connection to the session (OpenSSH's
//! `session-bind@openssh.com`), the gateway checks the host's signature over
//! the session id on every request, and the request must name that session,
//! a granted user and this key. An SSHSIG signature is made only in a
//! granted namespace, and only on a connection no session is bound to, since
//! an SSH client binds every agent connection it forwards.

pub mod wire;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{AgentError, Result};
use wire::{put_string, Reader};

pub const ED25519: &str = "ssh-ed25519";
pub const ECDSA_P256: &str = "ecdsa-sha2-nistp256";

const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
const PUBLICKEY: &[u8] = b"publickey";
const PUBLICKEY_HOSTBOUND: &[u8] = b"publickey-hostbound-v00@openssh.com";
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";

/// The longest session id read: OpenSSH's own agent's limit.
const MAX_SESSION_ID: usize = 128;

pub use keep_approval::change::MAX_SSH_ITEMS;

/// An Ed25519 SSH key, wiped when dropped.
pub struct SshKey(ed25519_dalek::SigningKey);

impl SshKey {
    /// A fresh key, and the seed the vault stores for it.
    pub fn generate() -> Result<(Self, Zeroizing<[u8; 32]>)> {
        let seed = Zeroizing::new(
            keep_core::entropy::try_random_bytes::<32>()
                .map_err(|e| AgentError::Other(format!("entropy: {e}")))?,
        );
        Ok((Self(ed25519_dalek::SigningKey::from_bytes(&seed)), seed))
    }

    /// The key a stored seed holds.
    pub fn from_seed(seed: &[u8]) -> Option<Self> {
        let seed: &[u8; 32] = seed.try_into().ok()?;
        Some(Self(ed25519_dalek::SigningKey::from_bytes(seed)))
    }

    /// The public key in the SSH encoding.
    pub fn public_blob(&self) -> Vec<u8> {
        let mut blob = Vec::with_capacity(51);
        put_string(&mut blob, ED25519.as_bytes());
        put_string(&mut blob, self.0.verifying_key().as_bytes());
        blob
    }

    /// An `ssh-ed25519` signature over `data`, in the SSH encoding.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let mut out = Vec::with_capacity(83);
        put_string(&mut out, ED25519.as_bytes());
        put_string(&mut out, &self.0.sign(data).to_bytes());
        out
    }
}

/// A public key as `authorized_keys` and `known_hosts` write it: its type, a
/// space, and its encoding in base64.
pub fn public_key_text(blob: &[u8]) -> Option<String> {
    Some(format!("{} {}", key_type(blob)?, STANDARD.encode(blob)))
}

/// A public key's fingerprint as OpenSSH prints it.
pub fn fingerprint(blob: &[u8]) -> String {
    format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(keep_approval::sha256(blob))
    )
}

/// A host key as an approver is shown it: its type and fingerprint.
pub fn host_key_label(blob: &[u8]) -> Option<String> {
    Some(format!("{} {}", key_type(blob)?, fingerprint(blob)))
}

/// The encoding of a host key written as `known_hosts` writes it (type,
/// space, base64, nothing else): an `ssh-ed25519` or `ecdsa-sha2-nistp256`
/// key, a valid point on its curve. The decoder takes only canonical base64,
/// padded, with no stray bits.
pub fn parse_host_key(text: &str) -> Option<Vec<u8>> {
    let (kind, encoded) = text.split_once(' ')?;
    let blob = STANDARD.decode(encoded).ok()?;
    (key_type(&blob) == Some(kind)).then_some(blob)
}

/// The type of a well-formed `ssh-ed25519` or `ecdsa-sha2-nistp256` public
/// key encoding, its point checked.
fn key_type(blob: &[u8]) -> Option<&'static str> {
    let mut r = Reader::new(blob);
    let kind = match r.string()? {
        k if k == ED25519.as_bytes() => {
            let point: [u8; 32] = r.string()?.try_into().ok()?;
            ed25519_dalek::VerifyingKey::from_bytes(&point).ok()?;
            ED25519
        }
        k if k == ECDSA_P256.as_bytes() => {
            if r.string()? != b"nistp256" {
                return None;
            }
            // Uncompressed, as OpenSSH writes it.
            let point = r.string()?;
            if point.len() != 65 {
                return None;
            }
            p256::ecdsa::VerifyingKey::from_sec1_bytes(point).ok()?;
            ECDSA_P256
        }
        _ => return None,
    };
    r.is_empty().then_some(kind)
}

/// Whether `sig`, in the SSH encoding, is host key `host`'s signature over
/// `data`.
fn host_signed(host: &[u8], sig: &[u8], data: &[u8]) -> bool {
    let mut key = Reader::new(host);
    let mut sig = Reader::new(sig);
    match key_type(host) {
        Some(ED25519) => {
            let (Some(_), Some(point)) = (key.string(), key.string()) else {
                return false;
            };
            let Ok(point) = <[u8; 32]>::try_from(point) else {
                return false;
            };
            let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&point) else {
                return false;
            };
            let (Some(kind), Some(bytes)) = (sig.string(), sig.string()) else {
                return false;
            };
            let Ok(bytes) = <[u8; 64]>::try_from(bytes) else {
                return false;
            };
            kind == ED25519.as_bytes()
                && sig.is_empty()
                && vk
                    .verify_strict(data, &ed25519_dalek::Signature::from_bytes(&bytes))
                    .is_ok()
        }
        Some(ECDSA_P256) => {
            use p256::ecdsa::signature::Verifier;
            let (Some(_), Some(_), Some(point)) = (key.string(), key.string(), key.string()) else {
                return false;
            };
            let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(point) else {
                return false;
            };
            let (Some(kind), Some(inner)) = (sig.string(), sig.string()) else {
                return false;
            };
            let mut inner = Reader::new(inner);
            let (Some(r), Some(s)) = (
                inner.string().and_then(mpint32),
                inner.string().and_then(mpint32),
            ) else {
                return false;
            };
            let Ok(signature) = p256::ecdsa::Signature::from_scalars(r, s) else {
                return false;
            };
            kind == ECDSA_P256.as_bytes()
                && sig.is_empty()
                && inner.is_empty()
                && vk.verify(data, &signature).is_ok()
        }
        _ => false,
    }
}

/// A positive `mpint` of at most 32 bytes, minimally encoded, as 32
/// big-endian bytes.
fn mpint32(b: &[u8]) -> Option<[u8; 32]> {
    let digits = match b {
        [] => return None,
        [first, ..] if first & 0x80 != 0 => return None,
        [0, next, ..] if next & 0x80 != 0 => &b[1..],
        [0, ..] => return None,
        _ => b,
    };
    if digits.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - digits.len()..].copy_from_slice(digits);
    Some(out)
}

/// What an SSH key may sign: logins as one of `users` to a host holding one
/// of `host_keys` (each as `known_hosts` writes it), and SSHSIG signatures
/// in one of `sshsig_namespaces`. Each list is sorted, without repeats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshRule {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sshsig_namespaces: Vec<String>,
}

fn refuse<T>(message: impl Into<String>) -> Result<T> {
    Err(AgentError::ScopeViolation(message.into()))
}

impl SshRule {
    pub fn validate(&self) -> Result<()> {
        use keep_approval::change::{ssh_user_ok, sshsig_namespace_ok};
        for (list, what) in [
            (&self.users, "users"),
            (&self.host_keys, "host_keys"),
            (&self.sshsig_namespaces, "sshsig_namespaces"),
        ] {
            if list.len() > MAX_SSH_ITEMS {
                return refuse(format!("an SSH rule lists at most {MAX_SSH_ITEMS} {what}"));
            }
            if !list.windows(2).all(|w| w[0] < w[1]) {
                return refuse(format!("an SSH rule's {what} must be sorted, each once"));
            }
        }
        if self.users.is_empty() != self.host_keys.is_empty() {
            return refuse("an SSH rule names users and host keys together");
        }
        if self.users.is_empty() && self.sshsig_namespaces.is_empty() {
            return refuse("an SSH rule must allow at least one use");
        }
        if !self.users.iter().all(|u| ssh_user_ok(u)) {
            return refuse("an SSH user is 1 to 64 letters, digits, '.', '_' or '-'");
        }
        if !self
            .sshsig_namespaces
            .iter()
            .all(|n| sshsig_namespace_ok(n))
        {
            return refuse("an SSHSIG namespace is 1 to 64 letters, digits, '@', '.', '_' or '-'");
        }
        if let Some(bad) = self.host_keys.iter().find(|k| parse_host_key(k).is_none()) {
            return refuse(format!(
                "host key {bad:?} is not an ssh-ed25519 or ecdsa-sha2-nistp256 key as known_hosts writes it (type, space, base64)"
            ));
        }
        Ok(())
    }

    /// The rule as an approver is shown it, host keys by fingerprint.
    pub fn change(&self) -> keep_approval::change::ChangeSsh {
        let mut host_keys: Vec<String> = self
            .host_keys
            .iter()
            .filter_map(|k| host_key_label(&parse_host_key(k)?))
            .collect();
        host_keys.sort();
        keep_approval::change::ChangeSsh {
            users: self.users.clone(),
            host_keys,
            sshsig_namespaces: self.sshsig_namespaces.clone(),
        }
    }
}

/// A signature request that passed every check.
#[derive(Debug, PartialEq, Eq)]
pub enum Signing<'a> {
    /// A login as `user` to the host holding `host`.
    Login { user: &'a str, host: Vec<u8> },
    /// An SSHSIG signature in `namespace`.
    Sshsig { namespace: &'a str },
}

/// Check a request to sign `data` with the key whose encoding is `key`,
/// under `rule`. `bindings` are the `session-bind@openssh.com` bodies the
/// client sent on its agent connection, in order (host key, session id,
/// signature, forwarding flag). An error is the reason, for the audit log
/// alone.
pub fn check_request<'a>(
    rule: &SshRule,
    key: &[u8],
    data: &'a [u8],
    bindings: &[Vec<u8>],
) -> std::result::Result<Signing<'a>, &'static str> {
    if let Some(body) = data.strip_prefix(SSHSIG_MAGIC) {
        return check_sshsig(rule, body, bindings);
    }
    let binding = match bindings {
        [one] => one,
        [] => return Err("a login on a connection no SSH session is bound to"),
        _ => return Err("a login on a connection bound more than once"),
    };
    let mut b = Reader::new(binding);
    let (Some(host), Some(session), Some(host_sig), Some(forwarding)) =
        (b.string(), b.string(), b.string(), b.u8())
    else {
        return Err("a malformed session binding");
    };
    if !b.is_empty() || session.is_empty() || session.len() > MAX_SESSION_ID {
        return Err("a malformed session binding");
    }
    if forwarding != 0 {
        return Err("a session bound for agent forwarding");
    }
    if !rule
        .host_keys
        .iter()
        .any(|k| parse_host_key(k).as_deref() == Some(host))
    {
        return Err("a host key the rule does not name");
    }
    if !host_signed(host, host_sig, session) {
        return Err("a session binding the host key did not sign");
    }
    let mut r = Reader::new(data);
    let parsed = (|| {
        let id = r.string()?;
        let msg = r.u8()?;
        let user = r.text()?;
        let service = r.string()?;
        let method = r.string()?;
        let has_signature = r.u8()?;
        let alg = r.string()?;
        let blob = r.string()?;
        let bound_host = if method == PUBLICKEY_HOSTBOUND {
            Some(r.string()?)
        } else {
            None
        };
        Some((
            id,
            msg,
            user,
            service,
            method,
            has_signature,
            alg,
            blob,
            bound_host,
        ))
    })();
    let Some((id, msg, user, service, method, has_signature, alg, blob, bound_host)) = parsed
    else {
        return Err("data that is neither a login nor an SSHSIG signature");
    };
    if !r.is_empty()
        || msg != SSH_MSG_USERAUTH_REQUEST
        || service != b"ssh-connection"
        || !(method == PUBLICKEY || method == PUBLICKEY_HOSTBOUND)
        || has_signature != 1
        || alg != ED25519.as_bytes()
    {
        return Err("data that is not a public key login request");
    }
    if id != session {
        return Err("a login for another session than the one bound");
    }
    if blob != key {
        return Err("a login naming another key");
    }
    if bound_host.is_some_and(|h| h != host) {
        return Err("a login naming another host key than the one bound");
    }
    if !rule.users.iter().any(|u| u == user) {
        return Err("a user the rule does not name");
    }
    Ok(Signing::Login {
        user,
        host: host.to_vec(),
    })
}

fn check_sshsig<'a>(
    rule: &SshRule,
    body: &'a [u8],
    bindings: &[Vec<u8>],
) -> std::result::Result<Signing<'a>, &'static str> {
    if !bindings.is_empty() {
        return Err("an SSHSIG signature on a connection bound to an SSH session");
    }
    let mut r = Reader::new(body);
    let (Some(namespace), Some(reserved), Some(alg), Some(hash)) =
        (r.text(), r.string(), r.string(), r.string())
    else {
        return Err("malformed SSHSIG data");
    };
    let hash_len = match alg {
        b"sha256" => 32,
        b"sha512" => 64,
        _ => return Err("an SSHSIG hash algorithm other than sha256 or sha512"),
    };
    if !r.is_empty() || !reserved.is_empty() || hash.len() != hash_len {
        return Err("malformed SSHSIG data");
    }
    if !rule.sshsig_namespaces.iter().any(|n| n == namespace) {
        return Err("an SSHSIG namespace the rule does not name");
    }
    Ok(Signing::Sshsig { namespace })
}

#[cfg(test)]
mod tests;
