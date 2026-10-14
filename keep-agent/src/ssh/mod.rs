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
const PUBLICKEY_HOSTBOUND: &[u8] = b"publickey-hostbound-v00@openssh.com";
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";

/// The lengths a session id has: the output of the key exchange's hash,
/// SHA-1, SHA-256, SHA-384 or SHA-512.
const SESSION_ID_LENGTHS: [usize; 4] = [20, 32, 48, 64];

/// The most session bindings a request carries: a login needs exactly one.
pub const MAX_BINDINGS: usize = 4;

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
    pub fn from_bytes(seed: &[u8]) -> Option<Self> {
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
pub(crate) fn host_signed(host: &[u8], sig: &[u8], data: &[u8]) -> bool {
    let check = || -> Option<()> {
        let mut key = Reader::new(host);
        let mut sig = Reader::new(sig);
        let kind = key_type(host)?;
        key.string()?;
        if sig.string()? != kind.as_bytes() {
            return None;
        }
        let ok = if kind == ED25519 {
            let vk =
                ed25519_dalek::VerifyingKey::from_bytes(key.string()?.try_into().ok()?).ok()?;
            let bytes: [u8; 64] = sig.string()?.try_into().ok()?;
            vk.verify_strict(data, &ed25519_dalek::Signature::from_bytes(&bytes))
                .is_ok()
        } else {
            use p256::ecdsa::signature::Verifier;
            key.string()?;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(key.string()?).ok()?;
            let mut inner = Reader::new(sig.string()?);
            let r = mpint32(inner.string()?)?;
            let s = mpint32(inner.string()?)?;
            let signature = p256::ecdsa::Signature::from_scalars(r, s).ok()?;
            inner.is_empty() && vk.verify(data, &signature).is_ok()
        };
        (ok && sig.is_empty()).then_some(())
    };
    check().is_some()
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
    /// Valid as an approver checks it (see
    /// [`keep_approval::change::ChangeSsh::check`]), with each host key a
    /// well-formed key and the keys sorted, each once.
    pub fn validate(&self) -> Result<()> {
        if let Some(bad) = self.host_keys.iter().find(|k| parse_host_key(k).is_none()) {
            return refuse(format!(
                "host key {bad:?} is not an ssh-ed25519 or ecdsa-sha2-nistp256 key as known_hosts writes it (type, space, base64)"
            ));
        }
        if !self.host_keys.windows(2).all(|w| w[0] < w[1]) {
            return refuse("an SSH rule's host_keys must be sorted, each once");
        }
        self.change()
            .check()
            .map_err(|e| AgentError::ScopeViolation(e.to_string()))
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
///
/// A login must use `publickey-hostbound-v00@openssh.com`, which names the
/// bound host key in the signed data, and the server checks it is its own.
/// A plain `publickey` login names no server, so anyone holding a granted
/// host's private key could bind another server's session to it.
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
    if !b.is_empty() || !SESSION_ID_LENGTHS.contains(&session.len()) {
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
    let (
        Some(id),
        Some(msg),
        Some(user),
        Some(service),
        Some(method),
        Some(has_signature),
        Some(alg),
        Some(blob),
    ) = (
        r.string(),
        r.u8(),
        r.text(),
        r.string(),
        r.string(),
        r.u8(),
        r.string(),
        r.string(),
    )
    else {
        return Err("data that is neither a login nor an SSHSIG signature");
    };
    if msg != SSH_MSG_USERAUTH_REQUEST
        || service != b"ssh-connection"
        || has_signature != 1
        || alg != ED25519.as_bytes()
    {
        return Err("data that is not a public key login request");
    }
    if method != PUBLICKEY_HOSTBOUND {
        return Err("a login by a method that does not name the host key");
    }
    if r.string() != Some(host) || !r.is_empty() {
        return Err("a login naming another host key than the one bound");
    }
    if id != session {
        return Err("a login for another session than the one bound");
    }
    if blob != key {
        return Err("a login naming another key");
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
