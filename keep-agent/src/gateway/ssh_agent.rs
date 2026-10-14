// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! `keep agent ssh-agent`: an SSH agent for the agent's SSH clients whose
//! keys stay in the gateway. It serves the agent protocol (RFC 9987) on a
//! socket in a directory only its user can enter, lists the SSH keys the
//! credential is granted, and passes each signature request to the
//! gateway's `ssh_sign` with the session bindings the client sent on that
//! connection. It holds no key and decides nothing: the gateway checks every
//! request.

use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use super::bridge::Bridge;
use crate::error::{AgentError, Result};
use crate::ssh::wire::{put_string, Reader};

/// The longest message read or written: OpenSSH's own agent's limit.
pub const MAX_MESSAGE: usize = 256 * 1024;
/// The most connections served at once.
pub const MAX_CONNECTIONS: usize = 16;
/// The most session bindings kept for one connection: the gateway signs a
/// login only with exactly one.
const MAX_BINDINGS: usize = 4;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";

/// One SSH key the credential is granted.
#[derive(Clone)]
struct Identity {
    secret: String,
    blob: Vec<u8>,
    comment: String,
}

/// What a client sent on one connection.
#[derive(Default)]
pub struct Connection {
    bindings: Vec<Vec<u8>>,
    /// More bindings came than are kept, so no login is signed on it.
    overflowed: bool,
}

/// The agent: one gateway connection shared by every client connection,
/// one request at a time.
pub struct SshAgent {
    bridge: Mutex<Bridge>,
    identities: Mutex<Vec<Identity>>,
    next_id: AtomicI64,
    connections: AtomicUsize,
}

impl SshAgent {
    pub fn new(bridge: Bridge) -> Self {
        Self {
            bridge: Mutex::new(bridge),
            identities: Mutex::new(Vec::new()),
            next_id: AtomicI64::new(1),
            connections: AtomicUsize::new(0),
        }
    }

    /// Call `tool` on the gateway: its result, or `None` when it refused or
    /// could not be reached.
    fn tool(&self, tool: &str, arguments: Value) -> Option<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let message = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": tool, "arguments": arguments },
        });
        let message = serde_json::to_vec(&message).ok()?;
        let answer = self
            .bridge
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .call(json!(id), &message);
        let result = answer.get("result")?;
        if result.get("isError") != Some(&Value::Bool(false)) {
            tracing::warn!(tool, "the gateway refused the request");
            return None;
        }
        serde_json::from_str(result["content"][0]["text"].as_str()?).ok()
    }

    /// The granted SSH keys the gateway lists as usable, kept for signing.
    fn refresh_identities(&self) -> Option<Vec<Identity>> {
        let listed = self.tool("list_secrets", json!({}))?;
        let identities: Vec<Identity> = listed["secrets"]
            .as_array()?
            .iter()
            .filter(|s| s["kind"] == "ssh_key" && s["usable"] == true)
            .filter_map(|s| {
                let blob = crate::ssh::parse_host_key(s["public_key"].as_str()?)?;
                Some(Identity {
                    secret: s["id"].as_str()?.to_string(),
                    blob,
                    comment: s["name"].as_str().unwrap_or_default().to_string(),
                })
            })
            .collect();
        *self.identities.lock().unwrap_or_else(|e| e.into_inner()) = identities.clone();
        Some(identities)
    }

    fn secret_for(&self, blob: &[u8]) -> Option<String> {
        let find = |list: &[Identity]| {
            list.iter()
                .find(|i| i.blob == blob)
                .map(|i| i.secret.clone())
        };
        let known = find(&self.identities.lock().unwrap_or_else(|e| e.into_inner()));
        known.or_else(|| find(&self.refresh_identities()?))
    }

    /// The answer to one request body (type byte and contents).
    pub fn handle(&self, conn: &mut Connection, request: &[u8]) -> Vec<u8> {
        let failure = vec![SSH_AGENT_FAILURE];
        let Some((&kind, body)) = request.split_first() else {
            return failure;
        };
        match kind {
            SSH_AGENTC_REQUEST_IDENTITIES if body.is_empty() => {
                let Some(identities) = self.refresh_identities() else {
                    return failure;
                };
                let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
                out.extend_from_slice(&(identities.len() as u32).to_be_bytes());
                for i in &identities {
                    put_string(&mut out, &i.blob);
                    put_string(&mut out, i.comment.as_bytes());
                }
                out
            }
            SSH_AGENTC_SIGN_REQUEST => {
                let mut r = Reader::new(body);
                let (Some(blob), Some(data), Some(flags)) = (r.string(), r.string(), r.u32())
                else {
                    return failure;
                };
                if !r.is_empty() || conn.overflowed {
                    return failure;
                }
                let Some(secret) = self.secret_for(blob) else {
                    return failure;
                };
                let bindings: Vec<String> = conn.bindings.iter().map(|b| B64.encode(b)).collect();
                let signed = self.tool(
                    "ssh_sign",
                    json!({
                        "secret": secret,
                        "data": B64.encode(data),
                        "flags": flags,
                        "bindings": bindings,
                    }),
                );
                let Some(signature) = signed
                    .as_ref()
                    .and_then(|s| s["signature"].as_str())
                    .and_then(|s| B64.decode(s).ok())
                else {
                    return failure;
                };
                let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
                put_string(&mut out, &signature);
                out
            }
            SSH_AGENTC_EXTENSION => {
                let mut r = Reader::new(body);
                if r.string() != Some(SESSION_BIND) {
                    return failure;
                }
                // The rest is the binding, which the gateway parses and
                // checks on every signature request.
                let binding = &body[4 + SESSION_BIND.len()..];
                if conn.bindings.len() < MAX_BINDINGS {
                    conn.bindings.push(binding.to_vec());
                } else {
                    conn.overflowed = true;
                }
                vec![SSH_AGENT_SUCCESS]
            }
            _ => failure,
        }
    }

    /// Serve the agent protocol on `listener` until it fails.
    pub fn serve(self: Arc<Self>, listener: UnixListener, owner: u32) -> Result<()> {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "accepting a client failed");
                    continue;
                }
            };
            match rustix::net::sockopt::socket_peercred(&stream) {
                Ok(peer) if peer.uid.as_raw() == owner => {}
                _ => continue,
            }
            if self.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                self.connections.fetch_sub(1, Ordering::SeqCst);
                continue;
            }
            let agent = self.clone();
            std::thread::spawn(move || {
                if let Err(e) = agent.serve_connection(stream) {
                    tracing::debug!(error = %e, "a client connection ended");
                }
                agent.connections.fetch_sub(1, Ordering::SeqCst);
            });
        }
        Err(AgentError::Other("the listening socket closed".into()))
    }

    fn serve_connection(&self, mut stream: UnixStream) -> std::io::Result<()> {
        let mut conn = Connection::default();
        loop {
            let mut len = [0u8; 4];
            match stream.read_exact(&mut len) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            }
            let len = u32::from_be_bytes(len) as usize;
            if len == 0 || len > MAX_MESSAGE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "a message of no length or over the limit",
                ));
            }
            let mut request = vec![0u8; len];
            stream.read_exact(&mut request)?;
            let answer = self.handle(&mut conn, &request);
            let mut framed = Vec::with_capacity(4 + answer.len());
            framed.extend_from_slice(&(answer.len() as u32).to_be_bytes());
            framed.extend_from_slice(&answer);
            stream.write_all(&framed)?;
        }
    }
}

/// Listen at `path`, in a directory `owner` owns and no one else can enter.
/// A socket of `owner`'s left at `path` by an earlier run is replaced.
pub fn listen(path: &Path, owner: u32) -> Result<UnixListener> {
    let fail = |m: String| AgentError::Other(format!("{}: {m}", path.display()));
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| fail("a socket path needs a directory".into()))?;
    let meta = std::fs::symlink_metadata(dir).map_err(|e| fail(format!("its directory: {e}")))?;
    if !meta.file_type().is_dir() || meta.uid() != owner || meta.mode() & 0o077 != 0 {
        return Err(fail(format!(
            "its directory must be a directory of uid {owner}'s that no one else can enter \
             (mkdir -m 700)"
        )));
    }
    match std::fs::symlink_metadata(path) {
        Ok(old) if old.file_type().is_socket() && old.uid() == owner => {
            std::fs::remove_file(path).map_err(|e| fail(format!("removing the old socket: {e}")))?
        }
        Ok(_) => return Err(fail("something other than an old socket is there".into())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(fail(e.to_string())),
    }
    let listener = UnixListener::bind(path).map_err(|e| fail(e.to_string()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| fail(e.to_string()))?;
    Ok(listener)
}

#[cfg(test)]
mod tests;
