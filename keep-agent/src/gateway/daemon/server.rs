// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The gateway's sockets: the agent socket every agent uid can reach, and the
//! admin socket for root and the owner's admin uid. Each connection's peer uid
//! comes from `SO_PEERCRED`; nothing the peer says about itself is trusted.

use std::collections::HashMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use zeroize::Zeroizing;

use super::state::State;
use crate::error::{AgentError, Result};

/// The longest request line read, which holds the largest PSBT keep signs.
pub const MAX_LINE: usize = 1024 * 1024;

/// Connection limits and timeouts.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Open agent connections one uid may hold.
    pub connections_per_uid: usize,
    /// Open agent connections in all.
    pub connections: usize,
    /// Open admin connections.
    pub admin_connections: usize,
    /// How long a new agent connection has to present an accepted token.
    pub pre_auth: Duration,
    /// How long an authenticated agent connection may sit idle.
    pub idle: Duration,
    /// How long an admin connection may sit idle.
    pub admin_idle: Duration,
    /// How long writing an answer may take.
    pub write: Duration,
    /// Refused requests a connection may send before any token is accepted.
    pub pre_auth_refusals: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connections_per_uid: 8,
            connections: 128,
            admin_connections: 4,
            pre_auth: Duration::from_secs(5),
            idle: Duration::from_secs(600),
            admin_idle: Duration::from_secs(60),
            write: Duration::from_secs(10),
            pre_auth_refusals: 3,
        }
    }
}

/// Where the sockets are.
#[derive(Debug, Clone)]
pub struct Sockets {
    pub agent: PathBuf,
    pub admin: PathBuf,
}

/// The state every connection shares. A poisoned lock (a request that
/// panicked) stops the gateway rather than serving from state a request left
/// half changed.
type Shared = Arc<Mutex<State>>;

/// Check a socket's directory and clear a stale socket from an earlier run.
/// The directory must already exist, be a real directory owned by the gateway
/// and open to no one outside its group, so the socket is never reachable by
/// more than the directory allows, not even between bind and chmod.
fn prepare(path: &Path, euid: u32) -> Result<()> {
    let fail = |m: String| Err(AgentError::Other(format!("{}: {m}", path.display())));
    let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) else {
        return fail("a socket path needs a directory".into());
    };
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) => return fail(format!("its directory cannot be read: {e}")),
    };
    if !meta.file_type().is_dir() {
        return fail("its directory is not a directory".into());
    }
    if meta.uid() != euid {
        return fail(format!(
            "its directory is owned by uid {}, not the gateway's {euid}",
            meta.uid()
        ));
    }
    if meta.mode() & 0o007 != 0 {
        return fail(format!(
            "its directory has mode {:o}; it must be closed to others (0750 or tighter)",
            meta.mode() & 0o7777
        ));
    }
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => fail(format!("cannot be read: {e}")),
        Ok(m) if !m.file_type().is_socket() || m.uid() != euid => {
            fail("exists and is not the gateway's socket".into())
        }
        Ok(_) => match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => fail("another gateway is listening on it".into()),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(path)
                    .or_else(|e| fail(format!("stale socket cannot be removed: {e}")))
            }
            Err(e) => fail(format!("cannot be checked: {e}")),
        },
    }
}

/// Bind a socket in a checked directory. Access is the directory's: the
/// socket itself is opened to everyone who can reach it.
pub fn bind(path: &Path, euid: u32) -> Result<UnixListener> {
    prepare(path, euid)?;
    let listener = UnixListener::bind(path)
        .map_err(|e| AgentError::Other(format!("bind {}: {e}", path.display())))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
        .map_err(|e| AgentError::Other(format!("chmod {}: {e}", path.display())))?;
    Ok(listener)
}

/// Reads newline-terminated lines of at most `max` bytes, wiping every buffer
/// a line passed through, since request lines carry tokens.
pub struct LineReader<R> {
    inner: R,
    pending: Zeroizing<Vec<u8>>,
    max: usize,
}

impl<R: AsyncRead + Unpin> LineReader<R> {
    pub fn new(inner: R, max: usize) -> Self {
        Self {
            inner,
            pending: Zeroizing::new(Vec::with_capacity(16 * 1024)),
            max,
        }
    }

    /// The next line without its `\n` (and `\r`), `None` at end of stream,
    /// or an error once a line runs past the limit.
    pub async fn next_line(&mut self) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
        loop {
            if let Some(pos) = self.pending.iter().position(|&b| b == b'\n') {
                let mut line = Zeroizing::new(self.pending[..pos].to_vec());
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                let rest = Zeroizing::new(self.pending[pos + 1..].to_vec());
                self.pending.clear();
                self.pending.extend_from_slice(&rest);
                return Ok(Some(line));
            }
            if self.pending.len() > self.max {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "request line too long",
                ));
            }
            let mut chunk = Zeroizing::new([0u8; 8192]);
            let n = self.inner.read(&mut chunk[..]).await?;
            if n == 0 {
                return Ok(None);
            }
            self.reserve(n);
            self.pending.extend_from_slice(&chunk[..n]);
        }
    }

    /// Grow the buffer into a new one and wipe the old, so a reallocation
    /// never frees a copy of a token unwiped.
    fn reserve(&mut self, more: usize) {
        let needed = self.pending.len() + more;
        if needed <= self.pending.capacity() {
            return;
        }
        let mut grown = Zeroizing::new(Vec::with_capacity(needed.max(2 * self.pending.capacity())));
        grown.extend_from_slice(&self.pending);
        self.pending = grown;
    }
}

/// Counts open connections per uid; a slot is returned when its guard drops.
#[derive(Clone, Default)]
struct Slots(Arc<Mutex<HashMap<u32, usize>>>);

struct Slot {
    slots: Slots,
    uid: u32,
}

impl Slots {
    fn take(&self, uid: u32, per_uid: usize, total: usize) -> Option<Slot> {
        let mut map = self.0.lock().ok()?;
        let all: usize = map.values().sum();
        let mine = map.get(&uid).copied().unwrap_or(0);
        if all >= total || mine >= per_uid {
            return None;
        }
        map.insert(uid, mine + 1);
        Some(Slot {
            slots: self.clone(),
            uid,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Ok(mut map) = self.slots.0.lock() {
            if let Some(n) = map.get_mut(&self.uid) {
                *n -= 1;
                if *n == 0 {
                    map.remove(&self.uid);
                }
            }
        }
    }
}

/// Run `f` on the state off the async threads. `None` means the lock is
/// poisoned: the caller refuses and the gateway stops.
async fn with_state<T: Send + 'static>(
    state: &Shared,
    stop: &watch::Sender<bool>,
    f: impl FnOnce(&mut State) -> T + Send + 'static,
) -> Option<T> {
    let state = state.clone();
    let result = tokio::task::spawn_blocking(move || match state.lock() {
        Ok(mut s) => Some(f(&mut s)),
        Err(_) => None,
    })
    .await
    .ok()
    .flatten();
    if result.is_none() {
        tracing::error!("gateway state is unusable after a failed request; stopping");
        let _ = stop.send(true);
    }
    result
}

async fn write_line(
    w: &mut tokio::net::unix::OwnedWriteHalf,
    line: &Zeroizing<String>,
    limit: Duration,
) -> bool {
    let mut out = Zeroizing::new(Vec::with_capacity(line.len() + 1));
    out.extend_from_slice(line.as_bytes());
    out.push(b'\n');
    matches!(
        tokio::time::timeout(limit, w.write_all(&out)).await,
        Ok(Ok(()))
    )
}

async fn agent_connection(
    stream: UnixStream,
    uid: u32,
    state: Shared,
    limits: Limits,
    stop: watch::Sender<bool>,
    _slot: Slot,
) {
    let (read, mut write) = stream.into_split();
    let mut reader = LineReader::new(read, MAX_LINE);
    let deadline = tokio::time::Instant::now() + limits.pre_auth;
    let mut authenticated = false;
    let mut refusals = 0u32;
    loop {
        let next = if authenticated {
            tokio::time::timeout(limits.idle, reader.next_line()).await
        } else {
            tokio::time::timeout_at(deadline, reader.next_line()).await
        };
        let request = match next {
            Ok(Ok(Some(line))) => line,
            _ => return,
        };
        if request.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Some(answer) = with_state(&state, &stop, move |s| s.agent_request(uid, &request)).await
        else {
            return;
        };
        if answer.authenticated {
            authenticated = true;
        } else if !authenticated {
            refusals += 1;
        }
        if let Some(line) = &answer.line {
            if !write_line(&mut write, line, limits.write).await {
                return;
            }
        }
        if !authenticated && refusals >= limits.pre_auth_refusals {
            return;
        }
    }
}

async fn admin_connection(
    stream: UnixStream,
    state: Shared,
    limits: Limits,
    stop: watch::Sender<bool>,
    _slot: Slot,
) {
    let (read, mut write) = stream.into_split();
    let mut reader = LineReader::new(read, MAX_LINE);
    loop {
        let request = match tokio::time::timeout(limits.admin_idle, reader.next_line()).await {
            Ok(Ok(Some(line))) => line,
            _ => return,
        };
        if request.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Some(answer) = with_state(&state, &stop, move |s| s.admin_request(&request)).await
        else {
            return;
        };
        if !write_line(&mut write, &answer, limits.write).await {
            return;
        }
    }
}

/// An accept that failed (out of descriptors, say) is retried after a pause,
/// so the loop never spins.
async fn accept_failed(e: std::io::Error) {
    tracing::warn!(error = %e, "accept failed");
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Serve both sockets until `shutdown` resolves or the state becomes
/// unusable, then write out what is held in memory.
pub async fn serve(
    state: State,
    agent: UnixListener,
    admin: UnixListener,
    limits: Limits,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let admin_uid = state.admin_uid();
    let is_admin = move |uid: u32| uid == 0 || admin_uid == Some(uid);
    let state: Shared = Arc::new(Mutex::new(state));
    let (stop, mut stopped) = watch::channel(false);
    let agent_slots = Slots::default();
    let admin_slots = Slots::default();
    let mut flush = tokio::time::interval(Duration::from_secs(10));
    let mut heartbeat = tokio::time::interval(Duration::from_secs(60));
    tokio::pin!(shutdown);
    let failed = loop {
        tokio::select! {
            () = &mut shutdown => break false,
            _ = stopped.changed() => break true,
            _ = flush.tick() => {
                with_state(&state, &stop, State::tick).await;
            }
            _ = heartbeat.tick() => {
                if let Some(Err(e)) = with_state(&state, &stop, State::persist_heartbeat).await {
                    tracing::error!(error = %e, "the gateway clock could not be persisted");
                }
            }
            accepted = agent.accept() => {
                let stream = match accepted {
                    Ok((stream, _)) => stream,
                    Err(e) => {
                        accept_failed(e).await;
                        continue;
                    }
                };
                let Ok(cred) = stream.peer_cred() else { continue };
                let uid = cred.uid();
                match agent_slots.take(uid, limits.connections_per_uid, limits.connections) {
                    Some(slot) => {
                        tokio::spawn(agent_connection(
                            stream, uid, state.clone(), limits.clone(), stop.clone(), slot,
                        ));
                    }
                    None => tracing::warn!(uid, "agent connection refused: too many open"),
                }
            }
            accepted = admin.accept() => {
                let stream = match accepted {
                    Ok((stream, _)) => stream,
                    Err(e) => {
                        accept_failed(e).await;
                        continue;
                    }
                };
                let Ok(cred) = stream.peer_cred() else { continue };
                let uid = cred.uid();
                if !is_admin(uid) {
                    tracing::warn!(uid, "admin connection refused: not root or the admin uid");
                    continue;
                }
                match admin_slots.take(0, limits.admin_connections, limits.admin_connections) {
                    Some(slot) => {
                        tokio::spawn(admin_connection(
                            stream, state.clone(), limits.clone(), stop.clone(), slot,
                        ));
                    }
                    None => tracing::warn!(uid, "admin connection refused: too many open"),
                }
            }
        }
    };
    drop(agent);
    drop(admin);
    let state = state.clone();
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(mut s) = state.lock() {
            s.shut_down();
        }
    })
    .await;
    if failed {
        return Err(AgentError::Other(
            "the gateway stopped after a request failed".into(),
        ));
    }
    Ok(())
}

/// Remove a socket this gateway bound, if it is still there.
pub fn remove_socket(path: &Path) {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
        let _ = std::fs::remove_file(path);
    }
}
