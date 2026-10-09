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

use super::state::{pool, BoundUids, State, UNBOUND};
use crate::error::{AgentError, Result};

/// The longest request line read, which holds the largest PSBT keep signs.
pub const MAX_LINE: usize = 1024 * 1024;

/// Connection limits and timeouts.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Open agent connections one uid a credential is bound to may hold.
    pub connections_per_uid: usize,
    /// Open agent connections every uid no credential is bound to may hold
    /// together.
    pub unbound_connections: usize,
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
    /// Refused requests in a row, before or after a token is accepted, that
    /// close a connection.
    pub refusals_in_a_row: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connections_per_uid: 8,
            unbound_connections: 8,
            connections: 128,
            admin_connections: 4,
            pre_auth: Duration::from_secs(5),
            idle: Duration::from_secs(600),
            admin_idle: Duration::from_secs(60),
            write: Duration::from_secs(10),
            refusals_in_a_row: 3,
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
    // Group members may enter the directory, but neither they nor anyone else
    // may write to it, or they could swap the socket for their own.
    if meta.mode() & 0o027 != 0 {
        return fail(format!(
            "its directory has mode {:o}; it must be writable by the gateway alone and closed \
             to others (0750 or tighter)",
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

/// How long a client waits for the gateway to accept a connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a client's connection to a gateway socket was not made. Nothing was
/// sent either way.
#[derive(Debug)]
pub enum ConnectError {
    /// No gateway is there: the socket or its directory does not exist,
    /// nothing listens on it, or it did not accept in time.
    Absent(String),
    /// What is there is not the gateway's, or cannot be checked.
    Rejected(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent(m) | Self::Rejected(m) => f.write_str(m),
        }
    }
}

impl From<ConnectError> for AgentError {
    fn from(e: ConnectError) -> Self {
        AgentError::Other(e.to_string())
    }
}

/// Connect to a gateway socket as a client, refusing unless the socket's
/// directory is a real directory owned by `gateway_uid` and writable by it
/// alone, and the peer is `gateway_uid` too. No one else could have put a
/// socket there, so the peer is the gateway and not an impostor collecting
/// what clients send or faking what they are told.
pub fn connect_checked(path: &Path, gateway_uid: u32) -> Result<std::os::unix::net::UnixStream> {
    connect_verified(path, gateway_uid, CONNECT_TIMEOUT).map_err(Into::into)
}

/// [`connect_checked`], waiting at most `timeout` for the gateway to accept,
/// and telling a gateway that is not there from one that cannot be trusted.
pub fn connect_verified(
    path: &Path,
    gateway_uid: u32,
    timeout: Duration,
) -> std::result::Result<std::os::unix::net::UnixStream, ConnectError> {
    let absent = |m: String| ConnectError::Absent(format!("{}: {m}", path.display()));
    let rejected = |m: String| ConnectError::Rejected(format!("{}: {m}", path.display()));
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| rejected("a socket path needs a directory".into()))?;
    let meta = std::fs::symlink_metadata(dir).map_err(|e| {
        let m = format!("its directory cannot be read: {e}");
        if e.kind() == std::io::ErrorKind::NotFound {
            absent(m)
        } else {
            rejected(m)
        }
    })?;
    if !meta.file_type().is_dir() {
        return Err(rejected("its directory is not a directory".into()));
    }
    if meta.uid() != gateway_uid {
        return Err(rejected(format!(
            "its directory is owned by uid {}, not the gateway's uid {gateway_uid}",
            meta.uid()
        )));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(rejected(format!(
            "its directory has mode {:o}; anyone but its owner could replace the socket",
            meta.mode() & 0o7777
        )));
    }
    let stream = connect_within(path, timeout).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::TimedOut => absent(e.to_string()),
        _ => rejected(e.to_string()),
    })?;
    let peer = rustix::net::sockopt::socket_peercred(&stream)
        .map_err(|e| rejected(format!("SO_PEERCRED: {e}")))?
        .uid
        .as_raw();
    if peer != gateway_uid {
        return Err(rejected(format!(
            "it is served by uid {peer}, not the gateway's uid {gateway_uid}"
        )));
    }
    Ok(stream)
}

/// Connect, waiting at most `timeout` for room in the listener's backlog: a
/// blocking connect would wait for as long as the gateway does not accept.
fn connect_within(
    path: &Path,
    timeout: Duration,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    let fd = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )?;
    let addr = SocketAddrUnix::new(path)?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match rustix::net::connect(&fd, &addr) {
            Ok(()) => break,
            Err(rustix::io::Errno::INTR) => {}
            // A Unix socket with a full backlog refuses a non-blocking
            // connect at once.
            Err(rustix::io::Errno::AGAIN) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(rustix::io::Errno::AGAIN) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the gateway did not accept the connection in time",
                ))
            }
            Err(e) => return Err(e.into()),
        }
    }
    rustix::io::ioctl_fionbio(&fd, false)?;
    Ok(std::os::unix::net::UnixStream::from(fd))
}

/// Reads newline-terminated lines of at most `max` bytes, wiping every buffer
/// a line passed through, since request lines carry tokens. Each byte is
/// scanned once and copied at most twice, so a stream of tiny lines costs no
/// more than one long one.
pub struct LineReader<R> {
    inner: R,
    buf: Zeroizing<Vec<u8>>,
    /// Where the next line starts.
    start: usize,
    /// How far the buffer has been searched for a newline.
    scanned: usize,
    max: usize,
}

impl<R: AsyncRead + Unpin> LineReader<R> {
    pub fn new(inner: R, max: usize) -> Self {
        Self {
            inner,
            buf: Zeroizing::new(Vec::with_capacity(16 * 1024)),
            start: 0,
            scanned: 0,
            max,
        }
    }

    fn too_long() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "request line too long")
    }

    /// The next line without its `\n` (and `\r`), `None` at end of stream,
    /// or an error once a line runs past the limit.
    pub async fn next_line(&mut self) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
        loop {
            if let Some(offset) = self.buf[self.scanned..].iter().position(|&b| b == b'\n') {
                let end = self.scanned + offset;
                if end - self.start > self.max {
                    return Err(Self::too_long());
                }
                let mut line = Zeroizing::new(self.buf[self.start..end].to_vec());
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                self.start = end + 1;
                self.scanned = self.start;
                return Ok(Some(line));
            }
            self.scanned = self.buf.len();
            if self.buf.len() - self.start > self.max {
                return Err(Self::too_long());
            }
            self.compact();
            let mut chunk = Zeroizing::new([0u8; 8192]);
            let n = self.inner.read(&mut chunk[..]).await?;
            if n == 0 {
                return Ok(None);
            }
            self.reserve(n);
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Move the unread bytes to the front and wipe what they leave behind.
    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        let len = self.buf.len();
        self.buf.copy_within(self.start..len, 0);
        let kept = len - self.start;
        self.buf[kept..].fill(0);
        self.buf.truncate(kept);
        self.scanned -= self.start;
        self.start = 0;
    }

    /// Grow the buffer into a new one and wipe the old, so a reallocation
    /// never frees a copy of a token unwiped.
    fn reserve(&mut self, more: usize) {
        let needed = self.buf.len() + more;
        if needed <= self.buf.capacity() {
            return;
        }
        let mut grown = Zeroizing::new(Vec::with_capacity(needed.max(2 * self.buf.capacity())));
        grown.extend_from_slice(&self.buf);
        self.buf = grown;
    }
}

/// Logs a refused connection at most once a minute per key (a bound uid, or
/// [`UNBOUND`] for every other), so a peer cannot flood the journal and push
/// out what matters.
#[derive(Default)]
struct Throttle(HashMap<u32, tokio::time::Instant>);

impl Throttle {
    fn allow(&mut self, uid: u32) -> bool {
        let now = tokio::time::Instant::now();
        if self
            .0
            .get(&uid)
            .is_some_and(|t| now.duration_since(*t) < Duration::from_secs(60))
        {
            return false;
        }
        if self.0.len() >= 1_024 {
            self.0.clear();
        }
        self.0.insert(uid, now);
        true
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

/// A slot for an agent connection from `uid`: its own when a credential is
/// bound to it, otherwise one of the few every unbound uid shares.
fn agent_slot(slots: &Slots, bound: &BoundUids, uid: u32, limits: &Limits) -> Option<Slot> {
    let key = pool(bound, uid);
    let per_key = if key == UNBOUND {
        limits.unbound_connections
    } else {
        limits.connections_per_uid
    };
    slots.take(key, per_key, limits.connections)
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
    // Refused requests since the last accepted one.
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
        // Blank lines are requests too: refused and counted like any other,
        // so they cannot be sent for free.
        let Some(answer) = with_state(&state, &stop, move |s| s.agent_request(uid, &request)).await
        else {
            return;
        };
        if answer.authenticated {
            authenticated = true;
            refusals = 0;
        } else {
            refusals += 1;
        }
        if let Some(line) = &answer.line {
            if !write_line(&mut write, line, limits.write).await {
                return;
            }
        }
        // Refused requests in a row end the connection, before or after a
        // token was accepted on it.
        if refusals >= limits.refusals_in_a_row {
            return;
        }
        tokio::task::yield_now().await;
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
        let Some(answer) = with_state(&state, &stop, move |s| s.admin_request(&request)).await
        else {
            return;
        };
        if !write_line(&mut write, &answer, limits.write).await {
            return;
        }
        tokio::task::yield_now().await;
    }
}

/// An accept that failed (out of descriptors, say) is retried after a pause,
/// so the loop never spins.
async fn accept_failed(e: std::io::Error) {
    tracing::warn!(error = %e, "accept failed");
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Record deferred refusals and passed refusal windows every 10 seconds, and
/// persist the clock every minute. Apart from the accept loop, so a timer
/// waiting on the state never holds up accepting connections or stopping.
async fn timers(state: Shared, stop: watch::Sender<bool>) {
    let mut flush = tokio::time::interval(Duration::from_secs(10));
    let mut heartbeat = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = flush.tick() => {
                with_state(&state, &stop, State::tick).await;
            }
            _ = heartbeat.tick() => {
                if let Some(Err(e)) = with_state(&state, &stop, State::persist_heartbeat).await {
                    tracing::error!(error = %e, "the gateway clock could not be persisted");
                }
            }
        }
    }
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
    let bound = state.bound_uids();
    let state: Shared = Arc::new(Mutex::new(state));
    let (stop, mut stopped) = watch::channel(false);
    let agent_slots = Slots::default();
    let mut refused_log = Throttle::default();
    let admin_slots = Slots::default();
    let timers = tokio::spawn(timers(state.clone(), stop.clone()));
    tokio::pin!(shutdown);
    let failed = loop {
        tokio::select! {
            () = &mut shutdown => break false,
            _ = stopped.changed() => break true,
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
                match agent_slot(&agent_slots, &bound, uid, &limits) {
                    Some(slot) => {
                        tokio::spawn(agent_connection(
                            stream, uid, state.clone(), limits.clone(), stop.clone(), slot,
                        ));
                    }
                    None => {
                        if refused_log.allow(pool(&bound, uid)) {
                            tracing::warn!(uid, "agent connection refused: too many open");
                        }
                    }
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
                    if refused_log.allow(uid) {
                        tracing::warn!(uid, "admin connection refused: not root or the admin uid");
                    }
                    continue;
                }
                match admin_slots.take(0, limits.admin_connections, limits.admin_connections) {
                    Some(slot) => {
                        tokio::spawn(admin_connection(
                            stream, state.clone(), limits.clone(), stop.clone(), slot,
                        ));
                    }
                    None => {
                        if refused_log.allow(uid) {
                            tracing::warn!(uid, "admin connection refused: too many open");
                        }
                    }
                }
            }
        }
    };
    timers.abort();
    let _ = timers.await;
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
        tracing::error!(
            "a request failed while holding the gateway state; open refusal counts and the \
             clock were not written out, and the next start resumes the clock from the vault"
        );
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

#[cfg(test)]
mod tests {
    use super::{agent_slot, Limits, LineReader, Slots, Throttle};
    use crate::gateway::daemon::state::BoundUids;

    /// Uids credentials are bound to get their own slots, under the total;
    /// every other uid shares a few, so controlling many uids crowds out no
    /// bound one.
    #[test]
    fn unbound_uids_share_a_few_slots_and_every_slot_counts_toward_the_total() {
        let limits = Limits {
            connections_per_uid: 2,
            unbound_connections: 3,
            connections: 6,
            ..Limits::default()
        };
        let bound = BoundUids::default();
        bound.write().unwrap().extend([10, 11]);
        let slots = Slots::default();
        let take = |uid| agent_slot(&slots, &bound, uid, &limits);
        let unbound: Vec<_> = (100..103).map(|uid| take(uid).unwrap()).collect();
        assert!(take(103).is_none(), "the unbound share is full");
        assert!(take(u32::MAX).is_none());
        let a = [take(10).unwrap(), take(10).unwrap()];
        assert!(take(10).is_none(), "per bound uid");
        let b = take(11).unwrap();
        assert!(take(11).is_none(), "the total is reached");
        drop(unbound);
        assert!(take(11).is_some());
        drop((a, b));
        // A uid bound later gets its own slots.
        bound.write().unwrap().insert(103);
        assert!(take(103).is_some());
    }

    /// A gateway that does not accept is waited on for a bounded time, and
    /// a missing one is told apart from one that cannot be trusted.
    #[test]
    fn a_client_connect_is_bounded_and_says_why_it_failed() {
        use super::{connect_verified, ConnectError};
        use rustix::net::{AddressFamily, SocketAddrUnix, SocketType};
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let me = rustix::process::geteuid().as_raw();
        let path = dir.path().join("s");
        let absent = |r: Result<_, ConnectError>| matches!(r, Err(ConnectError::Absent(_)));
        assert!(absent(connect_verified(&path, me, Duration::from_secs(1))));
        assert!(absent(connect_verified(
            &dir.path().join("missing").join("s"),
            me,
            Duration::from_secs(1)
        )));
        // A listener that never accepts, its backlog already full.
        let listener = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None).unwrap();
        rustix::net::bind(&listener, &SocketAddrUnix::new(&path).unwrap()).unwrap();
        rustix::net::listen(&listener, 0).unwrap();
        let _queued = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let started = Instant::now();
        let waited = connect_verified(&path, me, Duration::from_millis(300));
        assert!(absent(waited), "the backlog is full");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(matches!(
            connect_verified(&path, me + 1, Duration::from_secs(1)),
            Err(ConnectError::Rejected(_))
        ));
        drop(listener);
        // A socket nothing listens on any more.
        assert!(absent(connect_verified(&path, me, Duration::from_secs(1))));
    }

    #[tokio::test(start_paused = true)]
    async fn refused_connections_are_logged_once_a_minute_per_uid() {
        let mut t = Throttle::default();
        assert!(t.allow(1));
        assert!(!t.allow(1));
        assert!(t.allow(2), "another uid is counted apart");
        tokio::time::advance(std::time::Duration::from_secs(59)).await;
        assert!(!t.allow(1));
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        assert!(t.allow(1));
        for uid in 10..2_000 {
            t.allow(uid);
        }
        assert!(t.0.len() <= 1_024, "bounded");
    }

    async fn lines(input: &[u8], max: usize) -> (Vec<Vec<u8>>, Option<std::io::ErrorKind>) {
        let mut reader = LineReader::new(input, max);
        let mut out = Vec::new();
        loop {
            match reader.next_line().await {
                Ok(Some(line)) => out.push(line.to_vec()),
                Ok(None) => return (out, None),
                Err(e) => return (out, Some(e.kind())),
            }
        }
    }

    #[tokio::test]
    async fn lines_are_split_and_a_trailing_partial_line_is_dropped() {
        let (got, err) = lines(b"a\r\nbc\n\n\rd\nend", 16).await;
        assert_eq!(
            got,
            [b"a".to_vec(), b"bc".to_vec(), vec![], b"\rd".to_vec()]
        );
        assert_eq!(err, None);
    }

    #[tokio::test]
    async fn a_line_over_the_limit_is_refused_even_with_its_newline() {
        for max in [1, 10, 8_191, 8_192, 8_193, 20_000] {
            let mut ok = vec![b'a'; max];
            ok.push(b'\n');
            let (got, err) = lines(&ok, max).await;
            assert_eq!((got.len(), err), (1, None), "a line of exactly {max}");
            let mut over = vec![b'a'; max + 1];
            over.extend_from_slice(b"\nb\n");
            let (got, err) = lines(&over, max).await;
            assert!(got.is_empty(), "{max}");
            assert_eq!(err, Some(std::io::ErrorKind::InvalidData), "{max}");
            let (_, err) = lines(&vec![b'a'; max + 1], max).await;
            assert_eq!(
                err,
                Some(std::io::ErrorKind::InvalidData),
                "{max} with no newline"
            );
        }
        // A short line after a long one that fit is unaffected.
        let mut input = vec![b'a'; 9_000];
        input.extend_from_slice(b"\nok\n");
        let (got, err) = lines(&input, 9_000).await;
        assert_eq!((got.len(), got[1].as_slice(), err), (2, &b"ok"[..], None));
    }

    /// A megabyte of empty lines is read in linear time: each byte is scanned
    /// once, not once per line.
    #[tokio::test]
    async fn many_tiny_lines_cost_linear_time() {
        let input = vec![b'\n'; 1 << 20];
        let started = std::time::Instant::now();
        let (got, err) = lines(&input, 1 << 20).await;
        assert_eq!((got.len(), err), (1 << 20, None));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(15),
            "{:?}",
            started.elapsed()
        );
    }
}
