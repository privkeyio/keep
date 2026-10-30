// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use crate::network::validate_relay_url;
use crate::{KeepMobile, KeepMobileError};
use keep_nip46::types::{
    ApprovalRequest, ApprovalResult, LogEvent, RememberDuration, ServerCallbacks,
};
use keep_nip46::{
    FrostSigner, NetworkFrostSigner, Permission, PreGrantedApp, RateLimitConfig, Server,
    ServerConfig, SignerHandler,
};
use nostr_sdk::{Kind, PublicKey};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

/// How long this side waits for the foreign prompt before denying.
///
/// The same 60 seconds keep-cli, keep-web and keep-desktop each apply to their
/// own approval channel, so no answer means a denial on every surface rather
/// than on three of four.
///
/// [`BunkerCallbacks::request_approval`] still requires the implementation to
/// bound its own wait, and keep-android does. This is the backstop for one that
/// does not: without it the contract is unenforceable from here, and an
/// implementation that waits forever stops every later request from every
/// client, because the handler reads one at a time.
///
/// The platform's own wait has to end before this one. Two timers of the same
/// length started at nearly the same moment let an approval land on the
/// platform side just after this side denied, and a platform that records the
/// approval, such as trusting a client on connect, then holds state this side
/// refused. [`nip46_approval_timeout_secs`] exports the value so a platform
/// can derive its wait from it rather than copy it.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

/// Seconds a bunker request waits for an answer before it is denied. A
/// platform's [`BunkerCallbacks::request_approval`] has to give up sooner.
#[uniffi::export]
pub fn nip46_approval_timeout_secs() -> u64 {
    APPROVAL_TIMEOUT.as_secs()
}

/// How many prompts may be waiting on the platform at once.
///
/// The handler reads one request at a time, so more than one is outstanding
/// only when earlier prompts timed out and their threads are still parked in a
/// platform call that never returned. Against such an implementation the
/// threads accumulate at roughly one per [`APPROVAL_TIMEOUT`], each holding a
/// stack, a JVM attachment and a copy of the request, which trades a stalled
/// bunker for memory pressure on the whole app. Past this many, the answer is
/// a refusal without asking.
///
/// keep-android bounds its own wait and caps its own concurrent prompts, so
/// this is not reached in practice; it is the ceiling for an implementation
/// that does neither.
const MAX_OUTSTANDING_APPROVALS: usize = 4;

const STATUS_STOPPED: u8 = 0;
const STATUS_STARTING: u8 = 1;
const STATUS_RUNNING: u8 = 2;
const STATUS_ERROR: u8 = 3;

#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum BunkerStatus {
    Stopped,
    Starting,
    Running,
    Error,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct BunkerLogEvent {
    pub app: String,
    pub action: String,
    pub success: bool,
    pub detail: Option<String>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct BunkerApprovalRequest {
    pub app_pubkey: String,
    pub app_name: String,
    pub method: String,
    pub event_kind: Option<u32>,
    pub event_content: Option<String>,
    pub requested_permissions: Option<String>,
    /// NIP-98 (kind 27235) HTTP-auth target the UI must show so the user is not
    /// approving a blind bearer credential. Present only for kind-27235 sign
    /// requests; `None` otherwise.
    pub http_auth: Option<BunkerHttpAuthDetails>,
}

/// The `u` (URL) and `method` a NIP-98 HTTP-auth signature will authenticate.
/// Render both in the approval prompt; a `None` field means the request omitted
/// that tag and should read as "unspecified", not be hidden.
#[derive(uniffi::Record, Clone, Debug)]
pub struct BunkerHttpAuthDetails {
    pub url: Option<String>,
    pub method: Option<String>,
}

/// How long an approval persists. Mirrors keep-android's
/// `nip55/PermissionEntities.kt::PermissionDuration` and Amber's `RememberType`
/// so the same enum maps cleanly to the existing `Nip46ApprovalScreen` picker.
/// `JustThisTime` is the one-shot default (no grant persisted); `Forever`
/// permanently auto-approves the (app, kind) pair; the timed variants persist
/// a per-(app, kind) grant with the matching expiry.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum BunkerRememberDuration {
    JustThisTime,
    OneMinute,
    FiveMinutes,
    TenMinutes,
    OneHour,
    OneDay,
    Forever,
}

impl From<BunkerRememberDuration> for RememberDuration {
    fn from(d: BunkerRememberDuration) -> Self {
        match d {
            BunkerRememberDuration::JustThisTime => RememberDuration::JustThisTime,
            BunkerRememberDuration::OneMinute => RememberDuration::OneMinute,
            BunkerRememberDuration::FiveMinutes => RememberDuration::FiveMinutes,
            BunkerRememberDuration::TenMinutes => RememberDuration::TenMinutes,
            BunkerRememberDuration::OneHour => RememberDuration::OneHour,
            BunkerRememberDuration::OneDay => RememberDuration::OneDay,
            BunkerRememberDuration::Forever => RememberDuration::Forever,
        }
    }
}

/// Result of an approval prompt as returned by the native UI.
///
/// `remember` is honoured on both answers, not only on approval. With
/// `approved=true` and a non-`JustThisTime` duration, a per-(app, kind) grant
/// is persisted and later requests skip the prompt. With `approved=false` and a
/// duration, the refusal is remembered the same way and later requests are
/// refused without prompting, which is what stops a client that retries from
/// re-asking indefinitely.
///
/// A native surface must therefore send `JustThisTime` on rejection unless the
/// user chose a duration for that answer. Passing through a value left over
/// from an earlier interaction would silently create a block nobody asked for.
/// Rejecting with `JustThisTime` records nothing.
#[derive(uniffi::Record, Clone, Copy, Debug)]
pub struct BunkerApprovalResult {
    pub approved: bool,
    pub remember: BunkerRememberDuration,
}

impl From<BunkerApprovalResult> for ApprovalResult {
    fn from(r: BunkerApprovalResult) -> Self {
        ApprovalResult {
            approved: r.approved,
            remember: r.remember.into(),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct ParsedBunkerUrl {
    pub pubkey: String,
    pub relays: Vec<String>,
    pub secret: Option<String>,
}

#[uniffi::export]
pub fn parse_bunker_url(url: &str) -> Result<ParsedBunkerUrl, KeepMobileError> {
    let (pubkey, relays, secret) = keep_nip46::parse_bunker_url(url)
        .map_err(|e| KeepMobileError::InvalidRelayUrl { msg: e })?;
    Ok(ParsedBunkerUrl {
        pubkey: pubkey.to_hex(),
        relays,
        secret,
    })
}

/// Why a NIP-46 connect was authorized, asserted by the signer core. The Kotlin
/// consumer should persist a client as authorized only for an explicit-consent
/// reason (`SecretMatched`/`UserApproved`), never for `AutoApproved`, so that
/// authorization does not depend on the callback merely having fired.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectAuthorization {
    SecretMatched,
    UserApproved,
    AutoApproved,
}

impl From<keep_nip46::types::ConnectAuthorization> for ConnectAuthorization {
    fn from(a: keep_nip46::types::ConnectAuthorization) -> Self {
        match a {
            keep_nip46::types::ConnectAuthorization::SecretMatched => Self::SecretMatched,
            keep_nip46::types::ConnectAuthorization::UserApproved => Self::UserApproved,
            keep_nip46::types::ConnectAuthorization::AutoApproved => Self::AutoApproved,
        }
    }
}

#[uniffi::export(with_foreign)]
pub trait BunkerCallbacks: Send + Sync {
    fn on_log(&self, event: BunkerLogEvent);
    /// Asks the operator to allow one request, blocking the caller until it is
    /// answered.
    ///
    /// The implementation must bound that wait and reject when it expires,
    /// sooner than [`nip46_approval_timeout_secs`]. The NIP-46 handler reads
    /// one request at a time, so a wait that never ends stops every later
    /// request from every client, not just this one.
    ///
    /// That requirement is backed rather than merely stated: an answer that
    /// does not arrive within [`APPROVAL_TIMEOUT`] is treated as a refusal, and
    /// an approval the implementation records after that point is one this
    /// side already refused.
    fn request_approval(&self, request: BunkerApprovalRequest) -> BunkerApprovalResult;
    /// Fired when an app completes the NIP-46 connect handshake. `pubkey` and
    /// `name` are untrusted, remote-derived values: render them as inert text,
    /// never as markup. `authorization` states why the core authorized the
    /// connect; persist authorization only for explicit-consent reasons.
    fn on_connect(&self, pubkey: String, name: String, authorization: ConnectAuthorization);
}

/// One outstanding prompt, released when the platform answers.
struct OutstandingApproval(Arc<AtomicUsize>);

impl OutstandingApproval {
    fn take(count: &Arc<AtomicUsize>) -> Option<Self> {
        count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |in_flight| {
                (in_flight < MAX_OUTSTANDING_APPROVALS).then_some(in_flight + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(count)))
    }
}

impl Drop for OutstandingApproval {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct CallbackBridge {
    callbacks: Arc<dyn BunkerCallbacks>,
    mobile: Arc<KeepMobile>,
    /// How long to wait for the foreign prompt. A field rather than the
    /// constant directly so a test can reach the timeout without taking a
    /// minute to do it.
    approval_timeout: Duration,
    /// The live generation this server started under. An approval that comes
    /// back after the node was torn down is refused, since the server would
    /// otherwise sign it with the share that was deleted or switched away
    /// from: the prompt blocks the server's own task, so the teardown cannot
    /// stop it until the prompt returns.
    generation: u64,
    /// Prompts handed to the platform that have not come back, including the
    /// ones this side has already stopped waiting for.
    outstanding: Arc<AtomicUsize>,
    /// The transport key and group this server serves under, which the grants
    /// it persists are tagged with.
    grant_scope: String,
    /// Cleared by `stop_bunker`, after which this server persists nothing.
    serving: Arc<AtomicBool>,
}

impl CallbackBridge {
    /// A refusal that grants nothing. `JustThisTime` carries no duration, so
    /// the handler cannot turn it into a stored denial or a grant.
    fn refused() -> ApprovalResult {
        ApprovalResult {
            approved: false,
            remember: RememberDuration::JustThisTime,
        }
    }
}

impl ServerCallbacks for CallbackBridge {
    fn on_log(&self, event: LogEvent) {
        self.callbacks.on_log(BunkerLogEvent {
            app: event.app,
            action: event.action,
            success: event.success,
            detail: event.detail,
        });
    }

    fn request_approval(&self, request: ApprovalRequest) -> ApprovalResult {
        let request = BunkerApprovalRequest {
            app_pubkey: request.app_pubkey.to_hex(),
            app_name: request.app_name,
            method: request.method,
            event_kind: request.event_kind.map(|k| k.as_u16() as u32),
            event_content: request.event_content,
            requested_permissions: request.requested_permissions,
            http_auth: request.http_auth.map(|d| BunkerHttpAuthDetails {
                url: d.url,
                method: d.method,
            }),
        };
        // A synchronous foreign call cannot be interrupted, so the wait is
        // bounded by making it somebody else's thread and timing out the
        // answer. The thread outlives the timeout: it stays parked in the
        // platform prompt until that returns, and its answer is dropped. That
        // is the cost of bounding a call that offers no cancellation, and it is
        // preferable to the alternative, where one unanswered prompt holds the
        // handler forever.
        //
        // Kept for the log, because the request itself moves onto the thread
        // and a refusal that does not say which app it refused is not much use
        // when reading one back. The name is left out deliberately: it is
        // remote-derived and unbounded, where the pubkey and method are
        // neither.
        let asked_by = request.app_pubkey.clone();
        let asked_for = request.method.clone();

        // A slot is taken before the thread exists, and released by the guard
        // when the platform finally answers, so the count tracks threads still
        // parked rather than requests still being waited on.
        let slot = match OutstandingApproval::take(&self.outstanding) {
            Some(slot) => slot,
            None => {
                tracing::warn!(
                    "Refusing {asked_for} from {asked_by} without asking: \
                     {MAX_OUTSTANDING_APPROVALS} earlier prompts have not come back"
                );
                return Self::refused();
            }
        };

        let (tx, rx) = std::sync::mpsc::channel();
        let callbacks = Arc::clone(&self.callbacks);
        // Named, and a failure to spawn is a refusal rather than a panic.
        // `std::thread::spawn` panics when the OS refuses the thread, and that
        // panic unwinds through the handler and out of the notification loop,
        // which stops the bunker while its status still reads running.
        if let Err(e) = std::thread::Builder::new()
            .name("nip46-approval".into())
            .spawn(move || {
                // Dropped when the platform returns, however it returns, so a
                // callback that panics releases its slot too.
                let _slot = slot;
                // Ignored deliberately: a send fails only once the timeout
                // below has already answered for this request and dropped the
                // receiver.
                let _ = tx.send(callbacks.request_approval(request));
            })
        {
            tracing::error!("Refusing {asked_for} from {asked_by}, no thread to ask on: {e}");
            return Self::refused();
        }

        // Hand this worker's core off for the wait, as the FROST approval path
        // does in `lib.rs`. Queued tasks on the worker are stealable either
        // way; what `block_in_place` adds is moving the one task in the LIFO
        // slot back to the run queue and sending the core to another thread, so
        // the worker's work keeps draining instead of waiting out the prompt.
        // Later NIP-46 requests stall regardless, since the handler's
        // notification loop reads one at a time; what the timeout changes is
        // that the stall is now bounded.
        //
        // It also leaves the runtime for the duration of the wait, so a foreign
        // callback that re-enters an exported method built on
        // `runtime.block_on` stops panicking and can deadlock instead if it
        // waits on this runtime. Nothing in keep-android does that today.
        //
        // The gate reads the flavor rather than just `try_current`, because
        // `block_in_place` panics on a current-thread runtime where
        // `try_current` succeeds. It is still narrower than tokio's real
        // precondition, which also forbids a `LocalSet` on a multi-thread
        // runtime; nothing in-tree uses one.
        let blocking = matches!(
            tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()),
            Ok(tokio::runtime::RuntimeFlavor::MultiThread)
        );
        let answered = if blocking {
            tokio::task::block_in_place(|| rx.recv_timeout(self.approval_timeout))
        } else {
            rx.recv_timeout(self.approval_timeout)
        };

        match answered {
            Ok(_) if *self.mobile.live_generation.borrow() != self.generation => {
                tracing::warn!(
                    "Refusing {asked_for} from {asked_by}: the share changed while it was asked"
                );
                Self::refused()
            }
            Ok(result) => result.into(),
            // Denied, not retried. The operator did not answer, and the
            // request's own rate limiting decides whether the client gets
            // another prompt. The two errors are reported apart because they
            // are different events: one is nobody answering, the other is the
            // platform callback having panicked, which fails closed at once.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                tracing::warn!(
                    "Refusing {asked_for} from {asked_by}: no answer within {}s",
                    self.approval_timeout.as_secs()
                );
                Self::refused()
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                tracing::error!("Refusing {asked_for} from {asked_by}: the prompt did not return");
                Self::refused()
            }
        }
    }

    fn on_connect(
        &self,
        pubkey: &str,
        name: &str,
        authorization: keep_nip46::types::ConnectAuthorization,
    ) {
        self.callbacks
            .on_connect(pubkey.to_string(), name.to_string(), authorization.into());
    }

    fn persist_permissions(&self, grants: Vec<keep_core::relay::StoredBunkerPermission>) {
        let serving = || {
            self.serving.load(Ordering::Acquire)
                && *self.mobile.live_generation.borrow() == self.generation
        };
        if let Err(e) = self
            .mobile
            .persist_bunker_permissions(grants, &self.grant_scope, serving)
        {
            tracing::warn!("failed to persist bunker permissions: {e}");
        }
    }
}

/// How `stop_bunker` and a start meet, kept under one lock: a stop either
/// signals a published server or, when a start is still in flight, leaves a
/// request that start honors instead of publishing.
#[derive(Default)]
struct Lifecycle {
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// From claiming the status, before the start waits on the start lock, to
    /// publishing or failing.
    starting: bool,
    stop_requested: bool,
}

#[derive(uniffi::Object)]
pub struct BunkerHandler {
    mobile: Arc<KeepMobile>,
    status: Arc<AtomicU8>,
    bunker_url: std::sync::Mutex<Option<String>>,
    lifecycle: std::sync::Mutex<Lifecycle>,
    /// The `serving` flag of the server last started, which `stop_bunker`
    /// clears.
    serving: std::sync::Mutex<Arc<AtomicBool>>,
}

impl Drop for BunkerHandler {
    // Dropping the handler drops the shutdown sender, which stops its server,
    // but an approval still open there could persist before it does.
    fn drop(&mut self) {
        self.serving
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .store(false, Ordering::Release);
    }
}

impl BunkerHandler {
    fn set_status(&self, status: u8) {
        self.status.store(status, Ordering::Release);
    }

    fn load_status(&self) -> u8 {
        self.status.load(Ordering::Acquire)
    }

    fn lifecycle(&self) -> std::sync::MutexGuard<'_, Lifecycle> {
        self.lifecycle.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Stop any running bunker, whichever handler started it: `stop_bunker`
    /// reaches only one this handler started, so the generation moves too.
    fn stop_serving(&self) {
        self.stop_bunker();
        self.mobile
            .live_generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    /// Persist a fresh connect secret, and a fresh transport secret too when
    /// `transport`, with `change` applied to the rest of the record. Callers
    /// hold the start lock and have stopped the bunker.
    fn rewrite_bunker_config(
        &self,
        transport: bool,
        change: impl FnOnce(&mut crate::persistence::StoredBunkerConfig),
    ) -> Result<(), KeepMobileError> {
        self.with_bunker_config(|stored| {
            if transport {
                let secret = Zeroizing::new(keep_core::crypto::try_random_bytes::<32>()?);
                stored.transport_secret = Some(hex::encode(&secret[..]));
            }
            let connect = Zeroizing::new(keep_core::crypto::try_random_bytes::<16>()?);
            stored.connect_secret = Some(hex::encode(&connect[..]));
            change(stored);
            crate::persistence::persist_bunker_config(
                &self.mobile.storage,
                crate::BUNKER_CONFIG_STORAGE_KEY,
                stored,
            )
        })
    }

    /// Runs `f` on the stored bunker config under its lock.
    fn with_bunker_config<T>(
        &self,
        f: impl FnOnce(&mut crate::persistence::StoredBunkerConfig) -> Result<T, KeepMobileError>,
    ) -> Result<T, KeepMobileError> {
        let _guard =
            self.mobile
                .bunker_config_lock
                .lock()
                .map_err(|_| KeepMobileError::StorageError {
                    msg: "bunker config lock poisoned".into(),
                })?;

        let mut stored = crate::persistence::load_bunker_config(
            &self.mobile.storage,
            crate::BUNKER_CONFIG_STORAGE_KEY,
        )?
        .unwrap_or_default();

        // Zeroize the decrypted plaintext secrets in `stored` on every exit path
        // (the new secrets on success, the loaded old secrets on any error),
        // since `StoredBunkerConfig` is not `ZeroizeOnDrop`.
        let result = f(&mut stored);

        if let Some(s) = stored.transport_secret.as_mut() {
            s.zeroize();
        }
        if let Some(s) = stored.connect_secret.as_mut() {
            s.zeroize();
        }
        result
    }

    /// The clients a revoke left pending: whether every client was revoked,
    /// and the hex pubkeys of single revokes.
    fn pending_revokes(&self) -> Result<(bool, Vec<String>), KeepMobileError> {
        self.with_bunker_config(|stored| {
            Ok((stored.pending_revoke_all, stored.pending_revokes.clone()))
        })
    }

    /// Drops the persisted grants of every client a revoke left pending, then
    /// clears what it finished.
    fn finish_pending_revokes(&self) -> Result<(), KeepMobileError> {
        let (all, clients) = self.pending_revokes()?;
        if !all && clients.is_empty() {
            return Ok(());
        }
        if all {
            self.mobile.forget_bunker_permissions(None)?;
        }
        for client in &clients {
            // Written by `revoke_client` from a parsed key; one that does not
            // parse names no grant.
            if let Ok(client) = PublicKey::from_hex(client) {
                self.mobile.forget_bunker_permissions(Some(&client))?;
            }
        }
        self.with_bunker_config(|stored| {
            stored.pending_revoke_all &= !all;
            stored.pending_revokes.retain(|c| !clients.contains(c));
            crate::persistence::persist_bunker_config(
                &self.mobile.storage,
                crate::BUNKER_CONFIG_STORAGE_KEY,
                stored,
            )
        })
    }

    /// The persisted grants a start restores, less those of any client a
    /// revoke left pending. Those revokes are finished first where they can
    /// be. Where they cannot, the grants stay on disk but are not served, and
    /// the engine's next persist replaces them.
    fn grants_to_restore(&self, scope: &str) -> Result<Vec<PreGrantedApp>, KeepMobileError> {
        let (all, clients) = self.pending_revokes()?;
        if let Err(e) = self.finish_pending_revokes() {
            tracing::warn!(error = %e, "revoked clients' grants are still stored; not restoring them");
        }
        if all {
            return Ok(Vec::new());
        }
        let revoked: std::collections::HashSet<PublicKey> = clients
            .iter()
            .filter_map(|c| PublicKey::from_hex(c).ok())
            .collect();
        Ok(self
            .mobile
            .load_bunker_permissions(scope)
            .iter()
            .filter(|grant| {
                PublicKey::from_hex(&grant.pubkey_hex).map_or(true, |pk| !revoked.contains(&pk))
            })
            .filter_map(PreGrantedApp::from_stored)
            .collect())
    }

    /// Records a revoke: a new connect secret and the pending mark `change`
    /// sets, written together, then the grants dropped. Once that write
    /// lands the revoke holds, since a start never serves a pending client's
    /// grants, so a failure dropping them is logged rather than returned. If
    /// the write fails the grants are still dropped where they can be, and
    /// its error returned.
    fn record_revoke(
        &self,
        change: impl FnOnce(&mut crate::persistence::StoredBunkerConfig),
        forget: Option<&PublicKey>,
    ) -> Result<(), KeepMobileError> {
        if let Err(e) = self.rewrite_bunker_config(false, change) {
            if let Err(forget_err) = self.mobile.forget_bunker_permissions(forget) {
                tracing::warn!(error = %forget_err, "could not drop revoked grants either");
            }
            return Err(e);
        }
        if let Err(e) = self.finish_pending_revokes() {
            tracing::warn!(error = %e, "revoked grants are still stored; a start will not restore them");
        }
        Ok(())
    }

    /// See `KeepMobile::bunker_start_lock`. It guards no data, so a panic
    /// while it was held leaves nothing to repair.
    fn start_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.mobile
            .bunker_start_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Publish a started server, making its engine the one revokes reach and
    /// its `serving` flag the one `stop_bunker` clears, unless a stop came while
    /// it was starting. Returns whether it was published; when it was not, the
    /// caller stops the server.
    fn publish_server(
        &self,
        url: String,
        handler: &Arc<SignerHandler>,
        serving: Arc<AtomicBool>,
        tx: tokio::sync::oneshot::Sender<()>,
    ) -> bool {
        let mut lifecycle = self.lifecycle();
        lifecycle.starting = false;
        if std::mem::take(&mut lifecycle.stop_requested) {
            return false;
        }
        *self.bunker_url.lock().unwrap_or_else(|e| e.into_inner()) = Some(url);
        *self
            .mobile
            .live_bunker
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Arc::downgrade(handler));
        *self.serving.lock().unwrap_or_else(|e| e.into_inner()) = serving;
        lifecycle.shutdown_tx = Some(tx);
        true
    }

    /// Run a published server. RUNNING is stored before its task is spawned,
    /// so it is what a caller reads once `start_bunker` returns, and the task
    /// can only replace it with the state the server ends in.
    fn serve(
        &self,
        server: Server,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
        invalidated: tokio::sync::watch::Receiver<u64>,
        serving: Arc<AtomicBool>,
    ) -> tokio::task::JoinHandle<()> {
        self.set_status(STATUS_RUNNING);
        self.mobile.runtime.spawn(run_server(
            server,
            shutdown_rx,
            invalidated,
            Arc::clone(&self.status),
            serving,
        ))
    }

    fn live_handler(&self) -> Option<Arc<SignerHandler>> {
        self.mobile
            .live_bunker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
    }
}

#[uniffi::export]
impl BunkerHandler {
    #[uniffi::constructor]
    pub fn new(mobile: Arc<KeepMobile>) -> Self {
        Self {
            mobile,
            status: Arc::new(AtomicU8::new(STATUS_STOPPED)),
            bunker_url: std::sync::Mutex::new(None),
            lifecycle: std::sync::Mutex::new(Lifecycle::default()),
            serving: std::sync::Mutex::new(Arc::new(AtomicBool::new(false))),
        }
    }

    pub fn start_bunker(
        &self,
        relays: Vec<String>,
        callbacks: Arc<dyn BunkerCallbacks>,
    ) -> Result<(), KeepMobileError> {
        self.do_start_bunker(relays, callbacks, None)
    }

    pub fn start_bunker_with_proxy(
        &self,
        relays: Vec<String>,
        callbacks: Arc<dyn BunkerCallbacks>,
        proxy_host: String,
        proxy_port: u16,
    ) -> Result<(), KeepMobileError> {
        let proxy = crate::network::parse_loopback_proxy(&proxy_host, proxy_port)?;
        self.do_start_bunker(relays, callbacks, Some(proxy))
    }

    pub fn stop_bunker(&self) {
        {
            let mut lifecycle = self.lifecycle();
            if let Some(tx) = lifecycle.shutdown_tx.take() {
                let _ = tx.send(());
            }
            if lifecycle.starting {
                lifecycle.stop_requested = true;
            }
        }
        self.serving
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .store(false, Ordering::Release);
        *self.bunker_url.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Revokes a single client: drops its grants in the running engine, so any
    /// remembered (auto-approved) kinds stop signing immediately, and its
    /// persisted grants, so a later start does not restore them, and takes it
    /// out of `authorized_clients`. The pubkey is the client's hex-encoded
    /// x-only public key.
    ///
    /// The client still holds the connect secret, which would let it connect
    /// again under this key or a fresh one, so the running bunker is stopped
    /// and the secret replaced: the caller starts it again, and publishes the
    /// new URL. The transport key stays, so other clients' remembered grants
    /// stay, and those that sign without sending `connect` again carry on. A
    /// client that was only connected loses its session at the stop, and one
    /// that sends `connect` again needs the new URL.
    ///
    /// The new secret, the client's removal and a pending mark are written
    /// together, and its grants dropped after. A start never restores a
    /// pending client's grants, so once that write lands the revoke holds even
    /// if dropping them fails, and that is not an error. On `Err` the write
    /// failed and the old secret is still valid for the next start: callers
    /// must not report success. The bunker is left stopped either way.
    pub fn revoke_client(&self, pubkey: String) -> Result<(), KeepMobileError> {
        let pubkey = PublicKey::from_hex(&pubkey).map_err(|_| KeepMobileError::InvalidInput {
            msg: "Invalid client pubkey hex".into(),
        })?;
        // A start between reading the persisted grants and publishing its
        // handler would restore what this removes, unseen by either step.
        let _start_guard = self.start_guard();
        // Stopped first, so no error below leaves the old secret serving.
        self.stop_serving();
        if let Some(handler) = self.live_handler() {
            self.mobile
                .runtime
                .block_on(async { handler.revoke_client(&pubkey).await });
        }
        self.record_revoke(
            |stored| {
                stored
                    .authorized_clients
                    .retain(|c| PublicKey::parse(c).ok() != Some(pubkey));
                let hex = pubkey.to_hex();
                if !stored.pending_revokes.contains(&hex) {
                    stored.pending_revokes.push(hex);
                }
            },
            Some(&pubkey),
        )
    }

    /// Revokes every client: in the running engine, in the persisted grants
    /// and in `authorized_clients`, and with a new connect secret, as
    /// `revoke_client` does for one.
    pub fn revoke_all_clients(&self) -> Result<(), KeepMobileError> {
        let _start_guard = self.start_guard();
        self.stop_serving();
        if let Some(handler) = self.live_handler() {
            self.mobile
                .runtime
                .block_on(async { handler.revoke_all_clients().await });
        }
        self.record_revoke(
            |stored| {
                stored.authorized_clients.clear();
                stored.pending_revoke_all = true;
            },
            None,
        )
    }

    /// Rotate the bunker credentials: generate a fresh transport secret (new
    /// bunker pubkey) and connect secret (new URL) and persist them, so any
    /// previously distributed `bunker://` URL can no longer pair or sign — the
    /// remedy for a leaked URL. Signals any running bunker to stop (dropping its
    /// in-memory grants); the caller restarts it to obtain and publish the new
    /// URL, and existing clients must re-pair.
    ///
    /// A start in flight on this handler is cancelled and fails with "The bunker
    /// was stopped while it was starting"; the caller starts it again.
    ///
    /// On `Err`, rotation did NOT happen and the previous (possibly leaked)
    /// credential is still valid — callers must not report success.
    pub fn rotate_bunker_credentials(&self) -> Result<(), KeepMobileError> {
        // Serialize against `do_start_bunker`, which holds this from before it
        // reads the keys until it publishes: any start either published (and
        // the stop below signals it) or is waiting here, and the stop below
        // cancels one started through this handler.
        let _start_guard = self.start_guard();

        // Signal the running bunker to stop so its old keys/URL and grants tear
        // down; server shutdown completes asynchronously in its own task.
        self.stop_serving();
        self.rewrite_bunker_config(true, |_| {})
    }

    pub fn get_bunker_url(&self) -> Option<String> {
        self.bunker_url
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn get_bunker_status(&self) -> BunkerStatus {
        match self.load_status() {
            STATUS_STARTING => BunkerStatus::Starting,
            STATUS_RUNNING => BunkerStatus::Running,
            STATUS_ERROR => BunkerStatus::Error,
            _ => BunkerStatus::Stopped,
        }
    }
}

/// Global event kinds the bunker signs without a per-request prompt for any
/// client. Kept to the safe engine default (kind 7 reactions) only. NIP-98 is
/// NOT global; see `bunker_connect_auto_approve_kinds`.
fn bunker_auto_approve_kinds() -> std::collections::HashSet<Kind> {
    std::collections::HashSet::from([Kind::Reaction])
}

/// Event kinds auto-approved per-app for each client that completes the connect
/// handshake, scoped to that client's pubkey instead of granted globally.
///
/// **Empty by default as of #575.** Previously this returned `{NIP98_HTTP_AUTH}`
/// so web clients such as nostr-tools' `BunkerSigner` (which signs a fresh NIP-98
/// event per HTTP call) would not be blocked by a 60s-per-request prompt. That
/// silent grant turned the bunker URL + connect secret into an HTTP-auth bearer
/// credential: anyone holding it could mint NIP-98 tokens authenticating as the
/// user to any URL/method with no prompt. Per-app scoping does not bound that
/// threat as long as the connect secret is reusable.
///
/// NIP-98 sign requests now fall through to the existing per-request approval
/// callback. The next step (mobile UI, tracked as a follow-up under #575) is to
/// extend the approval response with a remember-duration so the user can opt in
/// to "remember for 1 hour / 1 day / always" after seeing the first request,
/// matching Amber's UX without the silent-grant trade-off.
fn bunker_connect_auto_approve_kinds() -> std::collections::HashSet<Kind> {
    std::collections::HashSet::new()
}

/// What the grants of a bunker serving with `transport_secret` for
/// `group_pubkey` are tagged with: its bunker pubkey and the group, both hex.
/// A grant is for the identity it was approved under, through the bunker key
/// it was approved on.
fn grant_scope(
    transport_secret: &[u8; 32],
    group_pubkey: &[u8; 32],
) -> Result<String, KeepMobileError> {
    let transport = nostr_sdk::SecretKey::from_slice(transport_secret)
        .map(|key| nostr_sdk::Keys::new(key).public_key().to_hex())
        .map_err(|e| KeepMobileError::InitializationFailed { msg: e.to_string() })?;
    Ok(format!("{transport}:{}", hex::encode(group_pubkey)))
}

/// Decodes a persisted transport secret, returning `None` when the stored value
/// is malformed, the wrong length, or not a valid secp256k1 scalar (zero or
/// `>=` the curve order). The value is persisted and reused on every start, so a
/// corrupt-but-32-byte hex string would otherwise be cached forever and brick
/// the bunker permanently; rejecting it here lets `load_or_create_bunker_keys`
/// regenerate and self-heal. The decoded buffer is zeroized on drop.
fn decode_transport_secret(hex_str: &str) -> Option<Zeroizing<[u8; 32]>> {
    let decoded = Zeroizing::new(hex::decode(hex_str).ok()?);
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(decoded.as_slice().try_into().ok()?);
    nostr_sdk::secp256k1::SecretKey::from_slice(bytes.as_slice()).ok()?;
    Some(bytes)
}

/// Loads the persisted bunker transport key + connect secret, generating and
/// persisting fresh values on first start (or when absent/corrupt). The
/// bunker:// pubkey is derived from the transport key and the URL embeds the
/// connect secret, so reusing the persisted values keeps the bunker URL stable
/// across service restarts — saved client sessions (readstr and the like) keep
/// receiving responses after a reboot or off/on toggle. The secrets live in the
/// same SQLCipher-backed SecureStorage as the FROST share material.
fn load_or_create_bunker_keys(
    mobile: &KeepMobile,
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<String>), KeepMobileError> {
    let storage = &mobile.storage;

    // Serialize the whole load-modify-store against `save_bunker_config`, which
    // performs the same read-modify-write on this record. Without the lock a
    // config save that read a stale snapshot (transport_secret: None) could
    // overwrite the keys we generate and persist here, rotating the bunker URL
    // and breaking already-paired clients — the failure this code prevents.
    let _guard = mobile
        .bunker_config_lock
        .lock()
        .map_err(|_| KeepMobileError::StorageError {
            msg: "bunker config lock poisoned".into(),
        })?;

    let mut stored =
        crate::persistence::load_bunker_config(storage, crate::BUNKER_CONFIG_STORAGE_KEY)?
            .unwrap_or_default();

    let mut dirty = false;

    let transport_secret = match stored
        .transport_secret
        .as_deref()
        .and_then(decode_transport_secret)
    {
        Some(bytes) => bytes,
        None => {
            let bytes = Zeroizing::new(keep_core::crypto::try_random_bytes::<32>()?);
            stored.transport_secret = Some(hex::encode(&bytes[..]));
            dirty = true;
            bytes
        }
    };

    let connect_secret = match stored.connect_secret.as_deref() {
        Some(secret) if !secret.is_empty() => Zeroizing::new(secret.to_owned()),
        _ => {
            let secret = Zeroizing::new(hex::encode(keep_core::crypto::try_random_bytes::<16>()?));
            stored.connect_secret = Some(secret.as_str().to_owned());
            dirty = true;
            secret
        }
    };

    if dirty {
        crate::persistence::persist_bunker_config(
            storage,
            crate::BUNKER_CONFIG_STORAGE_KEY,
            &stored,
        )?;
    }

    // `stored` still holds a plaintext hex copy of the transport and connect
    // secrets; clear them before drop so the decrypted key material does not
    // linger in memory.
    if let Some(s) = stored.transport_secret.as_mut() {
        s.zeroize();
    }
    if let Some(s) = stored.connect_secret.as_mut() {
        s.zeroize();
    }

    Ok((transport_secret, connect_secret))
}

impl BunkerHandler {
    fn do_start_bunker(
        &self,
        relays: Vec<String>,
        callbacks: Arc<dyn BunkerCallbacks>,
        proxy: Option<std::net::SocketAddr>,
    ) -> Result<(), KeepMobileError> {
        if relays.is_empty() {
            return Err(KeepMobileError::InvalidRelayUrl {
                msg: "At least one relay required".into(),
            });
        }

        for relay in &relays {
            validate_relay_url(relay)?;
        }

        // Claimed before waiting on the start lock, so a stop made while this
        // start waits is recorded for it.
        {
            let mut lifecycle = self.lifecycle();
            if self
                .status
                .compare_exchange(
                    STATUS_STOPPED,
                    STATUS_STARTING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return Err(KeepMobileError::InitializationFailed {
                    msg: "Bunker already running or starting".into(),
                });
            }
            lifecycle.starting = true;
            lifecycle.stop_requested = false;
        }

        // Held for the whole start, so a revoke or rotation cannot fall between
        // reading the persisted grants and publishing the engine, and a
        // rotation's new keys are read by any start that waited on it.
        let _start_guard = self.start_guard();

        // Cert-pin the bunker relays before serving, matching do_initialize.
        // Held on the sync stack across the block_on (like do_initialize) so the
        // trust-on-first-use pin persist cannot race a concurrent cert-pin FFI
        // call. Lock order bunker_start_lock -> cert_pin_lock is acyclic: the
        // cert-pin FFI methods and init never take bunker_start_lock.
        let _cert_pins = self
            .mobile
            .cert_pin_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Before the node is read, so a teardown after this point stops the
        // server even if the node it read is the one torn down.
        let mut invalidated = self.mobile.live_generation.subscribe();
        let generation = *invalidated.borrow_and_update();
        let result = self.mobile.runtime.block_on(async {
            let verified_relays = self.mobile.verify_and_pin_relays(&relays, proxy).await?;

            let node_guard = self.mobile.node.read().await;
            let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;

            // An imported nsec is a 1-of-1 FROST share; its single locally-held
            // share satisfies the threshold, so the bunker can sign locally
            // instead of dispatching a networked FROST session that no peer will
            // ever answer (which otherwise times out). Multi-share groups still
            // need the network to gather co-signers.
            //
            // The gate, the group pubkey, and the signer share all come from the
            // node's in-memory, decrypted-at-init copy (loaded while biometric
            // auth was available). Deriving the group pubkey from plaintext
            // storage metadata instead could disagree with the share FrostSigner
            // is built from and fail the bunker outright rather than fall back to
            // the network path. Note the in-memory metadata is not itself
            // cryptographically authenticated (ShareMetadata is stored plaintext
            // beside the AEAD ciphertext; only the key_package is integrity-
            // protected), but using it consistently keeps the gate and signer in
            // agreement. Re-decrypting from storage here would also fail: the
            // bunker auto-starts in a background service with no staged biometric
            // cipher, so the storage callback throws StorageException.
            let group_pubkey_bytes: [u8; 32] = node.share_package().metadata.group_pubkey;
            let local_complete = {
                let meta = &node.share_package().metadata;
                meta.threshold == 1 && meta.total_shares == 1
            };

            let (transport_secret, connect_secret) = load_or_create_bunker_keys(&self.mobile)?;
            let grant_scope = grant_scope(&transport_secret, &group_pubkey_bytes)?;

            // Restore persisted per-(app, kind) remember-grants so they survive a
            // bunker restart. The engine is the single source of truth for these
            // grants; they are durably mirrored to the relay config on every
            // grant/revoke via the `persist_permissions` callback below.
            let pre_grants = self.grants_to_restore(&grant_scope)?;

            let config = ServerConfig {
                rate_limit: Some(RateLimitConfig::default()),
                expected_secret: Some(connect_secret.as_str().to_owned()),
                pre_grants,
                // Approving the bunker connection (the secret in the bunker URL
                // is the grant) must let the client sign, mirroring the
                // always-on bunker in keep-web. Without this the client only
                // gets get_public_key and every sign_event is denied — the
                // client logs in but its signed-request calls all fail.
                //
                // TRUST MODEL: this connect grant authorizes signing, but
                // NIP-98 (kind 27235) is NEVER auto-approved. Per #575 it always
                // falls through to the per-request approval prompt and is never
                // remembered (see `bunker_connect_auto_approve_kinds`, now
                // empty), so a shared connect secret cannot silently mint NIP-98
                // HTTP-auth tokens. The connect secret is still a shared bearer
                // credential for non-NIP-98 signing; a per-app/URL-method
                // allowlist is follow-up work.
                connect_grant: Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT,
                auto_approve_kinds: bunker_auto_approve_kinds(),
                connect_auto_approve_kinds: bunker_connect_auto_approve_kinds(),
                // Enforce the SPKI pin inside the handshake of the socket that
                // carries remote-signing traffic, not only on the
                // `verify_and_pin_relays` probe above. Read-only: the live
                // handshake never records a pin, so a bunker reconnect cannot
                // write trust into the pin store.
                tls_pinning: Some(self.mobile.live_pinning()?),
                ..ServerConfig::default()
            };

            let serving = Arc::new(AtomicBool::new(true));
            let server_callbacks = Some(Arc::new(CallbackBridge {
                approval_timeout: APPROVAL_TIMEOUT,
                generation,
                outstanding: Arc::new(AtomicUsize::new(0)),
                callbacks,
                mobile: Arc::clone(&self.mobile),
                grant_scope,
                serving: Arc::clone(&serving),
            }) as Arc<dyn ServerCallbacks>);

            let mut server = if local_complete {
                // Wrap the node's in-memory share in a FrostSigner for local
                // signing. The share is re-encrypted under an ephemeral data key
                // purely to satisfy the FrostSigner API; it never leaves the
                // process.
                let active_share = node.share_package();
                let data_key = keep_core::crypto::SecretKey::generate()
                    .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?;
                let stored = keep_core::frost::StoredShare::encrypt(active_share, &data_key)
                    .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?;
                let frost_signer = FrostSigner::new(group_pubkey_bytes, vec![stored], data_key)
                    .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?;

                Server::new_frost_with_proxy(
                    frost_signer,
                    *transport_secret,
                    &verified_relays,
                    server_callbacks,
                    config,
                    proxy,
                )
                .await
                .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?
            } else {
                let network_signer =
                    NetworkFrostSigner::with_shared_node(group_pubkey_bytes, Arc::clone(node));

                Server::new_network_frost_with_proxy(
                    network_signer,
                    *transport_secret,
                    &verified_relays,
                    server_callbacks,
                    config,
                    proxy,
                )
                .await
                .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?
            };

            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
            let published = self.publish_server(
                server.bunker_url(),
                &server.handler(),
                Arc::clone(&serving),
                shutdown_tx,
            );
            if !published {
                server.stop().await;
                return Err(KeepMobileError::InitializationFailed {
                    msg: "The bunker was stopped while it was starting".into(),
                });
            }

            self.serve(server, shutdown_rx, invalidated, serving);

            Ok::<(), KeepMobileError>(())
        });

        if result.is_err() {
            let mut lifecycle = self.lifecycle();
            lifecycle.starting = false;
            lifecycle.stop_requested = false;
            self.set_status(STATUS_STOPPED);
        }
        result
    }
}

async fn run_server(
    mut server: Server,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    mut invalidated: tokio::sync::watch::Receiver<u64>,
    status: Arc<AtomicU8>,
    serving: Arc<AtomicBool>,
) {
    // Biased so a teardown is seen before more requests are drained, since
    // those that need no prompt would otherwise sign with the old share.
    tokio::select! {
        biased;
        // The share was deleted, switched or reloaded, or the relay pins
        // changed, so this server is signing with a share or trusting pins
        // that are no longer current. It stays stopped until the app starts a
        // new one.
        _ = invalidated.changed() => {
            server.stop().await;
            status.store(STATUS_STOPPED, Ordering::Release);
        }
        // Before `run` for the same reason: a stopped server must not sign one
        // more queued request, which a revoke made since could not reach.
        _ = shutdown_rx => {
            server.stop().await;
            status.store(STATUS_STOPPED, Ordering::Release);
        }
        result = server.run() => {
            match result {
                Ok(()) => status.store(STATUS_STOPPED, Ordering::Release),
                Err(_) => status.store(STATUS_ERROR, Ordering::Release),
            };
        }
    }
    // However it stopped, including a handler dropped without `stop_bunker`.
    serving.store(false, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{load_bunker_config, persist_bunker_config, StoredBunkerConfig};
    use crate::storage::{SecureStorage, ShareMetadataInfo};
    use crate::KeepMobileError;
    use crate::BUNKER_CONFIG_STORAGE_KEY;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Default)]
    struct MemStorage {
        data: Mutex<HashMap<String, Vec<u8>>>,
        /// A key whose writes fail, as a platform write can.
        fail_writes_to: Mutex<Option<String>>,
    }

    impl SecureStorage for MemStorage {
        fn store_share(
            &self,
            _data: Vec<u8>,
            _metadata: ShareMetadataInfo,
        ) -> Result<(), KeepMobileError> {
            unimplemented!()
        }
        fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
            unimplemented!()
        }
        fn has_share(&self) -> bool {
            false
        }
        fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
            None
        }
        fn delete_share(&self) -> Result<(), KeepMobileError> {
            unimplemented!()
        }
        fn store_share_by_key(
            &self,
            key: String,
            data: Vec<u8>,
            _metadata: ShareMetadataInfo,
        ) -> Result<(), KeepMobileError> {
            if self.fail_writes_to.lock().unwrap().as_deref() == Some(key.as_str()) {
                return Err(KeepMobileError::StorageError {
                    msg: "write failed".into(),
                });
            }
            self.data.lock().unwrap().insert(key, data);
            Ok(())
        }
        fn load_share_by_key(&self, key: String) -> Result<Vec<u8>, KeepMobileError> {
            self.data
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .ok_or(KeepMobileError::StorageNotFound)
        }
        fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
            Vec::new()
        }
        fn delete_share_by_key(&self, key: String) -> Result<(), KeepMobileError> {
            self.data.lock().unwrap().remove(&key);
            Ok(())
        }
        fn get_active_share_key(&self) -> Option<String> {
            None
        }
        fn read_active_share_key(&self) -> crate::signing_policy::StorageRead {
            match self.get_active_share_key() {
                Some(value) => crate::signing_policy::StorageRead::Found { value },
                None => crate::signing_policy::StorageRead::Absent,
            }
        }
        fn set_active_share_key(&self, _key: Option<String>) -> Result<(), KeepMobileError> {
            Ok(())
        }
    }

    // (a) Configs serialized before the transport_secret/connect_secret fields
    // existed must still deserialize, leaving the new fields as None.
    #[test]
    fn old_bunker_config_deserializes() {
        let legacy = br#"{"enabled":true,"authorized_clients":["abc"]}"#;
        let config: StoredBunkerConfig = serde_json::from_slice(legacy).unwrap();
        assert!(config.enabled);
        assert_eq!(config.authorized_clients, vec!["abc".to_string()]);
        assert!(config.transport_secret.is_none());
        assert!(config.connect_secret.is_none());
        assert!(config.pending_revokes.is_empty());
        assert!(!config.pending_revoke_all);
    }

    // (c) A fresh storage generates and persists new transport key + secret.
    #[test]
    fn fresh_storage_generates_and_persists() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());

        assert!(load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .is_none());

        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let (transport, secret) = load_or_create_bunker_keys(&mobile).unwrap();
        assert!(!secret.is_empty());

        let stored = load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .expect("config persisted on first start");
        assert_eq!(
            stored
                .transport_secret
                .as_deref()
                .and_then(decode_transport_secret)
                .map(|t| *t),
            Some(*transport)
        );
        assert_eq!(stored.connect_secret.as_deref(), Some(secret.as_str()));
    }

    // (b) Starting the bunker twice against the same storage reuses the same
    // transport key + connect secret, so the derived bunker:// URI is stable.
    #[test]
    fn restart_reuses_persisted_keys() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());

        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let (transport1, secret1) = load_or_create_bunker_keys(&mobile).unwrap();
        let (transport2, secret2) = load_or_create_bunker_keys(&mobile).unwrap();

        assert_eq!(*transport1, *transport2);
        assert_eq!(*secret1, *secret2);
    }

    // Corrupt (invalid-hex transport) or empty (blank connect secret) persisted
    // values must be treated as absent: regenerated to valid material, persisted,
    // and stable across the next load — the junk is never propagated.
    #[test]
    fn corrupt_or_empty_keys_regenerate_and_persist() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());

        let stored = StoredBunkerConfig {
            transport_secret: Some("zzz".into()),
            connect_secret: Some(String::new()),
            ..StoredBunkerConfig::default()
        };
        persist_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY, &stored).unwrap();

        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let (transport, secret) = load_or_create_bunker_keys(&mobile).unwrap();
        assert!(!secret.is_empty());
        assert_ne!(secret.as_str(), "");
        assert_eq!(transport.len(), 32);

        let reloaded = load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .expect("regenerated config persisted");
        assert_eq!(
            reloaded
                .transport_secret
                .as_deref()
                .and_then(decode_transport_secret)
                .map(|t| *t),
            Some(*transport)
        );
        assert_eq!(reloaded.connect_secret.as_deref(), Some(secret.as_str()));

        let (transport2, secret2) = load_or_create_bunker_keys(&mobile).unwrap();
        assert_eq!(*transport, *transport2);
        assert_eq!(*secret, *secret2);
    }

    /// A prompt that is never answered is a denial, not a wait without end.
    ///
    /// The implementation is required to bound its own wait and keep-android
    /// does, so this is the backstop for one that does not. Before it, the
    /// handler read the foreign answer straight through and a callback that
    /// never returned stopped every later request from every client.
    #[test]
    fn an_unanswered_prompt_is_denied_rather_than_waited_on() {
        struct NeverAnswers(Mutex<std::sync::mpsc::Receiver<()>>);
        impl BunkerCallbacks for NeverAnswers {
            fn on_log(&self, _event: BunkerLogEvent) {}
            fn request_approval(&self, _request: BunkerApprovalRequest) -> BunkerApprovalResult {
                // Parked until the test ends, which is what an implementation
                // with no timeout of its own does.
                let _ = self.0.lock().unwrap().recv();
                BunkerApprovalResult {
                    approved: true,
                    remember: BunkerRememberDuration::Forever,
                }
            }
            fn on_connect(&self, _pubkey: String, _name: String, _a: ConnectAuthorization) {}
        }

        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        // Held so the sender outlives the call and the callback stays parked
        // rather than waking on a disconnect.
        let (_hold, rx) = std::sync::mpsc::channel();
        // `mobile` stays owned here: it holds a runtime of its own, and
        // letting the bridge carry the last reference into the async block
        // below drops that runtime from inside an async context, which panics.
        let bridge = CallbackBridge {
            callbacks: Arc::new(NeverAnswers(Mutex::new(rx))),
            mobile: Arc::clone(&mobile),
            approval_timeout: Duration::from_millis(200),
            generation: 0,
            outstanding: Arc::new(AtomicUsize::new(0)),
            grant_scope: String::new(),
            serving: Arc::new(AtomicBool::new(true)),
        };

        let started = std::time::Instant::now();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let result =
            rt.block_on(async { ServerCallbacks::request_approval(&bridge, an_approval()) });

        assert!(
            !result.approved,
            "an unanswered prompt must not be approved"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait must be bounded by the timeout, not by the callback"
        );
    }

    /// Prompts that never came back do not accumulate without limit. Past the
    /// ceiling the answer is a refusal without asking, so a platform that
    /// never returns costs a bounded number of parked threads rather than
    /// steady memory and thread pressure on the whole app.
    #[test]
    fn prompts_that_never_return_stop_being_asked() {
        struct NeverAnswers(Mutex<std::sync::mpsc::Receiver<()>>);
        impl BunkerCallbacks for NeverAnswers {
            fn on_log(&self, _event: BunkerLogEvent) {}
            fn request_approval(&self, _request: BunkerApprovalRequest) -> BunkerApprovalResult {
                let _ = self.0.lock().unwrap().recv();
                BunkerApprovalResult {
                    approved: true,
                    remember: BunkerRememberDuration::Forever,
                }
            }
            fn on_connect(&self, _pubkey: String, _name: String, _a: ConnectAuthorization) {}
        }

        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let (_hold, rx) = std::sync::mpsc::channel();
        let outstanding = Arc::new(AtomicUsize::new(0));
        let bridge = CallbackBridge {
            callbacks: Arc::new(NeverAnswers(Mutex::new(rx))),
            mobile: Arc::clone(&mobile),
            approval_timeout: Duration::from_millis(50),
            generation: 0,
            outstanding: Arc::clone(&outstanding),
            grant_scope: String::new(),
            serving: Arc::new(AtomicBool::new(true)),
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            for _ in 0..MAX_OUTSTANDING_APPROVALS + 3 {
                assert!(!ServerCallbacks::request_approval(&bridge, an_approval()).approved);
            }
        });

        // Every slot is held by a thread still parked in the platform call, and
        // nothing above the ceiling was handed out.
        assert_eq!(
            outstanding.load(Ordering::Acquire),
            MAX_OUTSTANDING_APPROVALS,
            "outstanding prompts must stop at the ceiling"
        );
    }

    /// A slot is released however the platform call ends, including when it
    /// panics, so a panicking callback does not retire a slot for good.
    #[test]
    fn a_panicking_prompt_releases_its_slot() {
        struct Panics;
        impl BunkerCallbacks for Panics {
            fn on_log(&self, _event: BunkerLogEvent) {}
            fn request_approval(&self, _request: BunkerApprovalRequest) -> BunkerApprovalResult {
                panic!("the platform callback failed");
            }
            fn on_connect(&self, _pubkey: String, _name: String, _a: ConnectAuthorization) {}
        }

        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let outstanding = Arc::new(AtomicUsize::new(0));
        let bridge = CallbackBridge {
            callbacks: Arc::new(Panics),
            mobile: Arc::clone(&mobile),
            approval_timeout: Duration::from_secs(5),
            generation: 0,
            outstanding: Arc::clone(&outstanding),
            grant_scope: String::new(),
            serving: Arc::new(AtomicBool::new(true)),
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            for _ in 0..MAX_OUTSTANDING_APPROVALS + 2 {
                assert!(
                    !ServerCallbacks::request_approval(&bridge, an_approval()).approved,
                    "a panicking prompt is a refusal"
                );
            }
        });

        assert_eq!(
            outstanding.load(Ordering::Acquire),
            0,
            "a panicking callback must not retire its slot"
        );
    }

    fn an_approval() -> ApprovalRequest {
        ApprovalRequest {
            app_pubkey: PublicKey::from_slice(
                keep_core::keys::NostrKeypair::generate()
                    .unwrap()
                    .public_bytes(),
            )
            .unwrap(),
            app_name: "an app".into(),
            method: "sign_event".into(),
            event_kind: None,
            event_content: None,
            requested_permissions: None,
            http_auth: None,
        }
    }

    // Two properties of the approval bridge, in the two runtime shapes that
    // can reach it.
    //
    // On one worker thread, the foreign callback blocks on a channel that only
    // another spawned task can feed. That task is queued behind the blocking
    // call, so it runs only because `block_in_place` sends the core to another
    // thread: without it the single worker is occupied, the feeder never runs
    // and the callback reports the refusal its timeout produces.
    //
    // On a current-thread runtime the same call must not panic, which is what
    // the flavor gate buys over the bare `Handle::try_current()` the FROST path
    // in `lib.rs` uses. `block_in_place` would abort there.
    #[test]
    fn the_approval_bridge_leaves_the_worker_and_survives_a_current_thread_runtime() {
        struct Waiter(Mutex<Option<std::sync::mpsc::Receiver<()>>>);
        impl BunkerCallbacks for Waiter {
            fn on_log(&self, _event: BunkerLogEvent) {}
            fn request_approval(&self, _request: BunkerApprovalRequest) -> BunkerApprovalResult {
                let rx = self.0.lock().unwrap().take().expect("one call per Waiter");
                BunkerApprovalResult {
                    approved: rx.recv_timeout(Duration::from_secs(5)).is_ok(),
                    remember: BunkerRememberDuration::OneHour,
                }
            }
            fn on_connect(&self, _pubkey: String, _name: String, _a: ConnectAuthorization) {}
        }

        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let bridge = |rx| CallbackBridge {
            callbacks: Arc::new(Waiter(Mutex::new(Some(rx)))),
            mobile: Arc::clone(&mobile),
            approval_timeout: APPROVAL_TIMEOUT,
            generation: 0,
            outstanding: Arc::new(AtomicUsize::new(0)),
            grant_scope: String::new(),
            serving: Arc::new(AtomicBool::new(true)),
        };
        let ask = |bridge: &CallbackBridge| {
            ServerCallbacks::request_approval(
                bridge,
                ApprovalRequest {
                    app_pubkey: PublicKey::from_slice(
                        keep_core::keys::NostrKeypair::generate()
                            .unwrap()
                            .public_bytes(),
                    )
                    .unwrap(),
                    app_name: "an app".into(),
                    method: "sign_event".into(),
                    event_kind: None,
                    event_content: None,
                    requested_permissions: None,
                    http_auth: None,
                },
            )
        };

        let (tx, rx) = std::sync::mpsc::channel();
        let worker = bridge(rx);
        let result = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                tokio::spawn(async move {
                    tokio::spawn(async move {
                        let _ = tx.send(());
                    });
                    ask(&worker)
                })
                .await
                .unwrap()
            });
        assert!(
            result.approved,
            "the blocking callback kept the only worker, so the task that answers it never ran"
        );
        assert!(
            matches!(
                result.remember,
                keep_nip46::types::RememberDuration::OneHour
            ),
            "the remember duration must survive the bridge unchanged"
        );

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(()).unwrap();
        let single = bridge(rx);
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async { ask(&single) });
        assert!(result.approved, "the answer must survive the fallback path");
    }

    // Rotating replaces both persisted secrets, so the derived bunker:// URL
    // changes and any previously leaked URL can no longer pair.
    #[test]
    fn rotate_credentials_changes_transport_and_connect_secret() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());

        let (transport1, secret1) = load_or_create_bunker_keys(&mobile).unwrap();

        let handler = BunkerHandler::new(Arc::clone(&mobile));
        handler.rotate_bunker_credentials().unwrap();

        let (transport2, secret2) = load_or_create_bunker_keys(&mobile).unwrap();
        assert_ne!(*transport1, *transport2, "transport secret must rotate");
        assert_ne!(
            secret1.as_str(),
            secret2.as_str(),
            "connect secret must rotate"
        );
        assert_eq!(transport2.len(), 32);
    }

    const GROUP: [u8; 32] = [7; 32];

    fn remembered(client: &PublicKey) -> keep_core::relay::StoredBunkerPermission {
        keep_core::relay::StoredBunkerPermission {
            pubkey_hex: client.to_hex(),
            name: "client".into(),
            permissions: keep_nip46::Permission::SIGN_EVENT.bits(),
            auto_approve_kinds: vec![1],
            duration: keep_core::relay::StoredPermissionDuration::Forever,
            connected_at: 0,
            timed_kind_grants: Vec::new(),
            explicitly_remembered: Some(true),
            kinds_vetted: true,
        }
    }

    fn restored_clients(mobile: &KeepMobile) -> Vec<String> {
        let (transport, _) = load_or_create_bunker_keys(mobile).unwrap();
        mobile
            .load_bunker_permissions(&grant_scope(&transport, &GROUP).unwrap())
            .into_iter()
            .map(|grant| grant.pubkey_hex)
            .collect()
    }

    fn persist_remembered(mobile: &KeepMobile, clients: &[PublicKey]) {
        let (transport, _) = load_or_create_bunker_keys(mobile).unwrap();
        mobile
            .persist_bunker_permissions(
                clients.iter().map(remembered).collect(),
                &grant_scope(&transport, &GROUP).unwrap(),
                || true,
            )
            .unwrap();
    }

    // With no bunker running there is no engine to persist a revoke, so the
    // revoke has to reach the persisted grants itself, or the next start
    // restores the client it revoked.
    #[test]
    fn a_revoke_while_stopped_removes_the_persisted_grants() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let (a, b) = (
            nostr_sdk::Keys::generate().public_key(),
            nostr_sdk::Keys::generate().public_key(),
        );
        persist_remembered(&mobile, &[a, b]);
        assert_eq!(restored_clients(&mobile).len(), 2);

        let handler = BunkerHandler::new(Arc::clone(&mobile));
        handler.revoke_client(a.to_hex()).unwrap();
        assert_eq!(restored_clients(&mobile), vec![b.to_hex()]);
        handler.revoke_all_clients().unwrap();
        assert!(restored_clients(&mobile).is_empty());
    }

    // A client remembered before a rotation would otherwise sign its
    // remembered kinds under the new bunker key without pairing again, since
    // that key is public as the author of every response.
    #[test]
    fn grants_from_before_a_rotation_are_not_restored() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        persist_remembered(&mobile, &[nostr_sdk::Keys::generate().public_key()]);
        assert_eq!(restored_clients(&mobile).len(), 1);

        BunkerHandler::new(Arc::clone(&mobile))
            .rotate_bunker_credentials()
            .unwrap();
        assert!(restored_clients(&mobile).is_empty());
    }

    // A grant was approved for the identity the bunker signed as, so one made
    // while another share was active is not restored.
    #[test]
    fn grants_for_another_share_are_not_restored() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        persist_remembered(&mobile, &[nostr_sdk::Keys::generate().public_key()]);
        let (transport, _) = load_or_create_bunker_keys(&mobile).unwrap();
        assert!(mobile
            .load_bunker_permissions(&grant_scope(&transport, &[8; 32]).unwrap())
            .is_empty());
        assert_eq!(restored_clients(&mobile).len(), 1);
    }

    // Grants saved before they were tagged with a bunker key cannot be told
    // apart from grants made before a rotation.
    #[test]
    fn untagged_grants_are_not_restored() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let key = crate::relay_config_key(None);
        let stored = crate::persistence::StoredRelayConfig {
            bunker_permissions: vec![remembered(&nostr_sdk::Keys::generate().public_key())],
            ..Default::default()
        };
        crate::persistence::persist_relay_config(&mobile.storage, &key, &stored).unwrap();
        assert!(restored_clients(&mobile).is_empty());
    }

    fn engine_knowing(
        client: &PublicKey,
    ) -> (
        Arc<SignerHandler>,
        Arc<tokio::sync::Mutex<keep_nip46::PermissionManager>>,
    ) {
        let mut pm = keep_nip46::PermissionManager::new();
        assert!(pm.connect(*client, "client".into()));
        let permissions = Arc::new(tokio::sync::Mutex::new(pm));
        let handler = Arc::new(SignerHandler::new(
            Arc::new(tokio::sync::Mutex::new(keep_core::keyring::Keyring::new())),
            Arc::clone(&permissions),
            Arc::new(tokio::sync::Mutex::new(keep_nip46::AuditLog::new(10))),
            None,
        ));
        (handler, permissions)
    }

    // The app makes a new handler for every start, so a revoke can arrive
    // through one that did not start the running bunker, and must still reach
    // its engine.
    #[test]
    fn a_revoke_reaches_a_bunker_started_through_another_handler() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let client = nostr_sdk::Keys::generate().public_key();
        let (engine, permissions) = engine_knowing(&client);
        assert!(BunkerHandler::new(Arc::clone(&mobile)).publish_server(
            String::new(),
            &engine,
            Arc::new(AtomicBool::new(true)),
            tokio::sync::oneshot::channel().0,
        ));

        BunkerHandler::new(Arc::clone(&mobile))
            .revoke_client(client.to_hex())
            .unwrap();
        assert!(mobile
            .runtime
            .block_on(permissions.lock())
            .get_app(&client)
            .is_none());
    }

    // `stop_bunker` must reach the flag of the server it stops, or that server
    // keeps persisting while it winds down.
    #[test]
    fn stopping_a_bunker_clears_its_serving_flag() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let (engine, _) = engine_knowing(&nostr_sdk::Keys::generate().public_key());
        let serving = Arc::new(AtomicBool::new(true));
        let handler = BunkerHandler::new(Arc::clone(&mobile));
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        assert!(handler.publish_server(String::new(), &engine, Arc::clone(&serving), tx));
        handler.stop_bunker();
        assert!(!serving.load(Ordering::Acquire));
        assert!(rx.try_recv().is_ok(), "the server is signalled to stop");
    }

    // A stop while a start is still connecting finds no server to signal. The
    // start must see it and not publish, or it leaves a server running that
    // nothing can stop or revoke.
    #[test]
    fn a_stop_during_a_start_stops_that_start() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let (engine, _) = engine_knowing(&nostr_sdk::Keys::generate().public_key());
        let handler = BunkerHandler::new(Arc::clone(&mobile));

        handler.lifecycle().starting = true;
        handler.stop_bunker();
        let published = handler.publish_server(
            "bunker://".into(),
            &engine,
            Arc::new(AtomicBool::new(true)),
            tokio::sync::oneshot::channel().0,
        );
        assert!(!published);
        assert!(handler.live_handler().is_none());
        assert!(handler.get_bunker_url().is_none());

        assert!(
            handler.publish_server(
                "bunker://".into(),
                &engine,
                Arc::new(AtomicBool::new(true)),
                tokio::sync::oneshot::channel().0,
            ),
            "the request stops one start, not the next"
        );

        // A server that stopped by itself leaves its sender behind, and a stop
        // that finds it must still reach the start in flight.
        let restarted = BunkerHandler::new(Arc::clone(&mobile));
        let (dead, _) = tokio::sync::oneshot::channel();
        restarted.lifecycle().shutdown_tx = Some(dead);
        restarted.lifecycle().starting = true;
        restarted.stop_bunker();
        assert!(!restarted.publish_server(
            "bunker://".into(),
            &engine,
            Arc::new(AtomicBool::new(true)),
            tokio::sync::oneshot::channel().0,
        ));

        let idle = BunkerHandler::new(Arc::clone(&mobile));
        idle.stop_bunker();
        assert!(
            idle.publish_server(
                "bunker://".into(),
                &engine,
                Arc::new(AtomicBool::new(true)),
                tokio::sync::oneshot::channel().0,
            ),
            "a stop with nothing starting leaves no request behind"
        );
    }

    // A rotation stops a bunker started through any handler, so the old keys
    // stop serving and its approvals and persists are refused.
    #[test]
    fn a_rotation_moves_the_live_generation() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let before = *mobile.live_generation.borrow();
        BunkerHandler::new(Arc::clone(&mobile))
            .rotate_bunker_credentials()
            .unwrap();
        assert_ne!(*mobile.live_generation.borrow(), before);
    }

    // A server still winding down after a stop must not write back grants a
    // revoke cleared in the meantime.
    #[test]
    fn a_stopped_server_persists_nothing() {
        struct Silent;
        impl BunkerCallbacks for Silent {
            fn on_log(&self, _event: BunkerLogEvent) {}
            fn request_approval(&self, _request: BunkerApprovalRequest) -> BunkerApprovalResult {
                BunkerApprovalResult {
                    approved: false,
                    remember: BunkerRememberDuration::JustThisTime,
                }
            }
            fn on_connect(&self, _pubkey: String, _name: String, _a: ConnectAuthorization) {}
        }

        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let (transport, _) = load_or_create_bunker_keys(&mobile).unwrap();
        let bridge = CallbackBridge {
            callbacks: Arc::new(Silent),
            mobile: Arc::clone(&mobile),
            approval_timeout: Duration::from_secs(1),
            generation: *mobile.live_generation.borrow(),
            outstanding: Arc::new(AtomicUsize::new(0)),
            grant_scope: grant_scope(&transport, &GROUP).unwrap(),
            serving: Arc::new(AtomicBool::new(true)),
        };
        let client = nostr_sdk::Keys::generate().public_key();
        bridge.serving.store(false, Ordering::Release);
        bridge.persist_permissions(vec![remembered(&client)]);
        assert!(restored_clients(&mobile).is_empty());
        bridge.serving.store(true, Ordering::Release);
        mobile
            .live_generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        bridge.persist_permissions(vec![remembered(&client)]);
        assert!(
            restored_clients(&mobile).is_empty(),
            "a server from before a teardown persists nothing either"
        );
        let bridge = CallbackBridge {
            generation: *mobile.live_generation.borrow(),
            ..bridge
        };
        bridge.persist_permissions(vec![remembered(&client)]);
        assert_eq!(restored_clients(&mobile), vec![client.to_hex()]);
    }

    struct RefusesAndCounts(Arc<AtomicUsize>);
    impl BunkerCallbacks for RefusesAndCounts {
        fn on_log(&self, _event: BunkerLogEvent) {}
        fn request_approval(&self, _request: BunkerApprovalRequest) -> BunkerApprovalResult {
            self.0.fetch_add(1, Ordering::AcqRel);
            BunkerApprovalResult {
                approved: false,
                remember: BunkerRememberDuration::JustThisTime,
            }
        }
        fn on_connect(&self, _pubkey: String, _name: String, _a: ConnectAuthorization) {}
    }

    /// Sends `method` with `params` from `client` to the bunker at `bunker`
    /// and returns its answer, or `None` when none comes within five seconds.
    async fn ask_over_relay(
        client: &nostr_sdk::Client,
        keys: &nostr_sdk::Keys,
        bunker: PublicKey,
        id: &str,
        method: &str,
        params: serde_json::Value,
    ) -> Option<serde_json::Value> {
        use nostr_sdk::nips::nip44;
        let mut notifications = client.notifications();
        let request = serde_json::json!({ "id": id, "method": method, "params": params });
        let content = nip44::encrypt(
            keys.secret_key(),
            &bunker,
            serde_json::to_string(&request).unwrap(),
            nip44::Version::V2,
        )
        .unwrap();
        let event = nostr_sdk::EventBuilder::new(Kind::NostrConnect, content)
            .tag(nostr_sdk::Tag::public_key(bunker))
            .sign_with_keys(keys)
            .unwrap();
        client.send_event(&event).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let Ok(nostr_sdk::RelayPoolNotification::Event { event, .. }) =
                    notifications.recv().await
                else {
                    continue;
                };
                if event.kind != Kind::NostrConnect || event.pubkey != bunker {
                    continue;
                }
                let Ok(plain) = nip44::decrypt(keys.secret_key(), &bunker, event.content.as_str())
                else {
                    continue;
                };
                let response: serde_json::Value = serde_json::from_str(&plain).unwrap();
                if response.get("id").and_then(|v| v.as_str()) == Some(id) {
                    return response;
                }
            }
        })
        .await
        .ok()
    }

    /// A kind 1 `sign_event` over the relay: the signed event, or `None` when
    /// the bunker refused or did not answer.
    async fn sign_over_relay(
        client: &nostr_sdk::Client,
        keys: &nostr_sdk::Keys,
        bunker: PublicKey,
        id: &str,
    ) -> Option<nostr_sdk::Event> {
        let unsigned = serde_json::json!({
            "kind": 1,
            "content": id,
            "tags": [],
            "created_at": nostr_sdk::Timestamp::now().as_secs(),
        });
        let params = serde_json::json!([serde_json::to_string(&unsigned).unwrap()]);
        ask_over_relay(client, keys, bunker, id, "sign_event", params)
            .await?
            .get("result")
            .and_then(|v| v.as_str())
            .filter(|r| !r.is_empty())
            .map(|r| <nostr_sdk::Event as nostr_sdk::JsonUtil>::from_json(r).unwrap())
    }

    /// A bunker on `url` serving the grants stored under `scope`, with the
    /// stored connect secret, its engine published through `starter`, and the
    /// task running it.
    fn serve_stored(
        mobile: &Arc<KeepMobile>,
        starter: &BunkerHandler,
        url: &str,
        keyring: Arc<tokio::sync::Mutex<keep_core::keyring::Keyring>>,
        scope: &str,
        prompts: &Arc<AtomicUsize>,
    ) -> (PublicKey, Arc<AtomicBool>, tokio::task::JoinHandle<()>) {
        let (_, secret) = load_or_create_bunker_keys(mobile).unwrap();
        let pre_grants: Vec<PreGrantedApp> = mobile
            .load_bunker_permissions(scope)
            .iter()
            .filter_map(PreGrantedApp::from_stored)
            .collect();
        let serving = Arc::new(AtomicBool::new(true));
        let bridge = CallbackBridge {
            callbacks: Arc::new(RefusesAndCounts(Arc::clone(prompts))),
            mobile: Arc::clone(mobile),
            approval_timeout: Duration::from_secs(5),
            generation: *mobile.live_generation.borrow(),
            outstanding: Arc::new(AtomicUsize::new(0)),
            grant_scope: scope.to_owned(),
            serving: Arc::clone(&serving),
        };
        let invalidated = mobile.live_generation.subscribe();
        let server = mobile.runtime.block_on(async {
            Server::new_with_config(
                keyring,
                None,
                None,
                &[url.to_owned()],
                Some(Arc::new(bridge) as Arc<dyn ServerCallbacks>),
                ServerConfig {
                    pre_grants,
                    expected_secret: Some(secret.as_str().to_owned()),
                    ..ServerConfig::default()
                },
            )
            .await
            .unwrap()
        });
        let bunker = server.pubkey();
        let (tx, rx) = tokio::sync::oneshot::channel();
        assert!(starter.publish_server(String::new(), &server.handler(), Arc::clone(&serving), tx));
        let running = starter.serve(server, rx, invalidated, Arc::clone(&serving));
        std::thread::sleep(Duration::from_millis(500));
        (bunker, serving, running)
    }

    // A start reads RUNNING as soon as it returns, not once its task is
    // scheduled, and a stop after that still ends at STOPPED.
    #[test]
    fn a_served_bunker_reads_running_before_its_task_runs() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(storage).unwrap());
        let relay = mobile
            .runtime
            .block_on(nostr_relay_builder::MockRelay::run())
            .unwrap();
        let url = mobile.runtime.block_on(relay.url()).to_string();
        let mut keyring = keep_core::keyring::Keyring::new();
        let keypair = keep_core::keys::NostrKeypair::generate().unwrap();
        keyring
            .load_key(
                *keypair.public_bytes(),
                *keypair.secret_bytes(),
                keep_core::keys::KeyType::Nostr,
                "test".into(),
            )
            .unwrap();
        let server = mobile
            .runtime
            .block_on(Server::new_with_config(
                Arc::new(tokio::sync::Mutex::new(keyring)),
                None,
                None,
                &[url],
                None,
                ServerConfig::default(),
            ))
            .unwrap();

        let handler = BunkerHandler::new(Arc::clone(&mobile));
        handler.set_status(STATUS_STARTING);
        let serving = Arc::new(AtomicBool::new(true));
        let (tx, rx) = tokio::sync::oneshot::channel();
        assert!(handler.publish_server(String::new(), &server.handler(), Arc::clone(&serving), tx));
        let running = handler.serve(server, rx, mobile.live_generation.subscribe(), serving);
        assert_eq!(handler.load_status(), STATUS_RUNNING);

        handler.stop_bunker();
        mobile.runtime.block_on(running).unwrap();
        assert_eq!(handler.load_status(), STATUS_STOPPED);
    }

    // A revoke takes the client out of the app's list however it was written
    // there, leaves the others, and replaces only the connect secret; revoking
    // every client clears the list.
    #[test]
    fn a_revoke_rotates_only_the_connect_secret_and_drops_the_client() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let (a, b) = (
            nostr_sdk::Keys::generate().public_key(),
            nostr_sdk::Keys::generate().public_key(),
        );
        let (transport, secret) = load_or_create_bunker_keys(&mobile).unwrap();
        let mut stored = load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .unwrap();
        stored.authorized_clients = vec![
            a.to_hex(),
            nostr_sdk::ToBech32::to_bech32(&a).unwrap(),
            b.to_hex(),
        ];
        persist_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY, &stored).unwrap();
        let before = *mobile.live_generation.borrow();

        let handler = BunkerHandler::new(Arc::clone(&mobile));
        handler.revoke_client(a.to_hex()).unwrap();
        let stored = load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .unwrap();
        assert_eq!(stored.authorized_clients, vec![b.to_hex()]);
        let (kept, rotated) = load_or_create_bunker_keys(&mobile).unwrap();
        assert_eq!(*kept, *transport);
        assert_ne!(rotated.as_str(), secret.as_str());
        assert_ne!(
            *mobile.live_generation.borrow(),
            before,
            "a running bunker stops"
        );

        handler.revoke_all_clients().unwrap();
        let stored = load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .unwrap();
        assert!(stored.authorized_clients.is_empty());
        let (kept, again) = load_or_create_bunker_keys(&mobile).unwrap();
        assert_eq!(*kept, *transport);
        assert_ne!(again.as_str(), rotated.as_str());
    }

    /// A client on `url` listening for the bunker at `bunker`'s answers.
    fn listening(
        mobile: &KeepMobile,
        url: &str,
        keys: &nostr_sdk::Keys,
        bunker: PublicKey,
    ) -> nostr_sdk::Client {
        mobile.runtime.block_on(async {
            let client = nostr_sdk::Client::new(keys.clone());
            client.add_relay(url).await.unwrap();
            client.connect().await;
            client
                .subscribe(
                    nostr_sdk::Filter::new()
                        .kind(Kind::NostrConnect)
                        .author(bunker)
                        .pubkey(keys.public_key()),
                    None,
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            client
        })
    }

    fn error_of(answer: Option<serde_json::Value>) -> Option<String> {
        answer
            .expect("the bunker answers")
            .get("error")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    }

    // End to end over a relay, with the production callback bridge and grants
    // restored from storage. A revoke made through another handler stops the
    // bunker and leaves nothing to restore, and replaces the connect secret but
    // not the transport key. The bunker started again refuses the revoked
    // client its signing request and its old secret, and the old secret to any
    // key; the new secret works, and a client still remembered signs without
    // pairing again.
    #[test]
    fn a_revoked_client_cannot_sign_or_connect_again_end_to_end() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let (transport, old_secret) = load_or_create_bunker_keys(&mobile).unwrap();
        let scope = grant_scope(&transport, &GROUP).unwrap();
        let revoked = nostr_sdk::Keys::generate();
        let kept = nostr_sdk::Keys::generate();
        persist_remembered(&mobile, &[revoked.public_key(), kept.public_key()]);
        let prompts = Arc::new(AtomicUsize::new(0));
        let relay = mobile
            .runtime
            .block_on(nostr_relay_builder::MockRelay::run())
            .unwrap();
        let url = mobile.runtime.block_on(relay.url()).to_string();
        let keyring = {
            let mut keyring = keep_core::keyring::Keyring::new();
            let keypair = keep_core::keys::NostrKeypair::generate().unwrap();
            keyring
                .load_key(
                    *keypair.public_bytes(),
                    *keypair.secret_bytes(),
                    keep_core::keys::KeyType::Nostr,
                    "test".into(),
                )
                .unwrap();
            Arc::new(tokio::sync::Mutex::new(keyring))
        };

        let starter = BunkerHandler::new(Arc::clone(&mobile));
        let (bunker, serving, running) = serve_stored(
            &mobile,
            &starter,
            &url,
            Arc::clone(&keyring),
            &scope,
            &prompts,
        );
        let client = listening(&mobile, &url, &revoked, bunker);
        let signed = mobile
            .runtime
            .block_on(sign_over_relay(&client, &revoked, bunker, "remembered"))
            .expect("a remembered kind is signed");
        signed.verify().unwrap();

        BunkerHandler::new(Arc::clone(&mobile))
            .revoke_client(revoked.public_key().to_hex())
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !running.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(running.is_finished(), "the revoke stops the bunker");
        assert!(!serving.load(Ordering::Acquire));
        assert_eq!(restored_clients(&mobile), vec![kept.public_key().to_hex()]);
        let (kept_transport, new_secret) = load_or_create_bunker_keys(&mobile).unwrap();
        assert_eq!(*kept_transport, *transport, "the transport key stays");
        assert_ne!(new_secret.as_str(), old_secret.as_str());

        let restarter = BunkerHandler::new(Arc::clone(&mobile));
        let (again, _, _) = serve_stored(&mobile, &restarter, &url, keyring, &scope, &prompts);
        assert_eq!(again, bunker);
        let connect = |secret: &str| serde_json::json!([bunker.to_hex(), secret]);
        let ask = |client: &nostr_sdk::Client, keys, id, method, params| {
            mobile
                .runtime
                .block_on(ask_over_relay(client, keys, bunker, id, method, params))
        };

        let unsigned = serde_json::json!({
            "kind": 1, "content": "x", "tags": [],
            "created_at": nostr_sdk::Timestamp::now().as_secs(),
        });
        let sign = serde_json::json!([unsigned.to_string()]);
        assert_eq!(
            error_of(ask(&client, &revoked, "revoked-sign", "sign_event", sign)).as_deref(),
            Some("Permission denied"),
            "the revoked client cannot sign"
        );
        assert_eq!(
            error_of(ask(
                &client,
                &revoked,
                "revoked-connect",
                "connect",
                connect(old_secret.as_str())
            ))
            .as_deref(),
            Some("Permission denied"),
            "nor connect with the old secret"
        );
        let fresh = nostr_sdk::Keys::generate();
        let fresh_client = listening(&mobile, &url, &fresh, bunker);
        assert_eq!(
            error_of(ask(
                &fresh_client,
                &fresh,
                "fresh-old",
                "connect",
                connect(old_secret.as_str())
            ))
            .as_deref(),
            Some("Permission denied"),
            "the old secret is refused to any key"
        );
        assert_eq!(
            error_of(ask(
                &fresh_client,
                &fresh,
                "fresh-new",
                "connect",
                connect(new_secret.as_str())
            )),
            None,
            "the new secret is accepted"
        );
        let kept_client = listening(&mobile, &url, &kept, bunker);
        assert!(
            mobile
                .runtime
                .block_on(sign_over_relay(&kept_client, &kept, bunker, "still-kept"))
                .is_some(),
            "a client still remembered signs without pairing again"
        );
        assert_eq!(prompts.load(Ordering::Acquire), 0, "nothing asked the user");
        restarter.stop_bunker();
        for c in [client, fresh_client, kept_client] {
            mobile.runtime.block_on(c.disconnect());
        }
    }

    // A revoke that cannot complete leaves the bunker stopped, so the old
    // secret does not keep serving, and reports the failure.
    #[test]
    fn a_revoke_that_fails_leaves_the_bunker_stopped() {
        let mem = Arc::new(MemStorage::default());
        let storage: Arc<dyn SecureStorage> = mem.clone();
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        *mem.fail_writes_to.lock().unwrap() = Some(BUNKER_CONFIG_STORAGE_KEY.into());
        let before = *mobile.live_generation.borrow();
        assert!(BunkerHandler::new(Arc::clone(&mobile))
            .revoke_client(nostr_sdk::Keys::generate().public_key().to_hex())
            .is_err());
        assert_ne!(*mobile.live_generation.borrow(), before, "stopped");
    }

    fn stored_config(storage: &Arc<dyn SecureStorage>) -> StoredBunkerConfig {
        load_bunker_config(storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .expect("config persisted")
    }

    fn served_clients(handler: &BunkerHandler) -> Vec<String> {
        let (transport, _) = load_or_create_bunker_keys(&handler.mobile).unwrap();
        handler
            .grants_to_restore(&grant_scope(&transport, &GROUP).unwrap())
            .unwrap()
            .into_iter()
            .map(|grant| grant.pubkey.to_hex())
            .collect()
    }

    // The grants live in the relay config, a different record from the
    // secret, so a revoke can land its secret and pending mark and then fail
    // to drop them. A start must not serve them, and finishes the revoke when
    // it can.
    #[test]
    fn a_pending_revokes_grants_are_never_served() {
        let mem = Arc::new(MemStorage::default());
        let storage: Arc<dyn SecureStorage> = mem.clone();
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let (a, b) = (
            nostr_sdk::Keys::generate().public_key(),
            nostr_sdk::Keys::generate().public_key(),
        );
        persist_remembered(&mobile, &[a, b]);
        let (_, old_secret) = load_or_create_bunker_keys(&mobile).unwrap();
        let handler = BunkerHandler::new(Arc::clone(&mobile));

        *mem.fail_writes_to.lock().unwrap() = Some(crate::relay_config_key(None));
        handler
            .revoke_client(a.to_hex())
            .expect("the revoke holds once its secret and mark are written");
        assert_eq!(restored_clients(&mobile).len(), 2, "the grant write failed");
        let stored = stored_config(&storage);
        assert_ne!(stored.connect_secret.as_deref(), Some(old_secret.as_str()));
        assert_eq!(stored.pending_revokes, vec![a.to_hex()]);
        assert_eq!(served_clients(&handler), vec![b.to_hex()]);
        assert_eq!(restored_clients(&mobile).len(), 2, "still stored");

        *mem.fail_writes_to.lock().unwrap() = None;
        assert_eq!(served_clients(&handler), vec![b.to_hex()]);
        assert_eq!(restored_clients(&mobile), vec![b.to_hex()], "finished");
        assert!(stored_config(&storage).pending_revokes.is_empty());

        *mem.fail_writes_to.lock().unwrap() = Some(crate::relay_config_key(None));
        handler.revoke_all_clients().unwrap();
        assert!(stored_config(&storage).pending_revoke_all);
        assert!(served_clients(&handler).is_empty());
        assert_eq!(restored_clients(&mobile), vec![b.to_hex()], "still stored");
        *mem.fail_writes_to.lock().unwrap() = None;
        assert!(served_clients(&handler).is_empty());
        assert!(restored_clients(&mobile).is_empty());
        assert!(!stored_config(&storage).pending_revoke_all);
    }

    // A relay config that cannot be read keeps the mark set, but must not
    // keep the bunker from starting: it restores nothing either way.
    #[test]
    fn an_unreadable_relay_config_does_not_block_a_start_after_a_revoke() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let handler = BunkerHandler::new(Arc::clone(&mobile));
        storage
            .store_share_by_key(
                crate::relay_config_key(None),
                b"not json".to_vec(),
                crate::persistence::storage_metadata("relay_config"),
            )
            .unwrap();
        let a = nostr_sdk::Keys::generate().public_key();
        handler.revoke_client(a.to_hex()).unwrap();
        assert_eq!(stored_config(&storage).pending_revokes, vec![a.to_hex()]);
        assert!(served_clients(&handler).is_empty());
    }

    // When the secret itself cannot be written the revoke fails, but the
    // client's grants are still dropped where they can be.
    #[test]
    fn a_revoke_that_cannot_write_the_secret_still_drops_the_grants() {
        let mem = Arc::new(MemStorage::default());
        let storage: Arc<dyn SecureStorage> = mem.clone();
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let (a, b) = (
            nostr_sdk::Keys::generate().public_key(),
            nostr_sdk::Keys::generate().public_key(),
        );
        persist_remembered(&mobile, &[a, b]);
        let (_, old_secret) = load_or_create_bunker_keys(&mobile).unwrap();
        let handler = BunkerHandler::new(Arc::clone(&mobile));

        *mem.fail_writes_to.lock().unwrap() = Some(BUNKER_CONFIG_STORAGE_KEY.into());
        assert!(handler.revoke_client(a.to_hex()).is_err());
        assert_eq!(restored_clients(&mobile), vec![b.to_hex()]);
        assert!(handler.revoke_all_clients().is_err());
        assert!(restored_clients(&mobile).is_empty());
        *mem.fail_writes_to.lock().unwrap() = None;
        let stored = stored_config(&storage);
        assert_eq!(stored.connect_secret.as_deref(), Some(old_secret.as_str()));
        assert!(stored.pending_revokes.is_empty());
        assert!(!stored.pending_revoke_all);
    }

    // A persisted transport secret that is valid 32-byte hex but not a valid
    // secp256k1 scalar (here all-zero) must be rejected and regenerated, so a
    // corrupt key cannot brick the bunker permanently.
    #[test]
    fn invalid_scalar_transport_secret_regenerates() {
        assert!(decode_transport_secret(&"00".repeat(32)).is_none());

        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let stored = StoredBunkerConfig {
            transport_secret: Some("00".repeat(32)),
            connect_secret: Some("preserved-secret".into()),
            ..StoredBunkerConfig::default()
        };
        persist_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY, &stored).unwrap();

        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let (transport, secret) = load_or_create_bunker_keys(&mobile).unwrap();
        assert_ne!(*transport, [0u8; 32]);
        assert!(nostr_sdk::secp256k1::SecretKey::from_slice(&transport[..]).is_ok());
        // Regenerating the corrupt transport key must not rotate the still-valid
        // connect secret, or the bunker URL would change on next restart.
        assert_eq!(*secret, "preserved-secret");
        let reloaded = load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .expect("config persisted");
        assert_eq!(reloaded.connect_secret.as_deref(), Some("preserved-secret"));
        let (_, secret2) = load_or_create_bunker_keys(&mobile).unwrap();
        assert_eq!(*secret2, "preserved-secret");
    }

    // Drive the real `KeepMobile::save_bunker_config`: persisted transport key +
    // connect secret survive an unrelated config save (disable + add a client).
    #[test]
    fn save_bunker_config_preserves_secrets() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());

        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let (transport, secret) = load_or_create_bunker_keys(&mobile).unwrap();

        let mut stored = load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .unwrap();
        stored.pending_revokes = vec!["p".into()];
        stored.pending_revoke_all = true;
        persist_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY, &stored).unwrap();

        mobile
            .save_bunker_config(crate::BunkerConfigInfo {
                enabled: false,
                authorized_clients: vec!["c".into()],
            })
            .unwrap();

        let reloaded = load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .expect("config persisted");
        assert!(!reloaded.enabled);
        assert_eq!(reloaded.authorized_clients, vec!["c".to_string()]);
        assert_eq!(
            reloaded
                .transport_secret
                .as_deref()
                .and_then(decode_transport_secret)
                .map(|t| *t),
            Some(*transport)
        );
        assert_eq!(reloaded.connect_secret.as_deref(), Some(secret.as_str()));
        assert_eq!(reloaded.pending_revokes, vec!["p".to_string()]);
        assert!(reloaded.pending_revoke_all);
    }

    // Saving unrelated config (e.g. toggling enabled) must not rotate the keys.
    #[test]
    fn rewriting_config_preserves_keys() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());

        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let (transport1, secret1) = load_or_create_bunker_keys(&mobile).unwrap();

        let mut stored = load_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY)
            .unwrap()
            .unwrap();
        stored.enabled = false;
        stored.authorized_clients.push("client".into());
        persist_bunker_config(&storage, BUNKER_CONFIG_STORAGE_KEY, &stored).unwrap();

        let (transport2, secret2) = load_or_create_bunker_keys(&mobile).unwrap();
        assert_eq!(*transport1, *transport2);
        assert_eq!(*secret1, *secret2);
    }

    // A running bunker holds its own copy of the share, or a handle to the old
    // node, and the relay pins it started with. Tearing the live node down, as
    // deleting or switching the share or editing the pins does, has to stop it
    // too, or it signs on with a share that is gone.
    #[test]
    fn a_running_bunker_stops_when_the_live_node_is_torn_down() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let invalidated = mobile.live_generation.subscribe();
        let status = Arc::new(AtomicU8::new(STATUS_RUNNING));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let (_relay, server, url) = mobile.runtime.block_on(async {
            let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
            let url = relay.url().await.to_string();
            let mut keyring = keep_core::keyring::Keyring::new();
            let keypair = keep_core::keys::NostrKeypair::generate().unwrap();
            keyring
                .load_key(
                    *keypair.public_bytes(),
                    *keypair.secret_bytes(),
                    keep_core::keys::KeyType::Nostr,
                    "test".into(),
                )
                .unwrap();
            let server = Server::new_with_config(
                Arc::new(tokio::sync::Mutex::new(keyring)),
                None,
                None,
                std::slice::from_ref(&url),
                None,
                ServerConfig::default(),
            )
            .await
            .unwrap();
            (relay, server, url)
        });
        let bunker = server.pubkey();
        let handler = Arc::downgrade(&server.handler());
        let persisting = Arc::new(AtomicBool::new(true));
        let serving = mobile.runtime.spawn(run_server(
            server,
            shutdown_rx,
            invalidated,
            Arc::clone(&status),
            Arc::clone(&persisting),
        ));
        assert!(
            mobile.runtime.block_on(pings_back(&url, bunker)),
            "the server is serving before the teardown"
        );

        mobile.clear_certificate_pins().unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !serving.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(serving.is_finished(), "the server stopped with the node");
        assert_eq!(status.load(Ordering::Acquire), STATUS_STOPPED);
        assert!(
            !persisting.load(Ordering::Acquire),
            "a stopped server persists nothing"
        );
        assert!(
            handler.upgrade().is_none(),
            "the signer, and the share it holds, went with the server"
        );
    }

    /// Whether the bunker at `bunker` answers a NIP-46 `ping` on `url`.
    async fn pings_back(url: &str, bunker: PublicKey) -> bool {
        use nostr_sdk::nips::nip44;
        let keys = nostr_sdk::Keys::generate();
        let client = nostr_sdk::Client::new(keys.clone());
        client.add_relay(url).await.unwrap();
        client.connect().await;
        client
            .subscribe(
                nostr_sdk::Filter::new()
                    .kind(Kind::NostrConnect)
                    .author(bunker)
                    .pubkey(keys.public_key()),
                None,
            )
            .await
            .unwrap();
        let mut notifications = client.notifications();
        // Sent again each second: a ping that reaches the relay before the
        // server has subscribed is not kept for it, since NIP-46 events are
        // ephemeral.
        let mut answered = false;
        for _ in 0..10 {
            let request = serde_json::json!({ "id": "ping", "method": "ping", "params": [] });
            let content = nip44::encrypt(
                keys.secret_key(),
                &bunker,
                request.to_string(),
                nip44::Version::V2,
            )
            .unwrap();
            let event = nostr_sdk::EventBuilder::new(Kind::NostrConnect, content)
                .tag(nostr_sdk::Tag::public_key(bunker))
                .sign_with_keys(&keys)
                .unwrap();
            client.send_event(&event).await.unwrap();
            answered = tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    let Ok(nostr_sdk::RelayPoolNotification::Event { event, .. }) =
                        notifications.recv().await
                    else {
                        continue;
                    };
                    if event.pubkey != bunker {
                        continue;
                    }
                    if let Ok(plain) =
                        nip44::decrypt(keys.secret_key(), &bunker, event.content.as_str())
                    {
                        return plain.contains("pong");
                    }
                }
            })
            .await
            .unwrap_or(false);
            if answered {
                break;
            }
        }
        client.disconnect().await;
        answered
    }

    // A prompt blocks the server's own task, so a teardown while it is open
    // cannot stop the server until it returns. An approval that comes back
    // after the share changed must not be signed with the old one.
    #[test]
    fn an_approval_that_returns_after_a_teardown_is_refused() {
        struct ApprovesAfterTeardown(Arc<KeepMobile>);
        impl BunkerCallbacks for ApprovesAfterTeardown {
            fn on_log(&self, _event: BunkerLogEvent) {}
            fn request_approval(&self, _request: BunkerApprovalRequest) -> BunkerApprovalResult {
                self.0.invalidate_live_node();
                BunkerApprovalResult {
                    approved: true,
                    remember: BunkerRememberDuration::Forever,
                }
            }
            fn on_connect(&self, _pubkey: String, _name: String, _a: ConnectAuthorization) {}
        }

        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = Arc::new(KeepMobile::new(Arc::clone(&storage)).unwrap());
        let bridge = CallbackBridge {
            callbacks: Arc::new(ApprovesAfterTeardown(Arc::clone(&mobile))),
            mobile: Arc::clone(&mobile),
            approval_timeout: Duration::from_secs(5),
            generation: *mobile.live_generation.borrow(),
            outstanding: Arc::new(AtomicUsize::new(0)),
            grant_scope: String::new(),
            serving: Arc::new(AtomicBool::new(true)),
        };
        let result = ServerCallbacks::request_approval(&bridge, an_approval());
        assert!(!result.approved, "the share changed while it was asked");
    }
}
