// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Everything the gateway decides, under one lock: authentication, rate
//! limits, policy, budgets, signing and audit for agents, and management for
//! the owner. The socket layer passes each line in with the peer's uid and
//! writes back what this returns.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use keep_bitcoin::Network;
use keep_core::agent::{bindable_uid, AgentCredential, AgentRefusal};
use keep_core::keys::KeyType;
use keep_core::Keep;
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

mod approvals;
mod inject;

pub use approvals::{reset_store, Pending};
pub use inject::InjectSettings;
#[cfg(test)]
pub(crate) use inject::MAX_IN_FLIGHT;
pub(crate) use inject::{checked_response, InjectJob, InjectOutcome};

use super::clock::{self, Clock, Heartbeat, Seed, TimeSource, HEARTBEAT_KEY};
use super::limits::Counters;
use super::tools;
use crate::error::{AgentError, Result};
use crate::gateway::{
    authenticate, issue_credential, AgentAudit, GrantedCredential, RefusalKind, RefusedBecause,
    AUDIT_BUDGET_PER_DAY, GATEWAY_AUDIT_BUDGET_PER_DAY,
};
use crate::policy::{
    evaluate, Budgets, Decision, DenyReason, Grant, Ledger, Request, RequestLimits, Reservation,
    ReservedKeys,
};
use crate::scope::Operation;

/// The JSON-RPC error code every refused token, malformed envelope or
/// rate-limited uid gets, with the same message, so a token's state never
/// leaks to whoever presents it.
pub const REFUSED_CODE: i64 = -32001;
pub const REFUSED_MESSAGE: &str = "request refused";

/// A credential lives this long unless the owner says otherwise.
pub const DEFAULT_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// The most audit entries one admin `audit` request returns.
pub const MAX_AUDIT_READ: usize = 10_000;

/// Credentials whose request counts are tracked at once. Well above the
/// vault's cap, which deleted credentials' stale counts may briefly join.
const MAX_TRACKED_CREDENTIALS: usize = 1_024;

/// Agent uids whose request counts are tracked at once.
const MAX_TRACKED_UIDS: usize = 1_024;

/// The uids some stored credential is bound to, revoked and expired ones
/// included. Shared with the socket layer, which gives connections from these
/// uids their own slots.
pub type BoundUids = Arc<RwLock<HashSet<u32>>>;

/// The one key every uid no credential is bound to is counted under, for
/// connections and requests. No token can be served to such a uid, so all of
/// them together get only enough room to be refused, and however many uids an
/// agent controls, it cannot crowd out the uids credentials are bound to.
/// Never bindable, so never a bound uid.
pub const UNBOUND: u32 = u32::MAX;

/// The key `uid` is counted under: its own when a credential is bound to it,
/// otherwise [`UNBOUND`]. A poisoned set counts every uid as unbound.
pub fn pool(bound: &BoundUids, uid: u32) -> u32 {
    match bound.read() {
        Ok(set) if set.contains(&uid) => uid,
        _ => UNBOUND,
    }
}

/// What the host the gateway runs on says about uids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Host {
    /// The gateway's effective uid.
    pub euid: u32,
    /// The kernel's overflow uid (`/proc/sys/kernel/overflowuid`).
    pub overflow_uid: u32,
    /// The owner of the vault directory.
    pub vault_owner: u32,
}

impl Host {
    /// Read the running host, for the vault at `vault`.
    pub fn detect(vault: &std::path::Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let overflow = std::fs::read_to_string("/proc/sys/kernel/overflowuid")
            .map_err(|e| AgentError::Other(format!("read the overflow uid: {e}")))?;
        let overflow_uid = overflow
            .trim()
            .parse()
            .map_err(|_| AgentError::Other(format!("unexpected overflow uid {overflow:?}")))?;
        let vault_owner = std::fs::metadata(vault)
            .map_err(|e| AgentError::Other(format!("read {}: {e}", vault.display())))?
            .uid();
        Ok(Self {
            euid: rustix::process::geteuid().as_raw(),
            overflow_uid,
            vault_owner,
        })
    }
}

/// The owner's settings for a running gateway.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The one non-root uid allowed on the admin socket.
    pub admin_uid: Option<u32>,
    /// The relay helper's user, when approvals are on: the only uid the
    /// relay socket serves, so no credential may be bound to it.
    pub relay_uid: Option<u32>,
    /// What every credential together may take out of one key's wallet in any
    /// budget window, fees included. Zero refuses every spend.
    pub wallet_budget_sats: u64,
    /// Requests one agent uid may make, authenticated or not. Uids no
    /// credential is bound to share one such allowance.
    pub uid_limits: RequestLimits,
    /// Audit entries a day: one credential's, and every credential's together.
    pub audit_budgets: (u32, u32),
    /// Where inject workers are reached, when `http_request` is served.
    pub inject: Option<InjectSettings>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            admin_uid: None,
            relay_uid: None,
            wallet_budget_sats: 0,
            uid_limits: RequestLimits {
                per_minute: 120,
                per_hour: 3_000,
                per_day: 20_000,
            },
            audit_budgets: (AUDIT_BUDGET_PER_DAY, GATEWAY_AUDIT_BUDGET_PER_DAY),
            inject: None,
        }
    }
}

/// What to send back for one request line.
pub struct Answer {
    /// The line to write, if any (a notification gets none).
    pub line: Option<Zeroizing<String>>,
    /// Whether the request's token was accepted.
    pub authenticated: bool,
    /// A request waiting for an approver: its line comes later.
    pub pending: Option<Pending>,
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Answer")
            .field("authenticated", &self.authenticated)
            .field("pending", &self.pending.is_some())
            .finish_non_exhaustive()
    }
}

/// An answer now, or one that waits for an approver.
enum Reply {
    Now(Zeroizing<String>),
    Later(Pending),
}

impl Answer {
    fn refused(id: Value) -> Self {
        Self {
            line: Some(rpc_error(id, REFUSED_CODE, REFUSED_MESSAGE)),
            authenticated: false,
            pending: None,
        }
    }

    fn authenticated(reply: Option<Reply>) -> Self {
        let (line, pending) = match reply {
            Some(Reply::Now(line)) => (Some(line), None),
            Some(Reply::Later(pending)) => (None, Some(pending)),
            None => (None, None),
        };
        Self {
            line,
            authenticated: true,
            pending,
        }
    }
}

fn line(value: &Value) -> Zeroizing<String> {
    Zeroizing::new(value.to_string())
}

fn rpc_error(id: Value, code: i64, message: &str) -> Zeroizing<String> {
    line(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    }))
}

fn rpc_result(id: Value, result: Value) -> Zeroizing<String> {
    line(&json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

/// A `tools/call` result.
fn tool_result(id: Value, content: &Value, is_error: bool) -> Zeroizing<String> {
    let text = match content {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    rpc_result(
        id,
        json!({ "content": [{ "type": "text", "text": text }], "isError": is_error }),
    )
}

/// The envelope an agent sends: its token and one JSON-RPC message.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    token: Zeroizing<String>,
    message: Value,
}

/// Why an authenticated request was not served.
enum Refusal {
    /// The request is malformed: a JSON-RPC error with `code`.
    Invalid { code: i64, message: String },
    /// The policy denied it, or it needs an approval: a tool error the agent
    /// may read, and the fuller detail the audit log keeps.
    Policy {
        kind: RefusalKind,
        message: String,
        detail: String,
    },
    /// The gateway could not serve it (the vault or the audit log failed).
    Internal(String),
    /// The policy asks for an approval, which no approver can give.
    NeedsApproval(crate::policy::ApprovalReason),
    /// The policy asks for an approval: park it for the approvers.
    Park(Box<approvals::ParkAsk>),
}

impl Refusal {
    /// What the owner's entry about a request that was not carried out says.
    fn owner_text(&self) -> String {
        match self {
            Self::Invalid { message, .. } | Self::Internal(message) => message.clone(),
            Self::Policy { detail, .. } => detail.clone(),
            Self::NeedsApproval(reason) => format!("needs approval again: {reason:?}"),
            Self::Park(_) => "asked for an approval again".into(),
        }
    }

    fn params(message: impl Into<String>) -> Self {
        Self::Invalid {
            code: -32602,
            message: message.into(),
        }
    }

    fn denied(reason: impl std::fmt::Display) -> Self {
        let message = format!("denied: {reason}");
        Self::Policy {
            kind: RefusalKind::Denied,
            detail: message.clone(),
            message,
        }
    }

    /// A request that waits for no approval: one already pending, or too
    /// many waiting, or too large to ask about.
    fn refused_approval(message: &str) -> Self {
        Self::Policy {
            kind: RefusalKind::NeedsApproval,
            message: message.into(),
            detail: message.into(),
        }
    }

    /// A policy denial. What the wallet has spent across every credential is
    /// kept from the agent, which may know only its own spends.
    fn deny(reason: DenyReason) -> Self {
        match reason {
            DenyReason::WalletBudgetExceeded { .. } => Self::Policy {
                kind: RefusalKind::Denied,
                message: "denied: this spend would exceed the wallet's budget".into(),
                detail: format!("denied: {reason}"),
            },
            reason => Self::denied(reason),
        }
    }
}

type Served = std::result::Result<Value, Refusal>;

/// The gateway's state. Every request runs to completion under the one lock
/// that holds it, so a decision, the ledgers it reserves in and the audit
/// entry that records it cannot interleave with another request, a freeze or
/// a revocation.
pub struct State {
    keep: Keep,
    audit: AgentAudit,
    clock: Clock,
    settings: Settings,
    host: Host,
    bound: BoundUids,
    uid_counts: Counters<u32>,
    credential_counts: Counters<[u8; 16]>,
    /// The minute each uid last had a refusal logged to the journal, so an
    /// agent cannot flood it.
    journal: HashMap<u32, u64>,
    /// Journal lines waiting for the next tick, written then rather than
    /// before the answer, like deferred refusals.
    journal_lines: Vec<(u32, &'static str)>,
    /// Set once the gateway has written out its state to stop: nothing more is
    /// served, so nothing is left unwritten.
    closed: bool,
    /// Approvals over Nostr, when the channel key is loaded.
    approvals: Option<approvals::Approvals>,
    /// Whether owner entries may be owed in the vault, so the timer reads
    /// the approval state only then. True at start, until it has looked.
    owed_waiting: bool,
    /// A credential was refused as expired since the last tick: the clock is
    /// persisted then, so a crash cannot bring the calendar back behind that
    /// expiry. Not before the answer, which would time apart expired tokens.
    expiry_seen: bool,
    /// The stored heartbeat could not be read at start.
    heartbeat_ignored: bool,
    /// Refused tokens that matched a credential, recorded on the next tick
    /// rather than before the answer, so how long a refusal takes never tells
    /// whoever presented a token whether it is real.
    deferred: Vec<Deferred>,
    /// Deferred refusals dropped because the queue was full, since the last
    /// tick.
    dropped: u64,
    /// Keys no grant may name: the channel key and every registered approver
    /// device's keys.
    reserved: ReservedKeys,
    /// `http_request`s in flight, and the way to the inject workers.
    injects: inject::Injects,
    /// Tests only: how many withdrawals got as far as reading a credential
    /// row, and as far as checking the token against every credential.
    #[cfg(test)]
    pub(crate) withdrawal_checks: (usize, usize),
}

/// A refusal to record against the credential a token matched.
struct Deferred {
    credential: [u8; 16],
    detail: String,
    at: u64,
}

/// Deferred refusals held between ticks at most. Requests are rate limited
/// per uid well below this.
const MAX_DEFERRED: usize = 4_096;

impl State {
    /// Take over an unlocked vault: check it can be served safely, then start
    /// the clock from what it has persisted (see [`clock`]).
    pub fn start(
        keep: Keep,
        settings: Settings,
        host: Host,
        source: Box<dyn TimeSource>,
        boot_id: String,
    ) -> Result<Self> {
        if !keep.is_unlocked() {
            return Err(AgentError::Other("the vault is locked".into()));
        }
        if host.euid == 0 {
            return Err(AgentError::Other(
                "the gateway must run as its own user, not root".into(),
            ));
        }
        if let Some(admin) = settings.admin_uid {
            if admin == host.euid || admin == host.overflow_uid || !bindable_uid(admin) {
                return Err(AgentError::Other(format!(
                    "uid {admin} cannot be the admin uid"
                )));
            }
        }
        // An agent sharing the helper's uid could take its one connection
        // and cut the phones off.
        if let Some(relay) = settings.relay_uid {
            if relay == 0
                || relay == host.euid
                || relay == host.vault_owner
                || relay == host.overflow_uid
                || settings.admin_uid == Some(relay)
            {
                return Err(AgentError::Other(format!(
                    "uid {relay} cannot be the relay helper's user: give it a user of its own, \
                     not root, the gateway's, the vault owner's or the admin's"
                )));
            }
        }
        // Read before anything is served: an unreadable freeze refuses to start.
        let frozen = keep
            .agent_freeze()
            .map_err(|e| AgentError::Other(format!("the agent freeze cannot be read: {e}")))?;
        let mut floor = 0u64;
        let mut issued = 0u64;
        let mut bound_wrongly = Vec::new();
        let mut bound = HashSet::new();
        for id in keep.agent_credential_ids()? {
            match load_credential(&keep, &id) {
                // Issue times are on the calendar clock: they hold the calendar,
                // never the budget clock.
                Ok(Some(c)) => {
                    issued = issued.max(c.created_at);
                    bound.insert(c.uid);
                    let forbidden = forbidden_uid(&host, &settings, c.uid);
                    if !c.revoked && forbidden {
                        bound_wrongly
                            .push((format!("{} (uid {})", c.id_hex(), c.uid), c.expires_at));
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::error!(
                    id = %hex::encode(id),
                    error = %e,
                    "agent credential cannot be read; every token is refused until it is deleted"
                ),
            }
            floor = floor.max(ledger_last_seen(&keep, &id));
        }
        let pubkeys: Vec<[u8; 32]> = keep.keyring().list().map(|s| s.pubkey).collect();
        for pubkey in &pubkeys {
            for network in LEDGER_NETWORKS {
                floor = floor.max(ledger_last_seen(&keep, &wallet_key(pubkey, network)));
            }
        }
        let mut heartbeat_ignored = false;
        let heartbeat = match keep.load_agent_ledger(HEARTBEAT_KEY)? {
            None => None,
            // Without it the clock resumes from the ledgers and credentials,
            // which hold every spend: budgets are kept, never released early.
            Some(bytes) => match Heartbeat::decode(&bytes) {
                Ok(hb) => Some(hb),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "ignoring an unreadable clock heartbeat: the clocks resume from the \
                         ledgers and credentials"
                    );
                    heartbeat_ignored = true;
                    None
                }
            },
        };
        if let Some(hb) = &heartbeat {
            floor = floor.max(hb.clock);
        }
        let seed = Seed {
            heartbeat: heartbeat.as_ref(),
            floor,
            wall: source.wall(),
            boot_id: &boot_id,
            boottime: source.boottime(),
        };
        let start = clock::start_time(&seed);
        let calendar = clock::calendar_start(&seed, issued);
        let clock = Clock::new(start, calendar, boot_id, source);
        // Expired credentials can serve nothing, so only live ones stop a start
        // (revoking needs the running gateway).
        let calendar_now = clock.calendar();
        let bound_wrongly: Vec<String> = bound_wrongly
            .into_iter()
            .filter(|(_, expires_at)| calendar_now < *expires_at)
            .map(|(credential, _)| credential)
            .collect();
        if !bound_wrongly.is_empty() {
            return Err(AgentError::Other(format!(
                "credentials bound to the gateway's, the vault owner's, the admin's, the relay \
                 helper's or the overflow uid must be revoked first: {}",
                bound_wrongly.join(", ")
            )));
        }
        let (credential_budget, gateway_budget) = settings.audit_budgets;
        let injects = inject::Injects::new(settings.inject.clone());
        let mut state = Self {
            keep,
            audit: AgentAudit::with_budgets(credential_budget, gateway_budget),
            clock,
            settings,
            host,
            bound: Arc::new(RwLock::new(bound)),
            uid_counts: Counters::new(MAX_TRACKED_UIDS),
            credential_counts: Counters::new(MAX_TRACKED_CREDENTIALS),
            journal: HashMap::new(),
            journal_lines: Vec::new(),
            closed: false,
            approvals: None,
            owed_waiting: true,
            expiry_seen: false,
            heartbeat_ignored,
            deferred: Vec::new(),
            dropped: 0,
            reserved: ReservedKeys::new(),
            injects,
            #[cfg(test)]
            withdrawal_checks: (0, 0),
        };
        state.persist_heartbeat()?;
        tracing::info!(clock = start, frozen, "agent gateway state ready");
        Ok(state)
    }

    /// The budget clock now.
    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    /// The calendar clock now, which credential lifetimes are measured on.
    pub fn calendar(&self) -> u64 {
        self.clock.calendar()
    }

    /// The one non-root uid allowed on the admin socket.
    pub fn admin_uid(&self) -> Option<u32> {
        self.settings.admin_uid
    }

    /// The uids stored credentials are bound to, kept current as credentials
    /// are issued and deleted.
    pub fn bound_uids(&self) -> BoundUids {
        self.bound.clone()
    }

    /// Recount the bound uids from the vault, after a credential is deleted.
    fn refresh_bound(&mut self) -> Result<()> {
        let mut bound = HashSet::new();
        for id in self.keep.agent_credential_ids()? {
            if let Ok(Some(c)) = load_credential(&self.keep, &id) {
                bound.insert(c.uid);
            }
        }
        if let Ok(mut set) = self.bound.write() {
            *set = bound;
        }
        Ok(())
    }

    /// Persist the clock, so a restart continues it.
    pub fn persist_heartbeat(&mut self) -> Result<()> {
        let bytes = self.clock.heartbeat().encode()?;
        self.keep
            .update_agent_ledgers(&[HEARTBEAT_KEY], |_| Ok(vec![bytes]))?;
        Ok(())
    }

    /// Record the refusals deferred since the last tick, then write out
    /// refusal counts whose window has passed.
    pub fn tick(&mut self) {
        self.write_journal();
        self.record_deferred();
        if std::mem::take(&mut self.expiry_seen) {
            if let Err(e) = self.persist_heartbeat() {
                tracing::error!(error = %e, "the gateway clock could not be persisted");
            }
        }
        let now = self.clock.now();
        if let Err(e) = self.audit.flush_expired(&mut self.keep, now) {
            tracing::error!(error = %e, "agent refusal counts could not be written");
        }
    }

    /// Write out every open refusal count and the clock, and serve nothing
    /// more.
    pub fn shut_down(&mut self) {
        self.cancel_all("canceled: the gateway is stopping");
        self.closed = true;
        self.write_journal();
        self.record_deferred();
        let now = self.clock.now();
        if let Err(e) = self.audit.flush_all(&mut self.keep, now) {
            tracing::error!(error = %e, "agent refusal counts could not be written");
        }
        if let Err(e) = self.persist_heartbeat() {
            tracing::error!(error = %e, "the gateway clock could not be persisted");
        }
    }

    fn defer_refusal(&mut self, credential: [u8; 16], detail: String, at: u64) {
        if self.deferred.len() >= MAX_DEFERRED {
            self.dropped += 1;
            return;
        }
        self.deferred.push(Deferred {
            credential,
            detail,
            at,
        });
    }

    fn record_deferred(&mut self) {
        for d in std::mem::take(&mut self.deferred) {
            // A credential deleted since has nothing left to record against.
            if matches!(self.keep.load_agent_credential(&d.credential), Ok(None)) {
                continue;
            }
            if let Err(e) = self.audit.record_refusal(
                &mut self.keep,
                &d.credential,
                RefusalKind::Unauthenticated,
                &d.detail,
                d.at,
            ) {
                tracing::error!(error = %e, "agent refusal could not be recorded");
            }
        }
        if self.dropped > 0 {
            tracing::error!(
                dropped = self.dropped,
                "refused agent tokens went unrecorded: too many between ticks"
            );
            self.dropped = 0;
        }
    }

    /// Log a refusal to the journal at most once a minute per uid, and for at
    /// most [`MAX_TRACKED_UIDS`] uids a minute, so no number of uids can flood
    /// it and no one uid can hide the others.
    fn journal_refusal(&mut self, peer_uid: u32, now: u64, what: &'static str) {
        let minute = now / 60;
        if self.journal.get(&peer_uid) == Some(&minute) {
            return;
        }
        if self.journal.len() >= MAX_TRACKED_UIDS {
            self.journal.retain(|_, m| *m == minute);
            if self.journal.len() >= MAX_TRACKED_UIDS {
                return;
            }
        }
        self.journal.insert(peer_uid, minute);
        self.journal_lines.push((peer_uid, what));
    }

    fn write_journal(&mut self) {
        for (peer_uid, what) in std::mem::take(&mut self.journal_lines) {
            tracing::warn!(peer_uid, what, "agent request refused");
        }
    }

    /// Handle one line from the agent socket, sent by `peer_uid`.
    pub fn agent_request(&mut self, peer_uid: u32, request: &[u8]) -> Answer {
        let cancellation = cancellation(request);
        // A line refused before it is read is answered with a null id, except
        // a cancellation, a notification, which is never answered: a client
        // waiting on a request never takes that refusal for the request's.
        let unread = |cancellation: &Option<Envelope>| match cancellation {
            Some(_) => Answer {
                line: None,
                authenticated: false,
                pending: None,
            },
            None => Answer::refused(Value::Null),
        };
        if self.closed {
            return unread(&cancellation);
        }
        let now = self.clock.now();
        if let Some(answer) = cancellation
            .as_ref()
            .and_then(|envelope| self.withdrawal(peer_uid, envelope))
        {
            return answer;
        }
        let counted = pool(&self.bound, peer_uid);
        if let Err(window) = self.uid_counts.hit(counted, &self.settings.uid_limits, now) {
            self.journal_refusal(peer_uid, now, window);
            return unread(&cancellation);
        }
        let envelope: Envelope = match cancellation {
            Some(envelope) => envelope,
            None => match serde_json::from_slice(request) {
                Ok(e) => e,
                Err(_) => {
                    self.journal_refusal(peer_uid, now, "malformed envelope");
                    return Answer::refused(Value::Null);
                }
            },
        };
        let Envelope { token, message } = envelope;
        let id = message.get("id").cloned();
        let refused = |id: Option<Value>| match id {
            Some(id) => Answer::refused(id),
            None => Answer {
                line: None,
                authenticated: false,
                pending: None,
            },
        };
        // A uid no credential may be bound to is refused whatever it presents,
        // but its token is still matched, so a real one is recorded against
        // its credential as the theft signal it is.
        let forbidden =
            forbidden_uid(&self.host, &self.settings, peer_uid) || !bindable_uid(peer_uid);
        let granted = match authenticate(
            &self.keep,
            &token,
            peer_uid,
            self.clock.calendar(),
            &self.reserved,
        ) {
            Ok(Ok(granted)) if !forbidden => granted,
            Ok(Ok(granted)) => {
                drop(token);
                self.defer_refusal(
                    granted.credential.id,
                    format!("presented by uid {peer_uid}, which may hold no credential"),
                    now,
                );
                return refused(id);
            }
            Ok(Err(refusal)) => {
                drop(token);
                match refusal.credential {
                    Some(cid) => {
                        let detail = match refusal.because {
                            RefusedBecause::Credential(AgentRefusal::WrongUid) => {
                                format!("presented by uid {peer_uid}")
                            }
                            RefusedBecause::Credential(reason) => {
                                if reason == AgentRefusal::Expired {
                                    self.expiry_seen = true;
                                }
                                reason.to_string()
                            }
                            RefusedBecause::Grant => "grant does not load".into(),
                        };
                        self.defer_refusal(cid, detail, now);
                    }
                    None => self.journal_refusal(peer_uid, now, "unknown token"),
                }
                if forbidden {
                    self.journal_refusal(peer_uid, now, "uid may not hold a credential");
                }
                return refused(id);
            }
            Err(e) => {
                tracing::error!(error = %e, "agent credentials cannot be read");
                return refused(id);
            }
        };
        drop(token);
        Answer::authenticated(self.serve(&granted, &message, id, now))
    }

    /// A cancellation of a request this uid parked, with the token of the
    /// credential that parked it: withdrawn here, neither refused by the
    /// uid's request limit nor counted against it, so an agent at its limit
    /// can still take back what it asked for. Anything else goes the counted
    /// way, which refuses and records it. Before the limit, a line costs at
    /// most a look at the uid's own parked requests and one credential row;
    /// only a token that row matches is checked in full.
    fn withdrawal(&mut self, peer_uid: u32, envelope: &Envelope) -> Option<Answer> {
        let parked = envelope.message.get("params")?.get("requestId")?;
        let credential = self.parked_agent_request(peer_uid, parked)?;
        let hash = keep_core::agent::hash_presented_token(&envelope.token)?;
        #[cfg(test)]
        {
            self.withdrawal_checks.0 += 1;
        }
        if !load_credential(&self.keep, &credential)
            .ok()??
            .matches_hash(&hash)
        {
            return None;
        }
        #[cfg(test)]
        {
            self.withdrawal_checks.1 += 1;
        }
        // The rest of what a token must be: live, unfrozen, its uid's.
        authenticate(
            &self.keep,
            &envelope.token,
            peer_uid,
            self.clock.calendar(),
            &self.reserved,
        )
        .ok()?
        .ok()?;
        self.cancel_agent_request(&credential, parked);
        Some(Answer::authenticated(None))
    }

    /// Serve an authenticated request.
    fn serve(
        &mut self,
        granted: &GrantedCredential,
        message: &Value,
        id: Option<Value>,
        now: u64,
    ) -> Option<Reply> {
        let cid = granted.credential.id;
        let method = message.get("method").and_then(Value::as_str);
        // The agent withdrew a request that waits for an approver: before the
        // request limit and never counted against it, so an agent at its
        // limit can still take back what it asked for.
        if id.is_none() && method == Some("notifications/cancelled") {
            if let Some(request) = message.get("params").and_then(|p| p.get("requestId")) {
                self.cancel_agent_request(&cid, request);
            }
            return None;
        }
        if let Err(window) = self.credential_counts.hit(cid, &granted.grant.limits, now) {
            let detail = if window == "tracker" {
                "the gateway is tracking too many credentials".to_string()
            } else {
                format!("over its per-{window} limit")
            };
            self.record_refusal(&cid, RefusalKind::RateLimited, &detail, now);
            return id
                .map(|id| Reply::Now(rpc_error(id, -32002, &format!("rate limited: {detail}"))));
        }
        let id = match (id, method) {
            (Some(id), Some(_)) => id,
            // Any other notification is never answered or acted on.
            (None, Some(_)) => return None,
            (id, None) => {
                self.record_refusal(&cid, RefusalKind::Invalid, "no method", now);
                return id.map(|id| Reply::Now(rpc_error(id, -32600, "invalid request")));
            }
        };
        let method = method.unwrap_or_default();
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            self.record_refusal(&cid, RefusalKind::Invalid, "not JSON-RPC 2.0", now);
            return Some(Reply::Now(rpc_error(id, -32600, "invalid request")));
        }
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        match method {
            "ping" => {
                // Returns nothing, so it is only checked against the budget.
                if let Err(e) = self.audit.admit(&mut self.keep, &cid, now) {
                    tracing::warn!(error = %e, "agent ping refused");
                    return Some(Reply::Now(rpc_error(
                        id,
                        -32603,
                        "the gateway could not complete the request",
                    )));
                }
                Some(Reply::Now(rpc_result(id, json!({}))))
            }
            "initialize" | "tools/list" => {
                if let Err(e) = self
                    .audit
                    .record_served(&mut self.keep, &cid, method, None, now)
                {
                    tracing::error!(error = %e, "agent handshake could not be recorded");
                    return Some(Reply::Now(rpc_error(
                        id,
                        -32603,
                        "the gateway could not complete the request",
                    )));
                }
                let result = if method == "initialize" {
                    json!({
                        "protocolVersion": "2024-11-05",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "keep-gateway", "version": env!("CARGO_PKG_VERSION") }
                    })
                } else {
                    json!({ "tools": tools::list(&granted.grant) })
                };
                Some(Reply::Now(rpc_result(id, result)))
            }
            "tools/call" => Some(self.tools_call(granted, id, &params, now)),
            other => {
                self.record_refusal(&cid, RefusalKind::Invalid, other, now);
                Some(Reply::Now(rpc_error(id, -32601, "method not found")))
            }
        }
    }

    fn record_refusal(&mut self, cid: &[u8; 16], kind: RefusalKind, detail: &str, now: u64) {
        if let Err(e) = self
            .audit
            .record_refusal(&mut self.keep, cid, kind, detail, now)
        {
            tracing::error!(error = %e, "agent refusal could not be recorded");
        }
    }

    fn tools_call(
        &mut self,
        granted: &GrantedCredential,
        id: Value,
        params: &Value,
        now: u64,
    ) -> Reply {
        let cid = granted.credential.id;
        let name = params.get("name").and_then(Value::as_str);
        let empty = json!({});
        let args = match params.get("arguments") {
            None | Some(Value::Null) => &empty,
            Some(a @ Value::Object(_)) => a,
            Some(_) => {
                self.record_refusal(&cid, RefusalKind::Invalid, "arguments", now);
                return Reply::Now(rpc_error(id, -32602, "arguments must be an object"));
            }
        };
        let served = match name {
            Some(tools::GET_PUBKEY) => self.get_pubkey(granted, args, now),
            Some(tools::SIGN_EVENT) => self.sign_event(granted, args, now),
            Some(tools::GET_ADDRESS) => self.get_address(granted, args, now),
            Some(tools::SIGN_PSBT) => self.sign_psbt(granted, args, now),
            Some(tools::SESSION_INFO) => self.session_info(granted, args, now),
            Some(tools::LIST_SECRETS) => self.list_secrets(granted, args, now),
            Some(tools::HTTP_REQUEST) => return self.http_request(granted, id, args, now),
            _ => Err(Refusal::Invalid {
                code: -32602,
                message: "unknown tool".into(),
            }),
        };
        let label = name.unwrap_or("no tool");
        match served {
            Err(Refusal::Park(ask)) => {
                let tool = match name {
                    Some(tools::SIGN_PSBT) => tools::SIGN_PSBT,
                    _ => tools::SIGN_EVENT,
                };
                match self.park_agent(granted, id.clone(), tool, *ask, now) {
                    Ok(pending) => Reply::Later(pending),
                    Err(refusal) => {
                        Reply::Now(self.answer_tool(granted, id, label, Err(refusal), now))
                    }
                }
            }
            served => Reply::Now(self.answer_tool(granted, id, label, served, now)),
        }
    }

    /// The line answering a tool call, recording a refusal first.
    fn answer_tool(
        &mut self,
        granted: &GrantedCredential,
        id: Value,
        label: &str,
        served: Served,
        now: u64,
    ) -> Zeroizing<String> {
        let cid = granted.credential.id;
        match served {
            Ok(content) => tool_result(id, &content, false),
            Err(Refusal::NeedsApproval(reason)) => {
                let message =
                    format!("needs approval, which this gateway cannot obtain yet: {reason}");
                self.record_refusal(
                    &cid,
                    RefusalKind::NeedsApproval,
                    &format!("{label}: {message}"),
                    now,
                );
                tool_result(id, &Value::String(message), true)
            }
            Err(Refusal::Park(_)) => {
                tracing::error!(tool = label, "a request to park was not parked");
                rpc_error(id, -32603, "the gateway could not complete the request")
            }
            Err(Refusal::Invalid { code, message }) => {
                self.record_refusal(
                    &cid,
                    RefusalKind::Invalid,
                    &format!("{label}: {message}"),
                    now,
                );
                rpc_error(id, code, &message)
            }
            Err(Refusal::Policy {
                kind,
                message,
                detail,
            }) => {
                self.record_refusal(&cid, kind, &format!("{label}: {detail}"), now);
                tool_result(id, &Value::String(message), true)
            }
            Err(Refusal::Internal(message)) => {
                // The detail stays with the owner; the agent learns only that
                // the request failed.
                tracing::error!(tool = label, error = %message, "agent request failed");
                self.record_refusal(
                    &cid,
                    RefusalKind::Failed,
                    &format!("{label}: {message}"),
                    now,
                );
                rpc_error(id, -32603, "the gateway could not complete the request")
            }
        }
    }

    /// Decide a request that reserves nothing.
    fn decide(&self, grant: &Grant, key: &[u8; 32], request: &Request<'_>, now: u64) -> Served {
        // Requests other than a spend never touch a ledger.
        let (mut c, mut w) = (Ledger::default(), Ledger::default());
        let mut budgets = Budgets {
            credential: &mut c,
            wallet: &mut w,
            wallet_window_sats: 0,
        };
        match evaluate(grant, key, request, &mut budgets, now) {
            Decision::Allow => Ok(Value::Null),
            Decision::Deny(reason) => Err(Refusal::deny(reason)),
            Decision::RequireApproval(reason) => Err(Refusal::NeedsApproval(reason)),
            Decision::Spend(_) => Err(Refusal::Internal(
                "a request that spends nothing reserved a spend".into(),
            )),
        }
    }

    /// The vault secret of granted `key`, which must be a signing key.
    fn secret(&self, key: &[u8; 32]) -> std::result::Result<Zeroizing<[u8; 32]>, Refusal> {
        let slot = self
            .keep
            .keyring()
            .get(key)
            .ok_or_else(|| Refusal::denied("that key is not in the vault"))?;
        if !matches!(slot.key_type, KeyType::Nostr | KeyType::Bitcoin) {
            return Err(Refusal::denied("that key is not a signing key"));
        }
        Ok(Zeroizing::new(*slot.expose_secret()))
    }

    fn get_pubkey(&mut self, granted: &GrantedCredential, args: &Value, now: u64) -> Served {
        only_args(args, &["key"])?;
        let key = key_arg(&granted.grant, args)?;
        self.decide(&granted.grant, &key, &Request::GetPublicKey, now)?;
        self.secret(&key)?;
        let hex = hex::encode(key);
        self.served(granted, tools::GET_PUBKEY, &hex, now)?;
        Ok(json!({ "npub": keep_core::keys::bytes_to_npub(&key), "hex": hex }))
    }

    fn sign_event(&mut self, granted: &GrantedCredential, args: &Value, now: u64) -> Served {
        use nostr_sdk::prelude::{EventBuilder, Keys, Kind, SecretKey, Tag};
        only_args(args, &["key", "kind", "content", "tags"])?;
        let key = key_arg(&granted.grant, args)?;
        let kind = args
            .get("kind")
            .and_then(Value::as_u64)
            .and_then(|k| u16::try_from(k).ok())
            .ok_or_else(|| Refusal::params("kind must be an integer from 0 to 65535"))?;
        let content = args
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| Refusal::params("content must be a string"))?;
        let tags: Vec<Tag> = match args.get("tags") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(tags)) => tags
                .iter()
                .map(|t| {
                    let parts: Vec<String> = serde_json::from_value(t.clone())
                        .map_err(|_| Refusal::params("each tag is an array of strings"))?;
                    if parts.is_empty() {
                        return Err(Refusal::params("a tag cannot be empty"));
                    }
                    Tag::parse(parts).map_err(|e| Refusal::params(format!("invalid tag: {e}")))
                })
                .collect::<std::result::Result<_, _>>()?,
            Some(_) => return Err(Refusal::params("tags must be an array")),
        };
        match self.decide(&granted.grant, &key, &Request::SignNostrEvent { kind }, now) {
            Err(Refusal::NeedsApproval(reason)) if self.approvals_active() => {
                // The exact event, its time fixed now, is what the approver
                // is shown and what is signed.
                let event = keep_approval::binding::UnsignedEventFields {
                    pubkey: keep_approval::Hex32(key),
                    created_at: self.clock.calendar(),
                    kind,
                    tags: tags.iter().map(|t| t.as_slice().to_vec()).collect(),
                    content: content.to_string(),
                };
                return Err(Refusal::Park(Box::new(approvals::ParkAsk {
                    object: crate::approval::ParkedObject::NostrEvent(event),
                    reason: approvals::wire_reason(&reason),
                    budget: None,
                })));
            }
            decided => {
                decided?;
            }
        }
        let secret = self.secret(&key)?;
        let keys = SecretKey::from_slice(secret.as_slice())
            .map(Keys::new)
            .map_err(|e| Refusal::Internal(format!("vault key: {e}")))?;
        drop(secret);
        if keys.public_key().to_bytes() != key {
            return Err(Refusal::Internal(
                "the vault key does not match its public key".into(),
            ));
        }
        let event = EventBuilder::new(Kind::from(kind), content)
            .tags(tags)
            .sign_with_keys(&keys)
            .map_err(|e| Refusal::Internal(format!("sign: {e}")))?;
        drop(keys);
        let context = format!("sign_nostr_event kind {kind} id {}", event.id);
        self.audit
            .record_signature(
                &mut self.keep,
                &granted.credential.id,
                &key,
                event.id.as_bytes(),
                &context,
                now,
            )
            .map_err(withheld)?;
        serde_json::to_value(&event).map_err(|e| Refusal::Internal(e.to_string()))
    }

    fn get_address(&mut self, granted: &GrantedCredential, args: &Value, now: u64) -> Served {
        only_args(args, &["key", "type", "network"])?;
        let key = key_arg(&granted.grant, args)?;
        match args.get("type") {
            None | Some(Value::Null) => {}
            Some(Value::String(t)) if t == "p2tr" => {}
            Some(_) => return Err(Refusal::params("only p2tr addresses are served")),
        }
        let network = network_arg(&granted.grant, args)?;
        self.decide(
            &granted.grant,
            &key,
            &Request::GetBitcoinAddress { network },
            now,
        )?;
        let mut secret = self.secret(&key)?;
        let signer = keep_bitcoin::BitcoinSigner::new(&mut secret, network)
            .map_err(|e| Refusal::Internal(e.to_string()))?;
        drop(secret);
        let address = signer
            .get_receive_address(0)
            .map_err(|e| Refusal::Internal(e.to_string()))?;
        drop(signer);
        self.served(
            granted,
            tools::GET_ADDRESS,
            &format!("{network} {address}"),
            now,
        )?;
        Ok(json!({ "address": address, "type": "p2tr", "network": network.to_string() }))
    }

    fn sign_psbt(&mut self, granted: &GrantedCredential, args: &Value, now: u64) -> Served {
        only_args(args, &["key", "psbt", "network"])?;
        let key = key_arg(&granted.grant, args)?;
        let encoded = args
            .get("psbt")
            .and_then(Value::as_str)
            .ok_or_else(|| Refusal::params("psbt must be a base64 string"))?;
        let network = network_arg(&granted.grant, args)?;
        // Checked before the key is touched; the spend itself is decided below
        // with the analysis.
        let cid = granted.credential.id;
        if !granted.grant.keys.contains(&key) {
            return Err(Refusal::denied(DenyReason::KeyNotGranted));
        }
        if !granted.grant.operations.contains(&Operation::SignPsbt) {
            return Err(Refusal::denied(DenyReason::OperationNotGranted(
                Operation::SignPsbt,
            )));
        }
        let mut psbt = keep_bitcoin::psbt::parse_psbt_base64(encoded)
            .map_err(|e| Refusal::params(format!("invalid PSBT: {e}")))?;
        let mut secret = self.secret(&key)?;
        let signer = keep_bitcoin::BitcoinSigner::new(&mut secret, network)
            .map_err(|e| Refusal::Internal(e.to_string()))?;
        drop(secret);
        let analysis = signer
            .analyze_psbt(&psbt)
            .map_err(|e| Refusal::params(format!("PSBT cannot be analyzed: {e}")))?;
        let request = Request::SignPsbt {
            analysis: &analysis,
        };
        let wallet = wallet_key(&key, network);
        let wallet_window_sats = self.settings.wallet_budget_sats;
        let mut decision = None;
        let mut wallet_spent = 0;
        // Evaluate and reserve in one durable transaction with both ledgers.
        self.keep
            .update_agent_ledgers(&[&cid, &wallet], |current| {
                let mut credential = decode_ledger(current[0].as_ref().map(|v| v.as_slice()))?;
                let mut wallet = decode_ledger(current[1].as_ref().map(|v| v.as_slice()))?;
                let mut budgets = Budgets {
                    credential: &mut credential,
                    wallet: &mut wallet,
                    wallet_window_sats,
                };
                decision = Some(evaluate(&granted.grant, &key, &request, &mut budgets, now));
                wallet_spent = wallet.spent(now);
                Ok(vec![encode_ledger(&credential)?, encode_ledger(&wallet)?])
            })
            .map_err(|e| Refusal::Internal(format!("the budget ledgers cannot be updated: {e}")))?;
        let reservation = match decision {
            Some(Decision::Allow) => None,
            Some(Decision::Spend(reservation)) => Some(reservation),
            Some(Decision::Deny(reason)) => return Err(Refusal::deny(reason)),
            Some(Decision::RequireApproval(reason)) if self.approvals_active() => {
                let crate::policy::ApprovalReason::AboveThreshold { spent, .. } = reason else {
                    return Err(Refusal::NeedsApproval(reason));
                };
                let window_sats = granted.grant.bitcoin.as_ref().map_or(0, |b| b.window_sats);
                let mut change = Vec::new();
                for output in analysis.outputs.iter().filter(|o| o.is_change) {
                    let index = signer.change_index(&psbt, output.index).ok_or_else(|| {
                        Refusal::Internal("a change output has no change index".into())
                    })?;
                    change.push((output.index, index));
                }
                drop(signer);
                return Err(Refusal::Park(Box::new(approvals::ParkAsk {
                    object: crate::approval::ParkedObject::Psbt {
                        psbt: Box::new(psbt),
                        analysis,
                        key,
                        change,
                    },
                    reason: approvals::wire_reason(&reason),
                    budget: Some(keep_approval::messages::Budget {
                        credential_spent: spent,
                        credential_window: window_sats,
                        wallet_spent,
                        wallet_window: wallet_window_sats,
                    }),
                })));
            }
            Some(Decision::RequireApproval(reason)) => return Err(Refusal::NeedsApproval(reason)),
            None => return Err(Refusal::Internal("no decision".into())),
        };
        let signed = signer
            .sign_psbt(&mut psbt)
            .map_err(|e| Refusal::Internal(format!("sign: {e}")))
            .and_then(|count| {
                if count == 0 {
                    return Err(Refusal::params("the PSBT has no input this key can sign"));
                }
                let txid = psbt.unsigned_tx.compute_txid();
                let context = format!(
                    "sign_bitcoin_psbt txid {txid} inputs {count} leaving {} sats fee {} sats",
                    analysis.leaving_wallet_sats(),
                    analysis.fee_sats
                );
                self.audit
                    .record_signature(&mut self.keep, &cid, &key, txid.as_ref(), &context, now)
                    .map_err(withheld)?;
                Ok(count)
            });
        drop(signer);
        match signed {
            Ok(count) => Ok(json!({
                "signed_psbt": keep_bitcoin::psbt::serialize_psbt_base64(&psbt),
                "inputs_signed": count,
                "fee_sats": analysis.fee_sats,
                "leaving_wallet_sats": analysis.leaving_wallet_sats(),
                "network": network.to_string()
            })),
            Err(refusal) => {
                // No signature left the gateway: return the reservation.
                if let Some(reservation) = reservation {
                    self.release(&cid, &wallet, reservation);
                }
                Err(refusal)
            }
        }
    }

    fn release(&mut self, cid: &[u8; 16], wallet: &[u8], reservation: Reservation) {
        let released = self.keep.update_agent_ledgers(&[cid, wallet], |current| {
            let mut credential = decode_ledger(current[0].as_ref().map(|v| v.as_slice()))?;
            let mut wallet = decode_ledger(current[1].as_ref().map(|v| v.as_slice()))?;
            reservation.release(&mut credential, &mut wallet);
            Ok(vec![encode_ledger(&credential)?, encode_ledger(&wallet)?])
        });
        if let Err(e) = released {
            // The spend stays counted, which only errs toward less spending.
            tracing::error!(error = %e, "an unused spend reservation could not be released");
        }
    }

    fn session_info(&mut self, granted: &GrantedCredential, args: &Value, now: u64) -> Served {
        only_args(args, &[])?;
        self.served(granted, tools::SESSION_INFO, "", now)?;
        let c = &granted.credential;
        Ok(json!({
            "id": c.id_hex(),
            "name": c.name,
            "expires_at": c.expires_at,
            "grant": grant_json(&granted.grant),
            "approvals": {
                "enabled": self.approvals_active(),
                "deadline_secs": self.approval_deadline(),
            },
        }))
    }

    /// The secrets the grant names, with what each may be used for: never a
    /// value. A secret deleted, sealed or of a kind its use does not allow
    /// since the grant was issued is listed as unusable.
    fn list_secrets(&mut self, granted: &GrantedCredential, args: &Value, now: u64) -> Served {
        only_args(args, &[])?;
        if granted.grant.secrets.is_empty() {
            return Err(Refusal::deny(DenyReason::SecretNotGranted));
        }
        let secrets: Vec<Value> = granted
            .grant
            .secrets
            .iter()
            .map(|entry| {
                let id = hex::encode(entry.secret);
                match self.keep.secret_info(&entry.secret) {
                    Ok(info) => json!({
                        "id": id,
                        "name": info.name,
                        "kind": info.kind.as_str(),
                        "usable": !info.sealed
                            && crate::inject::rule::HTTP_KINDS.contains(&info.kind),
                        "http": entry.http,
                    }),
                    Err(_) => json!({ "id": id, "usable": false, "http": entry.http }),
                }
            })
            .collect();
        self.served(granted, tools::LIST_SECRETS, "", now)?;
        Ok(json!({ "secrets": secrets }))
    }

    fn served(
        &mut self,
        granted: &GrantedCredential,
        label: &str,
        detail: &str,
        now: u64,
    ) -> std::result::Result<(), Refusal> {
        let detail = (!detail.is_empty()).then_some(detail);
        self.audit
            .record_served(&mut self.keep, &granted.credential.id, label, detail, now)
            .map_err(withheld)
    }

    /// Handle one line from the admin socket, as root on connection 0. A
    /// request that waits for an approver answers only that it is pending.
    #[cfg(test)]
    pub(crate) fn admin_request(&mut self, request: &[u8]) -> Zeroizing<String> {
        self.admin_request_from(0, 0, request).0
    }

    /// Handle one line from the admin socket, from `uid` on connection
    /// `conn`. The caller has checked the peer is root or the admin uid. A
    /// change that gives agents more power, with an approver registered,
    /// waits for one: the answer then says so, and the outcome comes later.
    pub fn admin_request_from(
        &mut self,
        uid: u32,
        conn: u64,
        request: &[u8],
    ) -> (Zeroizing<String>, Option<Pending>) {
        let failed = |e: AgentError| line(&json!({ "ok": false, "error": e.to_string() }));
        if self.closed {
            return (
                failed(AgentError::Other("the gateway is stopping".into())),
                None,
            );
        }
        let request = match serde_json::from_slice::<AdminRequest>(request) {
            Ok(r) => r,
            Err(e) => {
                return (
                    failed(AgentError::Other(format!("invalid admin request: {e}"))),
                    None,
                )
            }
        };
        let approve = self.approvals_active();
        match request {
            AdminRequest::Issue {
                name,
                uid: agent_uid,
                grant,
                ttl_secs,
            } => {
                let ttl = ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
                if approve {
                    match self.issuable_grant(agent_uid, grant) {
                        Ok(grant) => self.park_issue(conn, &name, agent_uid, grant, ttl),
                        Err(e) => (failed(e), None),
                    }
                } else {
                    (
                        self.issue(&name, agent_uid, grant, ttl_secs)
                            .unwrap_or_else(failed),
                        None,
                    )
                }
            }
            AdminRequest::Unfreeze { id } if approve => match parse_id(&id) {
                Ok(id) => self.park_unfreeze(
                    conn,
                    keep_approval::change::Scope::Credential(keep_approval::Hex16(id)),
                ),
                Err(e) => (failed(e), None),
            },
            AdminRequest::UnfreezeAll {} if approve => {
                self.park_unfreeze(conn, keep_approval::change::Scope::All)
            }
            AdminRequest::ApproverPair { label } => self.pair(uid, conn, &label),
            AdminRequest::ApproverConfirm {} => self.confirm_pair(conn, true),
            AdminRequest::ApproverReject {} => self.confirm_pair(conn, false),
            AdminRequest::ApproverRemove { transport } => {
                let mut key = [0u8; 32];
                if hex::decode_to_slice(&transport, &mut key).is_err() {
                    return (
                        failed(AgentError::Other("a transport key is 64 hex digits".into())),
                        None,
                    );
                }
                if !approve {
                    return (
                        failed(AgentError::Other(
                            "no approver device is registered here".into(),
                        )),
                        None,
                    );
                }
                self.park_remove(conn, &key)
            }
            AdminRequest::ApproverReset {} if uid != 0 => (
                failed(AgentError::Other(
                    "only root may reset the approver devices".into(),
                )),
                None,
            ),
            AdminRequest::ApproverReset {} => (
                self.reset_approvers()
                    .map(|result| line(&json!({ "ok": true, "result": result })))
                    .unwrap_or_else(failed),
                None,
            ),
            request => (
                self.admin(request)
                    .map(|result| line(&json!({ "ok": true, "result": result })))
                    .unwrap_or_else(failed),
                None,
            ),
        }
    }

    /// The grant a credential for `uid` may be issued with, parsed from
    /// `grant`: see [`Self::checked_grant`].
    fn issuable_grant(&self, uid: u32, mut grant: Value) -> Result<Grant> {
        self.resolve_secret_names(&mut grant)?;
        let grant: Grant = serde_json::from_value(grant)
            .map_err(|e| AgentError::ScopeViolation(format!("invalid grant: {e}")))?;
        self.checked_grant(uid, grant)
    }

    /// Replace each secret the owner named as `{"name": ...}` with its id,
    /// then sort the entries by id, as a grant lists them. A name no secret
    /// has and one several share get one answer, so the admin socket cannot
    /// tell those two apart.
    fn resolve_secret_names(&self, grant: &mut Value) -> Result<()> {
        let Some(secrets) = grant.get_mut("secrets").and_then(Value::as_array_mut) else {
            return Ok(());
        };
        for entry in secrets.iter_mut() {
            let Some(slot) = entry.get_mut("secret") else {
                continue;
            };
            let Some(named) = slot.as_object() else {
                continue;
            };
            let name = match (named.len(), named.get("name").and_then(Value::as_str)) {
                (1, Some(name)) => name.to_string(),
                _ => {
                    return Err(AgentError::ScopeViolation(
                        "a secret is given by its id or as {\"name\": ...}".into(),
                    ))
                }
            };
            let id = self.keep.find_secret(&name).map_err(|_| {
                AgentError::ScopeViolation("unknown or ambiguous secret name".into())
            })?;
            *slot = Value::String(hex::encode(id));
        }
        secrets.sort_by(|a, b| {
            let id = |v: &Value| v.get("secret").and_then(Value::as_str).map(str::to_owned);
            id(a).cmp(&id(b))
        });
        Ok(())
    }

    /// `grant`, if a credential for `uid` may be issued with it now: the uid
    /// may hold one, the grant validates, and every key it names is a
    /// signing key in the vault. Checked again when an approved issue is
    /// carried out, since keys and uids may change while it waits.
    fn checked_grant(&self, uid: u32, grant: Grant) -> Result<Grant> {
        if forbidden_uid(&self.host, &self.settings, uid) || !bindable_uid(uid) {
            return Err(AgentError::ScopeViolation(format!(
                "uid {uid} is root, the gateway's, the vault owner's, the admin's, the relay \
                 helper's, the overflow uid or (with injection on) one systemd gives \
                 dynamic services; a credential bound to it would stop nothing"
            )));
        }
        for key in &grant.keys {
            match self.keep.keyring().get(key) {
                Some(slot) if matches!(slot.key_type, KeyType::Nostr | KeyType::Bitcoin) => {}
                Some(_) => {
                    return Err(AgentError::ScopeViolation(format!(
                        "key {} is not a signing key",
                        hex::encode(key)
                    )))
                }
                None => {
                    return Err(AgentError::ScopeViolation(format!(
                        "key {} is not in the vault",
                        hex::encode(key)
                    )))
                }
            }
        }
        for entry in &grant.secrets {
            let id = hex::encode(entry.secret);
            let info = self.keep.secret_info(&entry.secret).map_err(|_| {
                AgentError::ScopeViolation(format!("secret {id} is not in the vault"))
            })?;
            if info.sealed {
                return Err(AgentError::ScopeViolation(format!(
                    "secret {id} is threshold-sealed, and cannot be used by an agent"
                )));
            }
            if !entry.http.is_empty() && !crate::inject::rule::HTTP_KINDS.contains(&info.kind) {
                return Err(AgentError::ScopeViolation(format!(
                    "secret {id} is a {}, which is not sent over HTTP",
                    info.kind.as_str()
                )));
            }
        }
        // Only once the rules are valid: a header value is built from each
        // rule's format.
        let grant = grant.validated(&self.reserved)?;
        for entry in grant.secrets.iter().filter(|e| !e.http.is_empty()) {
            let id = hex::encode(entry.secret);
            let value = self
                .keep
                .use_secret(&entry.secret, &crate::inject::rule::HTTP_KINDS)
                .map_err(|_| AgentError::ScopeViolation(format!("secret {id} cannot be read")))?;
            for rule in &entry.http {
                rule.header_value(&value).map_err(|e| {
                    AgentError::ScopeViolation(format!("secret {id} cannot be sent: {e}"))
                })?;
            }
        }
        Ok(grant)
    }

    /// Issue a credential. The answer is the one line that carries its token,
    /// written straight into a buffer that is wiped, with the token beside
    /// the credential rather than inside a JSON value that would be freed
    /// unwiped.
    fn issue(
        &mut self,
        name: &str,
        uid: u32,
        grant: Value,
        ttl_secs: Option<u64>,
    ) -> Result<Zeroizing<String>> {
        // Credentials live on the calendar clock, which they are checked against.
        let now = self.clock.calendar();
        let grant = self.issuable_grant(uid, grant)?;
        let ttl = ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
        let (issued, token) =
            issue_credential(&mut self.keep, name, uid, grant, &self.reserved, now, ttl)?;
        Ok(self.issued_line(&issued.credential, &token))
    }

    /// Note credential `credential`'s uid as bound, and the answer that
    /// carries it and its token. `head` holds no secret; the token goes only
    /// into the answer, sized so it never reallocates. Tokens are lowercase
    /// hex behind a fixed prefix, so they need no escaping.
    fn issued_line(&mut self, credential: &AgentCredential, token: &str) -> Zeroizing<String> {
        if let Ok(mut set) = self.bound.write() {
            set.insert(credential.uid);
        }
        let now = self.clock.calendar();
        let head = json!({
            "ok": true,
            "result": credential_json(credential, now, &self.reserved)
        })
        .to_string();
        let mut out = Zeroizing::new(String::with_capacity(head.len() + token.len() + 16));
        out.push_str(&head[..head.len() - 1]);
        out.push_str(",\"token\":\"");
        out.push_str(token);
        out.push_str("\"}");
        out
    }

    /// Issue a credential an approver approved, with the id, issue time and
    /// lifetime the approved change carries. The answer carries its token, as
    /// [`Self::issue`]'s does.
    fn issue_approved(
        &mut self,
        id: [u8; 16],
        name: &str,
        uid: u32,
        grant: Grant,
        created_at: u64,
        ttl: u64,
    ) -> Result<Zeroizing<String>> {
        let grant = self.checked_grant(uid, grant)?;
        let bytes =
            serde_json::to_vec(&grant).map_err(|e| AgentError::Serialization(e.to_string()))?;
        let (credential, token) = self
            .keep
            .issue_agent_credential_with_id(id, name, uid, bytes, created_at, ttl)?;
        Ok(self.issued_line(&credential, &token))
    }

    fn admin(&mut self, request: AdminRequest) -> Result<Value> {
        let now = self.clock.calendar();
        match request {
            AdminRequest::Status {} => Ok(json!({
                "clock": self.clock.now(),
                "calendar": now,
                "wall": clock::wall_clock().ok(),
                "heartbeat_ignored_at_start": self.heartbeat_ignored,
                "frozen": self.keep.agent_freeze()?,
                "credentials": self.keep.agent_credential_ids()?.len(),
                "wallet_budget_sats": self.settings.wallet_budget_sats,
                "approvals": self.approval_status(),
                "audit_warnings": self
                    .keep
                    .audit_warnings()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                "version": env!("CARGO_PKG_VERSION"),
            })),
            AdminRequest::ApproverList {} => Ok(self.approvers()),
            AdminRequest::List {} => {
                let mut list = Vec::new();
                for id in self.keep.agent_credential_ids()? {
                    list.push(match load_credential(&self.keep, &id) {
                        Ok(Some(c)) => credential_json(&c, now, &self.reserved),
                        Ok(None) => continue,
                        Err(e) => json!({ "id": hex::encode(id), "unreadable": e.to_string() }),
                    });
                }
                Ok(Value::Array(list))
            }
            // Answered by `Self::issue`, which keeps the token out of values.
            AdminRequest::Issue { .. } => Err(AgentError::Other("issue is answered apart".into())),
            AdminRequest::Revoke { id } => {
                let id = parse_id(&id)?;
                // Canceled first, so a revoke that fails leaves nothing of
                // the credential's to be approved and signed.
                self.cancel_revoked(&id);
                self.keep.revoke_agent_credential(&id)?;
                Ok(json!({ "revoked": hex::encode(id) }))
            }
            AdminRequest::Delete { id } => {
                let id = parse_id(&id)?;
                self.cancel_revoked(&id);
                self.delete_credential(&id)?;
                self.audit.reset(&id);
                self.credential_counts.remove(&id);
                // The credential is gone either way; a stale bound uid only
                // keeps its own slots until the next start.
                if let Err(e) = self.refresh_bound() {
                    tracing::error!(error = %e, "the bound uids could not be recounted");
                }
                Ok(json!({ "deleted": hex::encode(id) }))
            }
            AdminRequest::Freeze { id } => {
                let id = parse_id(&id)?;
                self.load_known(&id)?;
                self.freeze(credential_scope(id), "the admin socket", self.store().ok())?;
                Ok(json!({ "frozen": hex::encode(id) }))
            }
            AdminRequest::Unfreeze { id } => {
                let id = parse_id(&id)?;
                self.load_known(&id)?;
                self.unfreeze_now(credential_scope(id))?;
                Ok(json!({ "unfrozen": hex::encode(id) }))
            }
            AdminRequest::FreezeAll {} => {
                self.freeze(
                    keep_approval::change::Scope::All,
                    "the admin socket",
                    self.store().ok(),
                )?;
                Ok(json!({ "frozen": "all" }))
            }
            AdminRequest::UnfreezeAll {} => {
                self.unfreeze_now(keep_approval::change::Scope::All)?;
                Ok(json!({ "unfrozen": "all" }))
            }
            AdminRequest::ApproverPair { .. }
            | AdminRequest::ApproverConfirm {}
            | AdminRequest::ApproverReject {}
            | AdminRequest::ApproverRemove { .. }
            | AdminRequest::ApproverReset {} => Err(AgentError::Other("answered apart".into())),
            AdminRequest::Audit { limit } => {
                let limit = limit.unwrap_or(100).min(MAX_AUDIT_READ);
                let entries = self.keep.read_audit_entries()?;
                let skip = entries.len().saturating_sub(limit);
                Ok(Value::Array(
                    entries
                        .iter()
                        .skip(skip)
                        .map(|e| {
                            json!({
                                "timestamp": e.timestamp,
                                "event": e.event_type.to_string(),
                                "success": e.success,
                                "pubkey": e.pubkey,
                                "message_hash": e.message_hash,
                                "reason": e.reason,
                            })
                        })
                        .collect(),
                ))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn journal_lines(&self) -> usize {
        self.journal_lines.len()
    }

    #[cfg(test)]
    pub(crate) fn keep(&self) -> &Keep {
        &self.keep
    }

    #[cfg(test)]
    pub(crate) fn keep_mut(&mut self) -> &mut Keep {
        &mut self.keep
    }
}

/// A management request from the admin socket.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminRequest {
    // Every variant has braces: serde refuses unknown fields only in those.
    Status {},
    List {},
    Issue {
        name: String,
        uid: u32,
        grant: Value,
        ttl_secs: Option<u64>,
    },
    Revoke {
        id: String,
    },
    Delete {
        id: String,
    },
    Freeze {
        id: String,
    },
    Unfreeze {
        id: String,
    },
    FreezeAll {},
    UnfreezeAll {},
    Audit {
        limit: Option<usize>,
    },
    /// Open a pairing session for an approver device labeled `label`.
    ApproverPair {
        label: String,
    },
    /// The fingerprint matches on both screens: register the device, or ask
    /// an existing device to.
    ApproverConfirm {},
    /// The fingerprint does not match: refuse the device.
    ApproverReject {},
    ApproverList {},
    /// Ask an existing device to approve removing the device with this
    /// transport key.
    ApproverRemove {
        transport: String,
    },
    /// Remove every approver device: root only.
    ApproverReset {},
}

/// Whether a credential must never be bound to `uid` on this host: binding it
/// to the gateway's own uid, the vault owner's, the admin's or the overflow
/// uid would stop nothing, and an agent with the relay helper's could take
/// the helper's connection.
fn forbidden_uid(host: &Host, settings: &Settings, uid: u32) -> bool {
    uid == host.euid
        || uid == host.vault_owner
        || uid == host.overflow_uid
        || settings.admin_uid == Some(uid)
        || settings.relay_uid == Some(uid)
        || (settings.inject.is_some() && DYNAMIC_UIDS.contains(&uid))
}

/// The uids systemd gives services that run under `DynamicUser=`, as inject
/// workers do: no credential is bound to one.
pub const DYNAMIC_UIDS: std::ops::RangeInclusive<u32> = 61_184..=65_519;

/// The longest line taken for a cancellation before the uid's request limit:
/// a longer one is refused as any line is, with a null id, so the bridge
/// never sends one.
pub const MAX_CANCELLATION_LINE: usize = 4 * 1024;

/// `request` as a `notifications/cancelled` envelope, when it is one. Only a
/// short line that names the method is parsed, so a line refused by the
/// uid's limit is not parsed first.
fn cancellation(request: &[u8]) -> Option<Envelope> {
    const METHOD: &[u8] = b"notifications/cancelled";
    if request.len() > MAX_CANCELLATION_LINE || !request.windows(METHOD.len()).any(|w| w == METHOD)
    {
        return None;
    }
    let envelope: Envelope = serde_json::from_slice(request).ok()?;
    (envelope.message.get("id").is_none()
        && envelope.message.get("method").and_then(Value::as_str)
            == Some("notifications/cancelled"))
    .then_some(envelope)
}

fn load_credential(keep: &Keep, id: &[u8; 16]) -> Result<Option<AgentCredential>> {
    Ok(keep.load_agent_credential(id)?)
}

fn ledger_last_seen(keep: &Keep, key: &[u8]) -> u64 {
    match keep.load_agent_ledger(key) {
        Ok(Some(bytes)) => match decode_ledger(Some(&bytes)) {
            Ok(ledger) => ledger.last_seen(),
            Err(e) => {
                tracing::warn!(key = %hex::encode(key), error = %e, "agent ledger cannot be read");
                0
            }
        },
        Ok(None) => 0,
        Err(e) => {
            tracing::warn!(key = %hex::encode(key), error = %e, "agent ledger cannot be read");
            0
        }
    }
}

/// One network of each wallet ledger: mainnet, and the test networks.
const LEDGER_NETWORKS: [Network; 2] = [Network::Bitcoin, Network::Testnet];

/// The ledger key of `pubkey`'s wallet on `network`. Mainnet has its own
/// budget, so spends of test coins never use up the mainnet budget; the test
/// networks share one, as they share the wallet's keys. Never 16 bytes, so
/// never a credential's.
pub fn wallet_key(pubkey: &[u8; 32], network: Network) -> Vec<u8> {
    let tag: &[u8] = match network {
        Network::Bitcoin => b"wallet:main:",
        _ => b"wallet:test:",
    };
    let mut key = tag.to_vec();
    key.extend_from_slice(pubkey);
    key
}

fn decode_ledger(bytes: Option<&[u8]>) -> keep_core::error::Result<Ledger> {
    match bytes {
        None => Ok(Ledger::default()),
        Some(bytes) => serde_json::from_slice(bytes).map_err(|e| {
            keep_core::error::KeepError::Other(format!("agent ledger does not decode: {e}"))
        }),
    }
}

fn encode_ledger(ledger: &Ledger) -> keep_core::error::Result<Vec<u8>> {
    serde_json::to_vec(ledger).map_err(|e| keep_core::error::KeepError::Other(e.to_string()))
}

fn withheld(e: AgentError) -> Refusal {
    Refusal::Internal(format!("withheld: it could not be recorded: {e}"))
}

fn only_args(args: &Value, allowed: &[&str]) -> std::result::Result<(), Refusal> {
    let Some(map) = args.as_object() else {
        return Err(Refusal::params("arguments must be an object"));
    };
    match map.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(Refusal::params(format!(
            "unknown argument {:?}",
            keep_core::agent::cap_text(k, keep_core::agent::MAX_AUDIT_TEXT)
        ))),
        None => Ok(()),
    }
}

/// A secret id as an agent names it: 64 lowercase hex characters.
fn parse_secret_id(s: &str) -> Option<[u8; 32]> {
    keep_approval::Hex32::parse(s).ok().map(|h| h.0)
}

/// The key a request names, or the grant's only key.
fn key_arg(grant: &Grant, args: &Value) -> std::result::Result<[u8; 32], Refusal> {
    match args.get("key") {
        None | Some(Value::Null) => {
            let mut keys = grant.keys.iter();
            match (keys.next(), keys.next()) {
                (Some(key), None) => Ok(*key),
                _ => Err(Refusal::params(
                    "name the key: this credential may use several",
                )),
            }
        }
        Some(Value::String(s)) => {
            parse_key(s).ok_or_else(|| Refusal::params("key must be hex or an npub"))
        }
        Some(_) => Err(Refusal::params("key must be a string")),
    }
}

/// A public key given as 64 hex digits or an npub.
pub fn parse_key(s: &str) -> Option<[u8; 32]> {
    if s.starts_with("npub1") {
        return keep_core::keys::npub_to_bytes(s).ok();
    }
    let mut key = [0u8; 32];
    (s.len() == 64)
        .then(|| hex::decode_to_slice(s, &mut key).ok())
        .flatten()
        .map(|()| key)
}

/// The grant's network; a `network` argument may only name it.
fn network_arg(grant: &Grant, args: &Value) -> std::result::Result<Network, Refusal> {
    let granted = grant
        .bitcoin
        .as_ref()
        .map(|b| b.network)
        .ok_or_else(|| Refusal::denied(DenyReason::NoBitcoinGrant))?;
    match args.get("network") {
        None | Some(Value::Null) => Ok(granted),
        Some(Value::String(name)) => {
            let named = keep_bitcoin::parse_network(name)
                .map_err(|_| Refusal::params("unknown network"))?;
            if named != granted {
                return Err(Refusal::denied(DenyReason::NetworkMismatch {
                    requested: named,
                    granted,
                }));
            }
            Ok(granted)
        }
        Some(_) => Err(Refusal::params("network must be a string")),
    }
}

fn credential_scope(id: [u8; 16]) -> keep_approval::change::Scope {
    keep_approval::change::Scope::Credential(keep_approval::Hex16(id))
}

fn parse_id(s: &str) -> Result<[u8; 16]> {
    let mut id = [0u8; 16];
    hex::decode_to_slice(s, &mut id)
        .map_err(|_| AgentError::Other("a credential id is 32 hex digits".into()))?;
    Ok(id)
}

fn grant_json(grant: &Grant) -> Value {
    json!({
        "keys": grant.keys.iter().map(hex::encode).collect::<Vec<_>>(),
        "operations": grant.operations.iter().map(Operation::as_str).collect::<Vec<_>>(),
        "event_kinds": grant.event_kinds,
        "nip44_peers": grant.nip44_peers.iter().map(hex::encode).collect::<Vec<_>>(),
        "bitcoin": grant.bitcoin,
        "limits": grant.limits,
        "secrets": grant.secrets,
    })
}

fn credential_json(c: &AgentCredential, now: u64, reserved: &ReservedKeys) -> Value {
    let grant = crate::gateway::GrantedCredential::new(c.clone(), reserved)
        .map(|g| grant_json(&g.grant))
        .unwrap_or_else(|e| json!({ "unreadable": e.to_string() }));
    json!({
        "id": c.id_hex(),
        "name": c.name,
        "uid": c.uid,
        "created_at": c.created_at,
        "expires_at": c.expires_at,
        "expired": now >= c.expires_at,
        "revoked": c.revoked,
        "frozen": c.frozen,
        "grant": grant,
    })
}
